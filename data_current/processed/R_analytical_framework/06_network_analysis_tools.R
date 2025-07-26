#!/usr/bin/env Rscript
#' Brazilian Legislative Dataset - Phase 2: Network Analysis Tools
#' 
#' This script implements network analysis capabilities for the Brazilian legislative
#' dataset, including citation/amendment relationship parsing, network graph creation,
#' centrality measures, and community detection for policy clustering.
#' 
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-07-26
#' @version 1.0.0

# Load required libraries
suppressPackageStartupMessages({
  library(igraph)
  library(networkD3)
  library(visNetwork)
  library(tidygraph)
  library(ggraph)
  library(dplyr)
  library(stringr)
  library(arrow)
  library(purrr)
  library(tibble)
  library(ggplot2)
  library(viridis)
  library(RColorBrewer)
  library(plotly)
  library(DT)
  library(logger)
})

# Set up logging
log_threshold(INFO)

#' Network Analysis Functions
#' ==========================

#' Extract citation and amendment relationships from URN metadata
#' @param legislative_data Data frame with legislative documents
#' @return List of edges and nodes for network construction
extract_legislative_relationships <- function(legislative_data) {
  
  log_info("Extracting legislative relationships from URN metadata...")
  
  # Clean and prepare data
  clean_data <- legislative_data %>%
    filter(!is.na(urn), urn != "", !is.na(titulo)) %>%
    mutate(
      urn_clean = str_trim(urn),
      doc_id = row_number()
    )
  
  # Extract different types of relationships
  relationships <- list()
  
  # 1. Direct citations in text (lei, decreto, etc.)
  citation_edges <- extract_text_citations(clean_data)
  relationships$citations <- citation_edges
  
  # 2. URN-based relationships (amendments, regulations)
  urn_edges <- extract_urn_relationships(clean_data)
  relationships$urn_based <- urn_edges
  
  # 3. Subject-matter relationships (shared topics)
  subject_edges <- extract_subject_relationships(clean_data)
  relationships$subject_based <- subject_edges
  
  # 4. Authority-based relationships (same issuing authority)
  authority_edges <- extract_authority_relationships(clean_data)
  relationships$authority_based <- authority_edges
  
  # 5. Temporal relationships (sequential policies)
  temporal_edges <- extract_temporal_relationships(clean_data)
  relationships$temporal <- temporal_edges
  
  # Create comprehensive edge list
  all_edges <- bind_rows(
    relationships$citations %>% mutate(relationship_type = "citation"),
    relationships$urn_based %>% mutate(relationship_type = "urn_based"),
    relationships$subject_based %>% mutate(relationship_type = "subject"),
    relationships$authority_based %>% mutate(relationship_type = "authority"),
    relationships$temporal %>% mutate(relationship_type = "temporal")
  ) %>%
    distinct(from, to, relationship_type, .keep_all = TRUE)
  
  # Create node list with attributes
  nodes <- clean_data %>%
    select(doc_id, urn_clean, titulo, categoria, modal, autoridade, jurisdicao, data, year) %>%
    mutate(
      node_id = as.character(doc_id),
      label = str_trunc(titulo, 50),
      authority_level = case_when(
        str_detect(tolower(autoridade %||% ""), "federal") | jurisdicao == "Federal" ~ "Federal",
        str_detect(tolower(autoridade %||% ""), "estadual|estado") ~ "State",
        str_detect(tolower(autoridade %||% ""), "municipal|prefeitura") ~ "Municipal",
        TRUE ~ "Unknown"
      ),
      time_period = case_when(
        year < 1990 ~ "Pre-1990",
        year >= 1990 & year < 2000 ~ "1990s",
        year >= 2000 & year < 2010 ~ "2000s",
        year >= 2010 & year < 2020 ~ "2010s",
        year >= 2020 ~ "2020s"
      )
    )
  
  log_info("Extracted {nrow(all_edges)} relationships across {nrow(nodes)} documents")
  
  return(list(
    edges = all_edges,
    nodes = nodes,
    relationships = relationships
  ))
}

#' Extract citations from document text
#' @param data Legislative data
#' @return Data frame of citation edges
extract_text_citations <- function(data) {
  
  # Patterns for Brazilian legal citations
  citation_patterns <- c(
    "lei\\s+n[°º]?\\s*(\\d+)(?:/?(\\d{4}))?",
    "decreto\\s+n[°º]?\\s*(\\d+)(?:/?(\\d{4}))?",
    "resolução\\s+n[°º]?\\s*(\\d+)(?:/?(\\d{4}))?",
    "portaria\\s+n[°º]?\\s*(\\d+)(?:/?(\\d{4}))?",
    "instrução\\s+normativa\\s+n[°º]?\\s*(\\d+)(?:/?(\\d{4}))?"
  )
  
  citation_edges <- map_dfr(1:nrow(data), function(i) {
    doc <- data[i, ]
    text_to_search <- paste(doc$titulo, doc$assuntos, doc$ementa, sep = " ")
    
    # Find all citations in this document
    all_citations <- map_dfr(citation_patterns, function(pattern) {
      matches <- str_match_all(tolower(text_to_search), pattern)[[1]]
      if (nrow(matches) > 0) {
        tibble(
          from = as.character(doc$doc_id),
          cited_number = matches[, 2],
          cited_year = ifelse(is.na(matches[, 3]), year(doc$data), matches[, 3]),
          citation_type = str_extract(pattern, "^\\w+")
        )
      } else {
        tibble()
      }
    })
    
    return(all_citations)
  })
  
  # Match citations to actual documents in dataset
  matched_citations <- citation_edges %>%
    inner_join(
      data %>% 
        mutate(
          doc_number = str_extract(urn_clean, "\\d+$"),
          doc_year = str_extract(urn_clean, "\\d{4}")
        ) %>%
        select(doc_id, doc_number, doc_year),
      by = c("cited_number" = "doc_number", "cited_year" = "doc_year")
    ) %>%
    select(from, to = doc_id, citation_type, weight = 1) %>%
    mutate(to = as.character(to))
  
  return(matched_citations)
}

#' Extract URN-based relationships
#' @param data Legislative data
#' @return Data frame of URN-based edges
extract_urn_relationships <- function(data) {
  
  # Group by URN base (without specific identifiers) to find related documents
  urn_groups <- data %>%
    mutate(
      urn_base = str_remove(urn_clean, ";\\d+.*$"),  # Remove specific numbers
      urn_type = str_extract(urn_clean, ":(\\w+):", group = 1),
      urn_authority = str_extract(urn_clean, ":br:(\\w+):", group = 1)
    ) %>%
    filter(!is.na(urn_base), urn_base != "")
  
  # Find documents with similar URN patterns (potential amendments/related docs)
  urn_edges <- urn_groups %>%
    group_by(urn_base) %>%
    filter(n() > 1) %>%  # Only groups with multiple documents
    do({
      docs <- .
      expand_grid(
        from = as.character(docs$doc_id),
        to = as.character(docs$doc_id)
      ) %>%
        filter(from != to) %>%
        mutate(weight = 1)
    }) %>%
    ungroup()
  
  return(urn_edges)
}

#' Extract subject-matter relationships
#' @param data Legislative data
#' @return Data frame of subject-based edges
extract_subject_relationships <- function(data) {
  
  # Extract key terms from subjects and summary
  subject_terms <- data %>%
    mutate(
      combined_subjects = paste(coalesce(assuntos, ""), coalesce(ementa, ""), sep = " "),
      # Extract important terms (transport-related terms)
      transport_terms = str_extract_all(tolower(combined_subjects), 
        "\\b(transport|rodoviário|ferroviário|marítimo|aéreo|portuário|logística|mobilidade|infraestrutura|antt|antaq|anac|dnit)\\b")
    ) %>%
    filter(map_int(transport_terms, length) > 0)
  
  # Create edges between documents sharing similar subjects
  subject_edges <- subject_terms %>%
    rowwise() %>%
    do({
      doc <- .
      # Find other documents with overlapping terms
      overlaps <- subject_terms %>%
        filter(doc_id != doc$doc_id) %>%
        rowwise() %>%
        mutate(
          overlap_count = length(intersect(unlist(doc$transport_terms), unlist(transport_terms)))
        ) %>%
        filter(overlap_count >= 2) %>%  # At least 2 shared terms
        select(to = doc_id, overlap_count)
      
      if (nrow(overlaps) > 0) {
        tibble(
          from = as.character(doc$doc_id),
          to = as.character(overlaps$to),
          weight = overlaps$overlap_count
        )
      } else {
        tibble()
      }
    }) %>%
    ungroup() %>%
    filter(nrow(.) > 0)
  
  return(subject_edges)
}

#' Extract authority-based relationships
#' @param data Legislative data
#' @return Data frame of authority-based edges
extract_authority_relationships <- function(data) {
  
  authority_edges <- data %>%
    filter(!is.na(autoridade), autoridade != "") %>%
    group_by(autoridade) %>%
    filter(n() >= 3) %>%  # Only authorities with 3+ documents
    do({
      docs <- .
      expand_grid(
        from = as.character(docs$doc_id),
        to = as.character(docs$doc_id)
      ) %>%
        filter(from != to) %>%
        mutate(weight = 0.5)  # Lower weight for authority relationships
    }) %>%
    ungroup()
  
  return(authority_edges)
}

#' Extract temporal relationships
#' @param data Legislative data
#' @return Data frame of temporal edges
extract_temporal_relationships <- function(data) {
  
  # Connect documents that are temporally close and from same authority/category
  temporal_edges <- data %>%
    filter(!is.na(data)) %>%
    arrange(data) %>%
    group_by(autoridade, categoria) %>%
    mutate(
      next_doc = lead(doc_id),
      next_date = lead(data),
      time_diff = as.numeric(difftime(next_date, data, units = "days"))
    ) %>%
    filter(
      !is.na(next_doc),
      time_diff <= 365,  # Within 1 year
      time_diff > 0
    ) %>%
    select(from = doc_id, to = next_doc, time_diff) %>%
    mutate(
      from = as.character(from),
      to = as.character(to),
      weight = 1 / (1 + time_diff/365)  # Closer in time = higher weight
    ) %>%
    ungroup()
  
  return(temporal_edges)
}

#' Create network graph object
#' @param network_data Output from extract_legislative_relationships
#' @param min_weight Minimum edge weight to include
#' @return igraph object
create_legislative_network <- function(network_data, min_weight = 0.5) {
  
  log_info("Creating legislative network graph...")
  
  # Filter edges by weight
  filtered_edges <- network_data$edges %>%
    filter(weight >= min_weight) %>%
    select(from, to, weight, relationship_type)
  
  # Ensure nodes exist for all edges
  edge_nodes <- unique(c(filtered_edges$from, filtered_edges$to))
  filtered_nodes <- network_data$nodes %>%
    filter(node_id %in% edge_nodes)
  
  # Create igraph object
  graph <- graph_from_data_frame(
    d = filtered_edges,
    vertices = filtered_nodes,
    directed = TRUE
  )
  
  # Add graph-level attributes
  graph <- graph %>%
    set_graph_attr("name", "Brazilian Legislative Network") %>%
    set_graph_attr("description", "Network of legislative documents with various relationship types")
  
  log_info("Created network with {vcount(graph)} nodes and {ecount(graph)} edges")
  
  return(graph)
}

#' Calculate network centrality measures
#' @param graph igraph object
#' @return Data frame with centrality measures
calculate_centrality_measures <- function(graph) {
  
  log_info("Calculating network centrality measures...")
  
  # Calculate various centrality measures
  centrality_measures <- tibble(
    node_id = V(graph)$name,
    
    # Degree centrality
    degree = degree(graph),
    in_degree = degree(graph, mode = "in"),
    out_degree = degree(graph, mode = "out"),
    
    # Betweenness centrality
    betweenness = betweenness(graph, normalized = TRUE),
    
    # Closeness centrality
    closeness = closeness(graph, normalized = TRUE),
    
    # Eigenvector centrality
    eigenvector = eigen_centrality(graph)$vector,
    
    # PageRank
    pagerank = page_rank(graph)$vector,
    
    # Authority and hub scores
    authority = authority_score(graph)$vector,
    hub = hub_score(graph)$vector
  ) %>%
    # Add node attributes
    left_join(
      tibble(
        node_id = V(graph)$name,
        titulo = V(graph)$titulo,
        categoria = V(graph)$categoria,
        modal = V(graph)$modal,
        authority_level = V(graph)$authority_level,
        time_period = V(graph)$time_period
      ),
      by = "node_id"
    ) %>%
    # Rank by different centrality measures
    mutate(
      degree_rank = dense_rank(desc(degree)),
      betweenness_rank = dense_rank(desc(betweenness)),
      pagerank_rank = dense_rank(desc(pagerank)),
      
      # Composite centrality score
      centrality_composite = scale(degree)[,1] + scale(betweenness)[,1] + scale(pagerank)[,1]
    )
  
  log_info("Calculated centrality measures for {nrow(centrality_measures)} nodes")
  
  return(centrality_measures)
}

#' Perform community detection
#' @param graph igraph object
#' @return List with community detection results
detect_communities <- function(graph) {
  
  log_info("Performing community detection...")
  
  # Convert to undirected for community detection
  undirected_graph <- as.undirected(graph, mode = "collapse")
  
  # Multiple community detection algorithms
  communities <- list()
  
  # 1. Louvain algorithm
  communities$louvain <- cluster_louvain(undirected_graph)
  
  # 2. Fast greedy
  communities$fast_greedy <- cluster_fast_greedy(undirected_graph)
  
  # 3. Walktrap
  communities$walktrap <- cluster_walktrap(undirected_graph)
  
  # 4. Edge betweenness
  communities$edge_betweenness <- cluster_edge_betweenness(undirected_graph)
  
  # Compare modularity scores
  modularity_scores <- map_dbl(communities, modularity)
  best_algorithm <- names(modularity_scores)[which.max(modularity_scores)]
  
  # Get best community assignment
  best_communities <- communities[[best_algorithm]]
  
  # Community summary
  community_summary <- tibble(
    node_id = V(undirected_graph)$name,
    community = membership(best_communities)
  ) %>%
    left_join(
      tibble(
        node_id = V(undirected_graph)$name,
        titulo = V(undirected_graph)$titulo,
        categoria = V(undirected_graph)$categoria,
        modal = V(undirected_graph)$modal
      ),
      by = "node_id"
    ) %>%
    group_by(community) %>%
    summarise(
      size = n(),
      dominant_category = names(sort(table(categoria), decreasing = TRUE))[1],
      dominant_modal = names(sort(table(modal), decreasing = TRUE))[1],
      .groups = "drop"
    )
  
  log_info("Detected {length(best_communities)} communities using {best_algorithm} algorithm")
  log_info("Best modularity score: {round(max(modularity_scores), 3)}")
  
  return(list(
    communities = communities,
    best_algorithm = best_algorithm,
    best_communities = best_communities,
    modularity_scores = modularity_scores,
    community_summary = community_summary,
    membership = membership(best_communities)
  ))
}

#' Generate network visualizations
#' @param graph igraph object
#' @param centrality_data Centrality measures
#' @param community_data Community detection results
#' @param output_dir Output directory
generate_network_visualizations <- function(graph, centrality_data, community_data, output_dir) {
  
  log_info("Generating network visualizations...")
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # 1. Basic network layout
  set.seed(123)
  layout <- layout_with_fr(graph)
  
  # 2. Network plot colored by category
  category_plot <- ggraph(graph, layout = layout) +
    geom_edge_link(aes(alpha = weight), color = "gray50") +
    geom_node_point(aes(color = categoria, size = degree), alpha = 0.8) +
    scale_color_viridis_d() +
    scale_size_continuous(range = c(1, 6)) +
    theme_graph() +
    labs(title = "Legislative Network by Category",
         color = "Category", size = "Degree")
  
  # 3. Network plot colored by communities
  V(graph)$community <- community_data$membership[match(V(graph)$name, names(community_data$membership))]
  
  community_plot <- ggraph(graph, layout = layout) +
    geom_edge_link(alpha = 0.3, color = "gray70") +
    geom_node_point(aes(color = factor(community), size = degree), alpha = 0.8) +
    scale_color_brewer(type = "qual", palette = "Set3") +
    scale_size_continuous(range = c(1, 6)) +
    theme_graph() +
    labs(title = "Legislative Network Communities",
         color = "Community", size = "Degree")
  
  # 4. Centrality comparison plot
  centrality_comparison <- centrality_data %>%
    select(node_id, titulo, degree, betweenness, pagerank, centrality_composite) %>%
    top_n(20, centrality_composite) %>%
    mutate(titulo_short = str_trunc(titulo, 40)) %>%
    ggplot(aes(x = reorder(titulo_short, centrality_composite))) +
    geom_col(aes(y = centrality_composite), fill = "steelblue") +
    coord_flip() +
    labs(title = "Top 20 Most Central Documents",
         subtitle = "Based on composite centrality score",
         x = "Document", y = "Centrality Score") +
    theme_minimal()
  
  # 5. Community size distribution
  community_dist_plot <- community_data$community_summary %>%
    ggplot(aes(x = reorder(paste("Community", community), size), y = size)) +
    geom_col(fill = "darkgreen") +
    coord_flip() +
    labs(title = "Community Size Distribution",
         x = "Community", y = "Number of Documents") +
    theme_minimal()
  
  # Save static plots
  ggsave(file.path(output_dir, "network_by_category.png"), category_plot,
         width = 12, height = 10, dpi = 300)
  ggsave(file.path(output_dir, "network_communities.png"), community_plot,
         width = 12, height = 10, dpi = 300)
  ggsave(file.path(output_dir, "centrality_ranking.png"), centrality_comparison,
         width = 10, height = 8, dpi = 300)
  ggsave(file.path(output_dir, "community_distribution.png"), community_dist_plot,
         width = 10, height = 6, dpi = 300)
  
  # 6. Interactive network visualization
  # Prepare data for visNetwork
  vis_nodes <- centrality_data %>%
    select(id = node_id, label = titulo, group = categoria, 
           value = degree, title = titulo) %>%
    mutate(
      label = str_trunc(label, 30),
      title = paste("Title:", title, "<br>Category:", group, "<br>Degree:", value)
    )
  
  vis_edges <- as_data_frame(graph, what = "edges") %>%
    select(from, to, value = weight) %>%
    mutate(title = paste("Weight:", round(value, 2)))
  
  # Create interactive network
  interactive_network <- visNetwork(vis_nodes, vis_edges) %>%
    visOptions(highlightNearest = TRUE, nodesIdSelection = TRUE) %>%
    visLayout(randomSeed = 123) %>%
    visPhysics(stabilization = FALSE)
  
  # Save interactive network
  visSave(interactive_network, file.path(output_dir, "interactive_network.html"))
  
  log_info("Network visualizations saved to {output_dir}")
}

#' Main network analysis pipeline
#' @param data_source Path to data file or data frame
#' @param output_dir Output directory for results
run_network_analysis <- function(data_source, output_dir) {
  
  log_info("=== STARTING NETWORK ANALYSIS PIPELINE ===")
  
  # 1. Load data
  if (is.character(data_source)) {
    legislative_data <- read_parquet(data_source)
  } else {
    legislative_data <- data_source
  }
  
  # 2. Extract relationships
  network_data <- extract_legislative_relationships(legislative_data)
  
  # 3. Create network graph
  graph <- create_legislative_network(network_data)
  
  # 4. Calculate centrality measures
  centrality_data <- calculate_centrality_measures(graph)
  
  # 5. Detect communities
  community_data <- detect_communities(graph)
  
  # 6. Generate visualizations
  generate_network_visualizations(graph, centrality_data, community_data, output_dir)
  
  # 7. Save results
  network_results <- list(
    graph = graph,
    network_data = network_data,
    centrality_data = centrality_data,
    community_data = community_data
  )
  
  saveRDS(network_results, file.path(output_dir, "network_analysis_results.rds"))
  write_parquet(centrality_data, file.path(output_dir, "centrality_measures.parquet"))
  
  # 8. Generate summary report
  summary_stats <- list(
    total_nodes = vcount(graph),
    total_edges = ecount(graph),
    network_density = edge_density(graph),
    average_degree = mean(degree(graph)),
    num_communities = length(community_data$best_communities),
    modularity = max(community_data$modularity_scores),
    most_central_doc = centrality_data$titulo[which.max(centrality_data$centrality_composite)]
  )
  
  saveRDS(summary_stats, file.path(output_dir, "network_summary_stats.rds"))
  
  log_info("=== NETWORK ANALYSIS COMPLETED ===")
  log_info("Network: {summary_stats$total_nodes} nodes, {summary_stats$total_edges} edges")
  log_info("Density: {round(summary_stats$network_density, 4)}")
  log_info("Communities: {summary_stats$num_communities} (modularity: {round(summary_stats$modularity, 3)})")
  
  return(network_results)
}

# Execute if run as script
if (!interactive()) {
  # Set paths
  parquet_file <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/parquet_dataset/combined_legislative_dataset.parquet"
  output_dir <- file.path(dirname(dirname(parquet_file)), "network_analysis_results")
  
  # Check if Parquet file exists
  if (!file.exists(parquet_file)) {
    cat("Parquet file not found. Please run CSV to Parquet conversion first.\n")
    quit(status = 1)
  }
  
  # Run network analysis
  results <- run_network_analysis(parquet_file, output_dir)
  
  cat("Network analysis completed. Results saved to:", output_dir, "\n")
}