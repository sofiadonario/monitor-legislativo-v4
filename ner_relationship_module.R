# Named Entity Recognition and Relationship Extraction Module
# MackMonitor v4 - Entity and Citation Network Analysis
# Author: Analytics Module
# Date: 2025-01-25

library(spacyr)
library(openNLP)
library(NLP)
library(udpipe)
library(igraph)
library(ggraph)
library(dplyr)
library(stringr)
library(tidyr)
library(purrr)

# ============================================================================
# 1. CONFIGURATION AND SETUP
# ============================================================================

# Initialize NLP models
initialize_nlp_models <- function() {
  models <- list()
  
  # Try spaCy first (best option for Portuguese)
  tryCatch({
    spacy_initialize(model = "pt_core_news_sm")
    models$spacy_available <- TRUE
    cat("✓ spaCy Portuguese model loaded\n")
  }, error = function(e) {
    cat("✗ spaCy not available, falling back to alternatives\n")
    models$spacy_available <- FALSE
  })
  
  # UDPipe as fallback
  if (!models$spacy_available) {
    # Download Portuguese model if not exists
    model_file <- "portuguese-bosque-ud-2.5-191206.udpipe"
    if (!file.exists(model_file)) {
      udpipe_download_model(language = "portuguese", model_dir = ".")
    }
    models$udpipe <- udpipe_load_model(model_file)
    cat("✓ UDPipe Portuguese model loaded\n")
  }
  
  return(models)
}

# Entity type mappings for Portuguese legal texts
ENTITY_TYPES <- list(
  # Organizations
  organizations = c(
    "ministério", "secretaria", "departamento", "agência",
    "autarquia", "empresa", "companhia", "sociedade",
    "tribunal", "procuradoria", "defensoria", "conselho",
    "comissão", "câmara", "senado", "assembleia"
  ),
  
  # Government agencies specific to transportation
  transport_agencies = c(
    "ANTT", "ANTAQ", "ANAC", "DNIT", "INFRAERO",
    "DENATRAN", "CONTRAN", "DER", "DETRAN", "ARTESP"
  ),
  
  # Legal instruments
  legal_instruments = c(
    "lei", "decreto", "portaria", "resolução", "instrução",
    "medida provisória", "emenda", "parecer", "súmula"
  ),
  
  # Technologies and infrastructure
  technologies = c(
    "rodovia", "ferrovia", "aeroporto", "porto", "terminal",
    "veículo", "aeronave", "embarcação", "navio", "trem",
    "ônibus", "caminhão", "automóvel", "motocicleta"
  ),
  
  # Energy and fuels
  fuels = c(
    "gasolina", "diesel", "etanol", "biodiesel", "GNV",
    "querosene", "combustível", "biocombustível", "energia"
  )
)

# ============================================================================
# 2. ENTITY EXTRACTION FUNCTIONS
# ============================================================================

#' Extract entities using spaCy
#' @param texts Character vector of texts
#' @return Data frame with extracted entities
extract_entities_spacy <- function(texts) {
  if (!exists("spacy_parse")) {
    stop("spaCy not initialized")
  }
  
  # Parse texts
  parsed <- spacy_parse(texts, 
                       entity = TRUE,
                       nounphrase = TRUE,
                       dependency = FALSE)
  
  # Extract entities
  entities <- parsed %>%
    filter(!is.na(entity)) %>%
    select(doc_id, token, entity) %>%
    rename(text = token, type = entity)
  
  return(entities)
}

#' Extract entities using UDPipe
#' @param texts Character vector of texts
#' @param udpipe_model Loaded UDPipe model
#' @return Data frame with extracted entities
extract_entities_udpipe <- function(texts, udpipe_model) {
  # Annotate texts
  annotations <- udpipe_annotate(udpipe_model, x = texts)
  annotations_df <- as.data.frame(annotations)
  
  # Extract named entities (simplified)
  entities <- annotations_df %>%
    filter(upos %in% c("PROPN", "NOUN")) %>%
    mutate(
      is_entity = lead(upos) == "PROPN" | lag(upos) == "PROPN",
      entity_group = cumsum(!is_entity & lead(is_entity, default = FALSE))
    ) %>%
    filter(is_entity) %>%
    group_by(doc_id, entity_group) %>%
    summarise(
      text = paste(token, collapse = " "),
      type = "ENTITY",
      start = min(start),
      end = max(end)
    ) %>%
    ungroup() %>%
    select(doc_id, text, type)
  
  return(entities)
}

#' Extract domain-specific entities
#' @param texts Character vector of texts
#' @param entity_dict Domain-specific entity dictionary
#' @return Data frame with extracted entities
extract_domain_entities <- function(texts, entity_dict = ENTITY_TYPES) {
  
  entities_list <- list()
  
  for (i in seq_along(texts)) {
    text_lower <- tolower(texts[i])
    text_entities <- list()
    
    for (entity_type in names(entity_dict)) {
      # Create pattern for each entity type
      pattern <- paste0("\\b(", paste(entity_dict[[entity_type]], collapse = "|"), ")\\b")
      
      # Find all matches
      matches <- str_extract_all(text_lower, pattern)[[1]]
      
      if (length(matches) > 0) {
        text_entities[[entity_type]] <- data.frame(
          doc_id = i,
          text = matches,
          type = entity_type,
          stringsAsFactors = FALSE
        )
      }
    }
    
    entities_list[[i]] <- bind_rows(text_entities)
  }
  
  return(bind_rows(entities_list))
}

#' Extract legal citations and references
#' @param texts Character vector of texts
#' @return Data frame with citations
extract_legal_citations <- function(texts) {
  
  citation_patterns <- list(
    # Federal laws (Lei nº 12.345/2020)
    lei_federal = "lei\\s+(federal\\s+)?n[º°]?\\s*([0-9\\.]+)/?([0-9]{4})?",
    
    # Decrees
    decreto = "decreto\\s+(federal\\s+)?n[º°]?\\s*([0-9\\.]+)/?([0-9]{4})?",
    
    # Portarias
    portaria = "portaria\\s+n[º°]?\\s*([0-9\\.]+)/?([0-9]{4})?",
    
    # Resolutions
    resolucao = "resolução\\s+n[º°]?\\s*([0-9\\.]+)/?([0-9]{4})?",
    
    # Article references
    artigo = "art(igo)?\\s*\\.?\\s*([0-9]+)[º°]?",
    
    # Constitutional references
    constituicao = "constituição\\s+(federal|estadual)?(\\s+de\\s+[0-9]{4})?"
  )
  
  citations_list <- list()
  
  for (i in seq_along(texts)) {
    text_lower <- tolower(texts[i])
    doc_citations <- list()
    
    for (citation_type in names(citation_patterns)) {
      matches <- str_match_all(text_lower, citation_patterns[[citation_type]])[[1]]
      
      if (nrow(matches) > 0) {
        doc_citations[[citation_type]] <- data.frame(
          doc_id = i,
          citation = matches[, 1],
          type = citation_type,
          number = matches[, 2],
          year = if(ncol(matches) >= 3) matches[, 3] else NA,
          stringsAsFactors = FALSE
        )
      }
    }
    
    citations_list[[i]] <- bind_rows(doc_citations)
  }
  
  return(bind_rows(citations_list))
}

# ============================================================================
# 3. RELATIONSHIP EXTRACTION
# ============================================================================

#' Extract relationships between entities
#' @param entities Data frame of entities
#' @param texts Original texts
#' @param window Size of context window
#' @return Data frame of entity relationships
extract_entity_relationships <- function(entities, texts, window = 50) {
  
  relationships <- list()
  
  # Group entities by document
  entities_by_doc <- split(entities, entities$doc_id)
  
  for (doc_id in names(entities_by_doc)) {
    doc_entities <- entities_by_doc[[doc_id]]
    
    if (nrow(doc_entities) < 2) next
    
    # Get document text
    text <- texts[as.numeric(doc_id)]
    
    # Find co-occurring entities within window
    for (i in 1:(nrow(doc_entities) - 1)) {
      entity1 <- doc_entities[i, ]
      
      # Find position in text
      pos1 <- str_locate(tolower(text), 
                        fixed(tolower(entity1$text)))[1, "start"]
      
      for (j in (i + 1):nrow(doc_entities)) {
        entity2 <- doc_entities[j, ]
        
        # Find position
        pos2 <- str_locate(tolower(text), 
                          fixed(tolower(entity2$text)))[1, "start"]
        
        # Check if within window
        if (!is.na(pos1) && !is.na(pos2) && abs(pos2 - pos1) <= window) {
          # Extract context
          context_start <- max(1, min(pos1, pos2) - 20)
          context_end <- min(nchar(text), max(pos1, pos2) + 20)
          context <- substr(text, context_start, context_end)
          
          relationships[[length(relationships) + 1]] <- data.frame(
            doc_id = doc_id,
            entity1 = entity1$text,
            entity1_type = entity1$type,
            entity2 = entity2$text,
            entity2_type = entity2$type,
            distance = abs(pos2 - pos1),
            context = context,
            stringsAsFactors = FALSE
          )
        }
      }
    }
  }
  
  return(bind_rows(relationships))
}

#' Build citation network
#' @param citations Data frame of citations
#' @param documents Document metadata
#' @return igraph network object
build_citation_network <- function(citations, documents) {
  
  # Create nodes for each unique citation
  unique_citations <- citations %>%
    filter(!is.na(number)) %>%
    distinct(type, number, year) %>%
    mutate(
      node_id = paste(type, number, year, sep = "_"),
      label = paste(type, number, ifelse(is.na(year), "", paste0("/", year)))
    )
  
  # Create edges between citations in same document
  edges <- citations %>%
    filter(!is.na(number)) %>%
    mutate(node_id = paste(type, number, year, sep = "_")) %>%
    group_by(doc_id) %>%
    filter(n() > 1) %>%
    do({
      nodes <- .$node_id
      if (length(nodes) > 1) {
        expand.grid(from = nodes, to = nodes, stringsAsFactors = FALSE) %>%
          filter(from < to)
      } else {
        data.frame(from = character(), to = character())
      }
    }) %>%
    ungroup() %>%
    group_by(from, to) %>%
    summarise(weight = n()) %>%
    ungroup()
  
  # Create graph
  g <- graph_from_data_frame(edges, 
                            directed = FALSE,
                            vertices = unique_citations)
  
  # Add node attributes
  V(g)$type <- unique_citations$type
  V(g)$label <- unique_citations$label
  
  # Calculate centrality measures
  V(g)$degree <- degree(g)
  V(g)$betweenness <- betweenness(g)
  V(g)$closeness <- closeness(g)
  
  return(g)
}

# ============================================================================
# 4. NETWORK ANALYSIS
# ============================================================================

#' Analyze entity network properties
#' @param relationships Entity relationships data frame
#' @return Network statistics
analyze_entity_network <- function(relationships) {
  
  # Create weighted network
  edges <- relationships %>%
    group_by(entity1, entity2) %>%
    summarise(
      weight = n(),
      avg_distance = mean(distance),
      types = paste(unique(c(entity1_type, entity2_type)), collapse = "-")
    ) %>%
    ungroup()
  
  # Build graph
  g <- graph_from_data_frame(edges, directed = FALSE)
  
  # Network statistics
  stats <- list(
    nodes = vcount(g),
    edges = ecount(g),
    density = edge_density(g),
    diameter = diameter(g, directed = FALSE),
    avg_path_length = mean_distance(g, directed = FALSE),
    clustering_coef = transitivity(g),
    components = components(g)$no,
    largest_component_size = max(components(g)$csize)
  )
  
  # Node importance
  node_metrics <- data.frame(
    entity = V(g)$name,
    degree = degree(g),
    betweenness = betweenness(g),
    closeness = closeness(g),
    eigenvector = eigen_centrality(g)$vector,
    pagerank = page_rank(g)$vector
  ) %>%
    arrange(desc(pagerank))
  
  # Community detection
  communities <- cluster_louvain(g)
  
  # Add community membership
  node_metrics$community <- membership(communities)
  
  return(list(
    statistics = stats,
    node_metrics = node_metrics,
    communities = communities,
    graph = g
  ))
}

#' Find key entity clusters
#' @param network_analysis Network analysis results
#' @param min_size Minimum cluster size
#' @return Data frame of clusters
identify_entity_clusters <- function(network_analysis, min_size = 3) {
  
  communities <- network_analysis$communities
  node_metrics <- network_analysis$node_metrics
  
  # Get cluster information
  clusters <- node_metrics %>%
    group_by(community) %>%
    summarise(
      size = n(),
      members = paste(entity[order(pagerank, decreasing = TRUE)][1:min(5, n())], 
                     collapse = ", "),
      avg_degree = mean(degree),
      max_pagerank = max(pagerank),
      key_entity = entity[which.max(pagerank)]
    ) %>%
    filter(size >= min_size) %>%
    arrange(desc(size))
  
  return(clusters)
}

# ============================================================================
# 5. VISUALIZATION FUNCTIONS
# ============================================================================

#' Plot entity network
#' @param network_analysis Network analysis results
#' @param top_n Number of top entities to label
#' @return ggraph plot
plot_entity_network <- function(network_analysis, top_n = 20) {
  
  g <- network_analysis$graph
  node_metrics <- network_analysis$node_metrics
  
  # Get top entities for labeling
  top_entities <- head(node_metrics$entity, top_n)
  
  # Create layout
  layout <- create_layout(g, layout = "fr")
  
  # Add node metrics to layout
  layout <- layout %>%
    left_join(node_metrics, by = c("name" = "entity"))
  
  # Plot
  p <- ggraph(layout) +
    geom_edge_link(aes(width = weight), alpha = 0.3, color = "gray50") +
    geom_node_point(aes(size = pagerank, color = factor(community))) +
    geom_node_text(
      aes(label = ifelse(name %in% top_entities, name, "")),
      repel = TRUE,
      size = 3
    ) +
    scale_edge_width(range = c(0.5, 2)) +
    scale_size_continuous(range = c(2, 10)) +
    theme_graph() +
    theme(legend.position = "none") +
    labs(title = "Entity Co-occurrence Network",
         subtitle = "Node size = importance, Color = community")
  
  return(p)
}

#' Plot citation network
#' @param citation_graph Citation network graph
#' @return ggraph plot
plot_citation_network <- function(citation_graph) {
  
  # Filter to significant nodes
  sig_nodes <- V(citation_graph)[degree(citation_graph) > 2]
  g_sub <- induced_subgraph(citation_graph, sig_nodes)
  
  if (vcount(g_sub) == 0) {
    return(NULL)
  }
  
  # Color by citation type
  type_colors <- c(
    "lei_federal" = "#e74c3c",
    "decreto" = "#3498db",
    "portaria" = "#2ecc71",
    "resolucao" = "#f39c12",
    "artigo" = "#9b59b6",
    "constituicao" = "#34495e"
  )
  
  p <- ggraph(g_sub, layout = "fr") +
    geom_edge_link(alpha = 0.5, color = "gray70") +
    geom_node_point(aes(size = degree, color = type)) +
    geom_node_text(aes(label = label), repel = TRUE, size = 3) +
    scale_color_manual(values = type_colors) +
    scale_size_continuous(range = c(3, 10)) +
    theme_graph() +
    labs(title = "Legal Citation Network",
         subtitle = "Connections show co-citations in documents",
         color = "Citation Type",
         size = "Degree")
  
  return(p)
}

#' Create entity type distribution plot
#' @param entities Entity extraction results
#' @return ggplot object
plot_entity_distribution <- function(entities) {
  
  entity_counts <- entities %>%
    group_by(type) %>%
    summarise(count = n()) %>%
    arrange(desc(count))
  
  p <- ggplot(entity_counts, aes(x = reorder(type, count), y = count, fill = type)) +
    geom_bar(stat = "identity") +
    coord_flip() +
    theme_minimal() +
    theme(legend.position = "none") +
    labs(title = "Distribution of Entity Types",
         x = "Entity Type",
         y = "Count")
  
  return(p)
}

# ============================================================================
# 6. MAIN PIPELINE
# ============================================================================

#' Complete NER and relationship extraction pipeline
#' @param documents Data frame with document texts
#' @param method NER method to use
#' @return List with extraction results
run_ner_relationship_pipeline <- function(documents, method = "domain") {
  
  cat("\n=== NER AND RELATIONSHIP EXTRACTION PIPELINE ===\n")
  
  results <- list()
  
  # 1. Initialize models
  cat("\n1. Initializing NLP models...\n")
  models <- initialize_nlp_models()
  
  # 2. Extract entities
  cat("\n2. Extracting named entities...\n")
  
  if (method == "spacy" && models$spacy_available) {
    results$entities <- extract_entities_spacy(documents$conteudo)
  } else if (method == "udpipe" && !is.null(models$udpipe)) {
    results$entities <- extract_entities_udpipe(documents$conteudo, models$udpipe)
  } else {
    # Use domain-specific extraction
    results$entities <- extract_domain_entities(documents$conteudo)
  }
  
  cat(sprintf("  Extracted %d entities\n", nrow(results$entities)))
  
  # 3. Extract legal citations
  cat("\n3. Extracting legal citations...\n")
  results$citations <- extract_legal_citations(documents$conteudo)
  cat(sprintf("  Extracted %d citations\n", nrow(results$citations)))
  
  # 4. Extract relationships
  cat("\n4. Extracting entity relationships...\n")
  results$relationships <- extract_entity_relationships(
    results$entities, 
    documents$conteudo
  )
  cat(sprintf("  Found %d relationships\n", nrow(results$relationships)))
  
  # 5. Build networks
  cat("\n5. Building networks...\n")
  
  # Entity network
  if (nrow(results$relationships) > 0) {
    results$entity_network <- analyze_entity_network(results$relationships)
    cat(sprintf("  Entity network: %d nodes, %d edges\n", 
                results$entity_network$statistics$nodes,
                results$entity_network$statistics$edges))
  }
  
  # Citation network
  if (nrow(results$citations) > 0) {
    results$citation_graph <- build_citation_network(
      results$citations, 
      documents
    )
    cat(sprintf("  Citation network: %d nodes, %d edges\n",
                vcount(results$citation_graph),
                ecount(results$citation_graph)))
  }
  
  # 6. Identify key patterns
  cat("\n6. Identifying key patterns...\n")
  
  # Entity clusters
  if (!is.null(results$entity_network)) {
    results$entity_clusters <- identify_entity_clusters(results$entity_network)
    cat(sprintf("  Found %d significant entity clusters\n", nrow(results$entity_clusters)))
  }
  
  # Most cited laws
  results$top_citations <- results$citations %>%
    filter(!is.na(number)) %>%
    group_by(type, number, year) %>%
    summarise(
      frequency = n(),
      documents = n_distinct(doc_id)
    ) %>%
    arrange(desc(frequency)) %>%
    head(20)
  
  # 7. Generate visualizations
  cat("\n7. Creating visualizations...\n")
  results$plots <- list()
  
  results$plots$entity_dist <- plot_entity_distribution(results$entities)
  
  if (!is.null(results$entity_network)) {
    results$plots$entity_network <- plot_entity_network(results$entity_network)
  }
  
  if (!is.null(results$citation_graph) && vcount(results$citation_graph) > 0) {
    results$plots$citation_network <- plot_citation_network(results$citation_graph)
  }
  
  # 8. Summary statistics
  results$summary <- list(
    total_entities = nrow(results$entities),
    unique_entities = n_distinct(results$entities$text),
    entity_types = table(results$entities$type),
    total_citations = nrow(results$citations),
    unique_citations = n_distinct(paste(results$citations$type, 
                                       results$citations$number)),
    total_relationships = nrow(results$relationships),
    network_density = ifelse(!is.null(results$entity_network),
                           results$entity_network$statistics$density, NA)
  )
  
  cat("\nNER and relationship extraction complete!\n")
  
  return(results)
}

# ============================================================================
# 7. EXPORT FUNCTIONS
# ============================================================================

#' Save NER and relationship results
#' @param results Pipeline results
#' @param output_dir Output directory
save_ner_results <- function(results, output_dir = "ner_relationship_output") {
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Save entity data
  write.csv(results$entities, 
            file.path(output_dir, "extracted_entities.csv"), 
            row.names = FALSE)
  
  write.csv(results$citations, 
            file.path(output_dir, "legal_citations.csv"), 
            row.names = FALSE)
  
  if (!is.null(results$relationships)) {
    write.csv(results$relationships, 
              file.path(output_dir, "entity_relationships.csv"), 
              row.names = FALSE)
  }
  
  # Save network data
  if (!is.null(results$entity_network)) {
    write.csv(results$entity_network$node_metrics, 
              file.path(output_dir, "entity_network_metrics.csv"), 
              row.names = FALSE)
    
    write.csv(results$entity_clusters, 
              file.path(output_dir, "entity_clusters.csv"), 
              row.names = FALSE)
  }
  
  # Save top citations
  write.csv(results$top_citations, 
            file.path(output_dir, "top_citations.csv"), 
            row.names = FALSE)
  
  # Save plots
  for (plot_name in names(results$plots)) {
    if (!is.null(results$plots[[plot_name]])) {
      ggsave(
        file.path(output_dir, paste0(plot_name, ".png")),
        results$plots[[plot_name]],
        width = 12,
        height = 8
      )
    }
  }
  
  # Save graphs for later use
  if (!is.null(results$citation_graph)) {
    saveRDS(results$citation_graph, 
            file.path(output_dir, "citation_graph.rds"))
  }
  
  if (!is.null(results$entity_network)) {
    saveRDS(results$entity_network$graph, 
            file.path(output_dir, "entity_graph.rds"))
  }
  
  # Save summary
  saveRDS(results$summary, file.path(output_dir, "ner_summary.rds"))
  
  cat(sprintf("\nResults saved to %s/\n", output_dir))
}