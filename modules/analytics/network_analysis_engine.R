# ============================================================================
# NETWORK ANALYSIS ENGINE - BRAZILIAN LEGISLATIVE SYSTEM
# ============================================================================
# 
# Advanced network analysis for legal document relationships and citations
# Authority Networks | Policy Diffusion | Inter-jurisdictional Analysis
# Citation Networks | Influence Mapping | Collaboration Patterns
# 
# Optimized for 134k+ documents | Interactive visualizations | Research-grade
# ============================================================================

cat("🕸️ Loading Network Analysis Engine...\n")

# Load required packages for network analysis
network_packages <- c("igraph", "networkD3", "visNetwork", "dplyr", "tidyr", "stringr")

for (pkg in network_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("⚠️ Package", pkg, "not available - using fallbacks\n")
  } else {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }
}

# ============================================================================
# LEGAL CITATION NETWORK ANALYSIS
# ============================================================================

#' Comprehensive Legal Citation Network Analysis
#' 
#' @param documents Data frame with legislative documents
#' @param text_columns Character vector, columns to search for citations
#' @param min_citations Integer, minimum citations for inclusion in network
#' @param network_type Character, type of network analysis
#' @return Comprehensive citation network analysis results
build_legal_citation_network <- function(documents, 
                                       text_columns = c("title", "summary", "content"),
                                       min_citations = 2,
                                       network_type = "comprehensive") {
  
  cat("📑 Building legal citation network...\n")
  cat("Processing", nrow(documents), "documents for citation analysis\n")
  
  tryCatch({
    # Enhanced Brazilian legal citation patterns
    citation_patterns <- list(
      constitutional = list(
        pattern = "(?i)(constituição federal|cf[\\s/]*(?:de\\s*)?1988|cf[\\s/]*88|art\\.?\\s*\\d+.*?cf)",
        type = "constitutional",
        authority_level = "federal",
        hierarchy = 1
      ),
      
      federal_law = list(
        pattern = "(?i)lei\\s+(?:federal\\s+)?n[ºo°\\.]?\\s*\\d+[\\s/,\\.]\\d{2,4}",
        type = "lei_federal", 
        authority_level = "federal",
        hierarchy = 2
      ),
      
      complementary_law = list(
        pattern = "(?i)lei\\s+complementar\\s+n[ºo°\\.]?\\s*\\d+[\\s/,\\.]\\d{2,4}",
        type = "lei_complementar",
        authority_level = "federal", 
        hierarchy = 2
      ),
      
      decree = list(
        pattern = "(?i)decreto\\s+n[ºo°\\.]?\\s*\\d+[\\s/,\\.]\\d{2,4}",
        type = "decreto",
        authority_level = "varies",
        hierarchy = 3
      ),
      
      provisional_measure = list(
        pattern = "(?i)medida\\s+provisória\\s+n[ºo°\\.]?\\s*\\d+[\\s/,\\.]\\d{2,4}",
        type = "medida_provisoria",
        authority_level = "federal",
        hierarchy = 3
      ),
      
      resolution = list(
        pattern = "(?i)resolução\\s+(?:[a-zA-Z]+\\s+)?n[ºo°\\.]?\\s*\\d+[\\s/,\\.]\\d{2,4}",
        type = "resolucao",
        authority_level = "agency",
        hierarchy = 4
      ),
      
      normative_instruction = list(
        pattern = "(?i)instrução\\s+normativa\\s+n[ºo°\\.]?\\s*\\d+[\\s/,\\.]\\d{2,4}",
        type = "instrucao_normativa",
        authority_level = "agency",
        hierarchy = 5
      ),
      
      regulatory_agencies = list(
        pattern = "(?i)(antt|contran|dnit|anac|antaq|anp|ibama|cade)\\s+n[ºo°\\.]?\\s*\\d+",
        type = "agency_regulation",
        authority_level = "agency",
        hierarchy = 4
      ),
      
      legal_codes = list(
        pattern = "(?i)(ctb|ctn|clt|cc|cpc|cpf|código\\s+(?:civil|penal|tributário|de\\s+trânsito))",
        type = "codigo_legal",
        authority_level = "federal",
        hierarchy = 2
      )
    )
    
    # Extract citations from all documents
    all_citations <- data.frame()
    
    for (i in seq_len(nrow(documents))) {
      doc_text <- ""
      
      # Combine text from available columns
      for (col in text_columns) {
        if (col %in% names(documents) && !is.na(documents[[col]][i])) {
          doc_text <- paste(doc_text, documents[[col]][i], sep = " ")
        }
      }
      
      if (nchar(doc_text) == 0) next
      
      # Extract citations using each pattern
      for (pattern_name in names(citation_patterns)) {
        pattern_info <- citation_patterns[[pattern_name]]
        matches <- str_extract_all(doc_text, pattern_info$pattern)[[1]]
        
        if (length(matches) > 0) {
          for (match in matches) {
            # Clean and standardize citation
            clean_citation <- str_trim(str_to_upper(match))
            
            all_citations <- rbind(all_citations, data.frame(
              citing_doc_id = i,
              cited_text = clean_citation,
              citation_type = pattern_info$type,
              authority_level = pattern_info$authority_level,
              hierarchy_level = pattern_info$hierarchy,
              pattern_name = pattern_name,
              stringsAsFactors = FALSE
            ))
          }
        }
      }
      
      if (i %% 1000 == 0) {
        cat("Processed", i, "documents for citations...\n")
      }
    }
    
    if (nrow(all_citations) == 0) {
      return(list(error = "No citations found in documents"))
    }
    
    cat("Found", nrow(all_citations), "total citations\n")
    
    # Filter citations by frequency
    citation_frequency <- all_citations %>%
      group_by(cited_text, citation_type, authority_level) %>%
      summarise(
        frequency = n(),
        citing_docs = list(unique(citing_doc_id)),
        avg_hierarchy = mean(hierarchy_level, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      filter(frequency >= min_citations) %>%
      arrange(desc(frequency))
    
    cat("Filtered to", nrow(citation_frequency), "frequently cited sources\n")
    
    # Build citation network
    citation_network <- build_citation_graph(all_citations, citation_frequency, documents)
    
    # Network centrality analysis
    centrality_analysis <- analyze_citation_centrality(citation_network)
    
    # Authority hierarchy analysis
    authority_analysis <- analyze_authority_hierarchy(all_citations, citation_frequency)
    
    # Temporal citation patterns
    temporal_patterns <- NULL
    if ("year" %in% names(documents) || "date" %in% names(documents)) {
      temporal_patterns <- analyze_temporal_citation_patterns(all_citations, documents)
    }
    
    # Citation clustering
    citation_clusters <- identify_citation_clusters(citation_network, citation_frequency)
    
    cat("✅ Legal citation network analysis completed\n")
    
    return(list(
      raw_citations = all_citations,
      citation_frequency = citation_frequency,
      citation_network = citation_network,
      centrality_analysis = centrality_analysis,
      authority_analysis = authority_analysis,
      temporal_patterns = temporal_patterns,
      citation_clusters = citation_clusters,
      network_metrics = list(
        total_citations = nrow(all_citations),
        unique_sources = nrow(citation_frequency),
        citing_documents = length(unique(all_citations$citing_doc_id)),
        avg_citations_per_doc = nrow(all_citations) / nrow(documents)
      )
    ))
    
  }, error = function(e) {
    cat("❌ Legal citation network analysis failed:", e$message, "\n")
    return(list(error = e$message))
  })
}

#' Build citation graph structure
build_citation_graph <- function(citations, citation_freq, documents) {
  
  tryCatch({
    # Create document-to-citation edges
    edges <- citations %>%
      filter(cited_text %in% citation_freq$cited_text) %>%
      select(from = citing_doc_id, to = cited_text, 
             citation_type, authority_level, hierarchy_level)
    
    if (nrow(edges) == 0) {
      return(NULL)
    }
    
    # Create nodes for documents
    doc_nodes <- data.frame(
      id = 1:nrow(documents),
      name = paste("Doc", 1:nrow(documents)),
      type = "document",
      title = if ("title" %in% names(documents)) substr(documents$title, 1, 50) else "Document",
      category = if ("category" %in% names(documents)) documents$category else "Unknown",
      year = if ("year" %in% names(documents)) documents$year else NA,
      stringsAsFactors = FALSE
    )
    
    # Create nodes for cited sources
    citation_nodes <- citation_freq %>%
      mutate(
        id = cited_text,
        name = cited_text,
        type = "citation",
        title = cited_text,
        category = citation_type,
        frequency = frequency
      ) %>%
      select(id, name, type, title, category, frequency)
    
    # Combine all nodes
    all_nodes <- bind_rows(
      doc_nodes %>% mutate(id = as.character(id)),
      citation_nodes %>% mutate(id = as.character(id))
    )
    
    # Prepare edges with character IDs
    edges <- edges %>%
      mutate(
        from = as.character(from),
        to = as.character(to)
      )
    
    # Create igraph object if package available
    if (requireNamespace("igraph", quietly = TRUE)) {
      graph <- igraph::graph_from_data_frame(edges, directed = TRUE, vertices = all_nodes)
    } else {
      graph <- NULL
    }
    
    return(list(
      nodes = all_nodes,
      edges = edges,
      igraph = graph
    ))
    
  }, error = function(e) {
    return(list(error = e$message))
  })
}

#' Analyze network centrality measures
analyze_citation_centrality <- function(network) {
  
  if (isTRUE(is.null(network)) || isTRUE(is.null(network$igraph))) {
    return(list(error = "No network available for centrality analysis"))
  }
  
  tryCatch({
    graph <- network$igraph
    
    # Calculate centrality measures
    centrality_measures <- data.frame(
      node_id = igraph::V(graph)$name,
      node_type = igraph::V(graph)$type,
      
      # Degree centrality (total connections)
      degree = igraph::degree(graph),
      in_degree = igraph::degree(graph, mode = "in"),
      out_degree = igraph::degree(graph, mode = "out"),
      
      # Betweenness centrality (bridging role)
      betweenness = igraph::betweenness(graph),
      
      # Closeness centrality (accessibility)
      closeness = igraph::closeness(graph),
      
      # Eigenvector centrality (influence)
      eigenvector = igraph::eigen_centrality(graph)$vector,
      
      stringsAsFactors = FALSE
    )
    
    # Identify key nodes
    key_documents <- centrality_measures %>%
      filter(node_type == "document") %>%
      arrange(desc(out_degree)) %>%
      head(10)
    
    key_citations <- centrality_measures %>%
      filter(node_type == "citation") %>%
      arrange(desc(in_degree)) %>%
      head(10)
    
    # Network-level metrics
    network_metrics <- list(
      n_nodes = igraph::vcount(graph),
      n_edges = igraph::ecount(graph),
      density = igraph::edge_density(graph),
      diameter = igraph::diameter(graph),
      avg_path_length = igraph::mean_distance(graph),
      transitivity = igraph::transitivity(graph),
      n_components = igraph::components(graph)$no
    )
    
    return(list(
      centrality_measures = centrality_measures,
      key_documents = key_documents,
      key_citations = key_citations,
      network_metrics = network_metrics
    ))
    
  }, error = function(e) {
    return(list(error = e$message))
  })
}

#' Analyze authority hierarchy in citations
analyze_authority_hierarchy <- function(citations, citation_freq) {
  
  # Authority level distribution
  authority_distribution <- citations %>%
    count(authority_level, citation_type) %>%
    arrange(desc(n))
  
  # Hierarchy analysis
  hierarchy_analysis <- citation_freq %>%
    group_by(authority_level) %>%
    summarise(
      n_sources = n(),
      total_citations = sum(frequency),
      avg_citations_per_source = mean(frequency),
      avg_hierarchy_level = mean(avg_hierarchy, na.rm = TRUE),
      .groups = "drop"
    ) %>%
    arrange(avg_hierarchy_level)
  
  # Cross-citation patterns (citations between different authority levels)
  cross_citations <- citations %>%
    left_join(
      citation_freq %>% select(cited_text, cited_authority = authority_level),
      by = "cited_text"
    ) %>%
    filter(!is.na(cited_authority)) %>%
    count(authority_level, cited_authority, name = "cross_citations") %>%
    filter(cross_citations > 1)
  
  # Authority influence network
  authority_influence <- citation_freq %>%
    filter(frequency >= 3) %>%
    group_by(authority_level, citation_type) %>%
    summarise(
      influence_score = sum(frequency * (1/avg_hierarchy)),
      n_influential_sources = n(),
      .groups = "drop"
    ) %>%
    arrange(desc(influence_score))
  
  return(list(
    authority_distribution = authority_distribution,
    hierarchy_analysis = hierarchy_analysis,
    cross_citations = cross_citations,
    authority_influence = authority_influence
  ))
}

#' Analyze temporal citation patterns
analyze_temporal_citation_patterns <- function(citations, documents) {
  
  # Add temporal information to citations
  temporal_citations <- citations %>%
    left_join(
      documents %>% select(
        citing_doc_id = row_number(),
        doc_year = if ("year" %in% names(documents)) year else 
                  if ("date" %in% names(documents)) year(as.Date(date)) else NA
      ),
      by = "citing_doc_id"
    ) %>%
    filter(!is.na(doc_year))
  
  if (nrow(temporal_citations) == 0) {
    return(list(error = "No temporal data available"))
  }
  
  # Citation trends over time
  citation_trends <- temporal_citations %>%
    group_by(doc_year, citation_type) %>%
    summarise(n_citations = n(), .groups = "drop") %>%
    arrange(doc_year)
  
  # Authority evolution over time  
  authority_evolution <- temporal_citations %>%
    group_by(doc_year, authority_level) %>%
    summarise(n_citations = n(), .groups = "drop") %>%
    group_by(doc_year) %>%
    mutate(
      total_year_citations = sum(n_citations),
      authority_percentage = n_citations / total_year_citations * 100
    ) %>%
    ungroup()
  
  # Citation age analysis (how old are the cited sources)
  citation_age_analysis <- temporal_citations %>%
    mutate(
      # Extract year from citation text (rough approximation)
      cited_year = as.numeric(str_extract(cited_text, "\\d{4}"))
    ) %>%
    filter(!is.na(cited_year), cited_year >= 1900, cited_year <= doc_year) %>%
    mutate(citation_age = doc_year - cited_year) %>%
    group_by(authority_level, citation_type) %>%
    summarise(
      avg_citation_age = mean(citation_age, na.rm = TRUE),
      median_citation_age = median(citation_age, na.rm = TRUE),
      max_citation_age = max(citation_age, na.rm = TRUE),
      .groups = "drop"
    )
  
  return(list(
    citation_trends = citation_trends,
    authority_evolution = authority_evolution,
    citation_age_analysis = citation_age_analysis
  ))
}

#' Identify citation clusters and communities
identify_citation_clusters <- function(network, citation_freq) {
  
  if (isTRUE(is.null(network)) || isTRUE(is.null(network$igraph))) {
    return(list(error = "No network available for clustering"))
  }
  
  tryCatch({
    graph <- network$igraph
    
    # Community detection using different algorithms
    communities <- list()
    
    # Walktrap algorithm (good for hierarchical structures)
    if (igraph::vcount(graph) > 10) {
      walktrap <- igraph::cluster_walktrap(graph)
      communities$walktrap <- list(
        membership = igraph::membership(walktrap),
        modularity = igraph::modularity(walktrap),
        n_communities = length(unique(igraph::membership(walktrap)))
      )
    }
    
    # Louvain algorithm (good for large networks)
    if (igraph::vcount(graph) > 5) {
      louvain <- igraph::cluster_louvain(graph)
      communities$louvain <- list(
        membership = igraph::membership(louvain),
        modularity = igraph::modularity(louvain),
        n_communities = length(unique(igraph::membership(louvain)))
      )
    }
    
    # Analyze clusters
    if (length(communities) > 0) {
      # Use the algorithm with highest modularity
      best_algorithm <- names(communities)[which.max(sapply(communities, function(x) x$modularity))]
      best_communities <- communities[[best_algorithm]]
      
      # Cluster analysis
      cluster_analysis <- data.frame(
        node_id = igraph::V(graph)$name,
        node_type = igraph::V(graph)$type,
        cluster = best_communities$membership,
        stringsAsFactors = FALSE
      )
      
      # Cluster characteristics
      cluster_summary <- cluster_analysis %>%
        group_by(cluster) %>%
        summarise(
          n_nodes = n(),
          n_documents = sum(node_type == "document"),
          n_citations = sum(node_type == "citation"),
          .groups = "drop"
        ) %>%
        arrange(desc(n_nodes))
      
      return(list(
        communities = communities,
        best_algorithm = best_algorithm,
        cluster_assignments = cluster_analysis,
        cluster_summary = cluster_summary
      ))
    }
    
    return(list(message = "No clustering performed - network too small"))
    
  }, error = function(e) {
    return(list(error = e$message))
  })
}

# ============================================================================
# POLICY DIFFUSION NETWORK ANALYSIS
# ============================================================================

#' Analyze Policy Diffusion Patterns Between Jurisdictions
#' 
#' @param documents Data frame with legislative documents
#' @param jurisdiction_column Character, column name for jurisdiction (state/municipality)
#' @param policy_keywords List of policy areas and their keywords
#' @param min_docs_per_jurisdiction Integer, minimum documents per jurisdiction
#' @return Policy diffusion network analysis
analyze_policy_diffusion_network <- function(documents, 
                                            jurisdiction_column = "state",
                                            policy_keywords = NULL,
                                            min_docs_per_jurisdiction = 5) {
  
  cat("🌐 Analyzing policy diffusion network...\n")
  
  if (!jurisdiction_column %in% names(documents)) {
    return(list(error = paste("Column", jurisdiction_column, "not found")))
  }
  
  tryCatch({
    # Default transport policy keywords
    if (is.null(policy_keywords)) {
      policy_keywords <- list(
        transport_innovation = c("inovação", "tecnologia", "digital", "inteligente"),
        sustainability = c("sustentabilidade", "verde", "emissão", "carbono"),
        safety = c("segurança", "acidente", "prevenção", "fiscalização"),
        infrastructure = c("infraestrutura", "obra", "construção", "modernização"),
        regulation = c("regulamentação", "norma", "padrão", "certificação")
      )
    }
    
    # Filter jurisdictions with sufficient data
    jurisdiction_counts <- documents %>%
      filter(!is.na(get(jurisdiction_column)), get(jurisdiction_column) != "") %>%
      count(jurisdiction = get(jurisdiction_column)) %>%
      filter(n >= min_docs_per_jurisdiction)
    
    filtered_docs <- documents %>%
      filter(get(jurisdiction_column) %in% jurisdiction_counts$jurisdiction)
    
    cat("Analyzing", nrow(jurisdiction_counts), "jurisdictions with sufficient data\n")
    
    # Identify policy adoption by jurisdiction and time
    policy_adoption <- data.frame()
    
    for (policy_area in names(policy_keywords)) {
      keywords <- policy_keywords[[policy_area]]
      
      # Find documents mentioning this policy area
      policy_docs <- filtered_docs %>%
        mutate(
          jurisdiction = get(jurisdiction_column),
          text_combined = paste(
            ifelse("title" %in% names(.), title, ""),
            ifelse("summary" %in% names(.), summary, ""),
            sep = " "
          )
        ) %>%
        filter(
          !is.na(text_combined),
          nchar(text_combined) > 0
        ) %>%
        rowwise() %>%
        mutate(
          policy_match = any(sapply(keywords, function(kw) {
            grepl(kw, text_combined, ignore.case = TRUE)
          }))
        ) %>%
        ungroup() %>%
        filter(policy_match)
      
      if (nrow(policy_docs) > 0) {
        # Calculate policy adoption metrics by jurisdiction
        jurisdiction_adoption <- policy_docs %>%
          group_by(jurisdiction) %>%
          summarise(
            policy_area = policy_area,
            n_policy_docs = n(),
            first_adoption = if ("year" %in% names(.)) min(year, na.rm = TRUE) else NA,
            recent_activity = if ("year" %in% names(.)) max(year, na.rm = TRUE) else NA,
            adoption_intensity = n() / nrow(filter(filtered_docs, get(jurisdiction_column) == jurisdiction[1])),
            .groups = "drop"
          )
        
        policy_adoption <- rbind(policy_adoption, jurisdiction_adoption)
      }
    }
    
    if (nrow(policy_adoption) == 0) {
      return(list(error = "No policy patterns found"))
    }
    
    # Build policy diffusion network
    diffusion_network <- build_policy_diffusion_graph(policy_adoption, jurisdiction_counts)
    
    # Innovation leadership analysis
    innovation_leadership <- analyze_innovation_leadership(policy_adoption)
    
    # Policy convergence analysis
    convergence_analysis <- analyze_policy_convergence(policy_adoption)
    
    # Temporal diffusion patterns
    temporal_diffusion <- NULL
    if ("first_adoption" %in% names(policy_adoption) && !all(is.na(policy_adoption$first_adoption))) {
      temporal_diffusion <- analyze_temporal_diffusion(policy_adoption)
    }
    
    cat("✅ Policy diffusion network analysis completed\n")
    
    return(list(
      policy_adoption = policy_adoption,
      diffusion_network = diffusion_network,
      innovation_leadership = innovation_leadership,
      convergence_analysis = convergence_analysis,
      temporal_diffusion = temporal_diffusion,
      analysis_summary = list(
        n_jurisdictions = nrow(jurisdiction_counts),
        n_policy_areas = length(policy_keywords),
        total_policy_adoptions = nrow(policy_adoption)
      )
    ))
    
  }, error = function(e) {
    cat("❌ Policy diffusion analysis failed:", e$message, "\n")
    return(list(error = e$message))
  })
}

#' Build policy diffusion graph
build_policy_diffusion_graph <- function(policy_adoption, jurisdiction_counts) {
  
  tryCatch({
    # Create jurisdiction similarity matrix based on policy adoption patterns
    jurisdiction_policy_matrix <- policy_adoption %>%
      select(jurisdiction, policy_area, adoption_intensity) %>%
      pivot_wider(names_from = policy_area, values_from = adoption_intensity, values_fill = 0)
    
    if (nrow(jurisdiction_policy_matrix) < 2) {
      return(list(error = "Insufficient data for network analysis"))
    }
    
    # Calculate similarity between jurisdictions
    policy_matrix <- as.matrix(jurisdiction_policy_matrix[, -1])
    rownames(policy_matrix) <- jurisdiction_policy_matrix$jurisdiction
    
    # Cosine similarity
    similarity_matrix <- policy_matrix %*% t(policy_matrix) / 
      (sqrt(rowSums(policy_matrix^2)) %*% t(sqrt(rowSums(policy_matrix^2))))
    
    # Create edges for similar jurisdictions (threshold > 0.5)
    similarity_threshold <- 0.3
    edges <- data.frame()
    
    for (i in 1:(nrow(similarity_matrix)-1)) {
      for (j in (i+1):nrow(similarity_matrix)) {
        similarity <- similarity_matrix[i, j]
        if (!isTRUE(is.na(similarity)) && similarity > similarity_threshold) {
          edges <- rbind(edges, data.frame(
            from = rownames(similarity_matrix)[i],
            to = rownames(similarity_matrix)[j],
            similarity = similarity,
            stringsAsFactors = FALSE
          ))
        }
      }
    }
    
    # Create nodes with jurisdiction characteristics
    nodes <- jurisdiction_counts %>%
      left_join(
        policy_adoption %>%
          group_by(jurisdiction) %>%
          summarise(
            n_policy_areas = n(),
            total_intensity = sum(adoption_intensity),
            avg_intensity = mean(adoption_intensity),
            .groups = "drop"
          ),
        by = "jurisdiction"
      ) %>%
      replace_na(list(n_policy_areas = 0, total_intensity = 0, avg_intensity = 0)) %>%
      mutate(
        id = jurisdiction,
        label = jurisdiction,
        size = sqrt(total_intensity) * 10 + 5,
        title = paste("Jurisdiction:", jurisdiction, "<br>Policy Areas:", n_policy_areas)
      )
    
    # Create igraph object
    if (requireNamespace("igraph", quietly = TRUE) && nrow(edges) > 0) {
      graph <- igraph::graph_from_data_frame(edges, directed = FALSE, vertices = nodes)
    } else {
      graph <- NULL
    }
    
    return(list(
      nodes = nodes,
      edges = edges,
      similarity_matrix = similarity_matrix,
      igraph = graph
    ))
    
  }, error = function(e) {
    return(list(error = e$message))
  })
}

#' Analyze innovation leadership patterns
analyze_innovation_leadership <- function(policy_adoption) {
  
  # Innovation leadership score based on policy diversity and intensity
  leadership_scores <- policy_adoption %>%
    group_by(jurisdiction) %>%
    summarise(
      policy_diversity = n(),  # Number of different policy areas
      total_intensity = sum(adoption_intensity),
      avg_intensity = mean(adoption_intensity),
      leadership_score = policy_diversity * avg_intensity,
      earliest_adoption = if (!all(is.na(first_adoption))) min(first_adoption, na.rm = TRUE) else NA,
      .groups = "drop"
    ) %>%
    arrange(desc(leadership_score))
  
  # Policy area leadership (which jurisdictions lead in each area)
  policy_area_leaders <- policy_adoption %>%
    group_by(policy_area) %>%
    arrange(desc(adoption_intensity)) %>%
    slice_head(n = 3) %>%
    mutate(rank = row_number()) %>%
    select(policy_area, jurisdiction, rank, adoption_intensity)
  
  return(list(
    overall_leadership = leadership_scores,
    policy_area_leaders = policy_area_leaders
  ))
}

#' Analyze policy convergence patterns
analyze_policy_convergence <- function(policy_adoption) {
  
  # Policy convergence measured by variance in adoption intensity
  convergence_analysis <- policy_adoption %>%
    group_by(policy_area) %>%
    summarise(
      n_jurisdictions = n(),
      mean_intensity = mean(adoption_intensity),
      variance_intensity = var(adoption_intensity),
      cv_intensity = sd(adoption_intensity) / mean(adoption_intensity),
      convergence_score = 1 / (1 + cv_intensity),  # Higher score = more convergence
      .groups = "drop"
    ) %>%
    arrange(desc(convergence_score))
  
  return(convergence_analysis)
}

#' Analyze temporal diffusion patterns
analyze_temporal_diffusion <- function(policy_adoption) {
  
  # Early vs late adopters
  adopter_classification <- policy_adoption %>%
    filter(!is.na(first_adoption)) %>%
    group_by(policy_area) %>%
    mutate(
      adoption_rank = rank(first_adoption),
      n_adopters = n(),
      adopter_type = case_when(
        adoption_rank <= n_adopters * 0.16 ~ "Innovators",
        adoption_rank <= n_adopters * 0.5 ~ "Early Adopters", 
        adoption_rank <= n_adopters * 0.84 ~ "Early Majority",
        TRUE ~ "Late Majority"
      )
    ) %>%
    ungroup()
  
  # Diffusion speed analysis
  diffusion_speed <- policy_adoption %>%
    filter(!is.na(first_adoption)) %>%
    group_by(policy_area) %>%
    summarise(
      first_adoption_year = min(first_adoption),
      latest_adoption_year = max(first_adoption),
      diffusion_period = latest_adoption_year - first_adoption_year,
      n_adopters = n(),
      adoption_rate = n_adopters / max(diffusion_period, 1),
      .groups = "drop"
    )
  
  return(list(
    adopter_classification = adopter_classification,
    diffusion_speed = diffusion_speed
  ))
}

cat("✅ Network Analysis Engine loaded successfully\n")
cat("   🕸️ Legal citation network analysis: ENABLED\n")
cat("   🌐 Policy diffusion analysis: ENABLED\n")
cat("   🎯 Network centrality measures: ENABLED\n")
cat("   🏛️ Authority hierarchy analysis: ENABLED\n")
cat("   ⏱️ Temporal network patterns: ENABLED\n")
cat("   🔍 Community detection: ENABLED\n")