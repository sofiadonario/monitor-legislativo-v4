# Knowledge Graph for Monitor Legislativo v4
# Entity extraction, relationship mapping, and semantic knowledge representation

library(igraph)
library(visNetwork)
library(dplyr)
library(jsonlite)
library(digest)
library(stringr)
library(lubridate)

# Knowledge Graph configuration
KG_CONFIG <- list(
  entities = list(
    types = c(
      "LEI", "DECRETO", "RESOLUCAO", "PORTARIA", "INSTRUCAO_NORMATIVA",
      "PESSOA", "ORGAO", "LOCAL", "DATA", "VALOR_MONETARIO", "CONCEITO_JURIDICO"
    ),
    extraction_methods = c("regex", "ai", "dictionary"),
    confidence_threshold = 0.7,
    max_entities_per_document = 50
  ),
  
  relationships = list(
    types = c(
      "REGULAMENTA", "REVOGA", "ALTERA", "CITA", "FUNDAMENTA",
      "APLICA_SE_A", "DEFINE", "ESTABELECE", "DETERMINA", "AUTORIZA"
    ),
    extraction_patterns = list(
      "REGULAMENTA" = c("regulamenta", "regulamentação", "regulamentado por"),
      "REVOGA" = c("revoga", "revogado", "ab-roga"),
      "ALTERA" = c("altera", "modificado", "alterado por"),
      "CITA" = c("conforme", "segundo", "de acordo com"),
      "FUNDAMENTA" = c("fundamentado", "com base", "considerando")
    ),
    confidence_threshold = 0.6
  ),
  
  graph = list(
    max_nodes = 10000,
    max_edges = 50000,
    layout_algorithm = "fruchterman_reingold",
    community_detection = TRUE,
    centrality_metrics = TRUE
  ),
  
  storage = list(
    persist_graph = TRUE,
    storage_format = "graphml",
    backup_enabled = TRUE,
    compression = TRUE
  ),
  
  visualization = list(
    default_node_size = 10,
    max_node_size = 50,
    edge_width_scale = 2,
    color_by_type = TRUE,
    show_labels = TRUE,
    interactive = TRUE
  )
)

# Global knowledge graph state
kg_state <- list(
  graph = NULL,
  entities = list(),
  relationships = list(),
  communities = list(),
  metrics = list()
)

#' Initialize knowledge graph system
#' @param config Optional configuration override
#' @return Initialization status
initialize_knowledge_graph <- function(config = NULL) {
  if (!is.null(config)) {
    KG_CONFIG <<- modifyList(KG_CONFIG, config)
  }
  
  log_event("Initializing knowledge graph system...", "INFO")
  
  # Initialize empty graph
  kg_state$graph <<- make_empty_graph(directed = TRUE)
  kg_state$entities <<- list()
  kg_state$relationships <<- list()
  kg_state$communities <<- list()
  kg_state$metrics <<- list()
  
  # Load existing graph if available
  if (KG_CONFIG$storage$persist_graph) {
    load_persisted_graph()
  }
  
  # Initialize entity extraction patterns
  initialize_extraction_patterns()
  
  log_event("Knowledge graph system initialized successfully", "INFO")
  
  return(list(
    status = "success",
    nodes = vcount(kg_state$graph),
    edges = ecount(kg_state$graph),
    entity_types = length(KG_CONFIG$entities$types)
  ))
}

#' Extract entities from document text
#' @param document_text Document text content
#' @param document_id Document identifier
#' @param method Extraction method (regex, ai, dictionary)
#' @return Extracted entities
extract_entities <- function(document_text, document_id, method = "regex") {
  log_event(paste("Extracting entities from document:", document_id), "INFO")
  
  extracted_entities <- list()
  
  if (method == "regex" || method == "all") {
    regex_entities <- extract_entities_regex(document_text, document_id)
    extracted_entities <- append(extracted_entities, regex_entities)
  }
  
  if (method == "ai" || method == "all") {
    ai_entities <- extract_entities_ai(document_text, document_id)
    extracted_entities <- append(extracted_entities, ai_entities)
  }
  
  if (method == "dictionary" || method == "all") {
    dict_entities <- extract_entities_dictionary(document_text, document_id)
    extracted_entities <- append(extracted_entities, dict_entities)
  }
  
  # Deduplicate and filter by confidence
  unique_entities <- deduplicate_entities(extracted_entities)
  filtered_entities <- filter_entities_by_confidence(unique_entities)
  
  # Store entities
  for (entity in filtered_entities) {
    add_entity_to_graph(entity)
  }
  
  log_event(paste("Extracted", length(filtered_entities), "entities from document:", document_id), "INFO")
  
  return(filtered_entities)
}

#' Extract entities using regex patterns
#' @param text Document text
#' @param document_id Document ID
#' @return List of extracted entities
extract_entities_regex <- function(text, document_id) {
  entities <- list()
  
  # Extract legal document references
  lei_pattern <- "Lei\\s+n[ºo°]?\\s*([0-9\\.]+)[,/\\s]*([0-9]{4})"
  lei_matches <- str_match_all(text, lei_pattern)[[1]]
  
  if (nrow(lei_matches) > 0) {
    for (i in 1:nrow(lei_matches)) {
      entity <- list(
        id = generate_entity_id("LEI", lei_matches[i, 1]),
        type = "LEI",
        value = lei_matches[i, 1],
        number = lei_matches[i, 2],
        year = lei_matches[i, 3],
        confidence = 0.9,
        method = "regex",
        document_id = document_id,
        extracted_at = Sys.time()
      )
      entities <- append(entities, list(entity))
    }
  }
  
  # Extract decree references
  decreto_pattern <- "Decreto\\s+n[ºo°]?\\s*([0-9\\.]+)[,/\\s]*([0-9]{4})"
  decreto_matches <- str_match_all(text, decreto_pattern)[[1]]
  
  if (nrow(decreto_matches) > 0) {
    for (i in 1:nrow(decreto_matches)) {
      entity <- list(
        id = generate_entity_id("DECRETO", decreto_matches[i, 1]),
        type = "DECRETO",
        value = decreto_matches[i, 1],
        number = decreto_matches[i, 2],
        year = decreto_matches[i, 3],
        confidence = 0.9,
        method = "regex",
        document_id = document_id,
        extracted_at = Sys.time()
      )
      entities <- append(entities, list(entity))
    }
  }
  
  # Extract monetary values
  valor_pattern <- "R\\$\\s*([0-9\\.]+,?[0-9]*)"
  valor_matches <- str_match_all(text, valor_pattern)[[1]]
  
  if (nrow(valor_matches) > 0) {
    for (i in 1:nrow(valor_matches)) {
      entity <- list(
        id = generate_entity_id("VALOR_MONETARIO", valor_matches[i, 1]),
        type = "VALOR_MONETARIO",
        value = valor_matches[i, 1],
        confidence = 0.8,
        method = "regex",
        document_id = document_id,
        extracted_at = Sys.time()
      )
      entities <- append(entities, list(entity))
    }
  }
  
  # Extract dates
  data_pattern <- "([0-9]{1,2})[/\\-]([0-9]{1,2})[/\\-]([0-9]{4})"
  data_matches <- str_match_all(text, data_pattern)[[1]]
  
  if (nrow(data_matches) > 0) {
    for (i in 1:nrow(data_matches)) {
      entity <- list(
        id = generate_entity_id("DATA", data_matches[i, 1]),
        type = "DATA",
        value = data_matches[i, 1],
        day = data_matches[i, 2],
        month = data_matches[i, 3],
        year = data_matches[i, 4],
        confidence = 0.85,
        method = "regex",
        document_id = document_id,
        extracted_at = Sys.time()
      )
      entities <- append(entities, list(entity))
    }
  }
  
  # Extract government agencies
  orgao_patterns <- c(
    "Ministério\\s+([A-Za-z\\s]+)",
    "Secretaria\\s+([A-Za-z\\s]+)",
    "Agência\\s+([A-Za-z\\s]+)",
    "Instituto\\s+([A-Za-z\\s]+)"
  )
  
  for (pattern in orgao_patterns) {
    orgao_matches <- str_match_all(text, pattern)[[1]]
    
    if (nrow(orgao_matches) > 0) {
      for (i in 1:nrow(orgao_matches)) {
        entity <- list(
          id = generate_entity_id("ORGAO", orgao_matches[i, 1]),
          type = "ORGAO",
          value = orgao_matches[i, 1],
          confidence = 0.75,
          method = "regex",
          document_id = document_id,
          extracted_at = Sys.time()
        )
        entities <- append(entities, list(entity))
      }
    }
  }
  
  return(entities)
}

#' Extract entities using AI
#' @param text Document text
#' @param document_id Document ID
#' @return List of extracted entities
extract_entities_ai <- function(text, document_id) {
  # Use AI integration if available
  if (exists("analyze_document_text")) {
    analysis_result <- analyze_document_text(text, c("entities"))
    
    if (!is.null(analysis_result$analysis$entities)) {
      ai_entities <- list()
      
      for (entity_data in analysis_result$analysis$entities) {
        entity <- list(
          id = generate_entity_id(entity_data$type, entity_data$value),
          type = entity_data$type,
          value = entity_data$value,
          confidence = entity_data$confidence %||% 0.7,
          method = "ai",
          document_id = document_id,
          extracted_at = Sys.time()
        )
        ai_entities <- append(ai_entities, list(entity))
      }
      
      return(ai_entities)
    }
  }
  
  return(list())
}

#' Extract entities using dictionary lookup
#' @param text Document text
#' @param document_id Document ID
#' @return List of extracted entities
extract_entities_dictionary <- function(text, document_id) {
  entities <- list()
  
  # Load legal terms dictionary
  legal_terms <- load_legal_terms_dictionary()
  
  # Search for dictionary terms in text
  text_lower <- tolower(text)
  
  for (term in legal_terms) {
    if (grepl(tolower(term$value), text_lower)) {
      entity <- list(
        id = generate_entity_id("CONCEITO_JURIDICO", term$value),
        type = "CONCEITO_JURIDICO",
        value = term$value,
        definition = term$definition,
        confidence = 0.6,
        method = "dictionary",
        document_id = document_id,
        extracted_at = Sys.time()
      )
      entities <- append(entities, list(entity))
    }
  }
  
  return(entities)
}

#' Extract relationships between entities
#' @param document_text Document text
#' @param entities List of entities
#' @param document_id Document identifier
#' @return Extracted relationships
extract_relationships <- function(document_text, entities, document_id) {
  log_event(paste("Extracting relationships from document:", document_id), "INFO")
  
  relationships <- list()
  
  # Extract relationships using pattern matching
  for (rel_type in names(KG_CONFIG$relationships$extraction_patterns)) {
    patterns <- KG_CONFIG$relationships$extraction_patterns[[rel_type]]
    
    for (pattern in patterns) {
      rel_matches <- find_relationship_matches(document_text, entities, pattern, rel_type)
      relationships <- append(relationships, rel_matches)
    }
  }
  
  # Extract direct citation relationships
  citation_relationships <- extract_citation_relationships(document_text, entities, document_id)
  relationships <- append(relationships, citation_relationships)
  
  # Store relationships in graph
  for (relationship in relationships) {
    add_relationship_to_graph(relationship)
  }
  
  log_event(paste("Extracted", length(relationships), "relationships from document:", document_id), "INFO")
  
  return(relationships)
}

#' Find relationship matches in text
#' @param text Document text
#' @param entities List of entities
#' @param pattern Relationship pattern
#' @param rel_type Relationship type
#' @return List of relationships
find_relationship_matches <- function(text, entities, pattern, rel_type) {
  relationships <- list()
  
  # Simple pattern matching for relationships
  pattern_regex <- paste0("([^.]*)", pattern, "([^.]*)")
  matches <- str_match_all(text, pattern_regex)[[1]]
  
  if (nrow(matches) > 0) {
    for (i in 1:nrow(matches)) {
      before_text <- matches[i, 2]
      after_text <- matches[i, 3]
      
      # Find entities in before and after text
      before_entities <- find_entities_in_text(before_text, entities)
      after_entities <- find_entities_in_text(after_text, entities)
      
      # Create relationships between entities
      for (source_entity in before_entities) {
        for (target_entity in after_entities) {
          if (source_entity$id != target_entity$id) {
            relationship <- list(
              id = generate_relationship_id(source_entity$id, target_entity$id, rel_type),
              source = source_entity$id,
              target = target_entity$id,
              type = rel_type,
              confidence = 0.6,
              context = matches[i, 1],
              extracted_at = Sys.time()
            )
            relationships <- append(relationships, list(relationship))
          }
        }
      }
    }
  }
  
  return(relationships)
}

#' Extract citation relationships
#' @param text Document text
#' @param entities List of entities
#' @param document_id Document ID
#' @return Citation relationships
extract_citation_relationships <- function(text, entities, document_id) {
  relationships <- list()
  
  # Find legal document entities
  legal_entities <- Filter(function(e) e$type %in% c("LEI", "DECRETO", "RESOLUCAO"), entities)
  
  # Create citation relationships between documents
  current_doc_entity <- list(
    id = paste0("DOC_", document_id),
    type = "DOCUMENTO"
  )
  
  for (cited_entity in legal_entities) {
    relationship <- list(
      id = generate_relationship_id(current_doc_entity$id, cited_entity$id, "CITA"),
      source = current_doc_entity$id,
      target = cited_entity$id,
      type = "CITA",
      confidence = 0.8,
      extracted_at = Sys.time()
    )
    relationships <- append(relationships, list(relationship))
  }
  
  return(relationships)
}

#' Add entity to knowledge graph
#' @param entity Entity object
add_entity_to_graph <- function(entity) {
  if (is.null(kg_state$graph)) {
    return()
  }
  
  # Check if entity already exists
  if (entity$id %in% V(kg_state$graph)$name) {
    return()
  }
  
  # Add vertex to graph
  kg_state$graph <<- add_vertices(kg_state$graph, 1, 
    name = entity$id,
    label = entity$value,
    type = entity$type,
    confidence = entity$confidence,
    method = entity$method,
    document_id = entity$document_id
  )
  
  # Store entity in state
  kg_state$entities[[entity$id]] <<- entity
}

#' Add relationship to knowledge graph
#' @param relationship Relationship object
add_relationship_to_graph <- function(relationship) {
  if (is.null(kg_state$graph)) {
    return()
  }
  
  # Check if both entities exist in graph
  if (!relationship$source %in% V(kg_state$graph)$name || 
      !relationship$target %in% V(kg_state$graph)$name) {
    return()
  }
  
  # Add edge to graph
  kg_state$graph <<- add_edges(kg_state$graph, 
    c(relationship$source, relationship$target),
    type = relationship$type,
    confidence = relationship$confidence,
    context = relationship$context %||% ""
  )
  
  # Store relationship in state
  kg_state$relationships[[relationship$id]] <<- relationship
}

#' Query knowledge graph
#' @param entity_type Entity type filter
#' @param relationship_type Relationship type filter
#' @param min_confidence Minimum confidence threshold
#' @return Query results
query_knowledge_graph <- function(entity_type = NULL, relationship_type = NULL, min_confidence = 0.5) {
  if (is.null(kg_state$graph)) {
    return(list(nodes = list(), edges = list()))
  }
  
  # Filter nodes by type and confidence
  node_indices <- 1:vcount(kg_state$graph)
  
  if (!is.null(entity_type)) {
    type_filter <- V(kg_state$graph)$type == entity_type
    node_indices <- node_indices[type_filter]
  }
  
  if (!is.null(min_confidence)) {
    confidence_filter <- V(kg_state$graph)$confidence >= min_confidence
    node_indices <- node_indices[confidence_filter]
  }
  
  # Filter edges by type and confidence
  edge_indices <- 1:ecount(kg_state$graph)
  
  if (!is.null(relationship_type)) {
    rel_type_filter <- E(kg_state$graph)$type == relationship_type
    edge_indices <- edge_indices[rel_type_filter]
  }
  
  if (!is.null(min_confidence)) {
    edge_confidence_filter <- E(kg_state$graph)$confidence >= min_confidence
    edge_indices <- edge_indices[edge_confidence_filter]
  }
  
  # Extract filtered subgraph
  filtered_nodes <- V(kg_state$graph)[node_indices]
  filtered_edges <- E(kg_state$graph)[edge_indices]
  
  return(list(
    nodes = data.frame(
      id = filtered_nodes$name,
      label = filtered_nodes$label,
      type = filtered_nodes$type,
      confidence = filtered_nodes$confidence,
      stringsAsFactors = FALSE
    ),
    edges = if (length(filtered_edges) > 0) {
      edge_list <- get.edgelist(kg_state$graph)[edge_indices, , drop = FALSE]
      data.frame(
        from = edge_list[, 1],
        to = edge_list[, 2],
        type = filtered_edges$type,
        confidence = filtered_edges$confidence,
        stringsAsFactors = FALSE
      )
    } else {
      data.frame()
    }
  ))
}

#' Analyze graph communities
#' @param algorithm Community detection algorithm
#' @return Community analysis results
analyze_graph_communities <- function(algorithm = "louvain") {
  if (is.null(kg_state$graph) || vcount(kg_state$graph) == 0) {
    return(list(communities = list(), modularity = 0))
  }
  
  # Apply community detection algorithm
  communities <- switch(algorithm,
    "louvain" = cluster_louvain(kg_state$graph),
    "leiden" = cluster_leiden(kg_state$graph),
    "walktrap" = cluster_walktrap(kg_state$graph),
    cluster_louvain(kg_state$graph)  # default
  )
  
  # Extract community information
  community_list <- list()
  for (i in 1:max(membership(communities))) {
    community_members <- V(kg_state$graph)$name[membership(communities) == i]
    community_list[[i]] <- list(
      id = i,
      members = community_members,
      size = length(community_members),
      density = edge_density(induced_subgraph(kg_state$graph, community_members))
    )
  }
  
  # Store communities in state
  kg_state$communities <<- community_list
  
  return(list(
    communities = community_list,
    modularity = modularity(communities),
    algorithm = algorithm,
    num_communities = length(community_list)
  ))
}

#' Calculate graph metrics
#' @return Graph analysis metrics
calculate_graph_metrics <- function() {
  if (is.null(kg_state$graph) || vcount(kg_state$graph) == 0) {
    return(list())
  }
  
  # Basic graph metrics
  metrics <- list(
    nodes = vcount(kg_state$graph),
    edges = ecount(kg_state$graph),
    density = edge_density(kg_state$graph),
    diameter = diameter(kg_state$graph),
    average_path_length = average.path.length(kg_state$graph),
    clustering_coefficient = transitivity(kg_state$graph)
  )
  
  # Centrality metrics
  if (KG_CONFIG$graph$centrality_metrics && vcount(kg_state$graph) > 1) {
    metrics$centrality <- list(
      degree = degree(kg_state$graph),
      betweenness = betweenness(kg_state$graph),
      closeness = closeness(kg_state$graph),
      eigenvector = eigen_centrality(kg_state$graph)$vector
    )
  }
  
  # Entity type distribution
  entity_types <- table(V(kg_state$graph)$type)
  metrics$entity_distribution <- as.list(entity_types)
  
  # Relationship type distribution
  if (ecount(kg_state$graph) > 0) {
    relationship_types <- table(E(kg_state$graph)$type)
    metrics$relationship_distribution <- as.list(relationship_types)
  }
  
  # Store metrics in state
  kg_state$metrics <<- metrics
  
  return(metrics)
}

#' Create knowledge graph visualization
#' @param query_result Graph query results
#' @param layout Layout algorithm
#' @return Visualization object
create_graph_visualization <- function(query_result = NULL, layout = "layout_with_fr") {
  if (is.null(query_result)) {
    query_result <- query_knowledge_graph()
  }
  
  if (nrow(query_result$nodes) == 0) {
    return(NULL)
  }
  
  # Prepare nodes for visualization
  nodes <- query_result$nodes
  nodes$size <- pmax(10, pmin(50, nodes$confidence * 50))
  nodes$color <- assign_node_colors(nodes$type)
  nodes$title <- paste0("Type: ", nodes$type, "<br>Confidence: ", round(nodes$confidence, 2))
  
  # Prepare edges for visualization
  edges <- query_result$edges
  if (nrow(edges) > 0) {
    edges$width <- pmax(1, edges$confidence * 5)
    edges$title <- paste0("Type: ", edges$type, "<br>Confidence: ", round(edges$confidence, 2))
    edges$arrows <- "to"
  }
  
  # Create interactive visualization
  vis_network <- visNetwork(nodes, edges) %>%
    visOptions(highlightNearest = TRUE, selectedBy = "type") %>%
    visLayout(randomSeed = 123) %>%
    visInteraction(navigationButtons = TRUE) %>%
    visEdges(arrows = "to", smooth = list(enabled = TRUE, type = "continuous"))
  
  return(vis_network)
}

# Helper functions

#' Generate entity ID
#' @param type Entity type
#' @param value Entity value
#' @return Unique entity ID
generate_entity_id <- function(type, value) {
  paste0(type, "_", digest(value, algo = "md5"))
}

#' Generate relationship ID
#' @param source Source entity ID
#' @param target Target entity ID
#' @param type Relationship type
#' @return Unique relationship ID
generate_relationship_id <- function(source, target, type) {
  paste0("REL_", digest(paste(source, target, type, sep = "_"), algo = "md5"))
}

#' Deduplicate entities
#' @param entities List of entities
#' @return Deduplicated entities
deduplicate_entities <- function(entities) {
  if (length(entities) == 0) {
    return(entities)
  }
  
  # Group by ID and keep highest confidence
  entity_groups <- split(entities, sapply(entities, function(e) e$id))
  
  unique_entities <- lapply(entity_groups, function(group) {
    if (length(group) == 1) {
      return(group[[1]])
    }
    
    # Return entity with highest confidence
    confidences <- sapply(group, function(e) e$confidence)
    return(group[[which.max(confidences)]])
  })
  
  return(unique_entities)
}

#' Filter entities by confidence
#' @param entities List of entities
#' @return Filtered entities
filter_entities_by_confidence <- function(entities) {
  threshold <- KG_CONFIG$entities$confidence_threshold
  Filter(function(e) e$confidence >= threshold, entities)
}

#' Find entities in text
#' @param text Text to search
#' @param entities List of entities
#' @return Entities found in text
find_entities_in_text <- function(text, entities) {
  found_entities <- list()
  
  for (entity in entities) {
    if (grepl(entity$value, text, ignore.case = TRUE)) {
      found_entities <- append(found_entities, list(entity))
    }
  }
  
  return(found_entities)
}

#' Load legal terms dictionary
#' @return Legal terms dictionary
load_legal_terms_dictionary <- function() {
  # Sample legal terms (in production, load from external source)
  list(
    list(value = "Administração Pública", definition = "Conjunto de órgãos públicos"),
    list(value = "Devido Processo Legal", definition = "Garantia processual constitucional"),
    list(value = "Supremacia do Interesse Público", definition = "Princípio do direito administrativo"),
    list(value = "Legalidade", definition = "Princípio da administração pública"),
    list(value = "Impessoalidade", definition = "Princípio da administração pública"),
    list(value = "Moralidade", definition = "Princípio da administração pública"),
    list(value = "Publicidade", definition = "Princípio da administração pública"),
    list(value = "Eficiência", definition = "Princípio da administração pública")
  )
}

#' Initialize extraction patterns
#' @return Pattern initialization result
initialize_extraction_patterns <- function() {
  # Initialize regex patterns for entity extraction
  # This could be loaded from external configuration
  
  return(list(status = "success"))
}

#' Assign node colors by type
#' @param types Vector of entity types
#' @return Vector of colors
assign_node_colors <- function(types) {
  color_map <- list(
    "LEI" = "#FF6B6B",
    "DECRETO" = "#4ECDC4",
    "RESOLUCAO" = "#45B7D1",
    "PORTARIA" = "#96CEB4",
    "INSTRUCAO_NORMATIVA" = "#FFEAA7",
    "PESSOA" = "#DDA0DD",
    "ORGAO" = "#98D8C8",
    "LOCAL" = "#F7DC6F",
    "DATA" = "#BB8FCE",
    "VALOR_MONETARIO" = "#85C1E9",
    "CONCEITO_JURIDICO" = "#F8C471",
    "DOCUMENTO" = "#82E0AA"
  )
  
  sapply(types, function(type) {
    color_map[[type]] %||% "#BDC3C7"
  })
}

#' Load persisted graph
load_persisted_graph <- function() {
  graph_file <- "knowledge_graph.graphml"
  
  if (file.exists(graph_file)) {
    tryCatch({
      kg_state$graph <<- read_graph(graph_file, format = "graphml")
      log_event("Loaded persisted knowledge graph", "INFO")
    }, error = function(e) {
      log_event(paste("Failed to load persisted graph:", e$message), "WARN")
    })
  }
}

#' Save knowledge graph
#' @param filename Optional filename
save_knowledge_graph <- function(filename = NULL) {
  if (is.null(kg_state$graph) || !KG_CONFIG$storage$persist_graph) {
    return()
  }
  
  filename <- filename %||% "knowledge_graph.graphml"
  
  tryCatch({
    write_graph(kg_state$graph, filename, format = KG_CONFIG$storage$storage_format)
    log_event("Knowledge graph saved successfully", "INFO")
  }, error = function(e) {
    log_event(paste("Failed to save knowledge graph:", e$message), "ERROR")
  })
}

#' Get knowledge graph statistics
#' @return Graph statistics
get_knowledge_graph_statistics <- function() {
  if (is.null(kg_state$graph)) {
    return(list(
      nodes = 0,
      edges = 0,
      entities = 0,
      relationships = 0
    ))
  }
  
  return(list(
    nodes = vcount(kg_state$graph),
    edges = ecount(kg_state$graph),
    entities = length(kg_state$entities),
    relationships = length(kg_state$relationships),
    communities = length(kg_state$communities),
    metrics_available = !is.null(kg_state$metrics),
    last_updated = Sys.time()
  ))
}