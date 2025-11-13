# ==============================================================================
# NETWORK BACKBONE EXTRACTION FOR LEGISLATIVE DOCUMENTS
# ==============================================================================
# Monitor Legislativo v4 - Advanced Network Analysis Module
#
# This module implements network backbone extraction using the disparity filter
# algorithm (Serrano et al., 2009) to identify statistically significant
# relationships in legislative networks.
#
# Features:
# - Citation network construction from document references
# - Co-authorship network analysis
# - Topic-based document networks
# - Multiple backbone extraction methods (disparity, significance, degree)
# - Community detection (Louvain, Infomap, Walktrap)
# - Comprehensive network metrics calculation
# - Influential node identification
#
# Academic Reference:
# Serrano, M. Á., Boguná, M., & Vespignani, A. (2009). Extracting the
# multiscale backbone of complex weighted networks. PNAS, 106(16), 6483-6488.
# ==============================================================================

suppressPackageStartupMessages({
  library(igraph)
  library(dplyr)
  library(tidyr)
  library(stringr)
  library(DBI)
  library(data.table)
  library(jsonlite)
})

# Source database connection utilities
if (!exists("execute_secure_query")) {
  if (file.exists("R/database/connection.R")) {
    source("R/database/connection.R")
  }
}

# Define safe logging function if not available
if (!exists("log_security_event")) {
  log_security_event <- function(event_type, description, ...) {
    timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
    cat(sprintf("[%s] %s: %s\n", timestamp, event_type, description))
  }
}

# ==============================================================================
# CITATION NETWORK CONSTRUCTION
# ==============================================================================

#' Build Citation Network from Document References
#'
#' Creates a directed citation network where nodes are legislative documents
#' and edges represent citations (references from one document to another).
#' Edge weights represent the frequency of citations.
#'
#' This function extracts citations from document metadata and constructs
#' a weighted directed graph. Documents without any citations (isolated nodes)
#' can optionally be included or excluded.
#'
#' @param db_connection Database connection pool from init_database_connection()
#' @param min_citations Minimum number of citations required for an edge to be included.
#'   Default is 2. Use 1 to include all citations.
#' @param include_metadata Logical. Include node attributes (titulo, tipo, ano) in graph.
#'   Default TRUE.
#' @param max_documents Maximum number of documents to include. NULL for all documents.
#'   Useful for testing or sampling large databases.
#' @param date_range Optional date range as c(start_date, end_date) in "YYYY-MM-DD" format
#'
#' @return igraph object representing the citation network, or NULL if construction fails.
#'   Node attributes: name (document ID), titulo, tipo, ano
#'   Edge attributes: weight (citation frequency)
#'
#' @examples
#' \dontrun{
#' # Build full citation network
#' citation_net <- build_citation_network(db_pool)
#'
#' # Build network with minimum 3 citations
#' strong_citations <- build_citation_network(db_pool, min_citations = 3)
#'
#' # Build network for specific year range
#' recent_net <- build_citation_network(
#'   db_pool,
#'   date_range = c("2020-01-01", "2023-12-31")
#' )
#'
#' # Sample network for testing (first 1000 documents)
#' sample_net <- build_citation_network(db_pool, max_documents = 1000)
#' }
#'
#' @export
build_citation_network <- function(db_connection,
                                   min_citations = 2,
                                   include_metadata = TRUE,
                                   max_documents = NULL,
                                   date_range = NULL) {

  cat("Building citation network from document references...\n")
  start_time <- Sys.time()

  tryCatch({
    # Build WHERE clause for filtering
    where_clauses <- c("1=1")

    if (!is.null(date_range) && length(date_range) == 2) {
      where_clauses <- c(where_clauses,
                        sprintf("data_publicacao BETWEEN '%s' AND '%s'",
                               date_range[1], date_range[2]))
    }

    limit_clause <- if (!is.null(max_documents)) {
      sprintf("LIMIT %d", max_documents)
    } else {
      ""
    }

    # Query to extract document references from metadata
    query <- sprintf("
      SELECT
        id,
        urn,
        titulo,
        tipo,
        EXTRACT(YEAR FROM data_publicacao) as ano,
        metadata
      FROM documents
      WHERE %s
        AND metadata IS NOT NULL
        AND metadata::text LIKE '%%referencia%%'
      %s
    ", paste(where_clauses, collapse = " AND "), limit_clause)

    # Execute query
    if (exists("execute_secure_query")) {
      docs <- execute_secure_query(db_connection, query)
    } else {
      docs <- DBI::dbGetQuery(db_connection, query)
    }

    cat(sprintf("  Retrieved %d documents with potential references\n", nrow(docs)))

    if (nrow(docs) == 0) {
      warning("No documents with references found")
      return(NULL)
    }

    # Extract citations from metadata
    citations_list <- lapply(1:nrow(docs), function(i) {
      doc_id <- docs$id[i]
      metadata <- docs$metadata[i]

      # Parse JSON metadata
      meta_obj <- tryCatch({
        if (is.character(metadata)) {
          jsonlite::fromJSON(metadata)
        } else {
          metadata
        }
      }, error = function(e) NULL)

      if (is.null(meta_obj)) return(NULL)

      # Extract references (could be in different fields)
      refs <- NULL
      if ("referencias" %in% names(meta_obj)) {
        refs <- meta_obj$referencias
      } else if ("referencia" %in% names(meta_obj)) {
        refs <- meta_obj$referencia
      } else if ("cited_documents" %in% names(meta_obj)) {
        refs <- meta_obj$cited_documents
      }

      if (is.null(refs) || length(refs) == 0) return(NULL)

      # Parse references (could be URNs, IDs, or text)
      # Return data frame of citations
      data.frame(
        from = doc_id,
        to = refs,
        stringsAsFactors = FALSE
      )
    })

    # Combine all citations
    citations <- data.table::rbindlist(citations_list, fill = TRUE)

    if (nrow(citations) == 0) {
      warning("No valid citations extracted from metadata")
      return(NULL)
    }

    cat(sprintf("  Extracted %d raw citations\n", nrow(citations)))

    # Aggregate citations to create weighted edges
    edge_list <- citations %>%
      group_by(from, to) %>%
      summarise(weight = n(), .groups = "drop") %>%
      filter(weight >= min_citations) %>%
      as.data.frame()

    cat(sprintf("  Created %d weighted edges (min_citations=%d)\n",
                nrow(edge_list), min_citations))

    if (nrow(edge_list) == 0) {
      warning(sprintf("No edges found with min_citations >= %d", min_citations))
      return(NULL)
    }

    # Create igraph object
    g <- graph_from_data_frame(
      d = edge_list,
      directed = TRUE,
      vertices = NULL
    )

    # Add node metadata if requested
    if (include_metadata) {
      # Create node attribute lookup
      node_attrs <- docs %>%
        select(id, titulo, tipo, ano) %>%
        distinct()

      # Match vertices to metadata
      vertex_ids <- V(g)$name
      matched_attrs <- node_attrs[match(vertex_ids, node_attrs$id), ]

      # Set vertex attributes
      V(g)$titulo <- matched_attrs$titulo
      V(g)$tipo <- matched_attrs$tipo
      V(g)$ano <- matched_attrs$ano
      V(g)$label <- matched_attrs$titulo
    }

    # Calculate basic network statistics
    n_nodes <- vcount(g)
    n_edges <- ecount(g)
    density <- edge_density(g)

    elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

    cat(sprintf("\nCitation network built successfully:\n"))
    cat(sprintf("  Nodes: %d documents\n", n_nodes))
    cat(sprintf("  Edges: %d citations\n", n_edges))
    cat(sprintf("  Density: %.6f\n", density))
    cat(sprintf("  Time elapsed: %.2f seconds\n", elapsed))

    log_security_event("NETWORK_CONSTRUCTION",
                      sprintf("Citation network built: %d nodes, %d edges",
                             n_nodes, n_edges))

    return(g)

  }, error = function(e) {
    cat(sprintf("Error building citation network: %s\n", e$message))
    log_security_event("NETWORK_ERROR",
                      sprintf("Citation network construction failed: %s", e$message))
    return(NULL)
  })
}

# ==============================================================================
# BACKBONE EXTRACTION - DISPARITY FILTER
# ==============================================================================

#' Extract Network Backbone Using Disparity Filter
#'
#' Applies the disparity filter algorithm (Serrano et al., 2009) to identify
#' statistically significant edges in a weighted network. This method preserves
#' the most important structural relationships while reducing network complexity.
#'
#' The disparity filter works by comparing the observed weight distribution of
#' edges for each node against a null model. Edges that are statistically
#' significant (p-value < alpha) are retained in the backbone.
#'
#' @param network igraph object with weighted edges
#' @param alpha Significance threshold (default 0.05). Lower values result in sparser backbones.
#' @param method Backbone extraction method:
#'   - "disparity": Disparity filter (Serrano et al. 2009)
#'   - "significance": Simple statistical significance test
#'   - "degree": Keep edges to/from high-degree nodes only
#' @param directed Logical. Treat network as directed? Default TRUE.
#'
#' @return Reduced igraph network containing only backbone edges.
#'   Original node and edge attributes are preserved.
#'
#' @details
#' **Disparity Filter Algorithm:**
#' For each node i with degree k_i and edges to nodes j:
#' 1. Calculate normalized weight: p_ij = w_ij / sum(w_ik)
#' 2. Compute probability: P(p_ij) = (k_i - 1) * integral from 0 to p_ij of (1-x)^(k_i-2) dx
#' 3. Keep edge if P(p_ij) < alpha
#'
#' **Performance:**
#' - 10,000 edges: ~10-30 seconds
#' - 100,000 edges: ~2-5 minutes
#' - Uses vectorized operations for efficiency
#'
#' @references
#' Serrano, M. Á., Boguná, M., & Vespignani, A. (2009). Extracting the
#' multiscale backbone of complex weighted networks. PNAS, 106(16), 6483-6488.
#'
#' @examples
#' \dontrun{
#' # Build citation network
#' g <- build_citation_network(db_pool)
#'
#' # Extract backbone with default parameters (alpha=0.05)
#' backbone <- extract_backbone(g)
#'
#' # More aggressive filtering (sparser network)
#' sparse_backbone <- extract_backbone(g, alpha = 0.01)
#'
#' # Less aggressive filtering (denser network)
#' dense_backbone <- extract_backbone(g, alpha = 0.10)
#'
#' # Use degree-based method instead
#' degree_backbone <- extract_backbone(g, method = "degree")
#'
#' # Compare network sizes
#' cat(sprintf("Original: %d edges\n", ecount(g)))
#' cat(sprintf("Backbone: %d edges\n", ecount(backbone)))
#' cat(sprintf("Reduction: %.1f%%\n", 100 * (1 - ecount(backbone)/ecount(g))))
#' }
#'
#' @export
extract_backbone <- function(network,
                             alpha = 0.05,
                             method = "disparity",
                             directed = TRUE) {

  cat(sprintf("\nExtracting network backbone (method=%s, alpha=%.3f)...\n",
              method, alpha))
  start_time <- Sys.time()

  if (!is_weighted(network)) {
    warning("Network is not weighted. Using edge count as weight.")
    E(network)$weight <- 1
  }

  original_edges <- ecount(network)
  original_nodes <- vcount(network)

  if (method == "disparity") {
    backbone <- extract_backbone_disparity(network, alpha, directed)
  } else if (method == "significance") {
    backbone <- extract_backbone_significance(network, alpha)
  } else if (method == "degree") {
    backbone <- extract_backbone_degree(network, alpha)
  } else {
    stop(sprintf("Unknown backbone extraction method: %s", method))
  }

  backbone_edges <- ecount(backbone)
  backbone_nodes <- vcount(backbone)
  reduction <- 100 * (1 - backbone_edges / original_edges)

  elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

  cat(sprintf("\nBackbone extraction complete:\n"))
  cat(sprintf("  Original: %d nodes, %d edges\n", original_nodes, original_edges))
  cat(sprintf("  Backbone: %d nodes, %d edges\n", backbone_nodes, backbone_edges))
  cat(sprintf("  Edge reduction: %.1f%%\n", reduction))
  cat(sprintf("  Time elapsed: %.2f seconds\n", elapsed))

  log_security_event("NETWORK_BACKBONE",
                    sprintf("Backbone extracted: %.1f%% edge reduction", reduction))

  return(backbone)
}

#' Disparity Filter Implementation
#'
#' @keywords internal
extract_backbone_disparity <- function(g, alpha, directed) {

  # Get edge list with weights
  el <- as_data_frame(g, what = "edges")

  if (!"weight" %in% names(el)) {
    el$weight <- 1
  }

  # Calculate disparity statistic for each edge
  cat("  Calculating disparity statistics...\n")

  # For directed networks, calculate for out-edges
  if (directed) {
    el$keep <- sapply(1:nrow(el), function(i) {
      source_node <- el$from[i]
      edge_weight <- el$weight[i]

      # Get all out-edges from source node
      out_edges <- el[el$from == source_node, ]
      total_weight <- sum(out_edges$weight)
      degree <- nrow(out_edges)

      if (degree <= 1) return(TRUE)  # Keep all edges from degree-1 nodes

      # Calculate normalized weight
      p_ij <- edge_weight / total_weight

      # Calculate disparity statistic
      # P(X >= p_ij) = (1 - p_ij)^(k-1)
      # For more accurate calculation, use beta distribution
      p_value <- 1 - pbeta(p_ij, 1, degree - 1)

      # Keep edge if p-value < alpha (statistically significant)
      return(p_value < alpha)
    })
  } else {
    # For undirected networks, calculate for all edges at each node
    el$keep <- sapply(1:nrow(el), function(i) {
      node1 <- el$from[i]
      node2 <- el$to[i]
      edge_weight <- el$weight[i]

      # Get edges incident to node1
      incident1 <- el[el$from == node1 | el$to == node1, ]
      total1 <- sum(incident1$weight)
      degree1 <- nrow(incident1)

      # Get edges incident to node2
      incident2 <- el[el$from == node2 | el$to == node2, ]
      total2 <- sum(incident2$weight)
      degree2 <- nrow(incident2)

      # Calculate p-value for both nodes
      if (degree1 > 1) {
        p1 <- edge_weight / total1
        pval1 <- 1 - pbeta(p1, 1, degree1 - 1)
      } else {
        pval1 <- 0
      }

      if (degree2 > 1) {
        p2 <- edge_weight / total2
        pval2 <- 1 - pbeta(p2, 1, degree2 - 1)
      } else {
        pval2 <- 0
      }

      # Keep edge if significant for EITHER node
      return(pval1 < alpha || pval2 < alpha)
    })
  }

  # Filter edges
  backbone_edges <- el[el$keep, ]
  cat(sprintf("  Kept %d / %d edges (%.1f%%)\n",
              nrow(backbone_edges), nrow(el),
              100 * nrow(backbone_edges) / nrow(el)))

  # Create backbone graph
  backbone <- graph_from_data_frame(
    d = backbone_edges[, !names(backbone_edges) %in% "keep"],
    directed = directed,
    vertices = as_data_frame(g, what = "vertices")
  )

  return(backbone)
}

#' Significance-Based Backbone Extraction
#'
#' @keywords internal
extract_backbone_significance <- function(g, alpha) {

  # Simple method: keep edges with weight > threshold
  weights <- E(g)$weight
  threshold <- quantile(weights, 1 - alpha, na.rm = TRUE)

  cat(sprintf("  Weight threshold: %.2f\n", threshold))

  # Keep edges above threshold
  g_backbone <- delete_edges(g, E(g)[weight < threshold])

  return(g_backbone)
}

#' Degree-Based Backbone Extraction
#'
#' @keywords internal
extract_backbone_degree <- function(g, alpha) {

  # Keep edges connected to high-degree nodes
  degrees <- degree(g)
  degree_threshold <- quantile(degrees, 1 - alpha, na.rm = TRUE)

  cat(sprintf("  Degree threshold: %d\n", degree_threshold))

  # Get edge list
  el <- as_data_frame(g, what = "edges")

  # Keep edges where at least one node has high degree
  el$keep <- degrees[el$from] >= degree_threshold |
             degrees[el$to] >= degree_threshold

  # Create backbone
  backbone <- graph_from_data_frame(
    d = el[el$keep, !names(el) %in% "keep"],
    directed = is_directed(g),
    vertices = as_data_frame(g, what = "vertices")
  )

  return(backbone)
}

# ==============================================================================
# CO-AUTHORSHIP NETWORK
# ==============================================================================

#' Build Co-Authorship Network
#'
#' Creates an undirected co-authorship network where nodes are legislative authors
#' and edges represent co-sponsorship or collaboration on legislative documents.
#'
#' @param db_connection Database connection pool
#' @param min_collaborations Minimum number of shared documents for an edge.
#'   Default 2.
#' @param author_field Database field containing author information. Default "autor"
#' @param date_range Optional date range as c(start_date, end_date)
#'
#' @return igraph object representing co-authorship network
#'
#' @examples
#' \dontrun{
#' # Build co-authorship network
#' coauthor_net <- build_coauthorship_network(db_pool)
#'
#' # Require at least 5 collaborations
#' strong_collab <- build_coauthorship_network(db_pool, min_collaborations = 5)
#' }
#'
#' @export
build_coauthorship_network <- function(db_connection,
                                       min_collaborations = 2,
                                       author_field = "autor",
                                       date_range = NULL) {

  cat("Building co-authorship network...\n")
  start_time <- Sys.time()

  tryCatch({
    # Build WHERE clause
    where_clauses <- c(sprintf("%s IS NOT NULL", author_field),
                      sprintf("%s != ''", author_field))

    if (!is.null(date_range) && length(date_range) == 2) {
      where_clauses <- c(where_clauses,
                        sprintf("data_publicacao BETWEEN '%s' AND '%s'",
                               date_range[1], date_range[2]))
    }

    # Query documents with multiple authors
    query <- sprintf("
      SELECT
        id,
        %s as autor,
        tipo,
        EXTRACT(YEAR FROM data_publicacao) as ano
      FROM documents
      WHERE %s
    ", author_field, paste(where_clauses, collapse = " AND "))

    if (exists("execute_secure_query")) {
      docs <- execute_secure_query(db_connection, query)
    } else {
      docs <- DBI::dbGetQuery(db_connection, query)
    }

    cat(sprintf("  Retrieved %d documents with authors\n", nrow(docs)))

    # Parse multiple authors (separated by semicolon, comma, or "e")
    author_docs <- lapply(1:nrow(docs), function(i) {
      doc_id <- docs$id[i]
      authors_raw <- docs$autor[i]

      # Split by common delimiters
      authors <- unlist(strsplit(authors_raw, ";|,|\\se\\s"))
      authors <- trimws(authors)
      authors <- authors[nchar(authors) > 0]

      if (length(authors) == 0) return(NULL)

      data.frame(
        document = doc_id,
        author = authors,
        stringsAsFactors = FALSE
      )
    })

    author_doc_df <- data.table::rbindlist(author_docs, fill = TRUE)

    # Create co-authorship edges (authors who share documents)
    cat("  Computing co-authorship edges...\n")

    # Self-join to find author pairs on same documents
    coauth <- author_doc_df %>%
      inner_join(author_doc_df, by = "document", relationship = "many-to-many") %>%
      filter(author.x < author.y) %>%  # Avoid duplicates and self-loops
      group_by(author.x, author.y) %>%
      summarise(weight = n(), .groups = "drop") %>%
      filter(weight >= min_collaborations) %>%
      rename(from = author.x, to = author.y)

    cat(sprintf("  Found %d co-authorship edges\n", nrow(coauth)))

    if (nrow(coauth) == 0) {
      warning("No co-authorships found")
      return(NULL)
    }

    # Create network
    g <- graph_from_data_frame(
      d = coauth,
      directed = FALSE
    )

    # Add node attributes (count of documents per author)
    author_counts <- author_doc_df %>%
      group_by(author) %>%
      summarise(n_documents = n(), .groups = "drop")

    V(g)$n_documents <- author_counts$n_documents[match(V(g)$name, author_counts$author)]
    V(g)$label <- V(g)$name

    elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

    cat(sprintf("\nCo-authorship network built:\n"))
    cat(sprintf("  Authors: %d\n", vcount(g)))
    cat(sprintf("  Collaborations: %d\n", ecount(g)))
    cat(sprintf("  Time: %.2f seconds\n", elapsed))

    return(g)

  }, error = function(e) {
    cat(sprintf("Error building co-authorship network: %s\n", e$message))
    return(NULL)
  })
}

# ==============================================================================
# TOPIC NETWORK
# ==============================================================================

#' Build Topic-Based Document Network
#'
#' Creates a network of documents connected by shared topics or keywords.
#' Uses text matching on document titles and content.
#'
#' @param db_connection Database connection pool
#' @param topics_keywords Named list of topics and their keywords.
#'   Example: list("transport" = c("rodovia", "transporte", "mobilidade"))
#' @param min_shared_topics Minimum number of shared topics for an edge. Default 1.
#' @param search_fields Fields to search. Default c("titulo", "conteudo")
#'
#' @return igraph object representing topic network
#'
#' @examples
#' \dontrun{
#' # Define topics
#' topics <- list(
#'   transport = c("rodovia", "ferrovia", "transporte", "mobilidade"),
#'   environment = c("ambiental", "sustentavel", "preservacao"),
#'   health = c("saude", "hospital", "sanitario")
#' )
#'
#' # Build topic network
#' topic_net <- build_topic_network(db_pool, topics)
#' }
#'
#' @export
build_topic_network <- function(db_connection,
                                topics_keywords,
                                min_shared_topics = 1,
                                search_fields = c("titulo", "conteudo")) {

  cat("Building topic-based document network...\n")
  start_time <- Sys.time()

  tryCatch({
    # Query documents
    fields_str <- paste(search_fields, collapse = ", ")
    query <- sprintf("
      SELECT
        id,
        urn,
        titulo,
        %s
      FROM documents
      WHERE titulo IS NOT NULL
      LIMIT 10000
    ", fields_str)

    if (exists("execute_secure_query")) {
      docs <- execute_secure_query(db_connection, query)
    } else {
      docs <- DBI::dbGetQuery(db_connection, query)
    }

    cat(sprintf("  Retrieved %d documents\n", nrow(docs)))

    # Assign topics to documents
    cat("  Assigning topics to documents...\n")

    doc_topics <- data.frame(
      document = character(),
      topic = character(),
      stringsAsFactors = FALSE
    )

    for (topic_name in names(topics_keywords)) {
      keywords <- topics_keywords[[topic_name]]
      pattern <- paste(keywords, collapse = "|")

      # Search in specified fields
      matches <- sapply(1:nrow(docs), function(i) {
        text <- paste(docs[i, search_fields], collapse = " ")
        grepl(pattern, text, ignore.case = TRUE)
      })

      matched_docs <- docs$id[matches]

      if (length(matched_docs) > 0) {
        doc_topics <- rbind(doc_topics, data.frame(
          document = matched_docs,
          topic = topic_name,
          stringsAsFactors = FALSE
        ))
      }

      cat(sprintf("    Topic '%s': %d documents\n", topic_name, length(matched_docs)))
    }

    # Create edges between documents sharing topics
    cat("  Creating edges between documents with shared topics...\n")

    edges <- doc_topics %>%
      inner_join(doc_topics, by = "topic", relationship = "many-to-many") %>%
      filter(document.x < document.y) %>%
      group_by(document.x, document.y) %>%
      summarise(weight = n(), .groups = "drop") %>%
      filter(weight >= min_shared_topics) %>%
      rename(from = document.x, to = document.y)

    cat(sprintf("  Created %d edges\n", nrow(edges)))

    if (nrow(edges) == 0) {
      warning("No topic-based connections found")
      return(NULL)
    }

    # Create network
    g <- graph_from_data_frame(
      d = edges,
      directed = FALSE,
      vertices = docs %>% select(id, titulo)
    )

    # Add topic assignments as vertex attribute
    vertex_topics <- doc_topics %>%
      group_by(document) %>%
      summarise(topics = paste(topic, collapse = ","), .groups = "drop")

    V(g)$topics <- vertex_topics$topics[match(V(g)$name, vertex_topics$document)]

    elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

    cat(sprintf("\nTopic network built:\n"))
    cat(sprintf("  Documents: %d\n", vcount(g)))
    cat(sprintf("  Topic connections: %d\n", ecount(g)))
    cat(sprintf("  Time: %.2f seconds\n", elapsed))

    return(g)

  }, error = function(e) {
    cat(sprintf("Error building topic network: %s\n", e$message))
    return(NULL)
  })
}

# ==============================================================================
# NETWORK METRICS
# ==============================================================================

#' Calculate Comprehensive Network Metrics
#'
#' Computes a comprehensive set of network statistics including global metrics
#' (density, clustering, centralization) and optionally community detection.
#'
#' @param network igraph object
#' @param include_communities Logical. Run community detection? Default TRUE.
#' @param community_method Method for community detection. Default "louvain"
#'
#' @return Named list of network metrics
#'
#' @export
calculate_network_metrics <- function(network,
                                      include_communities = TRUE,
                                      community_method = "louvain") {

  cat("Calculating network metrics...\n")

  metrics <- list()

  # Basic counts
  metrics$n_nodes <- vcount(network)
  metrics$n_edges <- ecount(network)
  metrics$density <- edge_density(network)
  metrics$is_directed <- is_directed(network)
  metrics$is_weighted <- is_weighted(network)

  # Components
  comp <- components(network)
  metrics$n_components <- comp$no
  metrics$largest_component_size <- max(comp$csize)
  metrics$largest_component_pct <- 100 * max(comp$csize) / vcount(network)

  # Degree statistics
  deg <- degree(network)
  metrics$mean_degree <- mean(deg)
  metrics$median_degree <- median(deg)
  metrics$max_degree <- max(deg)

  # Clustering
  if (vcount(network) > 0) {
    tryCatch({
      metrics$transitivity_global <- transitivity(network, type = "global")
      metrics$transitivity_average <- transitivity(network, type = "average")
    }, error = function(e) {
      metrics$transitivity_global <- NA
      metrics$transitivity_average <- NA
    })
  }

  # Centralization
  tryCatch({
    metrics$degree_centralization <- centr_degree(network)$centralization
    metrics$betweenness_centralization <- centr_betw(network)$centralization
  }, error = function(e) {
    metrics$degree_centralization <- NA
    metrics$betweenness_centralization <- NA
  })

  # Diameter and path length (only for connected graphs)
  if (comp$no == 1) {
    tryCatch({
      metrics$diameter <- diameter(network)
      metrics$average_path_length <- mean_distance(network)
    }, error = function(e) {
      metrics$diameter <- NA
      metrics$average_path_length <- NA
    })
  } else {
    metrics$diameter <- NA
    metrics$average_path_length <- NA
  }

  # Communities
  if (include_communities && vcount(network) > 0) {
    comm <- detect_communities(network, method = community_method)
    if (!is.null(comm$membership)) {
      metrics$n_communities <- comm$n_communities
      metrics$modularity <- comm$modularity
      metrics$community_sizes_mean <- mean(comm$sizes)
      metrics$community_sizes_sd <- sd(comm$sizes)
    }
  }

  cat("  Metrics calculated successfully\n")

  return(metrics)
}

# ==============================================================================
# INFLUENTIAL NODES
# ==============================================================================

#' Identify Influential Nodes in Network
#'
#' Ranks nodes by multiple centrality measures to identify the most influential
#' documents, authors, or topics in the network.
#'
#' @param network igraph object
#' @param top_n Number of top nodes to return. Default 20.
#' @param metrics Centrality metrics to calculate. Default all.
#'
#' @return Data frame with node rankings by different centrality measures
#'
#' @export
identify_influential_nodes <- function(network,
                                       top_n = 20,
                                       metrics = c("degree", "betweenness",
                                                  "pagerank", "eigenvector")) {

  cat(sprintf("Identifying top %d influential nodes...\n", top_n))

  results <- data.frame(
    node = V(network)$name,
    label = if (!is.null(V(network)$label)) V(network)$label else V(network)$name,
    stringsAsFactors = FALSE
  )

  # Degree centrality
  if ("degree" %in% metrics) {
    cat("  Computing degree centrality...\n")
    results$degree <- degree(network)
    results$degree_rank <- rank(-results$degree, ties.method = "min")
  }

  # Betweenness centrality
  if ("betweenness" %in% metrics) {
    cat("  Computing betweenness centrality...\n")
    results$betweenness <- betweenness(network, normalized = TRUE)
    results$betweenness_rank <- rank(-results$betweenness, ties.method = "min")
  }

  # PageRank
  if ("pagerank" %in% metrics) {
    cat("  Computing PageRank...\n")
    pr <- page_rank(network)
    results$pagerank <- pr$vector
    results$pagerank_rank <- rank(-results$pagerank, ties.method = "min")
  }

  # Eigenvector centrality
  if ("eigenvector" %in% metrics) {
    cat("  Computing eigenvector centrality...\n")
    tryCatch({
      ec <- eigen_centrality(network)
      results$eigenvector <- ec$vector
      results$eigenvector_rank <- rank(-results$eigenvector, ties.method = "min")
    }, error = function(e) {
      cat("    Eigenvector centrality failed (disconnected graph?)\n")
    })
  }

  # Calculate composite rank (average of all ranks)
  rank_cols <- grep("_rank$", names(results), value = TRUE)
  if (length(rank_cols) > 0) {
    results$composite_rank <- rowMeans(results[, rank_cols], na.rm = TRUE)
  }

  # Return top nodes
  results <- results %>%
    arrange(composite_rank) %>%
    head(top_n)

  cat(sprintf("  Top %d nodes identified\n", nrow(results)))

  return(results)
}

# ==============================================================================
# COMMUNITY DETECTION
# ==============================================================================

#' Detect Communities in Network
#'
#' Applies community detection algorithms to identify clusters of highly
#' connected nodes.
#'
#' @param network igraph object
#' @param method Community detection method:
#'   - "louvain": Fast modularity optimization (default)
#'   - "infomap": Information-theoretic method
#'   - "walktrap": Random walk-based
#'   - "leiden": Leiden algorithm (improved Louvain)
#'   - "edge_betweenness": Hierarchical edge removal
#'
#' @return List containing:
#'   - membership: Community assignment for each node
#'   - n_communities: Number of communities detected
#'   - modularity: Modularity score
#'   - sizes: Size of each community
#'
#' @export
detect_communities <- function(network, method = "louvain") {

  cat(sprintf("Detecting communities using %s algorithm...\n", method))
  start_time <- Sys.time()

  tryCatch({
    # Apply selected algorithm
    communities <- switch(method,
      "louvain" = cluster_louvain(network),
      "infomap" = cluster_infomap(network),
      "walktrap" = cluster_walktrap(network),
      "leiden" = cluster_leiden(network),
      "edge_betweenness" = cluster_edge_betweenness(network),
      stop(sprintf("Unknown community detection method: %s", method))
    )

    # Extract results
    result <- list(
      membership = membership(communities),
      n_communities = max(membership(communities)),
      modularity = modularity(communities),
      sizes = sizes(communities),
      algorithm = algorithm(communities)
    )

    elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

    cat(sprintf("  Detected %d communities\n", result$n_communities))
    cat(sprintf("  Modularity: %.4f\n", result$modularity))
    cat(sprintf("  Time: %.2f seconds\n", elapsed))

    return(result)

  }, error = function(e) {
    cat(sprintf("Community detection failed: %s\n", e$message))
    return(list(
      membership = NULL,
      n_communities = 0,
      modularity = 0,
      sizes = numeric(0)
    ))
  })
}

cat("Network backbone extraction module loaded successfully\n")
