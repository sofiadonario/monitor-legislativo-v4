# ==============================================================================
# MULTI-JURISDICTIONAL COMPARISON ANALYTICS
# ==============================================================================
# Comprehensive system to compare legislative patterns across Brazilian jurisdictions
# (Federal, State, Municipal) and between individual states.
#
# Features:
# - Volume metrics: document count, growth rate, monthly average
# - Diversity metrics: document type diversity, Shannon entropy
# - Temporal metrics: seasonality, trend coefficients
# - Complexity metrics: document length, vocabulary richness
# - Cross-jurisdiction similarity analysis
# - State clustering by legislative patterns
#
# Author: Monitor Legislativo v4 - Data Science Team
# Date: 2025-11-13
# Database: PostgreSQL with 118,920+ documents
# ==============================================================================

library(dplyr)
library(tidyr)
library(DBI)

#' Compare Legislative Activity by Jurisdiction Level
#'
#' Compares Federal, Estadual (State), and Municipal jurisdiction levels
#' across multiple metrics including volume, diversity, and growth.
#'
#' @param db_connection DBI connection object to PostgreSQL database
#' @param start_year Integer. Starting year for analysis (default: 2015)
#' @param end_year Integer. Ending year for analysis (default: current year)
#' @return Data frame with jurisdiction-level comparative statistics
#'
#' @details
#' Returns metrics:
#' - doc_count: Total number of documents
#' - avg_per_month: Average documents per month
#' - growth_rate: Year-over-year growth rate (%)
#' - diversity_index: Shannon entropy of document types
#' - unique_types: Number of unique document types
#' - avg_doc_length: Average document length in characters
#' - temporal_coverage: Number of years with data
#'
#' @examples
#' \dontrun{
#' conn <- dbConnect(RPostgres::Postgres(), ...)
#' results <- compare_by_jurisdiction(conn, 2020, 2024)
#' }
#'
#' @export
compare_by_jurisdiction <- function(db_connection, start_year = 2015, end_year = NULL) {

  if (is.null(db_connection)) {
    stop("Database connection is required")
  }

  if (is.null(end_year)) {
    end_year <- as.integer(format(Sys.Date(), "%Y"))
  }

  tryCatch({

    # Build comprehensive comparison query
    query <- sprintf("
      WITH jurisdiction_data AS (
        SELECT
          COALESCE(nivel, 'Não Especificado') AS jurisdiction_level,
          ano,
          mes,
          tipo,
          LENGTH(texto_completo) AS doc_length
        FROM documents
        WHERE ano >= %d AND ano <= %d
          AND ano IS NOT NULL
      ),

      volume_metrics AS (
        SELECT
          jurisdiction_level,
          COUNT(*) AS doc_count,
          COUNT(*) / NULLIF(COUNT(DISTINCT ano || '-' || LPAD(mes::text, 2, '0')), 0)::numeric AS avg_per_month,
          COUNT(DISTINCT ano) AS temporal_coverage
        FROM jurisdiction_data
        GROUP BY jurisdiction_level
      ),

      diversity_metrics AS (
        SELECT
          jurisdiction_level,
          COUNT(DISTINCT tipo) AS unique_types,
          -- Shannon entropy calculation for document type diversity
          -SUM(p * LN(p)) AS diversity_index
        FROM (
          SELECT
            jurisdiction_level,
            tipo,
            COUNT(*)::numeric / SUM(COUNT(*)) OVER (PARTITION BY jurisdiction_level) AS p
          FROM jurisdiction_data
          WHERE tipo IS NOT NULL
          GROUP BY jurisdiction_level, tipo
        ) type_probs
        GROUP BY jurisdiction_level
      ),

      complexity_metrics AS (
        SELECT
          jurisdiction_level,
          ROUND(AVG(doc_length)::numeric, 0) AS avg_doc_length,
          PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY doc_length) AS median_doc_length
        FROM jurisdiction_data
        WHERE doc_length IS NOT NULL AND doc_length > 0
        GROUP BY jurisdiction_level
      ),

      growth_metrics AS (
        SELECT
          jurisdiction_level,
          CASE
            WHEN first_year_count > 0 THEN
              ROUND(((last_year_count - first_year_count)::numeric / first_year_count * 100), 2)
            ELSE NULL
          END AS growth_rate
        FROM (
          SELECT
            jurisdiction_level,
            SUM(CASE WHEN ano = %d THEN 1 ELSE 0 END) AS first_year_count,
            SUM(CASE WHEN ano = %d THEN 1 ELSE 0 END) AS last_year_count
          FROM jurisdiction_data
          GROUP BY jurisdiction_level
        ) year_counts
      )

      SELECT
        v.jurisdiction_level,
        v.doc_count,
        ROUND(v.avg_per_month, 2) AS avg_per_month,
        v.temporal_coverage,
        d.unique_types,
        ROUND(d.diversity_index, 3) AS diversity_index,
        c.avg_doc_length,
        c.median_doc_length,
        g.growth_rate
      FROM volume_metrics v
      LEFT JOIN diversity_metrics d ON v.jurisdiction_level = d.jurisdiction_level
      LEFT JOIN complexity_metrics c ON v.jurisdiction_level = c.jurisdiction_level
      LEFT JOIN growth_metrics g ON v.jurisdiction_level = g.jurisdiction_level
      ORDER BY v.doc_count DESC
    ", start_year, end_year, start_year, end_year)

    result <- dbGetQuery(db_connection, query)

    # Add quality score (composite metric)
    if (nrow(result) > 0) {
      result <- result %>%
        mutate(
          quality_score = scales::rescale(doc_count, to = c(0, 100)) * 0.4 +
                         scales::rescale(diversity_index, to = c(0, 100)) * 0.3 +
                         scales::rescale(temporal_coverage, to = c(0, 100)) * 0.3
        )
    }

    return(result)

  }, error = function(e) {
    message("Error in compare_by_jurisdiction: ", e$message)
    return(data.frame(
      jurisdiction_level = character(),
      doc_count = integer(),
      avg_per_month = numeric(),
      error_message = e$message
    ))
  })
}


#' Compare Specific States
#'
#' Detailed comparison of legislative activity across selected Brazilian states.
#'
#' @param db_connection DBI connection object
#' @param states_vector Character vector of state codes (e.g., c("SP", "RJ", "MG"))
#' @param start_year Integer. Starting year for analysis
#' @param end_year Integer. Ending year for analysis
#' @return Data frame with per-state comparative metrics
#'
#' @examples
#' \dontrun{
#' results <- compare_by_state(conn, c("SP", "RJ", "MG"), 2020, 2024)
#' }
#'
#' @export
compare_by_state <- function(db_connection, states_vector, start_year = 2015, end_year = NULL) {

  if (is.null(db_connection)) {
    stop("Database connection is required")
  }

  if (is.null(states_vector) || length(states_vector) == 0) {
    stop("At least one state code must be provided")
  }

  if (is.null(end_year)) {
    end_year <- as.integer(format(Sys.Date(), "%Y"))
  }

  # Validate state codes
  valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
                    "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
                    "RS", "RO", "RR", "SC", "SP", "SE", "TO")

  invalid_states <- setdiff(states_vector, valid_states)
  if (length(invalid_states) > 0) {
    warning("Invalid state codes removed: ", paste(invalid_states, collapse = ", "))
    states_vector <- intersect(states_vector, valid_states)
  }

  if (length(states_vector) == 0) {
    stop("No valid state codes provided")
  }

  tryCatch({

    # Build state comparison query
    states_list <- paste0("'", states_vector, "'", collapse = ", ")

    query <- sprintf("
      WITH state_data AS (
        SELECT
          estado,
          ano,
          mes,
          tipo,
          poder,
          LENGTH(texto_completo) AS doc_length
        FROM documents
        WHERE estado IN (%s)
          AND ano >= %d AND ano <= %d
          AND ano IS NOT NULL
      ),

      volume_metrics AS (
        SELECT
          estado AS state,
          COUNT(*) AS total_documents,
          COUNT(*) / NULLIF(COUNT(DISTINCT ano || '-' || LPAD(mes::text, 2, '0')), 0)::numeric AS docs_per_month,
          COUNT(DISTINCT ano) AS years_covered,
          MIN(ano) AS first_year,
          MAX(ano) AS last_year
        FROM state_data
        GROUP BY estado
      ),

      diversity_metrics AS (
        SELECT
          estado AS state,
          COUNT(DISTINCT tipo) AS document_types,
          COUNT(DISTINCT poder) AS branches,
          -- Shannon entropy for document type diversity
          -SUM(p * LN(p)) AS type_diversity
        FROM (
          SELECT
            estado,
            tipo,
            poder,
            COUNT(*)::numeric / SUM(COUNT(*)) OVER (PARTITION BY estado) AS p
          FROM state_data
          WHERE tipo IS NOT NULL
          GROUP BY estado, tipo, poder
        ) probs
        GROUP BY estado
      ),

      temporal_metrics AS (
        SELECT
          estado AS state,
          -- Coefficient of variation (CV) as seasonality index
          CASE
            WHEN AVG(monthly_count) > 0 THEN
              ROUND((STDDEV(monthly_count) / AVG(monthly_count) * 100)::numeric, 2)
            ELSE NULL
          END AS seasonality_index,
          -- Linear trend coefficient
          REGR_SLOPE(monthly_count, month_num) AS trend_coefficient
        FROM (
          SELECT
            estado,
            ano * 12 + mes AS month_num,
            COUNT(*) AS monthly_count
          FROM state_data
          WHERE mes IS NOT NULL
          GROUP BY estado, ano, mes
        ) monthly
        GROUP BY estado
      ),

      complexity_metrics AS (
        SELECT
          estado AS state,
          ROUND(AVG(doc_length)::numeric, 0) AS avg_length,
          PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY doc_length) AS median_length,
          PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY doc_length) AS p90_length
        FROM state_data
        WHERE doc_length IS NOT NULL AND doc_length > 0
        GROUP BY estado
      ),

      growth_metrics AS (
        SELECT
          estado AS state,
          CASE
            WHEN first_year_docs > 0 THEN
              ROUND(((last_year_docs - first_year_docs)::numeric / first_year_docs * 100), 2)
            ELSE NULL
          END AS growth_rate
        FROM (
          SELECT
            estado,
            SUM(CASE WHEN ano = %d THEN 1 ELSE 0 END) AS first_year_docs,
            SUM(CASE WHEN ano = %d THEN 1 ELSE 0 END) AS last_year_docs
          FROM state_data
          GROUP BY estado
        ) yearly
      )

      SELECT
        v.state,
        v.total_documents,
        ROUND(v.docs_per_month, 2) AS avg_docs_per_month,
        v.years_covered,
        v.first_year,
        v.last_year,
        d.document_types,
        d.branches,
        ROUND(d.type_diversity, 3) AS diversity_index,
        t.seasonality_index,
        ROUND(t.trend_coefficient::numeric, 4) AS trend_coefficient,
        c.avg_length,
        c.median_length,
        c.p90_length,
        g.growth_rate
      FROM volume_metrics v
      LEFT JOIN diversity_metrics d ON v.state = d.state
      LEFT JOIN temporal_metrics t ON v.state = t.state
      LEFT JOIN complexity_metrics c ON v.state = c.state
      LEFT JOIN growth_metrics g ON v.state = g.state
      ORDER BY v.total_documents DESC
    ", states_list, start_year, end_year, start_year, end_year)

    result <- dbGetQuery(db_connection, query)

    return(result)

  }, error = function(e) {
    message("Error in compare_by_state: ", e$message)
    return(data.frame(
      state = character(),
      total_documents = integer(),
      error_message = e$message
    ))
  })
}


#' Cross-Level Topic Analysis
#'
#' Analyzes how similar topics/keywords are addressed across different
#' jurisdiction levels (Federal, State, Municipal).
#'
#' @param db_connection DBI connection object
#' @param topic_keywords Character vector of keywords to search for
#' @return Data frame with topic distribution across jurisdiction levels
#'
#' @examples
#' \dontrun{
#' results <- cross_level_analysis(conn, c("tributário", "imposto", "ICMS"))
#' }
#'
#' @export
cross_level_analysis <- function(db_connection, topic_keywords) {

  if (is.null(db_connection)) {
    stop("Database connection is required")
  }

  if (is.null(topic_keywords) || length(topic_keywords) == 0) {
    stop("At least one keyword must be provided")
  }

  tryCatch({

    # Build keyword search pattern
    keyword_pattern <- paste0(
      "(",
      paste(sapply(topic_keywords, function(kw) {
        paste0("LOWER(titulo) LIKE '%", tolower(kw), "%' OR ",
               "LOWER(texto_completo) LIKE '%", tolower(kw), "%'")
      }), collapse = " OR "),
      ")"
    )

    query <- sprintf("
      WITH topic_docs AS (
        SELECT
          COALESCE(nivel, 'Não Especificado') AS jurisdiction_level,
          estado,
          tipo,
          ano,
          titulo,
          LENGTH(texto_completo) AS text_length
        FROM documents
        WHERE %s
          AND ano >= 2015
      )

      SELECT
        jurisdiction_level,
        COUNT(*) AS document_count,
        COUNT(DISTINCT estado) AS states_affected,
        COUNT(DISTINCT tipo) AS document_types,
        ROUND(AVG(text_length)::numeric, 0) AS avg_length,
        MIN(ano) AS earliest_year,
        MAX(ano) AS latest_year,
        -- Top document types
        STRING_AGG(DISTINCT tipo, ', ' ORDER BY tipo) FILTER (WHERE tipo IS NOT NULL) AS top_types
      FROM topic_docs
      GROUP BY jurisdiction_level
      ORDER BY document_count DESC
    ", keyword_pattern)

    result <- dbGetQuery(db_connection, query)

    # Add topic keywords as metadata
    if (nrow(result) > 0) {
      result$search_keywords <- paste(topic_keywords, collapse = ", ")
    }

    return(result)

  }, error = function(e) {
    message("Error in cross_level_analysis: ", e$message)
    return(data.frame(
      jurisdiction_level = character(),
      document_count = integer(),
      error_message = e$message
    ))
  })
}


#' State Clustering by Legislative Patterns
#'
#' Performs hierarchical clustering of Brazilian states based on their
#' legislative activity patterns (document volume, diversity, complexity).
#'
#' @param db_connection DBI connection object
#' @param start_year Integer. Starting year for analysis (default: 2015)
#' @param end_year Integer. Ending year for analysis
#' @return List containing:
#'   - cluster_data: Data frame with state features for clustering
#'   - distance_matrix: Distance matrix between states
#'   - dendrogram: hclust object for visualization
#'
#' @details
#' Clustering features:
#' - Document volume (normalized)
#' - Document type diversity (Shannon entropy)
#' - Average document complexity (length)
#' - Temporal activity (trend coefficient)
#' - Branch diversity (Executivo, Legislativo, Judiciário)
#'
#' @examples
#' \dontrun{
#' clusters <- state_clustering(conn)
#' plot(clusters$dendrogram, main = "State Clustering Dendrogram")
#' }
#'
#' @export
state_clustering <- function(db_connection, start_year = 2015, end_year = NULL) {

  if (is.null(db_connection)) {
    stop("Database connection is required")
  }

  if (is.null(end_year)) {
    end_year <- as.integer(format(Sys.Date(), "%Y"))
  }

  # Check if required packages are available
  if (!requireNamespace("stats", quietly = TRUE)) {
    stop("Package 'stats' is required for clustering")
  }

  tryCatch({

    # Get clustering features for all states
    query <- sprintf("
      WITH state_features AS (
        SELECT
          estado,
          COUNT(*) AS doc_volume,
          COUNT(DISTINCT tipo) AS type_diversity,
          AVG(LENGTH(texto_completo)) AS avg_complexity,
          COUNT(DISTINCT poder) AS branch_diversity,
          -- Temporal trend
          COALESCE(
            REGR_SLOPE(COUNT(*)::numeric, ano::numeric) OVER (PARTITION BY estado),
            0
          ) AS temporal_trend
        FROM documents
        WHERE estado IS NOT NULL
          AND estado NOT IN ('Federal', 'Nacional', 'Justiça Trabalho', 'Não Identificado')
          AND LENGTH(estado) = 2  -- Valid state codes only
          AND ano >= %d AND ano <= %d
        GROUP BY estado, ano
      )

      SELECT
        estado AS state,
        SUM(doc_volume) AS total_volume,
        MAX(type_diversity) AS max_type_diversity,
        ROUND(AVG(avg_complexity)::numeric, 0) AS avg_document_length,
        MAX(branch_diversity) AS branch_count,
        ROUND(AVG(temporal_trend)::numeric, 2) AS trend_slope
      FROM state_features
      GROUP BY estado
      HAVING SUM(doc_volume) >= 100  -- Minimum threshold for reliable clustering
      ORDER BY estado
    ", start_year, end_year)

    cluster_data <- dbGetQuery(db_connection, query)

    if (nrow(cluster_data) < 2) {
      warning("Insufficient data for clustering (minimum 2 states required)")
      return(NULL)
    }

    # Prepare feature matrix for clustering
    rownames(cluster_data) <- cluster_data$state
    feature_matrix <- cluster_data %>%
      select(total_volume, max_type_diversity, avg_document_length,
             branch_count, trend_slope) %>%
      as.matrix()

    # Normalize features (z-score standardization)
    feature_matrix_scaled <- scale(feature_matrix)

    # Calculate distance matrix (Euclidean)
    dist_matrix <- dist(feature_matrix_scaled, method = "euclidean")

    # Perform hierarchical clustering
    hc <- hclust(dist_matrix, method = "ward.D2")

    # Cut tree into optimal number of clusters (3-5 clusters)
    optimal_k <- min(5, max(3, ceiling(nrow(cluster_data) / 5)))
    cluster_assignments <- cutree(hc, k = optimal_k)

    cluster_data$cluster <- cluster_assignments

    return(list(
      cluster_data = cluster_data,
      distance_matrix = as.matrix(dist_matrix),
      dendrogram = hc,
      optimal_clusters = optimal_k,
      feature_importance = colMeans(abs(feature_matrix_scaled))
    ))

  }, error = function(e) {
    message("Error in state_clustering: ", e$message)
    return(NULL)
  })
}


#' Temporal Jurisdiction Trends
#'
#' Time series comparison of legislative activity across jurisdiction levels.
#'
#' @param db_connection DBI connection object
#' @param metric Character. Metric to analyze: "count", "diversity",
#'   "avg_length", "complexity"
#' @param start_year Integer. Starting year (default: 2015)
#' @param end_year Integer. Ending year
#' @return Data frame with temporal trends for each jurisdiction level
#'
#' @examples
#' \dontrun{
#' trends <- temporal_jurisdiction_trends(conn, metric = "count")
#' }
#'
#' @export
temporal_jurisdiction_trends <- function(db_connection, metric = "count",
                                        start_year = 2015, end_year = NULL) {

  if (is.null(db_connection)) {
    stop("Database connection is required")
  }

  if (is.null(end_year)) {
    end_year <- as.integer(format(Sys.Date(), "%Y"))
  }

  valid_metrics <- c("count", "diversity", "avg_length", "complexity")
  if (!metric %in% valid_metrics) {
    stop("Invalid metric. Choose from: ", paste(valid_metrics, collapse = ", "))
  }

  tryCatch({

    # Build query based on selected metric
    metric_calculation <- switch(metric,
      "count" = "COUNT(*) AS value",
      "diversity" = "COUNT(DISTINCT tipo) AS value",
      "avg_length" = "ROUND(AVG(LENGTH(texto_completo))::numeric, 0) AS value",
      "complexity" = paste0(
        "ROUND(AVG(LENGTH(texto_completo))::numeric / ",
        "NULLIF(AVG(LENGTH(REGEXP_SPLIT_TO_ARRAY(texto_completo, E'\\\\s+')::text[])), 0), 2) AS value"
      )
    )

    query <- sprintf("
      SELECT
        COALESCE(nivel, 'Não Especificado') AS jurisdiction_level,
        ano AS year,
        mes AS month,
        TO_DATE(ano || '-' || LPAD(mes::text, 2, '0') || '-01', 'YYYY-MM-DD') AS date,
        %s
      FROM documents
      WHERE ano >= %d AND ano <= %d
        AND ano IS NOT NULL
        AND mes IS NOT NULL
      GROUP BY nivel, ano, mes
      ORDER BY ano, mes, nivel
    ", metric_calculation, start_year, end_year)

    result <- dbGetQuery(db_connection, query)

    # Add metric name for reference
    if (nrow(result) > 0) {
      result$metric_name <- metric
    }

    return(result)

  }, error = function(e) {
    message("Error in temporal_jurisdiction_trends: ", e$message)
    return(data.frame(
      jurisdiction_level = character(),
      year = integer(),
      month = integer(),
      value = numeric(),
      error_message = e$message
    ))
  })
}


#' Calculate Similarity Coefficients Between States
#'
#' Computes pairwise similarity scores between states based on their
#' legislative activity patterns.
#'
#' @param db_connection DBI connection object
#' @param states_vector Character vector of state codes to compare
#' @param method Character. Similarity method: "cosine", "jaccard", "correlation"
#' @return Matrix of pairwise similarity scores (0-1 scale)
#'
#' @export
calculate_state_similarity <- function(db_connection, states_vector, method = "cosine") {

  if (is.null(db_connection) || is.null(states_vector)) {
    stop("Database connection and states vector are required")
  }

  if (length(states_vector) < 2) {
    stop("At least 2 states required for similarity comparison")
  }

  tryCatch({

    states_list <- paste0("'", states_vector, "'", collapse = ", ")

    # Get document type distribution for each state
    query <- sprintf("
      SELECT
        estado AS state,
        tipo AS document_type,
        COUNT(*) AS count
      FROM documents
      WHERE estado IN (%s)
        AND tipo IS NOT NULL
        AND ano >= 2015
      GROUP BY estado, tipo
      ORDER BY estado, count DESC
    ", states_list)

    type_dist <- dbGetQuery(db_connection, query)

    # Create document-type matrix
    type_matrix <- type_dist %>%
      pivot_wider(
        names_from = document_type,
        values_from = count,
        values_fill = 0
      ) %>%
      as.data.frame()

    rownames(type_matrix) <- type_matrix$state
    type_matrix$state <- NULL
    type_matrix <- as.matrix(type_matrix)

    # Calculate similarity based on method
    similarity_matrix <- switch(method,
      "cosine" = {
        # Cosine similarity
        norm_matrix <- type_matrix / sqrt(rowSums(type_matrix^2))
        norm_matrix %*% t(norm_matrix)
      },
      "jaccard" = {
        # Jaccard similarity (binary)
        binary_matrix <- type_matrix > 0
        intersection <- binary_matrix %*% t(binary_matrix)
        union_matrix <- outer(rowSums(binary_matrix), rowSums(binary_matrix), "+") - intersection
        intersection / union_matrix
      },
      "correlation" = {
        # Pearson correlation
        cor(t(type_matrix))
      }
    )

    return(similarity_matrix)

  }, error = function(e) {
    message("Error calculating state similarity: ", e$message)
    return(NULL)
  })
}


#' Get Brazilian States List
#'
#' Returns a complete list of Brazilian states with metadata.
#'
#' @return Data frame with state codes, names, and regions
#' @export
get_brazilian_states <- function() {
  data.frame(
    code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
             "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
             "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    name = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará",
             "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
             "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará",
             "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro",
             "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", "Roraima",
             "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
    region = c("Norte", "Nordeste", "Norte", "Norte", "Nordeste", "Nordeste",
               "Centro-Oeste", "Sudeste", "Centro-Oeste", "Nordeste",
               "Centro-Oeste", "Centro-Oeste", "Sudeste", "Norte",
               "Nordeste", "Sul", "Nordeste", "Nordeste", "Sudeste",
               "Nordeste", "Sul", "Norte", "Norte",
               "Sul", "Sudeste", "Nordeste", "Norte"),
    stringsAsFactors = FALSE
  )
}
