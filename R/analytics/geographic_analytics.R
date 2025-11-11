# Geographic Analytics Module
# Monitor Legislativo v4 - State-level and Regional Analysis
# ===========================================================

library(dplyr)
library(tidyr)

#' Calculate State Rankings by Various Metrics
#'
#' @param db_connection Database connection
#' @param metric Metric to rank by ("total_docs", "recent_activity", "productivity", "diversity")
#' @param limit Number of top states to return (default 27 for all states)
#' @return Data frame with ranked states
#' @export
calculate_state_rankings <- function(db_connection, metric = "total_docs", limit = 27) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- switch(metric,
      "total_docs" = "
        SELECT
          estado AS state,
          COUNT(*) AS value,
          'Total de Documentos' AS metric_name
        FROM documents
        WHERE estado IS NOT NULL AND estado != ''
        GROUP BY estado
        ORDER BY value DESC
        LIMIT $1
      ",

      "recent_activity" = sprintf("
        SELECT
          estado AS state,
          COUNT(*) AS value,
          'Atividade Recente (5 anos)' AS metric_name
        FROM documents
        WHERE estado IS NOT NULL AND estado != ''
          AND ano >= %d
        GROUP BY estado
        ORDER BY value DESC
        LIMIT $1
      ", as.integer(format(Sys.Date(), "%Y")) - 5),

      "productivity" = sprintf("
        SELECT
          estado AS state,
          ROUND(COUNT(*)::numeric / COUNT(DISTINCT ano), 2) AS value,
          'Produtividade (docs/ano)' AS metric_name
        FROM documents
        WHERE estado IS NOT NULL AND estado != ''
          AND ano >= %d
        GROUP BY estado
        HAVING COUNT(DISTINCT ano) > 0
        ORDER BY value DESC
        LIMIT $1
      ", as.integer(format(Sys.Date(), "%Y")) - 10),

      "diversity" = "
        SELECT
          estado AS state,
          COUNT(DISTINCT tipo) AS value,
          'Diversidade de Tipos' AS metric_name
        FROM documents
        WHERE estado IS NOT NULL AND estado != ''
          AND tipo IS NOT NULL AND tipo != ''
        GROUP BY estado
        ORDER BY value DESC
        LIMIT $1
      "
    )

    result <- DBI::dbGetQuery(db_connection, query, list(limit))
    result$rank <- 1:nrow(result)
    return(result)

  }, error = function(e) {
    message("Error calculating state rankings: ", e$message)
    return(NULL)
  })
}


#' Compare States Head-to-Head
#'
#' @param db_connection Database connection
#' @param state1 First state code
#' @param state2 Second state code
#' @return Data frame with comparison metrics
#' @export
compare_states <- function(db_connection, state1, state2) {

  if (is.null(db_connection) || is.null(state1) || is.null(state2)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      SELECT
        estado AS state,
        COUNT(*) AS total_documents,
        COUNT(DISTINCT tipo) AS document_types,
        COUNT(DISTINCT ano) AS years_covered,
        MIN(ano) AS earliest_year,
        MAX(ano) AS latest_year,
        COUNT(DISTINCT municipio) FILTER (WHERE municipio IS NOT NULL) AS municipalities
      FROM documents
      WHERE estado IN ($1, $2)
      GROUP BY estado
    "

    result <- DBI::dbGetQuery(db_connection, query, list(state1, state2))

    # Calculate percentage differences
    if (nrow(result) == 2) {
      result$docs_diff_pct <- c(
        NA,
        round((result$total_documents[2] - result$total_documents[1]) / result$total_documents[1] * 100, 1)
      )
    }

    return(result)

  }, error = function(e) {
    message("Error comparing states: ", e$message)
    return(NULL)
  })
}


#' Calculate Regional Aggregated Statistics
#'
#' @param db_connection Database connection
#' @return Data frame with regional statistics
#' @export
calculate_regional_statistics <- function(db_connection) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  # Define Brazilian regions
  regions <- list(
    Norte = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
    Nordeste = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
    "Centro-Oeste" = c("DF", "GO", "MT", "MS"),
    Sudeste = c("ES", "MG", "RJ", "SP"),
    Sul = c("PR", "RS", "SC")
  )

  tryCatch({
    results_list <- list()

    for (region_name in names(regions)) {
      states <- regions[[region_name]]
      state_list <- paste0("'", paste(states, collapse = "','"), "'")

      query <- sprintf("
        SELECT
          '%s' AS region,
          COUNT(*) AS total_docs,
          COUNT(DISTINCT estado) AS states_covered,
          COUNT(DISTINCT tipo) AS document_types,
          MIN(ano) AS earliest_year,
          MAX(ano) AS latest_year,
          ROUND(AVG(ano), 0) AS avg_year
        FROM documents
        WHERE estado IN (%s)
      ", region_name, state_list)

      result <- DBI::dbGetQuery(db_connection, query)
      results_list[[region_name]] <- result
    }

    combined <- do.call(rbind, results_list)
    rownames(combined) <- NULL
    return(combined)

  }, error = function(e) {
    message("Error calculating regional statistics: ", e$message)
    return(NULL)
  })
}


#' Calculate Geographic Hotspots (Top Legislative Activity Clusters)
#'
#' @param db_connection Database connection
#' @param threshold Minimum number of documents to be considered a hotspot
#' @return Data frame with hotspot information
#' @export
calculate_geographic_hotspots <- function(db_connection, threshold = 100) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      SELECT
        estado AS state,
        municipio,
        COUNT(*) AS document_count,
        COUNT(DISTINCT tipo) AS document_types,
        MAX(ano) AS latest_year,
        MIN(ano) AS earliest_year
      FROM documents
      WHERE estado IS NOT NULL AND estado != ''
        AND municipio IS NOT NULL AND municipio != ''
      GROUP BY estado, municipio
      HAVING COUNT(*) >= $1
      ORDER BY document_count DESC
      LIMIT 50
    "

    result <- DBI::dbGetQuery(db_connection, query, list(threshold))
    result$hotspot_rank <- 1:nrow(result)
    result$activity_span_years <- result$latest_year - result$earliest_year + 1

    return(result)

  }, error = function(e) {
    message("Error calculating geographic hotspots: ", e$message)
    return(NULL)
  })
}


#' Analyze State Legislative Patterns Over Time
#'
#' @param db_connection Database connection
#' @param state State code to analyze
#' @param years_back Number of years to analyze (default 10)
#' @return Data frame with temporal pattern analysis
#' @export
analyze_state_patterns <- function(db_connection, state, years_back = 10) {

  if (is.null(db_connection) || is.null(state)) {
    return(NULL)
  }

  tryCatch({
    start_year <- as.integer(format(Sys.Date(), "%Y")) - years_back

    query <- "
      SELECT
        ano AS year,
        COUNT(*) AS total_docs,
        COUNT(DISTINCT tipo) AS doc_types,
        ARRAY_AGG(DISTINCT tipo) AS type_list
      FROM documents
      WHERE estado = $1
        AND ano >= $2
      GROUP BY ano
      ORDER BY ano
    "

    result <- DBI::dbGetQuery(db_connection, query, list(state, start_year))

    # Calculate year-over-year growth
    if (nrow(result) > 1) {
      result$yoy_growth <- c(NA, diff(result$total_docs))
      result$yoy_growth_pct <- c(NA, round(diff(result$total_docs) / result$total_docs[-nrow(result)] * 100, 1))
    }

    return(result)

  }, error = function(e) {
    message("Error analyzing state patterns: ", e$message)
    return(NULL)
  })
}


#' Calculate Cross-State Legislative Similarity
#'
#' @param db_connection Database connection
#' @param reference_state State to compare against
#' @param top_n Number of most similar states to return
#' @return Data frame with similarity scores
#' @export
calculate_state_similarity <- function(db_connection, reference_state, top_n = 10) {

  if (is.null(db_connection) || is.null(reference_state)) {
    return(NULL)
  }

  tryCatch({
    # Get document type distribution for reference state
    ref_query <- "
      SELECT tipo, COUNT(*) AS count
      FROM documents
      WHERE estado = $1
        AND tipo IS NOT NULL AND tipo != ''
      GROUP BY tipo
    "
    ref_dist <- DBI::dbGetQuery(db_connection, ref_query, list(reference_state))

    # Get all other states
    states_query <- "
      SELECT DISTINCT estado
      FROM documents
      WHERE estado IS NOT NULL
        AND estado != ''
        AND estado != $1
    "
    other_states <- DBI::dbGetQuery(db_connection, states_query, list(reference_state))

    # Calculate similarity for each state
    similarity_scores <- data.frame(
      state = character(),
      similarity_score = numeric(),
      common_types = integer(),
      stringsAsFactors = FALSE
    )

    for (state in other_states$estado) {
      state_query <- "
        SELECT tipo, COUNT(*) AS count
        FROM documents
        WHERE estado = $1
          AND tipo IS NOT NULL AND tipo != ''
        GROUP BY tipo
      "
      state_dist <- DBI::dbGetQuery(db_connection, state_query, list(state))

      # Calculate Jaccard similarity on document types
      common_types <- intersect(ref_dist$tipo, state_dist$tipo)
      all_types <- union(ref_dist$tipo, state_dist$tipo)
      similarity <- length(common_types) / length(all_types)

      similarity_scores <- rbind(
        similarity_scores,
        data.frame(
          state = state,
          similarity_score = round(similarity, 3),
          common_types = length(common_types)
        )
      )
    }

    # Sort and return top N
    similarity_scores <- similarity_scores[order(-similarity_scores$similarity_score), ]
    result <- head(similarity_scores, top_n)
    result$rank <- 1:nrow(result)

    return(result)

  }, error = function(e) {
    message("Error calculating state similarity: ", e$message)
    return(NULL)
  })
}


# Export all functions
.export_geographic_analytics <- function() {
  list(
    calculate_state_rankings = calculate_state_rankings,
    compare_states = compare_states,
    calculate_regional_statistics = calculate_regional_statistics,
    calculate_geographic_hotspots = calculate_geographic_hotspots,
    analyze_state_patterns = analyze_state_patterns,
    calculate_state_similarity = calculate_state_similarity
  )
}
