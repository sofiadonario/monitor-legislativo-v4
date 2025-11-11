# Content Analytics Module
# Monitor Legislativo v4 - Document Content and Type Analysis
# =============================================================

library(dplyr)
library(tidyr)

#' Analyze Document Type Evolution Over Time
#'
#' @param db_connection Database connection
#' @param years_back Number of years to analyze
#' @return Data frame with type evolution data
#' @export
analyze_document_type_evolution <- function(db_connection, years_back = 20) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    start_year <- as.integer(format(Sys.Date(), "%Y")) - years_back

    query <- "
      SELECT
        tipo AS doc_type,
        ano AS year,
        COUNT(*) AS count,
        ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (PARTITION BY ano), 2) AS percentage
      FROM documents
      WHERE tipo IS NOT NULL AND tipo != ''
        AND ano >= $1
      GROUP BY tipo, ano
      ORDER BY ano, count DESC
    "

    result <- DBI::dbGetQuery(db_connection, query, list(start_year))

    # Calculate type popularity rank per year
    if (nrow(result) > 0) {
      result <- result %>%
        group_by(year) %>%
        mutate(rank = rank(-count, ties.method = "first")) %>%
        ungroup() %>%
        as.data.frame()
    }

    return(result)

  }, error = function(e) {
    message("Error analyzing document type evolution: ", e$message)
    return(NULL)
  })
}


#' Calculate Authority Level Distribution Trends
#'
#' @param db_connection Database connection
#' @return Data frame with authority level statistics
#' @export
analyze_authority_distribution <- function(db_connection) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      WITH authority_classified AS (
        SELECT
          ano AS year,
          CASE
            WHEN estado IS NULL OR estado = '' OR estado = 'Federal' THEN 'Federal'
            WHEN municipio IS NOT NULL AND municipio != '' THEN 'Municipal'
            ELSE 'Estadual'
          END AS authority_level,
          COUNT(*) AS doc_count
        FROM documents
        WHERE ano >= 1990
        GROUP BY ano,
          CASE
            WHEN estado IS NULL OR estado = '' OR estado = 'Federal' THEN 'Federal'
            WHEN municipio IS NOT NULL AND municipio != '' THEN 'Municipal'
            ELSE 'Estadual'
          END
      )
      SELECT
        year,
        authority_level,
        doc_count,
        ROUND(100.0 * doc_count / SUM(doc_count) OVER (PARTITION BY year), 2) AS percentage,
        SUM(doc_count) OVER (PARTITION BY year) AS total_year_docs
      FROM authority_classified
      ORDER BY year, authority_level
    "

    result <- DBI::dbGetQuery(db_connection, query)

    # Calculate federal/state/municipal balance score
    if (nrow(result) > 0) {
      result <- result %>%
        group_by(year) %>%
        mutate(
          diversity_score = n_distinct(authority_level),
          balance_score = 100 - sd(percentage, na.rm = TRUE)
        ) %>%
        ungroup() %>%
        as.data.frame()
    }

    return(result)

  }, error = function(e) {
    message("Error analyzing authority distribution: ", e$message)
    return(NULL)
  })
}


#' Analyze Transport Theme Legislation Deep Dive
#'
#' @param db_connection Database connection
#' @return Data frame with transport-specific analysis
#' @export
analyze_transport_theme <- function(db_connection) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      WITH transport_docs AS (
        SELECT
          id,
          ano,
          estado,
          tipo,
          titulo,
          CASE
            WHEN LOWER(titulo) LIKE '%ônibus%' OR LOWER(titulo) LIKE '%onibus%' THEN 'Ônibus'
            WHEN LOWER(titulo) LIKE '%metrô%' OR LOWER(titulo) LIKE '%metro%' THEN 'Metrô'
            WHEN LOWER(titulo) LIKE '%rodov%' THEN 'Rodoviário'
            WHEN LOWER(titulo) LIKE '%ferrov%' THEN 'Ferroviário'
            WHEN LOWER(titulo) LIKE '%aérea%' OR LOWER(titulo) LIKE '%aereo%' THEN 'Aéreo'
            WHEN LOWER(titulo) LIKE '%hidrov%' OR LOWER(titulo) LIKE '%porto%' THEN 'Hidroviário'
            WHEN LOWER(titulo) LIKE '%biciclet%' OR LOWER(titulo) LIKE '%ciclov%' THEN 'Ciclovia'
            WHEN LOWER(titulo) LIKE '%mobilidade%' THEN 'Mobilidade Urbana'
            WHEN LOWER(titulo) LIKE '%trânsito%' OR LOWER(titulo) LIKE '%transito%' THEN 'Trânsito'
            ELSE 'Transporte Geral'
          END AS transport_category
        FROM documents
        WHERE LOWER(titulo) LIKE '%transport%'
           OR LOWER(titulo) LIKE '%trânsit%'
           OR LOWER(titulo) LIKE '%mobilidade%'
           OR LOWER(titulo) LIKE '%ônibus%'
           OR LOWER(titulo) LIKE '%metrô%'
           OR LOWER(titulo) LIKE '%rodov%'
      )
      SELECT
        transport_category,
        COUNT(*) AS document_count,
        COUNT(DISTINCT estado) AS states_covered,
        COUNT(DISTINCT tipo) AS document_types,
        MIN(ano) AS earliest_year,
        MAX(ano) AS latest_year
      FROM transport_docs
      GROUP BY transport_category
      ORDER BY document_count DESC
    "

    result <- DBI::dbGetQuery(db_connection, query)

    # Calculate percentage of total transport docs
    if (nrow(result) > 0) {
      total_transport <- sum(result$document_count)
      result$percentage <- round(100 * result$document_count / total_transport, 2)
    }

    return(result)

  }, error = function(e) {
    message("Error analyzing transport theme: ", e$message)
    return(NULL)
  })
}


#' Calculate Document Quality Metrics by Category
#'
#' @param data Data frame with documents (must include quality columns)
#' @return Data frame with quality analysis by category
#' @export
analyze_quality_by_category <- function(data) {

  if (is.null(data) || nrow(data) == 0) {
    return(NULL)
  }

  # Check if quality metrics exist
  has_quality <- all(c("text_quality", "completeness_score") %in% names(data))

  if (!has_quality) {
    message("Quality metrics not available")
    return(NULL)
  }

  tryCatch({
    result <- data %>%
      filter(!is.na(tipo)) %>%
      group_by(tipo) %>%
      summarise(
        document_count = n(),
        avg_text_quality = mean(text_quality, na.rm = TRUE),
        avg_completeness = mean(completeness_score, na.rm = TRUE),
        overall_quality = (mean(text_quality, na.rm = TRUE) + mean(completeness_score, na.rm = TRUE)) / 2,
        pct_high_quality = round(100 * sum(text_quality > 0.8 & completeness_score > 0.8, na.rm = TRUE) / n(), 2),
        pct_low_quality = round(100 * sum(text_quality < 0.5 | completeness_score < 0.5, na.rm = TRUE) / n(), 2),
        .groups = "drop"
      ) %>%
      arrange(desc(overall_quality)) %>%
      as.data.frame()

    result$quality_grade <- sapply(result$overall_quality, function(q) {
      if (is.na(q)) return("N/A")
      if (q >= 0.9) return("A")
      if (q >= 0.8) return("B")
      if (q >= 0.7) return("C")
      if (q >= 0.6) return("D")
      return("F")
    })

    return(result)

  }, error = function(e) {
    message("Error analyzing quality by category: ", e$message)
    return(NULL)
  })
}


#' Analyze Most Common Legal Terms
#'
#' @param db_connection Database connection
#' @param limit Number of top terms to return
#' @return Data frame with term frequencies
#' @export
analyze_common_legal_terms <- function(db_connection, limit = 50) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    # Use PostgreSQL full-text search to extract terms
    query <- "
      WITH term_stats AS (
        SELECT
          word,
          COUNT(*) AS frequency,
          COUNT(DISTINCT id) AS document_count
        FROM documents,
        LATERAL (
          SELECT unnest(tsvector_to_array(to_tsvector('portuguese', titulo))) AS word
        ) AS words
        WHERE titulo IS NOT NULL
          AND LENGTH(word) > 3  -- Filter short words
        GROUP BY word
      )
      SELECT
        word AS term,
        frequency,
        document_count,
        ROUND(100.0 * document_count / (SELECT COUNT(DISTINCT id) FROM documents), 2) AS doc_percentage
      FROM term_stats
      WHERE word NOT IN ('artigo', 'lei', 'decreto', 'para', 'sobre', 'pela', 'pelo')  -- Common stopwords
      ORDER BY frequency DESC
      LIMIT $1
    "

    result <- DBI::dbGetQuery(db_connection, query, list(limit))
    result$rank <- 1:nrow(result)

    return(result)

  }, error = function(e) {
    message("Error analyzing legal terms: ", e$message)
    return(NULL)
  })
}


#' Analyze Document Length Distribution
#'
#' @param db_connection Database connection
#' @return Data frame with length statistics
#' @export
analyze_document_length <- function(db_connection) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      SELECT
        tipo AS doc_type,
        COUNT(*) AS document_count,
        ROUND(AVG(LENGTH(titulo)), 0) AS avg_title_length,
        ROUND(AVG(LENGTH(content)), 0) AS avg_content_length,
        MIN(LENGTH(titulo)) AS min_title_length,
        MAX(LENGTH(titulo)) AS max_title_length,
        PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY LENGTH(titulo)) AS median_title_length
      FROM documents
      WHERE tipo IS NOT NULL AND tipo != ''
        AND titulo IS NOT NULL
      GROUP BY tipo
      HAVING COUNT(*) > 10  -- Only types with sufficient data
      ORDER BY document_count DESC
    "

    result <- DBI::dbGetQuery(db_connection, query)

    # Categorize by length
    if (nrow(result) > 0 && "avg_title_length" %in% names(result)) {
      result$length_category <- sapply(result$avg_title_length, function(len) {
        if (is.na(len)) return("Unknown")
        if (len < 50) return("Curto")
        if (len < 100) return("Médio")
        if (len < 200) return("Longo")
        return("Muito Longo")
      })
    }

    return(result)

  }, error = function(e) {
    message("Error analyzing document length: ", e$message)
    return(NULL)
  })
}


#' Detect Emerging Topics
#'
#' @param db_connection Database connection
#' @param recent_years Number of recent years to consider "emerging"
#' @param comparison_years Number of older years for comparison
#' @return Data frame with emerging topic analysis
#' @export
detect_emerging_topics <- function(db_connection, recent_years = 3, comparison_years = 10) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    current_year <- as.integer(format(Sys.Date(), "%Y"))
    recent_start <- current_year - recent_years
    comparison_start <- current_year - comparison_years - recent_years

    query <- "
      WITH recent_terms AS (
        SELECT
          word,
          COUNT(*) AS recent_freq
        FROM documents,
        LATERAL (
          SELECT unnest(tsvector_to_array(to_tsvector('portuguese', titulo))) AS word
        ) AS words
        WHERE ano >= $1
          AND LENGTH(word) > 4
        GROUP BY word
      ),
      older_terms AS (
        SELECT
          word,
          COUNT(*) AS older_freq
        FROM documents,
        LATERAL (
          SELECT unnest(tsvector_to_array(to_tsvector('portuguese', titulo))) AS word
        ) AS words
        WHERE ano >= $2 AND ano < $1
          AND LENGTH(word) > 4
        GROUP BY word
      )
      SELECT
        r.word AS term,
        r.recent_freq,
        COALESCE(o.older_freq, 0) AS older_freq,
        ROUND(
          CASE
            WHEN COALESCE(o.older_freq, 0) = 0 THEN 1000
            ELSE (r.recent_freq::numeric / o.older_freq) * 100
          END,
          2
        ) AS growth_rate_pct
      FROM recent_terms r
      LEFT JOIN older_terms o ON r.word = o.word
      WHERE r.recent_freq >= 5  -- Minimum frequency threshold
      ORDER BY growth_rate_pct DESC
      LIMIT 30
    "

    result <- DBI::dbGetQuery(db_connection, query, list(recent_start, comparison_start))

    # Categorize emergence level
    if (nrow(result) > 0) {
      result$emergence_level <- sapply(result$growth_rate_pct, function(rate) {
        if (is.na(rate)) return("Unknown")
        if (rate >= 500) return("Explosivo")
        if (rate >= 200) return("Muito Alto")
        if (rate >= 150) return("Alto")
        return("Moderado")
      })
    }

    return(result)

  }, error = function(e) {
    message("Error detecting emerging topics: ", e$message)
    return(NULL)
  })
}


# Export all functions
.export_content_analytics <- function() {
  list(
    analyze_document_type_evolution = analyze_document_type_evolution,
    analyze_authority_distribution = analyze_authority_distribution,
    analyze_transport_theme = analyze_transport_theme,
    analyze_quality_by_category = analyze_quality_by_category,
    analyze_common_legal_terms = analyze_common_legal_terms,
    analyze_document_length = analyze_document_length,
    detect_emerging_topics = detect_emerging_topics
  )
}
