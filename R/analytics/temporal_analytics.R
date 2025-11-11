# Temporal Analytics Module
# Monitor Legislativo v4 - Time-based Analysis
# ==============================================

library(dplyr)
library(tidyr)

#' Calculate Decade-by-Decade Trends
#'
#' @param db_connection Database connection
#' @return Data frame with decade statistics
#' @export
calculate_decade_trends <- function(db_connection) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      SELECT
        FLOOR(ano / 10) * 10 AS decade_start,
        COUNT(*) AS total_documents,
        COUNT(DISTINCT estado) AS states_active,
        COUNT(DISTINCT tipo) AS document_types,
        MIN(ano) AS earliest_year,
        MAX(ano) AS latest_year
      FROM documents
      WHERE ano IS NOT NULL
        AND ano >= 1820  -- Filter out invalid years
        AND ano <= EXTRACT(YEAR FROM CURRENT_DATE)
      GROUP BY FLOOR(ano / 10)
      ORDER BY decade_start
    "

    result <- DBI::dbGetQuery(db_connection, query)

    # Add decade labels
    result$decade_label <- paste0(result$decade_start, "s")

    # Calculate growth rates
    if (nrow(result) > 1) {
      result$growth_from_previous <- c(NA, diff(result$total_documents))
      result$growth_pct <- c(NA, round(diff(result$total_documents) / result$total_documents[-nrow(result)] * 100, 1))
    }

    return(result)

  }, error = function(e) {
    message("Error calculating decade trends: ", e$message)
    return(NULL)
  })
}


#' Analyze Seasonal Publication Patterns
#'
#' @param db_connection Database connection
#' @param years_back Number of recent years to analyze
#' @return Data frame with monthly/quarterly statistics
#' @export
analyze_seasonal_patterns <- function(db_connection, years_back = 5) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    start_year <- as.integer(format(Sys.Date(), "%Y")) - years_back

    query <- "
      SELECT
        EXTRACT(MONTH FROM data_publicacao) AS month,
        EXTRACT(QUARTER FROM data_publicacao) AS quarter,
        COUNT(*) AS document_count,
        AVG(COUNT(*)) OVER (PARTITION BY EXTRACT(MONTH FROM data_publicacao)) AS avg_per_month
      FROM documents
      WHERE data_publicacao IS NOT NULL
        AND ano >= $1
      GROUP BY EXTRACT(MONTH FROM data_publicacao), EXTRACT(QUARTER FROM data_publicacao)
      ORDER BY month
    "

    result <- DBI::dbGetQuery(db_connection, query, list(start_year))

    # Add month names in Portuguese
    month_names_pt <- c(
      "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
      "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"
    )

    if (nrow(result) > 0) {
      result$month_name <- month_names_pt[result$month]
      result$quarter_name <- paste0("Q", result$quarter)
    }

    return(result)

  }, error = function(e) {
    message("Error analyzing seasonal patterns: ", e$message)
    return(NULL)
  })
}


#' Detect Historical Legislative Milestones
#'
#' @param db_connection Database connection
#' @return Data frame with significant years and events
#' @export
detect_legislative_milestones <- function(db_connection) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      WITH yearly_counts AS (
        SELECT
          ano AS year,
          COUNT(*) AS doc_count,
          COUNT(DISTINCT tipo) AS type_count,
          COUNT(DISTINCT estado) AS state_count
        FROM documents
        WHERE ano IS NOT NULL
        GROUP BY ano
      ),
      stats AS (
        SELECT
          AVG(doc_count) AS avg_docs,
          STDDEV(doc_count) AS stddev_docs
        FROM yearly_counts
      )
      SELECT
        yc.year,
        yc.doc_count,
        yc.type_count,
        yc.state_count,
        ROUND((yc.doc_count - s.avg_docs) / NULLIF(s.stddev_docs, 0), 2) AS z_score,
        CASE
          WHEN (yc.doc_count - s.avg_docs) / NULLIF(s.stddev_docs, 0) > 2 THEN 'Alto'
          WHEN (yc.doc_count - s.avg_docs) / NULLIF(s.stddev_docs, 0) < -2 THEN 'Baixo'
          ELSE 'Normal'
        END AS activity_level
      FROM yearly_counts yc
      CROSS JOIN stats s
      WHERE (yc.doc_count - s.avg_docs) / NULLIF(s.stddev_docs, 0) > 2
         OR (yc.doc_count - s.avg_docs) / NULLIF(s.stddev_docs, 0) < -2
      ORDER BY ABS((yc.doc_count - s.avg_docs) / NULLIF(s.stddev_docs, 0)) DESC
      LIMIT 20
    "

    result <- DBI::dbGetQuery(db_connection, query)

    # Add context for known Brazilian historical events
    if (nrow(result) > 0) {
      result$potential_context <- sapply(result$year, function(yr) {
        case_when(
          yr == 1988 ~ "Constituição Federal",
          yr >= 1964 && yr <= 1985 ~ "Regime Militar",
          yr == 1889 ~ "Proclamação da República",
          yr >= 2003 && yr <= 2010 ~ "Governo Lula",
          yr >= 2011 && yr <= 2016 ~ "Governo Dilma",
          yr >= 2019 ~ "Governo Bolsonaro/Lula",
          TRUE ~ ""
        )
      })
    }

    return(result)

  }, error = function(e) {
    message("Error detecting milestones: ", e$message)
    return(NULL)
  })
}


#' Calculate Legislative Cycles Analysis
#'
#' @param db_connection Database connection
#' @param state Optional state filter
#' @return Data frame with cycle analysis
#' @export
analyze_legislative_cycles <- function(db_connection, state = NULL) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    # Analyze 4-year cycles (election cycles in Brazil)
    query <- "
      SELECT
        FLOOR((ano - 1990) / 4.0) AS cycle_number,
        (FLOOR((ano - 1990) / 4.0) * 4 + 1990) AS cycle_start_year,
        COUNT(*) AS total_docs,
        COUNT(DISTINCT tipo) AS doc_types,
        COUNT(DISTINCT estado) AS states_active
      FROM documents
      WHERE ano >= 1990
    "

    if (!is.null(state)) {
      query <- paste0(query, " AND estado = $1")
      result <- DBI::dbGetQuery(db_connection, query, list(state))
    } else {
      result <- DBI::dbGetQuery(db_connection, query)
    }

    query <- paste0(query, "
      GROUP BY FLOOR((ano - 1990) / 4.0)
      ORDER BY cycle_number
    ")

    if (!is.null(state)) {
      result <- DBI::dbGetQuery(db_connection, query, list(state))
    } else {
      result <- DBI::dbGetQuery(db_connection, query)
    }

    # Add cycle labels
    if (nrow(result) > 0) {
      result$cycle_end_year <- result$cycle_start_year + 3
      result$cycle_label <- paste0(result$cycle_start_year, "-", result$cycle_end_year)

      # Calculate cycle averages
      if (nrow(result) > 1) {
        result$deviation_from_avg <- result$total_docs - mean(result$total_docs)
        result$is_above_average <- result$total_docs > mean(result$total_docs)
      }
    }

    return(result)

  }, error = function(e) {
    message("Error analyzing legislative cycles: ", e$message)
    return(NULL)
  })
}


#' Calculate Time Series Forecast
#'
#' @param db_connection Database connection
#' @param years_ahead Number of years to forecast
#' @return Data frame with historical and forecasted values
#' @export
calculate_legislative_forecast <- function(db_connection, years_ahead = 3) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    # Get historical data
    query <- "
      SELECT
        ano AS year,
        COUNT(*) AS document_count
      FROM documents
      WHERE ano >= 2000
        AND ano <= EXTRACT(YEAR FROM CURRENT_DATE)
      GROUP BY ano
      ORDER BY ano
    "

    historical <- DBI::dbGetQuery(db_connection, query)

    if (nrow(historical) < 5) {
      message("Insufficient data for forecasting")
      return(historical)
    }

    # Simple linear regression forecast
    model <- lm(document_count ~ year, data = historical)

    current_year <- as.integer(format(Sys.Date(), "%Y"))
    future_years <- (current_year + 1):(current_year + years_ahead)

    forecast_data <- data.frame(
      year = future_years,
      document_count = predict(model, newdata = data.frame(year = future_years)),
      is_forecast = TRUE
    )

    historical$is_forecast <- FALSE

    result <- rbind(
      historical,
      forecast_data
    )

    # Add confidence intervals (simple ±10%)
    result$lower_bound <- ifelse(result$is_forecast,
                                 result$document_count * 0.9,
                                 NA)
    result$upper_bound <- ifelse(result$is_forecast,
                                 result$document_count * 1.1,
                                 NA)

    return(result)

  }, error = function(e) {
    message("Error calculating forecast: ", e$message)
    return(NULL)
  })
}


#' Analyze Legislative Velocity (Speed of Change)
#'
#' @param db_connection Database connection
#' @param window_years Rolling window size for velocity calculation
#' @return Data frame with velocity metrics
#' @export
analyze_legislative_velocity <- function(db_connection, window_years = 3) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- sprintf("
      WITH yearly_counts AS (
        SELECT
          ano AS year,
          COUNT(*) AS doc_count
        FROM documents
        WHERE ano >= 1990
        GROUP BY ano
        ORDER BY ano
      ),
      rolling_avg AS (
        SELECT
          year,
          doc_count,
          AVG(doc_count) OVER (
            ORDER BY year
            ROWS BETWEEN %d PRECEDING AND CURRENT ROW
          ) AS rolling_avg_%dy
        FROM yearly_counts
      )
      SELECT
        year,
        doc_count,
        rolling_avg_%dy AS rolling_average,
        doc_count - LAG(doc_count) OVER (ORDER BY year) AS absolute_change,
        ROUND(
          ((doc_count - LAG(doc_count) OVER (ORDER BY year))::numeric /
          NULLIF(LAG(doc_count) OVER (ORDER BY year), 0) * 100),
          2
        ) AS pct_change
      FROM rolling_avg
      ORDER BY year
    ", window_years - 1, window_years, window_years)

    result <- DBI::dbGetQuery(db_connection, query)

    # Calculate acceleration (change in velocity)
    if (nrow(result) > 2) {
      result$acceleration <- c(NA, NA, diff(result$absolute_change, lag = 1))
    }

    return(result)

  }, error = function(e) {
    message("Error analyzing velocity: ", e$message)
    return(NULL)
  })
}


# Export all functions
.export_temporal_analytics <- function() {
  list(
    calculate_decade_trends = calculate_decade_trends,
    analyze_seasonal_patterns = analyze_seasonal_patterns,
    detect_legislative_milestones = detect_legislative_milestones,
    analyze_legislative_cycles = analyze_legislative_cycles,
    calculate_legislative_forecast = calculate_legislative_forecast,
    analyze_legislative_velocity = analyze_legislative_velocity
  )
}
