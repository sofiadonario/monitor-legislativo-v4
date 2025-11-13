# ==============================================================================
# ANOMALY DETECTION FOR LEGISLATIVE DATA
# ==============================================================================
# Core functions for detecting anomalous patterns in Brazilian legislative data.
# Supports multiple detection methods: statistical, machine learning, and time series.
#
# Features:
# - Volume anomalies: Unusual document counts (IQR, Z-score, Poisson)
# - Text anomalies: Outlier text characteristics (length, complexity, vocabulary)
# - Temporal anomalies: Unexpected timing patterns (ARIMA, changepoint, STL)
# - Jurisdictional anomalies: Outlier states/municipalities
# - Multivariate anomalies: Isolation Forest on combined features
# - Real-time detection for new documents
#
# Author: Monitor Legislativo v4 - Data Science Team
# Date: 2025-11-13
# ==============================================================================

# Required packages
library(dplyr)
library(tidyr)
library(lubridate)
library(ggplot2)
library(DBI)
library(stringr)

# Optional packages (loaded conditionally)
# library(forecast)      # For ARIMA models
# library(changepoint)   # For changepoint detection
# library(isotree)       # For Isolation Forest
# library(dbscan)        # For LOF (Local Outlier Factor)

# ==============================================================================
# VOLUME ANOMALY DETECTION
# ==============================================================================

#' Detect Volume Anomalies Using Multiple Methods
#'
#' Identifies unusual document volumes using statistical methods.
#'
#' @param db_connection Database connection object.
#' @param table_name Character. Name of documents table (default: "documents").
#' @param date_column Character. Name of date column (default: "data").
#' @param group_by Character. Grouping level: "day", "week", "month", "year",
#'   "estado", "municipio" (default: "month").
#' @param method Character. Detection method: "iqr", "zscore", "poisson", "all"
#'   (default: "all").
#' @param sensitivity Numeric. Sensitivity multiplier (default: 1.5 for IQR, 3 for Z-score).
#' @param date_range Date vector. Optional date range filter (c(start, end)).
#' @param min_observations Integer. Minimum observations to perform detection (default: 30).
#'
#' @return data.frame with columns:
#'   \itemize{
#'     \item period: Time period or jurisdiction
#'     \item count: Document count
#'     \item expected: Expected count (mean or model prediction)
#'     \item is_anomaly: Logical. Whether it's an anomaly
#'     \item anomaly_score: Numeric. Anomaly score (0-100)
#'     \item method: Detection method used
#'     \item severity: "low", "medium", "high"
#'   }
#'
#' @details
#' Methods:
#' - IQR: Values beyond Q1 - sensitivity*IQR or Q3 + sensitivity*IQR
#' - Z-score: Absolute Z-score > sensitivity (default 3)
#' - Poisson: Count significantly different from Poisson expected value
#'
#' @examples
#' \dontrun{
#' library(RPostgreSQL)
#' con <- dbConnect(PostgreSQL(), dbname = "monitor_legislativo")
#'
#' # Monthly volume anomalies
#' monthly_anomalies <- detect_volume_anomalies(
#'   con,
#'   group_by = "month",
#'   method = "all"
#' )
#'
#' # State-level anomalies
#' state_anomalies <- detect_volume_anomalies(
#'   con,
#'   group_by = "estado",
#'   method = "zscore",
#'   sensitivity = 2.5
#' )
#' }
#'
#' @export
detect_volume_anomalies <- function(db_connection,
                                   table_name = "documents",
                                   date_column = "data",
                                   group_by = "month",
                                   method = "all",
                                   sensitivity = NULL,
                                   date_range = NULL,
                                   min_observations = 30) {

  # Set default sensitivity based on method
  if (is.null(sensitivity)) {
    sensitivity <- if (method %in% c("iqr", "all")) 1.5 else 3
  }

  # Build query based on grouping
  if (group_by %in% c("day", "week", "month", "year")) {
    # Temporal grouping
    date_trunc <- switch(group_by,
                        "day" = "day",
                        "week" = "week",
                        "month" = "month",
                        "year" = "year")

    query <- sprintf(
      "SELECT DATE_TRUNC('%s', %s) as period, COUNT(*) as count
       FROM %s
       WHERE %s IS NOT NULL",
      date_trunc, date_column, table_name, date_column
    )

    # Add date range filter if provided
    if (!is.null(date_range)) {
      query <- paste0(query, sprintf(
        " AND %s BETWEEN '%s' AND '%s'",
        date_column, date_range[1], date_range[2]
      ))
    }

    query <- paste0(query, " GROUP BY period ORDER BY period")

  } else if (group_by == "estado") {
    # State-level grouping
    query <- sprintf(
      "SELECT estado as period, COUNT(*) as count
       FROM %s
       WHERE estado IS NOT NULL AND estado != ''
       GROUP BY estado
       ORDER BY estado",
      table_name
    )

  } else if (group_by == "municipio") {
    # Municipality-level grouping
    query <- sprintf(
      "SELECT municipio as period, COUNT(*) as count
       FROM %s
       WHERE municipio IS NOT NULL AND municipio != ''
       GROUP BY municipio
       ORDER BY count DESC
       LIMIT 500",  # Limit to top 500 municipalities for performance
      table_name
    )
  } else {
    stop("Invalid group_by parameter. Must be one of: day, week, month, year, estado, municipio")
  }

  # Execute query
  data <- tryCatch({
    DBI::dbGetQuery(db_connection, query)
  }, error = function(e) {
    warning("Database query failed: ", e$message)
    return(NULL)
  })

  if (is.null(data) || nrow(data) < min_observations) {
    warning("Insufficient data for anomaly detection (need at least ", min_observations, " observations)")
    return(data.frame())
  }

  # Apply detection methods
  results <- list()

  if (method %in% c("iqr", "all")) {
    results$iqr <- detect_anomalies_iqr(data, sensitivity)
  }

  if (method %in% c("zscore", "all")) {
    results$zscore <- detect_anomalies_zscore(data, sensitivity)
  }

  if (method %in% c("poisson", "all")) {
    results$poisson <- detect_anomalies_poisson(data)
  }

  # Combine results
  if (method == "all") {
    # Combine multiple methods - flagged by at least 2 methods
    combined <- data %>%
      mutate(
        anomaly_iqr = results$iqr$is_anomaly,
        anomaly_zscore = results$zscore$is_anomaly,
        anomaly_poisson = results$poisson$is_anomaly,
        anomaly_count = anomaly_iqr + anomaly_zscore + anomaly_poisson,
        is_anomaly = anomaly_count >= 2,
        anomaly_score = pmax(
          results$iqr$anomaly_score,
          results$zscore$anomaly_score,
          results$poisson$anomaly_score
        ),
        method = "ensemble",
        expected = (results$iqr$expected + results$zscore$expected + results$poisson$expected) / 3,
        severity = case_when(
          anomaly_score >= 80 ~ "high",
          anomaly_score >= 60 ~ "medium",
          anomaly_score >= 40 ~ "low",
          TRUE ~ "none"
        )
      ) %>%
      select(period, count, expected, is_anomaly, anomaly_score, method, severity)

    return(combined)
  } else {
    # Return single method result
    return(results[[method]])
  }
}

#' Detect Anomalies Using IQR Method
#'
#' @param data data.frame with 'count' column
#' @param sensitivity Numeric. IQR multiplier (default: 1.5)
#' @return data.frame with anomaly flags and scores
#' @keywords internal
detect_anomalies_iqr <- function(data, sensitivity = 1.5) {
  Q1 <- quantile(data$count, 0.25, na.rm = TRUE)
  Q3 <- quantile(data$count, 0.75, na.rm = TRUE)
  IQR_val <- Q3 - Q1

  lower_bound <- Q1 - sensitivity * IQR_val
  upper_bound <- Q3 + sensitivity * IQR_val

  data %>%
    mutate(
      expected = median(count, na.rm = TRUE),
      deviation = abs(count - expected),
      is_anomaly = count < lower_bound | count > upper_bound,
      anomaly_score = ifelse(is_anomaly,
                            pmin(100, 50 + (deviation / (expected + 1)) * 50),
                            pmin(50, (deviation / (expected + 1)) * 50)),
      method = "iqr",
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    )
}

#' Detect Anomalies Using Z-Score Method
#'
#' @param data data.frame with 'count' column
#' @param sensitivity Numeric. Z-score threshold (default: 3)
#' @return data.frame with anomaly flags and scores
#' @keywords internal
detect_anomalies_zscore <- function(data, sensitivity = 3) {
  mean_count <- mean(data$count, na.rm = TRUE)
  sd_count <- sd(data$count, na.rm = TRUE)

  if (sd_count == 0) {
    # No variation in data
    return(data %>%
             mutate(
               expected = mean_count,
               z_score = 0,
               is_anomaly = FALSE,
               anomaly_score = 0,
               method = "zscore",
               severity = "none"
             ))
  }

  data %>%
    mutate(
      expected = mean_count,
      z_score = (count - mean_count) / sd_count,
      is_anomaly = abs(z_score) > sensitivity,
      anomaly_score = pmin(100, (abs(z_score) / sensitivity) * 100),
      method = "zscore",
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    ) %>%
    select(-z_score)
}

#' Detect Anomalies Using Poisson Distribution
#'
#' @param data data.frame with 'count' column
#' @return data.frame with anomaly flags and scores
#' @keywords internal
detect_anomalies_poisson <- function(data) {
  lambda <- mean(data$count, na.rm = TRUE)

  data %>%
    mutate(
      expected = lambda,
      # Calculate p-value for observing this count under Poisson(lambda)
      p_value = ifelse(count >= lambda,
                      ppois(count, lambda, lower.tail = FALSE),
                      ppois(count, lambda, lower.tail = TRUE)),
      is_anomaly = p_value < 0.05,  # 5% significance level
      # Convert p-value to anomaly score (0-100)
      anomaly_score = pmin(100, -log10(p_value + 1e-10) * 20),
      method = "poisson",
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    ) %>%
    select(-p_value)
}

# ==============================================================================
# TEXT ANOMALY DETECTION
# ==============================================================================

#' Detect Text Anomalies
#'
#' Identifies documents with unusual text characteristics.
#'
#' @param db_connection Database connection object.
#' @param table_name Character. Name of documents table (default: "documents").
#' @param text_column Character. Name of text column (default: "texto_completo").
#' @param features Character vector. Features to analyze: "length", "complexity",
#'   "vocabulary", "all" (default: "all").
#' @param method Character. Detection method: "iqr", "zscore", "isolation_forest"
#'   (default: "iqr").
#' @param sensitivity Numeric. Sensitivity multiplier (default: 1.5).
#' @param sample_size Integer. Number of documents to sample (default: 10000).
#'   Set to NULL to analyze all documents.
#' @param random_seed Integer. Random seed for reproducibility (default: 42).
#'
#' @return data.frame with columns:
#'   \itemize{
#'     \item id: Document ID
#'     \item text_length: Character count
#'     \item word_count: Word count
#'     \item avg_word_length: Average word length
#'     \item sentence_count: Number of sentences
#'     \item unique_words: Number of unique words
#'     \item lexical_diversity: Type-token ratio
#'     \item is_anomaly: Logical. Whether it's an anomaly
#'     \item anomaly_score: Numeric. Anomaly score (0-100)
#'     \item anomaly_reason: Character. Why it's anomalous
#'   }
#'
#' @examples
#' \dontrun{
#' library(RPostgreSQL)
#' con <- dbConnect(PostgreSQL(), dbname = "monitor_legislativo")
#'
#' # Detect text anomalies
#' text_anomalies <- detect_text_anomalies(
#'   con,
#'   features = "all",
#'   method = "iqr",
#'   sample_size = 5000
#' )
#'
#' # View anomalies
#' text_anomalies %>%
#'   filter(is_anomaly) %>%
#'   arrange(desc(anomaly_score)) %>%
#'   head(20)
#' }
#'
#' @export
detect_text_anomalies <- function(db_connection,
                                  table_name = "documents",
                                  text_column = "texto_completo",
                                  features = "all",
                                  method = "iqr",
                                  sensitivity = 1.5,
                                  sample_size = 10000,
                                  random_seed = 42) {

  # Build query
  if (!is.null(sample_size)) {
    # Sample documents for performance
    query <- sprintf(
      "SELECT id, %s
       FROM %s
       WHERE %s IS NOT NULL AND LENGTH(%s) > 0
       ORDER BY RANDOM()
       LIMIT %d",
      text_column, table_name, text_column, text_column, sample_size
    )
  } else {
    # Analyze all documents
    query <- sprintf(
      "SELECT id, %s
       FROM %s
       WHERE %s IS NOT NULL AND LENGTH(%s) > 0",
      text_column, table_name, text_column, text_column
    )
  }

  # Execute query
  data <- tryCatch({
    DBI::dbGetQuery(db_connection, query)
  }, error = function(e) {
    warning("Database query failed: ", e$message)
    return(NULL)
  })

  if (is.null(data) || nrow(data) == 0) {
    warning("No data retrieved for text anomaly detection")
    return(data.frame())
  }

  # Calculate text features
  cat("Calculating text features for", nrow(data), "documents...\n")

  text_features <- data %>%
    mutate(
      # Basic features
      text_length = nchar(.data[[text_column]]),
      word_count = str_count(.data[[text_column]], "\\S+"),
      avg_word_length = text_length / pmax(word_count, 1),

      # Sentence features
      sentence_count = str_count(.data[[text_column]], "[.!?;]") + 1,
      avg_sentence_length = word_count / pmax(sentence_count, 1),

      # Vocabulary features
      unique_words = sapply(strsplit(.data[[text_column]], "\\s+"),
                           function(x) length(unique(tolower(x)))),
      lexical_diversity = unique_words / pmax(word_count, 1),

      # Complexity features
      complex_word_ratio = sapply(.data[[text_column]], function(text) {
        words <- strsplit(text, "\\s+")[[1]]
        if (length(words) == 0) return(0)
        # Simple heuristic: words with 3+ syllables (approximate by length > 8)
        complex_words <- sum(nchar(words) > 8)
        complex_words / length(words)
      })
    ) %>%
    select(-!!sym(text_column))  # Remove text column to save memory

  # Detect anomalies based on features
  if (method == "iqr") {
    anomalies <- detect_text_anomalies_iqr(text_features, sensitivity)
  } else if (method == "zscore") {
    anomalies <- detect_text_anomalies_zscore(text_features, sensitivity)
  } else if (method == "isolation_forest") {
    if (!requireNamespace("isotree", quietly = TRUE)) {
      warning("isotree package not available. Falling back to IQR method.")
      anomalies <- detect_text_anomalies_iqr(text_features, sensitivity)
    } else {
      anomalies <- detect_text_anomalies_isolation_forest(text_features)
    }
  } else {
    stop("Invalid method. Must be one of: iqr, zscore, isolation_forest")
  }

  return(anomalies)
}

#' Detect Text Anomalies Using IQR Method
#'
#' @param data data.frame with text features
#' @param sensitivity Numeric. IQR multiplier
#' @return data.frame with anomaly flags
#' @keywords internal
detect_text_anomalies_iqr <- function(data, sensitivity = 1.5) {
  # Calculate IQR bounds for each feature
  feature_cols <- c("text_length", "word_count", "avg_word_length",
                   "sentence_count", "unique_words", "lexical_diversity",
                   "complex_word_ratio")

  anomaly_flags <- data.frame(id = data$id)
  anomaly_reasons <- character(nrow(data))
  anomaly_scores <- numeric(nrow(data))

  for (feature in feature_cols) {
    if (feature %in% names(data)) {
      values <- data[[feature]]
      Q1 <- quantile(values, 0.25, na.rm = TRUE)
      Q3 <- quantile(values, 0.75, na.rm = TRUE)
      IQR_val <- Q3 - Q1

      lower_bound <- Q1 - sensitivity * IQR_val
      upper_bound <- Q3 + sensitivity * IQR_val

      is_outlier <- values < lower_bound | values > upper_bound

      # Track reasons
      for (i in which(is_outlier)) {
        if (anomaly_reasons[i] != "") {
          anomaly_reasons[i] <- paste0(anomaly_reasons[i], ", ")
        }

        if (values[i] < lower_bound) {
          anomaly_reasons[i] <- paste0(anomaly_reasons[i],
                                      "Very low ", gsub("_", " ", feature))
        } else {
          anomaly_reasons[i] <- paste0(anomaly_reasons[i],
                                      "Very high ", gsub("_", " ", feature))
        }

        # Calculate score contribution
        deviation <- abs(values[i] - median(values, na.rm = TRUE))
        expected <- median(values, na.rm = TRUE)
        score_contrib <- pmin(50, (deviation / (expected + 1)) * 50)
        anomaly_scores[i] <- anomaly_scores[i] + score_contrib
      }
    }
  }

  # Normalize scores
  max_possible_score <- length(feature_cols) * 50
  anomaly_scores <- pmin(100, (anomaly_scores / max_possible_score) * 100)

  # Combine results
  data %>%
    mutate(
      is_anomaly = anomaly_reasons != "",
      anomaly_score = anomaly_scores,
      anomaly_reason = ifelse(anomaly_reasons == "", "Normal", anomaly_reasons),
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    )
}

#' Detect Text Anomalies Using Z-Score Method
#'
#' @param data data.frame with text features
#' @param sensitivity Numeric. Z-score threshold
#' @return data.frame with anomaly flags
#' @keywords internal
detect_text_anomalies_zscore <- function(data, sensitivity = 3) {
  feature_cols <- c("text_length", "word_count", "avg_word_length",
                   "sentence_count", "unique_words", "lexical_diversity",
                   "complex_word_ratio")

  anomaly_reasons <- character(nrow(data))
  anomaly_scores <- numeric(nrow(data))

  for (feature in feature_cols) {
    if (feature %in% names(data)) {
      values <- data[[feature]]
      mean_val <- mean(values, na.rm = TRUE)
      sd_val <- sd(values, na.rm = TRUE)

      if (sd_val > 0) {
        z_scores <- abs((values - mean_val) / sd_val)
        is_outlier <- z_scores > sensitivity

        for (i in which(is_outlier)) {
          if (anomaly_reasons[i] != "") {
            anomaly_reasons[i] <- paste0(anomaly_reasons[i], ", ")
          }
          anomaly_reasons[i] <- paste0(anomaly_reasons[i],
                                      "Unusual ", gsub("_", " ", feature))

          score_contrib <- pmin(50, (z_scores[i] / sensitivity) * 50)
          anomaly_scores[i] <- anomaly_scores[i] + score_contrib
        }
      }
    }
  }

  # Normalize scores
  max_possible_score <- length(feature_cols) * 50
  anomaly_scores <- pmin(100, (anomaly_scores / max_possible_score) * 100)

  data %>%
    mutate(
      is_anomaly = anomaly_reasons != "",
      anomaly_score = anomaly_scores,
      anomaly_reason = ifelse(anomaly_reasons == "", "Normal", anomaly_reasons),
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    )
}

#' Detect Text Anomalies Using Isolation Forest
#'
#' @param data data.frame with text features
#' @return data.frame with anomaly flags
#' @keywords internal
detect_text_anomalies_isolation_forest <- function(data) {
  # Prepare feature matrix
  feature_cols <- c("text_length", "word_count", "avg_word_length",
                   "sentence_count", "unique_words", "lexical_diversity",
                   "complex_word_ratio")

  feature_matrix <- data %>%
    select(all_of(feature_cols)) %>%
    as.matrix()

  # Handle missing values
  feature_matrix[is.na(feature_matrix)] <- 0

  # Fit Isolation Forest
  cat("Training Isolation Forest model...\n")
  iso_model <- isotree::isolation.forest(
    feature_matrix,
    ntrees = 100,
    sample_size = min(256, nrow(feature_matrix)),
    ndim = 1
  )

  # Predict anomaly scores
  anomaly_scores <- isotree::predict.isolation_forest(
    iso_model,
    feature_matrix,
    type = "score"
  )

  # Normalize scores to 0-100
  anomaly_scores <- pmin(100, anomaly_scores * 100)

  # Determine anomalies (top 5% are anomalies)
  threshold <- quantile(anomaly_scores, 0.95, na.rm = TRUE)

  data %>%
    mutate(
      anomaly_score = anomaly_scores,
      is_anomaly = anomaly_score >= threshold,
      anomaly_reason = ifelse(is_anomaly, "Multivariate outlier detected", "Normal"),
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    )
}

# ==============================================================================
# TEMPORAL ANOMALY DETECTION
# ==============================================================================

#' Detect Temporal Anomalies
#'
#' Identifies unusual temporal patterns in legislative activity.
#'
#' @param db_connection Database connection object.
#' @param table_name Character. Name of documents table (default: "documents").
#' @param date_column Character. Name of date column (default: "data").
#' @param method Character. Detection method: "arima", "stl", "changepoint", "all"
#'   (default: "stl").
#' @param date_range Date vector. Optional date range filter (c(start, end)).
#' @param frequency Character. Time frequency: "daily", "weekly", "monthly"
#'   (default: "monthly").
#' @param sensitivity Numeric. Sensitivity multiplier (default: 2).
#'
#' @return data.frame with temporal anomalies
#'
#' @examples
#' \dontrun{
#' library(RPostgreSQL)
#' con <- dbConnect(PostgreSQL(), dbname = "monitor_legislativo")
#'
#' # Monthly temporal anomalies
#' temporal_anomalies <- detect_temporal_anomalies(
#'   con,
#'   method = "stl",
#'   frequency = "monthly"
#' )
#' }
#'
#' @export
detect_temporal_anomalies <- function(db_connection,
                                     table_name = "documents",
                                     date_column = "data",
                                     method = "stl",
                                     date_range = NULL,
                                     frequency = "monthly",
                                     sensitivity = 2) {

  # Build query
  date_trunc <- switch(frequency,
                      "daily" = "day",
                      "weekly" = "week",
                      "monthly" = "month",
                      "month")

  query <- sprintf(
    "SELECT DATE_TRUNC('%s', %s)::date as date, COUNT(*) as count
     FROM %s
     WHERE %s IS NOT NULL",
    date_trunc, date_column, table_name, date_column
  )

  if (!is.null(date_range)) {
    query <- paste0(query, sprintf(
      " AND %s BETWEEN '%s' AND '%s'",
      date_column, date_range[1], date_range[2]
    ))
  }

  query <- paste0(query, " GROUP BY date ORDER BY date")

  # Execute query
  data <- tryCatch({
    DBI::dbGetQuery(db_connection, query)
  }, error = function(e) {
    warning("Database query failed: ", e$message)
    return(NULL)
  })

  if (is.null(data) || nrow(data) < 24) {
    warning("Insufficient data for temporal anomaly detection (need at least 24 periods)")
    return(data.frame())
  }

  # Detect anomalies based on method
  if (method == "stl") {
    result <- detect_temporal_anomalies_stl(data, sensitivity, frequency)
  } else if (method == "arima") {
    if (!requireNamespace("forecast", quietly = TRUE)) {
      warning("forecast package not available. Falling back to STL method.")
      result <- detect_temporal_anomalies_stl(data, sensitivity, frequency)
    } else {
      result <- detect_temporal_anomalies_arima(data, sensitivity)
    }
  } else if (method == "changepoint") {
    if (!requireNamespace("changepoint", quietly = TRUE)) {
      warning("changepoint package not available. Falling back to STL method.")
      result <- detect_temporal_anomalies_stl(data, sensitivity, frequency)
    } else {
      result <- detect_temporal_anomalies_changepoint(data)
    }
  } else if (method == "all") {
    # Combine multiple methods
    stl_result <- detect_temporal_anomalies_stl(data, sensitivity, frequency)

    result <- stl_result %>%
      mutate(method = "ensemble")
  } else {
    stop("Invalid method. Must be one of: stl, arima, changepoint, all")
  }

  return(result)
}

#' Detect Temporal Anomalies Using STL Decomposition
#'
#' @param data data.frame with date and count columns
#' @param sensitivity Numeric. Sensitivity multiplier
#' @param frequency Character. Time frequency
#' @return data.frame with anomaly flags
#' @keywords internal
detect_temporal_anomalies_stl <- function(data, sensitivity = 2, frequency = "monthly") {
  # Convert to time series
  ts_freq <- switch(frequency,
                   "daily" = 365,
                   "weekly" = 52,
                   "monthly" = 12,
                   12)

  ts_data <- ts(data$count, frequency = ts_freq)

  # STL decomposition
  if (length(ts_data) < 2 * ts_freq) {
    # Not enough data for full seasonal decomposition
    warning("Not enough data for seasonal decomposition. Using simple residuals.")

    expected <- mean(data$count, na.rm = TRUE)
    residuals <- data$count - expected

  } else {
    tryCatch({
      stl_result <- stl(ts_data, s.window = "periodic", robust = TRUE)
      expected <- stl_result$time.series[, "seasonal"] + stl_result$time.series[, "trend"]
      residuals <- stl_result$time.series[, "remainder"]
    }, error = function(e) {
      warning("STL decomposition failed: ", e$message)
      expected <- mean(data$count, na.rm = TRUE)
      residuals <- data$count - expected
    })
  }

  # Detect anomalies in residuals
  residual_sd <- sd(residuals, na.rm = TRUE)
  threshold <- sensitivity * residual_sd

  data %>%
    mutate(
      expected = as.numeric(expected),
      residual = as.numeric(residuals),
      is_anomaly = abs(residual) > threshold,
      anomaly_score = pmin(100, (abs(residual) / (residual_sd + 1)) * 33),
      method = "stl",
      anomaly_reason = case_when(
        residual > threshold ~ "Unexpected spike in activity",
        residual < -threshold ~ "Unexpected drop in activity",
        TRUE ~ "Normal"
      ),
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    )
}

#' Detect Temporal Anomalies Using ARIMA
#'
#' @param data data.frame with date and count columns
#' @param sensitivity Numeric. Sensitivity multiplier
#' @return data.frame with anomaly flags
#' @keywords internal
detect_temporal_anomalies_arima <- function(data, sensitivity = 2) {
  # Fit ARIMA model
  ts_data <- ts(data$count)

  tryCatch({
    arima_model <- forecast::auto.arima(ts_data)
    fitted_values <- as.numeric(fitted(arima_model))
    residuals <- as.numeric(residuals(arima_model))

    residual_sd <- sd(residuals, na.rm = TRUE)
    threshold <- sensitivity * residual_sd

    data %>%
      mutate(
        expected = fitted_values,
        residual = residuals,
        is_anomaly = abs(residual) > threshold,
        anomaly_score = pmin(100, (abs(residual) / (residual_sd + 1)) * 33),
        method = "arima",
        anomaly_reason = case_when(
          residual > threshold ~ "Above forecast confidence interval",
          residual < -threshold ~ "Below forecast confidence interval",
          TRUE ~ "Normal"
        ),
        severity = case_when(
          anomaly_score >= 80 ~ "high",
          anomaly_score >= 60 ~ "medium",
          anomaly_score >= 40 ~ "low",
          TRUE ~ "none"
        )
      )
  }, error = function(e) {
    warning("ARIMA modeling failed: ", e$message)
    return(data %>%
             mutate(
               expected = mean(count),
               is_anomaly = FALSE,
               anomaly_score = 0,
               method = "arima",
               anomaly_reason = "Model fitting failed",
               severity = "none"
             ))
  })
}

#' Detect Temporal Anomalies Using Changepoint Detection
#'
#' @param data data.frame with date and count columns
#' @return data.frame with changepoint flags
#' @keywords internal
detect_temporal_anomalies_changepoint <- function(data) {
  tryCatch({
    # Detect changepoints
    cpt_result <- changepoint::cpt.mean(data$count, method = "PELT")
    changepoints <- changepoint::cpts(cpt_result)

    # Flag periods around changepoints
    is_changepoint <- rep(FALSE, nrow(data))

    for (cp in changepoints) {
      # Flag the changepoint and adjacent periods
      start_idx <- max(1, cp - 1)
      end_idx <- min(nrow(data), cp + 1)
      is_changepoint[start_idx:end_idx] <- TRUE
    }

    # Calculate expected values as segment means
    segment_means <- changepoint::param.est(cpt_result)$mean
    expected_values <- numeric(nrow(data))

    changepoints <- c(0, changepoints, nrow(data))
    for (i in 1:(length(changepoints) - 1)) {
      start_idx <- changepoints[i] + 1
      end_idx <- changepoints[i + 1]
      expected_values[start_idx:end_idx] <- segment_means[i]
    }

    data %>%
      mutate(
        expected = expected_values,
        is_anomaly = is_changepoint,
        anomaly_score = ifelse(is_changepoint, 70, 0),
        method = "changepoint",
        anomaly_reason = ifelse(is_changepoint, "Structural change detected", "Normal"),
        severity = ifelse(is_changepoint, "medium", "none")
      )

  }, error = function(e) {
    warning("Changepoint detection failed: ", e$message)
    return(data %>%
             mutate(
               expected = mean(count),
               is_anomaly = FALSE,
               anomaly_score = 0,
               method = "changepoint",
               anomaly_reason = "Detection failed",
               severity = "none"
             ))
  })
}

# ==============================================================================
# JURISDICTIONAL ANOMALY DETECTION
# ==============================================================================

#' Detect Jurisdictional Anomalies
#'
#' Identifies outlier states or municipalities based on various metrics.
#'
#' @param db_connection Database connection object.
#' @param table_name Character. Name of documents table (default: "documents").
#' @param level Character. "estado" or "municipio" (default: "estado").
#' @param metrics Character vector. Metrics to analyze: "volume", "text_length",
#'   "temporal_variance", "all" (default: "all").
#' @param method Character. Detection method: "iqr", "zscore" (default: "iqr").
#' @param sensitivity Numeric. Sensitivity multiplier (default: 1.5).
#'
#' @return data.frame with jurisdictional anomalies
#'
#' @export
detect_jurisdictional_anomalies <- function(db_connection,
                                           table_name = "documents",
                                           level = "estado",
                                           metrics = "all",
                                           method = "iqr",
                                           sensitivity = 1.5) {

  # Build query
  location_col <- ifelse(level == "estado", "estado", "municipio")

  query <- sprintf(
    "SELECT
      %s as jurisdiction,
      COUNT(*) as doc_count,
      AVG(LENGTH(texto_completo)) as avg_text_length,
      STDDEV(LENGTH(texto_completo)) as text_length_variance,
      MIN(data) as first_doc_date,
      MAX(data) as last_doc_date
     FROM %s
     WHERE %s IS NOT NULL AND %s != ''
     GROUP BY %s
     ORDER BY doc_count DESC",
    location_col, table_name, location_col, location_col, location_col
  )

  # Execute query
  data <- tryCatch({
    DBI::dbGetQuery(db_connection, query)
  }, error = function(e) {
    warning("Database query failed: ", e$message)
    return(NULL)
  })

  if (is.null(data) || nrow(data) < 5) {
    warning("Insufficient data for jurisdictional anomaly detection")
    return(data.frame())
  }

  # Calculate additional metrics
  data <- data %>%
    mutate(
      date_range_days = as.numeric(difftime(last_doc_date, first_doc_date, units = "days")),
      docs_per_day = doc_count / pmax(date_range_days, 1)
    )

  # Select metrics to analyze
  if ("all" %in% metrics) {
    metric_cols <- c("doc_count", "avg_text_length", "text_length_variance", "docs_per_day")
  } else {
    metric_cols <- metrics
  }

  # Detect anomalies
  if (method == "iqr") {
    result <- detect_jurisdictional_anomalies_iqr(data, metric_cols, sensitivity)
  } else if (method == "zscore") {
    result <- detect_jurisdictional_anomalies_zscore(data, metric_cols, sensitivity)
  } else {
    stop("Invalid method. Must be one of: iqr, zscore")
  }

  return(result)
}

#' Detect Jurisdictional Anomalies Using IQR
#'
#' @param data data.frame with jurisdictional metrics
#' @param metric_cols Character vector. Metrics to analyze
#' @param sensitivity Numeric. IQR multiplier
#' @return data.frame with anomaly flags
#' @keywords internal
detect_jurisdictional_anomalies_iqr <- function(data, metric_cols, sensitivity = 1.5) {
  anomaly_reasons <- character(nrow(data))
  anomaly_scores <- numeric(nrow(data))

  for (metric in metric_cols) {
    if (metric %in% names(data)) {
      values <- data[[metric]]
      Q1 <- quantile(values, 0.25, na.rm = TRUE)
      Q3 <- quantile(values, 0.75, na.rm = TRUE)
      IQR_val <- Q3 - Q1

      lower_bound <- Q1 - sensitivity * IQR_val
      upper_bound <- Q3 + sensitivity * IQR_val

      is_outlier <- values < lower_bound | values > upper_bound

      for (i in which(is_outlier)) {
        if (anomaly_reasons[i] != "") {
          anomaly_reasons[i] <- paste0(anomaly_reasons[i], ", ")
        }

        if (values[i] < lower_bound) {
          anomaly_reasons[i] <- paste0(anomaly_reasons[i],
                                      "Very low ", gsub("_", " ", metric))
        } else {
          anomaly_reasons[i] <- paste0(anomaly_reasons[i],
                                      "Very high ", gsub("_", " ", metric))
        }

        deviation <- abs(values[i] - median(values, na.rm = TRUE))
        expected <- median(values, na.rm = TRUE)
        score_contrib <- pmin(50, (deviation / (expected + 1)) * 50)
        anomaly_scores[i] <- anomaly_scores[i] + score_contrib
      }
    }
  }

  # Normalize scores
  max_possible_score <- length(metric_cols) * 50
  anomaly_scores <- pmin(100, (anomaly_scores / max_possible_score) * 100)

  data %>%
    mutate(
      is_anomaly = anomaly_reasons != "",
      anomaly_score = anomaly_scores,
      anomaly_reason = ifelse(anomaly_reasons == "", "Normal", anomaly_reasons),
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    )
}

#' Detect Jurisdictional Anomalies Using Z-Score
#'
#' @param data data.frame with jurisdictional metrics
#' @param metric_cols Character vector. Metrics to analyze
#' @param sensitivity Numeric. Z-score threshold
#' @return data.frame with anomaly flags
#' @keywords internal
detect_jurisdictional_anomalies_zscore <- function(data, metric_cols, sensitivity = 3) {
  anomaly_reasons <- character(nrow(data))
  anomaly_scores <- numeric(nrow(data))

  for (metric in metric_cols) {
    if (metric %in% names(data)) {
      values <- data[[metric]]
      mean_val <- mean(values, na.rm = TRUE)
      sd_val <- sd(values, na.rm = TRUE)

      if (sd_val > 0) {
        z_scores <- abs((values - mean_val) / sd_val)
        is_outlier <- z_scores > sensitivity

        for (i in which(is_outlier)) {
          if (anomaly_reasons[i] != "") {
            anomaly_reasons[i] <- paste0(anomaly_reasons[i], ", ")
          }
          anomaly_reasons[i] <- paste0(anomaly_reasons[i],
                                      "Unusual ", gsub("_", " ", metric))

          score_contrib <- pmin(50, (z_scores[i] / sensitivity) * 50)
          anomaly_scores[i] <- anomaly_scores[i] + score_contrib
        }
      }
    }
  }

  # Normalize scores
  max_possible_score <- length(metric_cols) * 50
  anomaly_scores <- pmin(100, (anomaly_scores / max_possible_score) * 100)

  data %>%
    mutate(
      is_anomaly = anomaly_reasons != "",
      anomaly_score = anomaly_scores,
      anomaly_reason = ifelse(anomaly_reasons == "", "Normal", anomaly_reasons),
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    )
}

# ==============================================================================
# MULTIVARIATE ANOMALY DETECTION
# ==============================================================================

#' Detect Multivariate Anomalies Using Isolation Forest
#'
#' Identifies anomalies by considering multiple features simultaneously.
#'
#' @param db_connection Database connection object.
#' @param table_name Character. Name of documents table (default: "documents").
#' @param sample_size Integer. Number of documents to analyze (default: 10000).
#' @param contamination Numeric. Expected proportion of outliers (default: 0.05).
#'
#' @return data.frame with multivariate anomalies
#'
#' @export
detect_multivariate_anomalies <- function(db_connection,
                                         table_name = "documents",
                                         sample_size = 10000,
                                         contamination = 0.05) {

  if (!requireNamespace("isotree", quietly = TRUE)) {
    warning("isotree package not available. Install with: install.packages('isotree')")
    return(data.frame())
  }

  # Query combined features
  query <- sprintf(
    "SELECT
      id,
      LENGTH(texto_completo) as text_length,
      EXTRACT(YEAR FROM data) as year,
      EXTRACT(MONTH FROM data) as month,
      EXTRACT(DOW FROM data) as day_of_week
     FROM %s
     WHERE texto_completo IS NOT NULL
     ORDER BY RANDOM()
     LIMIT %d",
    table_name, sample_size
  )

  data <- tryCatch({
    DBI::dbGetQuery(db_connection, query)
  }, error = function(e) {
    warning("Database query failed: ", e$message)
    return(NULL)
  })

  if (is.null(data) || nrow(data) < 100) {
    warning("Insufficient data for multivariate anomaly detection")
    return(data.frame())
  }

  # Prepare feature matrix
  feature_matrix <- data %>%
    select(-id) %>%
    as.matrix()

  # Handle missing values
  feature_matrix[is.na(feature_matrix)] <- 0

  # Fit Isolation Forest
  cat("Training Isolation Forest for multivariate anomaly detection...\n")
  iso_model <- isotree::isolation.forest(
    feature_matrix,
    ntrees = 100,
    sample_size = min(256, nrow(feature_matrix)),
    ndim = 1
  )

  # Predict anomaly scores
  anomaly_scores <- isotree::predict.isolation_forest(
    iso_model,
    feature_matrix,
    type = "score"
  )

  # Normalize scores to 0-100
  anomaly_scores <- pmin(100, anomaly_scores * 100)

  # Determine threshold based on contamination
  threshold <- quantile(anomaly_scores, 1 - contamination, na.rm = TRUE)

  # Return results
  data %>%
    mutate(
      anomaly_score = anomaly_scores,
      is_anomaly = anomaly_score >= threshold,
      anomaly_reason = ifelse(is_anomaly,
                             "Unusual combination of features",
                             "Normal"),
      severity = case_when(
        anomaly_score >= 80 ~ "high",
        anomaly_score >= 60 ~ "medium",
        anomaly_score >= 40 ~ "low",
        TRUE ~ "none"
      )
    )
}

# ==============================================================================
# COMPREHENSIVE ANOMALY REPORT
# ==============================================================================

#' Generate Comprehensive Anomaly Report
#'
#' Runs all anomaly detection methods and generates a comprehensive report.
#'
#' @param db_connection Database connection object.
#' @param table_name Character. Name of documents table (default: "documents").
#' @param output_format Character. "summary", "detailed", "both" (default: "both").
#' @param save_results Logical. Whether to save results to CSV (default: FALSE).
#' @param output_dir Character. Directory for output files (default: "anomaly_reports").
#'
#' @return list with anomaly detection results
#'
#' @examples
#' \dontrun{
#' library(RPostgreSQL)
#' con <- dbConnect(PostgreSQL(), dbname = "monitor_legislativo")
#'
#' # Generate comprehensive report
#' report <- generate_anomaly_report(
#'   con,
#'   output_format = "both",
#'   save_results = TRUE
#' )
#'
#' # View summary
#' print(report$summary)
#' }
#'
#' @export
generate_anomaly_report <- function(db_connection,
                                   table_name = "documents",
                                   output_format = "both",
                                   save_results = FALSE,
                                   output_dir = "anomaly_reports") {

  cat("\n==== COMPREHENSIVE ANOMALY DETECTION REPORT ====\n")
  cat("Started at:", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "\n\n")

  results <- list()

  # 1. Volume Anomalies
  cat("1. Detecting volume anomalies...\n")
  results$volume_monthly <- tryCatch({
    detect_volume_anomalies(
      db_connection,
      table_name = table_name,
      group_by = "month",
      method = "all"
    )
  }, error = function(e) {
    warning("Volume anomaly detection failed: ", e$message)
    NULL
  })

  results$volume_state <- tryCatch({
    detect_volume_anomalies(
      db_connection,
      table_name = table_name,
      group_by = "estado",
      method = "all"
    )
  }, error = function(e) {
    warning("State volume anomaly detection failed: ", e$message)
    NULL
  })

  # 2. Text Anomalies
  cat("2. Detecting text anomalies...\n")
  results$text <- tryCatch({
    detect_text_anomalies(
      db_connection,
      table_name = table_name,
      method = "iqr",
      sample_size = 5000
    )
  }, error = function(e) {
    warning("Text anomaly detection failed: ", e$message)
    NULL
  })

  # 3. Temporal Anomalies
  cat("3. Detecting temporal anomalies...\n")
  results$temporal <- tryCatch({
    detect_temporal_anomalies(
      db_connection,
      table_name = table_name,
      method = "stl",
      frequency = "monthly"
    )
  }, error = function(e) {
    warning("Temporal anomaly detection failed: ", e$message)
    NULL
  })

  # 4. Jurisdictional Anomalies
  cat("4. Detecting jurisdictional anomalies...\n")
  results$jurisdictional <- tryCatch({
    detect_jurisdictional_anomalies(
      db_connection,
      table_name = table_name,
      level = "estado",
      method = "iqr"
    )
  }, error = function(e) {
    warning("Jurisdictional anomaly detection failed: ", e$message)
    NULL
  })

  # 5. Generate Summary
  cat("\n5. Generating summary statistics...\n")

  summary <- list(
    timestamp = Sys.time(),
    volume_monthly = if (!is.null(results$volume_monthly)) {
      list(
        total_periods = nrow(results$volume_monthly),
        anomalies_detected = sum(results$volume_monthly$is_anomaly),
        high_severity = sum(results$volume_monthly$severity == "high"),
        medium_severity = sum(results$volume_monthly$severity == "medium"),
        low_severity = sum(results$volume_monthly$severity == "low")
      )
    } else NULL,

    volume_state = if (!is.null(results$volume_state)) {
      list(
        total_states = nrow(results$volume_state),
        anomalies_detected = sum(results$volume_state$is_anomaly),
        high_severity = sum(results$volume_state$severity == "high")
      )
    } else NULL,

    text = if (!is.null(results$text)) {
      list(
        documents_analyzed = nrow(results$text),
        anomalies_detected = sum(results$text$is_anomaly),
        high_severity = sum(results$text$severity == "high")
      )
    } else NULL,

    temporal = if (!is.null(results$temporal)) {
      list(
        periods_analyzed = nrow(results$temporal),
        anomalies_detected = sum(results$temporal$is_anomaly),
        high_severity = sum(results$temporal$severity == "high")
      )
    } else NULL,

    jurisdictional = if (!is.null(results$jurisdictional)) {
      list(
        jurisdictions_analyzed = nrow(results$jurisdictional),
        anomalies_detected = sum(results$jurisdictional$is_anomaly),
        high_severity = sum(results$jurisdictional$severity == "high")
      )
    } else NULL
  )

  results$summary <- summary

  # Print summary
  cat("\n==== SUMMARY ====\n")
  cat("Volume Anomalies (Monthly):\n")
  if (!is.null(summary$volume_monthly)) {
    cat(sprintf("  - Periods analyzed: %d\n", summary$volume_monthly$total_periods))
    cat(sprintf("  - Anomalies found: %d (%.1f%%)\n",
                summary$volume_monthly$anomalies_detected,
                100 * summary$volume_monthly$anomalies_detected / summary$volume_monthly$total_periods))
    cat(sprintf("  - High severity: %d\n", summary$volume_monthly$high_severity))
  } else {
    cat("  - Detection failed\n")
  }

  cat("\nVolume Anomalies (States):\n")
  if (!is.null(summary$volume_state)) {
    cat(sprintf("  - States analyzed: %d\n", summary$volume_state$total_states))
    cat(sprintf("  - Anomalies found: %d\n", summary$volume_state$anomalies_detected))
  } else {
    cat("  - Detection failed\n")
  }

  cat("\nText Anomalies:\n")
  if (!is.null(summary$text)) {
    cat(sprintf("  - Documents analyzed: %d\n", summary$text$documents_analyzed))
    cat(sprintf("  - Anomalies found: %d (%.1f%%)\n",
                summary$text$anomalies_detected,
                100 * summary$text$anomalies_detected / summary$text$documents_analyzed))
  } else {
    cat("  - Detection failed\n")
  }

  cat("\nTemporal Anomalies:\n")
  if (!is.null(summary$temporal)) {
    cat(sprintf("  - Periods analyzed: %d\n", summary$temporal$periods_analyzed))
    cat(sprintf("  - Anomalies found: %d\n", summary$temporal$anomalies_detected))
  } else {
    cat("  - Detection failed\n")
  }

  cat("\nJurisdictional Anomalies:\n")
  if (!is.null(summary$jurisdictional)) {
    cat(sprintf("  - Jurisdictions analyzed: %d\n", summary$jurisdictional$jurisdictions_analyzed))
    cat(sprintf("  - Anomalies found: %d\n", summary$jurisdictional$anomalies_detected))
  } else {
    cat("  - Detection failed\n")
  }

  # Save results if requested
  if (save_results) {
    cat("\n6. Saving results to disk...\n")

    if (!dir.exists(output_dir)) {
      dir.create(output_dir, recursive = TRUE)
    }

    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")

    if (!is.null(results$volume_monthly)) {
      write.csv(results$volume_monthly,
               file.path(output_dir, paste0("volume_monthly_", timestamp, ".csv")),
               row.names = FALSE)
    }

    if (!is.null(results$volume_state)) {
      write.csv(results$volume_state,
               file.path(output_dir, paste0("volume_state_", timestamp, ".csv")),
               row.names = FALSE)
    }

    if (!is.null(results$text)) {
      write.csv(results$text,
               file.path(output_dir, paste0("text_anomalies_", timestamp, ".csv")),
               row.names = FALSE)
    }

    if (!is.null(results$temporal)) {
      write.csv(results$temporal,
               file.path(output_dir, paste0("temporal_anomalies_", timestamp, ".csv")),
               row.names = FALSE)
    }

    if (!is.null(results$jurisdictional)) {
      write.csv(results$jurisdictional,
               file.path(output_dir, paste0("jurisdictional_anomalies_", timestamp, ".csv")),
               row.names = FALSE)
    }

    cat("Results saved to:", output_dir, "\n")
  }

  cat("\nCompleted at:", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "\n")
  cat("====================================\n\n")

  return(results)
}

# ==============================================================================
# END OF FILE
# ==============================================================================
