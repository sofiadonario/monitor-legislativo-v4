# ==============================================================================
# ANOMALY SCORING AND EXPLANATION SYSTEM
# ==============================================================================
# Functions for scoring anomalies and generating human-readable explanations.
#
# Features:
# - Unified anomaly scoring (0-100 scale)
# - Severity classification (low, medium, high)
# - Contextual explanations
# - Confidence intervals
# - Historical comparisons
# - Real-time scoring for new documents
#
# Author: Monitor Legislativo v4 - Data Science Team
# Date: 2025-11-13
# ==============================================================================

library(dplyr)
library(stringr)

# ==============================================================================
# ANOMALY SCORE CALCULATION
# ==============================================================================

#' Calculate Unified Anomaly Score
#'
#' Combines multiple anomaly detection results into a single unified score.
#'
#' @param volume_score Numeric. Score from volume anomaly detection (0-100).
#' @param text_score Numeric. Score from text anomaly detection (0-100).
#' @param temporal_score Numeric. Score from temporal anomaly detection (0-100).
#' @param jurisdictional_score Numeric. Score from jurisdictional anomaly detection (0-100).
#' @param weights Named numeric vector. Weights for each component
#'   (default: equal weights).
#'
#' @return Numeric. Unified anomaly score (0-100).
#'
#' @examples
#' calculate_unified_score(
#'   volume_score = 80,
#'   text_score = 45,
#'   temporal_score = 65,
#'   jurisdictional_score = 30
#' )
#'
#' @export
calculate_unified_score <- function(volume_score = 0,
                                   text_score = 0,
                                   temporal_score = 0,
                                   jurisdictional_score = 0,
                                   weights = NULL) {

  # Default equal weights
  if (is.null(weights)) {
    weights <- c(
      volume = 0.3,
      text = 0.2,
      temporal = 0.3,
      jurisdictional = 0.2
    )
  }

  # Normalize weights to sum to 1
  weights <- weights / sum(weights)

  # Calculate weighted score
  unified_score <- (
    volume_score * weights["volume"] +
    text_score * weights["text"] +
    temporal_score * weights["temporal"] +
    jurisdictional_score * weights["jurisdictional"]
  )

  # Ensure score is between 0 and 100
  return(pmin(100, pmax(0, unified_score)))
}

#' Classify Anomaly Severity
#'
#' Converts anomaly score to severity level.
#'
#' @param score Numeric. Anomaly score (0-100).
#' @param thresholds Named numeric vector. Thresholds for severity levels
#'   (default: low=40, medium=60, high=80).
#'
#' @return Character. Severity level: "none", "low", "medium", "high", "critical".
#'
#' @examples
#' classify_severity(45)  # "low"
#' classify_severity(85)  # "high"
#'
#' @export
classify_severity <- function(score, thresholds = NULL) {
  if (is.null(thresholds)) {
    thresholds <- c(low = 40, medium = 60, high = 80, critical = 95)
  }

  severity <- case_when(
    score < thresholds["low"] ~ "none",
    score < thresholds["medium"] ~ "low",
    score < thresholds["high"] ~ "medium",
    score < thresholds["critical"] ~ "high",
    TRUE ~ "critical"
  )

  return(severity)
}

# ==============================================================================
# ANOMALY EXPLANATION GENERATION
# ==============================================================================

#' Generate Anomaly Explanation
#'
#' Creates human-readable explanation for why something is anomalous.
#'
#' @param anomaly_type Character. Type of anomaly: "volume", "text", "temporal",
#'   "jurisdictional", "multivariate".
#' @param score Numeric. Anomaly score (0-100).
#' @param context List. Contextual information about the anomaly.
#' @param language Character. Language for explanation: "pt" (Portuguese) or "en"
#'   (English) (default: "pt").
#'
#' @return Character. Human-readable explanation.
#'
#' @examples
#' explain_anomaly(
#'   anomaly_type = "volume",
#'   score = 85,
#'   context = list(
#'     observed = 500,
#'     expected = 150,
#'     period = "2023-06"
#'   )
#' )
#'
#' @export
explain_anomaly <- function(anomaly_type, score, context, language = "pt") {

  severity <- classify_severity(score)

  if (language == "pt") {
    explanation <- explain_anomaly_pt(anomaly_type, score, severity, context)
  } else {
    explanation <- explain_anomaly_en(anomaly_type, score, severity, context)
  }

  return(explanation)
}

#' Generate Portuguese Explanation
#'
#' @keywords internal
explain_anomaly_pt <- function(anomaly_type, score, severity, context) {

  severity_label <- switch(severity,
    "none" = "normal",
    "low" = "baixa gravidade",
    "medium" = "média gravidade",
    "high" = "alta gravidade",
    "critical" = "gravidade crítica"
  )

  base_text <- sprintf(
    "Anomalia detectada com pontuação %.1f/100 (%s).",
    score, severity_label
  )

  if (anomaly_type == "volume") {
    if (!is.null(context$observed) && !is.null(context$expected)) {
      deviation_pct <- ((context$observed - context$expected) / context$expected) * 100

      if (deviation_pct > 0) {
        detail <- sprintf(
          " Volume observado (%s documentos) está %.0f%% acima do esperado (%s documentos).",
          format(context$observed, big.mark = "."),
          abs(deviation_pct),
          format(round(context$expected), big.mark = ".")
        )
      } else {
        detail <- sprintf(
          " Volume observado (%s documentos) está %.0f%% abaixo do esperado (%s documentos).",
          format(context$observed, big.mark = "."),
          abs(deviation_pct),
          format(round(context$expected), big.mark = ".")
        )
      }

      if (!is.null(context$period)) {
        detail <- paste0(detail, sprintf(" Período: %s.", context$period))
      }

      return(paste0(base_text, detail))
    }

  } else if (anomaly_type == "text") {
    if (!is.null(context$features)) {
      detail <- sprintf(
        " Características textuais incomuns detectadas: %s.",
        paste(context$features, collapse = ", ")
      )
      return(paste0(base_text, detail))
    }

  } else if (anomaly_type == "temporal") {
    if (!is.null(context$pattern)) {
      detail <- sprintf(
        " Padrão temporal incomum: %s.",
        context$pattern
      )

      if (!is.null(context$date)) {
        detail <- paste0(detail, sprintf(" Data: %s.", context$date))
      }

      return(paste0(base_text, detail))
    }

  } else if (anomaly_type == "jurisdictional") {
    if (!is.null(context$jurisdiction)) {
      detail <- sprintf(
        " Jurisdição %s apresenta métricas atípicas.",
        context$jurisdiction
      )

      if (!is.null(context$metrics)) {
        detail <- paste0(detail, sprintf(" Métricas afetadas: %s.",
                                        paste(context$metrics, collapse = ", ")))
      }

      return(paste0(base_text, detail))
    }
  }

  # Default explanation if context is insufficient
  return(paste0(base_text, " Detalhes adicionais não disponíveis."))
}

#' Generate English Explanation
#'
#' @keywords internal
explain_anomaly_en <- function(anomaly_type, score, severity, context) {

  severity_label <- switch(severity,
    "none" = "normal",
    "low" = "low severity",
    "medium" = "medium severity",
    "high" = "high severity",
    "critical" = "critical severity"
  )

  base_text <- sprintf(
    "Anomaly detected with score %.1f/100 (%s).",
    score, severity_label
  )

  if (anomaly_type == "volume") {
    if (!is.null(context$observed) && !is.null(context$expected)) {
      deviation_pct <- ((context$observed - context$expected) / context$expected) * 100

      if (deviation_pct > 0) {
        detail <- sprintf(
          " Observed volume (%s documents) is %.0f%% above expected (%s documents).",
          format(context$observed, big.mark = ","),
          abs(deviation_pct),
          format(round(context$expected), big.mark = ",")
        )
      } else {
        detail <- sprintf(
          " Observed volume (%s documents) is %.0f%% below expected (%s documents).",
          format(context$observed, big.mark = ","),
          abs(deviation_pct),
          format(round(context$expected), big.mark = ",")
        )
      }

      if (!is.null(context$period)) {
        detail <- paste0(detail, sprintf(" Period: %s.", context$period))
      }

      return(paste0(base_text, detail))
    }

  } else if (anomaly_type == "text") {
    if (!is.null(context$features)) {
      detail <- sprintf(
        " Unusual text characteristics detected: %s.",
        paste(context$features, collapse = ", ")
      )
      return(paste0(base_text, detail))
    }

  } else if (anomaly_type == "temporal") {
    if (!is.null(context$pattern)) {
      detail <- sprintf(
        " Unusual temporal pattern: %s.",
        context$pattern
      )

      if (!is.null(context$date)) {
        detail <- paste0(detail, sprintf(" Date: %s.", context$date))
      }

      return(paste0(base_text, detail))
    }

  } else if (anomaly_type == "jurisdictional") {
    if (!is.null(context$jurisdiction)) {
      detail <- sprintf(
        " Jurisdiction %s shows atypical metrics.",
        context$jurisdiction
      )

      if (!is.null(context$metrics)) {
        detail <- paste0(detail, sprintf(" Affected metrics: %s.",
                                        paste(context$metrics, collapse = ", ")))
      }

      return(paste0(base_text, detail))
    }
  }

  return(paste0(base_text, " Additional details not available."))
}

# ==============================================================================
# REAL-TIME ANOMALY SCORING
# ==============================================================================

#' Score Single Document for Anomalies
#'
#' Evaluates a single document against historical patterns to detect anomalies.
#'
#' @param document_text Character. Full text of the document.
#' @param document_date Date. Date of the document.
#' @param jurisdiction Character. Jurisdiction (state or municipality).
#' @param historical_data data.frame. Historical data for comparison.
#' @param thresholds List. Pre-computed thresholds for anomaly detection.
#'
#' @return List with anomaly scores and explanations.
#'
#' @examples
#' \dontrun{
#' score <- score_document_realtime(
#'   document_text = "Lei municipal estabelece...",
#'   document_date = as.Date("2023-06-15"),
#'   jurisdiction = "SP",
#'   historical_data = historical_stats,
#'   thresholds = precomputed_thresholds
#' )
#' }
#'
#' @export
score_document_realtime <- function(document_text,
                                   document_date,
                                   jurisdiction,
                                   historical_data,
                                   thresholds) {

  scores <- list()
  explanations <- list()

  # 1. Text Length Anomaly
  text_length <- nchar(document_text)
  word_count <- str_count(document_text, "\\S+")

  if (!is.null(historical_data$text_stats)) {
    text_stats <- historical_data$text_stats

    # Z-score for text length
    z_length <- (text_length - text_stats$mean_length) / text_stats$sd_length
    scores$text_length <- pmin(100, abs(z_length) * 33)

    # Z-score for word count
    z_words <- (word_count - text_stats$mean_words) / text_stats$sd_words
    scores$word_count <- pmin(100, abs(z_words) * 33)

    # Combined text score
    scores$text <- max(scores$text_length, scores$word_count)

    if (scores$text > thresholds$text) {
      explanations$text <- sprintf(
        "Comprimento do texto (%d caracteres, %d palavras) é incomum",
        text_length, word_count
      )
    }
  }

  # 2. Temporal Anomaly
  if (!is.null(historical_data$temporal_stats)) {
    # Check if publication date is unusual (e.g., weekend, holiday)
    day_of_week <- lubridate::wday(document_date)
    month <- lubridate::month(document_date)

    temporal_stats <- historical_data$temporal_stats

    # Check if this day of week is unusual
    dow_freq <- temporal_stats$day_frequencies[day_of_week]
    if (dow_freq < temporal_stats$dow_threshold) {
      scores$temporal <- 70
      explanations$temporal <- sprintf(
        "Publicação em dia incomum (%s)",
        weekdays(document_date)
      )
    } else {
      scores$temporal <- 0
    }
  }

  # 3. Jurisdictional Context
  if (!is.null(historical_data$jurisdiction_stats) && !is.null(jurisdiction)) {
    juris_stats <- historical_data$jurisdiction_stats %>%
      filter(jurisdiction == !!jurisdiction)

    if (nrow(juris_stats) > 0) {
      # Check if text length is unusual for this jurisdiction
      z_juris <- (text_length - juris_stats$mean_length) / juris_stats$sd_length

      scores$jurisdictional <- pmin(100, abs(z_juris) * 33)

      if (scores$jurisdictional > thresholds$jurisdictional) {
        explanations$jurisdictional <- sprintf(
          "Comprimento incomum para documentos de %s",
          jurisdiction
        )
      }
    } else {
      scores$jurisdictional <- 0
    }
  }

  # Calculate unified score
  unified_score <- calculate_unified_score(
    volume_score = 0,  # Can't detect volume anomaly for single doc
    text_score = scores$text %||% 0,
    temporal_score = scores$temporal %||% 0,
    jurisdictional_score = scores$jurisdictional %||% 0
  )

  severity <- classify_severity(unified_score)

  # Generate comprehensive explanation
  if (length(explanations) > 0) {
    full_explanation <- paste(
      "Anomalias detectadas:",
      paste("-", unlist(explanations), collapse = "\n")
    )
  } else {
    full_explanation <- "Nenhuma anomalia detectada. Documento dentro dos padrões esperados."
  }

  return(list(
    unified_score = unified_score,
    severity = severity,
    component_scores = scores,
    explanation = full_explanation,
    is_anomaly = unified_score > thresholds$unified
  ))
}

# ==============================================================================
# CONFIDENCE INTERVALS AND UNCERTAINTY
# ==============================================================================

#' Calculate Confidence Intervals for Anomaly Scores
#'
#' Estimates confidence intervals for anomaly scores using bootstrap.
#'
#' @param data data.frame. Historical data.
#' @param method Character. Detection method used.
#' @param n_bootstrap Integer. Number of bootstrap iterations (default: 1000).
#' @param confidence_level Numeric. Confidence level (default: 0.95).
#'
#' @return data.frame with confidence intervals.
#'
#' @examples
#' \dontrun{
#' ci <- calculate_confidence_intervals(
#'   data = historical_volumes,
#'   method = "iqr",
#'   n_bootstrap = 1000
#' )
#' }
#'
#' @export
calculate_confidence_intervals <- function(data,
                                          method = "iqr",
                                          n_bootstrap = 1000,
                                          confidence_level = 0.95) {

  if (!"count" %in% names(data)) {
    stop("Data must have a 'count' column")
  }

  alpha <- 1 - confidence_level

  # Bootstrap resampling
  bootstrap_results <- replicate(n_bootstrap, {
    sample_data <- data %>%
      slice_sample(n = nrow(data), replace = TRUE)

    if (method == "iqr") {
      Q1 <- quantile(sample_data$count, 0.25)
      Q3 <- quantile(sample_data$count, 0.75)
      IQR_val <- Q3 - Q1
      c(lower = Q1 - 1.5 * IQR_val, upper = Q3 + 1.5 * IQR_val)
    } else if (method == "zscore") {
      mean_val <- mean(sample_data$count)
      sd_val <- sd(sample_data$count)
      c(lower = mean_val - 3 * sd_val, upper = mean_val + 3 * sd_val)
    }
  })

  # Calculate confidence intervals
  ci_lower <- apply(bootstrap_results, 1, quantile, probs = alpha / 2)
  ci_upper <- apply(bootstrap_results, 1, quantile, probs = 1 - alpha / 2)

  data.frame(
    bound = c("lower", "upper"),
    estimate = c(mean(bootstrap_results[1, ]), mean(bootstrap_results[2, ])),
    ci_lower = ci_lower,
    ci_upper = ci_upper,
    confidence_level = confidence_level
  )
}

# ==============================================================================
# ANOMALY RANKING AND PRIORITIZATION
# ==============================================================================

#' Rank Anomalies by Severity and Impact
#'
#' Ranks detected anomalies for prioritization.
#'
#' @param anomalies data.frame. Detected anomalies with scores.
#' @param criteria Character vector. Ranking criteria: "score", "impact",
#'   "recency", "jurisdiction_importance" (default: c("score", "impact")).
#' @param weights Named numeric vector. Weights for each criterion.
#'
#' @return data.frame with ranked anomalies.
#'
#' @examples
#' \dontrun{
#' ranked <- rank_anomalies(
#'   anomalies = detected_anomalies,
#'   criteria = c("score", "impact"),
#'   weights = c(score = 0.6, impact = 0.4)
#' )
#' }
#'
#' @export
rank_anomalies <- function(anomalies,
                          criteria = c("score", "impact"),
                          weights = NULL) {

  if (nrow(anomalies) == 0) {
    return(anomalies)
  }

  # Default weights
  if (is.null(weights)) {
    weights <- setNames(rep(1 / length(criteria), length(criteria)), criteria)
  }

  # Normalize weights
  weights <- weights / sum(weights)

  # Calculate ranking scores
  ranking_score <- numeric(nrow(anomalies))

  if ("score" %in% criteria && "anomaly_score" %in% names(anomalies)) {
    # Normalize anomaly score to 0-1
    score_normalized <- anomalies$anomaly_score / 100
    ranking_score <- ranking_score + weights["score"] * score_normalized
  }

  if ("impact" %in% criteria) {
    # Estimate impact based on severity and affected entities
    impact_score <- case_when(
      anomalies$severity == "critical" ~ 1.0,
      anomalies$severity == "high" ~ 0.8,
      anomalies$severity == "medium" ~ 0.5,
      anomalies$severity == "low" ~ 0.3,
      TRUE ~ 0.1
    )
    ranking_score <- ranking_score + weights["impact"] * impact_score
  }

  if ("recency" %in% criteria && "date" %in% names(anomalies)) {
    # More recent anomalies get higher priority
    days_since <- as.numeric(Sys.Date() - anomalies$date)
    max_days <- max(days_since, na.rm = TRUE)
    recency_score <- 1 - (days_since / max_days)
    recency_score[is.na(recency_score)] <- 0.5
    ranking_score <- ranking_score + weights["recency"] * recency_score
  }

  # Add ranking
  anomalies %>%
    mutate(
      ranking_score = ranking_score,
      rank = dense_rank(desc(ranking_score))
    ) %>%
    arrange(rank)
}

# ==============================================================================
# HISTORICAL COMPARISON AND CONTEXT
# ==============================================================================

#' Generate Historical Context for Anomaly
#'
#' Provides historical context to help interpret an anomaly.
#'
#' @param current_value Numeric. Current observed value.
#' @param historical_values Numeric vector. Historical values for comparison.
#' @param metric_name Character. Name of the metric.
#' @param language Character. Language for output: "pt" or "en" (default: "pt").
#'
#' @return Character. Historical context description.
#'
#' @examples
#' generate_historical_context(
#'   current_value = 500,
#'   historical_values = c(100, 120, 110, 95, 105),
#'   metric_name = "document volume"
#' )
#'
#' @export
generate_historical_context <- function(current_value,
                                       historical_values,
                                       metric_name,
                                       language = "pt") {

  # Calculate statistics
  hist_mean <- mean(historical_values, na.rm = TRUE)
  hist_sd <- sd(historical_values, na.rm = TRUE)
  hist_min <- min(historical_values, na.rm = TRUE)
  hist_max <- max(historical_values, na.rm = TRUE)
  hist_median <- median(historical_values, na.rm = TRUE)

  # Percentile rank
  percentile <- mean(historical_values < current_value) * 100

  # Generate context
  if (language == "pt") {
    context <- sprintf(
      "Valor atual (%s) comparado ao histórico:\n",
      format(current_value, big.mark = ".")
    )
    context <- paste0(context, sprintf(
      "- Média histórica: %s\n",
      format(round(hist_mean), big.mark = ".")
    ))
    context <- paste0(context, sprintf(
      "- Mediana histórica: %s\n",
      format(round(hist_median), big.mark = ".")
    ))
    context <- paste0(context, sprintf(
      "- Intervalo histórico: %s - %s\n",
      format(hist_min, big.mark = "."),
      format(hist_max, big.mark = ".")
    ))
    context <- paste0(context, sprintf(
      "- Percentil atual: %.0f%% (valor está acima de %.0f%% dos valores históricos)\n",
      percentile, percentile
    ))

    # Interpretation
    if (percentile > 95) {
      context <- paste0(context, "=> Valor excepcionalmente alto (top 5%)")
    } else if (percentile > 90) {
      context <- paste0(context, "=> Valor muito alto (top 10%)")
    } else if (percentile < 5) {
      context <- paste0(context, "=> Valor excepcionalmente baixo (bottom 5%)")
    } else if (percentile < 10) {
      context <- paste0(context, "=> Valor muito baixo (bottom 10%)")
    } else {
      context <- paste0(context, "=> Valor dentro da faixa esperada")
    }

  } else {
    context <- sprintf(
      "Current value (%s) compared to history:\n",
      format(current_value, big.mark = ",")
    )
    context <- paste0(context, sprintf(
      "- Historical mean: %s\n",
      format(round(hist_mean), big.mark = ",")
    ))
    context <- paste0(context, sprintf(
      "- Historical median: %s\n",
      format(round(hist_median), big.mark = ",")
    ))
    context <- paste0(context, sprintf(
      "- Historical range: %s - %s\n",
      format(hist_min, big.mark = ","),
      format(hist_max, big.mark = ",")
    ))
    context <- paste0(context, sprintf(
      "- Current percentile: %.0f%% (value exceeds %.0f%% of historical values)\n",
      percentile, percentile
    ))

    if (percentile > 95) {
      context <- paste0(context, "=> Exceptionally high value (top 5%)")
    } else if (percentile > 90) {
      context <- paste0(context, "=> Very high value (top 10%)")
    } else if (percentile < 5) {
      context <- paste0(context, "=> Exceptionally low value (bottom 5%)")
    } else if (percentile < 10) {
      context <- paste0(context, "=> Very low value (bottom 10%)")
    } else {
      context <- paste0(context, "=> Value within expected range")
    }
  }

  return(context)
}

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

#' Null-coalescing operator
#'
#' @keywords internal
`%||%` <- function(x, y) {
  if (is.null(x) || length(x) == 0 || is.na(x)) y else x
}

# ==============================================================================
# END OF FILE
# ==============================================================================
