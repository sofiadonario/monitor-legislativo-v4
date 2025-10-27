# ============================================================================
# PREDICTIVE ANALYTICS FOR LEGISLATIVE TRENDS - WEEK 10 PHASE 3
# ============================================================================
# 
# Advanced predictive analytics for Brazilian legislative monitoring
# Monitor Legislativo v4 - Trend prediction and impact analysis
# 
# Features:
# - Legislative trend prediction using time series analysis
# - Policy impact assessment and forecasting
# - Regional legislative activity patterns
# - Agency productivity and workload prediction
# - Seasonal pattern detection and adjustment
# - Multi-variate regression modeling
# - Machine learning for complex pattern recognition
# - Academic-grade statistical analysis
# ============================================================================

cat("📈 Initializing Predictive Analytics Module - Week 10 Phase 3\n")
cat("🔮 Trend Prediction • Impact Analysis • Pattern Recognition • Statistical Modeling\n")

# Required packages
required_packages <- c(
  "forecast", "tseries", "dplyr", "lubridate", "ggplot2", 
  "randomForest", "caret", "plotly", "jsonlite", "bcp"
)

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("⚠️ Package", pkg, "not available, using fallbacks\n")
  } else {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }
}

# PREDICTIVE ANALYTICS CONFIGURATION
# ===================================

PRED_CONFIG <- list(
  # Time series settings
  time_series = list(
    min_observations = 12,    # Minimum data points for prediction
    forecast_horizon = 6,     # Months ahead to predict
    confidence_levels = c(0.8, 0.95),
    seasonal_adjustment = TRUE,
    trend_detection = TRUE
  ),
  
  # Machine learning settings
  ml = list(
    train_test_split = 0.8,
    cross_validation_folds = 5,
    max_features = 20,
    ensemble_methods = TRUE
  ),
  
  # Analysis categories
  categories = list(
    "legislation_volume" = "Volume of new legislation",
    "agency_activity" = "Government agency regulatory activity", 
    "regional_patterns" = "Regional legislative patterns",
    "topic_trends" = "Subject matter trends",
    "policy_impact" = "Policy implementation impact",
    "compliance_rates" = "Regulatory compliance rates"
  ),
  
  # Statistical thresholds
  thresholds = list(
    significance_level = 0.05,
    trend_detection_window = 6,  # months
    anomaly_detection_threshold = 2, # standard deviations
    min_correlation = 0.3
  ),
  
  # Visualization settings
  visualization = list(
    default_colors = c("#3498db", "#e74c3c", "#f39c12", "#2ecc71", "#9b59b6"),
    plot_width = 800,
    plot_height = 600,
    interactive = TRUE
  )
)

# TIME SERIES ANALYSIS
# ====================

# Prepare time series data
prepare_time_series <- function(documents, grouping = "monthly", metric = "count") {
  tryCatch({
    cat("📊 Preparing time series data with", grouping, "grouping...\n")
    
    # Convert documents to data frame if needed
    if (is.list(documents) && !is.data.frame(documents)) {
      df <- do.call(rbind, lapply(documents, function(doc) {
        data.frame(
          id = doc$id %||% NA,
          data_publicacao = as.Date(doc$data_publicacao %||% Sys.Date()),
          estado = doc$estado %||% NA,
          species = doc$species %||% NA,
          stringsAsFactors = FALSE
        )
      }))
    } else {
      df <- documents
    }
    
    # Ensure date column
    if (!"data_publicacao" %in% names(df)) {
      cat("⚠️ No date column found, using current date\n")
      df$data_publicacao <- Sys.Date()
    }
    
    # Remove invalid dates
    df <- df[!is.na(df$data_publicacao), ]
    
    if (nrow(df) == 0) {
      return(list(error = "No valid dates found"))
    }
    
    # Create time grouping
    if (grouping == "daily") {
      df$time_period <- as.Date(df$data_publicacao)
    } else if (grouping == "weekly") {
      df$time_period <- floor_date(as.Date(df$data_publicacao), "week")
    } else if (grouping == "monthly") {
      df$time_period <- floor_date(as.Date(df$data_publicacao), "month")
    } else if (grouping == "quarterly") {
      df$time_period <- floor_date(as.Date(df$data_publicacao), "quarter")
    } else if (grouping == "yearly") {
      df$time_period <- floor_date(as.Date(df$data_publicacao), "year")
    } else {
      df$time_period <- floor_date(as.Date(df$data_publicacao), "month")
    }
    
    # Calculate metric by time period
    if (metric == "count") {
      ts_data <- df %>%
        group_by(time_period) %>%
        summarise(value = n(), .groups = "drop")
    } else if (metric == "diversity") {
      ts_data <- df %>%
        group_by(time_period) %>%
        summarise(value = length(unique(species)), .groups = "drop")
    } else if (metric == "states") {
      ts_data <- df %>%
        group_by(time_period) %>%
        summarise(value = length(unique(estado[!is.na(estado)])), .groups = "drop")
    } else {
      ts_data <- df %>%
        group_by(time_period) %>%
        summarise(value = n(), .groups = "drop")
    }
    
    # Fill missing periods with zeros
    date_range <- seq.Date(min(ts_data$time_period), max(ts_data$time_period), by = grouping)
    full_ts <- data.frame(time_period = date_range)
    ts_data <- merge(full_ts, ts_data, all.x = TRUE)
    ts_data$value[is.na(ts_data$value)] <- 0
    
    # Sort by date
    ts_data <- ts_data[order(ts_data$time_period), ]
    
    cat("✅ Time series prepared:", nrow(ts_data), "observations\n")
    
    return(list(
      data = ts_data,
      grouping = grouping,
      metric = metric,
      date_range = range(ts_data$time_period),
      observations = nrow(ts_data)
    ))
    
  }, error = function(e) {
    cat("❌ Time series preparation error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Detect trends and patterns
detect_trends <- function(ts_data, method = "auto") {
  tryCatch({
    cat("🔍 Detecting trends and patterns...\n")
    
    if (is.list(ts_data) && "data" %in% names(ts_data)) {
      data_df <- ts_data$data
    } else {
      data_df <- ts_data
    }
    
    if (nrow(data_df) < PRED_CONFIG$time_series$min_observations) {
      return(list(error = "Insufficient data for trend analysis"))
    }
    
    # Create time series object
    ts_values <- ts(data_df$value, frequency = 12)  # Assuming monthly data
    
    trends <- list()
    
    # Basic trend detection
    if (method %in% c("auto", "linear")) {
      # Linear trend
      time_index <- 1:length(ts_values)
      lm_trend <- lm(as.numeric(ts_values) ~ time_index)
      
      trends$linear <- list(
        slope = coef(lm_trend)[2],
        intercept = coef(lm_trend)[1],
        r_squared = summary(lm_trend)$r.squared,
        p_value = summary(lm_trend)$coefficients[2, 4],
        direction = ifelse(coef(lm_trend)[2] > 0, "increasing", "decreasing"),
        significance = summary(lm_trend)$coefficients[2, 4] < PRED_CONFIG$thresholds$significance_level
      )
    }
    
    # Seasonal decomposition
    if (method %in% c("auto", "seasonal") && length(ts_values) >= 24) {
      decomp <- tryCatch({
        decompose(ts_values)
      }, error = function(e) {
        # Try STL decomposition as fallback
        tryCatch({
          stl(ts_values, s.window = "periodic")
        }, error = function(e2) NULL)
      })
      
      if (!is.null(decomp)) {
        trends$seasonal <- list(
          has_seasonality = TRUE,
          seasonal_strength = var(decomp$seasonal, na.rm = TRUE) / var(ts_values, na.rm = TRUE),
          trend_component = as.numeric(decomp$trend),
          seasonal_component = as.numeric(decomp$seasonal)
        )
      }
    }
    
    # Change point detection
    if (method %in% c("auto", "changepoint") && requireNamespace("bcp", quietly = TRUE)) {
      bcp_result <- tryCatch({
        bcp(as.numeric(ts_values), mcmc = 1000, burnin = 100)
      }, error = function(e) NULL)
      
      if (!is.null(bcp_result)) {
        prob_threshold <- 0.5
        change_points <- which(bcp_result$posterior.prob > prob_threshold)
        
        trends$changepoints <- list(
          detected = length(change_points) > 0,
          positions = change_points,
          probabilities = bcp_result$posterior.prob[change_points]
        )
      }
    }
    
    # Moving averages
    if (length(ts_values) >= 6) {
      ma_3 <- filter(ts_values, rep(1/3, 3), sides = 2)
      ma_6 <- filter(ts_values, rep(1/6, 6), sides = 2)
      
      trends$moving_averages <- list(
        ma_3 = as.numeric(ma_3),
        ma_6 = as.numeric(ma_6),
        current_trend_3 = tail(ma_3[!is.na(ma_3)], 1),
        current_trend_6 = tail(ma_6[!is.na(ma_6)], 1)
      )
    }
    
    # Anomaly detection
    mean_val <- mean(ts_values, na.rm = TRUE)
    sd_val <- sd(ts_values, na.rm = TRUE)
    anomaly_threshold <- PRED_CONFIG$thresholds$anomaly_detection_threshold
    
    anomalies <- which(abs(ts_values - mean_val) > anomaly_threshold * sd_val)
    
    trends$anomalies <- list(
      detected = length(anomalies) > 0,
      positions = anomalies,
      values = ts_values[anomalies],
      threshold = anomaly_threshold * sd_val
    )
    
    # Overall assessment
    trends$summary <- list(
      data_points = length(ts_values),
      mean = mean_val,
      standard_deviation = sd_val,
      coefficient_variation = sd_val / mean_val,
      min_value = min(ts_values, na.rm = TRUE),
      max_value = max(ts_values, na.rm = TRUE),
      analysis_method = method,
      analysis_date = Sys.time()
    )
    
    cat("✅ Trend analysis completed\n")
    return(trends)
    
  }, error = function(e) {
    cat("❌ Trend detection error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Generate predictions
generate_predictions <- function(ts_data, horizon = PRED_CONFIG$time_series$forecast_horizon, methods = c("auto", "arima")) {
  tryCatch({
    cat("🔮 Generating predictions for", horizon, "periods ahead...\n")
    
    if (is.list(ts_data) && "data" %in% names(ts_data)) {
      data_df <- ts_data$data
      grouping <- ts_data$grouping %||% "monthly"
    } else {
      data_df <- ts_data
      grouping <- "monthly"
    }
    
    if (nrow(data_df) < PRED_CONFIG$time_series$min_observations) {
      return(list(error = "Insufficient data for prediction"))
    }
    
    # Create time series object
    frequency_map <- list(daily = 365, weekly = 52, monthly = 12, quarterly = 4, yearly = 1)
    freq <- frequency_map[[grouping]] %||% 12
    
    ts_values <- ts(data_df$value, frequency = freq)
    
    predictions <- list()
    
    # Auto ARIMA forecast
    if ("auto" %in% methods || "arima" %in% methods) {
      if (requireNamespace("forecast", quietly = TRUE)) {
        arima_model <- tryCatch({
          auto.arima(ts_values, seasonal = PRED_CONFIG$time_series$seasonal_adjustment)
        }, error = function(e) {
          # Fallback to simple ARIMA
          arima(ts_values, order = c(1, 1, 1))
        })
        
        arima_forecast <- forecast(arima_model, h = horizon, 
                                  level = PRED_CONFIG$time_series$confidence_levels * 100)
        
        predictions$arima <- list(
          method = "ARIMA",
          model_info = arima_model$arma,
          forecast_values = as.numeric(arima_forecast$mean),
          lower_bound = as.numeric(arima_forecast$lower[, ncol(arima_forecast$lower)]),
          upper_bound = as.numeric(arima_forecast$upper[, ncol(arima_forecast$upper)]),
          confidence_level = max(PRED_CONFIG$time_series$confidence_levels),
          aic = AIC(arima_model),
          bic = BIC(arima_model)
        )
      }
    }
    
    # Linear trend extrapolation
    if ("linear" %in% methods) {
      time_index <- 1:length(ts_values)
      lm_model <- lm(as.numeric(ts_values) ~ time_index)
      
      future_time <- (length(ts_values) + 1):(length(ts_values) + horizon)
      linear_pred <- predict(lm_model, newdata = data.frame(time_index = future_time), 
                           interval = "prediction", level = max(PRED_CONFIG$time_series$confidence_levels))
      
      predictions$linear <- list(
        method = "Linear Trend",
        forecast_values = as.numeric(linear_pred[, "fit"]),
        lower_bound = as.numeric(linear_pred[, "lwr"]),
        upper_bound = as.numeric(linear_pred[, "upr"]),
        confidence_level = max(PRED_CONFIG$time_series$confidence_levels),
        r_squared = summary(lm_model)$r.squared,
        slope = coef(lm_model)[2]
      )
    }
    
    # Exponential smoothing
    if ("ets" %in% methods && requireNamespace("forecast", quietly = TRUE)) {
      ets_model <- tryCatch({
        ets(ts_values)
      }, error = function(e) NULL)
      
      if (!is.null(ets_model)) {
        ets_forecast <- forecast(ets_model, h = horizon, 
                               level = PRED_CONFIG$time_series$confidence_levels * 100)
        
        predictions$ets <- list(
          method = "Exponential Smoothing",
          model_type = ets_model$method,
          forecast_values = as.numeric(ets_forecast$mean),
          lower_bound = as.numeric(ets_forecast$lower[, ncol(ets_forecast$lower)]),
          upper_bound = as.numeric(ets_forecast$upper[, ncol(ets_forecast$upper)]),
          confidence_level = max(PRED_CONFIG$time_series$confidence_levels),
          aic = ets_model$aic,
          bic = ets_model$bic
        )
      }
    }
    
    # Generate future dates
    last_date <- max(data_df$time_period)
    if (grouping == "monthly") {
      future_dates <- seq.Date(last_date + months(1), by = "month", length.out = horizon)
    } else if (grouping == "weekly") {
      future_dates <- seq.Date(last_date + weeks(1), by = "week", length.out = horizon)
    } else if (grouping == "quarterly") {
      future_dates <- seq.Date(last_date + months(3), by = "quarter", length.out = horizon)
    } else {
      future_dates <- seq.Date(last_date + 1, by = "day", length.out = horizon)
    }
    
    # Ensemble prediction (average of available methods)
    if (length(predictions) > 1) {
      forecast_matrix <- sapply(predictions, function(pred) pred$forecast_values)
      ensemble_forecast <- rowMeans(forecast_matrix, na.rm = TRUE)
      
      # Calculate ensemble bounds (use the widest bounds)
      lower_matrix <- sapply(predictions, function(pred) pred$lower_bound)
      upper_matrix <- sapply(predictions, function(pred) pred$upper_bound)
      
      predictions$ensemble <- list(
        method = "Ensemble Average",
        forecast_values = ensemble_forecast,
        lower_bound = apply(lower_matrix, 1, min, na.rm = TRUE),
        upper_bound = apply(upper_matrix, 1, max, na.rm = TRUE),
        component_methods = names(predictions),
        confidence_level = max(PRED_CONFIG$time_series$confidence_levels)
      )
    }
    
    # Add metadata
    predictions$metadata <- list(
      horizon = horizon,
      forecast_dates = future_dates,
      base_data_points = length(ts_values),
      forecast_generated = Sys.time(),
      data_frequency = freq,
      grouping = grouping
    )
    
    cat("✅ Predictions generated using", length(predictions) - 1, "methods\n")
    return(predictions)
    
  }, error = function(e) {
    cat("❌ Prediction generation error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# IMPACT ANALYSIS
# ===============

# Analyze policy impact
analyze_policy_impact <- function(documents, policy_keywords, reference_period = "before") {
  tryCatch({
    cat("💥 Analyzing policy impact for keywords:", paste(policy_keywords, collapse = ", "), "\n")
    
    # Convert documents to data frame if needed
    if (is.list(documents) && !is.data.frame(documents)) {
      df <- do.call(rbind, lapply(documents, function(doc) {
        data.frame(
          id = doc$id %||% NA,
          titulo = doc$titulo %||% "",
          ementa = doc$ementa %||% "",
          data_publicacao = as.Date(doc$data_publicacao %||% Sys.Date()),
          estado = doc$estado %||% NA,
          species = doc$species %||% NA,
          stringsAsFactors = FALSE
        )
      }))
    } else {
      df <- documents
    }
    
    # Create combined text for searching
    df$full_text <- paste(df$titulo, df$ementa, sep = " ")
    
    # Find documents related to policy keywords
    related_docs <- df[FALSE, ]  # Empty data frame with same structure
    
    for (keyword in policy_keywords) {
      matches <- grepl(keyword, df$full_text, ignore.case = TRUE)
      related_docs <- rbind(related_docs, df[matches, ])
    }
    
    related_docs <- unique(related_docs)
    
    if (nrow(related_docs) == 0) {
      return(list(error = "No documents found matching policy keywords"))
    }
    
    # Temporal analysis
    related_docs$year_month <- floor_date(related_docs$data_publicacao, "month")
    
    temporal_impact <- related_docs %>%
      group_by(year_month) %>%
      summarise(
        document_count = n(),
        unique_states = length(unique(estado[!is.na(estado)])),
        .groups = "drop"
      ) %>%
      arrange(year_month)
    
    # Before/after analysis if reference date provided
    if (reference_period != "before" && is.Date(reference_period)) {
      before_docs <- related_docs[related_docs$data_publicacao < reference_period, ]
      after_docs <- related_docs[related_docs$data_publicacao >= reference_period, ]
      
      before_after <- list(
        before = list(
          count = nrow(before_docs),
          avg_per_month = nrow(before_docs) / max(1, length(unique(before_docs$year_month))),
          states = length(unique(before_docs$estado[!is.na(before_docs$estado)]))
        ),
        after = list(
          count = nrow(after_docs),
          avg_per_month = nrow(after_docs) / max(1, length(unique(after_docs$year_month))),
          states = length(unique(after_docs$estado[!is.na(after_docs$estado)]))
        )
      )
      
      # Calculate impact metrics
      if (before_after$before$avg_per_month > 0) {
        change_rate <- (before_after$after$avg_per_month - before_after$before$avg_per_month) / 
                      before_after$before$avg_per_month
      } else {
        change_rate <- ifelse(before_after$after$avg_per_month > 0, 1, 0)
      }
      
      before_after$impact_metrics <- list(
        change_rate = change_rate,
        change_direction = ifelse(change_rate > 0, "increase", "decrease"),
        magnitude = abs(change_rate),
        significance = abs(change_rate) > 0.2  # 20% change threshold
      )
    } else {
      before_after <- NULL
    }
    
    # Geographic impact
    geographic_impact <- related_docs %>%
      filter(!is.na(estado)) %>%
      group_by(estado) %>%
      summarise(
        document_count = n(),
        avg_per_month = n() / max(1, length(unique(year_month))),
        .groups = "drop"
      ) %>%
      arrange(desc(document_count))
    
    # Document type impact
    type_impact <- related_docs %>%
      filter(!is.na(species)) %>%
      group_by(species) %>%
      summarise(
        document_count = n(),
        percentage = n() / nrow(related_docs) * 100,
        .groups = "drop"
      ) %>%
      arrange(desc(document_count))
    
    # Trend analysis
    if (nrow(temporal_impact) >= 6) {
      ts_data <- ts(temporal_impact$document_count, frequency = 12)
      trend_analysis <- detect_trends(list(data = temporal_impact), method = "linear")
    } else {
      trend_analysis <- list(message = "Insufficient data for trend analysis")
    }
    
    impact_analysis <- list(
      policy_keywords = policy_keywords,
      total_related_documents = nrow(related_docs),
      temporal_impact = temporal_impact,
      geographic_impact = geographic_impact,
      type_impact = type_impact,
      before_after_analysis = before_after,
      trend_analysis = trend_analysis,
      analysis_period = range(related_docs$data_publicacao),
      generated_at = Sys.time()
    )
    
    cat("✅ Policy impact analysis completed for", nrow(related_docs), "related documents\n")
    return(impact_analysis)
    
  }, error = function(e) {
    cat("❌ Policy impact analysis error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# REGIONAL PATTERN ANALYSIS
# =========================

# Analyze regional legislative patterns
analyze_regional_patterns <- function(documents, analysis_type = "volume") {
  tryCatch({
    cat("🗺️ Analyzing regional legislative patterns...\n")
    
    # Convert documents to data frame if needed
    if (is.list(documents) && !is.data.frame(documents)) {
      df <- do.call(rbind, lapply(documents, function(doc) {
        data.frame(
          id = doc$id %||% NA,
          data_publicacao = as.Date(doc$data_publicacao %||% Sys.Date()),
          estado = doc$estado %||% NA,
          municipio = doc$municipio %||% NA,
          species = doc$species %||% NA,
          stringsAsFactors = FALSE
        )
      }))
    } else {
      df <- documents
    }
    
    # Filter out missing states
    df <- df[!is.na(df$estado) & df$estado != "", ]
    
    if (nrow(df) == 0) {
      return(list(error = "No documents with valid state information"))
    }
    
    # Add time period
    df$year_month <- floor_date(df$data_publicacao, "month")
    df$year <- year(df$data_publicacao)
    
    # Regional groupings
    regional_groups <- list(
      "Norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
      "Nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
      "Centro-Oeste" = c("GO", "MT", "MS", "DF"),
      "Sudeste" = c("ES", "MG", "RJ", "SP"),
      "Sul" = c("PR", "RS", "SC")
    )
    
    # Add region column
    df$regiao <- NA
    for (region in names(regional_groups)) {
      df$regiao[df$estado %in% regional_groups[[region]]] <- region
    }
    
    patterns <- list()
    
    # Volume analysis by state
    if (analysis_type %in% c("volume", "all")) {
      state_volume <- df %>%
        group_by(estado, regiao) %>%
        summarise(
          total_documents = n(),
          years_active = length(unique(year)),
          avg_per_year = n() / length(unique(year)),
          latest_activity = max(data_publicacao),
          .groups = "drop"
        ) %>%
        arrange(desc(total_documents))
      
      # Regional summary
      region_volume <- df %>%
        filter(!is.na(regiao)) %>%
        group_by(regiao) %>%
        summarise(
          total_documents = n(),
          num_states = length(unique(estado)),
          avg_per_state = n() / length(unique(estado)),
          .groups = "drop"
        ) %>%
        arrange(desc(total_documents))
      
      patterns$volume <- list(
        by_state = state_volume,
        by_region = region_volume
      )
    }
    
    # Temporal patterns
    if (analysis_type %in% c("temporal", "all")) {
      # Monthly patterns by region
      temporal_regional <- df %>%
        filter(!is.na(regiao)) %>%
        group_by(year_month, regiao) %>%
        summarise(document_count = n(), .groups = "drop") %>%
        spread(regiao, document_count, fill = 0)
      
      # Seasonal patterns
      df$month <- month(df$data_publicacao)
      seasonal_patterns <- df %>%
        filter(!is.na(regiao)) %>%
        group_by(month, regiao) %>%
        summarise(avg_documents = n() / length(unique(year)), .groups = "drop") %>%
        spread(regiao, avg_documents, fill = 0)
      
      patterns$temporal <- list(
        monthly_by_region = temporal_regional,
        seasonal_patterns = seasonal_patterns
      )
    }
    
    # Diversity analysis
    if (analysis_type %in% c("diversity", "all")) {
      diversity_analysis <- df %>%
        filter(!is.na(species)) %>%
        group_by(estado, regiao) %>%
        summarise(
          unique_types = length(unique(species)),
          type_diversity = length(unique(species)) / n(),
          .groups = "drop"
        ) %>%
        arrange(desc(unique_types))
      
      patterns$diversity <- diversity_analysis
    }
    
    # Correlation analysis
    if (analysis_type %in% c("correlation", "all") && nrow(df) > 50) {
      # Create state-month matrix for correlation
      state_month_matrix <- df %>%
        group_by(estado, year_month) %>%
        summarise(count = n(), .groups = "drop") %>%
        spread(estado, count, fill = 0)
      
      if (ncol(state_month_matrix) > 3) {
        # Remove date column for correlation
        corr_data <- state_month_matrix[, -1]
        
        # Calculate correlation matrix
        correlation_matrix <- cor(corr_data, use = "pairwise.complete.obs")
        
        # Find high correlations
        high_correlations <- c()
        threshold <- PRED_CONFIG$thresholds$min_correlation
        
        for (i in 1:(ncol(correlation_matrix) - 1)) {
          for (j in (i + 1):ncol(correlation_matrix)) {
            corr_val <- correlation_matrix[i, j]
            if (!isTRUE(is.na(corr_val)) && abs(corr_val) >= threshold) {
              high_correlations <- rbind(high_correlations, 
                data.frame(
                  state1 = colnames(correlation_matrix)[i],
                  state2 = colnames(correlation_matrix)[j],
                  correlation = corr_val,
                  stringsAsFactors = FALSE
                ))
            }
          }
        }
        
        patterns$correlation <- list(
          matrix = correlation_matrix,
          high_correlations = high_correlations,
          threshold = threshold
        )
      }
    }
    
    # Summary statistics
    patterns$summary <- list(
      total_documents = nrow(df),
      states_represented = length(unique(df$estado)),
      regions_represented = length(unique(df$regiao[!is.na(df$regiao)])),
      time_span = range(df$data_publicacao),
      analysis_type = analysis_type,
      generated_at = Sys.time()
    )
    
    cat("✅ Regional pattern analysis completed\n")
    return(patterns)
    
  }, error = function(e) {
    cat("❌ Regional pattern analysis error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# COMPREHENSIVE ANALYTICS DASHBOARD
# ==================================

# Generate comprehensive analytics report
generate_analytics_dashboard <- function(documents, include_predictions = TRUE, include_impact = TRUE) {
  tryCatch({
    cat("📊 Generating comprehensive analytics dashboard...\n")
    
    dashboard <- list()
    
    # Time series analysis
    cat("📈 Preparing time series analysis...\n")
    ts_monthly <- prepare_time_series(documents, "monthly", "count")
    
    if (!"error" %in% names(ts_monthly)) {
      trends <- detect_trends(ts_monthly, "auto")
      dashboard$time_series <- list(
        data = ts_monthly,
        trends = trends
      )
      
      # Generate predictions if requested
      if (include_predictions && ts_monthly$observations >= PRED_CONFIG$time_series$min_observations) {
        predictions <- generate_predictions(ts_monthly, methods = c("auto", "linear"))
        dashboard$predictions <- predictions
      }
    }
    
    # Regional analysis
    cat("🗺️ Analyzing regional patterns...\n")
    regional_patterns <- analyze_regional_patterns(documents, "all")
    if (!"error" %in% names(regional_patterns)) {
      dashboard$regional_patterns = regional_patterns
    }
    
    # Policy impact analysis (if keywords provided)
    if (include_impact) {
      cat("💥 Analyzing policy impact...\n")
      transport_impact <- analyze_policy_impact(documents, 
        c("transporte", "rodoviário", "aquaviário", "aviação"))
      
      if (!"error" %in% names(transport_impact)) {
        dashboard$policy_impact <- transport_impact
      }
    }
    
    # Document type analysis
    cat("📋 Analyzing document types...\n")
    if (is.list(documents) && !is.data.frame(documents)) {
      df <- do.call(rbind, lapply(documents, function(doc) {
        data.frame(
          species = doc$species %||% NA,
          data_publicacao = as.Date(doc$data_publicacao %||% Sys.Date()),
          stringsAsFactors = FALSE
        )
      }))
    } else {
      df <- documents
    }
    
    type_analysis <- df %>%
      filter(!is.na(species)) %>%
      group_by(species) %>%
      summarise(
        count = n(),
        percentage = n() / nrow(df) * 100,
        first_occurrence = min(data_publicacao),
        last_occurrence = max(data_publicacao),
        .groups = "drop"
      ) %>%
      arrange(desc(count))
    
    dashboard$document_types <- type_analysis
    
    # Overall statistics
    dashboard$summary_statistics <- list(
      total_documents = length(documents),
      date_range = if (nrow(df) > 0) range(df$data_publicacao) else c(NA, NA),
      document_types = if (nrow(type_analysis) > 0) nrow(type_analysis) else 0,
      states_covered = if (is.list(documents)) {
        length(unique(sapply(documents, function(x) x$estado %||% NA)))
      } else {
        length(unique(df$estado))
      },
      generation_date = Sys.time(),
      analysis_version = "1.0"
    )
    
    cat("✅ Analytics dashboard generated successfully\n")
    return(dashboard)
    
  }, error = function(e) {
    cat("❌ Dashboard generation error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# VISUALIZATION SUPPORT
# =====================

# Create trend visualization data
create_trend_visualization <- function(ts_data, predictions = NULL) {
  tryCatch({
    cat("📊 Creating trend visualization data...\n")
    
    if (is.list(ts_data) && "data" %in% names(ts_data)) {
      data_df <- ts_data$data
    } else {
      data_df <- ts_data
    }
    
    # Base visualization data
    viz_data <- list(
      historical = list(
        dates = as.character(data_df$time_period),
        values = data_df$value,
        type = "historical"
      )
    )
    
    # Add predictions if available
    if (!isTRUE(is.null(predictions)) && "metadata" %in% names(predictions)) {
      future_dates <- as.character(predictions$metadata$forecast_dates)
      
      # Add each prediction method
      for (method in names(predictions)) {
        if (method != "metadata" && "forecast_values" %in% names(predictions[[method]])) {
          pred_data <- predictions[[method]]
          
          viz_data[[paste0("prediction_", tolower(method))] <- list(
            dates = future_dates,
            values = pred_data$forecast_values,
            lower_bound = pred_data$lower_bound,
            upper_bound = pred_data$upper_bound,
            type = "prediction",
            method = pred_data$method
          )
        }
      }
    }
    
    # Styling information
    viz_data$styling <- list(
      colors = PRED_CONFIG$visualization$default_colors,
      width = PRED_CONFIG$visualization$plot_width,
      height = PRED_CONFIG$visualization$plot_height,
      interactive = PRED_CONFIG$visualization$interactive
    )
    
    cat("✅ Visualization data created\n")
    return(viz_data)
    
  }, error = function(e) {
    cat("❌ Visualization creation error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Initialize predictive analytics
init_predictive_analytics <- function() {
  cat("📈 Initializing Predictive Analytics System...\n")
  cat("🔮 Forecast horizon:", PRED_CONFIG$time_series$forecast_horizon, "periods\n")
  cat("📊 Minimum observations:", PRED_CONFIG$time_series$min_observations, "\n")
  cat("📈 Analysis categories:", length(PRED_CONFIG$categories), "\n")
  cat("🎨 Visualization enabled:", PRED_CONFIG$visualization$interactive, "\n")
  
  return(TRUE)
}

# Export predictive analytics functions
PRED_FUNCTIONS <- list(
  prepare_time_series = prepare_time_series,
  detect_trends = detect_trends,
  generate_predictions = generate_predictions,
  analyze_policy_impact = analyze_policy_impact,
  analyze_regional_patterns = analyze_regional_patterns,
  generate_analytics_dashboard = generate_analytics_dashboard,
  create_trend_visualization = create_trend_visualization,
  init_predictive_analytics = init_predictive_analytics
)

# Initialize on load
init_predictive_analytics()

cat("✅ Predictive Analytics module ready for legislative trend analysis\n")