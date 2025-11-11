# Temporal Analysis Module - Monitor Legislativo v4
# Advanced Time-Series Analysis for Brazilian Legislative Trends
# ==============================================================

#' @title Temporal Analysis for Brazilian Legislative Research
#' @description Comprehensive time-series analysis of legislative patterns and trends
#' following academic research methodology standards with statistical significance testing
#' @author Monitor Legislativo v4 Team
#' @date 2025-09-08

# Required libraries for temporal analysis
suppressPackageStartupMessages({
  library(tidyverse)
  library(lubridate)
  library(forecast)
  library(tseries)
  library(changepoint)
  library(bcp)
  library(plotly)
  library(ggplot2)
  library(viridis)
  library(scales)
  library(gridExtra)
  library(zoo)
  library(xts)
  library(DT)
  library(corrplot)
  library(seasonal)
})

#' Conduct Comprehensive Temporal Analysis
#' 
#' Performs extensive temporal analysis of Brazilian legislative data
#' including trend analysis, seasonality detection, and change point identification
#' 
#' @param data Data frame with legislative documents and dates
#' @param date_column Name of the date column
#' @param category_column Optional category column for stratified analysis
#' @param analysis_level Temporal aggregation ("day", "week", "month", "quarter", "year")
#' @param academic_validation Enable academic statistical testing
#' @return Comprehensive temporal analysis results
#' @export
conduct_temporal_analysis <- function(data,
                                      date_column = "date",
                                      category_column = NULL,
                                      analysis_level = "month",
                                      academic_validation = TRUE) {
  
  cat("📅 Conducting Comprehensive Temporal Analysis\n")
  cat("📊 Analysis level:", analysis_level, "\n")
  cat("🔬 Academic validation:", academic_validation, "\n")
  
  # Validate inputs
  if (!date_column %in% names(data)) {
    stop("Date column '", date_column, "' not found in data")
  }
  
  # Prepare temporal data
  temporal_data <- data %>%
    mutate(
      date_parsed = as.Date(.data[[date_column]]),
      year = year(date_parsed),
      month = month(date_parsed),
      quarter = quarter(date_parsed),
      week = week(date_parsed),
      day = day(date_parsed),
      weekday = wday(date_parsed, label = TRUE),
      month_name = month(date_parsed, label = TRUE)
    ) %>%
    filter(!is.na(date_parsed))
  
  n_docs <- nrow(temporal_data)
  date_range <- range(temporal_data$date_parsed, na.rm = TRUE)
  
  cat("📊 Temporal dataset:", n_docs, "documents\n")
  cat("📅 Date range:", format(date_range[1]), "to", format(date_range[2]), "\n")
  
  # Create time series based on analysis level
  time_series <- create_time_series(temporal_data, analysis_level, category_column)
  
  # Initialize results list
  results <- list(
    data = temporal_data,
    time_series = time_series,
    analysis_level = analysis_level,
    date_range = date_range,
    n_documents = n_docs
  )
  
  # 1. Trend Analysis
  cat("📈 Conducting trend analysis...\n")
  results$trend_analysis <- analyze_trends(time_series, academic_validation)
  
  # 2. Seasonality Analysis
  cat("🔄 Analyzing seasonality patterns...\n")
  results$seasonality_analysis <- analyze_seasonality(time_series, analysis_level, academic_validation)
  
  # 3. Change Point Detection
  cat("🎯 Detecting change points...\n")
  results$change_points <- detect_change_points(time_series, academic_validation)
  
  # 4. Cyclical Patterns
  cat("🌊 Analyzing cyclical patterns...\n")
  results$cyclical_analysis <- analyze_cyclical_patterns(temporal_data, academic_validation)
  
  # 5. Statistical Tests
  if (academic_validation) {
    cat("🔬 Conducting academic statistical tests...\n")
    results$statistical_tests <- conduct_temporal_tests(time_series)
  }
  
  # 6. Forecasting (if sufficient data)
  if (nrow(time_series$main) >= 24) {  # At least 2 years for monthly data
    cat("🔮 Generating forecasts...\n")
    results$forecasts <- generate_forecasts(time_series$main, analysis_level)
  }
  
  # Add academic metadata
  results$academic <- list(
    methodology = "Time-series analysis with academic validation",
    statistical_tests = "Augmented Dickey-Fuller, KPSS, Ljung-Box, seasonal decomposition",
    significance_level = 0.05,
    confidence_level = 0.95,
    processing_date = Sys.time(),
    meets_standards = academic_validation && n_docs >= 100
  )
  
  cat("✅ Temporal analysis completed\n")
  cat("📊 Analysis components:", length(results) - 1, "\n\n")
  
  return(results)
}

#' Create Time Series Objects
#' 
#' Converts legislative data into time series format for analysis
#' 
#' @param data Prepared temporal data
#' @param level Aggregation level
#' @param category_col Optional category column
#' @return Time series objects
create_time_series <- function(data, level, category_col) {
  
  # Create aggregation formula
  group_vars <- switch(level,
    "day" = c("year", "month", "day"),
    "week" = c("year", "week"),
    "month" = c("year", "month"),
    "quarter" = c("year", "quarter"),
    "year" = "year"
  )
  
  # Main time series
  main_ts <- data %>%
    group_by(across(all_of(group_vars))) %>%
    summarise(
      count = n(),
      date = min(date_parsed, na.rm = TRUE),
      .groups = "drop"
    ) %>%
    arrange(date)
  
  # Convert to ts object
  if (level == "month") {
    start_year <- min(main_ts$year)
    start_month <- min(main_ts$month[main_ts$year == start_year])
    ts_main <- ts(main_ts$count, start = c(start_year, start_month), frequency = 12)
  } else if (level == "quarter") {
    start_year <- min(main_ts$year)
    start_quarter <- min(main_ts$quarter[main_ts$year == start_year])
    ts_main <- ts(main_ts$count, start = c(start_year, start_quarter), frequency = 4)
  } else if (level == "year") {
    ts_main <- ts(main_ts$count, start = min(main_ts$year), frequency = 1)
  } else {
    ts_main <- ts(main_ts$count, frequency = 1)
  }
  
  result <- list(
    main = main_ts,
    ts_object = ts_main
  )
  
  # Category-specific time series if requested
  if (!isTRUE(is.null(category_col)) && category_col %in% names(data)) {
    
    category_ts <- data %>%
      group_by(across(all_of(c(group_vars, category_col)))) %>%
      summarise(
        count = n(),
        date = min(date_parsed, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(date)
    
    # Pivot to wide format for multiple series
    category_wide <- category_ts %>%
      pivot_wider(
        names_from = all_of(category_col),
        values_from = count,
        values_fill = 0
      )
    
    result$by_category <- category_wide
  }
  
  return(result)
}

#' Analyze Temporal Trends
#' 
#' Conducts comprehensive trend analysis with statistical validation
#' 
#' @param time_series Time series object
#' @param academic_validation Enable statistical testing
#' @return Trend analysis results
analyze_trends <- function(time_series, academic_validation) {
  
  ts_data <- time_series$main
  ts_obj <- time_series$ts_object
  
  # Linear trend analysis
  time_index <- seq_along(ts_data$count)
  trend_model <- lm(count ~ time_index, data = cbind(ts_data, time_index = time_index))
  
  # Extract trend information
  trend_slope <- coef(trend_model)[2]
  trend_pvalue <- summary(trend_model)$coefficients[2, 4]
  r_squared <- summary(trend_model)$r.squared
  
  # Trend direction and significance
  trend_direction <- ifelse(trend_slope > 0, "Increasing", 
                           ifelse(trend_slope < 0, "Decreasing", "Stable"))
  trend_significant <- trend_pvalue < 0.05
  
  # Mann-Kendall test for non-parametric trend
  mk_test <- NULL
  if (academic_validation && require(Kendall, quietly = TRUE)) {
    mk_test <- tryCatch({
      Kendall::MannKendall(ts_data$count)
    }, error = function(e) NULL)
  }
  
  # Polynomial trend fitting
  if (length(ts_data$count) >= 10) {
    poly_model <- lm(count ~ poly(time_index, 2), data = cbind(ts_data, time_index = time_index))
    poly_significant <- summary(poly_model)$coefficients[3, 4] < 0.05
  } else {
    poly_model <- NULL
    poly_significant <- FALSE
  }
  
  # Create trend data for visualization
  trend_data <- ts_data %>%
    mutate(
      time_index = row_number(),
      linear_trend = predict(trend_model),
      polynomial_trend = if (!is.null(poly_model)) predict(poly_model) else linear_trend,
      residuals = count - linear_trend
    )
  
  results <- list(
    # Trend statistics
    slope = trend_slope,
    slope_pvalue = trend_pvalue,
    r_squared = r_squared,
    direction = trend_direction,
    significant = trend_significant,
    
    # Models
    linear_model = trend_model,
    polynomial_model = poly_model,
    polynomial_significant = poly_significant,
    
    # Non-parametric test
    mann_kendall = mk_test,
    
    # Visualization data
    trend_data = trend_data,
    
    # Academic interpretation
    interpretation = paste0(
      "The time series shows a ", tolower(trend_direction), " trend ",
      "(slope = ", round(trend_slope, 4), ") ",
      "which is ", ifelse(trend_significant, "statistically significant", "not significant"),
      " (p = ", round(trend_pvalue, 4), ")."
    )
  )
  
  return(results)
}

#' Analyze Seasonality Patterns
#' 
#' Detects and analyzes seasonal patterns in legislative activity
#' 
#' @param time_series Time series object
#' @param level Analysis level
#' @param academic_validation Enable statistical testing
#' @return Seasonality analysis results
analyze_seasonality <- function(time_series, level, academic_validation) {
  
  ts_obj <- time_series$ts_object
  ts_data <- time_series$main
  
  results <- list()
  
  # Classical seasonal decomposition
  if (length(ts_obj) >= 24 && level %in% c("month", "quarter")) {
    
    # STL decomposition (robust to outliers)
    stl_decomp <- tryCatch({
      stl(ts_obj, s.window = "periodic", robust = TRUE)
    }, error = function(e) NULL)
    
    if (!is.null(stl_decomp)) {
      results$stl_decomposition <- stl_decomp
      
      # Extract seasonal component
      seasonal_component <- as.numeric(stl_decomp$time.series[, "seasonal"])
      trend_component <- as.numeric(stl_decomp$time.series[, "trend"])
      remainder_component <- as.numeric(stl_decomp$time.series[, "remainder"])
      
      # Seasonal strength (ratio of seasonal variance to total variance)
      seasonal_strength <- var(seasonal_component, na.rm = TRUE) / 
                          var(ts_obj, na.rm = TRUE)
      
      results$seasonal_strength <- seasonal_strength
      results$strong_seasonality <- seasonal_strength > 0.1
    }
  }
  
  # Monthly patterns (if daily/weekly data)
  if (level %in% c("day", "week")) {
    monthly_pattern <- time_series$main %>%
      group_by(month) %>%
      summarise(
        avg_count = mean(count, na.rm = TRUE),
        median_count = median(count, na.rm = TRUE),
        sd_count = sd(count, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      mutate(
        month_name = month.name[month],
        cv = sd_count / avg_count  # Coefficient of variation
      )
    
    results$monthly_pattern <- monthly_pattern
    
    # Test for significant monthly differences
    if (academic_validation && nrow(time_series$main) >= 30) {
      monthly_test <- tryCatch({
        aov(count ~ factor(month), data = time_series$main)
      }, error = function(e) NULL)
      
      if (!is.null(monthly_test)) {
        results$monthly_anova <- monthly_test
        results$monthly_significant <- summary(monthly_test)[[1]][1, "Pr(>F)"] < 0.05
      }
    }
  }
  
  # Quarterly patterns
  quarterly_pattern <- time_series$main %>%
    group_by(quarter) %>%
    summarise(
      avg_count = mean(count, na.rm = TRUE),
      median_count = median(count, na.rm = TRUE),
      sd_count = sd(count, na.rm = TRUE),
      .groups = "drop"
    ) %>%
    mutate(
      quarter_name = paste0("Q", quarter),
      cv = sd_count / avg_count
    )
  
  results$quarterly_pattern <- quarterly_pattern
  
  # Weekday patterns (if daily data available)
  if ("weekday" %in% names(time_series$main)) {
    weekday_pattern <- time_series$main %>%
      group_by(weekday) %>%
      summarise(
        avg_count = mean(count, na.rm = TRUE),
        median_count = median(count, na.rm = TRUE),
        .groups = "drop"
      )
    
    results$weekday_pattern <- weekday_pattern
  }
  
  # Academic assessment
  results$academic_assessment <- list(
    has_seasonality = !isTRUE(is.null(results$stl_decomposition)) && (results$seasonal_strength > 0.1),
    seasonal_strength = results$seasonal_strength,
    significant_monthly_variation = results$monthly_significant %||% FALSE,
    methodology = "STL decomposition with robust estimation"
  )
  
  return(results)
}

#' Detect Change Points in Time Series
#' 
#' Identifies structural breaks and regime changes in legislative activity
#' 
#' @param time_series Time series object
#' @param academic_validation Enable statistical validation
#' @return Change point analysis results
detect_change_points <- function(time_series, academic_validation) {
  
  ts_data <- time_series$main$count
  
  results <- list()
  
  if (length(ts_data) >= 10) {
    
    # PELT algorithm for change point detection
    if (require(changepoint, quietly = TRUE)) {
      
      # Change in mean
      cpt_mean <- tryCatch({
        changepoint::cpt.mean(ts_data, method = "PELT", minseglen = 3)
      }, error = function(e) NULL)
      
      if (!is.null(cpt_mean)) {
        mean_changepoints <- changepoint::cpts(cpt_mean)
        results$mean_changepoints <- mean_changepoints
        results$n_mean_changes <- length(mean_changepoints)
      }
      
      # Change in variance
      cpt_var <- tryCatch({
        changepoint::cpt.var(ts_data, method = "PELT", minseglen = 3)
      }, error = function(e) NULL)
      
      if (!is.null(cpt_var)) {
        var_changepoints <- changepoint::cpts(cpt_var)
        results$var_changepoints <- var_changepoints
        results$n_var_changes <- length(var_changepoints)
      }
      
      # Change in mean and variance
      cpt_meanvar <- tryCatch({
        changepoint::cpt.meanvar(ts_data, method = "PELT", minseglen = 5)
      }, error = function(e) NULL)
      
      if (!is.null(cpt_meanvar)) {
        meanvar_changepoints <- changepoint::cpts(cpt_meanvar)
        results$meanvar_changepoints <- meanvar_changepoints
        results$n_meanvar_changes <- length(meanvar_changepoints)
      }
    }
    
    # Bayesian change point analysis
    if (require(bcp, quietly = TRUE) && length(ts_data) >= 20) {
      
      bcp_result <- tryCatch({
        bcp::bcp(ts_data, mcmc = 1000, burnin = 100)
      }, error = function(e) NULL)
      
      if (!is.null(bcp_result)) {
        # Find probable change points (probability > 0.5)
        prob_threshold <- 0.5
        probable_changes <- which(bcp_result$prob.mean > prob_threshold)
        
        results$bayesian_changepoints <- probable_changes
        results$bayesian_probabilities <- bcp_result$prob.mean[probable_changes]
        results$bcp_result <- bcp_result
      }
    }
    
    # Manual structural break test (if academic validation enabled)
    if (academic_validation && length(ts_data) >= 20) {
      
      # Chow test for structural break (simplified)
      mid_point <- floor(length(ts_data) / 2)
      
      # Split data
      first_half <- ts_data[1:mid_point]
      second_half <- ts_data[(mid_point + 1):length(ts_data)]
      
      # Test for difference in means
      t_test_result <- tryCatch({
        t.test(first_half, second_half, var.equal = FALSE)
      }, error = function(e) NULL)
      
      if (!is.null(t_test_result)) {
        results$structural_break_test <- t_test_result
        results$structural_break_significant <- t_test_result$p.value < 0.05
      }
    }
  }
  
  # Create change point summary
  all_changepoints <- c(
    results$mean_changepoints,
    results$var_changepoints,
    results$bayesian_changepoints
  )
  
  results$summary <- list(
    total_changepoints = length(unique(all_changepoints)),
    has_changepoints = length(unique(all_changepoints)) > 0,
    most_likely_changes = if (length(all_changepoints) > 0) {
      sort(table(all_changepoints), decreasing = TRUE)
    } else NULL
  )
  
  return(results)
}

#' Analyze Cyclical Patterns
#' 
#' Examines cyclical behavior in legislative activity
#' 
#' @param temporal_data Original temporal data with parsed dates
#' @param academic_validation Enable statistical testing
#' @return Cyclical analysis results
analyze_cyclical_patterns <- function(temporal_data, academic_validation) {
  
  results <- list()
  
  # Electoral cycle analysis (4-year cycles in Brazil)
  if ("year" %in% names(temporal_data)) {
    
    # Create electoral cycle variable (0-3 years from presidential election)
    # Brazilian presidential elections: 1989, 1994, 1998, 2002, 2006, 2010, 2014, 2018, 2022
    presidential_elections <- c(1989, 1994, 1998, 2002, 2006, 2010, 2014, 2018, 2022)
    
    electoral_cycle_data <- temporal_data %>%
      mutate(
        electoral_cycle = sapply(year, function(y) {
          # Find the most recent presidential election
          recent_election <- max(presidential_elections[presidential_elections <= y])
          cycle_year <- y - recent_election
          
          # Cap at 3 (4th year is election year = 0)
          ifelse(cycle_year >= 4, cycle_year %% 4, cycle_year)
        }),
        electoral_cycle_name = case_when(
          electoral_cycle == 0 ~ "Election Year",
          electoral_cycle == 1 ~ "Post-Election",
          electoral_cycle == 2 ~ "Mid-Term",
          electoral_cycle == 3 ~ "Pre-Election"
        )
      ) %>%
      group_by(electoral_cycle, electoral_cycle_name) %>%
      summarise(
        count = n(),
        avg_per_year = count / length(unique(year)),
        .groups = "drop"
      )
    
    results$electoral_cycle <- electoral_cycle_data
    
    # Statistical test for electoral cycle effect
    if (academic_validation && nrow(temporal_data) >= 100) {
      cycle_test <- tryCatch({
        aov(rep(1, nrow(temporal_data)) ~ factor(electoral_cycle), 
            data = temporal_data %>% 
              mutate(electoral_cycle = sapply(year, function(y) {
                recent_election <- max(presidential_elections[presidential_elections <= y])
                cycle_year <- y - recent_election
                ifelse(cycle_year >= 4, cycle_year %% 4, cycle_year)
              })))
      }, error = function(e) NULL)
      
      if (!is.null(cycle_test)) {
        results$electoral_cycle_test <- cycle_test
        results$electoral_cycle_significant <- summary(cycle_test)[[1]][1, "Pr(>F)"] < 0.05
      }
    }
  }
  
  # Congressional cycle analysis (legislative sessions)
  # Brazilian Congress has regular and extraordinary sessions
  congress_patterns <- temporal_data %>%
    mutate(
      congress_session = case_when(
        month %in% c(2, 3, 4, 5, 6, 7) ~ "Regular Session",
        month %in% c(8, 9, 10, 11, 12) ~ "Extended/Extraordinary",
        TRUE ~ "Recess"
      )
    ) %>%
    group_by(congress_session) %>%
    summarise(
      count = n(),
      proportion = n() / nrow(temporal_data),
      .groups = "drop"
    )
  
  results$congress_patterns <- congress_patterns
  
  # Year-end patterns (December effect)
  year_end_analysis <- temporal_data %>%
    mutate(
      period = case_when(
        month == 12 ~ "December",
        month %in% c(10, 11) ~ "Oct-Nov",
        month %in% c(1, 2) ~ "Jan-Feb",
        TRUE ~ "Other Months"
      )
    ) %>%
    group_by(period) %>%
    summarise(
      count = n(),
      avg_per_month = count / length(unique(paste(year, month))),
      .groups = "drop"
    )
  
  results$year_end_patterns <- year_end_analysis
  
  return(results)
}

#' Conduct Academic Temporal Tests
#' 
#' Performs statistical tests for time series properties
#' 
#' @param time_series Time series object
#' @return Statistical test results
conduct_temporal_tests <- function(time_series) {
  
  ts_data <- time_series$ts_object
  
  results <- list()
  
  # Stationarity tests
  if (length(ts_data) >= 20) {
    
    # Augmented Dickey-Fuller test
    adf_test <- tryCatch({
      tseries::adf.test(ts_data, alternative = "stationary")
    }, error = function(e) NULL)
    
    if (!is.null(adf_test)) {
      results$adf_test <- adf_test
      results$is_stationary_adf <- adf_test$p.value < 0.05
    }
    
    # KPSS test
    kpss_test <- tryCatch({
      tseries::kpss.test(ts_data, null = "Trend")
    }, error = function(e) NULL)
    
    if (!is.null(kpss_test)) {
      results$kpss_test <- kpss_test
      results$is_stationary_kpss <- kpss_test$p.value > 0.05  # Null is stationarity
    }
  }
  
  # Autocorrelation tests
  if (length(ts_data) >= 10) {
    
    # Ljung-Box test for autocorrelation
    lb_test <- tryCatch({
      Box.test(ts_data, lag = min(20, floor(length(ts_data)/4)), type = "Ljung-Box")
    }, error = function(e) NULL)
    
    if (!is.null(lb_test)) {
      results$ljung_box_test <- lb_test
      results$has_autocorrelation <- lb_test$p.value < 0.05
    }
    
    # Durbin-Watson test for serial correlation
    if (length(ts_data) >= 15) {
      dw_test <- tryCatch({
        car::durbinWatsonTest(lm(as.numeric(ts_data) ~ seq_along(ts_data)))
      }, error = function(e) NULL)
      
      if (!is.null(dw_test)) {
        results$durbin_watson_test <- dw_test
      }
    }
  }
  
  # Normality tests for residuals
  if (length(ts_data) >= 30) {
    
    # Shapiro-Wilk test
    sw_test <- tryCatch({
      shapiro.test(as.numeric(ts_data))
    }, error = function(e) NULL)
    
    if (!is.null(sw_test)) {
      results$shapiro_wilk_test <- sw_test
      results$is_normal <- sw_test$p.value > 0.05
    }
    
    # Jarque-Bera test
    if (require(tseries, quietly = TRUE)) {
      jb_test <- tryCatch({
        tseries::jarque.bera.test(as.numeric(ts_data))
      }, error = function(e) NULL)
      
      if (!is.null(jb_test)) {
        results$jarque_bera_test <- jb_test
        results$is_normal_jb <- jb_test$p.value > 0.05
      }
    }
  }
  
  # Academic interpretation
  results$academic_summary <- list(
    stationarity = case_when(
      results$is_stationary_adf && results$is_stationary_kpss ~ "Stationary (both tests)",
      results$is_stationary_adf ~ "Likely stationary (ADF only)",
      results$is_stationary_kpss ~ "Likely stationary (KPSS only)",
      TRUE ~ "Non-stationary"
    ),
    autocorrelation = ifelse(results$has_autocorrelation, "Present", "Absent"),
    normality = case_when(
      results$is_normal && results$is_normal_jb ~ "Normal distribution",
      results$is_normal ~ "Likely normal (Shapiro-Wilk)",
      results$is_normal_jb ~ "Likely normal (Jarque-Bera)",
      TRUE ~ "Non-normal distribution"
    ),
    sample_adequate = length(ts_data) >= 30
  )
  
  return(results)
}

#' Generate Temporal Forecasts
#' 
#' Creates forecasts using appropriate time series methods
#' 
#' @param ts_data Time series data frame
#' @param level Analysis level
#' @param forecast_periods Number of periods to forecast
#' @return Forecast results
generate_forecasts <- function(ts_data, level, forecast_periods = 12) {
  
  ts_obj <- ts(ts_data$count, frequency = switch(level,
    "month" = 12,
    "quarter" = 4,
    "year" = 1,
    1
  ))
  
  results <- list()
  
  if (length(ts_obj) >= 20) {
    
    # Automatic ARIMA forecasting
    auto_arima <- tryCatch({
      forecast::auto.arima(ts_obj, seasonal = TRUE, stepwise = FALSE, approximation = FALSE)
    }, error = function(e) NULL)
    
    if (!is.null(auto_arima)) {
      arima_forecast <- forecast::forecast(auto_arima, h = forecast_periods)
      
      results$arima <- list(
        model = auto_arima,
        forecast = arima_forecast,
        aic = AIC(auto_arima),
        bic = BIC(auto_arima)
      )
    }
    
    # Exponential smoothing
    ets_model <- tryCatch({
      forecast::ets(ts_obj)
    }, error = function(e) NULL)
    
    if (!is.null(ets_model)) {
      ets_forecast <- forecast::forecast(ets_model, h = forecast_periods)
      
      results$ets <- list(
        model = ets_model,
        forecast = ets_forecast,
        aic = AIC(ets_model)
      )
    }
    
    # Simple methods for comparison
    naive_forecast <- forecast::naive(ts_obj, h = forecast_periods)
    seasonal_naive <- tryCatch({
      forecast::snaive(ts_obj, h = forecast_periods)
    }, error = function(e) naive_forecast)
    
    results$naive <- naive_forecast
    results$seasonal_naive <- seasonal_naive
    
    # Model selection based on AIC
    model_comparison <- data.frame(
      Model = character(0),
      AIC = numeric(0),
      stringsAsFactors = FALSE
    )
    
    if (!is.null(results$arima)) {
      model_comparison <- rbind(model_comparison, 
                               data.frame(Model = "ARIMA", AIC = results$arima$aic))
    }
    
    if (!is.null(results$ets)) {
      model_comparison <- rbind(model_comparison,
                               data.frame(Model = "ETS", AIC = results$ets$aic))
    }
    
    if (nrow(model_comparison) > 0) {
      best_model <- model_comparison$Model[which.min(model_comparison$AIC)]
      results$best_model <- best_model
      results$model_comparison <- model_comparison
    }
  }
  
  return(results)
}

cat("✅ Temporal Analysis Module Loaded Successfully\n")
cat("📅 Features: Trend analysis, seasonality detection, change points, forecasting\n")
cat("🔬 Statistical tests: ADF, KPSS, Ljung-Box, normality tests\n")
cat("🎯 Academic validation: Publication-ready statistical analysis\n\n")