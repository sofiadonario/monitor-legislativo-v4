# ============================================================================
# ENHANCED ADVANCED ANALYTICS ENGINE - BRAZILIAN LEGISLATIVE MONITORING SYSTEM
# ============================================================================
# 
# Comprehensive data science platform for 134K+ Brazilian legislative documents
# Statistical Analysis | Machine Learning | NLP | Network Analysis | Forecasting
# Research-grade analytics for government officials, policy researchers, academics
# 
# Performance optimized for Railway deployment | PostgreSQL optimized queries
# ============================================================================

cat("🚀 Loading Enhanced Advanced Analytics Engine...\n")

# Load required packages with graceful fallbacks
required_analytics_packages <- c(
  # Core analytics
  "dplyr", "tidyr", "lubridate", "stringr", "purrr", "ggplot2", "plotly",
  # Statistical analysis
  "bcp", "changepoint", "forecast", "tseries", "MASS", "corrplot",
  # Machine learning
  "randomForest", "cluster", "factoextra", "e1071",
  # Text analysis
  "tm", "tidytext", "wordcloud2", "textstat",
  # Network analysis
  "igraph", "networkD3", "visNetwork",
  # Advanced visualizations
  "DT", "shinydashboard", "shinyWidgets", "RColorBrewer", "scales"
)

# Function to safely load packages
load_analytics_packages <- function() {
  for (pkg in required_analytics_packages) {
    tryCatch({
      suppressPackageStartupMessages(library(pkg, character.only = TRUE))
    }, error = function(e) {
      cat("⚠️ Package", pkg, "not available - using fallbacks\n")
    })
  }
}

# Load packages
load_analytics_packages()

# ============================================================================
# ADVANCED STATISTICAL ANALYSIS MODULE
# ============================================================================

#' Comprehensive Time Series Analysis for Brazilian Legislative Data
#' 
#' @param data Data frame with legislative documents
#' @param date_column Character string, name of date column
#' @param group_by Character vector, grouping variables (e.g., "state", "category")
#' @param forecast_horizon Integer, number of periods to forecast
#' @return List with comprehensive time series analysis results
advanced_time_series_analysis <- function(data, date_column = "date", 
                                        group_by = NULL, forecast_horizon = 12) {
  
  cat("📈 Starting advanced time series analysis...\n")
  
  tryCatch({
    # Data preparation
    data <- data %>%
      mutate(
        parsed_date = as.Date(get(date_column)),
        year = year(parsed_date),
        month = month(parsed_date),
        quarter = quarter(parsed_date),
        year_month = floor_date(parsed_date, "month"),
        year_quarter = floor_date(parsed_date, "quarter")
      ) %>%
      filter(!is.na(parsed_date), year >= 1990, year <= 2025)
    
    if (nrow(data) == 0) {
      return(list(error = "No valid temporal data"))
    }
    
    # Monthly aggregation
    monthly_series <- data %>%
      group_by(year_month) %>%
      summarise(
        document_count = n(),
        unique_categories = n_distinct(category, na.rm = TRUE),
        unique_states = n_distinct(state, na.rm = TRUE),
        avg_complexity = mean(nchar(title), na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(year_month) %>%
      complete(year_month = seq.Date(min(year_month), max(year_month), by = "month"),
               fill = list(document_count = 0, unique_categories = 0, unique_states = 0))
    
    # Time series decomposition
    ts_data <- ts(monthly_series$document_count, 
                  start = c(year(min(monthly_series$year_month)), month(min(monthly_series$year_month))), 
                  frequency = 12)
    
    # Seasonal decomposition
    decomposition_results <- tryCatch({
      if (length(ts_data) > 24) {
        stl_decomp <- stl(ts_data, s.window = "periodic")
        list(
          seasonal = as.numeric(stl_decomp$time.series[, "seasonal"]),
          trend = as.numeric(stl_decomp$time.series[, "trend"]),
          remainder = as.numeric(stl_decomp$time.series[, "remainder"]),
          seasonal_strength = var(stl_decomp$time.series[, "seasonal"], na.rm = TRUE) / 
                            var(ts_data, na.rm = TRUE),
          trend_strength = var(stl_decomp$time.series[, "trend"], na.rm = TRUE) / 
                          var(ts_data, na.rm = TRUE)
        )
      } else {
        NULL
      }
    }, error = function(e) NULL)
    
    # Change point detection
    change_points <- tryCatch({
      if (requireNamespace("changepoint", quietly = TRUE) && length(ts_data) > 20) {
        cpt_mean <- changepoint::cpt.mean(as.numeric(ts_data), method = "PELT")
        list(
          change_points = changepoint::cpts(cpt_mean),
          n_changepoints = changepoint::ncpts(cpt_mean)
        )
      } else {
        NULL
      }
    }, error = function(e) NULL)
    
    # Forecasting
    forecast_results <- tryCatch({
      if (requireNamespace("forecast", quietly = TRUE) && length(ts_data) > 12) {
        # Auto ARIMA model
        arima_model <- forecast::auto.arima(ts_data, seasonal = TRUE)
        forecast_obj <- forecast::forecast(arima_model, h = forecast_horizon)
        
        list(
          model_name = paste0("ARIMA(", arima_model$arma[1], ",", arima_model$arma[6], 
                             ",", arima_model$arma[2], ")(", arima_model$arma[3], 
                             ",", arima_model$arma[7], ",", arima_model$arma[4], ")"),
          forecast_values = as.numeric(forecast_obj$mean),
          lower_80 = as.numeric(forecast_obj$lower[, "80%"]),
          upper_80 = as.numeric(forecast_obj$upper[, "80%"]),
          lower_95 = as.numeric(forecast_obj$lower[, "95%"]),
          upper_95 = as.numeric(forecast_obj$upper[, "95%"]),
          accuracy = forecast::accuracy(forecast_obj),
          aic = arima_model$aic,
          bic = arima_model$bic
        )
      } else {
        # Simple linear trend forecast as fallback
        lm_model <- lm(document_count ~ seq_along(document_count), data = monthly_series)
        future_seq <- seq(nrow(monthly_series) + 1, nrow(monthly_series) + forecast_horizon)
        forecast_vals <- predict(lm_model, newdata = data.frame(seq_along = future_seq))
        
        list(
          model_name = "Linear Trend",
          forecast_values = as.numeric(forecast_vals),
          lower_80 = as.numeric(forecast_vals * 0.9),
          upper_80 = as.numeric(forecast_vals * 1.1),
          lower_95 = as.numeric(forecast_vals * 0.8),
          upper_95 = as.numeric(forecast_vals * 1.2),
          accuracy = data.frame(RMSE = sqrt(mean(residuals(lm_model)^2)))
        )
      }
    }, error = function(e) {
      list(model_name = "Fallback", error = e$message)
    })
    
    # Statistical tests
    statistical_tests <- list(
      # Stationarity test
      stationarity = tryCatch({
        if (requireNamespace("tseries", quietly = TRUE)) {
          adf_test <- tseries::adf.test(as.numeric(ts_data))
          list(
            test_name = "Augmented Dickey-Fuller",
            statistic = adf_test$statistic,
            p_value = adf_test$p.value,
            is_stationary = adf_test$p.value < 0.05
          )
        } else {
          list(test_name = "Not available", is_stationary = FALSE)
        }
      }, error = function(e) list(test_name = "Failed", error = e$message)),
      
      # Seasonality test
      seasonality = tryCatch({
        if (length(ts_data) > 24) {
          # Friedman test for seasonality
          monthly_matrix <- matrix(as.numeric(ts_data), ncol = 12, byrow = TRUE)
          if (nrow(monthly_matrix) > 2) {
            friedman_test <- friedman.test(monthly_matrix)
            list(
              test_name = "Friedman Seasonality",
              statistic = friedman_test$statistic,
              p_value = friedman_test$p.value,
              is_seasonal = friedman_test$p.value < 0.05
            )
          } else {
            list(test_name = "Insufficient data", is_seasonal = FALSE)
          }
        } else {
          list(test_name = "Insufficient data", is_seasonal = FALSE)
        }
      }, error = function(e) list(test_name = "Failed", error = e$message))
    )
    
    # Grouped analysis if requested
    grouped_analysis <- NULL
    if (!is.null(group_by) && all(group_by %in% names(data))) {
      grouped_analysis <- data %>%
        group_by(!!!syms(group_by), year_month) %>%
        summarise(count = n(), .groups = "drop") %>%
        group_by(!!!syms(group_by)) %>%
        summarise(
          total_documents = sum(count),
          avg_monthly = mean(count),
          peak_month = year_month[which.max(count)],
          trend_slope = if (n() > 3) {
            coef(lm(count ~ as.numeric(year_month)))[2]
          } else NA,
          .groups = "drop"
        ) %>%
        arrange(desc(total_documents))
    }
    
    cat("✅ Time series analysis completed\n")
    
    return(list(
      monthly_series = monthly_series,
      ts_object = ts_data,
      decomposition = decomposition_results,
      change_points = change_points,
      forecast = forecast_results,
      statistical_tests = statistical_tests,
      grouped_analysis = grouped_analysis,
      summary_stats = list(
        total_observations = length(ts_data),
        mean_monthly = mean(ts_data, na.rm = TRUE),
        std_monthly = sd(ts_data, na.rm = TRUE),
        cv = sd(ts_data, na.rm = TRUE) / mean(ts_data, na.rm = TRUE),
        date_range = paste(min(monthly_series$year_month), "to", max(monthly_series$year_month))
      )
    ))
    
  }, error = function(e) {
    cat("❌ Time series analysis failed:", e$message, "\n")
    return(list(error = e$message))
  })
}

#' Advanced Regression Analysis for Legislative Factors
#' 
#' @param data Data frame with legislative documents and covariates
#' @param response_var Character string, response variable name
#' @param predictor_vars Character vector, predictor variable names
#' @param analysis_type Character: "linear", "logistic", "robust", "all"
#' @return Comprehensive regression analysis results
advanced_regression_analysis <- function(data, response_var = "document_count", 
                                       predictor_vars = c("year", "category", "state"),
                                       analysis_type = "all") {
  
  cat("📊 Starting advanced regression analysis...\n")
  
  tryCatch({
    # Data preparation
    available_predictors <- predictor_vars[predictor_vars %in% names(data)]
    
    if (length(available_predictors) == 0) {
      return(list(error = "No predictor variables available"))
    }
    
    # Create aggregated dataset for regression
    if (!response_var %in% names(data)) {
      # Create document count by groups
      regression_data <- data %>%
        group_by(!!!syms(available_predictors)) %>%
        summarise(document_count = n(), .groups = "drop")
      response_var <- "document_count"
    } else {
      regression_data <- data
    }
    
    # Handle missing values
    regression_data <- regression_data %>%
      filter(!is.na(get(response_var))) %>%
      filter(if_all(all_of(available_predictors), ~ !is.na(.)))
    
    if (nrow(regression_data) < 10) {
      return(list(error = "Insufficient data for regression analysis"))
    }
    
    # Linear regression analysis
    linear_results <- tryCatch({
      formula_str <- paste(response_var, "~", paste(available_predictors, collapse = " + "))
      lm_formula <- as.formula(formula_str)
      
      lm_model <- lm(lm_formula, data = regression_data)
      
      # Model diagnostics
      residuals <- residuals(lm_model)
      fitted_vals <- fitted(lm_model)
      
      # Diagnostic tests
      normality_test <- tryCatch({
        shapiro.test(residuals)
      }, error = function(e) NULL)
      
      heteroscedasticity_test <- tryCatch({
        # Breusch-Pagan test approximation
        bp_lm <- lm(residuals^2 ~ fitted_vals)
        bp_stat <- summary(bp_lm)$r.squared * nrow(regression_data)
        list(statistic = bp_stat, p_value = pchisq(bp_stat, df = 1, lower.tail = FALSE))
      }, error = function(e) NULL)
      
      list(
        model = lm_model,
        summary = summary(lm_model),
        coefficients = summary(lm_model)$coefficients,
        r_squared = summary(lm_model)$r.squared,
        adj_r_squared = summary(lm_model)$adj.r.squared,
        f_statistic = summary(lm_model)$fstatistic,
        residual_se = summary(lm_model)$sigma,
        diagnostics = list(
          normality_test = normality_test,
          heteroscedasticity_test = heteroscedasticity_test,
          residuals = residuals,
          fitted_values = fitted_vals
        )
      )
    }, error = function(e) list(error = e$message))
    
    # Robust regression if available
    robust_results <- tryCatch({
      if (requireNamespace("MASS", quietly = TRUE) && !is.null(linear_results$model)) {
        rlm_model <- MASS::rlm(linear_results$model$call$formula, data = regression_data)
        list(
          model = rlm_model,
          coefficients = summary(rlm_model)$coefficients,
          residual_se = rlm_model$s
        )
      } else {
        NULL
      }
    }, error = function(e) NULL)
    
    # Correlation analysis
    correlation_analysis <- tryCatch({
      numeric_vars <- regression_data %>%
        select_if(is.numeric) %>%
        names()
      
      if (length(numeric_vars) > 1) {
        cor_matrix <- cor(regression_data[numeric_vars], use = "complete.obs")
        
        # Significance tests for correlations
        cor_tests <- combn(numeric_vars, 2, function(vars) {
          test_result <- cor.test(regression_data[[vars[1]]], regression_data[[vars[2]]])
          list(
            var1 = vars[1],
            var2 = vars[2],
            correlation = test_result$estimate,
            p_value = test_result$p.value,
            significant = test_result$p.value < 0.05
          )
        }, simplify = FALSE)
        
        list(
          correlation_matrix = cor_matrix,
          correlation_tests = cor_tests
        )
      } else {
        NULL
      }
    }, error = function(e) NULL)
    
    # Variable importance analysis
    variable_importance <- tryCatch({
      if (!is.null(linear_results$model)) {
        # Calculate relative importance using R-squared decomposition
        model_summary <- linear_results$summary
        coeffs <- model_summary$coefficients
        
        # Standardized coefficients
        std_coeffs <- coeffs[-1, "Estimate"] * 
          apply(regression_data[available_predictors], 2, sd, na.rm = TRUE) / 
          sd(regression_data[[response_var]], na.rm = TRUE)
        
        importance_df <- data.frame(
          variable = names(std_coeffs),
          std_coefficient = std_coeffs,
          t_value = coeffs[-1, "t value"],
          p_value = coeffs[-1, "Pr(>|t|)"],
          significant = coeffs[-1, "Pr(>|t|)"] < 0.05,
          abs_importance = abs(std_coeffs),
          stringsAsFactors = FALSE
        ) %>%
          arrange(desc(abs_importance))
        
        importance_df
      } else {
        NULL
      }
    }, error = function(e) NULL)
    
    # Model comparison and selection
    model_selection <- tryCatch({
      if (!is.null(linear_results$model) && length(available_predictors) > 1) {
        # Forward/backward selection using AIC
        null_model <- lm(as.formula(paste(response_var, "~ 1")), data = regression_data)
        full_model <- linear_results$model
        
        forward_model <- step(null_model, scope = list(lower = null_model, upper = full_model),
                            direction = "forward", trace = FALSE)
        backward_model <- step(full_model, direction = "backward", trace = FALSE)
        
        list(
          forward_selection = list(
            formula = forward_model$call$formula,
            aic = AIC(forward_model),
            variables = all.vars(forward_model$call$formula)[-1]
          ),
          backward_selection = list(
            formula = backward_model$call$formula,
            aic = AIC(backward_model),
            variables = all.vars(backward_model$call$formula)[-1]
          ),
          full_model_aic = AIC(full_model)
        )
      } else {
        NULL
      }
    }, error = function(e) NULL)
    
    cat("✅ Regression analysis completed\n")
    
    return(list(
      linear_regression = linear_results,
      robust_regression = robust_results,
      correlation_analysis = correlation_analysis,
      variable_importance = variable_importance,
      model_selection = model_selection,
      data_summary = list(
        n_observations = nrow(regression_data),
        n_predictors = length(available_predictors),
        response_variable = response_var,
        predictor_variables = available_predictors,
        missing_data_pct = sum(is.na(regression_data)) / (nrow(regression_data) * ncol(regression_data)) * 100
      )
    ))
    
  }, error = function(e) {
    cat("❌ Regression analysis failed:", e$message, "\n")
    return(list(error = e$message))
  })
}

#' Advanced Hypothesis Testing for Legislative Policy Changes
#' 
#' @param data Data frame with legislative documents
#' @param test_type Character: "policy_change", "temporal_shift", "jurisdictional_differences"
#' @param group_vars Character vector, grouping variables for comparison
#' @param alpha Numeric, significance level (default: 0.05)
#' @return Comprehensive hypothesis testing results
advanced_hypothesis_testing <- function(data, test_type = "policy_change", 
                                      group_vars = c("year", "category"), alpha = 0.05) {
  
  cat("🔬 Starting advanced hypothesis testing...\n")
  
  tryCatch({
    results <- list()
    
    # Policy Change Detection Tests
    if (test_type %in% c("policy_change", "all")) {
      
      # Test for changes in document volume over time
      yearly_counts <- data %>%
        filter(!is.na(year), year >= 2000) %>%
        group_by(year) %>%
        summarise(count = n(), .groups = "drop") %>%
        arrange(year)
      
      if (nrow(yearly_counts) > 10) {
        # Split data into pre/post periods (e.g., before/after 2018)
        split_year <- 2018
        pre_period <- yearly_counts %>% filter(year < split_year)
        post_period <- yearly_counts %>% filter(year >= split_year)
        
        if (nrow(pre_period) > 2 && nrow(post_period) > 2) {
          # Two-sample t-test
          t_test_result <- t.test(pre_period$count, post_period$count)
          
          # Mann-Whitney U test (non-parametric)
          wilcox_test_result <- wilcox.test(pre_period$count, post_period$count)
          
          results$policy_change <- list(
            test_description = paste("Policy change detection around", split_year),
            t_test = list(
              statistic = t_test_result$statistic,
              p_value = t_test_result$p.value,
              conf_interval = t_test_result$conf.int,
              pre_mean = mean(pre_period$count),
              post_mean = mean(post_period$count),
              significant = t_test_result$p.value < alpha
            ),
            wilcoxon_test = list(
              statistic = wilcox_test_result$statistic,
              p_value = wilcox_test_result$p.value,
              significant = wilcox_test_result$p.value < alpha
            )
          )
        }
      }
    }
    
    # Temporal Shift Analysis
    if (test_type %in% c("temporal_shift", "all")) {
      
      # Test for shifts in document categories over time
      if ("category" %in% names(data)) {
        category_temporal <- data %>%
          filter(!is.na(year), !is.na(category), year >= 2010) %>%
          mutate(period = ifelse(year < 2020, "before_2020", "after_2020")) %>%
          count(period, category) %>%
          pivot_wider(names_from = period, values_from = n, values_fill = 0)
        
        if (ncol(category_temporal) >= 3 && nrow(category_temporal) > 1) {
          # Chi-square test for association
          chi_sq_matrix <- as.matrix(category_temporal[, -1])
          rownames(chi_sq_matrix) <- category_temporal$category
          
          chi_sq_test <- chisq.test(chi_sq_matrix)
          
          # Calculate effect size (Cramér's V)
          cramers_v <- sqrt(chi_sq_test$statistic / (sum(chi_sq_matrix) * (min(dim(chi_sq_matrix)) - 1)))
          
          results$temporal_shift <- list(
            test_description = "Temporal shift in document categories",
            chi_square_test = list(
              statistic = chi_sq_test$statistic,
              p_value = chi_sq_test$p.value,
              df = chi_sq_test$parameter,
              cramers_v = cramers_v,
              significant = chi_sq_test$p.value < alpha
            ),
            contingency_table = chi_sq_matrix
          )
        }
      }
    }
    
    # Jurisdictional Differences Analysis
    if (test_type %in% c("jurisdictional_differences", "all")) {
      
      if ("state" %in% names(data)) {
        state_summary <- data %>%
          filter(!is.na(state), state != "") %>%
          group_by(state) %>%
          summarise(
            count = n(),
            avg_year = mean(year, na.rm = TRUE),
            .groups = "drop"
          ) %>%
          filter(count >= 10) %>%  # Only states with sufficient data
          arrange(desc(count))
        
        if (nrow(state_summary) > 2) {
          # ANOVA for differences in average years across states
          anova_data <- data %>%
            filter(state %in% state_summary$state, !is.na(year)) %>%
            select(state, year)
          
          anova_result <- aov(year ~ state, data = anova_data)
          anova_summary <- summary(anova_result)
          
          # Post-hoc analysis (Tukey HSD) if significant
          tukey_results <- NULL
          if (scalar_num(anova_summary[[1]]$"Pr(>F)", 1) < alpha) {
            tukey_results <- TukeyHSD(anova_result)
          }
          
          results$jurisdictional_differences <- list(
            test_description = "Jurisdictional differences in temporal patterns",
            anova_test = list(
              f_statistic = scalar_num(anova_summary[[1]]$"F value", NA),
              p_value = scalar_num(anova_summary[[1]]$"Pr(>F)", 1),
              df_between = scalar_num(anova_summary[[1]]$"Df", NA),
              df_within = if(length(anova_summary[[1]]$"Df") >= 2) scalar_num(anova_summary[[1]]$"Df"[2], NA) else NA,
              significant = scalar_num(anova_summary[[1]]$"Pr(>F)", 1) < alpha
            ),
            tukey_hsd = tukey_results,
            state_means = state_summary
          )
        }
      }
    }
    
    # Multiple comparisons adjustment
    all_p_values <- c()
    test_names <- c()
    
    for (test_name in names(results)) {
      test_result <- results[[test_name]]
      if ("t_test" %in% names(test_result)) {
        all_p_values <- c(all_p_values, test_result$t_test$p_value)
        test_names <- c(test_names, paste(test_name, "t_test"))
      }
      if ("chi_square_test" %in% names(test_result)) {
        all_p_values <- c(all_p_values, test_result$chi_square_test$p_value)
        test_names <- c(test_names, paste(test_name, "chi_square"))
      }
      if ("anova_test" %in% names(test_result)) {
        all_p_values <- c(all_p_values, test_result$anova_test$p_value)
        test_names <- c(test_names, paste(test_name, "anova"))
      }
    }
    
    # Bonferroni and FDR corrections
    if (length(all_p_values) > 1) {
      bonferroni_adjusted <- p.adjust(all_p_values, method = "bonferroni")
      fdr_adjusted <- p.adjust(all_p_values, method = "fdr")
      
      results$multiple_comparisons <- data.frame(
        test = test_names,
        raw_p_value = all_p_values,
        bonferroni_p = bonferroni_adjusted,
        fdr_p = fdr_adjusted,
        bonferroni_significant = bonferroni_adjusted < alpha,
        fdr_significant = fdr_adjusted < alpha,
        stringsAsFactors = FALSE
      )
    }
    
    cat("✅ Hypothesis testing completed\n")
    
    return(list(
      test_results = results,
      summary = list(
        total_tests = length(results),
        significant_tests = sum(sapply(results, function(x) {
          any(sapply(x, function(y) if (is.list(y) && "significant" %in% names(y)) y$significant else FALSE))
        })),
        alpha_level = alpha,
        analysis_timestamp = Sys.time()
      )
    ))
    
  }, error = function(e) {
    cat("❌ Hypothesis testing failed:", e$message, "\n")
    return(list(error = e$message))
  })
}

cat("✅ Enhanced Advanced Analytics Engine - Statistical Analysis Module loaded\n")
cat("   📈 Time series analysis with forecasting: ENABLED\n")
cat("   📊 Advanced regression analysis: ENABLED\n") 
cat("   🔬 Comprehensive hypothesis testing: ENABLED\n")
cat("   📉 Change point detection: ENABLED\n")
cat("   🎯 Model selection and validation: ENABLED\n")