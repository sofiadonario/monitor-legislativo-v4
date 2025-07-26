#!/usr/bin/env Rscript
#' Brazilian Legislative Dataset - Phase 2: Temporal Analysis Framework
#' 
#' This script implements comprehensive temporal analysis capabilities for the Brazilian
#' legislative dataset, including topic evolution, policy timeline visualization,
#' survival analysis, and forecasting using fable and tsibble.
#' 
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-07-26
#' @version 1.0.0

# Load required libraries
suppressPackageStartupMessages({
  library(dplyr)
  library(lubridate)
  library(tsibble)
  library(fable)
  library(fabletools)
  library(feasts)
  library(survival)
  library(survminer)
  library(ggplot2)
  library(plotly)
  library(viridis)
  library(arrow)
  library(stringr)
  library(purrr)
  library(tidyr)
  library(bcp)
  library(changepoint)
  library(forecast)
  library(prophet)
  library(stm)
  library(logger)
})

# Set up logging
log_threshold(INFO)

#' Temporal Analysis Functions
#' ===========================

#' Prepare temporal dataset from legislative data
#' @param data_source Path to Parquet file or data frame
#' @return Temporal data with proper time indexing
prepare_temporal_data <- function(data_source) {
  
  log_info("Preparing temporal dataset...")
  
  if (is.character(data_source)) {
    data <- read_parquet(data_source)
  } else {
    data <- data_source
  }
  
  # Clean and prepare temporal data
  temporal_data <- data %>%
    filter(!is.na(data)) %>%
    mutate(
      date = as.Date(data),
      year = year(date),
      month = month(date),
      quarter = quarter(date),
      decade = floor(year / 10) * 10,
      
      # Create year-month for monthly analysis
      year_month = yearmonth(date),
      
      # Categorize time periods
      time_period = case_when(
        year < 1990 ~ "Pre-1990",
        year >= 1990 & year < 2000 ~ "1990s",
        year >= 2000 & year < 2010 ~ "2000s", 
        year >= 2010 & year < 2020 ~ "2010s",
        year >= 2020 ~ "2020s"
      ),
      
      # Authority level standardization
      authority_level = case_when(
        str_detect(tolower(autoridade %||% ""), "federal") | jurisdicao == "Federal" ~ "Federal",
        str_detect(tolower(autoridade %||% ""), "estadual|estado") | (!is.na(estado) & estado != "") ~ "State",
        str_detect(tolower(autoridade %||% ""), "municipal|prefeitura") | (!is.na(municipio) & municipio != "") ~ "Municipal",
        TRUE ~ "Unknown"
      )
    ) %>%
    filter(
      year >= 1900,  # Remove obviously invalid dates
      year <= year(Sys.Date())  # Remove future dates
    ) %>%
    arrange(date)
  
  log_info("Prepared temporal dataset with {nrow(temporal_data)} documents spanning {min(temporal_data$year)}-{max(temporal_data$year)}")
  
  return(temporal_data)
}

#' Create time series for different aggregation levels
#' @param temporal_data Prepared temporal data
#' @param aggregation_level Time aggregation ("month", "quarter", "year")
#' @return tsibble object for time series analysis
create_time_series <- function(temporal_data, aggregation_level = "month") {
  
  log_info("Creating time series with {aggregation_level} aggregation...")
  
  # Define aggregation function
  agg_col <- switch(aggregation_level,
    "month" = "year_month",
    "quarter" = quo(yearquarter(date)),
    "year" = quo(year(date))
  )
  
  if (aggregation_level == "month") {
    time_series <- temporal_data %>%
      group_by(year_month, categoria, modal, authority_level) %>%
      summarise(
        count = n(),
        avg_text_length = mean(nchar(titulo %||% ""), na.rm = TRUE),
        .groups = "drop"
      ) %>%
      as_tsibble(key = c(categoria, modal, authority_level), index = year_month)
  } else {
    time_series <- temporal_data %>%
      group_by(!!agg_col, categoria, modal, authority_level) %>%
      summarise(
        count = n(),
        avg_text_length = mean(nchar(titulo %||% ""), na.rm = TRUE),
        .groups = "drop"
      ) %>%
      rename(time_index = !!agg_col) %>%
      as_tsibble(key = c(categoria, modal, authority_level), index = time_index)
  }
  
  log_info("Created time series with {nrow(time_series)} observations")
  return(time_series)
}

#' Analyze topic evolution over time using STM
#' @param temporal_data Temporal dataset
#' @param time_slices Vector of time periods for dynamic modeling
#' @param num_topics Number of topics for modeling
#' @return Topic evolution results
analyze_topic_evolution <- function(temporal_data, time_slices = NULL, num_topics = 15) {
  
  log_info("Analyzing topic evolution over time...")
  
  # Default time slices if not provided
  if (is.null(time_slices)) {
    time_slices <- seq(1990, 2025, by = 5)  # 5-year periods
  }
  
  # Prepare text data for STM
  stm_data <- temporal_data %>%
    filter(!is.na(titulo), nchar(titulo) > 10) %>%
    mutate(
      combined_text = paste(titulo, coalesce(assuntos, ""), coalesce(ementa, ""), sep = " "),
      time_slice = cut(year, breaks = time_slices, include.lowest = TRUE, labels = FALSE)
    ) %>%
    filter(!is.na(time_slice))
  
  # Prepare STM corpus
  processed <- textProcessor(stm_data$combined_text, 
                           metadata = stm_data,
                           language = "pt",
                           stem = TRUE,
                           wordLengths = c(3, Inf))
  
  out <- prepDocuments(processed$documents, processed$vocab, processed$meta,
                      lower.thresh = 5)
  
  # Fit STM model with time as prevalence covariate
  stm_model <- stm(documents = out$documents,
                  vocab = out$vocab,
                  K = num_topics,
                  prevalence = ~ year + categoria + authority_level,
                  data = out$meta,
                  init.type = "Spectral")
  
  # Extract topic evolution
  topic_evolution <- estimateEffect(1:num_topics ~ year + categoria + authority_level,
                                  stm_model, meta = out$meta, uncertainty = "Global")
  
  # Topic proportions over time
  topic_time_series <- map_dfr(1:num_topics, function(k) {
    topic_props <- map_dfr(time_slices[-length(time_slices)], function(time_period) {
      subset_meta <- out$meta[out$meta$year >= time_period & out$meta$year < time_period + 5, ]
      if (nrow(subset_meta) > 0) {
        props <- colMeans(stm_model$theta[rownames(subset_meta), ])
        tibble(
          time_period = time_period,
          topic = 1:num_topics,
          proportion = props
        )
      } else {
        tibble(time_period = time_period, topic = 1:num_topics, proportion = 0)
      }
    })
    topic_props %>% filter(topic == k) %>% mutate(topic_label = paste("Topic", k))
  })
  
  # Get topic labels (top words)
  topic_labels <- labelTopics(stm_model, n = 5)
  topic_words <- map_chr(1:num_topics, function(k) {
    paste(topic_labels$frex[k, ], collapse = ", ")
  })
  
  log_info("Topic evolution analysis completed for {num_topics} topics across {length(time_slices)-1} time periods")
  
  return(list(
    stm_model = stm_model,
    topic_evolution = topic_evolution,
    topic_time_series = topic_time_series,
    topic_words = topic_words,
    processed_data = out
  ))
}

#' Detect policy waves and regulatory changes
#' @param temporal_data Temporal dataset
#' @param change_point_method Method for change point detection
#' @return Change point analysis results
detect_policy_waves <- function(temporal_data, change_point_method = "bcp") {
  
  log_info("Detecting policy waves and regulatory changes...")
  
  # Aggregate by year and category
  yearly_counts <- temporal_data %>%
    group_by(year, categoria, authority_level) %>%
    summarise(count = n(), .groups = "drop") %>%
    complete(year = full_seq(year, 1), categoria, authority_level, fill = list(count = 0))
  
  change_points <- list()
  
  # Detect change points for each category-authority combination
  for (cat in unique(yearly_counts$categoria)) {
    for (auth in unique(yearly_counts$authority_level)) {
      
      series_data <- yearly_counts %>%
        filter(categoria == cat, authority_level == auth) %>%
        arrange(year)
      
      if (nrow(series_data) > 10 && sum(series_data$count) > 0) {
        
        if (change_point_method == "bcp") {
          # Bayesian Change Point analysis
          bcp_result <- bcp(series_data$count, mcmc = 5000, burnin = 1000)
          
          # Find significant change points (probability > 0.5)
          change_years <- series_data$year[which(bcp_result$prob.mean > 0.5)]
          
          change_points[[paste(cat, auth, sep = "_")]] <- list(
            categoria = cat,
            authority_level = auth,
            change_years = change_years,
            probabilities = bcp_result$prob.mean[bcp_result$prob.mean > 0.5],
            method = "BCP"
          )
          
        } else if (change_point_method == "cpt") {
          # PELT change point detection
          cpt_result <- cpt.mean(series_data$count, method = "PELT")
          change_indices <- cpts(cpt_result)
          
          if (length(change_indices) > 0) {
            change_years <- series_data$year[change_indices]
            
            change_points[[paste(cat, auth, sep = "_")]] <- list(
              categoria = cat,
              authority_level = auth,
              change_years = change_years,
              method = "PELT"
            )
          }
        }
      }
    }
  }
  
  # Summarize major policy waves
  all_change_years <- map(change_points, "change_years") %>% unlist() %>% table()
  major_waves <- names(all_change_years)[all_change_years >= 2]  # Years with changes in multiple categories
  
  log_info("Detected {length(change_points)} change point series and {length(major_waves)} major policy wave years")
  
  return(list(
    change_points = change_points,
    major_waves = as.numeric(major_waves),
    yearly_counts = yearly_counts
  ))
}

#' Perform survival analysis for policy lifespan
#' @param temporal_data Temporal dataset
#' @return Survival analysis results
analyze_policy_survival <- function(temporal_data) {
  
  log_info("Performing survival analysis for policy lifespan...")
  
  # Create survival dataset - policies that are amended/revoked
  # This is a simplified example - in practice, you'd need explicit amendment/revocation data
  
  survival_data <- temporal_data %>%
    filter(!is.na(urn), urn != "") %>%
    group_by(urn) %>%
    summarise(
      first_mention = min(date, na.rm = TRUE),
      last_mention = max(date, na.rm = TRUE),
      categoria = first(categoria),
      authority_level = first(authority_level),
      mentions = n(),
      .groups = "drop"
    ) %>%
    mutate(
      # Calculate policy "lifespan" in years
      lifespan_years = as.numeric(difftime(last_mention, first_mention, units = "days")) / 365.25,
      
      # Event indicator (1 if policy was "ended", 0 if still active)
      # Assume policies with no recent mentions (>2 years) have "ended"
      event = ifelse(last_mention < Sys.Date() - years(2), 1, 0),
      
      # Time to event or censoring
      time_to_event = ifelse(event == 1, lifespan_years, 
                           as.numeric(difftime(Sys.Date(), first_mention, units = "days")) / 365.25),
      
      # Only include policies with meaningful lifespan
      time_to_event = pmax(time_to_event, 0.01)
    ) %>%
    filter(time_to_event > 0, !is.na(categoria))
  
  # Fit survival models
  surv_object <- Surv(time = survival_data$time_to_event, event = survival_data$event)
  
  # Kaplan-Meier survival curves by category
  km_fit <- survfit(surv_object ~ categoria, data = survival_data)
  
  # Cox proportional hazards model
  cox_fit <- coxph(surv_object ~ categoria + authority_level, data = survival_data)
  
  # Survival statistics
  survival_summary <- survival_data %>%
    group_by(categoria) %>%
    summarise(
      n_policies = n(),
      median_lifespan = median(time_to_event, na.rm = TRUE),
      mean_lifespan = mean(time_to_event, na.rm = TRUE),
      event_rate = mean(event, na.rm = TRUE),
      .groups = "drop"
    )
  
  log_info("Survival analysis completed for {nrow(survival_data)} policies across {nrow(survival_summary)} categories")
  
  return(list(
    survival_data = survival_data,
    km_fit = km_fit,
    cox_fit = cox_fit,
    survival_summary = survival_summary
  ))
}

#' Forecast legislative activity using multiple models
#' @param time_series tsibble object with temporal data
#' @param forecast_horizon Number of periods to forecast
#' @return Forecasting results
forecast_legislative_activity <- function(time_series, forecast_horizon = 12) {
  
  log_info("Forecasting legislative activity for {forecast_horizon} periods ahead...")
  
  # Prepare data for forecasting (aggregate to avoid too many series)
  forecast_data <- time_series %>%
    group_by(year_month, categoria) %>%
    summarise(total_count = sum(count, na.rm = TRUE), .groups = "drop") %>%
    as_tsibble(key = categoria, index = year_month) %>%
    fill_gaps(total_count = 0)
  
  # Fit multiple forecasting models
  forecast_models <- forecast_data %>%
    model(
      # Exponential smoothing
      ETS = ETS(total_count),
      
      # ARIMA
      ARIMA = ARIMA(total_count),
      
      # Seasonal naive
      SNAIVE = SNAIVE(total_count),
      
      # Linear trend
      TSLM = TSLM(total_count ~ trend() + season()),
      
      # Prophet-style model (using TSLM with Fourier terms)
      PROPHET = TSLM(total_count ~ trend() + fourier(K = 3))
    )
  
  # Generate forecasts
  forecasts <- forecast_models %>%
    forecast(h = forecast_horizon)
  
  # Calculate accuracy metrics on training data
  accuracy_metrics <- forecast_models %>%
    accuracy()
  
  # Cross-validation for model selection
  cv_results <- forecast_data %>%
    stretch_tsibble(.init = 24, .step = 6) %>%  # 2-year initial window, 6-month steps
    model(
      ETS = ETS(total_count),
      ARIMA = ARIMA(total_count),
      SNAIVE = SNAIVE(total_count)
    ) %>%
    forecast(h = 6) %>%
    accuracy(forecast_data)
  
  log_info("Forecasting completed with {nrow(accuracy_metrics)} model-category combinations")
  
  return(list(
    forecasts = forecasts,
    models = forecast_models,
    accuracy_metrics = accuracy_metrics,
    cv_results = cv_results,
    forecast_data = forecast_data
  ))
}

#' Generate comprehensive temporal analysis visualizations
#' @param temporal_results List of all temporal analysis results
#' @param output_dir Output directory for plots
generate_temporal_visualizations <- function(temporal_results, output_dir) {
  
  log_info("Generating temporal analysis visualizations...")
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # 1. Legislative activity over time
  activity_plot <- temporal_results$data %>%
    group_by(year, categoria) %>%
    summarise(count = n(), .groups = "drop") %>%
    ggplot(aes(x = year, y = count, color = categoria)) +
    geom_line(size = 1.2) +
    geom_smooth(method = "loess", se = FALSE, alpha = 0.7) +
    scale_color_viridis_d() +
    labs(title = "Legislative Activity Over Time by Category",
         x = "Year", y = "Number of Documents", color = "Category") +
    theme_minimal() +
    theme(legend.position = "bottom")
  
  # 2. Topic evolution heatmap
  if (!is.null(temporal_results$topic_evolution)) {
    topic_evolution_plot <- temporal_results$topic_evolution$topic_time_series %>%
      mutate(topic_label = paste("Topic", topic)) %>%
      ggplot(aes(x = time_period, y = reorder(topic_label, topic), fill = proportion)) +
      geom_tile() +
      scale_fill_viridis_c() +
      labs(title = "Topic Evolution Over Time",
           x = "Time Period", y = "Topic", fill = "Proportion") +
      theme_minimal() +
      theme(axis.text.x = element_text(angle = 45, hjust = 1))
  }
  
  # 3. Policy waves detection
  if (!is.null(temporal_results$policy_waves)) {
    waves_data <- temporal_results$policy_waves$yearly_counts %>%
      group_by(year) %>%
      summarise(total_count = sum(count), .groups = "drop")
    
    waves_plot <- waves_data %>%
      ggplot(aes(x = year, y = total_count)) +
      geom_line(color = "steelblue", size = 1) +
      geom_vline(xintercept = temporal_results$policy_waves$major_waves, 
                 color = "red", linetype = "dashed", alpha = 0.7) +
      labs(title = "Legislative Activity with Detected Policy Waves",
           subtitle = "Red lines indicate major policy wave years",
           x = "Year", y = "Total Documents") +
      theme_minimal()
  }
  
  # 4. Survival curves
  if (!is.null(temporal_results$survival)) {
    survival_plot <- ggsurvplot(temporal_results$survival$km_fit,
                               data = temporal_results$survival$survival_data,
                               conf.int = TRUE,
                               pval = TRUE,
                               risk.table = TRUE,
                               ggtheme = theme_minimal(),
                               title = "Policy Survival Curves by Category")
  }
  
  # 5. Forecasts visualization
  if (!is.null(temporal_results$forecasts)) {
    forecast_plot <- temporal_results$forecasts$forecasts %>%
      autoplot(temporal_results$forecasts$forecast_data, level = c(80, 95)) +
      facet_wrap(~categoria, scales = "free_y") +
      labs(title = "Legislative Activity Forecasts by Category",
           x = "Time", y = "Number of Documents") +
      theme_minimal()
  }
  
  # Save plots
  ggsave(file.path(output_dir, "legislative_activity_timeline.png"), activity_plot,
         width = 12, height = 8, dpi = 300)
  
  if (exists("topic_evolution_plot")) {
    ggsave(file.path(output_dir, "topic_evolution_heatmap.png"), topic_evolution_plot,
           width = 12, height = 8, dpi = 300)
  }
  
  if (exists("waves_plot")) {
    ggsave(file.path(output_dir, "policy_waves_detection.png"), waves_plot,
           width = 14, height = 6, dpi = 300)
  }
  
  if (exists("survival_plot")) {
    ggsave2(file.path(output_dir, "policy_survival_curves.png"), survival_plot,
            width = 12, height = 10, dpi = 300)
  }
  
  if (exists("forecast_plot")) {
    ggsave(file.path(output_dir, "activity_forecasts.png"), forecast_plot,
           width = 14, height = 10, dpi = 300)
  }
  
  log_info("Temporal visualizations saved to {output_dir}")
}

#' Main temporal analysis pipeline
#' @param data_source Path to data file or data frame
#' @param output_dir Output directory for results
run_temporal_analysis <- function(data_source, output_dir) {
  
  log_info("=== STARTING TEMPORAL ANALYSIS PIPELINE ===")
  
  # 1. Prepare temporal data
  temporal_data <- prepare_temporal_data(data_source)
  
  # 2. Create time series
  monthly_ts <- create_time_series(temporal_data, "month")
  
  # 3. Topic evolution analysis
  topic_evolution <- analyze_topic_evolution(temporal_data)
  
  # 4. Policy waves detection
  policy_waves <- detect_policy_waves(temporal_data)
  
  # 5. Survival analysis
  survival_results <- analyze_policy_survival(temporal_data)
  
  # 6. Forecasting
  forecast_results <- forecast_legislative_activity(monthly_ts)
  
  # 7. Combine all results
  temporal_results <- list(
    data = temporal_data,
    time_series = monthly_ts,
    topic_evolution = topic_evolution,
    policy_waves = policy_waves,
    survival = survival_results,
    forecasts = forecast_results
  )
  
  # 8. Generate visualizations
  generate_temporal_visualizations(temporal_results, output_dir)
  
  # 9. Save results
  saveRDS(temporal_results, file.path(output_dir, "temporal_analysis_results.rds"))
  write_parquet(temporal_data, file.path(output_dir, "temporal_dataset.parquet"))
  
  log_info("=== TEMPORAL ANALYSIS COMPLETED ===")
  
  return(temporal_results)
}

# Execute if run as script
if (!interactive()) {
  # Set paths
  parquet_file <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/parquet_dataset/combined_legislative_dataset.parquet"
  output_dir <- file.path(dirname(dirname(parquet_file)), "temporal_analysis_results")
  
  # Check if Parquet file exists
  if (!file.exists(parquet_file)) {
    cat("Parquet file not found. Please run CSV to Parquet conversion first.\n")
    quit(status = 1)
  }
  
  # Run temporal analysis
  results <- run_temporal_analysis(parquet_file, output_dir)
  
  cat("Temporal analysis completed. Results saved to:", output_dir, "\n")
}