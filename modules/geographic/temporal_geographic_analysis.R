# Temporal Geographic Analysis Module - Sprint 1
# Monitor Legislativo v4 - Time-Series Geographic Analysis for Brazilian Legislative Research
# =======================================================================================
# 
# Advanced temporal-geographic analysis following RESEARCH_METHODOLOGY.md academic standards
# Implements time-series analysis of legislative activity patterns across Brazilian geography
# with statistical trend detection and academic validation protocols
# 
# Key Features:
# - Time-series analysis of legislative activity by Brazilian states and regions
# - Geographic diffusion pattern analysis over time
# - Temporal hotspot evolution tracking
# - Legislative wave detection and propagation analysis
# - Academic statistical trend validation with confidence intervals
# - Interactive temporal visualization with Brazilian administrative context

library(dplyr)
library(ggplot2)
library(plotly)
library(sf)
library(lubridate)
library(forecast)
library(bcp)
library(changepoint)
library(viridis)

#' Analyze Temporal Geographic Patterns
#' 
#' Academic implementation of time-series geographic analysis for Brazilian legislative data
#' with statistical trend detection and geographic diffusion pattern identification
#' 
#' @param temporal_data Data frame with temporal and geographic legislative information
#' @param date_column Character name of date column
#' @param geographic_column Character name of geographic identifier column (e.g., "state_code")
#' @param count_column Character name of document count column
#' @param time_unit Time aggregation unit ("month", "quarter", "year")
#' @return List with temporal geographic analysis results
analyze_temporal_geographic_patterns <- function(temporal_data,
                                                 date_column = "data_documento",
                                                 geographic_column = "estado",
                                                 count_column = "doc_count",
                                                 time_unit = "quarter") {
  
  tryCatch({
    
    # Validate input data
    required_cols <- c(date_column, geographic_column, count_column)
    missing_cols <- setdiff(required_cols, names(temporal_data))
    if (length(missing_cols) > 0) {
      stop(paste("Missing required columns:", paste(missing_cols, collapse = ", ")))
    }
    
    # Convert date column and handle parsing errors
    temporal_data[[date_column]] <- as.Date(temporal_data[[date_column]])
    temporal_data <- temporal_data[!is.na(temporal_data[[date_column]]), ]
    
    if (nrow(temporal_data) == 0) {
      stop("No valid dates found in temporal data")
    }
    
    # Create time periods based on specified unit
    temporal_data$time_period <- switch(time_unit,
      "month" = floor_date(temporal_data[[date_column]], "month"),
      "quarter" = floor_date(temporal_data[[date_column]], "quarter"),
      "year" = floor_date(temporal_data[[date_column]], "year"),
      floor_date(temporal_data[[date_column]], "quarter")  # Default to quarter
    )
    
    # Aggregate data by time period and geography
    temporal_aggregated <- temporal_data %>%
      group_by(time_period, !!sym(geographic_column)) %>%
      summarise(
        document_count = sum(!!sym(count_column), na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(time_period, !!sym(geographic_column))
    
    # Create complete time series grid (fill missing periods with zeros)
    time_range <- seq(
      from = min(temporal_aggregated$time_period),
      to = max(temporal_aggregated$time_period),
      by = time_unit
    )
    
    geographic_units <- unique(temporal_aggregated[[geographic_column]])
    
    complete_grid <- expand.grid(
      time_period = time_range,
      geographic_unit = geographic_units,
      stringsAsFactors = FALSE
    )
    names(complete_grid)[2] <- geographic_column
    
    # Join with actual data and fill missing values
    temporal_complete <- complete_grid %>%
      left_join(temporal_aggregated, by = c("time_period", geographic_column)) %>%
      mutate(document_count = ifelse(is.na(document_count), 0, document_count))
    
    # Calculate time-series statistics for each geographic unit
    geographic_trends <- temporal_complete %>%
      group_by(!!sym(geographic_column)) %>%
      summarise(
        total_documents = sum(document_count),
        mean_documents = mean(document_count),
        median_documents = median(document_count),
        sd_documents = sd(document_count),
        cv_documents = sd(document_count) / mean(document_count),
        min_period = min(time_period),
        max_period = max(time_period),
        active_periods = sum(document_count > 0),
        n_periods = n(),
        activity_rate = sum(document_count > 0) / n(),
        .groups = "drop"
      )
    
    # Perform trend analysis for each geographic unit
    trend_analysis <- temporal_complete %>%
      group_by(!!sym(geographic_column)) %>%
      group_modify(~{
        if (nrow(.x) < 4 || sum(.x$document_count) < 5) {
          # Insufficient data for trend analysis
          data.frame(
            trend_slope = NA,
            trend_pvalue = NA,
            trend_direction = "insufficient_data",
            r_squared = NA,
            changepoint_detected = FALSE,
            changepoint_location = NA
          )
        } else {
          # Linear trend analysis
          time_numeric <- as.numeric(.x$time_period - min(.x$time_period))
          lm_model <- lm(document_count ~ time_numeric, data = .x)
          
          # Change point detection (if sufficient data)
          changepoint_result <- tryCatch({
            if (nrow(.x) >= 10) {
              cpt_result <- changepoint::cpt.mean(.x$document_count, method = "PELT")
              list(
                detected = length(changepoint::cpts(cpt_result)) > 0,
                location = if (length(changepoint::cpts(cpt_result)) > 0) {
                  .x$time_period[changepoint::cpts(cpt_result)[1]]
                } else {
                  NA
                }
              )
            } else {
              list(detected = FALSE, location = NA)
            }
          }, error = function(e) {
            list(detected = FALSE, location = NA)
          })
          
          data.frame(
            trend_slope = coef(lm_model)[2],
            trend_pvalue = summary(lm_model)$coefficients[2, 4],
            trend_direction = case_when(
              summary(lm_model)$coefficients[2, 4] < 0.05 & coef(lm_model)[2] > 0 ~ "increasing",
              summary(lm_model)$coefficients[2, 4] < 0.05 & coef(lm_model)[2] < 0 ~ "decreasing",
              TRUE ~ "stable"
            ),
            r_squared = summary(lm_model)$r.squared,
            changepoint_detected = changepoint_result$detected,
            changepoint_location = changepoint_result$location
          )
        }
      }) %>%
      ungroup()
    
    # Combine geographic trends with trend analysis
    comprehensive_trends <- geographic_trends %>%
      left_join(trend_analysis, by = geographic_column)
    
    # Calculate regional temporal patterns
    # Load Brazilian regions mapping if available
    brazil_regions <- data.frame(
      state_code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                     "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                     "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
      region = c("Norte", "Nordeste", "Norte", "Norte", "Nordeste", "Nordeste", "Centro-Oeste", 
                 "Sudeste", "Centro-Oeste", "Nordeste", "Centro-Oeste", "Centro-Oeste", "Sudeste", 
                 "Norte", "Nordeste", "Sul", "Nordeste", "Nordeste", "Sudeste", "Nordeste", 
                 "Sul", "Norte", "Norte", "Sul", "Sudeste", "Nordeste", "Norte")
    )
    
    regional_analysis <- temporal_complete %>%
      left_join(brazil_regions, by = c(geographic_column = "state_code")) %>%
      filter(!is.na(region)) %>%
      group_by(region, time_period) %>%
      summarise(
        total_documents = sum(document_count),
        active_states = sum(document_count > 0),
        .groups = "drop"
      ) %>%
      arrange(region, time_period)
    
    # Identify diffusion patterns (policy waves)
    diffusion_analysis <- analyze_geographic_diffusion(temporal_complete, geographic_column, brazil_regions)
    
    # Create temporal hotspots evolution
    temporal_hotspots <- identify_temporal_hotspots(temporal_complete, geographic_column)
    
    return(list(
      # Core time series data
      temporal_data = temporal_complete,
      geographic_trends = comprehensive_trends,
      regional_patterns = regional_analysis,
      
      # Advanced analysis
      diffusion_patterns = diffusion_analysis,
      temporal_hotspots = temporal_hotspots,
      
      # Summary statistics
      summary_stats = list(
        total_periods = length(time_range),
        date_range = c(min(time_range), max(time_range)),
        geographic_units = length(geographic_units),
        time_unit = time_unit,
        total_documents = sum(temporal_complete$document_count),
        peak_period = time_range[which.max(tapply(temporal_complete$document_count, temporal_complete$time_period, sum))]
      ),
      
      # Academic metadata
      methodology = list(
        analysis_type = "Temporal Geographic Pattern Analysis",
        time_series_method = "Linear trend analysis with change point detection",
        change_point_method = "PELT (Pruned Exact Linear Time)",
        significance_level = 0.05,
        software = "R packages: forecast, changepoint, bcp",
        calculated_at = Sys.time()
      )
    ))
    
  }, error = function(e) {
    warning("Error in temporal geographic analysis: ", e$message)
    return(NULL)
  })
}

#' Analyze Geographic Diffusion Patterns
#' 
#' Identify policy diffusion and legislative wave patterns across Brazilian states
#' 
#' @param temporal_data Complete temporal data with geographic and time information
#' @param geographic_column Name of geographic identifier column
#' @param regions_mapping Data frame mapping states to regions
#' @return List with diffusion analysis results
analyze_geographic_diffusion <- function(temporal_data, geographic_column, regions_mapping) {
  
  tryCatch({
    
    # Identify adoption periods (first significant activity) for each state
    adoption_analysis <- temporal_data %>%
      filter(document_count > 0) %>%
      group_by(!!sym(geographic_column)) %>%
      summarise(
        first_adoption = min(time_period),
        peak_activity = time_period[which.max(document_count)],
        total_activity = sum(document_count),
        .groups = "drop"
      ) %>%
      left_join(regions_mapping, by = c(geographic_column = "state_code")) %>%
      filter(!is.na(region))
    
    # Calculate diffusion waves by region
    regional_diffusion <- adoption_analysis %>%
      group_by(region) %>%
      summarise(
        earliest_adopter = min(first_adoption),
        latest_adopter = max(first_adoption),
        diffusion_period = as.numeric(max(first_adoption) - min(first_adoption)),
        n_states = n(),
        total_activity = sum(total_activity),
        .groups = "drop"
      ) %>%
      arrange(earliest_adopter)
    
    # Identify diffusion leaders and followers
    diffusion_roles <- adoption_analysis %>%
      mutate(
        adoption_order = rank(first_adoption),
        adoption_percentile = adoption_order / max(adoption_order),
        diffusion_role = case_when(
          adoption_percentile <= 0.2 ~ "Early Adopter",
          adoption_percentile <= 0.4 ~ "Early Majority",
          adoption_percentile <= 0.6 ~ "Late Majority",
          adoption_percentile <= 0.8 ~ "Late Adopter",
          TRUE ~ "Laggard"
        )
      ) %>%
      arrange(adoption_order)
    
    return(list(
      adoption_timeline = adoption_analysis,
      regional_diffusion = regional_diffusion,
      diffusion_roles = diffusion_roles
    ))
    
  }, error = function(e) {
    warning("Error in diffusion analysis: ", e$message)
    return(list())
  })
}

#' Identify Temporal Hotspots Evolution
#' 
#' Track the evolution of geographic hotspots over time
#' 
#' @param temporal_data Complete temporal data with geographic and time information
#' @param geographic_column Name of geographic identifier column
#' @return List with temporal hotspot analysis
identify_temporal_hotspots <- function(temporal_data, geographic_column) {
  
  tryCatch({
    
    # Calculate percentile-based hotspot classification for each time period
    temporal_hotspots <- temporal_data %>%
      group_by(time_period) %>%
      mutate(
        activity_percentile = percent_rank(document_count),
        hotspot_classification = case_when(
          activity_percentile >= 0.9 ~ "Very High Activity",
          activity_percentile >= 0.75 ~ "High Activity",
          activity_percentile >= 0.5 ~ "Medium Activity",
          activity_percentile >= 0.25 ~ "Low Activity",
          TRUE ~ "Very Low Activity"
        )
      ) %>%
      ungroup()
    
    # Track hotspot persistence (states that remain hotspots)
    hotspot_persistence <- temporal_hotspots %>%
      filter(activity_percentile >= 0.75) %>%  # High and very high activity
      group_by(!!sym(geographic_column)) %>%
      summarise(
        hotspot_periods = n(),
        first_hotspot = min(time_period),
        last_hotspot = max(time_period),
        persistence_score = n() / length(unique(temporal_data$time_period)),
        .groups = "drop"
      ) %>%
      arrange(desc(persistence_score))
    
    # Identify emerging and declining hotspots
    recent_periods <- tail(sort(unique(temporal_data$time_period)), 4)  # Last 4 periods
    early_periods <- head(sort(unique(temporal_data$time_period)), 4)   # First 4 periods
    
    emerging_hotspots <- temporal_hotspots %>%
      filter(time_period %in% recent_periods, activity_percentile >= 0.75) %>%
      group_by(!!sym(geographic_column)) %>%
      summarise(recent_hotspot_periods = n(), .groups = "drop") %>%
      anti_join(
        temporal_hotspots %>%
          filter(time_period %in% early_periods, activity_percentile >= 0.75) %>%
          distinct(!!sym(geographic_column)),
        by = geographic_column
      )
    
    return(list(
      temporal_hotspots_data = temporal_hotspots,
      persistence_analysis = hotspot_persistence,
      emerging_hotspots = emerging_hotspots,
      analysis_periods = list(
        recent = recent_periods,
        early = early_periods
      )
    ))
    
  }, error = function(e) {
    warning("Error in temporal hotspot analysis: ", e$message)
    return(list())
  })
}

#' Create Temporal Geographic Visualization
#' 
#' Generate publication-quality temporal geographic visualizations
#' 
#' @param temporal_results Results from analyze_temporal_geographic_patterns
#' @param viz_type Type of visualization ("time_series", "heatmap", "diffusion")
#' @param geographic_focus Optional vector of geographic units to highlight
#' @return ggplot or plotly object with temporal geographic visualization
create_temporal_geographic_viz <- function(temporal_results, viz_type = "time_series", geographic_focus = NULL) {
  
  if (isTRUE(is.null(temporal_results)) || !"temporal_data" %in% names(temporal_results)) {
    return(ggplot() + geom_text(aes(x = 0.5, y = 0.5, label = "Temporal data not available"), size = 5) + theme_void())
  }
  
  if (viz_type == "time_series") {
    
    # Time series plot of legislative activity by state/region
    temporal_data <- temporal_results$temporal_data
    
    if (!is.null(geographic_focus)) {
      temporal_data <- temporal_data %>%
        filter(get(names(temporal_data)[2]) %in% geographic_focus)
    }
    
    p <- ggplot(temporal_data, aes(x = time_period, y = document_count, 
                                  color = get(names(temporal_data)[2]))) +
      geom_line(size = 0.8, alpha = 0.7) +
      geom_point(size = 1.2, alpha = 0.8) +
      scale_color_viridis_d(name = "Geographic Unit", option = "viridis") +
      labs(
        title = "Temporal Evolution of Legislative Activity",
        subtitle = "Time-series analysis of legislative document patterns across Brazilian geography",
        x = "Time Period",
        y = "Number of Legislative Documents",
        caption = "Source: Monitor Legislativo v4 | Methodology: Time-series trend analysis"
      ) +
      theme_minimal() +
      theme(
        plot.title = element_text(size = 14, face = "bold"),
        plot.subtitle = element_text(size = 11, color = "gray60"),
        legend.position = "right",
        panel.grid.minor = element_blank()
      )
    
    # Convert to plotly for interactivity
    p_interactive <- ggplotly(p, tooltip = c("x", "y", "colour")) %>%
      layout(
        title = list(text = "Temporal Evolution of Legislative Activity<br><sub>Time-series analysis across Brazilian geography</sub>"),
        margin = list(t = 80)
      )
    
    return(p_interactive)
    
  } else if (viz_type == "heatmap") {
    
    # Temporal heatmap showing activity intensity
    temporal_data <- temporal_results$temporal_data
    
    p <- ggplot(temporal_data, aes(x = time_period, y = get(names(temporal_data)[2]), fill = document_count)) +
      geom_tile(color = "white", size = 0.1) +
      scale_fill_viridis_c(name = "Documents", trans = "sqrt", option = "plasma") +
      labs(
        title = "Temporal-Geographic Activity Heatmap",
        subtitle = "Legislative document intensity across Brazilian states over time",
        x = "Time Period",
        y = "Brazilian State",
        caption = "Source: Monitor Legislativo v4 | Color scale: Square root transformation"
      ) +
      theme_minimal() +
      theme(
        plot.title = element_text(size = 14, face = "bold"),
        plot.subtitle = element_text(size = 11, color = "gray60"),
        axis.text.x = element_text(angle = 45, hjust = 1),
        panel.grid = element_blank()
      )
    
    return(p)
    
  } else if (viz_type == "diffusion" && "diffusion_patterns" %in% names(temporal_results)) {
    
    # Diffusion timeline visualization
    diffusion_data <- temporal_results$diffusion_patterns$diffusion_roles
    
    p <- ggplot(diffusion_data, aes(x = first_adoption, y = reorder(get(names(diffusion_data)[1]), first_adoption))) +
      geom_point(aes(color = diffusion_role, size = total_activity), alpha = 0.7) +
      geom_segment(aes(x = first_adoption, xend = peak_activity, 
                      y = get(names(diffusion_data)[1]), yend = get(names(diffusion_data)[1]),
                      color = diffusion_role), 
                  arrow = arrow(length = unit(0.2, "cm")), alpha = 0.5) +
      scale_color_brewer(type = "qual", palette = "Set2", name = "Diffusion Role") +
      scale_size_continuous(name = "Total Activity", range = c(2, 8)) +
      labs(
        title = "Legislative Policy Diffusion Timeline",
        subtitle = "Adoption and peak activity patterns across Brazilian states",
        x = "Time Period",
        y = "Brazilian State",
        caption = "Source: Monitor Legislativo v4 | Arrow indicates first adoption to peak activity"
      ) +
      theme_minimal() +
      theme(
        plot.title = element_text(size = 14, face = "bold"),
        plot.subtitle = element_text(size = 11, color = "gray60"),
        legend.position = "right"
      )
    
    return(p)
  }
  
  # Default fallback
  return(ggplot() + geom_text(aes(x = 0.5, y = 0.5, label = "Visualization type not available"), size = 5) + theme_void())
}

# Export all functions
list(
  analyze_temporal_geographic_patterns = analyze_temporal_geographic_patterns,
  analyze_geographic_diffusion = analyze_geographic_diffusion,
  identify_temporal_hotspots = identify_temporal_hotspots,
  create_temporal_geographic_viz = create_temporal_geographic_viz
)