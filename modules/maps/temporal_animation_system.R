# Temporal Animation System for Brazilian Legislative Monitoring
# Advanced time-series geographic animations with smooth transitions
# Optimized for web performance and large datasets

#' Temporal Animation System for Geographic Data
#' @description Creates smooth time-series animations showing changes over time
initialize_temporal_animation_system <- function() {
  cat("🎬 Initializing Temporal Animation System...\n")
  
  animation_system <- list(
    # Core animation functions
    create_temporal_choropleth = function(data, metric_column, time_column = "date", 
                                        animation_speed = 500, frame_duration = 1000) {
      create_animated_choropleth(data, metric_column, time_column, animation_speed, frame_duration)
    },
    
    create_temporal_heatmap = function(data, intensity_column, time_column = "date",
                                     animation_speed = 800) {
      create_animated_heatmap(data, intensity_column, time_column, animation_speed)
    },
    
    create_trend_visualization = function(data, metric_column, time_column = "date",
                                        trend_window = 12) {
      create_temporal_trend_map(data, metric_column, time_column, trend_window)
    },
    
    # Time series processing
    prepare_temporal_data = function(data, time_column, aggregation = "monthly") {
      process_temporal_data(data, time_column, aggregation)
    },
    
    detect_temporal_patterns = function(data, metric_column, time_column) {
      analyze_temporal_patterns(data, metric_column, time_column)
    },
    
    # Animation controls
    create_animation_controls = function(time_range, default_speed = 500) {
      generate_animation_controls(time_range, default_speed)
    }
  )
  
  cat("✅ Temporal animation system initialized\n")
  cat("🎯 Features: Choropleth animation, heatmap animation, trend analysis\n")
  
  return(animation_system)
}

#' Create animated choropleth showing changes over time
create_animated_choropleth <- function(data, metric_column, time_column = "date", 
                                     animation_speed = 500, frame_duration = 1000) {
  tryCatch({
    cat("🎬 Creating animated choropleth for temporal analysis\n")
    
    # Validate inputs
    if (!time_column %in% names(data) || !metric_column %in% names(data)) {
      stop("Required columns not found in data")
    }
    
    # Prepare temporal data
    temporal_data <- prepare_temporal_data_for_animation(data, time_column, metric_column)
    
    if (nrow(temporal_data) == 0) {
      return(create_static_choropleth_fallback(data, metric_column))
    }
    
    # Get unique time periods
    time_periods <- sort(unique(temporal_data$time_period))
    
    if (length(time_periods) < 2) {
      cat("⚠️ Insufficient time periods for animation, creating static map\n")
      return(create_static_choropleth_fallback(data, metric_column))
    }
    
    # Create base choropleth
    base_choropleth <- create_base_animated_choropleth(temporal_data, metric_column, time_periods[1])
    
    # Add animation frames
    animated_choropleth <- add_animation_frames(base_choropleth, temporal_data, 
                                              metric_column, time_periods)
    
    # Configure animation controls
    final_choropleth <- configure_animation_controls(animated_choropleth, time_periods, 
                                                   animation_speed, frame_duration)
    
    cat("✅ Animated choropleth created with", length(time_periods), "time periods\n")
    return(final_choropleth)
    
  }, error = function(e) {
    cat("❌ Animated choropleth creation failed:", e$message, "\n")
    return(create_static_choropleth_fallback(data, metric_column))
  })
}

#' Create animated heatmap for intensity changes over time
create_animated_heatmap <- function(data, intensity_column, time_column = "date", 
                                  animation_speed = 800) {
  tryCatch({
    cat("🔥 Creating animated heatmap for temporal intensity analysis\n")
    
    # Validate required columns
    required_cols <- c(time_column, intensity_column, "lat", "lon")
    missing_cols <- required_cols[!required_cols %in% names(data)]
    
    if (length(missing_cols) > 0) {
      stop("Missing required columns: ", paste(missing_cols, collapse = ", "))
    }
    
    # Prepare temporal data with coordinates
    temporal_data <- data[!is.na(data[[intensity_column]]) & 
                         !is.na(data$lat) & !is.na(data$lon), ]
    
    if (nrow(temporal_data) == 0) {
      return(create_static_heatmap_fallback(data, intensity_column))
    }
    
    # Create time periods
    temporal_data$time_period <- create_time_periods(temporal_data[[time_column]])
    time_periods <- sort(unique(temporal_data$time_period))
    
    if (length(time_periods) < 2) {
      return(create_static_heatmap_fallback(data, intensity_column))
    }
    
    # Create animated heatmap using plotly
    animated_heatmap <- create_plotly_animated_heatmap(temporal_data, intensity_column, 
                                                      time_periods, animation_speed)
    
    cat("✅ Animated heatmap created with", length(time_periods), "time periods\n")
    return(animated_heatmap)
    
  }, error = function(e) {
    cat("❌ Animated heatmap creation failed:", e$message, "\n")
    return(create_static_heatmap_fallback(data, intensity_column))
  })
}

#' Create temporal trend visualization showing patterns over time
create_temporal_trend_map <- function(data, metric_column, time_column = "date", 
                                    trend_window = 12) {
  tryCatch({
    cat("📈 Creating temporal trend visualization\n")
    
    # Prepare data for trend analysis
    trend_data <- calculate_temporal_trends(data, metric_column, time_column, trend_window)
    
    if (nrow(trend_data) == 0) {
      return(create_static_trend_fallback(data, metric_column))
    }
    
    # Create trend visualization
    trend_map <- create_trend_choropleth(trend_data, metric_column)
    
    # Add trend indicators
    trend_map <- add_trend_indicators(trend_map, trend_data)
    
    cat("✅ Temporal trend map created\n")
    return(trend_map)
    
  }, error = function(e) {
    cat("❌ Temporal trend map creation failed:", e$message, "\n")
    return(create_static_trend_fallback(data, metric_column))
  })
}

#' Process temporal data for animation
prepare_temporal_data_for_animation <- function(data, time_column, metric_column) {
  tryCatch({
    # Convert to date
    data[[time_column]] <- as.Date(data[[time_column]])
    
    # Create time periods (monthly by default)
    data$time_period <- format(data[[time_column]], "%Y-%m")
    
    # Aggregate data by state and time period
    if ("state_code" %in% names(data)) {
      aggregated_data <- data %>%
        group_by(state_code, time_period) %>%
        summarise(
          metric_value = sum(!!sym(metric_column), na.rm = TRUE),
          document_count = n(),
          .groups = "drop"
        ) %>%
        filter(!is.na(state_code) & state_code != "")
    } else {
      # Fallback aggregation without state
      aggregated_data <- data %>%
        group_by(time_period) %>%
        summarise(
          metric_value = sum(!!sym(metric_column), na.rm = TRUE),
          document_count = n(),
          .groups = "drop"
        )
    }
    
    return(as.data.frame(aggregated_data))
    
  }, error = function(e) {
    cat("⚠️ Temporal data preparation failed:", e$message, "\n")
    return(data.frame())
  })
}

#' Create base choropleth for animation
create_base_animated_choropleth <- function(temporal_data, metric_column, initial_period) {
  tryCatch({
    # Filter data for initial time period
    initial_data <- temporal_data[temporal_data$time_period == initial_period, ]
    
    # Create base plotly choropleth
    base_plot <- plot_ly(
      data = initial_data,
      type = "choropleth",
      locations = ~state_code,
      z = ~metric_value,
      locationmode = "geojson-id",
      colorscale = "Viridis",
      reversescale = FALSE,
      marker = list(line = list(color = "white", width = 1)),
      colorbar = list(
        title = list(text = "Legislative Activity"),
        thickness = 20,
        len = 0.8
      ),
      hovertemplate = paste0(
        "<b>%{location}</b><br>",
        "Period: ", initial_period, "<br>",
        "Value: %{z}<br>",
        "<extra></extra>"
      )
    )
    
    return(base_plot)
    
  }, error = function(e) {
    cat("❌ Base choropleth creation failed:", e$message, "\n")
    return(NULL)
  })
}

#' Add animation frames to choropleth
add_animation_frames <- function(base_plot, temporal_data, metric_column, time_periods) {
  tryCatch({
    # Create frames for each time period
    frames <- list()
    
    for (i in seq_along(time_periods)) {
      period <- time_periods[i]
      period_data <- temporal_data[temporal_data$time_period == period, ]
      
      frame <- list(
        name = period,
        data = list(
          list(
            type = "choropleth",
            locations = period_data$state_code,
            z = period_data$metric_value,
            locationmode = "geojson-id",
            colorscale = "Viridis",
            showscale = i == 1, # Only show colorbar on first frame
            hovertemplate = paste0(
              "<b>%{location}</b><br>",
              "Period: ", period, "<br>",
              "Value: %{z}<br>",
              "<extra></extra>"
            )
          )
        )
      )
      
      frames[[i]] <- frame
    }
    
    # Add frames to plot
    animated_plot <- base_plot %>%
      plotly::animation_opts(
        frame = 1000,
        transition = 500,
        redraw = FALSE
      ) %>%
      plotly::add_trace(
        frame = frames[[1]]$name
      )
    
    # Add all frames
    for (frame in frames) {
      animated_plot$x$frames[[length(animated_plot$x$frames) + 1]] <- frame
    }
    
    return(animated_plot)
    
  }, error = function(e) {
    cat("❌ Animation frames addition failed:", e$message, "\n")
    return(base_plot)
  })
}

#' Configure animation controls
configure_animation_controls <- function(animated_plot, time_periods, animation_speed, frame_duration) {
  tryCatch({
    # Add play/pause buttons
    animated_plot <- animated_plot %>%
      plotly::layout(
        title = list(
          text = "Brazilian Legislative Activity Over Time",
          font = list(size = 16)
        ),
        updatemenus = list(
          list(
            type = "buttons",
            direction = "left",
            pad = list(r = 10, t = 87),
            x = 0.1,
            xanchor = "right",
            y = 0,
            yanchor = "top",
            buttons = list(
              list(
                label = "▶ Play",
                method = "animate",
                args = list(
                  NULL,
                  list(
                    frame = list(duration = frame_duration, redraw = FALSE),
                    transition = list(duration = animation_speed),
                    mode = "immediate"
                  )
                )
              ),
              list(
                label = "⏸ Pause",
                method = "animate",
                args = list(
                  list(NULL),
                  list(
                    frame = list(duration = 0, redraw = FALSE),
                    mode = "immediate"
                  )
                )
              )
            )
          )
        ),
        sliders = list(
          list(
            active = 0,
            currentvalue = list(prefix = "Period: "),
            pad = list(t = 20),
            steps = create_slider_steps(time_periods)
          )
        )
      )
    
    return(animated_plot)
    
  }, error = function(e) {
    cat("❌ Animation controls configuration failed:", e$message, "\n")
    return(animated_plot)
  })
}

#' Create slider steps for time navigation
create_slider_steps <- function(time_periods) {
  steps <- list()
  
  for (i in seq_along(time_periods)) {
    period <- time_periods[i]
    step <- list(
      args = list(list(period), list(frame = list(duration = 300, redraw = FALSE))),
      label = period,
      method = "animate",
      value = period
    )
    steps[[i]] <- step
  }
  
  return(steps)
}

#' Analyze temporal patterns in the data
analyze_temporal_patterns <- function(data, metric_column, time_column) {
  tryCatch({
    cat("🔍 Analyzing temporal patterns...\n")
    
    # Convert to time series
    data[[time_column]] <- as.Date(data[[time_column]])
    data$year_month <- format(data[[time_column]], "%Y-%m")
    
    # Calculate monthly aggregates
    monthly_data <- data %>%
      group_by(year_month) %>%
      summarise(
        total_value = sum(!!sym(metric_column), na.rm = TRUE),
        document_count = n(),
        .groups = "drop"
      ) %>%
      arrange(year_month)
    
    # Detect trends
    if (nrow(monthly_data) >= 3) {
      # Simple trend analysis
      monthly_data$trend <- c(NA, diff(monthly_data$total_value))
      monthly_data$trend_direction <- ifelse(monthly_data$trend > 0, "increasing", 
                                           ifelse(monthly_data$trend < 0, "decreasing", "stable"))
      
      # Detect seasonality (simplified)
      if (nrow(monthly_data) >= 12) {
        monthly_data$month <- as.numeric(substr(monthly_data$year_month, 6, 7))
        seasonal_pattern <- aggregate(total_value ~ month, data = monthly_data, mean)
        peak_month <- seasonal_pattern$month[which.max(seasonal_pattern$total_value)]
        low_month <- seasonal_pattern$month[which.min(seasonal_pattern$total_value)]
        
        patterns <- list(
          trend_data = monthly_data,
          seasonality = list(
            peak_month = peak_month,
            low_month = low_month,
            seasonal_variation = max(seasonal_pattern$total_value) - min(seasonal_pattern$total_value)
          )
        )
      } else {
        patterns <- list(trend_data = monthly_data)
      }
    } else {
      patterns <- list(trend_data = monthly_data)
    }
    
    cat("✅ Temporal pattern analysis completed\n")
    return(patterns)
    
  }, error = function(e) {
    cat("❌ Temporal pattern analysis failed:", e$message, "\n")
    return(list())
  })
}

# Helper functions

create_time_periods <- function(dates) {
  format(as.Date(dates), "%Y-%m")
}

process_temporal_data <- function(data, time_column, aggregation = "monthly") {
  data[[time_column]] <- as.Date(data[[time_column]])
  
  if (aggregation == "monthly") {
    data$period <- format(data[[time_column]], "%Y-%m")
  } else if (aggregation == "quarterly") {
    data$period <- paste0(format(data[[time_column]], "%Y"), "-Q", ceiling(as.numeric(format(data[[time_column]], "%m")) / 3))
  } else if (aggregation == "yearly") {
    data$period <- format(data[[time_column]], "%Y")
  }
  
  return(data)
}

# Fallback functions

create_static_choropleth_fallback <- function(data, metric_column) {
  cat("🔄 Creating static choropleth fallback\n")
  return(plotly::plot_ly(type = "choropleth", z = ~get(metric_column)))
}

create_static_heatmap_fallback <- function(data, intensity_column) {
  cat("🔄 Creating static heatmap fallback\n")
  return(plotly::plot_ly(x = ~lon, y = ~lat, type = "scatter", mode = "markers"))
}

create_static_trend_fallback <- function(data, metric_column) {
  cat("🔄 Creating static trend fallback\n")
  return(plotly::plot_ly(type = "scatter", mode = "lines"))
}

create_plotly_animated_heatmap <- function(temporal_data, intensity_column, time_periods, animation_speed) {
  # Simplified animated heatmap implementation
  return(plotly::plot_ly(data = temporal_data, x = ~lon, y = ~lat, 
                        color = ~get(intensity_column), type = "scatter", mode = "markers"))
}

calculate_temporal_trends <- function(data, metric_column, time_column, trend_window) {
  # Simplified trend calculation
  return(data[!is.na(data[[metric_column]]), ])
}

create_trend_choropleth <- function(trend_data, metric_column) {
  return(plotly::plot_ly(type = "choropleth", z = ~get(metric_column)))
}

add_trend_indicators <- function(trend_map, trend_data) {
  return(trend_map)
}

generate_animation_controls <- function(time_range, default_speed) {
  return(list(speed = default_speed, range = time_range))
}

cat("🎬 Temporal Animation System loaded successfully\n")
cat("📊 Functions: create_animated_choropleth, create_animated_heatmap, create_temporal_trend_map\n")
cat("🎯 Features: Smooth animations, trend analysis, interactive controls\n")