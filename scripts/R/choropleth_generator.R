# Advanced Choropleth Map Generation for Brazilian Legislative Data
# Professional choropleth implementation with full state boundary fills

# Ensure pipe operator is available without requiring global library calls
if (!exists("%>%")) {
  if (requireNamespace("magrittr", quietly = TRUE)) {
    `%>%` <- magrittr::`%>%`
  } else if (requireNamespace("dplyr", quietly = TRUE)) {
    `%>%` <- dplyr::`%>%`
  }
}

#' Create professional choropleth map with filled state boundaries
#' @param state_data Data frame with state_code and metric columns
#' @param boundaries sf object with Brazilian state boundaries  
#' @param geojson GeoJSON object for plotly compatibility
#' @param metric_column Name of the data column to visualize
#' @param map_metric Type of metric (count, per_capita, activity, density)
#' @param colorscale Plotly colorscale name
#' @param show_labels Whether to show state code labels
#' @return plotly object with choropleth map
create_professional_choropleth <- function(state_data, boundaries, geojson, 
                                         metric_column, map_metric = "count",
                                         colorscale = "Viridis", show_labels = FALSE,
                                         opacity = 0.85, high_contrast = FALSE) {
  
  tryCatch({
    cat("🗺️ Creating professional choropleth map\n")
    
    # Enhanced input validation with type checking
    if (isTRUE(is.null(boundaries)) || isTRUE(is.null(geojson)) || isTRUE(is.null(state_data))) {
      stop("Missing required data for choropleth creation")
    }
    
    # Check geojson is not a closure or function
    if (is.function(geojson) || inherits(geojson, "closure")) {
      cat("⚠️ GeoJSON is a function/closure, not usable data\n")
      stop("GeoJSON data is not in the expected format (appears to be a function)")
    }
    
    if (!metric_column %in% names(state_data)) {
      stop("Metric column '", metric_column, "' not found in data")
    }
    
    # Additional safety check for state_data structure
    required_cols <- c("state_code", "state_name", metric_column)
    missing_cols <- required_cols[!required_cols %in% names(state_data)]
    if (length(missing_cols) > 0) {
      stop("Missing required columns in state_data: ", paste(missing_cols, collapse = ", "))
    }
    
    # Prepare data for choropleth
    # Create a safe column selection approach
    metric_col_data <- state_data[[metric_column]]
    choropleth_data <- data.frame(
      state_code = state_data$state_code,
      state_name = state_data$state_name,
      z_value = metric_col_data
    ) %>%
      dplyr::filter(!is.na(z_value) & z_value > 0)
    
    cat("📊 Prepared choropleth data for", nrow(choropleth_data), "states\n")
    
    # Create hover text
    choropleth_data$hover_text <- paste0(
      "<b>", choropleth_data$state_name, "</b><br>",
      "State: ", choropleth_data$state_code, "<br>",
      switch(map_metric,
        "count" = paste0("Documents: ", format(choropleth_data$z_value, big.mark = ",")),
        "per_capita" = paste0("Per 100k: ", round(choropleth_data$z_value, 2)),
        "activity" = paste0("Activity Index: ", round(choropleth_data$z_value, 2)),
        "density" = paste0("Regulatory Density: ", round(choropleth_data$z_value, 2))
      ),
      "<extra></extra>"
    )
    
    # Enhanced GeoJSON validation to prevent closure errors
    has_proper_geojson <- FALSE
    if (!is.null(geojson)) {
      # Multiple safety checks to avoid closure subsetting errors
      has_proper_geojson <- tryCatch({
        # First check if it's a proper R object (not a closure/function)
        if (is.function(geojson) || inherits(geojson, "closure")) {
          cat("⚠️ GeoJSON is a function/closure - cannot use for mapping\n")
          return(FALSE)
        }
        
        # Check if it's a list with proper structure
        if (!is.list(geojson)) {
          cat("⚠️ GeoJSON is not a list structure\n")
          return(FALSE)
        }
        
        # Safe property access using [[]] instead of $
        geojson_type <- tryCatch({
          geojson[["type"]]
        }, error = function(e) {
          cat("⚠️ Cannot access geojson type:", e$message, "\n")
          return(NULL)
        })
        
        # Check for FeatureCollection type
        if (isTRUE(is.null(geojson_type)) || geojson_type != "FeatureCollection") {
          cat("⚠️ GeoJSON is not a FeatureCollection\n")
          return(FALSE)
        }
        
        # Check for features property
        geojson_features <- tryCatch({
          geojson[["features"]]
        }, error = function(e) {
          cat("⚠️ Cannot access geojson features:", e$message, "\n")
          return(NULL)
        })
        
        # Validate features
        if (is.null(geojson_features)) {
          cat("⚠️ GeoJSON has no features\n")
          return(FALSE)
        }
        
        # Check if features is not just a simplified placeholder
        if (identical(geojson_features, "simplified") || 
            (is.character(geojson_features) && length(geojson_features) == 1)) {
          cat("⚠️ GeoJSON features are simplified/placeholder\n")
          return(FALSE)
        }
        
        # If we get here, the GeoJSON should be valid
        cat("✅ GeoJSON structure validated successfully\n")
        return(TRUE)
        
      }, error = function(e) {
        cat("⚠️ Error during GeoJSON validation:", e$message, "\n")
        return(FALSE)
      })
    } else {
      cat("⚠️ GeoJSON is NULL\n")
    }
    
    # Method 1: Try choroplethmapbox only if we have proper GeoJSON
    if (has_proper_geojson) {
      tryCatch({
        cat("🔧 Attempting choroplethmapbox with proper GeoJSON...\n")
        
        fig <- plot_ly(
          type = "choroplethmapbox",
          geojson = geojson,
          locations = choropleth_data$state_code,
          z = choropleth_data$z_value,
          featureidkey = "properties.abbrev_state",
          colorscale = colorscale,
          reversescale = FALSE,
        marker = list(
          line = list(
            color = if (high_contrast) "black" else "white", 
            width = if (high_contrast) 2 else 1.5
          ),
          opacity = opacity
        ),
        colorbar = list(
          title = list(
            text = switch(map_metric,
              "count" = "Documents",
              "per_capita" = "Per 100k Pop",
              "activity" = "Activity Index",
              "density" = "Density Score"
            ),
            font = list(size = 12)
          ),
          thickness = 20,
          len = 0.8,
          x = 1.02,
          bordercolor = "white",
          borderwidth = 1
        ),
        hovertemplate = choropleth_data$hover_text,
        showscale = TRUE
      ) %>%
      plotly::layout(
        mapbox = list(
          style = "carto-positron",
          zoom = 3.2,
          center = list(lat = -14.2, lon = -53.2),
          bearing = 0,
          pitch = 0
        ),
        margin = list(l = 0, r = 50, t = 40, b = 0),
        font = list(family = "Arial, sans-serif", size = 11)
      )
      
      # Add state labels if requested
      if (show_labels && !is.null(boundaries)) {
        state_centroids <- sf::st_centroid(boundaries$geometry)
        centroid_coords <- sf::st_coordinates(state_centroids)
        
        label_data <- data.frame(
          lon = centroid_coords[, 1],
          lat = centroid_coords[, 2], 
          label = boundaries$abbrev_state
        )
        
        fig <- fig %>%
          plotly::add_trace(
            data = label_data,
            lon = ~lon,
            lat = ~lat,
            type = "scattermapbox",
            mode = "text",
            text = ~label,
            textfont = list(size = 10, color = "white", family = "Arial Bold"),
            showlegend = FALSE,
            hoverinfo = "none"
          )
      }
      
      cat("✅ Choroplethmapbox created successfully\n")
      return(fig)
      
    }, error = function(e1) {
      cat("⚠️ Choroplethmapbox failed:", e1$message, "\n")
      
      # Method 2: Try standard choropleth
      tryCatch({
        cat("🔧 Attempting standard choropleth...\n")
        
        fig <- plot_ly(
          type = "choropleth",
          geojson = geojson,
          locations = choropleth_data$state_code,
          z = choropleth_data$z_value,
          featureidkey = "properties.abbrev_state",
          colorscale = colorscale,
          reversescale = FALSE,
          marker = list(line = list(color = "white", width = 1)),
          colorbar = list(
            title = switch(map_metric,
              "count" = "Documents",
              "per_capita" = "Per 100k Pop", 
              "activity" = "Activity Index",
              "density" = "Density Score"
            ),
            thickness = 20,
            len = 0.8
          ),
          hovertemplate = choropleth_data$hover_text
        ) %>%
        plotly::layout(
          geo = list(
            scope = "south america",
            projection = list(type = "natural earth"),
            showlakes = FALSE,
            showcountries = TRUE,
            countrycolor = "lightgray",
            countrywidth = 0.5,
            center = list(lat = -14, lon = -54),
            lonaxis = list(range = c(-75, -30)),
            lataxis = list(range = c(-35, 5))
          ),
          margin = list(l = 0, r = 0, t = 40, b = 0)
        )
        
        cat("✅ Standard choropleth created successfully\n")
        return(fig)
        
      }, error = function(e2) {
        cat("❌ Both choropleth methods failed\n")
        stop("Choropleth creation completely failed")
      })
    })
  } else {
    # No proper GeoJSON available, signal for fallback
    cat("🔄 No proper GeoJSON available, using fallback\n")
    return(NULL)
  }
    
  }, error = function(e) {
    cat("❌ Professional choropleth creation failed:", e$message, "\n")
    return(NULL)
  })
}

#' Create enhanced fallback map with large area-filling circles
#' @param state_data Data frame with state coordinates and metrics
#' @param metric_column Name of the data column to visualize
#' @param map_metric Type of metric for proper labeling
#' @param colorscale Plotly colorscale name
#' @param show_labels Whether to show state labels
#' @return plotly object with enhanced circle-based map
create_enhanced_fallback_map <- function(state_data, metric_column, map_metric = "count",
                                       colorscale = "Viridis", show_labels = FALSE,
                                       opacity = 0.85, high_contrast = FALSE) {
  
  tryCatch({
    cat("🔄 Creating enhanced fallback map with area-filling circles\n")
    
    # Prepare data (avoid tidy-eval to prevent closure errors in some envs)
    metric_values <- state_data[[metric_column]]
    map_data <- state_data[!is.na(metric_values) & metric_values > 0, , drop = FALSE]

    # Standardize coordinate column names: accept lng/longitude -> lon
    if (!("lon" %in% names(map_data))) {
      if ("lng" %in% names(map_data)) {
        map_data$lon <- map_data$lng
      } else if ("longitude" %in% names(map_data)) {
        map_data$lon <- map_data$longitude
      }
    }
    # Ensure latitude column exists: accept latitude -> lat
    if (!("lat" %in% names(map_data)) && ("latitude" %in% names(map_data))) {
      map_data$lat <- map_data$latitude
    }
    
    # Validate coordinates are present
    if (!("lon" %in% names(map_data)) || !("lat" %in% names(map_data))) {
      stop("Missing required coordinate columns (lon/lat or lng/lat)")
    }
    
    # Calculate appropriate circle sizes (logarithmic scaling for visual balance)
    map_data$circle_size <- pmin(pmax(log10(pmax(map_data[[metric_column]], 1) + 1) * 50, 35), 120)
    
    # Create enhanced hover text
    map_data$hover_text <- paste0(
      "<b>", map_data$state_name, "</b><br>",
      "State: ", map_data$state_code, "<br>",
      switch(map_metric,
        "count" = paste0("Documents: ", format(map_data[[metric_column]], big.mark = ",")),
        "per_capita" = paste0("Per 100k: ", round(map_data[[metric_column]], 2)),
        "activity" = paste0("Activity Index: ", round(map_data[[metric_column]], 2)),  
        "density" = paste0("Regulatory Density: ", round(map_data[[metric_column]], 2))
      )
    )
    
    # Create base map
    fig <- plot_ly(
      data = map_data,
      lon = ~lon,
      lat = ~lat,
      type = "scattermapbox",
      mode = "markers",
      marker = list(
        size = ~circle_size,
        color = map_data[[metric_column]],
        colorscale = colorscale,
        reversescale = FALSE,
        opacity = opacity,
        line = list(
          color = if (high_contrast) "black" else "white", 
          width = if (high_contrast) 4 else 3
        ),
        colorbar = list(
          title = list(
            text = switch(map_metric,
              "count" = "Documents", 
              "per_capita" = "Per 100k Pop",
              "activity" = "Activity Index",
              "density" = "Density Score"
            ),
            font = list(size = 12)
          ),
          thickness = 20,
          len = 0.8,
          x = 1.02
        ),
        symbol = "circle"
      ),
      text = if (show_labels) ~paste0("<b>", state_code, "</b>") else NULL,
      textposition = "middle center",
      textfont = list(size = 11, color = "white", family = "Arial Bold"),
      hovertext = ~hover_text,
      hoverinfo = "text",
      showlegend = FALSE
    ) %>%
    plotly::layout(
      mapbox = list(
        style = "carto-positron",
        zoom = 3.2,
        center = list(lat = -14.2, lon = -53.2)
      ),
      margin = list(l = 0, r = 50, t = 40, b = 0),
      font = list(family = "Arial, sans-serif")
    )
    
    cat("✅ Enhanced fallback map created successfully\n")
    return(fig)
    
  }, error = function(e) {
    cat("❌ Enhanced fallback map creation failed:", e$message, "\n")
    return(NULL)
  })
}

#' Main choropleth generation function with automatic fallbacks
#' @param state_data Data frame with state information and metrics
#' @param geospatial_system Initialized geospatial system from geospatial_utils.R
#' @param metric_column Name of the data column to visualize
#' @param map_metric Type of metric (count, per_capita, activity, density)
#' @param map_type Type of map display (states, municipalities, regions, density)
#' @param colorscale Plotly colorscale name
#' @param show_labels Whether to display state code labels
#' @param opacity Map opacity level (0.3 to 1.0)
#' @param high_contrast Whether to use high contrast mode
#' @return plotly object with the best available map type
generate_choropleth_map <- function(state_data, geospatial_system, metric_column,
                                  map_metric = "count", map_type = "states", 
                                  colorscale = "Viridis", show_labels = FALSE,
                                  opacity = 0.85, high_contrast = FALSE) {
  
  cat("🎯 Generating choropleth map - metric:", map_metric, "type:", map_type, "\n")
  
  # Validate inputs
  if (isTRUE(is.null(state_data)) || nrow(state_data) == 0) {
    cat("❌ No state data available for mapping\n")
    return(NULL)
  }
  
  if (!metric_column %in% names(state_data)) {
    cat("❌ Metric column '", metric_column, "' not found\n")
    return(NULL) 
  }
  
  # Choose color scale based on metric type
  final_colorscale <- switch(map_type,
    "density" = "Reds",
    "regions" = "Set3", 
    "municipalities" = "Plasma",
    colorscale  # Use provided colorscale as default
  )
  
  # Attempt professional choropleth with real boundaries
  safe_geo_available <- tryCatch({
    is.list(geospatial_system) && isTRUE(geospatial_system[["available"]])
  }, error = function(e) FALSE)

  if (safe_geo_available) {
    cat("🗺️ Using professional choropleth with state boundaries\n")
    
    # Additional safety check for geospatial system components
    geojson_safe <- tryCatch({
      geospatial_system$geojson
    }, error = function(e) {
      cat("⚠️ Error accessing geospatial_system$geojson:", e$message, "\n")
      NULL
    })
    
    boundaries_safe <- tryCatch({
      geospatial_system$boundaries
    }, error = function(e) {
      cat("⚠️ Error accessing geospatial_system$boundaries:", e$message, "\n")
      NULL
    })
    
    if (!isTRUE(is.null(geojson_safe)) && !is.null(boundaries_safe)) {
      choropleth_map <- create_professional_choropleth(
        state_data = state_data,
        boundaries = boundaries_safe,
        geojson = geojson_safe,
        metric_column = metric_column,
        map_metric = map_metric,
        colorscale = final_colorscale,
        show_labels = show_labels,
        opacity = opacity,
        high_contrast = high_contrast
      )
    } else {
      cat("⚠️ Geospatial system components not safely accessible\n")
      choropleth_map <- NULL
    }
    
    if (!is.null(choropleth_map)) {
      # Add title
      title_text <- paste(
        "Brazilian States Choropleth Map -",
        switch(map_metric,
          "count" = "Document Count",
          "per_capita" = "Per Capita Distribution", 
          "activity" = "Activity Index",
          "density" = "Regulatory Density"
        )
      )
      
      choropleth_map <- choropleth_map %>%
        plotly::layout(
          title = list(
            text = title_text,
            font = list(size = 16, family = "Arial"),
            x = 0.5
          )
        )
      
      cat("✅ Professional choropleth generated successfully\n")
      return(choropleth_map)
    }
  }
  
  # Fallback to enhanced circle-based map
  cat("🔄 Falling back to enhanced circle-based visualization\n")
  
  fallback_map <- create_enhanced_fallback_map(
    state_data = state_data,
    metric_column = metric_column,
    map_metric = map_metric,
    colorscale = final_colorscale,
    show_labels = show_labels,
    opacity = opacity,
    high_contrast = high_contrast
  )
  
  if (!is.null(fallback_map)) {
    # Add title and subtitle indicating fallback mode
    title_text <- paste(
      "Brazilian States Map -",
      switch(map_metric,
        "count" = "Document Count",
        "per_capita" = "Per Capita Distribution",
        "activity" = "Activity Index", 
        "density" = "Regulatory Density"
      ),
      "(Enhanced View)"
    )
    
    fallback_map <- fallback_map %>%
      plotly::layout(
        title = list(
          text = title_text,
          font = list(size = 16, family = "Arial"),
          x = 0.5
        ),
        annotations = list(
          list(
            text = "Circle size and color represent data values",
            showarrow = FALSE,
            x = 0.5,
            y = 0.02,
            xref = "paper",
            yref = "paper",
            font = list(size = 10, color = "gray")
          )
        )
      ) %>%
      plotly::config(
        displayModeBar = TRUE,
        scrollZoom = TRUE,
        displaylogo = FALSE,
        modeBarButtonsToRemove = c('pan2d', 'select2d', 'lasso2d')
      )
    
    cat("✅ Enhanced fallback map generated successfully\n")
    return(fallback_map)
  }
  
  # Ultimate fallback - basic error message
  cat("❌ All map generation methods failed\n")
  return(NULL)
}

# Integration with Advanced Maps System
# Try to load advanced system if available
advanced_maps_available <- FALSE
tryCatch({
  # Check if advanced maps integration is available
  if (file.exists("modules/maps/advanced_maps_integration.R")) {
    source("modules/maps/advanced_maps_integration.R")
    assign("ADVANCED_MAPS_SYSTEM", initialize_advanced_maps_system(), envir = .GlobalEnv)
    advanced_maps_available <- TRUE
    cat("🚀 Advanced Maps System integrated successfully\n")
  }
}, error = function(e) {
  cat("⚠️ Advanced Maps System not available, using standard choropleth\n")
})

#' Enhanced choropleth generation with advanced features integration
#' @param state_data Data frame with state information and metrics
#' @param geospatial_system Initialized geospatial system
#' @param metric_column Name of the data column to visualize
#' @param advanced_options List of advanced options (clustering, animation, etc.)
generate_enhanced_choropleth_map <- function(state_data, geospatial_system, metric_column,
                                           map_metric = "count", map_type = "states", 
                                           colorscale = "Viridis", show_labels = FALSE,
                                           opacity = 0.85, high_contrast = FALSE,
                                           advanced_options = list()) {
  
  # Check if advanced system is available and options are requested
  use_advanced <- advanced_maps_available && 
                 exists("ADVANCED_MAPS_SYSTEM") && 
                 (isTRUE(length(advanced_options) > 0) || 
                  !isTRUE(is.null(advanced_options$clustering)) ||
                  !isTRUE(is.null(advanced_options$animation)) ||
                  !is.null(advanced_options$optimization))
  
  if (use_advanced) {
    cat("🚀 Using Advanced Maps System for enhanced choropleth\n")
    
    tryCatch({
      # Use advanced system
      advanced_choropleth <- ADVANCED_MAPS_SYSTEM$create_choropleth(
        data = state_data,
        metric_column = metric_column,
        map_type = map_type,
        options = list(
          resolution = advanced_options$resolution %||% "medium",
          clustering = advanced_options$clustering %||% FALSE,
          animation = advanced_options$animation %||% FALSE,
          optimization = advanced_options$optimization %||% TRUE,
          webgl = advanced_options$webgl %||% TRUE,
          colorscale = colorscale,
          opacity = opacity,
          high_contrast = high_contrast
        )
      )
      
      if (!is.null(advanced_choropleth)) {
        cat("✅ Advanced choropleth created successfully\n")
        return(advanced_choropleth)
      } else {
        cat("⚠️ Advanced choropleth failed, falling back to standard\n")
      }
      
    }, error = function(e) {
      cat("❌ Advanced choropleth error:", e$message, "- falling back\n")
    })
  }
  
  # Fall back to original implementation
  cat("🗺️ Using standard choropleth generation\n")
  return(generate_choropleth_map(
    state_data = state_data,
    geospatial_system = geospatial_system,
    metric_column = metric_column,
    map_metric = map_metric,
    map_type = map_type,
    colorscale = colorscale,
    show_labels = show_labels,
    opacity = opacity,
    high_contrast = high_contrast
  ))
}

# Utility operator for advanced options
`%||%` <- function(x, y) if (is.null(x)) y else x

cat("🎨 Enhanced choropleth generator loaded\n")
cat("📊 Functions available: create_professional_choropleth, create_enhanced_fallback_map, generate_choropleth_map, generate_enhanced_choropleth_map\n")
if (advanced_maps_available) {
  cat("🚀 Advanced Maps System: AVAILABLE\n")
  cat("🎯 Advanced features: clustering, animation, optimization, WebGL acceleration\n")
} else {
  cat("⚠️ Advanced Maps System: NOT AVAILABLE (using standard features only)\n")
}