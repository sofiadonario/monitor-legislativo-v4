# Advanced Choropleth Map Generation for Brazilian Legislative Data
# Professional choropleth implementation with full state boundary fills

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
    if (is.null(boundaries) || is.null(geojson) || is.null(state_data)) {
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
    
    # Check if we have proper GeoJSON or simplified data
    # Safely check geojson properties to avoid "closure not subsettable" errors
    has_proper_geojson <- FALSE
    if (!is.null(geojson)) {
      # Use tryCatch to safely access geojson properties
      has_proper_geojson <- tryCatch({
        # Check if geojson is a list and has the required structure
        is.list(geojson) && 
        !is.null(geojson[["type"]]) && 
        geojson[["type"]] == "FeatureCollection" && 
        !identical(geojson[["features"]], "simplified")
      }, error = function(e) {
        cat("⚠️ Error checking GeoJSON structure:", e$message, "\n")
        FALSE
      })
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
      layout(
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
          add_trace(
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
        layout(
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
    layout(
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
  if (is.null(state_data) || nrow(state_data) == 0) {
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
  if (!is.null(geospatial_system) && isTRUE(geospatial_system$available)) {
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
    
    if (!is.null(geojson_safe) && !is.null(boundaries_safe)) {
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
        layout(
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
      layout(
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
      )
    
    cat("✅ Enhanced fallback map generated successfully\n")
    return(fallback_map)
  }
  
  # Ultimate fallback - basic error message
  cat("❌ All map generation methods failed\n")
  return(NULL)
}

cat("🎨 Professional choropleth generator loaded\n")
cat("📊 Functions available: create_professional_choropleth, create_enhanced_fallback_map, generate_choropleth_map\n")