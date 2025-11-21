# =============================================================================
# Leaflet Map Optimization System
# =============================================================================
# Monitor Legislativo v4 - Phase 4 Task 4.3
#
# Optimizes leaflet map rendering using leafletProxy for incremental updates
# instead of full map re-renders. Significantly improves performance for
# interactive geographic visualizations.
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# =============================================================================

#' Optimized Leaflet Map Manager
#'
#' Creates a leaflet map with proxy-based updates for better performance.
#' Instead of re-rendering the entire map on data changes, this system
#' uses leafletProxy to update only changed elements.
#'
#' @param map_id ID of the leaflet map output
#' @param session Shiny session object
#'
#' @return List with map management functions
#' @export
create_leaflet_manager <- function(map_id, session) {

  # Track current map state
  map_state <- reactiveValues(
    initialized = FALSE,
    markers = list(),
    polygons = list(),
    circles = list(),
    last_update = NULL,
    update_count = 0
  )

  # Initialize base map (only done once)
  initialize_map <- function(center_lat = -15.7801, center_lng = -47.9292, zoom = 4) {
    if (!map_state$initialized) {
      cat("🗺️ Initializing base leaflet map:", map_id, "\n")

      base_map <- leaflet::leaflet() %>%
        leaflet::addTiles(
          urlTemplate = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
          attribution = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        ) %>%
        leaflet::setView(lng = center_lng, lat = center_lat, zoom = zoom) %>%
        leaflet::addScaleBar(position = "bottomleft")

      map_state$initialized <- TRUE
      map_state$last_update <- Sys.time()

      return(base_map)
    }

    return(NULL)
  }

  # Update markers using proxy (efficient)
  update_markers <- function(data, lat_col = "lat", lng_col = "lng",
                            popup_col = NULL, label_col = NULL,
                            cluster = TRUE) {

    if (!map_state$initialized) {
      cat("⚠️ Map not initialized, cannot update markers\n")
      return(NULL)
    }

    cat(sprintf("🔄 Updating %d markers using leafletProxy\n", nrow(data)))

    proxy <- leaflet::leafletProxy(map_id, session = session)

    # Clear existing markers efficiently
    proxy <- proxy %>%
      leaflet::clearMarkers() %>%
      leaflet::clearMarkerClusters()

    # Add new markers
    if (nrow(data) > 0) {
      marker_args <- list(
        map = proxy,
        data = data,
        lng = as.formula(paste0("~", lng_col)),
        lat = as.formula(paste0("~", lat_col))
      )

      # Add popup if specified
      if (!is.null(popup_col) && popup_col %in% names(data)) {
        marker_args$popup <- as.formula(paste0("~", popup_col))
      }

      # Add label if specified
      if (!is.null(label_col) && label_col %in% names(data)) {
        marker_args$label <- as.formula(paste0("~", label_col))
      }

      # Use clustering for many markers
      if (cluster && nrow(data) > 100) {
        marker_args$clusterOptions <- leaflet::markerClusterOptions()
      }

      proxy <- do.call(leaflet::addMarkers, marker_args)

      # Update state
      map_state$markers <- data
      map_state$update_count <- map_state$update_count + 1
      map_state$last_update <- Sys.time()
    }

    return(invisible(NULL))
  }

  # Update polygons using proxy (efficient)
  update_polygons <- function(spatial_data, fill_col = NULL, weight = 2,
                             opacity = 0.8, fill_opacity = 0.6,
                             popup_col = NULL, label_col = NULL) {

    if (!map_state$initialized) {
      cat("⚠️ Map not initialized, cannot update polygons\n")
      return(NULL)
    }

    cat("🔄 Updating polygons using leafletProxy\n")

    proxy <- leaflet::leafletProxy(map_id, session = session)

    # Clear existing polygons efficiently
    proxy <- proxy %>%
      leaflet::clearShapes()

    # Add new polygons
    polygon_args <- list(
      map = proxy,
      data = spatial_data,
      weight = weight,
      opacity = opacity,
      fillOpacity = fill_opacity
    )

    # Add fill color if specified
    if (!is.null(fill_col) && fill_col %in% names(spatial_data)) {
      # Create color palette
      pal <- leaflet::colorNumeric(
        palette = "YlOrRd",
        domain = spatial_data[[fill_col]]
      )
      polygon_args$fillColor <- as.formula(paste0("~pal(", fill_col, ")"))
      polygon_args$color <- "#444444"
    }

    # Add popup if specified
    if (!is.null(popup_col) && popup_col %in% names(spatial_data)) {
      polygon_args$popup <- as.formula(paste0("~", popup_col))
    }

    # Add label if specified
    if (!is.null(label_col) && label_col %in% names(spatial_data)) {
      polygon_args$label <- as.formula(paste0("~", label_col))
    }

    proxy <- do.call(leaflet::addPolygons, polygon_args)

    # Update state
    map_state$polygons <- spatial_data
    map_state$update_count <- map_state$update_count + 1
    map_state$last_update <- Sys.time()

    return(invisible(NULL))
  }

  # Update circles using proxy (efficient)
  update_circles <- function(data, lat_col = "lat", lng_col = "lng",
                            radius_col = "radius", fill_col = NULL,
                            popup_col = NULL, label_col = NULL) {

    if (!map_state$initialized) {
      cat("⚠️ Map not initialized, cannot update circles\n")
      return(NULL)
    }

    cat(sprintf("🔄 Updating %d circles using leafletProxy\n", nrow(data)))

    proxy <- leaflet::leafletProxy(map_id, session = session)

    # Clear existing circles efficiently
    proxy <- proxy %>%
      leaflet::clearShapes()

    # Add new circles
    if (nrow(data) > 0) {
      circle_args <- list(
        map = proxy,
        data = data,
        lng = as.formula(paste0("~", lng_col)),
        lat = as.formula(paste0("~", lat_col)),
        radius = as.formula(paste0("~", radius_col))
      )

      # Add fill color if specified
      if (!is.null(fill_col) && fill_col %in% names(data)) {
        pal <- leaflet::colorNumeric(palette = "viridis", domain = data[[fill_col]])
        circle_args$fillColor <- as.formula(paste0("~pal(", fill_col, ")"))
        circle_args$fillOpacity <- 0.6
      }

      # Add popup if specified
      if (!is.null(popup_col) && popup_col %in% names(data)) {
        circle_args$popup <- as.formula(paste0("~", popup_col))
      }

      # Add label if specified
      if (!is.null(label_col) && label_col %in% names(data)) {
        circle_args$label <- as.formula(paste0("~", label_col))
      }

      proxy <- do.call(leaflet::addCircles, circle_args)

      # Update state
      map_state$circles <- data
      map_state$update_count <- map_state$update_count + 1
      map_state$last_update <- Sys.time()
    }

    return(invisible(NULL))
  }

  # Fly to location (smooth animation)
  fly_to <- function(lat, lng, zoom = 10) {
    leaflet::leafletProxy(map_id, session = session) %>%
      leaflet::flyTo(lng = lng, lat = lat, zoom = zoom)
  }

  # Fit bounds to data
  fit_bounds <- function(data, lat_col = "lat", lng_col = "lng", padding = 0.1) {
    if (nrow(data) > 0) {
      lat_range <- range(data[[lat_col]], na.rm = TRUE)
      lng_range <- range(data[[lng_col]], na.rm = TRUE)

      # Add padding
      lat_padding <- diff(lat_range) * padding
      lng_padding <- diff(lng_range) * padding

      leaflet::leafletProxy(map_id, session = session) %>%
        leaflet::fitBounds(
          lng1 = lng_range[1] - lng_padding,
          lat1 = lat_range[1] - lat_padding,
          lng2 = lng_range[2] + lng_padding,
          lat2 = lat_range[2] + lat_padding
        )
    }
  }

  # Add heatmap layer
  add_heatmap <- function(data, lat_col = "lat", lng_col = "lng",
                         intensity_col = NULL, blur = 15, radius = 10) {

    if (!requireNamespace("leaflet.extras", quietly = TRUE)) {
      cat("⚠️ leaflet.extras package required for heatmap\n")
      return(NULL)
    }

    cat(sprintf("🔥 Adding heatmap with %d points\n", nrow(data)))

    proxy <- leaflet::leafletProxy(map_id, session = session)

    if (!is.null(intensity_col) && intensity_col %in% names(data)) {
      proxy <- proxy %>%
        leaflet.extras::addHeatmap(
          data = data,
          lng = as.formula(paste0("~", lng_col)),
          lat = as.formula(paste0("~", lat_col)),
          intensity = as.formula(paste0("~", intensity_col)),
          blur = blur,
          radius = radius
        )
    } else {
      proxy <- proxy %>%
        leaflet.extras::addHeatmap(
          data = data,
          lng = as.formula(paste0("~", lng_col)),
          lat = as.formula(paste0("~", lat_col)),
          blur = blur,
          radius = radius
        )
    }

    return(invisible(NULL))
  }

  # Clear all layers
  clear_all <- function() {
    leaflet::leafletProxy(map_id, session = session) %>%
      leaflet::clearMarkers() %>%
      leaflet::clearMarkerClusters() %>%
      leaflet::clearShapes()

    map_state$markers <- list()
    map_state$polygons <- list()
    map_state$circles <- list()
  }

  # Get map statistics
  get_stats <- function() {
    list(
      initialized = map_state$initialized,
      marker_count = length(map_state$markers),
      polygon_count = length(map_state$polygons),
      circle_count = length(map_state$circles),
      update_count = map_state$update_count,
      last_update = map_state$last_update
    )
  }

  # Return manager interface
  list(
    initialize = initialize_map,
    update_markers = update_markers,
    update_polygons = update_polygons,
    update_circles = update_circles,
    add_heatmap = add_heatmap,
    fly_to = fly_to,
    fit_bounds = fit_bounds,
    clear_all = clear_all,
    get_stats = get_stats,
    state = map_state
  )
}

#' Debounced Map Update
#'
#' Creates a debounced version of map updates to prevent
#' excessive re-rendering during rapid user interactions
#'
#' @param update_function Function to debounce
#' @param delay_ms Delay in milliseconds (default 500)
#' @return Debounced function
#' @export
debounce_map_update <- function(update_function, delay_ms = 500) {
  shiny::debounce(update_function, delay_ms)
}

#' Batch Map Updates
#'
#' Batches multiple map updates into a single render cycle
#' for better performance
#'
#' @param map_manager Leaflet manager object
#' @param updates List of update operations
#' @export
batch_map_updates <- function(map_manager, updates) {
  cat("📦 Batching", length(updates), "map updates\n")

  start_time <- Sys.time()

  for (update in updates) {
    if (is.function(update)) {
      update()
    }
  }

  end_time <- Sys.time()
  duration_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000

  cat(sprintf("✅ Batch update completed in %.2f ms\n", duration_ms))
}

#' Optimize Spatial Data for Leaflet
#'
#' Simplifies spatial data to reduce rendering overhead
#'
#' @param spatial_data sf object or spatial data frame
#' @param tolerance Simplification tolerance
#' @return Optimized spatial data
#' @export
optimize_spatial_data <- function(spatial_data, tolerance = 0.01) {
  if (requireNamespace("sf", quietly = TRUE)) {
    if (inherits(spatial_data, "sf")) {
      cat("🔧 Simplifying spatial geometry\n")
      spatial_data <- sf::st_simplify(spatial_data, dTolerance = tolerance)
    }
  }

  return(spatial_data)
}

cat("✅ Leaflet optimization system loaded\n")
