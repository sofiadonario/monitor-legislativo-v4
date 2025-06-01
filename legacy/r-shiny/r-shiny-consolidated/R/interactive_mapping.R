# Interactive Mapping for Monitor Legislativo v4
# Advanced leaflet integration with clustering and Brazilian municipality-level analysis

library(leaflet)
library(leaflet.extras)
library(htmltools)
library(htmlwidgets)
library(dplyr)
library(sf)
library(RColorBrewer)

# Mapping configuration
MAP_CONFIG <- list(
  default_center = list(lat = -15.7942, lng = -47.8825),  # Brazil center
  default_zoom = 4,
  min_zoom = 3,
  max_zoom = 18,
  cluster_options = list(
    maxClusterRadius = 50,
    spiderfyOnMaxZoom = TRUE,
    showCoverageOnHover = FALSE,
    zoomToBoundsOnClick = TRUE
  ),
  color_palettes = list(
    default = "YlOrRd",
    sequential = "Blues",
    diverging = "RdYlBu",
    categorical = c("#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf")
  ),
  tile_providers = list(
    default = "CartoDB.Positron",
    satellite = "Esri.WorldImagery",
    terrain = "OpenTopoMap",
    dark = "CartoDB.DarkMatter"
  )
)

#' Create enhanced interactive map with clustering
#' @param legislative_data Data frame with legislative documents
#' @param geo_data SF object with geographic boundaries
#' @param map_style Map tile provider
#' @param color_variable Variable to use for coloring
#' @param enable_clustering Whether to enable marker clustering
#' @return Leaflet map object
create_enhanced_interactive_map <- function(legislative_data = NULL, geo_data = NULL, 
                                          map_style = "default", color_variable = "count",
                                          enable_clustering = TRUE) {
  
  log_event("Creating enhanced interactive map")
  
  # Initialize base map
  map <- leaflet() %>%
    setView(
      lng = MAP_CONFIG$default_center$lng,
      lat = MAP_CONFIG$default_center$lat,
      zoom = MAP_CONFIG$default_zoom
    ) %>%
    setMaxBounds(
      lng1 = -75, lat1 = 6,   # Northeast bounds
      lng2 = -30, lat2 -35    # Southwest bounds
    )
  
  # Add tile layer
  tile_provider <- MAP_CONFIG$tile_providers[[map_style]] %||% MAP_CONFIG$tile_providers$default
  map <- map %>% addProviderTiles(tile_provider, group = "Base Map")
  
  # Add geographic boundaries if provided
  if (!is.null(geo_data)) {
    map <- add_geographic_boundaries(map, geo_data, legislative_data, color_variable)
  }
  
  # Add legislative document markers if provided
  if (!is.null(legislative_data)) {
    map <- add_legislative_markers(map, legislative_data, geo_data, enable_clustering)
  }
  
  # Add map controls
  map <- add_map_controls(map)
  
  # Add custom CSS styling
  map <- add_custom_map_styling(map)
  
  log_event("Enhanced interactive map created")
  return(map)
}

#' Add geographic boundaries to map
#' @param map Leaflet map object
#' @param geo_data SF object with boundaries
#' @param legislative_data Legislative documents data
#' @param color_variable Variable for coloring
#' @return Enhanced map with boundaries
add_geographic_boundaries <- function(map, geo_data, legislative_data, color_variable) {
  
  if (is.null(geo_data) || nrow(geo_data) == 0) {
    return(map)
  }
  
  # Prepare choropleth data
  choropleth_data <- prepare_choropleth_data(geo_data, legislative_data, color_variable)
  
  # Create color palette
  color_palette <- create_color_palette(choropleth_data, color_variable)
  
  # Add choropleth layer
  map <- map %>%
    addPolygons(
      data = choropleth_data,
      fillColor = ~color_palette(get(color_variable)),
      fillOpacity = 0.7,
      color = "#333333",
      weight = 1,
      opacity = 0.8,
      highlightOptions = highlightOptions(
        weight = 3,
        color = "#666666",
        fillOpacity = 0.9,
        bringToFront = TRUE
      ),
      popup = ~create_boundary_popup(choropleth_data),
      popupOptions = popupOptions(maxWidth = 300),
      label = ~create_boundary_label(choropleth_data),
      labelOptions = labelOptions(
        style = list("font-weight" = "normal", padding = "3px 8px"),
        textsize = "13px",
        direction = "auto"
      ),
      group = "Geographic Boundaries"
    )
  
  # Add legend if data has variation
  if (length(unique(choropleth_data[[color_variable]])) > 1) {
    map <- map %>%
      addLegend(
        "bottomright",
        pal = color_palette,
        values = choropleth_data[[color_variable]],
        title = create_legend_title(color_variable),
        opacity = 0.7,
        group = "Geographic Boundaries"
      )
  }
  
  return(map)
}

#' Prepare choropleth data by aggregating legislative documents
#' @param geo_data Geographic boundaries
#' @param legislative_data Legislative documents
#' @param color_variable Variable for coloring
#' @return Enhanced geographic data with aggregated values
prepare_choropleth_data <- function(geo_data, legislative_data, color_variable) {
  
  if (is.null(legislative_data) || nrow(legislative_data) == 0) {
    # Return geo_data with zero values
    geo_data$count <- 0
    geo_data$density <- 0
    geo_data$latest <- as.Date("1900-01-01")
    geo_data$types <- 0
    return(geo_data)
  }
  
  # Determine join column based on geo_data structure
  if ("abbrev_state" %in% names(geo_data)) {
    join_col <- "abbrev_state"
    doc_col <- "estado"
  } else if ("code_muni" %in% names(geo_data)) {
    join_col <- "code_muni"
    doc_col <- "municipio"
  } else {
    # Default to state-level
    join_col <- "abbrev_state"
    doc_col <- "estado"
  }
  
  # Aggregate legislative data
  aggregated_data <- legislative_data %>%
    filter(!is.na(!!sym(doc_col))) %>%
    group_by(!!sym(doc_col)) %>%
    summarise(
      count = n(),
      latest = max(as.Date(data), na.rm = TRUE),
      types = length(unique(tipo[!is.na(tipo)])),
      avg_relevance = mean(relevancia_transporte %||% 50, na.rm = TRUE),
      quality_avg = mean(quality_score %||% 70, na.rm = TRUE),
      .groups = "drop"
    )
  
  # Join with geographic data
  enhanced_geo <- geo_data %>%
    left_join(aggregated_data, by = setNames(doc_col, join_col)) %>%
    mutate(
      count = coalesce(count, 0),
      density = if ("area_km2" %in% names(.)) count / area_km2 else count,
      latest = coalesce(latest, as.Date("1900-01-01")),
      types = coalesce(types, 0),
      avg_relevance = coalesce(avg_relevance, 0),
      quality_avg = coalesce(quality_avg, 0)
    )
  
  return(enhanced_geo)
}

#' Create color palette for choropleth mapping
#' @param data Data with values to color
#' @param color_variable Variable name for coloring
#' @return Color palette function
create_color_palette <- function(data, color_variable) {
  
  values <- data[[color_variable]]
  
  if (all(is.na(values)) || all(values == 0)) {
    # All zero or NA values
    return(colorFactor("grey", domain = values))
  }
  
  # Remove zero/NA values for palette calculation
  non_zero_values <- values[!is.na(values) & values > 0]
  
  if (length(non_zero_values) == 0) {
    return(colorFactor("grey", domain = values))
  }
  
  # Choose appropriate palette type
  palette_name <- MAP_CONFIG$color_palettes$default
  
  if (color_variable == "density") {
    palette_name <- MAP_CONFIG$color_palettes$sequential
  } else if (color_variable == "latest") {
    palette_name <- MAP_CONFIG$color_palettes$diverging
  }
  
  # Create palette based on data type
  if (is.numeric(non_zero_values)) {
    if (length(unique(non_zero_values)) <= 5) {
      # Few unique values - use ordinal palette
      colorFactor(palette_name, domain = values)
    } else {
      # Continuous values - use numeric palette
      colorNumeric(palette_name, domain = non_zero_values)
    }
  } else if (is.Date(non_zero_values) || inherits(non_zero_values, "Date")) {
    # Date values
    colorNumeric(palette_name, domain = as.numeric(non_zero_values))
  } else {
    # Categorical values
    colorFactor(MAP_CONFIG$color_palettes$categorical, domain = values)
  }
}

#' Create popup content for geographic boundaries
#' @param data Choropleth data
#' @return HTML popup content
create_boundary_popup <- function(data) {
  
  sapply(1:nrow(data), function(i) {
    row <- data[i, ]
    
    # Determine location name
    location_name <- coalesce(
      row$name_state,
      row$name_muni,
      row$abbrev_state,
      row$code_muni,
      "Local"
    )
    
    # Build popup content
    popup_content <- paste0(
      "<div style='font-family: Arial, sans-serif; max-width: 280px;'>",
      "<h4 style='margin: 0 0 10px 0; color: #2c3e50;'>", location_name, "</h4>",
      
      "<div style='margin-bottom: 8px;'>",
      "<strong>📄 Documentos:</strong> ", format(row$count %||% 0, big.mark = "."), "<br>",
      
      if (!is.null(row$area_km2) && !is.na(row$area_km2)) {
        paste0("<strong>📐 Área:</strong> ", format(round(row$area_km2), big.mark = "."), " km²<br>")
      } else "",
      
      if (!is.null(row$density) && !is.na(row$density)) {
        paste0("<strong>📊 Densidade:</strong> ", round(row$density, 3), " docs/km²<br>")
      } else "",
      
      if (!is.null(row$population) && !is.na(row$population)) {
        paste0("<strong>👥 População:</strong> ", format(row$population, big.mark = "."), "<br>")
      } else "",
      "</div>",
      
      if (!is.null(row$latest) && !is.na(row$latest) && row$latest > as.Date("1900-01-01")) {
        paste0(
          "<div style='margin-bottom: 8px;'>",
          "<strong>📅 Mais recente:</strong> ", format(row$latest, "%d/%m/%Y"), "<br>",
          "<strong>📑 Tipos diferentes:</strong> ", row$types %||% 0,
          "</div>"
        )
      } else "",
      
      if (!is.null(row$avg_relevance) && !is.na(row$avg_relevance)) {
        paste0(
          "<div style='margin-bottom: 8px;'>",
          "<strong>🎯 Relevância média:</strong> ", round(row$avg_relevance, 1), "%<br>",
          "<strong>⭐ Qualidade média:</strong> ", round(row$quality_avg %||% 0, 1), "%",
          "</div>"
        )
      } else "",
      
      if (!is.null(row$region_code) && !is.na(row$region_code)) {
        paste0("<div style='color: #7f8c8d; font-size: 0.9em;'>Região: ", row$region_code, "</div>")
      } else "",
      
      "</div>"
    )
    
    return(popup_content)
  })
}

#' Create label content for geographic boundaries
#' @param data Choropleth data
#' @return HTML label content
create_boundary_label <- function(data) {
  
  sapply(1:nrow(data), function(i) {
    row <- data[i, ]
    
    location_name <- coalesce(
      row$name_state,
      row$name_muni,
      row$abbrev_state,
      row$code_muni,
      "Local"
    )
    
    document_count <- row$count %||% 0
    
    paste0(
      "<div style='font-size: 12px; font-weight: bold;'>",
      location_name,
      if (document_count > 0) paste0("<br>", document_count, " documentos") else "",
      "</div>"
    )
  })
}

#' Add legislative document markers to map
#' @param map Leaflet map object
#' @param legislative_data Legislative documents
#' @param geo_data Geographic boundaries
#' @param enable_clustering Enable marker clustering
#' @return Enhanced map with markers
add_legislative_markers <- function(map, legislative_data, geo_data, enable_clustering) {
  
  if (is.null(legislative_data) || nrow(legislative_data) == 0) {
    return(map)
  }
  
  # Create document markers
  marker_data <- create_document_markers(legislative_data, geo_data)
  
  if (is.null(marker_data) || nrow(marker_data) == 0) {
    log_event("No valid marker data created", "WARN")
    return(map)
  }
  
  # Add markers with or without clustering
  if (enable_clustering) {
    map <- add_clustered_markers(map, marker_data)
  } else {
    map <- add_individual_markers(map, marker_data)
  }
  
  return(map)
}

#' Create marker data from legislative documents
#' @param legislative_data Legislative documents
#' @param geo_data Geographic boundaries
#' @return Data frame with marker information
create_document_markers <- function(legislative_data, geo_data) {
  
  # Filter documents with valid location information
  valid_docs <- legislative_data %>%
    filter(!is.na(estado), estado != "")
  
  if (nrow(valid_docs) == 0) {
    return(NULL)
  }
  
  # Get coordinates for each state from geo_data or fallback
  if (!is.null(geo_data)) {
    coordinates <- geo_data %>%
      st_drop_geometry() %>%
      select(
        state_code = abbrev_state %||% code_state,
        lat = centroid_lat,
        lng = centroid_lng
      ) %>%
      filter(!is.na(lat), !is.na(lng))
  } else {
    # Use fallback coordinates
    coordinates <- get_fallback_coordinates()
  }
  
  # Join documents with coordinates
  marker_data <- valid_docs %>%
    left_join(coordinates, by = c("estado" = "state_code")) %>%
    filter(!is.na(lat), !is.na(lng)) %>%
    mutate(
      # Add jitter to avoid exact overlaps
      lat_jitter = lat + runif(n(), -0.1, 0.1),
      lng_jitter = lng + runif(n(), -0.1, 0.1),
      
      # Create marker styling based on document properties
      marker_color = determine_marker_color(tipo, relevancia_transporte %||% 50),
      marker_size = determine_marker_size(quality_score %||% 70),
      marker_icon = determine_marker_icon(tipo)
    )
  
  return(marker_data)
}

#' Add clustered markers to map
#' @param map Leaflet map object
#' @param marker_data Marker data
#' @return Enhanced map with clustered markers
add_clustered_markers <- function(map, marker_data) {
  
  map <- map %>%
    addMarkers(
      data = marker_data,
      lng = ~lng_jitter,
      lat = ~lat_jitter,
      popup = ~create_document_popup(marker_data),
      popupOptions = popupOptions(maxWidth = 400),
      label = ~create_document_label(marker_data),
      labelOptions = labelOptions(
        style = list("font-weight" = "normal", padding = "3px 8px"),
        textsize = "12px",
        direction = "auto"
      ),
      clusterOptions = markerClusterOptions(
        maxClusterRadius = MAP_CONFIG$cluster_options$maxClusterRadius,
        spiderfyOnMaxZoom = MAP_CONFIG$cluster_options$spiderfyOnMaxZoom,
        showCoverageOnHover = MAP_CONFIG$cluster_options$showCoverageOnHover,
        zoomToBoundsOnClick = MAP_CONFIG$cluster_options$zoomToBoundsOnClick
      ),
      group = "Legislative Documents"
    )
  
  return(map)
}

#' Add individual markers to map
#' @param map Leaflet map object
#' @param marker_data Marker data
#' @return Enhanced map with individual markers
add_individual_markers <- function(map, marker_data) {
  
  # Create custom icons
  icons <- create_custom_icons(marker_data)
  
  map <- map %>%
    addMarkers(
      data = marker_data,
      lng = ~lng_jitter,
      lat = ~lat_jitter,
      icon = icons,
      popup = ~create_document_popup(marker_data),
      popupOptions = popupOptions(maxWidth = 400),
      label = ~create_document_label(marker_data),
      labelOptions = labelOptions(
        style = list("font-weight" = "normal", padding = "3px 8px"),
        textsize = "12px",
        direction = "auto"
      ),
      group = "Legislative Documents"
    )
  
  return(map)
}

#' Determine marker color based on document properties
#' @param types Vector of document types
#' @param relevance Vector of relevance scores
#' @return Vector of marker colors
determine_marker_color <- function(types, relevance) {
  
  mapply(function(type, rel) {
    
    # Color by relevance primarily
    if (rel >= 80) return("#d32f2f")      # High relevance - red
    if (rel >= 60) return("#f57c00")      # Medium relevance - orange
    if (rel >= 40) return("#388e3c")      # Low relevance - green
    
    # Color by type as fallback
    type_lower <- str_to_lower(type %||% "")
    
    if (str_detect(type_lower, "lei")) return("#1976d2")        # Blue for laws
    if (str_detect(type_lower, "decreto")) return("#7b1fa2")    # Purple for decrees
    if (str_detect(type_lower, "portaria")) return("#00796b")   # Teal for ordinances
    if (str_detect(type_lower, "resolucao")) return("#5d4037")  # Brown for resolutions
    
    return("#757575")  # Grey for others
    
  }, types, relevance)
}

#' Determine marker size based on document quality
#' @param quality_scores Vector of quality scores
#' @return Vector of marker sizes
determine_marker_size <- function(quality_scores) {
  
  sapply(quality_scores, function(quality) {
    if (quality >= 90) return("large")
    if (quality >= 70) return("medium")
    return("small")
  })
}

#' Determine marker icon based on document type
#' @param types Vector of document types
#' @return Vector of marker icons
determine_marker_icon <- function(types) {
  
  sapply(types, function(type) {
    type_lower <- str_to_lower(type %||% "")
    
    if (str_detect(type_lower, "lei")) return("gavel")
    if (str_detect(type_lower, "decreto")) return("file-text")
    if (str_detect(type_lower, "portaria")) return("clipboard")
    if (str_detect(type_lower, "resolucao")) return("check-circle")
    
    return("file")
  })
}

#' Create custom icons for markers
#' @param marker_data Marker data with styling information
#' @return Icons list for leaflet
create_custom_icons <- function(marker_data) {
  
  # Create icons based on marker properties
  icon_list <- mapply(function(color, size, icon_name) {
    
    # Determine icon size
    icon_size <- switch(size,
      "large" = c(25, 25),
      "medium" = c(20, 20),
      "small" = c(15, 15),
      c(20, 20)
    )
    
    # Create awesome icon
    awesomeIcons(
      icon = icon_name,
      iconColor = "white",
      markerColor = color,
      library = "fa",
      squareMarker = FALSE
    )
    
  }, marker_data$marker_color, marker_data$marker_size, marker_data$marker_icon,
  SIMPLIFY = FALSE)
  
  return(icon_list)
}

#' Create popup content for document markers
#' @param marker_data Marker data
#' @return HTML popup content
create_document_popup <- function(marker_data) {
  
  sapply(1:nrow(marker_data), function(i) {
    doc <- marker_data[i, ]
    
    popup_content <- paste0(
      "<div style='font-family: Arial, sans-serif; max-width: 350px;'>",
      "<h4 style='margin: 0 0 10px 0; color: #2c3e50; font-size: 16px;'>",
      str_trunc(doc$titulo %||% "Documento", 60), "</h4>",
      
      "<div style='margin-bottom: 8px;'>",
      "<strong>📋 Tipo:</strong> ", doc$tipo %||% "Não especificado", "<br>",
      "<strong>📅 Data:</strong> ", format(as.Date(doc$data), "%d/%m/%Y"), "<br>",
      "<strong>🏛️ Estado:</strong> ", doc$estado, "<br>",
      if (!is.null(doc$numero) && !is.na(doc$numero)) {
        paste0("<strong>🔢 Número:</strong> ", doc$numero, "<br>")
      } else "",
      "</div>",
      
      if (!is.null(doc$ementa) && !is.na(doc$ementa) && nchar(doc$ementa) > 0) {
        paste0(
          "<div style='margin-bottom: 8px;'>",
          "<strong>📝 Ementa:</strong><br>",
          "<div style='max-height: 80px; overflow-y: auto; padding: 5px; background: #f8f9fa; border-radius: 3px; font-size: 0.9em;'>",
          str_trunc(doc$ementa, 200),
          "</div></div>"
        )
      } else "",
      
      "<div style='margin-bottom: 8px;'>",
      if (!is.null(doc$relevancia_transporte)) {
        paste0("<strong>🎯 Relevância:</strong> ", round(doc$relevancia_transporte, 1), "%<br>")
      } else "",
      if (!is.null(doc$quality_score)) {
        paste0("<strong>⭐ Qualidade:</strong> ", round(doc$quality_score, 1), "%<br>")
      } else "",
      if (!is.null(doc$categoria_primaria)) {
        paste0("<strong>🏷️ Categoria:</strong> ", doc$categoria_primaria, "<br>")
      } else "",
      "</div>",
      
      if (!is.null(doc$url) && !is.na(doc$url) && nchar(doc$url) > 0) {
        paste0(
          "<div style='margin-top: 10px;'>",
          "<a href='", doc$url, "' target='_blank' style='color: #1976d2; text-decoration: none;'>",
          "🔗 Ver documento original</a>",
          "</div>"
        )
      } else "",
      
      "</div>"
    )
    
    return(popup_content)
  })
}

#' Create label content for document markers
#' @param marker_data Marker data
#' @return HTML label content
create_document_label <- function(marker_data) {
  
  sapply(1:nrow(marker_data), function(i) {
    doc <- marker_data[i, ]
    
    paste0(
      "<div style='font-size: 11px; font-weight: bold;'>",
      str_trunc(doc$titulo %||% "Documento", 40),
      "<br><span style='font-size: 10px; font-weight: normal;'>",
      doc$tipo %||% "", " - ", format(as.Date(doc$data), "%d/%m/%Y"),
      "</span></div>"
    )
  })
}

#' Add map controls and layers
#' @param map Leaflet map object
#' @return Enhanced map with controls
add_map_controls <- function(map) {
  
  map <- map %>%
    # Add layers control
    addLayersControl(
      baseGroups = c("Base Map"),
      overlayGroups = c("Geographic Boundaries", "Legislative Documents"),
      options = layersControlOptions(collapsed = FALSE)
    ) %>%
    
    # Add scale bar
    addScaleBar(position = "bottomleft") %>%
    
    # Add mini map
    addMiniMap(
      tiles = providers$CartoDB.Positron,
      toggleDisplay = TRUE,
      position = "bottomright",
      width = 120,
      height = 80
    ) %>%
    
    # Add measure tool
    addMeasure(
      position = "topleft",
      primaryLengthUnit = "kilometers",
      primaryAreaUnit = "sqkilometers",
      activeColor = "#3D535D",
      completedColor = "#7D4479"
    ) %>%
    
    # Add reset view control
    addResetMapButton() %>%
    
    # Add fullscreen control
    addFullscreenControl()
  
  return(map)
}

#' Add custom CSS styling to map
#' @param map Leaflet map object
#' @return Map with custom styling
add_custom_map_styling <- function(map) {
  
  custom_css <- "
    .leaflet-container {
      font-family: 'Arial', sans-serif;
    }
    
    .leaflet-popup-content-wrapper {
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    .leaflet-popup-content {
      margin: 12px 16px;
      line-height: 1.4;
    }
    
    .leaflet-popup-tip {
      background: white;
      border: none;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
    }
    
    .leaflet-control-layers {
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    .leaflet-bar a {
      border-radius: 4px;
    }
    
    .leaflet-bar a:first-child {
      border-top-left-radius: 8px;
      border-top-right-radius: 8px;
    }
    
    .leaflet-bar a:last-child {
      border-bottom-left-radius: 8px;
      border-bottom-right-radius: 8px;
    }
  "
  
  map %>%
    htmlwidgets::prependContent(
      tags$style(custom_css)
    )
}

#' Create legend title based on color variable
#' @param color_variable Variable name
#' @return Formatted legend title
create_legend_title <- function(color_variable) {
  
  titles <- list(
    "count" = "Documentos",
    "density" = "Docs/km²",
    "latest" = "Mais Recente", 
    "types" = "Tipos",
    "avg_relevance" = "Relevância (%)",
    "quality_avg" = "Qualidade (%)"
  )
  
  return(titles[[color_variable]] %||% str_to_title(str_replace_all(color_variable, "_", " ")))
}

#' Get fallback coordinates for Brazilian states
#' @return Data frame with state coordinates
get_fallback_coordinates <- function() {
  
  data.frame(
    state_code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    lat = c(-8.77, -9.71, 1.41, -3.07, -12.96, -5.20, -15.83, -19.19, -16.64, -2.55, -12.64, -20.51, -18.10, -5.53, -7.06, -24.89, -8.28, -8.28, -22.84, -5.22, -30.01, -11.22, 1.89, -27.33, -23.55, -10.90, -10.25),
    lng = c(-70.55, -36.82, -51.77, -61.66, -38.51, -39.53, -47.86, -40.34, -49.31, -44.30, -55.42, -54.54, -44.38, -52.29, -35.55, -51.55, -35.07, -43.68, -43.15, -36.52, -51.22, -61.95, -61.22, -49.44, -46.64, -37.07, -48.25),
    stringsAsFactors = FALSE
  )
}

#' Update map with new data
#' @param map_proxy Leaflet proxy object
#' @param legislative_data New legislative data
#' @param geo_data Geographic data
#' @param color_variable Color variable
#' @param enable_clustering Enable clustering
#' @return Updated map proxy
update_interactive_map <- function(map_proxy, legislative_data, geo_data, 
                                 color_variable = "count", enable_clustering = TRUE) {
  
  # Clear existing layers
  map_proxy %>%
    clearMarkers() %>%
    clearMarkerClusters() %>%
    clearShapes() %>%
    clearControls()
  
  # Re-add geographic boundaries
  if (!is.null(geo_data)) {
    map_proxy <- add_geographic_boundaries(map_proxy, geo_data, legislative_data, color_variable)
  }
  
  # Re-add markers
  if (!is.null(legislative_data)) {
    map_proxy <- add_legislative_markers(map_proxy, legislative_data, geo_data, enable_clustering)
  }
  
  return(map_proxy)
}

#' Helper function for string truncation
str_trunc <- function(string, width) {
  if (is.na(string) || nchar(string) <= width) {
    return(string)
  }
  paste0(substr(string, 1, width - 3), "...")
}

#' Helper function for null coalescing
coalesce <- function(...) {
  vals <- list(...)
  for (val in vals) {
    if (!is.null(val) && !all(is.na(val))) {
      return(val)
    }
  }
  return(NA)
}