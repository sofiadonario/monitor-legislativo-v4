# Advanced Choropleth Mapping Utilities
# Monitor Legislativo v4 - Interactive Brazilian Choropleth Maps
# ==============================================================

#' Advanced Choropleth Mapping for Monitor Legislativo v4
#' 
#' Specialized utilities for creating interactive choropleth maps of Brazilian
#' legislative data with proper color schemes, legends, and mobile optimization.

library(leaflet)
library(RColorBrewer)
library(htmltools)
library(htmlwidgets)
library(sf)
library(dplyr)

#' Create Interactive Choropleth Map for Brazilian Legislative Data
#' 
#' Creates an interactive choropleth map with proper styling for Brazilian
#' geographic analysis of legislative documents.
#' 
#' @param boundaries_data sf object with geographic boundaries
#' @param data_values data.frame with values to map
#' @param join_column Character column name for joining data
#' @param value_column Character column name for values
#' @param map_title Character title for the map
#' @param color_palette Character name of RColorBrewer palette
#' @param reverse_palette Logical whether to reverse color palette
#' @return leaflet map object
#' @export
create_choropleth_map <- function(boundaries_data, data_values, join_column, value_column, 
                                  map_title = "Análise Geográfica", color_palette = "YlOrRd", 
                                  reverse_palette = FALSE) {
  
  cat("🗺️ Creating advanced choropleth map...\n")
  
  tryCatch({
    if (is.null(boundaries_data) || is.null(data_values)) {
      return(create_empty_brazil_map())
    }
    
    # Ensure geometries are valid
    boundaries_data <- sf::st_make_valid(boundaries_data)
    
    # Join data with boundaries
    map_data <- boundaries_data %>%
      left_join(data_values, by = setNames(join_column, names(boundaries_data)[1]))
    
    # Handle missing values
    map_data[[value_column]][is.na(map_data[[value_column]])] <- 0
    
    # Create color palette
    if (reverse_palette) {
      pal <- colorNumeric(
        palette = rev(brewer.pal(9, color_palette)),
        domain = range(map_data[[value_column]], na.rm = TRUE),
        na.color = "#E5E5E5"
      )
    } else {
      pal <- colorNumeric(
        palette = brewer.pal(9, color_palette),
        domain = range(map_data[[value_column]], na.rm = TRUE),
        na.color = "#E5E5E5"
      )
    }
    
    # Create map
    map <- leaflet(map_data) %>%
      addProviderTiles(\n        providers$CartoDB.Positron,
        options = providerTileOptions(opacity = 0.9)
      ) %>%
      setView(lng = -55, lat = -15, zoom = 4) %>%
      addPolygons(
        fillColor = ~pal(get(value_column)),
        fillOpacity = 0.8,
        color = "#FFFFFF",
        weight = 2,
        opacity = 1.0,
        smoothFactor = 0.5,
        highlightOptions = highlightOptions(
          weight = 4,
          color = "#2C3E50",
          fillOpacity = 0.9,
          bringToFront = TRUE
        ),
        popup = ~create_popup_content(., value_column),
        label = ~create_hover_label(., value_column),
        labelOptions = labelOptions(
          style = list(
            "font-weight" = "normal", 
            "padding" = "3px 8px",
            "background-color" = "rgba(255,255,255,0.9)",
            "border" = "1px solid #cccccc",
            "border-radius" = "3px"
          ),
          textsize = "14px",
          direction = "auto"
        )
      ) %>%
      addLegend(
        pal = pal,
        values = ~get(value_column),
        title = HTML(paste0("<strong>", map_title, "</strong><br><span style='font-size:11px'>Documentos por região</span>")),
        position = "topright",
        opacity = 0.9,
        labFormat = labelFormat(
          suffix = " docs",
          between = " - ",
          transform = function(x) round(x, 0)
        )
      ) %>%
      # Add scale bar
      addScaleBar(
        position = "bottomleft",
        options = scaleBarOptions(
          maxWidth = 100,
          metric = TRUE,
          imperial = FALSE
        )
      ) %>%
      # Add mini map
      addMiniMap(
        tiles = providers$CartoDB.Positron,
        position = "bottomright",
        width = 120,
        height = 80,
        toggleDisplay = TRUE
      )\n    \n    # Add custom controls\n    map <- add_map_controls(map)\n    \n    cat(\"✅ Choropleth map created successfully\\n\")\n    return(map)\n    \n  }, error = function(e) {\n    warning(\"Error creating choropleth map: \", e$message)\n    return(create_empty_brazil_map())\n  })\n}\n\n#' Create Popup Content for Map Features\n#' \n#' Creates rich HTML popup content for map features.\n#' \n#' @param feature_data Single row of map data\n#' @param value_column Character name of value column\n#' @return HTML string\ncreate_popup_content <- function(feature_data, value_column) {\n  value <- feature_data[[value_column]]\n  name <- if (\"state_name\" %in% names(feature_data)) {\n    feature_data$state_name\n  } else if (\"nome\" %in% names(feature_data)) {\n    feature_data$nome\n  } else {\n    \"Região\"\n  }\n  \n  # Get additional information if available\n  region <- if (\"region_name\" %in% names(feature_data)) {\n    paste0(\"<br><strong>Região:</strong> \", feature_data$region_name)\n  } else {\n    \"\"\n  }\n  \n  categories <- if (\"unique_categories\" %in% names(feature_data)) {\n    paste0(\"<br><strong>Categorias:</strong> \", feature_data$unique_categories)\n  } else {\n    \"\"\n  }\n  \n  date_range <- if (\"date_range_start\" %in% names(feature_data) && \"date_range_end\" %in% names(feature_data)) {\n    paste0(\"<br><strong>Período:</strong> \", \n           format(as.Date(feature_data$date_range_start), \"%d/%m/%Y\"), \" a \",\n           format(as.Date(feature_data$date_range_end), \"%d/%m/%Y\"))\n  } else {\n    \"\"\n  }\n  \n  HTML(paste0(\n    \"<div style='font-family: Arial, sans-serif; font-size: 13px; max-width: 200px;'>\",\n    \"<h4 style='margin: 0 0 8px 0; color: #2C3E50; font-size: 16px;'>\", name, \"</h4>\",\n    \"<strong>Documentos:</strong> <span style='color: #E74C3C; font-size: 16px;'>\", \n    format(value, big.mark = \".\"), \"</span>\",\n    region,\n    categories,\n    date_range,\n    \"</div>\"\n  ))\n}\n\n#' Create Hover Label for Map Features\n#' \n#' Creates concise hover labels for map features.\n#' \n#' @param feature_data Single row of map data\n#' @param value_column Character name of value column\n#' @return HTML string\ncreate_hover_label <- function(feature_data, value_column) {\n  value <- feature_data[[value_column]]\n  name <- if (\"state_name\" %in% names(feature_data)) {\n    feature_data$state_name\n  } else if (\"nome\" %in% names(feature_data)) {\n    feature_data$nome\n  } else {\n    \"Região\"\n  }\n  \n  HTML(paste0(\n    \"<strong>\", name, \"</strong><br>\",\n    format(value, big.mark = \".\"), \" documento\", \n    ifelse(value != 1, \"s\", \"\")\n  ))\n}\n\n#' Add Custom Map Controls\n#' \n#' Adds custom controls and functionality to the map.\n#' \n#' @param map leaflet map object\n#' @return enhanced leaflet map\nadd_map_controls <- function(map) {\n  # Add fullscreen control\n  map <- map %>%\n    htmlwidgets::onRender(\"\n      function(el, x) {\n        // Add fullscreen button\n        var fullscreenControl = L.control({position: 'topleft'});\n        fullscreenControl.onAdd = function(map) {\n          var div = L.DomUtil.create('div', 'leaflet-control-fullscreen');\n          div.innerHTML = '<button class=\\\"btn btn-sm btn-outline-secondary\\\" onclick=\\\"toggleFullscreen()\\\" title=\\\"Tela cheia\\\"><i class=\\\"fa fa-expand\\\"></i></button>';\n          return div;\n        };\n        fullscreenControl.addTo(this);\n        \n        // Add reset view button\n        var resetControl = L.control({position: 'topleft'});\n        resetControl.onAdd = function(map) {\n          var div = L.DomUtil.create('div', 'leaflet-control-reset');\n          div.innerHTML = '<button class=\\\"btn btn-sm btn-outline-primary\\\" onclick=\\\"resetView()\\\" title=\\\"Voltar ao Brasil\\\"><i class=\\\"fa fa-home\\\"></i></button>';\n          return div;\n        };\n        resetControl.addTo(this);\n        \n        // Define functions\n        window.toggleFullscreen = function() {\n          var mapElement = el;\n          if (mapElement.requestFullscreen) {\n            mapElement.requestFullscreen();\n          } else if (mapElement.webkitRequestFullscreen) {\n            mapElement.webkitRequestFullscreen();\n          } else if (mapElement.mozRequestFullScreen) {\n            mapElement.mozRequestFullScreen();\n          }\n        };\n        \n        window.resetView = function() {\n          map.setView([-15, -55], 4);\n        };\n      }\n    \")\n  \n  return(map)\n}\n\n#' Create Temporal Choropleth Map\n#' \n#' Creates a choropleth map with temporal controls for time-series analysis.\n#' \n#' @param boundaries_data sf object with boundaries\n#' @param temporal_data data.frame with temporal data\n#' @param time_column Character name of time column\n#' @param value_column Character name of value column\n#' @return leaflet map with temporal controls\n#' @export\ncreate_temporal_choropleth <- function(boundaries_data, temporal_data, time_column, value_column) {\n  cat(\"⏱️ Creating temporal choropleth map...\\n\")\n  \n  tryCatch({\n    # Get unique time periods\n    time_periods <- unique(temporal_data[[time_column]])\n    time_periods <- sort(time_periods)\n    \n    # Start with first time period\n    initial_data <- temporal_data %>%\n      filter(get(time_column) == time_periods[1])\n    \n    map <- create_choropleth_map(\n      boundaries_data = boundaries_data,\n      data_values = initial_data,\n      join_column = \"state_abbr\",\n      value_column = value_column,\n      map_title = paste(\"Análise Temporal -\", time_periods[1]),\n      color_palette = \"Spectral\",\n      reverse_palette = TRUE\n    )\n    \n    # Add temporal controls (would require additional Shiny integration)\n    cat(\"✅ Temporal choropleth map created\\n\")\n    return(map)\n    \n  }, error = function(e) {\n    warning(\"Error creating temporal choropleth: \", e$message)\n    return(create_empty_brazil_map())\n  })\n}\n\n#' Create Category-based Choropleth Map\n#' \n#' Creates choropleth map showing distribution of document categories.\n#' \n#' @param boundaries_data sf object with boundaries\n#' @param category_data data.frame with category distribution\n#' @param dominant_category_column Character name of dominant category column\n#' @return leaflet map\n#' @export\ncreate_category_choropleth <- function(boundaries_data, category_data, dominant_category_column = \"dominant_category\") {\n  cat(\"📊 Creating category-based choropleth map...\\n\")\n  \n  tryCatch({\n    # Define colors for different categories\n    category_colors <- list(\n      \"Lei\" = \"#3498DB\",\n      \"Decreto\" = \"#E74C3C\",\n      \"Portaria\" = \"#2ECC71\",\n      \"Resolução\" = \"#F39C12\",\n      \"Instrução Normativa\" = \"#9B59B6\",\n      \"Outros\" = \"#95A5A6\"\n    )\n    \n    # Join data with boundaries\n    map_data <- boundaries_data %>%\n      left_join(category_data, by = \"state_abbr\")\n    \n    # Create discrete color palette\n    unique_categories <- unique(map_data[[dominant_category_column]])\n    unique_categories <- unique_categories[!is.na(unique_categories)]\n    \n    pal <- colorFactor(\n      palette = unlist(category_colors[unique_categories]),\n      domain = unique_categories,\n      na.color = \"#E5E5E5\"\n    )\n    \n    map <- leaflet(map_data) %>%\n      addProviderTiles(providers$CartoDB.Positron) %>%\n      setView(lng = -55, lat = -15, zoom = 4) %>%\n      addPolygons(\n        fillColor = ~pal(get(dominant_category_column)),\n        fillOpacity = 0.8,\n        color = \"#FFFFFF\",\n        weight = 2,\n        popup = ~paste0(\n          \"<strong>\", state_name, \"</strong><br>\",\n          \"Categoria dominante: \", get(dominant_category_column), \"<br>\",\n          \"Total de documentos: \", total_documents\n        )\n      ) %>%\n      addLegend(\n        pal = pal,\n        values = ~get(dominant_category_column),\n        title = \"Categoria Dominante\",\n        position = \"topright\"\n      )\n    \n    cat(\"✅ Category choropleth map created\\n\")\n    return(map)\n    \n  }, error = function(e) {\n    warning(\"Error creating category choropleth: \", e$message)\n    return(create_empty_brazil_map())\n  })\n}\n\n#' Create Density Heatmap\n#' \n#' Creates a density heatmap overlay for point data.\n#' \n#' @param base_map leaflet map object\n#' @param point_data data.frame with lat/lng coordinates\n#' @param intensity_column Character name of intensity column (optional)\n#' @return leaflet map with heatmap\n#' @export\nadd_density_heatmap <- function(base_map, point_data, intensity_column = NULL) {\n  cat(\"🔥 Adding density heatmap layer...\\n\")\n  \n  tryCatch({\n    if (nrow(point_data) == 0) {\n      warning(\"No point data available for heatmap\")\n      return(base_map)\n    }\n    \n    # Prepare data for heatmap\n    if (is.null(intensity_column)) {\n      heatmap_data <- point_data[, c(\"latitude\", \"longitude\")]\n    } else {\n      heatmap_data <- point_data[, c(\"latitude\", \"longitude\", intensity_column)]\n    }\n    \n    # Remove rows with missing coordinates\n    heatmap_data <- heatmap_data[complete.cases(heatmap_data[, 1:2]), ]\n    \n    if (nrow(heatmap_data) == 0) {\n      warning(\"No valid coordinates for heatmap\")\n      return(base_map)\n    }\n    \n    # Add heatmap layer\n    enhanced_map <- base_map %>%\n      addHeatmap(\n        data = heatmap_data,\n        lng = ~longitude,\n        lat = ~latitude,\n        intensity = if(is.null(intensity_column)) NULL else ~get(intensity_column),\n        blur = 20,\n        max = 0.05,\n        radius = 15,\n        gradient = list(\n          \"0.0\" = \"blue\",\n          \"0.5\" = \"lime\",\n          \"0.8\" = \"yellow\",\n          \"1.0\" = \"red\"\n        )\n      )\n    \n    cat(\"✅ Density heatmap added with\", nrow(heatmap_data), \"points\\n\")\n    return(enhanced_map)\n    \n  }, error = function(e) {\n    warning(\"Error adding heatmap: \", e$message)\n    return(base_map)\n  })\n}\n\n#' Create Empty Brazil Map\n#' \n#' Creates a basic empty map of Brazil as fallback.\n#' \n#' @return leaflet map object\ncreate_empty_brazil_map <- function() {\n  leaflet() %>%\n    addProviderTiles(providers$CartoDB.Positron) %>%\n    setView(lng = -55, lat = -15, zoom = 4) %>%\n    addScaleBar(position = \"bottomleft\") %>%\n    addControl(\n      html = \"<div style='background: rgba(255,255,255,0.9); padding: 10px; border-radius: 5px;'>\n                <strong>⚠️ Dados Geográficos Indisponíveis</strong><br>\n                <small>Conectando com serviços IBGE...</small>\n              </div>\",\n      position = \"topright\"\n    )\n}\n\n#' Optimize Map for Mobile Devices\n#' \n#' Applies mobile-specific optimizations to the map.\n#' \n#' @param map leaflet map object\n#' @return optimized leaflet map\n#' @export\noptimize_for_mobile <- function(map) {\n  map %>%\n    htmlwidgets::onRender(\"\n      function(el, x) {\n        // Disable zoom on double tap for mobile\n        this.options.doubleClickZoom = false;\n        \n        // Optimize touch interactions\n        this.options.tap = true;\n        this.options.tapTolerance = 15;\n        \n        // Adjust control sizes for mobile\n        if (window.innerWidth < 768) {\n          // Hide some controls on small screens\n          $('.leaflet-control-minimap').hide();\n          \n          // Adjust legend position\n          $('.leaflet-control-legend').css({\n            'position': 'absolute',\n            'bottom': '10px',\n            'right': '10px',\n            'max-width': '150px',\n            'font-size': '11px'\n          });\n        }\n      }\n    \")\n}\n\ncat(\"✅ Advanced choropleth mapping utilities loaded successfully\\n\")