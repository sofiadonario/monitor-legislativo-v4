# Enhanced Geographic Rendering
# Monitor Legislativo v4 - Toggleable Layer Map Rendering
# ===========================================================

#' Render Enhanced Leaflet Map with Toggleable Layers
#'
#' @param values Reactive values containing geographic data
#' @param input Shiny input object
#' @param db_connection Database connection (optional)
#' @return Leaflet map object with layer controls
#' @export
render_enhanced_geographic_map <- function(values, input, db_connection = NULL) {

  # Create base map centered on Brazil
  map <- leaflet() %>%
    addProviderTiles(
      providers$CartoDB.Positron,
      options = providerTileOptions(opacity = 0.9),
      group = "Base Map"
    ) %>%
    addProviderTiles(
      providers$Esri.WorldImagery,
      options = providerTileOptions(opacity = 0.9),
      group = "Satellite"
    ) %>%
    setView(lng = -55, lat = -15, zoom = 4) %>%
    addMiniMap(
      tiles = providers$CartoDB.Positron,
      toggleDisplay = TRUE,
      position = "bottomright"
    ) %>%
    addScaleBar(position = "bottomleft")

  # Track which layers to add
  selected_layers <- input$map_layers

  if (is.null(selected_layers) || length(selected_layers) == 0) {
    selected_layers <- c("bills_per_capita")  # Default
  }

  # Calculate and add each selected data layer
  for (layer_id in selected_layers) {
    map <- add_data_layer(map, layer_id, values, db_connection)
  }

  # Add reference layers (state boundaries, etc.)
  reference_layers <- input$reference_layers
  if (!is.null(reference_layers)) {
    for (ref_layer in reference_layers) {
      map <- add_reference_layer(map, ref_layer, values)
    }
  }

  # Add layer controls
  overlay_groups <- c()

  # Build list of active overlay group names
  layer_names <- list(
    population_density = "📊 População por Estado",
    bills_per_capita = "📈 Legislação per Capita",
    document_types = "📝 Tipos de Documentos",
    authority_levels = "🏛️ Nível de Autoridade",
    transport_docs = "🚗 Legislação de Transporte",
    productivity = "⚡ Produtividade Legislativa",
    quality_index = "⭐ Índice de Qualidade",
    recent_activity = "🗓️ Atividade Recente",
    municipal_coverage = "🏙️ Cobertura Municipal",
    states = "Limites Estaduais",
    municipalities = "Limites Municipais",
    highways = "Rodovias Principais"
  )

  # Collect all active layer names
  active_layers <- c(selected_layers, reference_layers)
  for (layer in active_layers) {
    if (!is.null(layer_names[[layer]])) {
      overlay_groups <- c(overlay_groups, layer_names[[layer]])
    }
  }

  # Add layers control with base maps and overlays
  if (length(overlay_groups) > 0) {
    map <- map %>%
      addLayersControl(
        baseGroups = c("Base Map", "Satellite"),
        overlayGroups = overlay_groups,
        options = layersControlOptions(collapsed = FALSE),
        position = "topleft"
      )
  }

  return(map)
}


#' Add Data Layer to Map
#'
#' @param map Leaflet map object
#' @param layer_id Layer identifier
#' @param values Reactive values
#' @param db_connection Database connection
#' @return Updated map object
add_data_layer <- function(map, layer_id, values, db_connection) {

  layer_data <- NULL
  layer_name <- NULL
  color_palette <- "YlOrRd"
  metric_column <- NULL
  legend_title <- NULL

  tryCatch({
    # Calculate layer data based on layer_id
    if (layer_id == "population_density") {
      layer_data <- calculate_population_density_layer(db_connection)
      metric_column <- "population"
      layer_name <- "📊 População por Estado"
      legend_title <- "População"
      color_palette <- "YlGnBu"

    } else if (layer_id == "bills_per_capita") {
      layer_data <- calculate_population_density_layer(db_connection)
      metric_column <- "bills_per_100k"
      layer_name <- "📈 Legislação per Capita"
      legend_title <- "Leis por 100k habitantes"
      color_palette <- "YlOrRd"

    } else if (layer_id == "document_types") {
      layer_data <- calculate_document_type_layer(db_connection)
      # For document types, we'll show total count
      if (!is.null(layer_data)) {
        layer_data <- layer_data %>%
          group_by(state) %>%
          summarise(total_types = n_distinct(doc_type),
                   total_docs = sum(count),
                   .groups = "drop")
        metric_column <- "total_types"
        layer_name <- "📝 Tipos de Documentos"
        legend_title <- "Tipos de documentos únicos"
        color_palette <- "Set3"
      }

    } else if (layer_id == "authority_levels") {
      layer_data <- calculate_authority_level_layer(values$filtered_data)
      if (!is.null(layer_data)) {
        layer_data <- layer_data %>%
          group_by(estado) %>%
          summarise(authority_diversity = n_distinct(authority_level),
                   total = sum(count),
                   .groups = "drop") %>%
          rename(state = estado)
        metric_column <- "authority_diversity"
        layer_name <- "🏛️ Nível de Autoridade"
        legend_title <- "Diversidade de autoridade"
        color_palette <- "RdYlBu"
      }

    } else if (layer_id == "transport_docs") {
      layer_data <- calculate_transport_layer(db_connection)
      metric_column <- "transport_docs"
      layer_name <- "🚗 Legislação de Transporte"
      legend_title <- "Documentos de transporte"
      color_palette <- "Oranges"

    } else if (layer_id == "productivity") {
      layer_data <- calculate_productivity_layer(db_connection)
      metric_column <- "docs_per_year"
      layer_name <- "⚡ Produtividade Legislativa"
      legend_title <- "Documentos por ano"
      color_palette <- "Greens"

    } else if (layer_id == "quality_index") {
      layer_data <- calculate_quality_layer(values$filtered_data)
      metric_column <- "quality_index"
      layer_name <- "⭐ Índice de Qualidade"
      legend_title <- "Índice de qualidade (0-100)"
      color_palette <- "RdYlGn"

    } else if (layer_id == "recent_activity") {
      layer_data <- calculate_recent_activity_layer(db_connection)
      metric_column <- "recent_docs"
      layer_name <- "🗓️ Atividade Recente"
      legend_title <- "Documentos (últimos 5 anos)"
      color_palette <- "PuRd"

    } else if (layer_id == "municipal_coverage") {
      layer_data <- calculate_municipal_coverage_layer(db_connection)
      metric_column <- "municipalities_count"
      layer_name <- "🏙️ Cobertura Municipal"
      legend_title <- "Municípios com dados"
      color_palette <- "BuPu"
    }

    # Add choropleth layer if data was calculated
    if (!is.null(layer_data) && !is.null(metric_column) && !is.null(values$state_boundaries)) {
      map <- add_choropleth_layer(
        map = map,
        spatial_data = values$state_boundaries,
        metric_data = layer_data,
        metric_column = metric_column,
        layer_id = layer_id,
        layer_name = layer_name,
        color_palette = color_palette,
        legend_title = legend_title
      )
    } else {
      message("Warning: Could not add layer ", layer_id, " - missing data or boundaries")
    }

  }, error = function(e) {
    message("Error adding layer ", layer_id, ": ", e$message)
  })

  return(map)
}


#' Add Reference Layer (boundaries, highways, etc.)
#'
#' @param map Leaflet map object
#' @param layer_id Reference layer identifier
#' @param values Reactive values
#' @return Updated map object
add_reference_layer <- function(map, layer_id, values) {

  tryCatch({
    if (layer_id == "states" && !is.null(values$state_boundaries)) {
      # Add state boundaries as simple outline
      map <- map %>%
        addPolygons(
          data = values$state_boundaries,
          fillColor = "transparent",
          fillOpacity = 0,
          color = "#2C5F2D",
          weight = 2,
          opacity = 0.8,
          group = "Limites Estaduais",
          highlightOptions = highlightOptions(
            weight = 3,
            color = "#666666",
            bringToFront = FALSE
          ),
          label = ~properties$nome,
          labelOptions = labelOptions(
            style = list("font-weight" = "normal", padding = "3px 8px"),
            textsize = "13px",
            direction = "auto"
          )
        )

    } else if (layer_id == "municipalities") {
      # Municipal boundaries (if available)
      # This would require IBGE municipality shapefile data
      message("Municipal boundaries layer not yet implemented")

    } else if (layer_id == "highways") {
      # Highway network (if available)
      # This would require highway geospatial data
      message("Highways layer not yet implemented")
    }

  }, error = function(e) {
    message("Error adding reference layer ", layer_id, ": ", e$message)
  })

  return(map)
}
