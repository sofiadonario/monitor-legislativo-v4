# Map-Based Search Functionality for Monitor Legislativo v4
# Interactive geographic search and spatial filtering capabilities

library(sf)
library(leaflet)
library(dplyr)
library(geojsonio)
library(htmltools)

# Map search configuration
MAP_SEARCH_CONFIG <- list(
  search_radius_km = c(5, 10, 25, 50, 100),
  default_search_radius = 25,
  max_search_results = 500,
  enable_drawing_tools = TRUE,
  enable_geocoding = TRUE,
  search_debounce_ms = 300
)

#' Initialize map-based search interface
#' @param map Leaflet map object
#' @param enable_drawing Enable drawing tools
#' @return Enhanced map with search capabilities
initialize_map_search <- function(map, enable_drawing = TRUE) {
  
  log_event("Initializing map-based search interface")
  
  # Add drawing tools if enabled
  if (enable_drawing) {
    map <- add_drawing_tools(map)
  }
  
  # Add search control
  map <- add_search_control(map)
  
  # Add location search
  map <- add_location_search(map)
  
  # Add radius search controls
  map <- add_radius_search_controls(map)
  
  log_event("Map search interface initialized")
  return(map)
}

#' Add drawing tools for spatial selection
#' @param map Leaflet map object
#' @return Map with drawing tools
add_drawing_tools <- function(map) {
  
  map %>%
    addDrawToolbar(
      targetGroup = "search_areas",
      polylineOptions = FALSE,
      circleOptions = drawCircleOptions(
        shapeOptions = drawShapeOptions(
          fillOpacity = 0.2,
          color = "#e74c3c",
          weight = 2
        )
      ),
      rectangleOptions = drawRectangleOptions(
        shapeOptions = drawShapeOptions(
          fillOpacity = 0.2,
          color = "#3498db",
          weight = 2
        )
      ),
      polygonOptions = drawPolygonOptions(
        shapeOptions = drawShapeOptions(
          fillOpacity = 0.2,
          color = "#2ecc71",
          weight = 2
        )
      ),
      markerOptions = drawMarkerOptions(),
      circleMarkerOptions = FALSE,
      singleFeature = TRUE,
      editOptions = editToolbarOptions(
        selectedPathOptions = selectedPathOptions()
      )
    )
}

#' Add search control widget
#' @param map Leaflet map object
#' @return Map with search control
add_search_control <- function(map) {
  
  search_control_html <- '
    <div class="map-search-control" style="
      background: white;
      padding: 10px;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      max-width: 300px;
      font-family: Arial, sans-serif;
    ">
      <h5 style="margin: 0 0 10px 0; color: #2c3e50;">🔍 Busca no Mapa</h5>
      
      <div style="margin-bottom: 10px;">
        <input type="text" id="map-location-search" placeholder="Digite um local..." 
               style="width: 100%; padding: 5px; border: 1px solid #ddd; border-radius: 4px;" />
      </div>
      
      <div style="margin-bottom: 10px;">
        <label style="font-size: 12px; color: #666;">Raio de busca:</label>
        <select id="map-search-radius" style="width: 100%; padding: 3px;">
          <option value="5">5 km</option>
          <option value="10">10 km</option>
          <option value="25" selected>25 km</option>
          <option value="50">50 km</option>
          <option value="100">100 km</option>
        </select>
      </div>
      
      <div style="text-align: center;">
        <button id="map-search-clear" style="
          padding: 5px 10px; 
          background: #e74c3c; 
          color: white; 
          border: none; 
          border-radius: 4px; 
          cursor: pointer;
          font-size: 12px;
        ">Limpar Seleção</button>
      </div>
    </div>
  '
  
  map %>%
    addControl(
      html = search_control_html,
      position = "topright",
      className = "map-search-widget"
    )
}

#' Add location search functionality
#' @param map Leaflet map object
#' @return Map with location search
add_location_search <- function(map) {
  
  # Add geocoding search plugin
  map %>%
    addSearchOSM(
      options = searchOptions(
        collapsed = FALSE,
        autoCollapse = TRUE,
        position = "topleft",
        zoom = 10,
        textPlaceholder = "Buscar localização...",
        textErr = "Local não encontrado",
        textCancel = "Cancelar",
        textNoResults = "Nenhum resultado"
      )
    )
}

#' Add radius search controls
#' @param map Leaflet map object
#' @return Map with radius controls
add_radius_search_controls <- function(map) {
  
  # This will be handled by JavaScript interaction in the Shiny app
  # The controls are added in add_search_control function
  return(map)
}

#' Perform spatial search based on drawn geometry
#' @param legislative_data Legislative documents data
#' @param search_geometry Spatial geometry (from map drawing)
#' @param geo_data Geographic boundaries data
#' @return Filtered documents within the search area
search_by_geometry <- function(legislative_data, search_geometry, geo_data) {
  
  if (is.null(legislative_data) || nrow(legislative_data) == 0) {
    log_event("No legislative data for spatial search", "WARN")
    return(data.frame())
  }
  
  if (is.null(search_geometry)) {
    log_event("No search geometry provided", "WARN")
    return(legislative_data)
  }
  
  log_event("Performing spatial search by geometry")
  
  tryCatch({
    
    # Convert search geometry to sf object if needed
    if (!inherits(search_geometry, "sf")) {
      search_geom <- process_search_geometry(search_geometry)
    } else {
      search_geom <- search_geometry
    }
    
    if (is.null(search_geom)) {
      log_event("Failed to process search geometry", "ERROR")
      return(legislative_data)
    }
    
    # Create spatial points from documents
    doc_points <- create_document_spatial_points(legislative_data, geo_data)
    
    if (is.null(doc_points) || nrow(doc_points) == 0) {
      log_event("No valid document points for spatial search", "WARN")
      return(data.frame())
    }
    
    # Ensure same CRS
    doc_points <- st_transform(doc_points, st_crs(search_geom))
    
    # Perform spatial intersection
    intersected_points <- st_intersection(doc_points, search_geom)
    
    if (nrow(intersected_points) == 0) {
      log_event("No documents found within search geometry")
      return(data.frame())
    }
    
    # Return filtered documents
    filtered_docs <- legislative_data[
      legislative_data$titulo %in% intersected_points$titulo, 
    ]
    
    log_event(paste("Spatial search completed:", nrow(filtered_docs), "documents found"))
    
    return(filtered_docs)
    
  }, error = function(e) {
    log_event(paste("Error in spatial search:", e$message), "ERROR")
    return(legislative_data)
  })
}

#' Search by circular radius around a point
#' @param legislative_data Legislative documents
#' @param center_lat Center latitude
#' @param center_lng Center longitude  
#' @param radius_km Radius in kilometers
#' @param geo_data Geographic boundaries
#' @return Filtered documents within radius
search_by_radius <- function(legislative_data, center_lat, center_lng, radius_km, geo_data) {
  
  if (is.null(legislative_data) || nrow(legislative_data) == 0) {
    return(data.frame())
  }
  
  log_event(paste("Performing radius search:", radius_km, "km around", center_lat, center_lng))
  
  tryCatch({
    
    # Create center point
    center_point <- st_point(c(center_lng, center_lat)) %>%
      st_sfc(crs = 4326) %>%
      st_sf()
    
    # Create buffer around center point
    search_buffer <- center_point %>%
      st_transform(3857) %>%  # Web Mercator for accurate buffer
      st_buffer(dist = radius_km * 1000) %>%  # Convert km to meters
      st_transform(4326)  # Back to WGS84
    
    # Use geometry search
    filtered_docs <- search_by_geometry(legislative_data, search_buffer, geo_data)
    
    # Add distance information
    if (nrow(filtered_docs) > 0) {
      doc_points <- create_document_spatial_points(filtered_docs, geo_data)
      
      if (!is.null(doc_points)) {
        distances <- st_distance(
          st_transform(doc_points, 3857),
          st_transform(center_point, 3857)
        )
        
        filtered_docs$distance_km <- round(as.numeric(distances) / 1000, 2)
        filtered_docs <- filtered_docs %>% arrange(distance_km)
      }
    }
    
    log_event(paste("Radius search completed:", nrow(filtered_docs), "documents found"))
    
    return(filtered_docs)
    
  }, error = function(e) {
    log_event(paste("Error in radius search:", e$message), "ERROR")
    return(data.frame())
  })
}

#' Search by administrative boundary (state/municipality)
#' @param legislative_data Legislative documents
#' @param boundary_name Name of boundary (state or municipality)
#' @param boundary_type Type of boundary ("state", "municipality")
#' @param geo_data Geographic boundaries
#' @return Filtered documents within boundary
search_by_boundary <- function(legislative_data, boundary_name, boundary_type = "state", geo_data) {
  
  if (is.null(legislative_data) || nrow(legislative_data) == 0) {
    return(data.frame())
  }
  
  log_event(paste("Performing boundary search:", boundary_type, "-", boundary_name))
  
  tryCatch({
    
    # Find the boundary geometry
    boundary_geom <- find_boundary_geometry(boundary_name, boundary_type, geo_data)
    
    if (is.null(boundary_geom)) {
      log_event(paste("Boundary not found:", boundary_name), "WARN")
      return(data.frame())
    }
    
    # Use geometry search
    filtered_docs <- search_by_geometry(legislative_data, boundary_geom, geo_data)
    
    log_event(paste("Boundary search completed:", nrow(filtered_docs), "documents found"))
    
    return(filtered_docs)
    
  }, error = function(e) {
    log_event(paste("Error in boundary search:", e$message), "ERROR")
    return(data.frame())
  })
}

#' Find boundary geometry by name
#' @param boundary_name Name of boundary
#' @param boundary_type Type of boundary
#' @param geo_data Geographic data
#' @return SF geometry object
find_boundary_geometry <- function(boundary_name, boundary_type, geo_data) {
  
  if (is.null(geo_data) || nrow(geo_data) == 0) {
    return(NULL)
  }
  
  # Search for boundary by name
  if (boundary_type == "state") {
    # Try matching state name or abbreviation
    matches <- geo_data %>%
      filter(
        str_detect(str_to_lower(name_state %||% ""), str_to_lower(boundary_name)) |
        str_detect(str_to_lower(abbrev_state %||% ""), str_to_lower(boundary_name))
      )
  } else if (boundary_type == "municipality") {
    # Try matching municipality name
    matches <- geo_data %>%
      filter(str_detect(str_to_lower(name_muni %||% ""), str_to_lower(boundary_name)))
  } else {
    return(NULL)
  }
  
  if (nrow(matches) == 0) {
    return(NULL)
  }
  
  # Return first match geometry
  return(matches[1, ])
}

#' Process search geometry from map drawing
#' @param geometry_data Geometry data from map
#' @return Processed SF geometry
process_search_geometry <- function(geometry_data) {
  
  tryCatch({
    
    # If it's GeoJSON, convert to sf
    if (is.character(geometry_data)) {
      geom_sf <- geojsonio::geojson_sf(geometry_data)
    } else if (is.list(geometry_data)) {
      # Convert list to GeoJSON then to sf
      geojson_str <- geojsonio::geojson_json(geometry_data)
      geom_sf <- geojsonio::geojson_sf(geojson_str)
    } else {
      return(NULL)
    }
    
    # Ensure valid CRS
    if (is.null(st_crs(geom_sf))) {
      geom_sf <- st_set_crs(geom_sf, 4326)
    }
    
    return(geom_sf)
    
  }, error = function(e) {
    log_event(paste("Error processing search geometry:", e$message), "ERROR")
    return(NULL)
  })
}

#' Create search summary statistics
#' @param original_data Original document data
#' @param filtered_data Filtered document data
#' @param search_type Type of search performed
#' @param search_params Search parameters
#' @return Search summary list
create_search_summary <- function(original_data, filtered_data, search_type, search_params = list()) {
  
  original_count <- if (is.null(original_data)) 0 else nrow(original_data)
  filtered_count <- if (is.null(filtered_data)) 0 else nrow(filtered_data)
  
  summary_stats <- list(
    search_type = search_type,
    search_params = search_params,
    original_count = original_count,
    filtered_count = filtered_count,
    reduction_percentage = if (original_count > 0) {
      round((1 - filtered_count / original_count) * 100, 1)
    } else 0,
    search_timestamp = Sys.time()
  )
  
  # Add type-specific statistics
  if (search_type == "radius" && !is.null(filtered_data) && nrow(filtered_data) > 0) {
    if ("distance_km" %in% names(filtered_data)) {
      summary_stats$distance_stats <- list(
        min_distance = min(filtered_data$distance_km, na.rm = TRUE),
        max_distance = max(filtered_data$distance_km, na.rm = TRUE),
        avg_distance = round(mean(filtered_data$distance_km, na.rm = TRUE), 2)
      )
    }
  }
  
  if (!is.null(filtered_data) && nrow(filtered_data) > 0) {
    # Document type distribution
    if ("tipo" %in% names(filtered_data)) {
      summary_stats$type_distribution <- filtered_data %>%
        count(tipo, sort = TRUE) %>%
        slice_head(n = 5)
    }
    
    # Date range
    if ("data" %in% names(filtered_data)) {
      valid_dates <- as.Date(filtered_data$data[!is.na(filtered_data$data)])
      if (length(valid_dates) > 0) {
        summary_stats$date_range <- list(
          earliest = min(valid_dates),
          latest = max(valid_dates),
          span_years = round(as.numeric(max(valid_dates) - min(valid_dates)) / 365, 1)
        )
      }
    }
    
    # Quality statistics
    if ("quality_score" %in% names(filtered_data)) {
      summary_stats$quality_stats <- list(
        avg_quality = round(mean(filtered_data$quality_score, na.rm = TRUE), 1),
        high_quality_count = sum(filtered_data$quality_score >= 80, na.rm = TRUE)
      )
    }
  }
  
  return(summary_stats)
}

#' Geocode address or location name
#' @param location Location string to geocode
#' @return List with coordinates and details
geocode_location <- function(location) {
  
  if (is.null(location) || nchar(str_trim(location)) == 0) {
    return(NULL)
  }
  
  log_event(paste("Geocoding location:", location))
  
  tryCatch({
    
    # Simple Brazilian cities geocoding (fallback approach)
    brazilian_cities <- get_major_brazilian_cities()
    
    # Try to match the location
    location_lower <- str_to_lower(str_trim(location))
    
    matches <- brazilian_cities %>%
      filter(
        str_detect(str_to_lower(city), location_lower) |
        str_detect(str_to_lower(state), location_lower) |
        str_detect(str_to_lower(full_name), location_lower)
      )
    
    if (nrow(matches) > 0) {
      best_match <- matches[1, ]
      
      result <- list(
        success = TRUE,
        lat = best_match$lat,
        lng = best_match$lng,
        display_name = best_match$full_name,
        city = best_match$city,
        state = best_match$state,
        confidence = 0.8
      )
      
      log_event(paste("Geocoding successful:", result$display_name))
      return(result)
    }
    
    # If no match found
    log_event(paste("No geocoding match found for:", location), "WARN")
    return(list(
      success = FALSE,
      message = "Localização não encontrada"
    ))
    
  }, error = function(e) {
    log_event(paste("Geocoding error:", e$message), "ERROR")
    return(list(
      success = FALSE,
      message = "Erro na busca de localização"
    ))
  })
}

#' Get major Brazilian cities with coordinates
#' @return Data frame with city information
get_major_brazilian_cities <- function() {
  
  data.frame(
    city = c(
      "São Paulo", "Rio de Janeiro", "Salvador", "Brasília", "Fortaleza",
      "Belo Horizonte", "Manaus", "Curitiba", "Recife", "Porto Alegre",
      "Goiânia", "Belém", "Guarulhos", "Campinas", "São Luís",
      "São Gonçalo", "Maceió", "Duque de Caxias", "Natal", "Teresina",
      "São Bernardo do Campo", "Nova Iguaçu", "João Pessoa", "Santo André",
      "Osasco", "São José dos Campos", "Jaboatão dos Guararapes", "Ribeirão Preto",
      "Uberlândia", "Sorocaba", "Contagem", "Aracaju", "Feira de Santana",
      "Cuiabá", "Joinville", "Aparecida de Goiânia", "Londrina", "Ananindeua",
      "Porto Velho", "Serra", "Niterói", "Caxias do Sul", "Macapá",
      "Mogi das Cruzes", "Campos dos Goytacazes", "São João de Meriti",
      "Florianópolis", "Vila Velha", "Mauá", "Carapicuíba"
    ),
    state = c(
      "SP", "RJ", "BA", "DF", "CE", "MG", "AM", "PR", "PE", "RS",
      "GO", "PA", "SP", "SP", "MA", "RJ", "AL", "RJ", "RN", "PI",
      "SP", "RJ", "PB", "SP", "SP", "SP", "PE", "SP", "MG", "SP",
      "MG", "SE", "BA", "MT", "SC", "GO", "PR", "PA", "RO", "ES",
      "RJ", "RS", "AP", "SP", "RJ", "RJ", "SC", "ES", "SP", "SP"
    ),
    lat = c(
      -23.5505, -22.9068, -12.9714, -15.8267, -3.7319,
      -19.9167, -3.1190, -25.4244, -8.0476, -30.0346,
      -16.6869, -1.4558, -23.4628, -22.9099, -2.5297,
      -22.8305, -9.6658, -22.7858, -5.7945, -5.0892,
      -23.6914, -22.7587, -7.1195, -23.6586, -23.5320,
      -23.2237, -8.1137, -21.1775, -18.9113, -23.5015,
      -19.9312, -10.9472, -12.2577, -15.6014, -26.3045,
      -16.8173, -23.3045, -1.4432, -8.7619, -20.3155,
      -22.8833, -29.1678, 0.0389, -23.5222, -21.7624,
      -22.8008, -27.5954, -20.3430, -23.6680, -23.5226
    ),
    lng = c(
      -46.6333, -43.1729, -38.5014, -47.9218, -38.5267,
      -43.9345, -60.0217, -49.2654, -34.8770, -51.2177,
      -49.2643, -48.5044, -46.5333, -47.0616, -44.3028,
      -43.0389, -35.7353, -43.3054, -35.2094, -42.8016,
      -46.5646, -43.4516, -34.8450, -46.5386, -46.7916,
      -45.8825, -35.0120, -47.8208, -48.2622, -47.4526,
      -44.0537, -37.0721, -38.9662, -56.0979, -48.8448,
      -49.2445, -51.1696, -48.3719, -63.8999, -40.2976,
      -43.1036, -51.1591, -51.0694, -46.6180, -41.3006,
      -43.3774, -48.5480, -40.3119, -46.4614, -46.8754
    ),
    stringsAsFactors = FALSE
  ) %>%
    mutate(
      full_name = paste(city, "-", state)
    )
}

#' Create interactive search result display
#' @param search_results Filtered search results
#' @param search_summary Search summary statistics
#' @return HTML content for search results
create_search_result_display <- function(search_results, search_summary) {
  
  if (is.null(search_results) || nrow(search_results) == 0) {
    return(tags$div(
      class = "search-no-results",
      style = "text-align: center; padding: 20px; color: #666;",
      tags$h4("Nenhum documento encontrado"),
      tags$p("Tente expandir a área de busca ou alterar os critérios.")
    ))
  }
  
  # Create summary header
  summary_html <- tags$div(
    class = "search-summary",
    style = "background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 15px;",
    
    tags$h5("📍 Resultado da Busca Geográfica", style = "margin: 0 0 10px 0; color: #2c3e50;"),
    
    tags$div(
      style = "display: flex; justify-content: space-between; align-items: center;",
      
      tags$div(
        tags$strong("Documentos encontrados: "), 
        tags$span(style = "color: #e74c3c; font-weight: bold;", search_summary$filtered_count),
        if (search_summary$original_count > 0) {
          tags$span(
            style = "color: #7f8c8d; margin-left: 10px;",
            paste0("(", search_summary$reduction_percentage, "% dos ", search_summary$original_count, " documentos)")
          )
        }
      ),
      
      if (!is.null(search_summary$distance_stats)) {
        tags$div(
          style = "font-size: 0.9em; color: #666;",
          paste0("Distância: ", search_summary$distance_stats$min_distance, "-", 
                search_summary$distance_stats$max_distance, " km")
        )
      }
    )
  )
  
  return(summary_html)
}

#' Clear map search selections
#' @param map_proxy Leaflet map proxy
#' @return Updated map proxy
clear_map_search <- function(map_proxy) {
  
  map_proxy %>%
    clearGroup("search_areas") %>%
    clearGroup("search_results") %>%
    clearGroup("search_radius")
}

#' Add search result highlights to map
#' @param map_proxy Leaflet map proxy
#' @param search_results Filtered documents
#' @param geo_data Geographic data
#' @return Updated map with highlighted results
highlight_search_results_on_map <- function(map_proxy, search_results, geo_data) {
  
  if (is.null(search_results) || nrow(search_results) == 0) {
    return(map_proxy)
  }
  
  # Create highlighted markers for search results
  marker_data <- create_document_markers(search_results, geo_data)
  
  if (!is.null(marker_data) && nrow(marker_data) > 0) {
    
    # Add highlighted markers
    map_proxy %>%
      addCircleMarkers(
        data = marker_data,
        lng = ~lng_jitter,
        lat = ~lat_jitter,
        radius = 8,
        fillColor = "#e74c3c",
        color = "#c0392b",
        weight = 2,
        opacity = 1,
        fillOpacity = 0.8,
        popup = ~create_document_popup(marker_data),
        group = "search_results"
      )
  }
  
  return(map_proxy)
}

#' Export map search results
#' @param search_results Filtered documents
#' @param search_summary Search summary
#' @param format Export format ("csv", "geojson", "kml")
#' @return File path or data for download
export_map_search_results <- function(search_results, search_summary, format = "csv") {
  
  if (is.null(search_results) || nrow(search_results) == 0) {
    return(NULL)
  }
  
  tryCatch({
    
    # Add search metadata to results
    enhanced_results <- search_results %>%
      mutate(
        search_type = search_summary$search_type,
        search_timestamp = search_summary$search_timestamp,
        exported_at = Sys.time()
      )
    
    if (format == "csv") {
      # Standard CSV export
      temp_file <- tempfile(fileext = ".csv")
      write.csv(enhanced_results, temp_file, row.names = FALSE)
      return(temp_file)
      
    } else if (format == "geojson") {
      # GeoJSON export with coordinates
      # This would require spatial point creation
      temp_file <- tempfile(fileext = ".geojson")
      # Implementation would create GeoJSON with document locations
      return(temp_file)
      
    } else if (format == "kml") {
      # KML export for Google Earth
      temp_file <- tempfile(fileext = ".kml")
      # Implementation would create KML with document locations
      return(temp_file)
    }
    
    return(NULL)
    
  }, error = function(e) {
    log_event(paste("Error exporting search results:", e$message), "ERROR")
    return(NULL)
  })
}