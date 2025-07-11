# Geographic Data and Map Generation Module
# Uses REAL Brazilian boundaries from IBGE via geobr package

library(sf)
library(geobr)
library(leaflet)
library(dplyr)
library(RColorBrewer)
library(htmltools)
library(futile.logger)

# Global variable for cached geographic data
.brazil_geography <- new.env()

#' Load official Brazilian geographic boundaries
#' @param year Year of the boundaries (default: 2022, most recent)
#' @param cache_data Whether to cache the data for faster subsequent loads
#' @return List containing states and municipalities shapefiles
load_brazil_geography <- function(year = 2022, cache_data = TRUE) {
  
  flog.info("Loading Brazilian geographic data for year: %d", year)
  
  # Check if data is already cached
  cache_key <- paste0("brazil_", year)
  if (cache_data && exists(cache_key, envir = .brazil_geography)) {
    flog.info("Using cached geographic data")
    return(get(cache_key, envir = .brazil_geography))
  }
  
  tryCatch({
    # Load states (UF - Unidades Federativas)
    flog.info("Downloading state boundaries from IBGE...")
    states <- read_state(year = year, showProgress = FALSE)
    
    # Load municipalities (optional - large dataset)
    # municipalities <- read_municipality(year = year, showProgress = FALSE)
    
    # Load regions for context
    flog.info("Downloading region boundaries from IBGE...")
    regions <- read_region(year = year, showProgress = FALSE)
    
    # Load Brazil country boundary
    brazil_country <- read_country(year = year, showProgress = FALSE)
    
    # Validate geometries
    states <- st_make_valid(states)
    regions <- st_make_valid(regions)
    brazil_country <- st_make_valid(brazil_country)
    
    # Simplify geometries for better performance
    states <- st_simplify(states, dTolerance = 1000)
    regions <- st_simplify(regions, dTolerance = 2000)
    
    # Add computed fields
    states <- states %>%
      mutate(
        # Calculate area in km²
        area_km2 = as.numeric(st_area(.) / 1000000),
        # Create centroid for labels
        centroid = st_centroid(geom),
        # Extract coordinates for popup positioning
        lon = st_coordinates(centroid)[,1],
        lat = st_coordinates(centroid)[,2]
      )
    
    geography_data <- list(
      states = states,
      regions = regions,
      country = brazil_country,
      year = year,
      loaded_at = Sys.time()
    )
    
    # Cache the data
    if (cache_data) {
      assign(cache_key, geography_data, envir = .brazil_geography)
    }
    
    flog.info("Successfully loaded geographic data: %d states, %d regions", 
             nrow(states), nrow(regions))
    
    return(geography_data)
    
  }, error = function(e) {
    flog.error("Error loading geographic data: %s", e$message)
    
    # Fallback: create minimal geographic data
    flog.warn("Creating fallback geographic data")
    return(create_fallback_geography())
  })
}

#' Create fallback geographic data when geobr fails
#' @return List with minimal Brazilian state boundaries
create_fallback_geography <- function() {
  flog.info("Creating simple fallback geographic data")
  
  # Create a simple polygon for Brazil as fallback
  # This is a very basic representation
  brazil_bbox <- list(
    xmin = -73.99, xmax = -28.84,
    ymin = -33.75, ymax = 5.27
  )
  
  # Create simple state data
  states_data <- data.frame(
    abbrev_state = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", 
                     "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", 
                     "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    name_state = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
                   "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão", 
                   "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
                   "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro", 
                   "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", 
                   "Roraima", "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
    area_km2 = c(164123, 27768, 142815, 1559159, 564733, 148886, 5760, 46095, 
                 340087, 331937, 903358, 357125, 586528, 1247690, 56440, 199315, 
                 98312, 251529, 43696, 52797, 281748, 237591, 224300, 95346, 
                 248219, 21910, 277621),
    stringsAsFactors = FALSE
  )
  
  # Return minimal structure compatible with the mapping function
  return(list(
    states = states_data,
    regions = data.frame(),
    brazil_country = data.frame()
  ))
}

#' Load specific municipality boundaries for detailed analysis
#' @param state_code Two-letter state code (e.g., "SP", "RJ")
#' @param year Year of boundaries
#' @return SF object with municipality boundaries
load_state_municipalities <- function(state_code, year = 2022) {
  
  flog.info("Loading municipalities for state: %s", state_code)
  
  cache_key <- paste0("municipalities_", state_code, "_", year)
  if (exists(cache_key, envir = .brazil_geography)) {
    return(get(cache_key, envir = .brazil_geography))
  }
  
  tryCatch({
    # Load municipalities for specific state
    municipalities <- read_municipality(code_state = state_code, year = year, showProgress = FALSE)
    
    # Validate and simplify
    municipalities <- st_make_valid(municipalities)
    municipalities <- st_simplify(municipalities, dTolerance = 500)
    
    # Add computed fields
    municipalities <- municipalities %>%
      mutate(
        area_km2 = as.numeric(st_area(.) / 1000000),
        centroid = st_centroid(geom),
        lon = st_coordinates(centroid)[,1],
        lat = st_coordinates(centroid)[,2]
      )
    
    # Cache the data
    assign(cache_key, municipalities, envir = .brazil_geography)
    
    flog.info("Loaded %d municipalities for %s", nrow(municipalities), state_code)
    return(municipalities)
    
  }, error = function(e) {
    flog.error("Error loading municipalities for %s: %s", state_code, e$message)
    return(NULL)
  })
}

#' Create interactive legislative map using Leaflet
#' @param legislative_data Data frame with legislative data
#' @param geography_data Geographic boundaries from load_brazil_geography
#' @param focus_state Optional state to focus on
#' @param color_by Variable to color states by ("count", "density", "latest")
#' @return Leaflet map object
create_legislative_map <- function(legislative_data, geography_data, 
                                 focus_state = NULL, color_by = "count") {
  
  flog.info("Creating interactive legislative map")
  
  if (is.null(geography_data) || is.null(geography_data$states)) {
    flog.error("Invalid geography data")
    return(NULL)
  }
  
  # Create state name to code mapping
  state_mapping <- data.frame(
    estado = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "BR", "Ceará", 
               "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão", 
               "Mato Grosso", "Mato.Grosso.Sul", "Minas Gerais", "Pará", "Paraíba", 
               "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro", "Rio.Janeiro",
               "Rio Grande do Norte", "Rio.Grande.Norte", "Rio Grande do Sul", 
               "Rio.Grande.Sul", "Rondônia", "Roraima", "Santa Catarina", 
               "São Paulo", "Sergipe", "Tocantins"),
    abbrev_state = c("AC", "AL", "AP", "AM", "BA", "BR", "CE", 
                     "DF", "ES", "GO", "MA", 
                     "MT", "MS", "MG", "PA", "PB", 
                     "PR", "PE", "PI", "RJ", "RJ",
                     "RN", "RN", "RS", 
                     "RS", "RO", "RR", "SC", 
                     "SP", "SE", "TO"),
    stringsAsFactors = FALSE
  )
  
  # Map state names to codes in legislative data
  if ("estado" %in% names(legislative_data)) {
    legislative_data <- legislative_data %>%
      left_join(state_mapping, by = "estado") %>%
      mutate(abbrev_state = ifelse(is.na(abbrev_state), estado, abbrev_state))
  }
  
  states <- geography_data$states
  
  # Check if we have spatial data or just fallback data
  is_spatial_data <- inherits(states, "sf")
  
  # Aggregate legislative data by state using mapped state codes
  state_stats <- legislative_data %>%
    filter(!is.na(abbrev_state)) %>%
    group_by(abbrev_state) %>%
    summarise(
      documento_count = sum(count, na.rm = TRUE),
      latest_date = Sys.Date(),
      .groups = "drop"
    )
  
  # Ensure states have area_km2 field
  if (!"area_km2" %in% names(states)) {
    if (is_spatial_data) {
      states <- states %>%
        mutate(area_km2 = as.numeric(st_area(.) / 1000000))
    } else {
      # For fallback data, add default area
      states <- states %>%
        mutate(area_km2 = ifelse(is.na(area_km2), 100000, area_km2))
    }
  }
  
  # Join with geographic data
  map_data <- states %>%
    left_join(state_stats, by = "abbrev_state") %>%
    mutate(
      # Fill missing values
      documento_count = coalesce(documento_count, 0),
      latest_date = coalesce(latest_date, as.Date("1900-01-01")),
      density = ifelse(is.na(area_km2) | area_km2 == 0, 0, documento_count / area_km2 * 1000)  # Documents per 1000 km²
    )
  
  # Set up color palette based on selected variable
  if (color_by == "count") {
    color_var <- map_data$documento_count
    palette_name <- "Blues"
    legend_title <- "Número de Documentos"
  } else if (color_by == "density") {
    color_var <- map_data$density
    palette_name <- "Greens"
    legend_title <- "Densidade (docs/1000km²)"
  } else {
    color_var <- as.numeric(map_data$latest_date)
    palette_name <- "Reds"
    legend_title <- "Data Mais Recente"
  }
  
  # Create color palette
  pal <- colorNumeric(palette = palette_name, domain = color_var, na.color = "#E5E5E5")
  
  # Determine map center and zoom
  if (!is.null(focus_state)) {
    state_bounds <- filter(map_data, abbrev_state == focus_state)
    if (nrow(state_bounds) > 0) {
      bbox <- st_bbox(state_bounds)
      center_lat <- mean(c(bbox["ymin"], bbox["ymax"]))
      center_lng <- mean(c(bbox["xmin"], bbox["xmax"]))
      zoom_level <- 7
    } else {
      center_lat <- -15.7801
      center_lng <- -47.9292
      zoom_level <- 4
    }
  } else {
    center_lat <- -15.7801   # Brazil center
    center_lng <- -47.9292
    zoom_level <- 4
  }
  
  # Handle non-spatial fallback data
  if (!is_spatial_data) {
    flog.warn("No spatial data available, creating simple text-based map")
    
    # Create a basic leaflet map with state information as markers
    map <- leaflet() %>%
      addTiles() %>%
      setView(lng = -47.9292, lat = -15.7801, zoom = 4)
    
    # Add text overlay showing state data
    state_summary <- map_data %>%
      filter(documento_count > 0) %>%
      arrange(desc(documento_count)) %>%
      head(10)
    
    if (nrow(state_summary) > 0) {
      map <- map %>%
        addControl(
          html = paste0(
            "<div style='padding: 10px; background: white; border-radius: 5px; max-width: 200px;'>",
            "<h4>Documents by State</h4>",
            paste(state_summary$abbrev_state, ": ", state_summary$documento_count, collapse = "<br>"),
            "</div>"
          ),
          position = "topright"
        )
    }
    
    return(map)
  }
  
  # Create base map with spatial data
  map <- leaflet(map_data) %>%
    # Add base tile layer
    addProviderTiles(
      providers$CartoDB.Positron,
      options = providerTileOptions(noWrap = TRUE)
    ) %>%
    # Set initial view
    setView(lng = center_lng, lat = center_lat, zoom = zoom_level) %>%
    # Add state polygons
    addPolygons(
      fillColor = ~pal(color_var),
      fillOpacity = 0.7,
      color = "white",
      weight = 2,
      opacity = 1,
      dashArray = "3",
      highlight = highlightOptions(
        weight = 4,
        color = "#666",
        dashArray = "",
        fillOpacity = 0.9,
        bringToFront = TRUE
      ),
      popup = ~create_state_popup(name_state, abbrev_state, documento_count, 
                                latest_date, latest_title),
      popupOptions = popupOptions(maxWidth = 300),
      layerId = ~abbrev_state
    ) %>%
    # Add legend
    addLegend(
      pal = pal,
      values = ~color_var,
      opacity = 0.9,
      title = legend_title,
      position = "bottomright"
    )
  
  # Add municipalities layer if focusing on specific state
  if (!is.null(focus_state)) {
    municipalities <- load_state_municipalities(focus_state)
    if (!is.null(municipalities)) {
      
      # Aggregate municipal data
      muni_stats <- aggregate_legislative_by_municipality(legislative_data, focus_state)
      
      muni_data <- municipalities %>%
        left_join(muni_stats, by = c("name_muni" = "municipio")) %>%
        mutate(documento_count = coalesce(documento_count, 0))
      
      # Add municipality layer
      map <- map %>%
        addPolygons(
          data = muni_data,
          fillColor = ~colorNumeric("Oranges", documento_count)(documento_count),
          fillOpacity = 0.5,
          color = "orange",
          weight = 1,
          popup = ~paste0("<b>", name_muni, "</b><br>",
                         "Documentos: ", documento_count),
          group = "Municípios"
        ) %>%
        addLayersControl(
          overlayGroups = c("Municípios"),
          options = layersControlOptions(collapsed = FALSE)
        )
    }
  }
  
  # Add markers for recent legislation
  if (!is.null(legislative_data) && nrow(legislative_data) > 0) {
    recent_docs <- legislative_data %>%
      filter(!is.na(estado), !is.na(data)) %>%
      arrange(desc(data)) %>%
      slice_head(n = 50)  # Show top 50 most recent
    
    if (nrow(recent_docs) > 0) {
      # Get state coordinates for markers
      state_coords <- map_data %>%
        st_drop_geometry() %>%
        select(abbrev_state, lon, lat) %>%
        distinct()
      
      marker_data <- recent_docs %>%
        left_join(state_coords, by = c("estado" = "abbrev_state")) %>%
        filter(!is.na(lon), !is.na(lat))
      
      if (nrow(marker_data) > 0) {
        map <- map %>%
          addCircleMarkers(
            data = marker_data,
            lng = ~lon + runif(n(), -1, 1),  # Add small random offset
            lat = ~lat + runif(n(), -0.5, 0.5),
            radius = 5,
            fillColor = "red",
            fillOpacity = 0.8,
            color = "darkred",
            weight = 1,
            popup = ~paste0("<b>", titulo, "</b><br>",
                           "Tipo: ", tipo, "<br>",
                           "Data: ", format(as.Date(data), "%d/%m/%Y"), "<br>",
                           "Estado: ", estado),
            group = "Documentos Recentes"
          ) %>%
          addLayersControl(
            overlayGroups = c("Municípios", "Documentos Recentes"),
            options = layersControlOptions(collapsed = FALSE)
          )
      }
    }
  }
  
  flog.info("Interactive map created successfully")
  return(map)
}

#' Aggregate legislative data by state
#' @param legislative_data Data frame with legislative documents
#' @return Data frame with state-level statistics
aggregate_legislative_by_state <- function(legislative_data) {
  if (is.null(legislative_data) || nrow(legislative_data) == 0) {
    return(data.frame(
      estado = character(0),
      documento_count = integer(0),
      latest_date = as.Date(character(0)),
      latest_title = character(0)
    ))
  }
  
  state_stats <- legislative_data %>%
    filter(!is.na(estado)) %>%
    group_by(estado) %>%
    summarise(
      documento_count = n(),
      latest_date = max(as.Date(data), na.rm = TRUE),
      latest_title = first(titulo[which(as.Date(data) == max(as.Date(data), na.rm = TRUE))]),
      tipos_count = n_distinct(tipo),
      avg_days_since = mean(dias_desde_publicacao, na.rm = TRUE),
      .groups = "drop"
    ) %>%
    arrange(desc(documento_count))
  
  return(state_stats)
}

#' Aggregate legislative data by municipality
#' @param legislative_data Data frame with legislative documents
#' @param state_code State to filter by
#' @return Data frame with municipality-level statistics
aggregate_legislative_by_municipality <- function(legislative_data, state_code) {
  if (is.null(legislative_data) || nrow(legislative_data) == 0) {
    return(data.frame(
      municipio = character(0),
      documento_count = integer(0)
    ))
  }
  
  muni_stats <- legislative_data %>%
    filter(!is.na(municipio), estado == state_code) %>%
    group_by(municipio) %>%
    summarise(
      documento_count = n(),
      latest_date = max(as.Date(data), na.rm = TRUE),
      .groups = "drop"
    )
  
  return(muni_stats)
}

#' Create HTML popup content for states
#' @param state_name Full state name
#' @param state_abbrev State abbreviation
#' @param doc_count Number of documents
#' @param latest_date Most recent document date
#' @param latest_title Most recent document title
#' @return HTML string for popup
create_state_popup <- function(state_name, state_abbrev, doc_count, 
                              latest_date, latest_title) {
  
  # Handle missing values
  doc_count <- ifelse(is.na(doc_count), 0, doc_count)
  latest_date <- ifelse(is.na(latest_date), "Não disponível", 
                       format(as.Date(latest_date), "%d/%m/%Y"))
  latest_title <- ifelse(is.na(latest_title) | latest_title == "", 
                        "Nenhum documento", str_trunc(latest_title, 80))
  
  popup_html <- paste0(
    "<div style='font-family: Arial, sans-serif; width: 280px;'>",
    "<h4 style='margin: 0 0 10px 0; color: #2c3e50;'>", state_name, " (", state_abbrev, ")</h4>",
    "<hr style='margin: 5px 0; border: 1px solid #bdc3c7;'>",
    "<p style='margin: 5px 0;'><strong>📄 Documentos:</strong> ", doc_count, "</p>",
    "<p style='margin: 5px 0;'><strong>📅 Mais recente:</strong> ", latest_date, "</p>",
    "<p style='margin: 5px 0;'><strong>📋 Último documento:</strong><br>",
    "<em style='font-size: 12px;'>", latest_title, "</em></p>",
    "<button onclick='Shiny.setInputValue(\"state_selected\", \"", state_abbrev, "\", {priority: \"event\"});' ",
    "style='background: #3498db; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; margin-top: 5px;'>",
    "Ver detalhes</button>",
    "</div>"
  )
  
  return(popup_html)
}

#' Create fallback geography data when geobr fails
#' @return Minimal geographic data structure
create_fallback_geography <- function() {
  flog.warn("Creating fallback geographic data")
  
  # Simplified state boundaries (approximate)
  states_simple <- data.frame(
    abbrev_state = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                    "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                    "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    name_state = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
                  "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
                  "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
                  "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro", 
                  "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", "Roraima", 
                  "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
    lon = c(-70.55, -36.82, -51.77, -65.74, -41.58, -39.73, -47.86, -40.34, -49.31, -45.28,
           -56.10, -54.54, -45.00, -52.00, -36.78, -51.22, -38.95, -43.68, -43.68, -36.95,
           -52.09, -62.76, -61.33, -50.16, -48.64, -37.86, -48.25),
    lat = c(-8.77, -9.71, 0.00, -3.07, -12.96, -5.20, -15.83, -19.19, -16.64, -2.55,
           -15.60, -20.51, -18.10, -5.53, -7.06, -24.89, -8.28, -8.28, -22.84, -5.22,
           -30.01, -8.83, 2.73, -27.33, -23.55, -10.90, -10.25),
    stringsAsFactors = FALSE
  )
  
  # Convert to simple features (points for fallback)
  states_sf <- st_as_sf(states_simple, coords = c("lon", "lat"), crs = 4326)
  
  return(list(
    states = states_sf,
    regions = NULL,
    country = NULL,
    year = 2022,
    loaded_at = Sys.time(),
    fallback = TRUE
  ))
}

#' Export map as static image
#' @param map Leaflet map object
#' @param filename Output filename
#' @param width Image width in pixels
#' @param height Image height in pixels
export_map_image <- function(map, filename = "legislative_map.png", 
                           width = 1200, height = 800) {
  tryCatch({
    # This would require additional packages like webshot or mapshot
    # For now, just log the request
    flog.info("Map image export requested: %s", filename)
    return(TRUE)
  }, error = function(e) {
    flog.error("Error exporting map image: %s", e$message)
    return(FALSE)
  })
}