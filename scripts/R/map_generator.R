# Geographic Data and Map Generation Module
# Uses REAL Brazilian boundaries from IBGE via geobr package
# Enhanced with multi-layer support for LexML data

library(sf)
library(geobr)
library(leaflet)
library(dplyr)
library(RColorBrewer)
library(htmltools)
library(futile.logger)
library(stringr)

# Load LexML geographic analytics
source("scripts/R/lexml_geographic_analytics.R")

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
    
    # Load municipalities for top states (to keep dataset manageable)
    # We'll load municipalities on-demand for states with significant document counts
    
    # Load regions for context
    flog.info("Downloading region boundaries from IBGE...")
    regions <- read_region(year = year, showProgress = FALSE)
    
    # Load Brazil country boundary
    brazil_country <- read_country(year = year, showProgress = FALSE)
    
    # Validate geometries and ensure consistent CRS
    states <- st_make_valid(states)
    regions <- st_make_valid(regions)
    brazil_country <- st_make_valid(brazil_country)
    
    # Transform to WGS84 for consistency
    states <- st_transform(states, crs = 4326)
    regions <- st_transform(regions, crs = 4326)
    brazil_country <- st_transform(brazil_country, crs = 4326)
    
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
  
  # Simple state mapping - use estado_codigo from database if available, otherwise map estado
  if ("estado_codigo" %in% names(legislative_data)) {
    # Use the standardized state codes from database
    legislative_data <- legislative_data %>%
      mutate(abbrev_state = coalesce(estado_codigo, estado))
  } else if ("estado" %in% names(legislative_data)) {
    # Simple mapping for standardized state names
    legislative_data <- legislative_data %>%
      mutate(abbrev_state = case_when(
        estado == "Acre" ~ "AC",
        estado == "Alagoas" ~ "AL", 
        estado == "Amapá" ~ "AP",
        estado == "Amazonas" ~ "AM",
        estado == "Bahia" ~ "BA",
        estado == "Ceará" ~ "CE",
        estado == "Distrito Federal" ~ "DF",
        estado == "Espírito Santo" ~ "ES",
        estado == "Goiás" ~ "GO",
        estado == "Maranhão" ~ "MA",
        estado == "Mato Grosso" ~ "MT",
        estado == "Mato Grosso do Sul" ~ "MS",
        estado == "Minas Gerais" ~ "MG",
        estado == "Pará" ~ "PA",
        estado == "Paraíba" ~ "PB",
        estado == "Paraná" ~ "PR",
        estado == "Pernambuco" ~ "PE",
        estado == "Piauí" ~ "PI",
        estado == "Rio de Janeiro" ~ "RJ",
        estado == "Rio Grande do Norte" ~ "RN",
        estado == "Rio Grande do Sul" ~ "RS",
        estado == "Rondônia" ~ "RO",
        estado == "Roraima" ~ "RR",
        estado == "Santa Catarina" ~ "SC",
        estado == "São Paulo" ~ "SP",
        estado == "Sergipe" ~ "SE",
        estado == "Tocantins" ~ "TO",
        estado %in% c("Federal", "Brasil", "BR") ~ "BR",
        TRUE ~ estado  # Keep original if no match
      ))
  }
  
  states <- geography_data$states
  
  # Check if we have spatial data or just fallback data
  is_spatial_data <- inherits(states, "sf")
  
  # Aggregate legislative data by state using mapped state codes
  # Handle different data structures
  if ("count" %in% names(legislative_data)) {
    # Data from database analytics (has count field)
    state_stats <- legislative_data %>%
      filter(!is.na(abbrev_state)) %>%
      group_by(abbrev_state) %>%
      summarise(
        documento_count = sum(count, na.rm = TRUE),
        latest_date = Sys.Date(),
        latest_title = "Legislative Document",
        tipos_count = 1,
        avg_days_since = 0,
        .groups = "drop"
      )
  } else if ("documento_count" %in% names(legislative_data)) {
    # Data already processed
    state_stats <- legislative_data %>%
      filter(!is.na(abbrev_state)) %>%
      select(abbrev_state, documento_count) %>%
      mutate(
        latest_date = Sys.Date(),
        latest_title = "Legislative Document",
        tipos_count = 1,
        avg_days_since = 0
      )
  } else {
    # Create empty data with proper structure
    state_stats <- data.frame(
      abbrev_state = character(0),
      documento_count = integer(0),
      latest_date = as.Date(character(0)),
      latest_title = character(0),
      tipos_count = integer(0),
      avg_days_since = numeric(0),
      stringsAsFactors = FALSE
    )
  }
  
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
    # Use custom red palette matching the app theme
    legend_title <- "Número de Documentos"
  } else if (color_by == "density") {
    color_var <- map_data$density
    legend_title <- "Densidade (docs/1000km²)"
  } else {
    color_var <- as.numeric(map_data$latest_date)
    legend_title <- "Data Mais Recente"
  }
  
  # Create custom red color palette matching the app theme (#e1001e)
  # Create a gradient from light pink to deep red
  red_colors <- c("#fff0f0", "#ffd4d4", "#ffb3b3", "#ff8080", "#ff4d4d", "#e1001e", "#c50019", "#a80016", "#8b0013")
  pal <- colorNumeric(palette = red_colors, domain = color_var, na.color = "#E5E5E5")
  
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
  
  # Add municipalities layer for states with significant document counts
  # First, check if we're focusing on a specific state
  if (!is.null(focus_state)) {
    municipalities <- load_state_municipalities(focus_state)
    if (!is.null(municipalities)) {
      
      # Aggregate municipal data
      muni_stats <- aggregate_legislative_by_municipality(legislative_data, focus_state)
      
      muni_data <- municipalities %>%
        left_join(muni_stats, by = c("name_muni" = "municipio")) %>%
        mutate(documento_count = coalesce(documento_count, 0))
      
      # Add municipality layer with red color scheme
      # Create a lighter red palette for municipalities
      muni_red_colors <- c("#ffe6e6", "#ffcccc", "#ffb3b3", "#ff9999", "#ff8080", "#ff6666", "#ff4d4d")
      muni_pal <- colorNumeric(palette = muni_red_colors, domain = muni_data$documento_count)
      
      map <- map %>%
        addPolygons(
          data = muni_data,
          fillColor = ~muni_pal(documento_count),
          fillOpacity = 0.5,
          color = "#e1001e",
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
  } else if (!is.null(legislative_data) && nrow(legislative_data) > 0) {
    # Auto-load municipalities for top 2 states with most documents (for overview map)
    tryCatch({
      if ("count" %in% names(legislative_data)) {
        top_states <- legislative_data %>%
          arrange(desc(count)) %>%
          head(2) %>%
          pull(estado)
      } else {
        state_counts <- legislative_data %>%
          group_by(estado) %>%
          summarise(count = n(), .groups = "drop") %>%
          arrange(desc(count)) %>%
          head(2)
        top_states <- state_counts$estado
      }
      
      # Load municipalities for top states
      all_muni_layers <- list()
      for (state in top_states) {
        if (!is.null(state) && !is.na(state) && nchar(state) > 0) {
          municipalities <- load_state_municipalities(state)
          if (!is.null(municipalities)) {
            muni_stats <- aggregate_legislative_by_municipality(legislative_data, state)
            
            muni_data <- municipalities %>%
              left_join(muni_stats, by = c("name_muni" = "municipio")) %>%
              mutate(
                documento_count = coalesce(documento_count, 0),
                state_code = state
              )
            
            if (nrow(muni_data) > 0) {
              all_muni_layers[[state]] <- muni_data
            }
          }
        }
      }
      
      # Add all municipality layers to the map
      if (length(all_muni_layers) > 0) {
        combined_muni_data <- bind_rows(all_muni_layers)
        
        if (nrow(combined_muni_data) > 0) {
          # Create a lighter red palette for municipalities
          muni_red_colors <- c("#ffe6e6", "#ffcccc", "#ffb3b3", "#ff9999", "#ff8080", "#ff6666", "#ff4d4d")
          muni_pal <- colorNumeric(palette = muni_red_colors, domain = combined_muni_data$documento_count)
          
          map <- map %>%
            addPolygons(
              data = combined_muni_data,
              fillColor = ~muni_pal(documento_count),
              fillOpacity = 0.3,
              color = "#e1001e",
              weight = 0.5,
              popup = ~paste0("<b>", name_muni, "</b><br>",
                             "Estado: ", state_code, "<br>",
                             "Documentos: ", documento_count),
              group = "Municípios (Top States)"
            ) %>%
            addLayersControl(
              overlayGroups = c("Municípios (Top States)"),
              options = layersControlOptions(collapsed = FALSE)
            )
        }
      }
    }, error = function(e) {
      flog.warn("Could not load municipalities for overview: %s", e$message)
    })
  }
  
  # Add markers for recent legislation
  if (!is.null(legislative_data) && nrow(legislative_data) > 0) {
    # Handle different date column names
    date_col <- if ("data_publicacao" %in% names(legislative_data)) {
      "data_publicacao"
    } else if ("data" %in% names(legislative_data)) {
      "data"
    } else {
      NULL
    }
    
    if (!is.null(date_col) && "estado" %in% names(legislative_data)) {
      recent_docs <- legislative_data %>%
        filter(!is.na(estado), !is.na(.data[[date_col]])) %>%
        arrange(desc(.data[[date_col]])) %>%
        slice_head(n = 50)  # Show top 50 most recent
    } else {
      recent_docs <- data.frame()
    }
    
    if (nrow(recent_docs) > 0) {
      # Get state coordinates for markers
      if (is_spatial_data) {
        state_coords <- map_data %>%
          st_drop_geometry() %>%
          select(abbrev_state, lon, lat) %>%
          distinct()
        
        marker_data <- recent_docs %>%
          left_join(state_coords, by = c("estado" = "abbrev_state")) %>%
          filter(!is.na(lon), !is.na(lat))
        
        if (nrow(marker_data) > 0) {
          # Create popup content safely
          popup_content <- paste0(
            "<b>", ifelse(is.na(marker_data$titulo), "Document", marker_data$titulo), "</b><br>",
            "Tipo: ", ifelse(is.na(marker_data$tipo), "N/A", marker_data$tipo), "<br>",
            "Data: ", format(as.Date(marker_data[[date_col]]), "%d/%m/%Y"), "<br>",
            "Estado: ", marker_data$estado
          )
          
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
              popup = popup_content,
              group = "Documentos Recentes"
            ) %>%
            addLayersControl(
              overlayGroups = c("Municípios", "Municípios (Top States)", "Documentos Recentes"),
              options = layersControlOptions(collapsed = FALSE)
            )
        }
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
  
  # Handle different date column names safely
  date_col <- if ("data_publicacao" %in% names(legislative_data)) {
    "data_publicacao"
  } else if ("data" %in% names(legislative_data)) {
    "data"
  } else {
    NULL
  }
  
  if (!is.null(date_col)) {
    state_stats <- legislative_data %>%
      filter(!is.na(estado)) %>%
      group_by(estado) %>%
      summarise(
        documento_count = n(),
        latest_date = max(as.Date(.data[[date_col]]), na.rm = TRUE),
        latest_title = first(titulo[which(as.Date(.data[[date_col]]) == max(as.Date(.data[[date_col]]), na.rm = TRUE))]),
        tipos_count = n_distinct(tipo),
        avg_days_since = if("dias_desde_publicacao" %in% names(legislative_data)) mean(dias_desde_publicacao, na.rm = TRUE) else 0,
        .groups = "drop"
      ) %>%
      arrange(desc(documento_count))
  } else {
    state_stats <- legislative_data %>%
      filter(!is.na(estado)) %>%
      group_by(estado) %>%
      summarise(
        documento_count = n(),
        latest_date = Sys.Date(),
        latest_title = first(titulo),
        tipos_count = n_distinct(tipo),
        avg_days_since = 0,
        .groups = "drop"
      ) %>%
      arrange(desc(documento_count))
  }
  
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
  
  # Handle different date column names safely
  date_col <- if ("data_publicacao" %in% names(legislative_data)) {
    "data_publicacao"
  } else if ("data" %in% names(legislative_data)) {
    "data"
  } else {
    NULL
  }
  
  if (!is.null(date_col)) {
    muni_stats <- legislative_data %>%
      filter(!is.na(municipio), estado == state_code) %>%
      group_by(municipio) %>%
      summarise(
        documento_count = n(),
        latest_date = max(as.Date(.data[[date_col]]), na.rm = TRUE),
        .groups = "drop"
      )
  } else {
    muni_stats <- legislative_data %>%
      filter(!is.na(municipio), estado == state_code) %>%
      group_by(municipio) %>%
      summarise(
        documento_count = n(),
        latest_date = Sys.Date(),
        .groups = "drop"
      )
  }
  
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
                        "Nenhum documento", 
                        ifelse(nchar(latest_title) > 80, 
                               paste0(substr(latest_title, 1, 77), "..."), 
                               latest_title))
  
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

#' Create multi-layer LexML interactive map
#' @param db_pool Database connection pool
#' @param category Category filter: NULL (all), "Legislação", "Jurisprudência"  
#' @param initial_layer Initial layer to display: "federal", "regional", "state", "municipal"
#' @param map_id Unique identifier for this map instance
#' @return Leaflet map object
create_lexml_multilayer_map <- function(db_pool = NULL, category = NULL, 
                                       initial_layer = "state", map_id = "map1") {
  
  cat("🗺️ Creating LexML multi-layer map with category:", category %||% "all", "\n")
  
  tryCatch({
    # Load Brazilian geography
    geo_data <- load_brazil_geography()
    
    if (is.null(geo_data) || is.null(geo_data$states)) {
      cat("⚠️ Geographic data not available, creating fallback map\n")
      return(create_fallback_lexml_map())
    }
    
    # Initialize base map
    map <- leaflet() %>%
      addTiles(group = "OpenStreetMap") %>%
      addProviderTiles("CartoDB.Positron", group = "CartoDB") %>%
      setView(lng = -54.0, lat = -14.0, zoom = 4) %>%
      addLayersControl(
        baseGroups = c("CartoDB", "OpenStreetMap"),
        position = "topright"
      )
    
    # Add federal layer data
    federal_data <- get_lexml_geographic_data(db_pool, "federal", category)
    if (nrow(federal_data) > 0) {
      map <- map %>%
        addPolygons(
          data = geo_data$country,
          fillColor = "#e74c3c",
          fillOpacity = 0.3,
          color = "#c0392b",
          weight = 2,
          popup = paste0("Federal Documents: ", federal_data$doc_count[1]),
          group = "Federal",
          layerId = paste0(map_id, "_federal")
        )
    }
    
    # Add regional layer data  
    regional_data <- get_lexml_geographic_data(db_pool, "regional", category)
    if (nrow(regional_data) > 0 && !is.null(geo_data$regions)) {
      # Create color palette for regions
      region_pal <- colorNumeric(
        palette = "YlOrRd",
        domain = regional_data$doc_count,
        na.color = "#cccccc"
      )
      
      # Merge regional data with geography
      geo_regions <- geo_data$regions %>%
        left_join(regional_data, by = c("name_region" = "name"))
      
      map <- map %>%
        addPolygons(
          data = geo_regions,
          fillColor = ~region_pal(doc_count),
          fillOpacity = 0.7,
          color = "#ffffff",
          weight = 1,
          popup = ~paste0(
            "<strong>", name_region, "</strong><br>",
            "Documents: ", ifelse(is.na(doc_count), 0, doc_count)
          ),
          group = "Regional",
          layerId = paste0(map_id, "_", name_region)
        ) %>%
        addLegend(
          pal = region_pal,
          values = regional_data$doc_count,
          title = "Regional Documents",
          position = "bottomright",
          group = "Regional"
        )
    }
    
    # Add state layer data
    state_data <- get_lexml_geographic_data(db_pool, "state", category)
    if (nrow(state_data) > 0) {
      # Create color palette for states
      state_pal <- colorNumeric(
        palette = "Blues",
        domain = state_data$doc_count,
        na.color = "#f0f0f0"
      )
      
      # Merge state data with geography
      geo_states <- geo_data$states %>%
        left_join(state_data, by = c("name_state" = "name"))
      
      map <- map %>%
        addPolygons(
          data = geo_states,
          fillColor = ~state_pal(doc_count),
          fillOpacity = 0.8,
          color = "#ffffff",
          weight = 1,
          popup = ~paste0(
            "<strong>", name_state, "</strong><br>",
            "Documents: ", ifelse(is.na(doc_count), 0, doc_count), "<br>",
            "<button onclick='Shiny.setInputValue(\"", map_id, "_state_selected\", \"", 
            abbrev_state, "\", {priority: \"event\"});'>View Municipalities</button>"
          ),
          group = "State",
          layerId = paste0(map_id, "_", abbrev_state)
        ) %>%
        addLegend(
          pal = state_pal,
          values = state_data$doc_count,
          title = "State Documents",
          position = "bottomright",
          group = "State"
        )
    }
    
    # Add layer group controls
    map <- map %>%
      addLayersControl(
        baseGroups = c("CartoDB", "OpenStreetMap"),
        overlayGroups = c("Federal", "Regional", "State"),
        options = layersControlOptions(collapsed = FALSE),
        position = "topleft"
      )
    
    # Show initial layer
    if (initial_layer == "federal") {
      map <- map %>% showGroup("Federal") %>% hideGroup(c("Regional", "State"))
    } else if (initial_layer == "regional") {
      map <- map %>% showGroup("Regional") %>% hideGroup(c("Federal", "State"))
    } else {
      map <- map %>% showGroup("State") %>% hideGroup(c("Federal", "Regional"))
    }
    
    cat("✅ Multi-layer map created successfully\n")
    return(map)
    
  }, error = function(e) {
    cat("❌ Error creating multi-layer map:", e$message, "\n")
    return(create_fallback_lexml_map())
  })
}

#' Add municipal layer to existing map
#' @param map Existing leaflet map
#' @param db_pool Database connection pool
#' @param selected_state State to show municipalities for
#' @param category Category filter
#' @param map_id Map instance identifier
#' @return Updated leaflet map with municipal layer
add_municipal_layer <- function(map, db_pool, selected_state, category = NULL, map_id = "map1") {
  
  cat("🏘️ Adding municipal layer for state:", selected_state, "\n")
  
  tryCatch({
    # Get municipal data
    municipal_data <- get_lexml_geographic_data(db_pool, "municipal", category, selected_state)
    
    if (nrow(municipal_data) == 0) {
      cat("⚠️ No municipal data found for", selected_state, "\n")
      return(map)
    }
    
    # Load municipal boundaries for the selected state
    geo_munis <- tryCatch({
      read_municipality(code_state = selected_state, year = 2022, showProgress = FALSE) %>%
        st_make_valid() %>%
        st_transform(crs = 4326) %>%
        st_simplify(dTolerance = 500)
    }, error = function(e) {
      cat("⚠️ Could not load municipal boundaries:", e$message, "\n")
      return(NULL)
    })
    
    if (!is.null(geo_munis)) {
      # Create municipal color palette
      muni_pal <- colorNumeric(
        palette = "Greens",
        domain = municipal_data$doc_count,
        na.color = "#f0f0f0"
      )
      
      # Merge municipal data with geography
      geo_munis <- geo_munis %>%
        left_join(municipal_data, by = c("name_muni" = "name"))
      
      # Add municipal polygons
      map <- map %>%
        addPolygons(
          data = geo_munis,
          fillColor = ~muni_pal(doc_count),
          fillOpacity = 0.7,
          color = "#ffffff",
          weight = 0.5,
          popup = ~paste0(
            "<strong>", name_muni, "</strong><br>",
            "Documents: ", ifelse(is.na(doc_count), 0, doc_count)
          ),
          group = "Municipal",
          layerId = paste0(map_id, "_", code_muni)
        ) %>%
        addLegend(
          pal = muni_pal,
          values = municipal_data$doc_count,
          title = "Municipal Documents",
          position = "bottomleft",
          group = "Municipal"
        ) %>%
        showGroup("Municipal")
      
      # Zoom to state bounds
      state_bounds <- st_bbox(geo_munis)
      map <- map %>% fitBounds(
        lng1 = state_bounds[1], lat1 = state_bounds[2],
        lng2 = state_bounds[3], lat2 = state_bounds[4]
      )
    }
    
    cat("✅ Municipal layer added for", selected_state, "\n")
    return(map)
    
  }, error = function(e) {
    cat("❌ Error adding municipal layer:", e$message, "\n")
    return(map)
  })
}

#' Create fallback map when geographic data fails
#' @return Basic leaflet map
create_fallback_lexml_map <- function() {
  leaflet() %>%
    addTiles() %>%
    setView(lng = -54.0, lat = -14.0, zoom = 4) %>%
    addMarkers(
      lng = -54.0, lat = -14.0,
      popup = "Geographic data temporarily unavailable. Please try again later."
    )
}

cat("✅ Enhanced map generator with multi-layer support loaded\n")