# IBGE Geographic Data Integration for Monitor Legislativo v4
# Real Brazilian geographic data using geobr package

library(geobr)
library(sf)
library(dplyr)
library(memoise)

# Memoize functions for performance
get_states_data <- memoise::memoise(geobr::read_state)
get_municipalities_data <- memoise::memoise(geobr::read_municipality)

#' Load Brazilian states geographic data
#' @param year Year for the data (default: 2020)
#' @param simplified Whether to use simplified geometries
#' @return SF object with states data
load_brazilian_states <- function(year = 2020, simplified = TRUE) {
  
  log_event("Loading Brazilian states geographic data")
  
  tryCatch({
    # Load states from geobr
    states_sf <- get_states_data(
      year = year, 
      simplified = simplified,
      showProgress = FALSE
    )
    
    # Standardize column names
    states_processed <- states_sf %>%
      select(
        state_code = abbrev_state,
        state_name = name_state,
        region_code = code_region,
        region_name = name_region,
        geometry = geom
      ) %>%
      mutate(
        # Add centroid coordinates for markers
        centroid = sf::st_centroid(geometry),
        lat = sf::st_coordinates(centroid)[, 2],
        lng = sf::st_coordinates(centroid)[, 1]
      ) %>%
      select(-centroid)
    
    log_event(paste("Loaded", nrow(states_processed), "Brazilian states"))
    return(states_processed)
    
  }, error = function(e) {
    log_event(paste("Error loading states data:", e$message), "ERROR")
    return(create_fallback_states_data())
  })
}

#' Load Brazilian municipalities geographic data
#' @param state_code Optional state code to filter municipalities
#' @param year Year for the data (default: 2020)
#' @param simplified Whether to use simplified geometries
#' @return SF object with municipalities data
load_brazilian_municipalities <- function(state_code = NULL, year = 2020, simplified = TRUE) {
  
  log_event(paste("Loading municipalities data for:", state_code %||% "all states"))
  
  tryCatch({
    # Load municipalities from geobr
    if (!is.null(state_code)) {
      municipalities_sf <- geobr::read_municipality(
        code_muni = state_code,
        year = year,
        simplified = simplified,
        showProgress = FALSE
      )
    } else {
      municipalities_sf <- get_municipalities_data(
        year = year,
        simplified = simplified,
        showProgress = FALSE
      )
    }
    
    # Standardize column names
    municipalities_processed <- municipalities_sf %>%
      select(
        municipality_code = code_muni,
        municipality_name = name_muni,
        state_code = abbrev_state,
        state_name = name_state,
        region_name = name_region,
        geometry = geom
      ) %>%
      mutate(
        # Add centroid coordinates
        centroid = sf::st_centroid(geometry),
        lat = sf::st_coordinates(centroid)[, 2],
        lng = sf::st_coordinates(centroid)[, 1],
        # Calculate area in km²
        area_km2 = as.numeric(sf::st_area(geometry)) / 1000000
      ) %>%
      select(-centroid)
    
    log_event(paste("Loaded", nrow(municipalities_processed), "municipalities"))
    return(municipalities_processed)
    
  }, error = function(e) {
    log_event(paste("Error loading municipalities data:", e$message), "ERROR")
    return(create_fallback_municipalities_data(state_code))
  })
}

#' Create fallback states data when geobr is unavailable
#' @return Simple states data frame
create_fallback_states_data <- function() {
  
  log_event("Creating fallback states data", "WARN")
  
  states_data <- data.frame(
    state_code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                   "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                   "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    state_name = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
                   "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
                   "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
                   "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro", 
                   "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", "Roraima",
                   "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
    region_name = c("Norte", "Nordeste", "Norte", "Norte", "Nordeste", "Nordeste",
                    "Centro-Oeste", "Sudeste", "Centro-Oeste", "Nordeste",
                    "Centro-Oeste", "Centro-Oeste", "Sudeste", "Norte", "Nordeste",
                    "Sul", "Nordeste", "Nordeste", "Sudeste", "Nordeste",
                    "Sul", "Norte", "Norte", "Sul", "Sudeste", "Nordeste", "Norte"),
    lat = c(-8.77, -9.71, 1.41, -3.07, -12.96, -5.20, -15.83, -19.19, -16.64, -2.55,
            -12.64, -20.51, -18.10, -5.53, -7.06, -24.89, -8.28, -8.28, -22.84, -5.22,
            -30.01, -11.22, 1.89, -27.33, -23.55, -10.90, -10.25),
    lng = c(-70.55, -36.82, -51.77, -61.66, -38.51, -39.53, -47.86, -40.34, -49.31, -44.30,
            -55.42, -54.54, -44.38, -52.29, -35.55, -51.55, -35.07, -43.68, -43.15, -36.52,
            -51.22, -61.95, -61.22, -49.44, -46.64, -37.07, -48.25),
    stringsAsFactors = FALSE
  )
  
  return(states_data)
}

#' Create fallback municipalities data
#' @param state_code Optional state filter
#' @return Simple municipalities data frame
create_fallback_municipalities_data <- function(state_code = NULL) {
  
  log_event("Creating fallback municipalities data", "WARN")
  
  # Sample municipalities for major states
  municipalities_sample <- data.frame(
    municipality_code = c(
      "3550308", "3304557", "4106902", "2927408", "1302603",
      "2111300", "5208707", "4314902", "1501402", "2304400"
    ),
    municipality_name = c(
      "São Paulo", "Rio de Janeiro", "Curitiba", "Salvador", "Manaus",
      "São Luís", "Goiânia", "Porto Alegre", "Belém", "Fortaleza"
    ),
    state_code = c("SP", "RJ", "PR", "BA", "AM", "MA", "GO", "RS", "PA", "CE"),
    state_name = c(
      "São Paulo", "Rio de Janeiro", "Paraná", "Bahia", "Amazonas",
      "Maranhão", "Goiás", "Rio Grande do Sul", "Pará", "Ceará"
    ),
    lat = c(-23.55, -22.91, -25.42, -12.97, -3.10, -2.53, -16.68, -30.03, -1.46, -3.72),
    lng = c(-46.64, -43.17, -49.27, -38.51, -60.03, -44.30, -49.25, -51.23, -48.50, -38.54),
    area_km2 = c(1521.11, 1200.27, 432.17, 693.45, 11401.09, 834.78, 739.49, 496.68, 1059.46, 314.93),
    stringsAsFactors = FALSE
  )
  
  # Filter by state if specified
  if (!is.null(state_code)) {
    municipalities_sample <- municipalities_sample %>%
      filter(state_code %in% !!state_code)
  }
  
  return(municipalities_sample)
}

#' Get municipalities for a specific state
#' @param state_code Two-letter state code
#' @param year Year for the data
#' @return Data frame with municipalities
get_state_municipalities <- function(state_code, year = 2020) {
  
  if (is.null(state_code) || state_code == "") {
    return(NULL)
  }
  
  # Check cache first
  cache_key <- paste0("monitor_legislativo:municipalities:", state_code, ":", year)
  cached_data <- get_cache(cache_key)
  if (!is.null(cached_data)) {
    return(cached_data)
  }
  
  # Load municipalities data
  municipalities <- load_brazilian_municipalities(state_code, year, simplified = TRUE)
  
  if (!is.null(municipalities) && nrow(municipalities) > 0) {
    # Create simplified list for dropdowns
    municipalities_list <- municipalities %>%
      sf::st_drop_geometry() %>%
      select(municipality_code, municipality_name) %>%
      arrange(municipality_name)
    
    # Cache for 24 hours
    set_cache(cache_key, municipalities_list, 86400)
    
    return(municipalities_list)
  }
  
  return(NULL)
}

#' Create choropleth map with legislative data
#' @param geographic_data SF object with geographic boundaries
#' @param legislative_data Data frame with legislative documents
#' @param join_by Column name to join data
#' @param value_column Column to use for coloring
#' @return Leaflet map with choropleth
create_choropleth_with_data <- function(geographic_data, legislative_data, 
                                      join_by = "state_code", value_column = "count") {
  
  if (is.null(geographic_data) || is.null(legislative_data)) {
    log_event("Missing data for choropleth creation", "WARN")
    return(NULL)
  }
  
  tryCatch({
    # Aggregate legislative data
    if (join_by == "state_code") {
      aggregated_data <- legislative_data %>%
        filter(!is.na(estado)) %>%
        count(estado, name = "document_count") %>%
        rename(!!join_by := estado)
    } else if (join_by == "municipality_code") {
      aggregated_data <- legislative_data %>%
        filter(!is.na(municipio)) %>%
        count(municipio, name = "document_count") %>%
        rename(!!join_by := municipio)
    } else {
      log_event(paste("Unsupported join column:", join_by), "ERROR")
      return(NULL)
    }
    
    # Join with geographic data
    choropleth_data <- geographic_data %>%
      left_join(aggregated_data, by = join_by) %>%
      mutate(document_count = ifelse(is.na(document_count), 0, document_count))
    
    # Create color palette
    if (all(choropleth_data$document_count == 0)) {
      fill_colors <- rep("#f0f0f0", nrow(choropleth_data))
      show_legend <- FALSE
    } else {
      color_pal <- colorNumeric(
        palette = "YlOrRd",
        domain = choropleth_data$document_count[choropleth_data$document_count > 0]
      )
      fill_colors <- ifelse(
        choropleth_data$document_count > 0,
        color_pal(choropleth_data$document_count),
        "#f0f0f0"
      )
      show_legend <- TRUE
    }
    
    # Create base map
    map <- leaflet(choropleth_data) %>%
      addProviderTiles(providers$CartoDB.Positron) %>%
      addPolygons(
        fillColor = fill_colors,
        fillOpacity = 0.7,
        color = "#333333",
        weight = 1,
        opacity = 0.8,
        highlightOptions = highlightOptions(
          weight = 3,
          color = "#666",
          fillOpacity = 0.9,
          bringToFront = TRUE
        ),
        popup = ~paste0(
          "<strong>", 
          ifelse(join_by == "state_code", state_name, municipality_name),
          "</strong><br>",
          "Documentos: ", document_count
        ),
        layerId = ~get(join_by)
      )
    
    # Add legend if there's data variation
    if (show_legend) {
      map <- map %>%
        addLegend(
          "bottomright",
          pal = color_pal,
          values = ~document_count[document_count > 0],
          title = "Documentos",
          opacity = 0.7
        )
    }
    
    return(map)
    
  }, error = function(e) {
    log_event(paste("Error creating choropleth:", e$message), "ERROR")
    return(NULL)
  })
}

#' Get geographic statistics for a region
#' @param legislative_data Legislative documents data
#' @param geographic_level Level of analysis ("state", "municipality")
#' @return List with geographic statistics
calculate_geographic_stats <- function(legislative_data, geographic_level = "state") {
  
  if (is.null(legislative_data) || nrow(legislative_data) == 0) {
    return(list(
      total_locations = 0,
      coverage_percentage = 0,
      top_locations = character(0),
      documents_with_location = 0
    ))
  }
  
  if (geographic_level == "state") {
    location_column <- "estado"
    total_possible <- 27  # Brazilian states including DF
  } else {
    location_column <- "municipio"
    total_possible <- 5570  # Brazilian municipalities
  }
  
  # Calculate statistics
  geo_data <- legislative_data %>%
    filter(!is.na(!!sym(location_column)))
  
  stats <- list(
    total_locations = length(unique(geo_data[[location_column]])),
    coverage_percentage = round(
      (length(unique(geo_data[[location_column]])) / total_possible) * 100, 1
    ),
    documents_with_location = nrow(geo_data),
    documents_without_location = nrow(legislative_data) - nrow(geo_data)
  )
  
  # Top locations by document count
  top_locations <- geo_data %>%
    count(!!sym(location_column), sort = TRUE) %>%
    slice_head(n = 5) %>%
    pull(!!sym(location_column))
  
  stats$top_locations <- paste(top_locations, collapse = ", ")
  
  return(stats)
}

#' Check if geobr package is available and working
#' @return Boolean indicating if geobr is functional
check_geobr_availability <- function() {
  
  if (!requireNamespace("geobr", quietly = TRUE)) {
    log_event("geobr package not available", "WARN")
    return(FALSE)
  }
  
  tryCatch({
    # Test with a small query
    test_data <- geobr::read_state(
      code_state = "DF",
      year = 2020,
      simplified = TRUE,
      showProgress = FALSE
    )
    
    log_event("geobr package is functional")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("geobr package test failed:", e$message), "WARN")
    return(FALSE)
  })
}

#' Initialize geographic data for the application
#' @param load_municipalities Whether to preload municipalities
#' @return List with geographic data
initialize_geographic_data <- function(load_municipalities = FALSE) {
  
  log_event("Initializing geographic data")
  
  # Check if geobr is available
  geobr_available <- check_geobr_availability()
  
  geographic_data <- list(
    geobr_available = geobr_available,
    states = NULL,
    municipalities = NULL,
    initialized_at = Sys.time()
  )
  
  # Load states data
  if (geobr_available) {
    geographic_data$states <- load_brazilian_states()
  } else {
    geographic_data$states <- create_fallback_states_data()
  }
  
  # Optionally load municipalities (can be memory intensive)
  if (load_municipalities && geobr_available) {
    geographic_data$municipalities <- load_brazilian_municipalities()
  }
  
  log_event("Geographic data initialization completed")
  return(geographic_data)
}