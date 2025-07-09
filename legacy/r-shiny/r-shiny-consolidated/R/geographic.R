# Geographic Functions for Monitor Legislativo v4
# Brazilian geographic analysis and visualization

library(leaflet)
library(sf)
library(dplyr)
library(RColorBrewer)

#' Add legislative data to leaflet map
#' @param map Leaflet map object
#' @param data Legislative data
#' @param color_by Variable to color by ("count", "density", "latest")
#' @return Updated leaflet map
add_legislative_data_to_map <- function(map, data, color_by = "count") {
  
  if (is.null(data) || nrow(data) == 0) {
    return(map)
  }
  
  log_event(paste("Adding", nrow(data), "documents to map"))
  
  # Filter data with geographic information
  geo_data <- data %>%
    filter(!is.na(estado)) %>%
    mutate(
      lat = get_state_center_lat(estado),
      lng = get_state_center_lng(estado)
    ) %>%
    filter(!is.na(lat), !is.na(lng))
  
  if (nrow(geo_data) == 0) {
    log_event("No geographic data available for mapping", "WARN")
    return(map)
  }
  
  # Aggregate data by state
  state_summary <- geo_data %>%
    group_by(estado, lat, lng) %>%
    summarise(
      count = n(),
      latest_date = max(as.Date(data), na.rm = TRUE),
      types = n_distinct(tipo, na.rm = TRUE),
      documents = paste(head(titulo, 3), collapse = "<br>"),
      .groups = "drop"
    ) %>%
    mutate(
      latest_days_ago = as.numeric(Sys.Date() - latest_date)
    )
  
  # Determine colors based on selected variable
  if (color_by == "count") {
    # Color by document count
    color_var <- state_summary$count
    color_palette <- colorNumeric("YlOrRd", domain = color_var)
    legend_title <- "Documentos"
  } else if (color_by == "latest") {
    # Color by recency
    color_var <- state_summary$latest_days_ago
    color_palette <- colorNumeric("RdYlBu", domain = color_var, reverse = TRUE)
    legend_title <- "Dias desde último doc"
  } else {
    # Default to count
    color_var <- state_summary$count
    color_palette <- colorNumeric("YlOrRd", domain = color_var)
    legend_title <- "Documentos"
  }
  
  # Add markers to map
  map <- map %>%
    addCircleMarkers(
      data = state_summary,
      lng = ~lng,
      lat = ~lat,
      radius = ~sqrt(count) * 3,  # Scale radius by document count
      fillColor = ~color_palette(color_var),
      color = "white",
      weight = 2,
      opacity = 0.8,
      fillOpacity = 0.6,
      popup = ~paste0(
        "<strong>", estado, "</strong><br>",
        "Documentos: ", count, "<br>",
        "Tipos: ", types, "<br>",
        "Mais recente: ", format(latest_date, "%d/%m/%Y"), "<br>",
        "<hr>",
        "<strong>Exemplos:</strong><br>",
        documents
      ),
      popupOptions = popupOptions(maxWidth = 300),
      layerId = ~estado
    ) %>%
    addLegend(
      "bottomright",
      pal = color_palette,
      values = color_var,
      title = legend_title,
      opacity = 0.7
    )
  
  # Load and add state boundaries if available
  geo_boundaries <- load_geographic_data()
  if (!is.null(geo_boundaries) && "states" %in% names(geo_boundaries)) {
    
    # Merge with document counts
    states_with_data <- geo_boundaries$states %>%
      left_join(
        state_summary %>% select(estado, count),
        by = c("abbrev_state" = "estado")
      ) %>%
      mutate(count = ifelse(is.na(count), 0, count))
    
    # Add state polygons
    map <- map %>%
      addPolygons(
        data = states_with_data,
        fillColor = ~ifelse(count > 0, color_palette(count), "#f0f0f0"),
        fillOpacity = 0.3,
        color = "#333333",
        weight = 1,
        opacity = 0.5,
        highlightOptions = highlightOptions(
          weight = 3,
          color = "#666",
          fillOpacity = 0.5,
          bringToFront = TRUE
        ),
        popup = ~paste0(
          "<strong>", name_state, "</strong><br>",
          "Documentos: ", ifelse(is.na(count), 0, count)
        ),
        layerId = ~paste0("state_", abbrev_state),
        group = "States"
      )
  }
  
  return(map)
}

#' Get latitude for Brazilian state center
#' @param state_code Two-letter state code
#' @return Latitude coordinate
get_state_center_lat <- function(state_code) {
  
  state_centers <- list(
    "AC" = -8.77, "AL" = -9.71, "AP" = 1.41, "AM" = -3.07,
    "BA" = -12.96, "CE" = -5.20, "DF" = -15.83, "ES" = -19.19,
    "GO" = -16.64, "MA" = -2.55, "MT" = -12.64, "MS" = -20.51,
    "MG" = -18.10, "PA" = -5.53, "PB" = -7.06, "PR" = -24.89,
    "PE" = -8.28, "PI" = -8.28, "RJ" = -22.84, "RN" = -5.22,
    "RS" = -30.01, "RO" = -11.22, "RR" = 1.89, "SC" = -27.33,
    "SP" = -23.55, "SE" = -10.90, "TO" = -10.25
  )
  
  return(state_centers[[state_code]] %||% NA)
}

#' Get longitude for Brazilian state center
#' @param state_code Two-letter state code
#' @return Longitude coordinate
get_state_center_lng <- function(state_code) {
  
  state_centers <- list(
    "AC" = -70.55, "AL" = -36.82, "AP" = -51.77, "AM" = -61.66,
    "BA" = -38.51, "CE" = -39.53, "DF" = -47.86, "ES" = -40.34,
    "GO" = -49.31, "MA" = -44.30, "MT" = -55.42, "MS" = -54.54,
    "MG" = -44.38, "PA" = -52.29, "PB" = -35.55, "PR" = -51.55,
    "PE" = -35.07, "PI" = -43.68, "RJ" = -43.15, "RN" = -36.52,
    "RS" = -51.22, "RO" = -61.95, "RR" = -61.22, "SC" = -49.44,
    "SP" = -46.64, "SE" = -37.07, "TO" = -48.25
  )
  
  return(state_centers[[state_code]] %||% NA)
}

#' Create choropleth map of Brazilian states with legislative data
#' @param data Legislative data
#' @param variable Variable to map ("count", "density", "latest")
#' @return Leaflet map
create_choropleth_map <- function(data, variable = "count") {
  
  if (is.null(data) || nrow(data) == 0) {
    # Return empty map
    return(
      leaflet() %>%
        addProviderTiles(providers$CartoDB.Positron) %>%
        setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
        addControl("Nenhum dado disponível para visualização", position = "topright")
    )
  }
  
  # Load geographic boundaries
  geo_boundaries <- load_geographic_data()
  if (is.null(geo_boundaries) || !"states" %in% names(geo_boundaries)) {
    log_event("Geographic boundaries not available", "WARN")
    return(add_legislative_data_to_map(
      leaflet() %>%
        addProviderTiles(providers$CartoDB.Positron) %>%
        setView(lng = -47.9292, lat = -15.7801, zoom = 4),
      data, variable
    ))
  }
  
  # Aggregate data by state
  state_data <- data %>%
    filter(!is.na(estado)) %>%
    group_by(estado) %>%
    summarise(
      count = n(),
      latest_date = max(as.Date(data), na.rm = TRUE),
      types = n_distinct(tipo, na.rm = TRUE),
      avg_year = round(mean(lubridate::year(as.Date(data)), na.rm = TRUE)),
      .groups = "drop"
    ) %>%
    mutate(
      latest_days_ago = as.numeric(Sys.Date() - latest_date),
      density = count / 1000  # Simple density approximation
    )
  
  # Merge with geographic data
  states_geo <- geo_boundaries$states %>%
    left_join(state_data, by = c("abbrev_state" = "estado")) %>%
    mutate(
      count = ifelse(is.na(count), 0, count),
      density = ifelse(is.na(density), 0, density),
      latest_days_ago = ifelse(is.na(latest_days_ago), 999, latest_days_ago)
    )
  
  # Set up color palette based on variable
  if (variable == "count") {
    pal_data <- states_geo$count
    pal_colors <- "YlOrRd"
    legend_title <- "Número de Documentos"
  } else if (variable == "density") {
    pal_data <- states_geo$density
    pal_colors <- "YlGnBu"
    legend_title <- "Densidade (docs/1000)"
  } else if (variable == "latest") {
    pal_data <- states_geo$latest_days_ago
    pal_colors <- "RdYlBu"
    legend_title <- "Dias desde último documento"
  } else {
    pal_data <- states_geo$count
    pal_colors <- "YlOrRd"
    legend_title <- "Número de Documentos"
  }
  
  # Create color palette
  if (all(pal_data == 0) || all(is.na(pal_data))) {
    # No variation in data
    fill_colors <- rep("#f0f0f0", nrow(states_geo))
    show_legend <- FALSE
  } else {
    color_pal <- colorNumeric(pal_colors, domain = pal_data[pal_data > 0])
    fill_colors <- ifelse(pal_data > 0, color_pal(pal_data), "#f0f0f0")
    show_legend <- TRUE
  }
  
  # Create map
  map <- leaflet(states_geo) %>%
    addProviderTiles(providers$CartoDB.Positron) %>%
    setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
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
        "<strong>", name_state, " (", abbrev_state, ")</strong><br>",
        "Documentos: ", ifelse(is.na(count), 0, count), "<br>",
        "Tipos únicos: ", ifelse(is.na(types), 0, types), "<br>",
        if (variable == "latest" && !is.na(latest_date)) {
          paste0("Mais recente: ", format(latest_date, "%d/%m/%Y"), "<br>")
        } else {
          ""
        },
        if (variable == "density") {
          paste0("Densidade: ", round(density, 2), "<br>")
        } else {
          ""
        }
      ),
      popupOptions = popupOptions(maxWidth = 250),
      layerId = ~abbrev_state
    )
  
  # Add legend if there's data variation
  if (show_legend && exists("color_pal")) {
    map <- map %>%
      addLegend(
        "bottomright",
        pal = color_pal,
        values = pal_data[pal_data > 0],
        title = legend_title,
        opacity = 0.7
      )
  }
  
  return(map)
}

#' Get geographic statistics for legislative data
#' @param data Legislative data
#' @return List with geographic statistics
get_geographic_stats <- function(data) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(list(
      total_states = 0,
      total_municipalities = 0,
      coverage_percentage = 0,
      top_states = "N/A",
      regional_distribution = "N/A"
    ))
  }
  
  # Filter data with geographic information
  geo_data <- data %>%
    filter(!is.na(estado))
  
  if (nrow(geo_data) == 0) {
    return(list(
      total_states = 0,
      total_municipalities = 0,
      coverage_percentage = 0,
      top_states = "N/A",
      regional_distribution = "N/A"
    ))
  }
  
  # Calculate statistics
  total_states <- length(unique(geo_data$estado))
  total_municipalities <- length(unique(geo_data$municipio[!is.na(geo_data$municipio)]))
  
  # Coverage percentage (out of 27 states including DF)
  coverage_percentage <- round((total_states / 27) * 100, 1)
  
  # Top states by document count
  top_states <- geo_data %>%
    count(estado, sort = TRUE) %>%
    slice_head(n = 5) %>%
    pull(estado) %>%
    paste(collapse = ", ")
  
  # Regional distribution
  regions <- list(
    "Norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
    "Nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
    "Centro-Oeste" = c("DF", "GO", "MT", "MS"),
    "Sudeste" = c("ES", "MG", "RJ", "SP"),
    "Sul" = c("PR", "RS", "SC")
  )
  
  regional_counts <- sapply(names(regions), function(region) {
    states_in_region <- regions[[region]]
    count <- sum(geo_data$estado %in% states_in_region, na.rm = TRUE)
    return(count)
  })
  
  regional_distribution <- paste(names(regional_counts), ":", regional_counts, collapse = " | ")
  
  return(list(
    total_states = total_states,
    total_municipalities = total_municipalities,
    coverage_percentage = paste0(coverage_percentage, "%"),
    top_states = top_states,
    regional_distribution = regional_distribution,
    documents_with_geo = nrow(geo_data),
    documents_without_geo = nrow(data) - nrow(geo_data)
  ))
}

#' Geocode Brazilian addresses using IBGE data
#' @param address Address string
#' @param state Optional state code for better accuracy
#' @return List with lat, lng, and confidence
geocode_brazilian_address <- function(address, state = NULL) {
  
  if (is.null(address) || address == "") {
    return(list(lat = NA, lng = NA, confidence = 0))
  }
  
  # Simple geocoding based on state and municipality matching
  # In a full implementation, this would use a proper geocoding service
  
  tryCatch({
    # Clean address
    clean_address <- tolower(trimws(address))
    
    # Extract state if mentioned in address
    if (is.null(state)) {
      state_codes <- get_brazilian_states()
      for (state_name in names(state_codes)) {
        if (grepl(tolower(state_name), clean_address)) {
          state <- state_codes[[state_name]]
          break
        }
      }
    }
    
    # If we have a state, return its center coordinates
    if (!is.null(state)) {
      lat <- get_state_center_lat(state)
      lng <- get_state_center_lng(state)
      
      if (!is.na(lat) && !is.na(lng)) {
        return(list(lat = lat, lng = lng, confidence = 0.7))
      }
    }
    
    # Default to Brazil center
    return(list(lat = -15.7801, lng = -47.9292, confidence = 0.3))
    
  }, error = function(e) {
    log_event(paste("Geocoding error:", e$message), "WARN")
    return(list(lat = NA, lng = NA, confidence = 0))
  })
}

#' Create custom map markers based on document type
#' @param tipo Document type
#' @return Icon specification for leaflet
create_document_icon <- function(tipo) {
  
  # Default icon specifications
  default_icon <- makeIcon(
    iconUrl = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png",
    iconWidth = 25,
    iconHeight = 41,
    iconAnchorX = 12,
    iconAnchorY = 41
  )
  
  # Custom icons based on document type
  icon_mapping <- list(
    "lei" = list(color = "#d73027", icon = "gavel"),
    "decreto" = list(color = "#f46d43", icon = "file-text"),
    "portaria" = list(color = "#fdae61", icon = "clipboard"),
    "resolucao" = list(color = "#abd9e9", icon = "check-circle"),
    "medida_provisoria" = list(color = "#74add1", icon = "clock")
  )
  
  if (tolower(tipo) %in% names(icon_mapping)) {
    icon_spec <- icon_mapping[[tolower(tipo)]]
    
    # Create awesome icon if possible
    if (require_package("leaflet", quiet = TRUE)) {
      return(awesomeIcons(
        icon = icon_spec$icon,
        iconColor = "white",
        markerColor = "red",  # leaflet awesome icons have limited colors
        library = "fa"
      ))
    }
  }
  
  return(default_icon)
}