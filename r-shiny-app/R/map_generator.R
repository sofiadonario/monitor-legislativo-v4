# Map Generator Module for Monitor Legislativo v4
# Creates interactive maps showing document distribution by state

library(dplyr)
library(shiny)

library(leaflet)

# Brazilian state coordinates for map markers
brazil_states <- data.frame(
  estado = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
             "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
             "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
  estado_nome = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
                  "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
                  "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
                  "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro", 
                  "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", 
                  "Roraima", "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
  lat = c(-9.0238, -9.5713, 0.9020, -3.4168, -12.9714, -3.7172, -15.7797, 
          -20.3222, -16.6869, -2.5297, -11.4095, -20.4697, -19.9167, 
          -1.4558, -7.2306, -25.4284, -8.0476, -5.0892, -22.9068, 
          -5.7793, -30.0346, -11.2202, 2.8235, -27.5954, -23.5505, 
          -10.9472, -10.2128),
  lng = c(-70.8120, -36.7820, -51.9253, -60.0217, -38.5014, -38.5434, 
          -47.9297, -40.3416, -49.2643, -44.3308, -56.0949, -54.6201, 
          -43.9345, -48.5024, -35.8855, -49.2733, -34.8813, -42.8016, 
          -43.1729, -35.2009, -51.2300, -62.8038, -60.6733, -48.5477, 
          -46.6333, -37.0731, -48.1283),
  stringsAsFactors = FALSE
)

#' Generate interactive map with document counts by state
#' @param document_stats Data frame with document counts by state
#' @return Leaflet map object or HTML fallback
generate_document_map <- function(document_stats = NULL) {
  
  # If no stats provided, create empty data
  if (is.null(document_stats)) {
    map_data <- brazil_states %>%
      mutate(count = 0)
  } else {
    # Join document stats with state coordinates
    map_data <- brazil_states %>%
      left_join(document_stats, by = "estado") %>%
      mutate(count = ifelse(is.na(count), 0, count))
  }
  
  # Create color palette based on document counts
  pal <- colorNumeric(
    palette = c("#FFF7EC", "#FEE8C8", "#FDD49E", "#FDBB84", "#FC8D59", 
                "#EF6548", "#D7301F", "#B30000", "#7F0000"),
    domain = c(0, max(map_data$count, 1))
  )
  
  # Create base map
  map <- leaflet(map_data) %>%
    setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
    addProviderTiles(providers$CartoDB.Positron)
  
  # Add circle markers for each state
  map <- map %>%
    addCircleMarkers(
      ~lng, ~lat,
      radius = ~sqrt(count) * 3 + 5,
      fillColor = ~pal(count),
      fillOpacity = 0.8,
      stroke = TRUE,
      color = "#666",
      weight = 1,
      popup = ~paste0(
        "<strong>", estado_nome, " (", estado, ")</strong><br/>",
        "Documents: ", format(count, big.mark = ",")
      ),
      label = ~paste0(estado, ": ", count, " documents"),
      layerId = ~estado
    )
  
  # Add legend
  map <- map %>%
    addLegend(
      position = "bottomright",
      pal = pal,
      values = ~count,
      title = "Document Count",
      opacity = 0.8
    )
  
  return(map)
}

#' Generate choropleth map with document density by state
#' @param document_stats Data frame with document counts by state
#' @param geojson_path Path to Brazil states GeoJSON (optional)
#' @return Leaflet map object or HTML fallback
generate_choropleth_map <- function(document_stats = NULL, geojson_path = NULL) {
  
  # For now, use circle markers as choropleth requires GeoJSON data
  # This can be enhanced later with actual state boundaries
  return(generate_document_map(document_stats))
}

#' Calculate document statistics by state
#' @param documents Data frame with documents containing 'estado' column
#' @return Data frame with state counts
calculate_state_statistics <- function(documents) {
  if (is.null(documents) || nrow(documents) == 0) {
    return(data.frame(estado = character(), count = numeric()))
  }
  
  state_stats <- documents %>%
    filter(!is.na(estado) & estado != "") %>%
    group_by(estado) %>%
    summarise(count = n()) %>%
    arrange(desc(count))
  
  return(state_stats)
}

#' Generate a simple Brazil map for testing
#' @return Leaflet map object or HTML fallback
generate_test_map <- function() {
  
  leaflet() %>%
    setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
    addProviderTiles(providers$CartoDB.Positron) %>%
    addMarkers(
      lng = -47.86, 
      lat = -15.83, 
      popup = "Brazil - Legislative Document Monitor"
    )
}