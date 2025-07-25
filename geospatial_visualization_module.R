# Geospatial Visualization Module for Brazilian Legislative Data
# MackMonitor v4 - Geographic Analysis and Mapping
# Author: Analytics Module  
# Date: 2025-01-25

library(leaflet)
library(sf)
library(geobr)
library(ggplot2)
library(dplyr)
library(tidyr)
library(viridis)
library(plotly)
library(htmlwidgets)

# ============================================================================
# 1. CONFIGURATION AND DATA LOADING
# ============================================================================

# Load Brazilian geographic data
load_brazil_geodata <- function() {
  geo_data <- list()
  
  cat("Loading Brazilian geographic data...\n")
  
  # Load state boundaries
  tryCatch({
    geo_data$states <- read_state(year = 2020, simplified = TRUE)
    cat("✓ State boundaries loaded\n")
  }, error = function(e) {
    cat("✗ Could not load state boundaries from geobr\n")
    # Fallback to local file if available
    if (file.exists("geodata/brazil_states.rds")) {
      geo_data$states <- readRDS("geodata/brazil_states.rds")
    }
  })
  
  # Load municipality boundaries (simplified)
  tryCatch({
    geo_data$municipalities <- read_municipality(year = 2020, simplified = TRUE)
    cat("✓ Municipality boundaries loaded\n")
  }, error = function(e) {
    cat("✗ Could not load municipality boundaries\n")
    if (file.exists("geodata/brazil_municipalities.rds")) {
      geo_data$municipalities <- readRDS("geodata/brazil_municipalities.rds")
    }
  })
  
  # Load regions
  tryCatch({
    geo_data$regions <- read_region(year = 2020)
    cat("✓ Regional boundaries loaded\n")
  }, error = function(e) {
    cat("✗ Could not load regional boundaries\n")
  })
  
  # State capitals coordinates
  geo_data$capitals <- data.frame(
    state = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
              "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
              "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    capital = c("Rio Branco", "Maceió", "Macapá", "Manaus", "Salvador", 
                "Fortaleza", "Brasília", "Vitória", "Goiânia", "São Luís",
                "Cuiabá", "Campo Grande", "Belo Horizonte", "Belém", "João Pessoa",
                "Curitiba", "Recife", "Teresina", "Rio de Janeiro", "Natal",
                "Porto Alegre", "Porto Velho", "Boa Vista", "Florianópolis",
                "São Paulo", "Aracaju", "Palmas"),
    lat = c(-9.97499, -9.66599, 0.03389, -3.11903, -12.97111, -3.71722,
            -15.79422, -20.31533, -16.68689, -2.53874, -15.59611, -20.44278,
            -19.92083, -1.45502, -7.11532, -25.42778, -8.05428, -5.08921,
            -22.90685, -5.79448, -30.03283, -8.76194, 2.81972, -27.59667,
            -23.54750, -10.94722, -10.24889),
    lon = c(-67.82444, -35.73528, -51.06639, -60.02131, -38.51083, -38.54306,
            -47.88222, -40.33778, -49.26478, -44.28297, -56.09667, -54.64639,
            -43.93778, -48.50444, -34.86306, -49.27306, -34.88111, -42.80194,
            -43.17290, -35.20944, -51.23000, -63.90389, -60.67333, -48.54917,
            -46.63611, -37.07167, -48.27722)
  )
  
  return(geo_data)
}

# Map state codes to names
STATE_MAPPING <- c(
  "AC" = "Acre", "AL" = "Alagoas", "AP" = "Amapá", "AM" = "Amazonas",
  "BA" = "Bahia", "CE" = "Ceará", "DF" = "Distrito Federal", "ES" = "Espírito Santo",
  "GO" = "Goiás", "MA" = "Maranhão", "MT" = "Mato Grosso", "MS" = "Mato Grosso do Sul",
  "MG" = "Minas Gerais", "PA" = "Pará", "PB" = "Paraíba", "PR" = "Paraná",
  "PE" = "Pernambuco", "PI" = "Piauí", "RJ" = "Rio de Janeiro", "RN" = "Rio Grande do Norte",
  "RS" = "Rio Grande do Sul", "RO" = "Rondônia", "RR" = "Roraima", "SC" = "Santa Catarina",
  "SP" = "São Paulo", "SE" = "Sergipe", "TO" = "Tocantins"
)

# ============================================================================
# 2. DATA AGGREGATION FUNCTIONS
# ============================================================================

#' Aggregate legislative data by geographic level
#' @param documents Data frame with documents
#' @param level Geographic level ("state", "municipality", "region")
#' @param analysis_results Optional analysis results to aggregate
#' @return Aggregated data by geography
aggregate_by_geography <- function(documents, 
                                 level = "state",
                                 analysis_results = NULL) {
  
  if (level == "state") {
    # Aggregate by state
    geo_summary <- documents %>%
      filter(!is.na(estado) & estado != "") %>%
      group_by(estado) %>%
      summarise(
        document_count = n(),
        unique_types = n_distinct(tipo),
        date_range = paste(min(data_publicacao, na.rm = TRUE),
                          max(data_publicacao, na.rm = TRUE), sep = " - "),
        dominant_type = names(sort(table(tipo), decreasing = TRUE))[1]
      )
    
    # Add analysis results if provided
    if (!is.null(analysis_results)) {
      if ("sentiment" %in% names(analysis_results)) {
        sentiment_by_state <- cbind(
          documents[, c("id", "estado")],
          analysis_results$sentiment
        ) %>%
          group_by(estado) %>%
          summarise(
            avg_sentiment = mean(sentiment_mean, na.rm = TRUE),
            sentiment_volatility = sd(sentiment_mean, na.rm = TRUE)
          )
        
        geo_summary <- geo_summary %>%
          left_join(sentiment_by_state, by = "estado")
      }
      
      if ("modality" %in% names(analysis_results)) {
        modality_by_state <- cbind(
          documents[, c("id", "estado")],
          analysis_results$modality
        ) %>%
          group_by(estado) %>%
          summarise(
            avg_strictness = mean(strictness_index, na.rm = TRUE),
            dominant_style = names(sort(table(regulatory_style), decreasing = TRUE))[1]
          )
        
        geo_summary <- geo_summary %>%
          left_join(modality_by_state, by = "estado")
      }
    }
    
  } else if (level == "municipality") {
    # Aggregate by municipality
    geo_summary <- documents %>%
      filter(!is.na(municipality) & municipality != "") %>%
      group_by(estado, municipality) %>%
      summarise(
        document_count = n(),
        unique_types = n_distinct(tipo),
        dominant_type = names(sort(table(tipo), decreasing = TRUE))[1]
      )
  }
  
  return(geo_summary)
}

#' Calculate geographic diffusion metrics
#' @param documents Documents with dates and locations
#' @param policy_pattern Pattern to identify specific policies
#' @return Diffusion metrics
calculate_diffusion_metrics <- function(documents, policy_pattern = NULL) {
  
  if (!is.null(policy_pattern)) {
    # Filter to specific policy
    policy_docs <- documents %>%
      filter(grepl(policy_pattern, conteudo, ignore.case = TRUE))
  } else {
    policy_docs <- documents
  }
  
  # Calculate adoption timeline by state
  adoption_timeline <- policy_docs %>%
    group_by(estado) %>%
    summarise(
      first_adoption = min(data_publicacao, na.rm = TRUE),
      total_adoptions = n(),
      adoption_rate = n() / as.numeric(difftime(max(data_publicacao), 
                                               min(data_publicacao), 
                                               units = "days"))
    ) %>%
    arrange(first_adoption)
  
  # Identify early vs late adopters
  adoption_timeline <- adoption_timeline %>%
    mutate(
      adoption_order = row_number(),
      adoption_category = case_when(
        adoption_order <= n() * 0.16 ~ "Innovators",
        adoption_order <= n() * 0.50 ~ "Early Adopters",
        adoption_order <= n() * 0.84 ~ "Late Majority",
        TRUE ~ "Laggards"
      )
    )
  
  # Calculate spatial clustering
  if (nrow(adoption_timeline) > 3) {
    # Simple contiguity analysis
    neighbor_adoption <- adoption_timeline %>%
      mutate(
        neighbors_adopted = sapply(estado, function(s) {
          # This would need actual neighbor data
          # Placeholder for demonstration
          0
        })
      )
  }
  
  return(adoption_timeline)
}

# ============================================================================
# 3. STATIC MAP FUNCTIONS
# ============================================================================

#' Create choropleth map of legislative activity
#' @param geo_summary Aggregated geographic data
#' @param geo_data Geographic boundaries
#' @param variable Variable to map
#' @param title Map title
#' @return ggplot map
create_choropleth_map <- function(geo_summary, 
                                geo_data,
                                variable = "document_count",
                                title = "Legislative Document Distribution") {
  
  # Join data with geography
  if ("estado" %in% names(geo_summary)) {
    # State level
    map_data <- geo_data$states %>%
      left_join(geo_summary, by = c("abbrev_state" = "estado"))
  } else {
    # Municipality level
    map_data <- geo_data$municipalities %>%
      left_join(geo_summary, by = c("name_muni" = "municipality"))
  }
  
  # Create map
  p <- ggplot(map_data) +
    geom_sf(aes_string(fill = variable), color = "white", size = 0.1) +
    scale_fill_viridis_c(
      name = gsub("_", " ", str_to_title(variable)),
      option = "plasma",
      na.value = "gray90"
    ) +
    theme_minimal() +
    theme(
      axis.text = element_blank(),
      axis.ticks = element_blank(),
      panel.grid = element_blank(),
      legend.position = "bottom"
    ) +
    labs(title = title)
  
  return(p)
}

#' Create faceted maps by time period
#' @param documents Document data with dates
#' @param geo_data Geographic boundaries
#' @param time_unit Time aggregation unit
#' @return ggplot faceted map
create_temporal_map <- function(documents, 
                              geo_data,
                              time_unit = "year") {
  
  # Aggregate by time and geography
  temporal_geo <- documents %>%
    mutate(period = floor_date(data_publicacao, time_unit)) %>%
    group_by(period, estado) %>%
    summarise(document_count = n()) %>%
    filter(!is.na(period))
  
  # Join with geography
  map_data <- geo_data$states %>%
    crossing(period = unique(temporal_geo$period)) %>%
    left_join(temporal_geo, by = c("abbrev_state" = "estado", "period"))
  
  # Create faceted map
  p <- ggplot(map_data) +
    geom_sf(aes(fill = document_count), color = "white", size = 0.1) +
    scale_fill_viridis_c(
      name = "Documents",
      option = "plasma",
      na.value = "gray90",
      trans = "log10"
    ) +
    facet_wrap(~ period) +
    theme_minimal() +
    theme(
      axis.text = element_blank(),
      axis.ticks = element_blank(),
      panel.grid = element_blank(),
      legend.position = "bottom"
    ) +
    labs(title = "Legislative Activity Over Time")
  
  return(p)
}

# ============================================================================
# 4. INTERACTIVE MAP FUNCTIONS
# ============================================================================

#' Create interactive leaflet map
#' @param geo_summary Geographic summary data
#' @param geo_data Geographic boundaries
#' @param analysis_results Optional analysis results
#' @return Leaflet map object
create_interactive_map <- function(geo_summary, 
                                 geo_data,
                                 analysis_results = NULL) {
  
  # Prepare data
  if ("estado" %in% names(geo_summary)) {
    # State level map
    map_data <- geo_data$states %>%
      left_join(geo_summary, by = c("abbrev_state" = "estado"))
    
    # Create popup content
    map_data$popup_content <- sprintf(
      "<strong>%s</strong><br/>
      Documents: %d<br/>
      Types: %d<br/>
      Period: %s<br/>
      Main type: %s",
      map_data$name_state,
      map_data$document_count,
      map_data$unique_types,
      map_data$date_range,
      map_data$dominant_type
    )
    
    if ("avg_sentiment" %in% names(map_data)) {
      map_data$popup_content <- paste0(
        map_data$popup_content,
        sprintf("<br/>Avg Sentiment: %.3f", map_data$avg_sentiment)
      )
    }
    
  } else {
    # Municipality level
    map_data <- geo_data$municipalities %>%
      left_join(geo_summary, by = c("name_muni" = "municipality"))
  }
  
  # Transform to WGS84 for leaflet
  map_data <- st_transform(map_data, 4326)
  
  # Create color palette
  pal <- colorNumeric(
    palette = "viridis",
    domain = map_data$document_count,
    na.color = "gray"
  )
  
  # Create map
  m <- leaflet(map_data) %>%
    addProviderTiles(providers$CartoDB.Positron) %>%
    addPolygons(
      fillColor = ~pal(document_count),
      weight = 1,
      opacity = 1,
      color = "white",
      dashArray = "3",
      fillOpacity = 0.7,
      highlightOptions = highlightOptions(
        weight = 3,
        color = "#666",
        dashArray = "",
        fillOpacity = 0.9,
        bringToFront = TRUE
      ),
      popup = ~popup_content,
      popupOptions = popupOptions(
        style = list("font-weight" = "normal", padding = "3px 8px")
      )
    ) %>%
    addLegend(
      pal = pal,
      values = ~document_count,
      opacity = 0.7,
      title = "Document Count",
      position = "bottomright"
    )
  
  return(m)
}

#' Create policy diffusion animation map
#' @param diffusion_data Diffusion timeline data
#' @param geo_data Geographic boundaries
#' @return Animated plotly map
create_diffusion_animation <- function(diffusion_data, geo_data) {
  
  # Prepare animation frames
  dates <- sort(unique(diffusion_data$first_adoption))
  
  # Create frame data
  frames_data <- map_dfr(dates, function(d) {
    adopted_states <- diffusion_data %>%
      filter(first_adoption <= d) %>%
      pull(estado)
    
    geo_data$states %>%
      mutate(
        adopted = abbrev_state %in% adopted_states,
        frame_date = d
      )
  })
  
  # Create animated map
  p <- ggplot(frames_data) +
    geom_sf(aes(fill = adopted), color = "white", size = 0.1) +
    scale_fill_manual(
      values = c("FALSE" = "gray90", "TRUE" = "darkgreen"),
      labels = c("Not Adopted", "Adopted")
    ) +
    theme_minimal() +
    theme(
      axis.text = element_blank(),
      axis.ticks = element_blank(),
      panel.grid = element_blank()
    ) +
    labs(
      title = "Policy Diffusion Over Time",
      subtitle = "Date: {frame_time}",
      fill = "Adoption Status"
    ) +
    transition_time(frame_date) +
    ease_aes('linear')
  
  return(p)
}

# ============================================================================
# 5. NETWORK GEOGRAPHIC VISUALIZATION
# ============================================================================

#' Create geographic network visualization
#' @param relationships Entity relationships with locations
#' @param geo_data Geographic data with coordinates
#' @return Leaflet map with network edges
create_geographic_network <- function(relationships, geo_data) {
  
  # Extract location pairs from relationships
  # This would need entity-location mapping
  # Placeholder implementation
  
  capitals <- geo_data$capitals
  
  # Create sample connections
  connections <- data.frame(
    from_state = sample(capitals$state, 20, replace = TRUE),
    to_state = sample(capitals$state, 20, replace = TRUE),
    weight = runif(20, 1, 10)
  ) %>%
    filter(from_state != to_state) %>%
    left_join(capitals, by = c("from_state" = "state")) %>%
    rename(from_lat = lat, from_lon = lon) %>%
    left_join(capitals, by = c("to_state" = "state")) %>%
    rename(to_lat = lat, to_lon = lon)
  
  # Create map
  m <- leaflet() %>%
    addProviderTiles(providers$CartoDB.DarkMatter) %>%
    setView(lng = -55, lat = -15, zoom = 4)
  
  # Add connections
  for (i in 1:nrow(connections)) {
    m <- m %>%
      addPolylines(
        lng = c(connections$from_lon[i], connections$to_lon[i]),
        lat = c(connections$from_lat[i], connections$to_lat[i]),
        weight = connections$weight[i],
        color = "cyan",
        opacity = 0.5
      )
  }
  
  # Add nodes
  m <- m %>%
    addCircleMarkers(
      data = capitals,
      lng = ~lon,
      lat = ~lat,
      popup = ~capital,
      radius = 5,
      color = "white",
      fillColor = "red",
      fillOpacity = 0.8
    )
  
  return(m)
}

# ============================================================================
# 6. MAIN GEOSPATIAL PIPELINE
# ============================================================================

#' Complete geospatial analysis pipeline
#' @param documents Document data frame
#' @param analysis_results Results from other analysis modules
#' @return List with maps and geographic analyses
run_geospatial_pipeline <- function(documents, analysis_results = NULL) {
  
  cat("\n=== GEOSPATIAL VISUALIZATION PIPELINE ===\n")
  
  results <- list()
  
  # 1. Load geographic data
  cat("\n1. Loading geographic boundaries...\n")
  geo_data <- load_brazil_geodata()
  
  # 2. Aggregate data by geography
  cat("\n2. Aggregating data by geography...\n")
  
  results$state_summary <- aggregate_by_geography(
    documents, 
    level = "state",
    analysis_results = analysis_results
  )
  
  cat(sprintf("  Data aggregated for %d states\n", nrow(results$state_summary)))
  
  # 3. Create static maps
  cat("\n3. Creating static visualizations...\n")
  
  results$maps <- list()
  
  # Document distribution map
  if (!is.null(geo_data$states)) {
    results$maps$document_distribution <- create_choropleth_map(
      results$state_summary,
      geo_data,
      variable = "document_count",
      title = "Legislative Documents by State"
    )
  }
  
  # Sentiment map if available
  if (!is.null(analysis_results) && "sentiment" %in% names(analysis_results) &&
      "avg_sentiment" %in% names(results$state_summary)) {
    results$maps$sentiment_map <- create_choropleth_map(
      results$state_summary,
      geo_data,
      variable = "avg_sentiment",
      title = "Average Document Sentiment by State"
    )
  }
  
  # Temporal map
  if (!is.null(geo_data$states)) {
    results$maps$temporal <- create_temporal_map(documents, geo_data, "year")
  }
  
  # 4. Create interactive maps
  cat("\n4. Creating interactive visualizations...\n")
  
  results$interactive_maps <- list()
  
  if (!is.null(geo_data$states)) {
    results$interactive_maps$main <- create_interactive_map(
      results$state_summary,
      geo_data,
      analysis_results
    )
  }
  
  # 5. Analyze policy diffusion
  cat("\n5. Analyzing policy diffusion patterns...\n")
  
  # Example: electrification policies
  results$diffusion <- calculate_diffusion_metrics(
    documents,
    policy_pattern = "eletrificação|energia elétrica|eletricidade"
  )
  
  # 6. Geographic statistics
  cat("\n6. Calculating geographic statistics...\n")
  
  results$geo_stats <- list(
    states_with_data = n_distinct(documents$estado[!is.na(documents$estado)]),
    municipalities_with_data = n_distinct(documents$municipality[!is.na(documents$municipality)]),
    geographic_coverage = results$state_summary %>%
      summarise(
        total_states = n(),
        avg_docs_per_state = mean(document_count),
        sd_docs_per_state = sd(document_count),
        gini_coefficient = ineq::Gini(document_count)
      ),
    top_states = results$state_summary %>%
      arrange(desc(document_count)) %>%
      head(10),
    bottom_states = results$state_summary %>%
      arrange(document_count) %>%
      head(10)
  )
  
  cat("\nGeospatial analysis complete!\n")
  
  return(results)
}

# ============================================================================
# 7. EXPORT FUNCTIONS
# ============================================================================

#' Save geospatial analysis results
#' @param results Geospatial pipeline results
#' @param output_dir Output directory
save_geospatial_results <- function(results, output_dir = "geospatial_output") {
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Save summary data
  write.csv(results$state_summary, 
            file.path(output_dir, "state_summary.csv"), 
            row.names = FALSE)
  
  if (!is.null(results$diffusion)) {
    write.csv(results$diffusion, 
              file.path(output_dir, "policy_diffusion.csv"), 
              row.names = FALSE)
  }
  
  # Save static maps
  for (map_name in names(results$maps)) {
    if (!is.null(results$maps[[map_name]])) {
      ggsave(
        file.path(output_dir, paste0(map_name, ".png")),
        results$maps[[map_name]],
        width = 12,
        height = 10
      )
    }
  }
  
  # Save interactive maps
  for (map_name in names(results$interactive_maps)) {
    if (!is.null(results$interactive_maps[[map_name]])) {
      saveWidget(
        results$interactive_maps[[map_name]],
        file.path(output_dir, paste0(map_name, "_interactive.html"))
      )
    }
  }
  
  # Save statistics
  saveRDS(results$geo_stats, file.path(output_dir, "geographic_statistics.rds"))
  
  # Create summary report
  sink(file.path(output_dir, "geographic_summary.txt"))
  cat("GEOGRAPHIC ANALYSIS SUMMARY\n")
  cat("===========================\n\n")
  
  cat(sprintf("States with data: %d\n", results$geo_stats$states_with_data))
  cat(sprintf("Municipalities with data: %d\n", results$geo_stats$municipalities_with_data))
  cat(sprintf("Average documents per state: %.1f (SD: %.1f)\n",
              results$geo_stats$geographic_coverage$avg_docs_per_state,
              results$geo_stats$geographic_coverage$sd_docs_per_state))
  cat(sprintf("Geographic inequality (Gini): %.3f\n",
              results$geo_stats$geographic_coverage$gini_coefficient))
  
  cat("\nTop 5 states by document count:\n")
  print(head(results$geo_stats$top_states, 5))
  
  sink()
  
  cat(sprintf("\nResults saved to %s/\n", output_dir))
}