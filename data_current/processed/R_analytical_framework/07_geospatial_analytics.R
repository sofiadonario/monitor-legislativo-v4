#!/usr/bin/env Rscript
#' Brazilian Legislative Dataset - Phase 2: Geospatial Analytics
#' 
#' This script implements geospatial analysis capabilities for the Brazilian legislative
#' dataset, including jurisdiction mapping, policy adoption visualization, spatial
#' diffusion analysis, and regulatory density mapping using sf and leaflet.
#' 
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-07-26
#' @version 1.0.0

# Load required libraries
suppressPackageStartupMessages({
  library(sf)
  library(leaflet)
  library(tmap)
  library(tmaptools)
  library(dplyr)
  library(ggplot2)
  library(viridis)
  library(RColorBrewer)
  library(plotly)
  library(geobr)
  library(arrow)
  library(stringr)
  library(purrr)
  library(tidyr)
  library(lubridate)
  library(DT)
  library(htmlwidgets)
  library(mapview)
  library(rgdal)
  library(raster)
  library(spdep)
  library(spatstat)
  library(logger)
})

# Set up logging
log_threshold(INFO)

#' Geospatial Analysis Functions
#' =============================

#' Load Brazilian geographic boundaries
#' @param level Geographic level ("country", "state", "municipality")
#' @param year Year for boundaries (default: 2020)
#' @return sf object with geographic boundaries
load_brazil_boundaries <- function(level = "state", year = 2020) {
  
  log_info("Loading Brazilian geographic boundaries for {level} level...")
  
  tryCatch({
    if (level == "country") {
      boundaries <- read_country(year = year)
    } else if (level == "state") {
      boundaries <- read_state(year = year)
    } else if (level == "municipality") {
      boundaries <- read_municipality(year = year)
    } else {
      stop("Invalid level. Choose 'country', 'state', or 'municipality'")
    }
    
    # Ensure CRS is WGS84
    boundaries <- st_transform(boundaries, crs = 4326)
    
    log_info("Loaded {nrow(boundaries)} {level} boundaries")
    return(boundaries)
    
  }, error = function(e) {
    log_warn("Failed to load boundaries from geobr: {e$message}")
    log_info("Creating simplified boundaries for demonstration...")
    
    # Create simplified boundaries for demonstration
    if (level == "state") {
      # Major Brazilian states
      demo_states <- tibble(
        code_state = c("11", "23", "31", "33", "35", "41", "43", "51", "52", "53"),
        name_state = c("Rondônia", "Ceará", "Minas Gerais", "Rio de Janeiro", 
                      "São Paulo", "Paraná", "Rio Grande do Sul", "Mato Grosso",
                      "Goiás", "Distrito Federal"),
        abbrev_state = c("RO", "CE", "MG", "RJ", "SP", "PR", "RS", "MT", "GO", "DF"),
        # Approximate coordinates for centroids
        longitude = c(-62.8, -39.3, -44.9, -43.2, -46.6, -51.2, -51.2, -56.1, -49.3, -47.9),
        latitude = c(-11.5, -5.2, -18.1, -22.9, -23.5, -24.9, -30.0, -12.6, -15.8, -15.8)
      )
      
      # Convert to sf points (simplified representation)
      boundaries <- demo_states %>%
        st_as_sf(coords = c("longitude", "latitude"), crs = 4326) %>%
        mutate(geom = st_buffer(geometry, dist = 2)) %>%  # Create simple buffer polygons
        select(-geometry) %>%
        rename(geometry = geom)
      
    } else {
      stop("Demo boundaries only available for state level")
    }
    
    return(boundaries)
  })
}

#' Prepare geospatial legislative data
#' @param data_source Path to Parquet file or data frame
#' @return Data frame with geographic information
prepare_geospatial_data <- function(data_source) {
  
  log_info("Preparing geospatial legislative data...")
  
  if (is.character(data_source)) {
    data <- read_parquet(data_source)
  } else {
    data <- data_source
  }
  
  # Prepare geographic data
  geo_data <- data %>%
    mutate(
      # Standardize authority levels
      authority_level = case_when(
        str_detect(tolower(autoridade %||% ""), "federal") | jurisdicao == "Federal" ~ "Federal",
        str_detect(tolower(autoridade %||% ""), "estadual|estado") | (!is.na(estado) & estado != "") ~ "State",
        str_detect(tolower(autoridade %||% ""), "municipal|prefeitura") | (!is.na(municipio) & municipio != "") ~ "Municipal",
        TRUE ~ "Unknown"
      ),
      
      # Extract geographic identifiers
      state_name = case_when(
        !is.na(estado) & estado != "" ~ estado,
        str_detect(tolower(autoridade %||% ""), "são paulo") ~ "São Paulo",
        str_detect(tolower(autoridade %||% ""), "rio de janeiro") ~ "Rio de Janeiro",
        str_detect(tolower(autoridade %||% ""), "minas gerais") ~ "Minas Gerais",
        str_detect(tolower(autoridade %||% ""), "paraná") ~ "Paraná",
        str_detect(tolower(autoridade %||% ""), "rio grande do sul") ~ "Rio Grande do Sul",
        TRUE ~ NA_character_
      ),
      
      # Extract municipality information
      municipality_name = case_when(
        !is.na(municipio) & municipio != "" ~ municipio,
        str_detect(tolower(autoridade %||% ""), "prefeitura") ~ str_extract(autoridade, "(?<=prefeitura\\s+de\\s+)\\w+"),
        TRUE ~ NA_character_
      ),
      
      # Temporal information
      year = year(as.Date(data)),
      decade = floor(year / 10) * 10,
      
      # Policy type categorization
      policy_type = case_when(
        str_detect(tolower(tipo %||% ""), "lei") ~ "Lei",
        str_detect(tolower(tipo %||% ""), "decreto") ~ "Decreto",
        str_detect(tolower(tipo %||% ""), "resolução") ~ "Resolução",
        str_detect(tolower(tipo %||% ""), "portaria") ~ "Portaria",
        TRUE ~ "Outros"
      )
    ) %>%
    filter(!is.na(year), year >= 1900, year <= year(Sys.Date()))
  
  log_info("Prepared geospatial data with {nrow(geo_data)} records")
  
  return(geo_data)
}

#' Create regulatory density maps
#' @param geo_data Geospatial legislative data
#' @param boundaries Geographic boundaries
#' @param level Geographic aggregation level
#' @return List with density analysis results
create_regulatory_density_maps <- function(geo_data, boundaries, level = "state") {
  
  log_info("Creating regulatory density maps...")
  
  # Aggregate data by geographic unit
  if (level == "state") {
    density_data <- geo_data %>%
      filter(authority_level %in% c("Federal", "State")) %>%
      group_by(state_name, authority_level, categoria, decade) %>%
      summarise(
        count = n(),
        avg_per_year = count / 10,  # Average per year in decade
        .groups = "drop"
      ) %>%
      filter(!is.na(state_name))
    
    # Join with boundaries
    boundaries_joined <- boundaries %>%
      left_join(
        density_data %>%
          group_by(state_name = name_state) %>%
          summarise(
            total_regulations = sum(count, na.rm = TRUE),
            federal_regulations = sum(count[authority_level == "Federal"], na.rm = TRUE),
            state_regulations = sum(count[authority_level == "State"], na.rm = TRUE),
            avg_per_year = mean(avg_per_year, na.rm = TRUE),
            dominant_category = names(sort(table(categoria), decreasing = TRUE))[1],
            .groups = "drop"
          ),
        by = c("name_state" = "state_name")
      ) %>%
      replace_na(list(total_regulations = 0, federal_regulations = 0, 
                     state_regulations = 0, avg_per_year = 0))
    
  } else if (level == "municipality") {
    density_data <- geo_data %>%
      filter(authority_level == "Municipal") %>%
      group_by(municipality_name, state_name, categoria, decade) %>%
      summarise(
        count = n(),
        avg_per_year = count / 10,
        .groups = "drop"
      ) %>%
      filter(!is.na(municipality_name))
    
    # This would require municipality boundaries
    boundaries_joined <- NULL  # Placeholder for municipality analysis
  }
  
  # Calculate density statistics
  density_stats <- list(
    total_units = nrow(boundaries_joined),
    units_with_data = sum(boundaries_joined$total_regulations > 0, na.rm = TRUE),
    max_density = max(boundaries_joined$total_regulations, na.rm = TRUE),
    mean_density = mean(boundaries_joined$total_regulations, na.rm = TRUE),
    coverage_rate = sum(boundaries_joined$total_regulations > 0, na.rm = TRUE) / nrow(boundaries_joined)
  )
  
  log_info("Regulatory density analysis: {density_stats$units_with_data}/{density_stats$total_units} units with data")
  
  return(list(
    density_data = density_data,
    boundaries_with_data = boundaries_joined,
    density_stats = density_stats
  ))
}

#' Analyze policy adoption patterns
#' @param geo_data Geospatial legislative data
#' @param focus_state State to focus analysis on (default: "São Paulo")
#' @return Policy adoption analysis results
analyze_policy_adoption <- function(geo_data, focus_state = "São Paulo") {
  
  log_info("Analyzing policy adoption patterns...")
  
  # Federal vs State vs Municipal adoption patterns
  adoption_patterns <- geo_data %>%
    group_by(year, authority_level, categoria, modal) %>%
    summarise(count = n(), .groups = "drop") %>%
    arrange(year) %>%
    group_by(authority_level, categoria, modal) %>%
    mutate(
      cumulative_count = cumsum(count),
      adoption_rate = count / lag(cumulative_count, default = 1)
    ) %>%
    ungroup()
  
  # State-specific analysis (São Paulo)
  state_analysis <- geo_data %>%
    filter(state_name == focus_state | authority_level == "Federal") %>%
    group_by(year, authority_level, categoria) %>%
    summarise(count = n(), .groups = "drop") %>%
    pivot_wider(names_from = authority_level, values_from = count, values_fill = 0) %>%
    mutate(
      federal_state_ratio = State / (Federal + 1),  # +1 to avoid division by zero
      innovation_index = State / (Federal + State)  # Proportion of state innovation
    )
  
  # Policy diffusion timing
  diffusion_analysis <- geo_data %>%
    filter(!is.na(assuntos)) %>%
    # Extract key policy terms
    mutate(
      transport_policy = str_detect(tolower(assuntos), "transport|mobilidade"),
      environmental_policy = str_detect(tolower(assuntos), "ambiental|sustentável"),
      digital_policy = str_detect(tolower(assuntos), "digital|tecnologia|internet")
    ) %>%
    pivot_longer(cols = ends_with("_policy"), names_to = "policy_area", values_to = "has_policy") %>%
    filter(has_policy) %>%
    group_by(policy_area, year, authority_level) %>%
    summarise(adoptions = n(), .groups = "drop") %>%
    arrange(policy_area, year) %>%
    group_by(policy_area, authority_level) %>%
    mutate(
      first_adoption = min(year),
      adoption_lag = year - first_adoption,
      cumulative_adoptions = cumsum(adoptions)
    )
  
  log_info("Policy adoption analysis completed")
  
  return(list(
    adoption_patterns = adoption_patterns,
    state_analysis = state_analysis,
    diffusion_analysis = diffusion_analysis,
    focus_state = focus_state
  ))
}

#' Perform spatial diffusion analysis
#' @param geo_data Geospatial legislative data
#' @param boundaries Geographic boundaries with data
#' @return Spatial diffusion analysis results
analyze_spatial_diffusion <- function(geo_data, boundaries) {
  
  log_info("Performing spatial diffusion analysis...")
  
  # Create spatial weights matrix
  if (nrow(boundaries) > 1 && "geometry" %in% names(boundaries)) {
    
    tryCatch({
      # Convert to sp for spdep
      boundaries_sp <- as(boundaries, "Spatial")
      
      # Create neighbor list (queen contiguity)
      neighbors <- poly2nb(boundaries_sp, queen = TRUE)
      
      # Create spatial weights
      weights <- nb2listw(neighbors, style = "W", zero.policy = TRUE)
      
      # Moran's I test for spatial autocorrelation
      moran_results <- list()
      
      if ("total_regulations" %in% names(boundaries)) {
        reg_values <- boundaries$total_regulations
        reg_values[is.na(reg_values)] <- 0
        
        if (var(reg_values) > 0) {
          moran_test <- moran.test(reg_values, weights, zero.policy = TRUE)
          moran_results$total_regulations <- list(
            statistic = moran_test$statistic,
            p_value = moran_test$p.value,
            interpretation = ifelse(moran_test$p.value < 0.05, "Significant spatial clustering", "No significant spatial pattern")
          )
        }
      }
      
      # Local Moran's I (LISA)
      if (length(reg_values) > 5 && var(reg_values) > 0) {
        lisa_results <- localmoran(reg_values, weights, zero.policy = TRUE)
        
        boundaries$lisa_ii <- lisa_results[, 1]  # Local Moran's I
        boundaries$lisa_pvalue <- lisa_results[, 5]  # P-values
        boundaries$lisa_cluster <- case_when(
          lisa_results[, 5] < 0.05 & lisa_results[, 1] > 0 ~ "High-High",
          lisa_results[, 5] < 0.05 & lisa_results[, 1] < 0 ~ "Low-Low", 
          lisa_results[, 5] >= 0.05 ~ "Not significant",
          TRUE ~ "Other"
        )
      }
      
    }, error = function(e) {
      log_warn("Spatial analysis failed: {e$message}")
      moran_results <- list()
      neighbors <- NULL
      weights <- NULL
    })
    
  } else {
    log_warn("Insufficient data for spatial analysis")
    moran_results <- list()
    neighbors <- NULL
    weights <- NULL
  }
  
  # Temporal diffusion patterns
  temporal_diffusion <- geo_data %>%
    group_by(state_name, year, categoria) %>%
    summarise(count = n(), .groups = "drop") %>%
    group_by(categoria) %>%
    arrange(year) %>%
    mutate(
      adoption_order = dense_rank(year),
      early_adopter = adoption_order <= quantile(adoption_order, 0.25, na.rm = TRUE),
      late_adopter = adoption_order >= quantile(adoption_order, 0.75, na.rm = TRUE)
    ) %>%
    ungroup()
  
  log_info("Spatial diffusion analysis completed")
  
  return(list(
    moran_results = moran_results,
    neighbors = neighbors,
    weights = weights,
    boundaries_with_lisa = if(exists("lisa_results")) boundaries else NULL,
    temporal_diffusion = temporal_diffusion
  ))
}

#' Generate interactive geospatial visualizations
#' @param geo_results All geospatial analysis results
#' @param output_dir Output directory
generate_geospatial_visualizations <- function(geo_results, output_dir) {
  
  log_info("Generating geospatial visualizations...")
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # 1. Regulatory density choropleth map
  if (!is.null(geo_results$density$boundaries_with_data)) {
    
    # Static choropleth
    density_map <- ggplot(geo_results$density$boundaries_with_data) +
      geom_sf(aes(fill = total_regulations), color = "white", size = 0.2) +
      scale_fill_viridis_c(name = "Total\nRegulations", trans = "sqrt") +
      theme_void() +
      labs(title = "Regulatory Density by State",
           subtitle = "Total number of legislative documents") +
      theme(legend.position = "bottom")
    
    # Interactive choropleth with leaflet
    pal <- colorNumeric(palette = "viridis", domain = geo_results$density$boundaries_with_data$total_regulations)
    
    interactive_map <- leaflet(geo_results$density$boundaries_with_data) %>%
      addTiles() %>%
      addPolygons(
        fillColor = ~pal(total_regulations),
        weight = 1,
        opacity = 1,
        color = "white",
        dashArray = "3",
        fillOpacity = 0.7,
        popup = ~paste0(
          "<strong>", name_state, "</strong><br/>",
          "Total Regulations: ", total_regulations, "<br/>",
          "Federal: ", federal_regulations, "<br/>",
          "State: ", state_regulations, "<br/>",
          "Avg per Year: ", round(avg_per_year, 1)
        )
      ) %>%
      addLegend(
        pal = pal,
        values = ~total_regulations,
        opacity = 0.7,
        title = "Total Regulations",
        position = "bottomright"
      )
    
    # Save maps
    ggsave(file.path(output_dir, "regulatory_density_map.png"), density_map,
           width = 12, height = 8, dpi = 300)
    saveWidget(interactive_map, file.path(output_dir, "interactive_density_map.html"))
  }
  
  # 2. Policy adoption timeline
  if (!is.null(geo_results$adoption)) {
    adoption_timeline <- geo_results$adoption$adoption_patterns %>%
      filter(year >= 1990) %>%
      ggplot(aes(x = year, y = count, color = authority_level)) +
      geom_line(size = 1.2) +
      geom_smooth(method = "loess", se = FALSE, alpha = 0.7) +
      facet_wrap(~categoria, scales = "free_y") +
      scale_color_viridis_d() +
      labs(title = "Policy Adoption Patterns Over Time",
           subtitle = "By authority level and category",
           x = "Year", y = "Number of Adoptions", color = "Authority Level") +
      theme_minimal() +
      theme(legend.position = "bottom")
    
    ggsave(file.path(output_dir, "policy_adoption_timeline.png"), adoption_timeline,
           width = 14, height = 10, dpi = 300)
  }
  
  # 3. Federal vs State policy innovation
  if (!is.null(geo_results$adoption$state_analysis)) {
    innovation_plot <- geo_results$adoption$state_analysis %>%
      filter(year >= 2000) %>%
      ggplot(aes(x = year)) +
      geom_line(aes(y = Federal, color = "Federal"), size = 1.2) +
      geom_line(aes(y = State, color = "State"), size = 1.2) +
      facet_wrap(~categoria, scales = "free_y") +
      scale_color_manual(values = c("Federal" = "blue", "State" = "red")) +
      labs(title = paste("Federal vs", geo_results$adoption$focus_state, "State Policy Activity"),
           x = "Year", y = "Number of Policies", color = "Authority") +
      theme_minimal()
    
    ggsave(file.path(output_dir, "federal_vs_state_innovation.png"), innovation_plot,
           width = 12, height = 8, dpi = 300)
  }
  
  # 4. Policy diffusion heatmap
  if (!is.null(geo_results$adoption$diffusion_analysis)) {
    diffusion_heatmap <- geo_results$adoption$diffusion_analysis %>%
      ggplot(aes(x = year, y = authority_level, fill = adoptions)) +
      geom_tile() +
      facet_wrap(~policy_area) +
      scale_fill_viridis_c() +
      labs(title = "Policy Diffusion Patterns",
           subtitle = "Adoption intensity by policy area and authority level",
           x = "Year", y = "Authority Level", fill = "Adoptions") +
      theme_minimal() +
      theme(axis.text.x = element_text(angle = 45, hjust = 1))
    
    ggsave(file.path(output_dir, "policy_diffusion_heatmap.png"), diffusion_heatmap,
           width = 12, height = 8, dpi = 300)
  }
  
  # 5. Spatial autocorrelation results
  if (!is.null(geo_results$diffusion$boundaries_with_lisa)) {
    spatial_clusters_map <- ggplot(geo_results$diffusion$boundaries_with_lisa) +
      geom_sf(aes(fill = lisa_cluster), color = "white", size = 0.2) +
      scale_fill_brewer(type = "qual", palette = "Set1") +
      theme_void() +
      labs(title = "Spatial Clustering of Regulatory Activity",
           subtitle = "Based on Local Moran's I (LISA)",
           fill = "Cluster Type") +
      theme(legend.position = "bottom")
    
    ggsave(file.path(output_dir, "spatial_clusters_map.png"), spatial_clusters_map,
           width = 10, height = 8, dpi = 300)
  }
  
  log_info("Geospatial visualizations saved to {output_dir}")
}

#' Main geospatial analysis pipeline
#' @param data_source Path to data file or data frame
#' @param output_dir Output directory for results
run_geospatial_analysis <- function(data_source, output_dir) {
  
  log_info("=== STARTING GEOSPATIAL ANALYSIS PIPELINE ===")
  
  # 1. Load geographic boundaries
  state_boundaries <- load_brazil_boundaries("state")
  
  # 2. Prepare geospatial data
  geo_data <- prepare_geospatial_data(data_source)
  
  # 3. Create regulatory density maps
  density_results <- create_regulatory_density_maps(geo_data, state_boundaries)
  
  # 4. Analyze policy adoption patterns
  adoption_results <- analyze_policy_adoption(geo_data)
  
  # 5. Perform spatial diffusion analysis
  diffusion_results <- analyze_spatial_diffusion(geo_data, density_results$boundaries_with_data)
  
  # 6. Combine all results
  geo_results <- list(
    geo_data = geo_data,
    boundaries = state_boundaries,
    density = density_results,
    adoption = adoption_results,
    diffusion = diffusion_results
  )
  
  # 7. Generate visualizations
  generate_geospatial_visualizations(geo_results, output_dir)
  
  # 8. Save results
  saveRDS(geo_results, file.path(output_dir, "geospatial_analysis_results.rds"))
  write_parquet(geo_data, file.path(output_dir, "geospatial_legislative_data.parquet"))
  
  # 9. Generate summary statistics
  summary_stats <- list(
    total_documents = nrow(geo_data),
    states_with_data = length(unique(geo_data$state_name[!is.na(geo_data$state_name)])),
    federal_documents = sum(geo_data$authority_level == "Federal"),
    state_documents = sum(geo_data$authority_level == "State"),
    municipal_documents = sum(geo_data$authority_level == "Municipal"),
    coverage_rate = density_results$density_stats$coverage_rate,
    spatial_clustering = if(!is.null(diffusion_results$moran_results$total_regulations)) 
      diffusion_results$moran_results$total_regulations$interpretation else "Not calculated"
  )
  
  saveRDS(summary_stats, file.path(output_dir, "geospatial_summary_stats.rds"))
  
  log_info("=== GEOSPATIAL ANALYSIS COMPLETED ===")
  log_info("Analyzed {summary_stats$total_documents} documents across {summary_stats$states_with_data} states")
  log_info("Federal: {summary_stats$federal_documents}, State: {summary_stats$state_documents}, Municipal: {summary_stats$municipal_documents}")
  
  return(geo_results)
}

# Execute if run as script
if (!interactive()) {
  # Set paths
  parquet_file <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/parquet_dataset/combined_legislative_dataset.parquet"
  output_dir <- file.path(dirname(dirname(parquet_file)), "geospatial_analysis_results")
  
  # Check if Parquet file exists
  if (!file.exists(parquet_file)) {
    cat("Parquet file not found. Please run CSV to Parquet conversion first.\n")
    quit(status = 1)
  }
  
  # Run geospatial analysis
  results <- run_geospatial_analysis(parquet_file, output_dir)
  
  cat("Geospatial analysis completed. Results saved to:", output_dir, "\n")
}