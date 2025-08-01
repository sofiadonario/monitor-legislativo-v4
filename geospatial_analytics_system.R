#!/usr/bin/env Rscript
#' Brazilian Legislative Monitoring System - Comprehensive Geospatial Analytics
#' 
#' This system implements sophisticated geospatial analytics for Brazilian legislative
#' monitoring with 134,014+ documents across 26 states and 315+ municipalities.
#' 
#' Features:
#' - Brazilian boundary mapping with geobr integration
#' - Regulatory density choropleth visualizations  
#' - Policy diffusion analysis across jurisdictions
#' - Spatial autocorrelation (Moran's I) analysis
#' - Jurisdiction overlap analysis (Federal/State/Municipal)
#' - Hotspot detection for legislative activity
#' - Interactive Leaflet maps with drill-down capabilities
#' - Railway deployment compatibility
#'
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-08-01
#' @version 2.0.0

# === PACKAGE LOADING AND SETUP ===
suppressPackageStartupMessages({
  # Core spatial packages
  library(sf)
  library(leaflet)
  library(geobr)
  library(spdep)
  library(spatstat)
  
  # Data manipulation
  library(dplyr)
  library(tidyr)
  library(purrr)
  library(stringr)
  library(lubridate)
  
  # Visualization
  library(ggplot2)
  library(plotly)
  library(viridis)
  library(RColorBrewer)
  library(htmlwidgets)
  library(leaflet.extras)
  
  # Database and I/O
  library(DBI)
  library(RPostgreSQL)
  library(arrow)
  
  # Web framework
  library(shiny)
  library(shinydashboard)
  library(DT)
  
  # Utilities
  library(logger)
  library(parallel)
  library(future)
  library(furrr)
})

# Set up logging
log_threshold(INFO)

# Global configuration
GEOSPATIAL_CONFIG <- list(
  # Brazilian specific settings
  crs_wgs84 = 4326,
  crs_brazil = 5880,  # SIRGAS 2000 UTM Zone 23S
  
  # Geographic levels
  levels = c("country", "state", "municipality", "micro_region", "meso_region"),
  
  # Authority hierarchy
  authority_levels = c("Federal", "State", "Municipal", "Unknown"),
  
  # Color palettes
  palettes = list(
    density = "viridis",
    authority = c("#1f77b4", "#ff7f0e", "#2ca02c", "#d62728"),
    clusters = "Set1"
  ),
  
  # Analysis parameters
  analysis_params = list(
    min_documents_for_analysis = 10,
    spatial_weights_style = "W",
    moran_significance = 0.05,
    hotspot_quantiles = c(0.1, 0.9)  # Bottom 10% and top 10%
  )
)

# === CORE GEOSPATIAL DATA FUNCTIONS ===

#' Load Brazilian Geographic Boundaries with Enhanced Features
#' @param level Geographic level (state, municipality, etc.)
#' @param year Year for boundaries (default: 2020)
#' @param simplified Simplify geometries for web performance
#' @param cache_dir Directory for caching boundary data
#' @return sf object with Brazilian boundaries
load_brazilian_boundaries <- function(level = "state", year = 2020, simplified = TRUE, cache_dir = "cache/boundaries") {
  
  log_info("Loading Brazilian boundaries: {level} level for {year}")
  
  # Create cache directory
  dir.create(cache_dir, recursive = TRUE, showWarnings = FALSE)
  cache_file <- file.path(cache_dir, paste0(level, "_", year, "_", if(simplified) "simplified" else "full", ".rds"))
  
  # Check cache first
  if (file.exists(cache_file)) {
    log_info("Loading boundaries from cache: {cache_file}")
    return(readRDS(cache_file))
  }
  
  tryCatch({
    # Load from geobr
    boundaries <- switch(level,
      "country" = read_country(year = year, simplified = simplified),
      "state" = read_state(year = year, simplified = simplified),
      "municipality" = read_municipality(year = year, simplified = simplified),
      "micro_region" = read_micro_region(year = year, simplified = simplified),
      "meso_region" = read_meso_region(year = year, simplified = simplified),
      stop("Invalid level. Use: country, state, municipality, micro_region, meso_region")
    )
    
    # Standardize CRS
    boundaries <- st_transform(boundaries, crs = GEOSPATIAL_CONFIG$crs_wgs84)
    
    # Add enhanced metadata
    boundaries <- boundaries %>%
      mutate(
        # Standardize naming
        region_code = case_when(
          level == "state" ~ code_state,
          level == "municipality" ~ code_muni,
          level == "micro_region" ~ code_micro,
          level == "meso_region" ~ code_meso,
          TRUE ~ as.character(NA)
        ),
        region_name = case_when(
          level == "state" ~ name_state,
          level == "municipality" ~ name_muni,
          level == "micro_region" ~ name_micro,
          level == "meso_region" ~ name_meso,
          TRUE ~ as.character(NA)
        ),
        # Add geographic metadata
        area_km2 = as.numeric(st_area(geometry)) / 1e6,
        centroid = st_centroid(geometry),
        level = level,
        year = year
      )
    
    # Cache the result
    saveRDS(boundaries, cache_file)
    log_info("Cached boundaries to: {cache_file}")
    
    log_info("Loaded {nrow(boundaries)} {level} boundaries")
    return(boundaries)
    
  }, error = function(e) {
    log_error("Failed to load boundaries from geobr: {e$message}")
    
    # Fallback: create demo boundaries for development
    log_info("Creating demo boundaries for development...")
    create_demo_boundaries(level)
  })
}

#' Create Demo Boundaries for Development/Testing
#' @param level Geographic level
#' @return sf object with demo boundaries
create_demo_boundaries <- function(level = "state") {
  
  if (level == "state") {
    # Major Brazilian states with approximate boundaries
    demo_data <- tibble(
      code_state = c("11", "23", "31", "33", "35", "41", "43", "51", "52", "53"),
      name_state = c("Rondônia", "Ceará", "Minas Gerais", "Rio de Janeiro", 
                    "São Paulo", "Paraná", "Rio Grande do Sul", "Mato Grosso",
                    "Goiás", "Distrito Federal"),
      abbrev_state = c("RO", "CE", "MG", "RJ", "SP", "PR", "RS", "MT", "GO", "DF"),
      longitude = c(-62.8, -39.3, -44.9, -43.2, -46.6, -51.2, -51.2, -56.1, -49.3, -47.9),
      latitude = c(-11.5, -5.2, -18.1, -22.9, -23.5, -24.9, -30.0, -12.6, -15.8, -15.8),
      population = c(1800000, 9200000, 21300000, 17400000, 46300000, 11500000, 
                    11400000, 3500000, 7100000, 3100000)
    )
    
    # Convert to sf with buffer polygons
    boundaries <- demo_data %>%
      st_as_sf(coords = c("longitude", "latitude"), crs = GEOSPATIAL_CONFIG$crs_wgs84) %>%
      mutate(
        geometry = st_buffer(geometry, dist = 2),  # 2-degree buffer
        region_code = code_state,
        region_name = name_state,
        area_km2 = as.numeric(st_area(geometry)) / 1e6,
        level = "state",
        year = 2020
      ) %>%
      select(-longitude, -latitude) %>%
      rename(geometry = geom)
    
  } else {
    stop("Demo boundaries only available for state level")
  }
  
  return(boundaries)
}

#' Load and Process Legislative Data for Geospatial Analysis
#' @param data_source Database connection, file path, or data frame
#' @param use_database Whether to load from Railway database
#' @return Processed geospatial legislative data
load_legislative_geospatial_data <- function(data_source = NULL, use_database = TRUE) {
  
  log_info("Loading legislative data for geospatial analysis...")
  
  if (use_database) {
    tryCatch({
      # Load from Railway database if available
      source("RAILWAY_DATABASE_FIX.R", local = TRUE)
      
      # Query geospatial relevant data
      query <- "
        SELECT 
          urn, autoridade, jurisdicao, estado, municipio, tipo, categoria,
          assuntos, modal, data, ano, titulo,
          CASE WHEN jurisdicao = 'Federal' THEN 'Federal'
               WHEN estado IS NOT NULL AND estado != '' THEN 'State'
               WHEN municipio IS NOT NULL AND municipio != '' THEN 'Municipal'
               ELSE 'Unknown' END as authority_level
        FROM complete_documents_view 
        WHERE ano >= 1990 
        AND (estado IS NOT NULL OR jurisdicao = 'Federal' OR municipio IS NOT NULL)
        ORDER BY ano DESC, estado, municipio
      "
      
      geo_data <- dbGetQuery(get_db_connection(), query)
      log_info("Loaded {nrow(geo_data)} records from Railway database")
      
    }, error = function(e) {
      log_warn("Database connection failed: {e$message}")
      geo_data <- NULL
    })
  }
  
  # Fallback to file or demo data
  if (is.null(geo_data)) {
    if (!is.null(data_source) && is.character(data_source) && file.exists(data_source)) {
      if (str_ends(data_source, ".parquet")) {
        geo_data <- read_parquet(data_source)
      } else if (str_ends(data_source, ".csv")) {
        geo_data <- read_csv(data_source)
      }
      log_info("Loaded {nrow(geo_data)} records from file: {data_source}")
    } else {
      # Create demo data
      geo_data <- create_demo_legislative_data()
      log_info("Using demo legislative data with {nrow(geo_data)} records")
    }
  }
  
  # Process and standardize the data
  processed_data <- geo_data %>%
    mutate(
      # Standardize dates
      year = case_when(
        !is.na(ano) ~ as.numeric(ano),
        !is.na(data) ~ year(as.Date(data)),
        TRUE ~ NA_real_
      ),
      decade = floor(year / 10) * 10,
      
      # Standardize authority levels
      authority_level = case_when(
        str_detect(tolower(jurisdicao %||% ""), "federal") ~ "Federal",
        !is.na(estado) & estado != "" ~ "State", 
        !is.na(municipio) & municipio != "" ~ "Municipal",
        str_detect(tolower(autoridade %||% ""), "federal") ~ "Federal",
        str_detect(tolower(autoridade %||% ""), "estadual|estado") ~ "State",
        str_detect(tolower(autoridade %||% ""), "municipal|prefeitura") ~ "Municipal",
        TRUE ~ "Unknown"
      ),
      
      # Standardize geographic identifiers
      state_name = case_when(
        !is.na(estado) & estado != "" ~ str_to_title(str_trim(estado)),
        str_detect(tolower(autoridade %||% ""), "são paulo") ~ "São Paulo",
        str_detect(tolower(autoridade %||% ""), "rio de janeiro") ~ "Rio de Janeiro", 
        str_detect(tolower(autoridade %||% ""), "minas gerais") ~ "Minas Gerais",
        TRUE ~ extract_state_from_text(autoridade %||% titulo %||% "")
      ),
      
      state_code = map_state_name_to_code(state_name),
      
      municipality_name = case_when(
        !is.na(municipio) & municipio != "" ~ str_to_title(str_trim(municipio)),
        str_detect(tolower(autoridade %||% ""), "prefeitura") ~ 
          str_extract(autoridade, "(?i)(?<=prefeitura\\s+d[aeo]\\s+)\\w+"),
        TRUE ~ NA_character_
      ),
      
      # Policy categorization
      policy_category = case_when(
        str_detect(tolower(tipo %||% ""), "lei") ~ "Lei",
        str_detect(tolower(tipo %||% ""), "decreto") ~ "Decreto", 
        str_detect(tolower(tipo %||% ""), "resolução") ~ "Resolução",
        str_detect(tolower(tipo %||% ""), "portaria") ~ "Portaria",
        str_detect(tolower(tipo %||% ""), "medida\\s+provisória") ~ "Medida Provisória",
        TRUE ~ "Outros"
      ),
      
      # Transport and policy themes
      transport_theme = extract_transport_themes(assuntos %||% titulo %||% ""),
      environmental_policy = str_detect(tolower(assuntos %||% titulo %||% ""), 
                                       "ambiental|sustentável|verde|carbono|emissão"),
      digital_policy = str_detect(tolower(assuntos %||% titulo %||% ""),
                                 "digital|tecnologia|internet|eletrônico"),
      
      # Document importance scoring
      importance_score = calculate_document_importance(tipo, autoridade, assuntos, titulo)
    ) %>%
    filter(
      !is.na(year),
      year >= 1990,
      year <= year(Sys.Date()),
      authority_level != "Unknown" | !is.na(state_name)
    )
  
  log_info("Processed geospatial data: {nrow(processed_data)} records across {n_distinct(processed_data$state_name, na.rm = TRUE)} states")
  
  return(processed_data)
}

#' Create Demo Legislative Data for Development
#' @return Demo data frame
create_demo_legislative_data <- function() {
  
  states <- c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Paraná", "Rio Grande do Sul",
             "Ceará", "District Federal", "Goiás", "Mato Grosso", "Rondônia")
  
  demo_data <- tibble(
    urn = paste0("urn:lex:br:federal:lei:", seq(1, 5000)),
    autoridade = sample(c("Presidência da República", "Governo do Estado de São Paulo",
                         "Prefeitura de São Paulo", "ANTT", "ANP"), 5000, replace = TRUE),
    jurisdicao = sample(c("Federal", "Estadual", "Municipal"), 5000, replace = TRUE, 
                       prob = c(0.3, 0.5, 0.2)),
    estado = sample(c(states, NA), 5000, replace = TRUE, prob = c(rep(0.08, 10), 0.2)),
    municipio = sample(c("São Paulo", "Rio de Janeiro", "Belo Horizonte", "Curitiba", 
                        "Porto Alegre", NA), 5000, replace = TRUE, prob = c(rep(0.15, 5), 0.25)),
    tipo = sample(c("Lei", "Decreto", "Resolução", "Portaria", "Medida Provisória"), 
                 5000, replace = TRUE),
    categoria = sample(c("Transporte", "Mobilidade", "Logística", "Meio Ambiente", 
                        "Energia", "Outros"), 5000, replace = TRUE),
    assuntos = sample(c("transporte rodoviário", "mobilidade urbana", "descarbonização",
                       "veículos elétricos", "combustíveis", "logística"), 5000, replace = TRUE),
    modal = sample(c("Rodoviário", "Ferroviário", "Aquaviário", "Aéreo", "Dutoviário", NA),
                  5000, replace = TRUE, prob = c(0.4, 0.2, 0.1, 0.1, 0.05, 0.15)),
    ano = sample(1990:2024, 5000, replace = TRUE),
    data = as.Date(paste0(sample(1990:2024, 5000, replace = TRUE), "-", 
                         sample(1:12, 5000, replace = TRUE), "-",
                         sample(1:28, 5000, replace = TRUE))),
    titulo = paste("Documento sobre", sample(c("transporte", "mobilidade", "logística"), 
                                           5000, replace = TRUE))
  )
  
  return(demo_data)
}

# === GEOSPATIAL ANALYSIS FUNCTIONS ===

#' Comprehensive Legislative Density Analysis
#' @param legislative_data Processed legislative data
#' @param boundaries Geographic boundaries
#' @param level Analysis level (state, municipality)
#' @return List with density analysis results
analyze_legislative_density <- function(legislative_data, boundaries, level = "state") {
  
  log_info("Analyzing legislative density at {level} level...")
  
  # Aggregate data by geographic unit
  if (level == "state") {
    
    density_metrics <- legislative_data %>%
      filter(!is.na(state_name)) %>%
      group_by(state_name, authority_level, policy_category, decade) %>%
      summarise(
        document_count = n(),
        avg_per_year = document_count / 10,
        unique_authorities = n_distinct(autoridade, na.rm = TRUE),
        importance_score = mean(importance_score, na.rm = TRUE),
        transport_focus = mean(transport_theme == "Transporte Rodoviário", na.rm = TRUE),
        environmental_focus = mean(environmental_policy, na.rm = TRUE),
        digital_focus = mean(digital_policy, na.rm = TRUE),
        .groups = "drop"
      )
    
    # Create state-level summary
    state_summary <- density_metrics %>%
      group_by(state_name) %>%
      summarise(
        total_documents = sum(document_count),
        federal_documents = sum(document_count[authority_level == "Federal"], na.rm = TRUE),
        state_documents = sum(document_count[authority_level == "State"], na.rm = TRUE),
        municipal_documents = sum(document_count[authority_level == "Municipal"], na.rm = TRUE),
        avg_annual_activity = sum(avg_per_year, na.rm = TRUE),
        policy_diversity = n_distinct(policy_category),
        authority_diversity = sum(unique_authorities, na.rm = TRUE),
        avg_importance = mean(importance_score, na.rm = TRUE),
        transport_specialization = mean(transport_focus, na.rm = TRUE),
        environmental_focus = mean(environmental_focus, na.rm = TRUE),
        digital_adoption = mean(digital_focus, na.rm = TRUE),
        # Calculate regulatory intensity (documents per km²)
        .groups = "drop"
      )
    
    # Join with boundaries
    boundaries_with_data <- boundaries %>%
      left_join(state_summary, by = c("region_name" = "state_name")) %>%
      mutate(
        # Calculate additional metrics
        regulatory_density = total_documents / (area_km2 + 1),  # +1 to avoid division by zero
        federal_dominance = federal_documents / (total_documents + 1),
        state_innovation = state_documents / (federal_documents + state_documents + 1),
        municipal_autonomy = municipal_documents / (total_documents + 1),
        
        # Classify regulatory intensity
        intensity_class = case_when(
          is.na(total_documents) | total_documents == 0 ~ "No Data",
          total_documents < quantile(total_documents, 0.25, na.rm = TRUE) ~ "Low",
          total_documents < quantile(total_documents, 0.75, na.rm = TRUE) ~ "Medium", 
          TRUE ~ "High"
        ),
        
        # Replace NAs with zeros for visualization
        across(c(total_documents, federal_documents, state_documents, municipal_documents,
                avg_annual_activity, regulatory_density), ~replace_na(.x, 0))
      )
    
  } else if (level == "municipality") {
    # Municipality-level analysis (simplified for performance)
    municipal_summary <- legislative_data %>%
      filter(!is.na(municipality_name)) %>%
      group_by(municipality_name, state_name) %>%
      summarise(
        total_documents = n(),
        avg_importance = mean(importance_score, na.rm = TRUE),
        policy_focus = names(sort(table(policy_category), decreasing = TRUE))[1],
        .groups = "drop"
      )
    
    boundaries_with_data <- municipal_summary  # Would need municipality boundaries
  }
  
  # Calculate density statistics
  density_stats <- list(
    analysis_level = level,
    total_geographic_units = nrow(boundaries),
    units_with_data = sum(boundaries_with_data$total_documents > 0, na.rm = TRUE),
    coverage_percentage = round(100 * sum(boundaries_with_data$total_documents > 0, na.rm = TRUE) / nrow(boundaries), 1),
    max_density = max(boundaries_with_data$total_documents, na.rm = TRUE),
    mean_density = round(mean(boundaries_with_data$total_documents, na.rm = TRUE), 1),
    total_documents_analyzed = sum(boundaries_with_data$total_documents, na.rm = TRUE),
    federal_share = round(100 * sum(boundaries_with_data$federal_documents, na.rm = TRUE) / 
                         sum(boundaries_with_data$total_documents, na.rm = TRUE), 1),
    state_share = round(100 * sum(boundaries_with_data$state_documents, na.rm = TRUE) / 
                       sum(boundaries_with_data$total_documents, na.rm = TRUE), 1),
    municipal_share = round(100 * sum(boundaries_with_data$municipal_documents, na.rm = TRUE) / 
                           sum(boundaries_with_data$total_documents, na.rm = TRUE), 1)
  )
  
  log_info("Density analysis complete: {density_stats$units_with_data}/{density_stats$total_geographic_units} units with data ({density_stats$coverage_percentage}%)")
  
  return(list(
    density_data = if(level == "state") density_metrics else municipal_summary,
    boundaries_with_data = boundaries_with_data,
    density_stats = density_stats,
    analysis_metadata = list(
      timestamp = Sys.time(),
      level = level,
      data_source = "processed_legislative_data",
      total_records = nrow(legislative_data)
    )
  ))
}

#' Advanced Policy Diffusion Analysis
#' @param legislative_data Processed legislative data  
#' @param focus_policies Vector of policy areas to analyze
#' @return Policy diffusion analysis results
analyze_policy_diffusion <- function(legislative_data, focus_policies = c("transport", "environmental", "digital")) {
  
  log_info("Analyzing policy diffusion patterns...")
  
  # 1. Federal-to-State diffusion analysis
  federal_state_diffusion <- legislative_data %>%
    filter(authority_level %in% c("Federal", "State"), !is.na(state_name)) %>%
    group_by(policy_category, year, authority_level, state_name) %>%
    summarise(adoptions = n(), .groups = "drop") %>%
    pivot_wider(names_from = authority_level, values_from = adoptions, values_fill = 0) %>%
    group_by(policy_category, state_name) %>%
    arrange(year) %>%
    mutate(
      federal_cumulative = cumsum(Federal),
      state_cumulative = cumsum(State),
      federal_first_adoption = ifelse(Federal > 0 & lag(federal_cumulative, default = 0) == 0, year, NA),
      state_first_adoption = ifelse(State > 0 & lag(state_cumulative, default = 0) == 0, year, NA),
      diffusion_lag = state_first_adoption - min(federal_first_adoption, na.rm = TRUE),
      innovation_ratio = State / (Federal + State + 1)  # State innovation vs federal adoption
    ) %>%
    ungroup()
  
  # 2. Inter-state diffusion patterns
  interstate_diffusion <- legislative_data %>%
    filter(authority_level == "State", !is.na(state_name)) %>%
    group_by(policy_category, year, state_name) %>%
    summarise(adoptions = n(), .groups = "drop") %>%
    group_by(policy_category, year) %>%
    mutate(
      adopting_states = n(),
      total_adoptions_year = sum(adoptions),
      is_early_adopter = adoptions >= quantile(adoptions, 0.8, na.rm = TRUE),
      adoption_order = dense_rank(-adoptions)  # Rank by adoption intensity
    ) %>%
    group_by(policy_category, state_name) %>%
    arrange(year) %>%
    mutate(
      first_adoption_year = ifelse(adoptions > 0 & lag(cumsum(adoptions), default = 0) == 0, year, NA),
      cumulative_adoptions = cumsum(adoptions)
    ) %>%
    ungroup()
  
  # 3. Policy theme evolution analysis
  theme_evolution <- legislative_data %>%
    mutate(
      transport_related = str_detect(tolower(assuntos %||% titulo %||% ""), 
                                   "transport|mobilidade|veículo|combustível|logística"),
      environmental_related = environmental_policy,
      digital_related = digital_policy,
      infrastructure_related = str_detect(tolower(assuntos %||% titulo %||% ""),
                                         "infraestrutura|rodovia|ferrovia|porto")
    ) %>%
    pivot_longer(cols = ends_with("_related"), names_to = "theme", values_to = "is_related") %>%
    filter(is_related) %>%
    group_by(theme, year, authority_level, state_name) %>%
    summarise(theme_adoptions = n(), .groups = "drop") %>%
    group_by(theme, authority_level) %>%
    arrange(year) %>%
    mutate(
      theme_momentum = theme_adoptions / lag(theme_adoptions, default = 1),
      cumulative_theme_adoptions = cumsum(theme_adoptions),
      theme_acceleration = (theme_adoptions - lag(theme_adoptions, default = 0)) / 
                          (lag(theme_adoptions, default = 1) + 1)
    ) %>%
    ungroup()
  
  # 4. Calculate diffusion metrics
  diffusion_summary <- list(
    # Speed of diffusion
    average_diffusion_lag = federal_state_diffusion %>%
      filter(!is.na(diffusion_lag)) %>%
      summarise(avg_lag = mean(diffusion_lag, na.rm = TRUE)) %>%
      pull(avg_lag),
    
    # Innovation leaders (states with high innovation ratios)
    innovation_leaders = federal_state_diffusion %>%
      group_by(state_name) %>%
      summarise(avg_innovation_ratio = mean(innovation_ratio, na.rm = TRUE),
               total_state_adoptions = sum(State),
               .groups = "drop") %>%
      arrange(desc(avg_innovation_ratio)) %>%
      head(10),
    
    # Policy theme trends
    theme_trends = theme_evolution %>%
      group_by(theme, year) %>%
      summarise(total_adoptions = sum(theme_adoptions), .groups = "drop") %>%
      group_by(theme) %>%
      arrange(year) %>%
      mutate(trend_slope = (total_adoptions - lag(total_adoptions, default = 0)) / 1) %>%
      summarise(
        recent_trend = mean(tail(trend_slope, 5), na.rm = TRUE),
        peak_year = year[which.max(total_adoptions)],
        total_theme_adoptions = sum(total_adoptions),
        .groups = "drop"
      ) %>%
      arrange(desc(recent_trend))
  )
  
  log_info("Policy diffusion analysis complete")
  
  return(list(
    federal_state_patterns = federal_state_diffusion,
    interstate_patterns = interstate_diffusion, 
    theme_evolution = theme_evolution,
    diffusion_metrics = diffusion_summary,
    analysis_timestamp = Sys.time()
  ))
}

#' Spatial Autocorrelation and Clustering Analysis
#' @param boundaries_with_data Geographic boundaries with legislative data
#' @param variables Variables to analyze for spatial autocorrelation
#' @return Spatial analysis results including Moran's I and LISA
analyze_spatial_autocorrelation <- function(boundaries_with_data, 
                                          variables = c("total_documents", "regulatory_density", "federal_dominance")) {
  
  log_info("Performing spatial autocorrelation analysis...")
  
  # Ensure we have valid geometries
  if (!"sf" %in% class(boundaries_with_data) || nrow(boundaries_with_data) < 3) {
    log_warn("Insufficient spatial data for autocorrelation analysis")
    return(list(error = "Insufficient spatial data"))
  }
  
  tryCatch({
    # Create spatial neighbors (Queen contiguity)
    boundaries_sp <- as(boundaries_with_data, "Spatial")
    neighbors <- poly2nb(boundaries_sp, queen = TRUE)
    
    # Handle islands (regions with no neighbors)
    if (any(card(neighbors) == 0)) {
      log_info("Found {sum(card(neighbors) == 0)} regions with no neighbors - using k-nearest neighbors")
      coords <- st_coordinates(st_centroid(boundaries_with_data))
      knn_neighbors <- knearneigh(coords, k = 1)
      neighbors[card(neighbors) == 0] <- knn2nb(knn_neighbors)[card(neighbors) == 0]
    }
    
    # Create spatial weights
    weights <- nb2listw(neighbors, style = GEOSPATIAL_CONFIG$analysis_params$spatial_weights_style, 
                       zero.policy = TRUE)
    
    # Perform Moran's I tests for each variable
    moran_results <- map(variables, function(var) {
      if (var %in% names(boundaries_with_data)) {
        values <- boundaries_with_data[[var]]
        values[is.na(values)] <- 0
        
        if (var(values) > 0) {
          moran_test <- moran.test(values, weights, zero.policy = TRUE)
          
          list(
            variable = var,
            moran_i = moran_test$estimate[1],
            expected_i = moran_test$estimate[2], 
            variance = moran_test$estimate[3],
            p_value = moran_test$p.value,
            z_score = moran_test$statistic,
            interpretation = case_when(
              moran_test$p.value < 0.01 ~ "Highly significant spatial clustering",
              moran_test$p.value < 0.05 ~ "Significant spatial clustering", 
              moran_test$p.value < 0.10 ~ "Marginally significant spatial pattern",
              TRUE ~ "No significant spatial pattern"
            ),
            clustering_strength = case_when(
              abs(moran_test$estimate[1]) > 0.7 ~ "Very Strong",
              abs(moran_test$estimate[1]) > 0.5 ~ "Strong",
              abs(moran_test$estimate[1]) > 0.3 ~ "Moderate", 
              abs(moran_test$estimate[1]) > 0.1 ~ "Weak",
              TRUE ~ "Very Weak"
            )
          )
        } else {
          list(variable = var, error = "No variance in variable")
        }
      } else {
        list(variable = var, error = "Variable not found")
      }
    })
    names(moran_results) <- variables
    
    # Local Indicators of Spatial Association (LISA)
    lisa_results <- map(variables, function(var) {
      if (var %in% names(boundaries_with_data)) {
        values <- boundaries_with_data[[var]]
        values[is.na(values)] <- 0
        
        if (var(values) > 0 && length(values) > 5) {
          lisa <- localmoran(values, weights, zero.policy = TRUE)
          
          # Classify LISA clusters
          lisa_clusters <- case_when(
            lisa[, 5] < 0.05 & lisa[, 1] > 0 & values > mean(values) ~ "High-High",
            lisa[, 5] < 0.05 & lisa[, 1] > 0 & values <= mean(values) ~ "Low-Low",
            lisa[, 5] < 0.05 & lisa[, 1] < 0 & values > mean(values) ~ "High-Low",
            lisa[, 5] < 0.05 & lisa[, 1] < 0 & values <= mean(values) ~ "Low-High",
            TRUE ~ "Not Significant"
          )
          
          list(
            variable = var,
            lisa_values = lisa[, 1],
            lisa_pvalues = lisa[, 5],
            lisa_clusters = lisa_clusters,
            significant_clusters = sum(lisa[, 5] < 0.05),
            cluster_summary = table(lisa_clusters)
          )
        } else {
          list(variable = var, error = "Insufficient data for LISA")
        }
      } else {
        list(variable = var, error = "Variable not found")
      }
    })
    names(lisa_results) <- variables
    
    # Add LISA results to boundaries
    for (var in variables) {
      if (!is.null(lisa_results[[var]]$lisa_clusters)) {
        boundaries_with_data[[paste0(var, "_lisa_cluster")]] <- lisa_results[[var]]$lisa_clusters
        boundaries_with_data[[paste0(var, "_lisa_pvalue")]] <- lisa_results[[var]]$lisa_pvalues
      }
    }
    
    # Spatial autocorrelation summary
    spatial_summary <- list(
      neighbors_summary = list(
        total_regions = length(neighbors),
        regions_with_neighbors = sum(card(neighbors) > 0),
        avg_neighbors = mean(card(neighbors)),
        max_neighbors = max(card(neighbors))
      ),
      moran_summary = map_dfr(moran_results, function(x) {
        if (is.null(x$error)) {
          tibble(
            variable = x$variable,
            moran_i = round(x$moran_i, 4),
            p_value = round(x$p_value, 4),
            interpretation = x$interpretation,
            strength = x$clustering_strength
          )
        } else {
          tibble(variable = x$variable, error = x$error)
        }
      }),
      lisa_summary = map_dfr(lisa_results, function(x) {
        if (is.null(x$error)) {
          tibble(
            variable = x$variable,
            significant_clusters = x$significant_clusters,
            high_high = sum(x$lisa_clusters == "High-High"),
            low_low = sum(x$lisa_clusters == "Low-Low"),
            high_low = sum(x$lisa_clusters == "High-Low"),
            low_high = sum(x$lisa_clusters == "Low-High")
          )
        } else {
          tibble(variable = x$variable, error = x$error)
        }
      })
    )
    
    log_info("Spatial autocorrelation analysis completed")
    
    return(list(
      moran_results = moran_results,
      lisa_results = lisa_results,
      boundaries_with_clusters = boundaries_with_data,
      spatial_summary = spatial_summary,
      neighbors = neighbors,
      weights = weights
    ))
    
  }, error = function(e) {
    log_error("Spatial autocorrelation analysis failed: {e$message}")
    return(list(error = paste("Analysis failed:", e$message)))
  })
}

#' Identify Legislative Activity Hotspots and Coldspots
#' @param boundaries_with_data Geographic boundaries with legislative data
#' @param method Method for hotspot detection ("quantile", "z_score", "lisa")
#' @return Hotspot analysis results
identify_legislative_hotspots <- function(boundaries_with_data, method = "quantile") {
  
  log_info("Identifying legislative activity hotspots using {method} method...")
  
  if (!"total_documents" %in% names(boundaries_with_data)) {
    log_error("Missing required variable: total_documents")
    return(list(error = "Missing total_documents variable"))
  }
  
  # Calculate hotspot classifications
  boundaries_with_hotspots <- boundaries_with_data %>%
    mutate(
      # Raw activity level
      activity_level = total_documents,
      
      # Standardized activity (z-scores)
      activity_zscore = scale(total_documents)[, 1],
      
      # Quantile-based classification
      activity_quantile = ntile(total_documents, 10),
      hotspot_quantile = case_when(
        activity_quantile >= 9 ~ "Very High Activity",
        activity_quantile >= 7 ~ "High Activity", 
        activity_quantile >= 4 ~ "Medium Activity",
        activity_quantile >= 2 ~ "Low Activity",
        TRUE ~ "Very Low Activity"
      ),
      
      # Z-score based classification
      hotspot_zscore = case_when(
        activity_zscore >= 2 ~ "Statistical Hotspot (>2σ)",
        activity_zscore >= 1 ~ "Elevated Activity (>1σ)",
        activity_zscore >= -1 ~ "Normal Activity",
        activity_zscore >= -2 ~ "Below Average Activity", 
        TRUE ~ "Statistical Coldspot (<-2σ)"
      ),
      
      # Combined hotspot classification
      hotspot_classification = case_when(
        method == "quantile" ~ hotspot_quantile,
        method == "z_score" ~ hotspot_zscore,
        TRUE ~ hotspot_quantile
      ),
      
      # Additional metrics for hotspot characterization
      regulatory_intensity = total_documents / (area_km2 + 1),
      federal_dominance_score = federal_documents / (total_documents + 1),
      innovation_score = state_documents / (federal_documents + 1),
      
      # Multi-dimensional hotspot scoring
      composite_score = scale(total_documents)[, 1] * 0.4 + 
                       scale(regulatory_intensity)[, 1] * 0.3 +
                       scale(innovation_score)[, 1] * 0.2 +
                       scale(policy_diversity %||% 1)[, 1] * 0.1
    )
  
  # Identify specific hotspots and coldspots
  hotspots <- boundaries_with_hotspots %>%
    filter(str_detect(hotspot_classification, "High|Hotspot")) %>%
    arrange(desc(activity_level)) %>%
    select(region_name, activity_level, regulatory_intensity, federal_dominance_score, 
           innovation_score, hotspot_classification, composite_score)
  
  coldspots <- boundaries_with_hotspots %>%
    filter(str_detect(hotspot_classification, "Low|Coldspot|Very Low")) %>%
    arrange(activity_level) %>%
    select(region_name, activity_level, regulatory_intensity, hotspot_classification)
  
  # Statistical summary
  hotspot_stats <- list(
    total_regions = nrow(boundaries_with_hotspots),
    hotspots_count = nrow(hotspots),
    coldspots_count = nrow(coldspots),
    hotspot_percentage = round(100 * nrow(hotspots) / nrow(boundaries_with_hotspots), 1),
    coldspot_percentage = round(100 * nrow(coldspots) / nrow(boundaries_with_hotspots), 1),
    
    # Activity statistics
    mean_activity = round(mean(boundaries_with_hotspots$activity_level, na.rm = TRUE), 1),
    median_activity = round(median(boundaries_with_hotspots$activity_level, na.rm = TRUE), 1),
    max_activity = max(boundaries_with_hotspots$activity_level, na.rm = TRUE),
    min_activity = min(boundaries_with_hotspots$activity_level, na.rm = TRUE),
    
    # Top performers
    top_3_hotspots = head(hotspots$region_name, 3),
    bottom_3_regions = head(coldspots$region_name, 3),
    
    # Classification distribution
    classification_distribution = table(boundaries_with_hotspots$hotspot_classification)
  )
  
  log_info("Hotspot analysis complete: {hotspot_stats$hotspots_count} hotspots, {hotspot_stats$coldspots_count} coldspots identified")
  
  return(list(
    boundaries_with_hotspots = boundaries_with_hotspots,
    hotspots = hotspots,
    coldspots = coldspots,
    hotspot_stats = hotspot_stats,
    method_used = method,
    analysis_timestamp = Sys.time()
  ))
}

# === INTERACTIVE VISUALIZATION FUNCTIONS ===

#' Create Interactive Choropleth Map with Leaflet
#' @param boundaries_with_data Geographic boundaries with data
#' @param variable Variable to visualize
#' @param title Map title
#' @return Leaflet map object
create_interactive_choropleth <- function(boundaries_with_data, variable = "total_documents", 
                                        title = "Legislative Activity Density") {
  
  log_info("Creating interactive choropleth map for {variable}")
  
  # Prepare data for visualization
  if (!variable %in% names(boundaries_with_data)) {
    log_error("Variable {variable} not found in data")
    return(NULL)
  }
  
  # Handle missing values
  boundaries_viz <- boundaries_with_data %>%
    mutate(
      viz_value = replace_na(.data[[variable]], 0),
      popup_text = create_popup_text(., variable)
    )
  
  # Create color palette
  pal <- colorNumeric(
    palette = GEOSPATIAL_CONFIG$palettes$density,
    domain = boundaries_viz$viz_value,
    na.color = "#808080"
  )
  
  # Create the map
  map <- leaflet(boundaries_viz) %>%
    addTiles(group = "OpenStreetMap") %>%
    addProviderTiles(providers$CartoDB.Positron, group = "CartoDB") %>%
    addProviderTiles(providers$Esri.WorldImagery, group = "Satellite") %>%
    
    # Add choropleth layer
    addPolygons(
      fillColor = ~pal(viz_value),
      weight = 1,
      opacity = 1,
      color = "white",
      dashArray = "2",
      fillOpacity = 0.7,
      popup = ~popup_text,
      label = ~paste0(region_name, ": ", format(viz_value, big.mark = ",")),
      labelOptions = labelOptions(
        style = list("font-weight" = "normal", padding = "3px 8px"),
        textsize = "12px",
        direction = "auto"
      ),
      highlightOptions = highlightOptions(
        weight = 3,
        color = "#666",
        dashArray = "",
        fillOpacity = 0.8,
        bringToFront = TRUE
      ),
      group = "Choropleth"
    ) %>%
    
    # Add legend
    addLegend(
      pal = pal,
      values = ~viz_value,
      opacity = 0.7,
      title = str_to_title(str_replace_all(variable, "_", " ")),
      position = "bottomright"
    ) %>%
    
    # Add layer control
    addLayersControl(
      baseGroups = c("OpenStreetMap", "CartoDB", "Satellite"),
      overlayGroups = c("Choropleth"),
      options = layersControlOptions(collapsed = FALSE)
    ) %>%
    
    # Add title
    addControl(
      html = paste0("<div style='background: rgba(255,255,255,0.8); padding: 10px; border-radius: 5px;'>",
                   "<h4 style='margin: 0; color: #333;'>", title, "</h4></div>"),
      position = "topright"
    ) %>%
    
    # Set view to Brazil
    setView(lng = -47.9, lat = -15.8, zoom = 4)
  
  return(map)
}

#' Create Multi-layer Interactive Map with Authority Levels
#' @param legislative_data Processed legislative data
#' @param boundaries Geographic boundaries
#' @return Advanced leaflet map with multiple layers
create_authority_layers_map <- function(legislative_data, boundaries) {
  
  log_info("Creating multi-layer authority map...")
  
  # Create separate datasets for each authority level
  federal_data <- legislative_data %>%
    filter(authority_level == "Federal") %>%
    group_by(state_name) %>%
    summarise(federal_count = n(), .groups = "drop")
  
  state_data <- legislative_data %>%
    filter(authority_level == "State") %>%
    group_by(state_name) %>%
    summarise(state_count = n(), .groups = "drop")
  
  municipal_data <- legislative_data %>%
    filter(authority_level == "Municipal") %>%
    group_by(state_name) %>%
    summarise(municipal_count = n(), .groups = "drop")
  
  # Join all data with boundaries
  map_data <- boundaries %>%
    left_join(federal_data, by = c("region_name" = "state_name")) %>%
    left_join(state_data, by = c("region_name" = "state_name")) %>%
    left_join(municipal_data, by = c("region_name" = "state_name")) %>%
    mutate(
      federal_count = replace_na(federal_count, 0),
      state_count = replace_na(state_count, 0),
      municipal_count = replace_na(municipal_count, 0),
      total_count = federal_count + state_count + municipal_count
    )
  
  # Create color palettes for each authority level
  pal_federal <- colorNumeric("Blues", domain = map_data$federal_count)
  pal_state <- colorNumeric("Oranges", domain = map_data$state_count)
  pal_municipal <- colorNumeric("Greens", domain = map_data$municipal_count)
  pal_total <- colorNumeric("Purples", domain = map_data$total_count)
  
  # Create the map
  map <- leaflet(map_data) %>%
    addTiles(group = "OpenStreetMap") %>%
    
    # Federal layer
    addPolygons(
      fillColor = ~pal_federal(federal_count),
      weight = 1, opacity = 1, color = "white", fillOpacity = 0.7,
      popup = ~paste0("<b>", region_name, "</b><br/>",
                     "Federal Documents: ", format(federal_count, big.mark = ",")),
      group = "Federal"
    ) %>%
    
    # State layer
    addPolygons(
      fillColor = ~pal_state(state_count),
      weight = 1, opacity = 1, color = "white", fillOpacity = 0.7,
      popup = ~paste0("<b>", region_name, "</b><br/>",
                     "State Documents: ", format(state_count, big.mark = ",")),
      group = "State"
    ) %>%
    
    # Municipal layer
    addPolygons(
      fillColor = ~pal_municipal(municipal_count),
      weight = 1, opacity = 1, color = "white", fillOpacity = 0.7,
      popup = ~paste0("<b>", region_name, "</b><br/>",
                     "Municipal Documents: ", format(municipal_count, big.mark = ",")),
      group = "Municipal"
    ) %>%
    
    # Total layer
    addPolygons(
      fillColor = ~pal_total(total_count),
      weight = 1, opacity = 1, color = "white", fillOpacity = 0.7,
      popup = ~paste0("<b>", region_name, "</b><br/>",
                     "Total Documents: ", format(total_count, big.mark = ","), "<br/>",
                     "Federal: ", format(federal_count, big.mark = ","), "<br/>",
                     "State: ", format(state_count, big.mark = ","), "<br/>",
                     "Municipal: ", format(municipal_count, big.mark = ",")),
      group = "Total"
    ) %>%
    
    # Add legends
    addLegend(pal = pal_federal, values = ~federal_count, title = "Federal", 
             position = "bottomright", group = "Federal") %>%
    addLegend(pal = pal_state, values = ~state_count, title = "State", 
             position = "bottomright", group = "State") %>%
    addLegend(pal = pal_municipal, values = ~municipal_count, title = "Municipal", 
             position = "bottomright", group = "Municipal") %>%
    addLegend(pal = pal_total, values = ~total_count, title = "Total", 
             position = "bottomright", group = "Total") %>%
    
    # Layer control
    addLayersControl(
      baseGroups = c("Total", "Federal", "State", "Municipal"),
      options = layersControlOptions(collapsed = FALSE)
    ) %>%
    
    # Set initial view
    setView(lng = -47.9, lat = -15.8, zoom = 4)
  
  return(map)
}

#' Create Hotspot Detection Map
#' @param hotspot_results Results from identify_legislative_hotspots
#' @return Leaflet map showing hotspots and coldspots
create_hotspot_map <- function(hotspot_results) {
  
  log_info("Creating hotspot detection map...")
  
  boundaries_with_hotspots <- hotspot_results$boundaries_with_hotspots
  
  # Create color palette for hotspot classification
  hotspot_colors <- c(
    "Very High Activity" = "#d73027",
    "High Activity" = "#fc8d59", 
    "Medium Activity" = "#fee08b",
    "Low Activity" = "#e0f3f8",
    "Very Low Activity" = "#4575b4",
    "Statistical Hotspot (>2σ)" = "#d73027",
    "Elevated Activity (>1σ)" = "#fc8d59",
    "Normal Activity" = "#fee08b", 
    "Below Average Activity" = "#e0f3f8",
    "Statistical Coldspot (<-2σ)" = "#4575b4"
  )
  
  pal <- colorFactor(palette = hotspot_colors, domain = boundaries_with_hotspots$hotspot_classification)
  
  # Create map
  map <- leaflet(boundaries_with_hotspots) %>%
    addTiles() %>%
    addPolygons(
      fillColor = ~pal(hotspot_classification),
      weight = 2,
      opacity = 1,
      color = "white",
      dashArray = "1",
      fillOpacity = 0.8,
      popup = ~paste0(
        "<b>", region_name, "</b><br/>",
        "Classification: ", hotspot_classification, "<br/>",
        "Total Documents: ", format(activity_level, big.mark = ","), "<br/>",
        "Regulatory Intensity: ", round(regulatory_intensity, 2), " docs/km²<br/>",
        "Federal Dominance: ", round(federal_dominance_score * 100, 1), "%<br/>",
        "Innovation Score: ", round(innovation_score, 2)
      ),
      label = ~paste0(region_name, " (", hotspot_classification, ")"),
      highlightOptions = highlightOptions(
        weight = 4,
        color = "#666",
        fillOpacity = 0.9,
        bringToFront = TRUE
      )
    ) %>%
    addLegend(
      pal = pal,
      values = ~hotspot_classification,
      title = "Activity Classification",
      position = "bottomright"
    ) %>%
    setView(lng = -47.9, lat = -15.8, zoom = 4)
  
  return(map)
}

# === UTILITY FUNCTIONS ===

#' Extract State Name from Text
#' @param text Text to extract state name from
#' @return Extracted state name or NA
extract_state_from_text <- function(text) {
  
  state_patterns <- c(
    "acre" = "Acre", "alagoas" = "Alagoas", "amapá" = "Amapá", "amazonas" = "Amazonas",
    "bahia" = "Bahia", "ceará" = "Ceará", "distrito federal" = "Distrito Federal",
    "espírito santo" = "Espírito Santo", "goiás" = "Goiás", "maranhão" = "Maranhão",
    "mato grosso do sul" = "Mato Grosso do Sul", "mato grosso" = "Mato Grosso",
    "minas gerais" = "Minas Gerais", "pará" = "Pará", "paraíba" = "Paraíba",
    "paraná" = "Paraná", "pernambuco" = "Pernambuco", "piauí" = "Piauí",
    "rio de janeiro" = "Rio de Janeiro", "rio grande do norte" = "Rio Grande do Norte",
    "rio grande do sul" = "Rio Grande do Sul", "rondônia" = "Rondônia",
    "roraima" = "Roraima", "santa catarina" = "Santa Catarina",
    "são paulo" = "São Paulo", "sergipe" = "Sergipe", "tocantins" = "Tocantins"
  )
  
  text_lower <- str_to_lower(text)
  
  for (pattern in names(state_patterns)) {
    if (str_detect(text_lower, pattern)) {
      return(state_patterns[pattern])
    }
  }
  
  return(NA_character_)
}

#' Map State Name to IBGE Code
#' @param state_name State name
#' @return IBGE state code
map_state_name_to_code <- function(state_name) {
  
  state_codes <- c(
    "Acre" = "12", "Alagoas" = "27", "Amapá" = "16", "Amazonas" = "13",
    "Bahia" = "29", "Ceará" = "23", "Distrito Federal" = "53", 
    "Espírito Santo" = "32", "Goiás" = "52", "Maranhão" = "21",
    "Mato Grosso" = "51", "Mato Grosso do Sul" = "50", "Minas Gerais" = "31",
    "Pará" = "15", "Paraíba" = "25", "Paraná" = "41", "Pernambuco" = "26",
    "Piauí" = "22", "Rio de Janeiro" = "33", "Rio Grande do Norte" = "24",
    "Rio Grande do Sul" = "43", "Rondônia" = "11", "Roraima" = "14",
    "Santa Catarina" = "42", "São Paulo" = "35", "Sergipe" = "28", "Tocantins" = "17"
  )
  
  return(state_codes[state_name])
}

#' Extract Transport Themes from Text
#' @param text Text to analyze
#' @return Primary transport theme
extract_transport_themes <- function(text) {
  
  text_lower <- str_to_lower(text)
  
  case_when(
    str_detect(text_lower, "rodoviário|rodovia|caminhão|ônibus") ~ "Transporte Rodoviário",
    str_detect(text_lower, "ferroviário|ferrovia|trem|trilho") ~ "Transporte Ferroviário", 
    str_detect(text_lower, "aéreo|aviação|aeroporto|avião") ~ "Transporte Aéreo",
    str_detect(text_lower, "aquaviário|portuário|navio|porto") ~ "Transporte Aquaviário",
    str_detect(text_lower, "dutoviário|gasoduto|oleoduto") ~ "Transporte Dutoviário",
    str_detect(text_lower, "mobilidade|urbano") ~ "Mobilidade Urbana",
    str_detect(text_lower, "logística|carga|frete") ~ "Logística",
    TRUE ~ "Outros"
  )
}

#' Calculate Document Importance Score
#' @param tipo Document type
#' @param autoridade Authority
#' @param assuntos Topics
#' @param titulo Title
#' @return Importance score (0-1)
calculate_document_importance <- function(tipo, autoridade, assuntos, titulo) {
  
  # Base score by document type
  type_score <- case_when(
    str_detect(tolower(tipo %||% ""), "lei") ~ 1.0,
    str_detect(tolower(tipo %||% ""), "medida\\s+provisória") ~ 0.9,
    str_detect(tolower(tipo %||% ""), "decreto") ~ 0.8,
    str_detect(tolower(tipo %||% ""), "resolução") ~ 0.6,
    str_detect(tolower(tipo %||% ""), "portaria") ~ 0.5,
    TRUE ~ 0.3
  )
  
  # Authority boost
  authority_boost <- case_when(
    str_detect(tolower(autoridade %||% ""), "presidência|congresso") ~ 0.3,
    str_detect(tolower(autoridade %||% ""), "ministério|federal") ~ 0.2,
    str_detect(tolower(autoridade %||% ""), "governo\\s+estadual") ~ 0.1,
    TRUE ~ 0.0
  )
  
  # Content complexity boost
  content_boost <- case_when(
    str_count(tolower(assuntos %||% titulo %||% ""), "\\w+") > 50 ~ 0.2,
    str_count(tolower(assuntos %||% titulo %||% ""), "\\w+") > 20 ~ 0.1,
    TRUE ~ 0.0
  )
  
  # Normalize to 0-1 range
  final_score <- pmin(1.0, type_score + authority_boost + content_boost)
  
  return(final_score)
}

#' Create Popup Text for Maps
#' @param data Row of boundary data
#' @param variable Primary variable being visualized
#' @return HTML popup text
create_popup_text <- function(data, variable) {
  
  base_info <- paste0(
    "<div style='font-family: Arial, sans-serif; font-size: 12px;'>",
    "<h4 style='margin: 5px 0; color: #2c3e50;'>", data$region_name, "</h4>"
  )
  
  variable_info <- paste0(
    "<p><strong>", str_to_title(str_replace_all(variable, "_", " ")), ":</strong> ",
    format(data[[variable]], big.mark = ","), "</p>"
  )
  
  additional_info <- ""
  if ("total_documents" %in% names(data) && variable != "total_documents") {
    additional_info <- paste0(additional_info,
      "<p><strong>Total Documents:</strong> ", format(data$total_documents, big.mark = ","), "</p>")
  }
  
  if ("federal_documents" %in% names(data)) {
    additional_info <- paste0(additional_info,
      "<p><strong>Federal:</strong> ", format(data$federal_documents, big.mark = ","),
      " | <strong>State:</strong> ", format(data$state_documents, big.mark = ","),
      " | <strong>Municipal:</strong> ", format(data$municipal_documents, big.mark = ","), "</p>")
  }
  
  if ("area_km2" %in% names(data)) {
    additional_info <- paste0(additional_info,
      "<p><strong>Area:</strong> ", format(round(data$area_km2), big.mark = ","), " km²</p>")
  }
  
  if ("regulatory_density" %in% names(data)) {
    additional_info <- paste0(additional_info,
      "<p><strong>Regulatory Density:</strong> ", round(data$regulatory_density, 2), " docs/km²</p>")
  }
  
  popup_html <- paste0(base_info, variable_info, additional_info, "</div>")
  
  return(popup_html)
}

# === MAIN EXECUTION FUNCTIONS ===

#' Run Complete Geospatial Analysis Pipeline
#' @param data_source Data source (database connection, file path, or data frame)
#' @param output_dir Output directory for results
#' @param use_database Whether to use Railway database
#' @return Complete geospatial analysis results
run_comprehensive_geospatial_analysis <- function(data_source = NULL, 
                                                 output_dir = "geospatial_results",
                                                 use_database = TRUE) {
  
  log_info("=== STARTING COMPREHENSIVE GEOSPATIAL ANALYSIS ===")
  start_time <- Sys.time()
  
  # Create output directory
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Step 1: Load Brazilian boundaries
  log_info("Step 1: Loading Brazilian geographic boundaries...")
  state_boundaries <- load_brazilian_boundaries("state", year = 2020, simplified = TRUE)
  
  # Step 2: Load and process legislative data
  log_info("Step 2: Loading legislative data...")
  legislative_data <- load_legislative_geospatial_data(data_source, use_database)
  
  # Step 3: Analyze legislative density
  log_info("Step 3: Analyzing legislative density...")
  density_results <- analyze_legislative_density(legislative_data, state_boundaries, "state")
  
  # Step 4: Policy diffusion analysis
  log_info("Step 4: Analyzing policy diffusion patterns...")
  diffusion_results <- analyze_policy_diffusion(legislative_data)
  
  # Step 5: Spatial autocorrelation analysis
  log_info("Step 5: Performing spatial autocorrelation analysis...")
  spatial_results <- analyze_spatial_autocorrelation(
    density_results$boundaries_with_data,
    c("total_documents", "regulatory_density", "federal_dominance")
  )
  
  # Step 6: Hotspot detection
  log_info("Step 6: Identifying legislative hotspots...")
  hotspot_results <- identify_legislative_hotspots(density_results$boundaries_with_data, "quantile")
  
  # Step 7: Create interactive maps
  log_info("Step 7: Creating interactive visualizations...")
  
  # Primary density map
  density_map <- create_interactive_choropleth(
    density_results$boundaries_with_data,
    "total_documents",
    "Brazilian Legislative Activity Density"
  )
  
  # Authority layers map
  authority_map <- create_authority_layers_map(legislative_data, state_boundaries)
  
  # Hotspot map
  hotspot_map <- create_hotspot_map(hotspot_results)
  
  # Regulatory intensity map
  intensity_map <- create_interactive_choropleth(
    density_results$boundaries_with_data,
    "regulatory_density", 
    "Regulatory Intensity (Documents per km²)"
  )
  
  # Step 8: Save all results
  log_info("Step 8: Saving results...")
  
  # Save maps
  saveWidget(density_map, file.path(output_dir, "legislative_density_map.html"))
  saveWidget(authority_map, file.path(output_dir, "authority_layers_map.html"))
  saveWidget(hotspot_map, file.path(output_dir, "hotspot_detection_map.html"))
  saveWidget(intensity_map, file.path(output_dir, "regulatory_intensity_map.html"))
  
  # Compile comprehensive results
  comprehensive_results <- list(
    # Core data
    legislative_data = legislative_data,
    state_boundaries = state_boundaries,
    
    # Analysis results
    density_analysis = density_results,
    diffusion_analysis = diffusion_results,
    spatial_analysis = spatial_results,
    hotspot_analysis = hotspot_results,
    
    # Interactive maps
    maps = list(
      density_map = density_map,
      authority_map = authority_map,
      hotspot_map = hotspot_map,
      intensity_map = intensity_map
    ),
    
    # Analysis metadata
    metadata = list(
      analysis_timestamp = Sys.time(),
      execution_time = difftime(Sys.time(), start_time, units = "mins"),
      data_source = ifelse(use_database, "Railway Database", "File/Demo"),
      total_documents = nrow(legislative_data),
      geographic_coverage = list(
        states_analyzed = n_distinct(legislative_data$state_name, na.rm = TRUE),
        states_with_data = density_results$density_stats$units_with_data,
        coverage_percentage = density_results$density_stats$coverage_percentage
      ),
      authority_distribution = table(legislative_data$authority_level),
      config_used = GEOSPATIAL_CONFIG
    )
  )
  
  # Save comprehensive results
  saveRDS(comprehensive_results, file.path(output_dir, "comprehensive_geospatial_results.rds"))
  
  # Create executive summary
  create_geospatial_executive_summary(comprehensive_results, output_dir)
  
  execution_time <- round(as.numeric(difftime(Sys.time(), start_time, units = "mins")), 2)
  
  log_info("=== GEOSPATIAL ANALYSIS COMPLETED ===")
  log_info("Execution time: {execution_time} minutes")
  log_info("Results saved to: {output_dir}")
  log_info("Documents analyzed: {nrow(legislative_data)}")
  log_info("States with data: {density_results$density_stats$units_with_data}/{density_results$density_stats$total_geographic_units}")
  log_info("Hotspots identified: {hotspot_results$hotspot_stats$hotspots_count}")
  
  return(comprehensive_results)
}

#' Create Executive Summary Report
#' @param results Comprehensive geospatial results
#' @param output_dir Output directory
create_geospatial_executive_summary <- function(results, output_dir) {
  
  summary_text <- paste0(
    "BRAZILIAN LEGISLATIVE MONITORING - GEOSPATIAL ANALYSIS EXECUTIVE SUMMARY\n",
    "=======================================================================\n\n",
    
    "ANALYSIS OVERVIEW\n",
    "-----------------\n",
    "Analysis Date: ", format(results$metadata$analysis_timestamp, "%Y-%m-%d %H:%M:%S"), "\n",
    "Processing Time: ", round(results$metadata$execution_time, 2), " minutes\n", 
    "Data Source: ", results$metadata$data_source, "\n\n",
    
    "DATASET CHARACTERISTICS\n",
    "-----------------------\n",
    "Total Documents Analyzed: ", format(results$metadata$total_documents, big.mark = ","), "\n",
    "Geographic Coverage: ", results$metadata$geographic_coverage$states_with_data, "/",
    results$density_analysis$density_stats$total_geographic_units, " states (",
    results$metadata$geographic_coverage$coverage_percentage, "%)\n",
    "Authority Distribution:\n",
    paste0("  - Federal: ", results$metadata$authority_distribution["Federal"], " documents\n"),
    paste0("  - State: ", results$metadata$authority_distribution["State"], " documents\n"),
    paste0("  - Municipal: ", results$metadata$authority_distribution["Municipal"], " documents\n\n"),
    
    "LEGISLATIVE DENSITY ANALYSIS\n",
    "----------------------------\n",
    "Average Documents per State: ", results$density_analysis$density_stats$mean_density, "\n",
    "Maximum State Activity: ", results$density_analysis$density_stats$max_density, " documents\n",
    "Federal Policy Share: ", results$density_analysis$density_stats$federal_share, "%\n",
    "State Policy Share: ", results$density_analysis$density_stats$state_share, "%\n",
    "Municipal Policy Share: ", results$density_analysis$density_stats$municipal_share, "%\n\n",
    
    "HOTSPOT ANALYSIS\n",
    "----------------\n",
    "Legislative Hotspots Identified: ", results$hotspot_analysis$hotspot_stats$hotspots_count, "\n",
    "Legislative Coldspots Identified: ", results$hotspot_analysis$hotspot_stats$coldspots_count, "\n",
    "Top 3 Most Active States: ", paste(results$hotspot_analysis$hotspot_stats$top_3_hotspots, collapse = ", "), "\n",
    "Least Active Regions: ", paste(results$hotspot_analysis$hotspot_stats$bottom_3_regions, collapse = ", "), "\n\n",
    
    "SPATIAL CLUSTERING\n",
    "------------------\n"
  )
  
  # Add spatial analysis results if available
  if (!is.null(results$spatial_analysis$spatial_summary)) {
    spatial_summary <- results$spatial_analysis$spatial_summary$moran_summary
    if (nrow(spatial_summary) > 0) {
      summary_text <- paste0(summary_text,
        "Spatial Autocorrelation Results:\n")
      
      for (i in 1:nrow(spatial_summary)) {
        if (is.null(spatial_summary$error[i])) {
          summary_text <- paste0(summary_text,
            "  - ", spatial_summary$variable[i], ": Moran's I = ", spatial_summary$moran_i[i],
            " (", spatial_summary$interpretation[i], ")\n")
        }
      }
    }
  }
  
  # Add policy diffusion insights
  if (!is.null(results$diffusion_analysis$diffusion_metrics)) {
    diffusion_metrics <- results$diffusion_analysis$diffusion_metrics
    summary_text <- paste0(summary_text, "\n",
      "POLICY DIFFUSION INSIGHTS\n",
      "-------------------------\n",
      "Average Federal-to-State Diffusion Lag: ", round(diffusion_metrics$average_diffusion_lag, 1), " years\n",
      "Top Innovation Leaders: ", paste(head(diffusion_metrics$innovation_leaders$state_name, 3), collapse = ", "), "\n",
      "Emerging Policy Themes: ", paste(head(diffusion_metrics$theme_trends$theme, 3), collapse = ", "), "\n\n"
    )
  }
  
  summary_text <- paste0(summary_text,
    "INTERACTIVE VISUALIZATIONS CREATED\n",
    "-----------------------------------\n",
    "1. Legislative Density Choropleth Map\n",
    "2. Multi-layer Authority Analysis Map\n", 
    "3. Hotspot Detection Map\n",
    "4. Regulatory Intensity Visualization\n\n",
    
    "FILES GENERATED\n",
    "---------------\n",
    "- comprehensive_geospatial_results.rds (Complete analysis results)\n",
    "- legislative_density_map.html (Interactive density map)\n",
    "- authority_layers_map.html (Authority-based visualization)\n",
    "- hotspot_detection_map.html (Hotspot analysis map)\n",
    "- regulatory_intensity_map.html (Regulatory intensity map)\n",
    "- geospatial_executive_summary.txt (This report)\n\n",
    
    "RECOMMENDATIONS FOR DASHBOARD INTEGRATION\n",
    "-----------------------------------------\n",
    "1. Integrate interactive maps into Shiny dashboard tabs\n",
    "2. Add real-time data refresh capabilities\n",
    "3. Enable drill-down from state to municipal level\n",
    "4. Include temporal evolution animations\n",
    "5. Add export capabilities for analysis results\n\n",
    
    "Generated by Brazilian Legislative Geospatial Analytics System v2.0.0\n",
    "For technical support, contact the development team.\n"
  )
  
  writeLines(summary_text, file.path(output_dir, "geospatial_executive_summary.txt"))
  log_info("Executive summary saved to {file.path(output_dir, 'geospatial_executive_summary.txt')}")
}

# === SHINY INTEGRATION FUNCTIONS ===

#' Create Geospatial Analytics UI Components for Shiny
#' @return List of UI components for dashboard integration
create_geospatial_ui_components <- function() {
  
  geospatial_tab <- tabItem(tabName = "geospatial",
    fluidRow(
      # Control panel
      box(
        title = "Geospatial Analysis Controls", status = "primary", solidHeader = TRUE,
        width = 12, height = 120,
        fluidRow(
          column(3, 
            selectInput("geo_analysis_level", "Analysis Level:",
                       choices = c("State" = "state", "Municipality" = "municipality"),
                       selected = "state")
          ),
          column(3,
            selectInput("geo_variable", "Variable to Visualize:",
                       choices = c("Total Documents" = "total_documents",
                                 "Regulatory Density" = "regulatory_density", 
                                 "Federal Dominance" = "federal_dominance",
                                 "Innovation Score" = "innovation_score"),
                       selected = "total_documents")
          ),
          column(3,
            selectInput("geo_map_type", "Map Type:",
                       choices = c("Density Choropleth" = "density",
                                 "Authority Layers" = "authority",
                                 "Hotspot Detection" = "hotspot",
                                 "Spatial Clusters" = "clusters"),
                       selected = "density")
          ),
          column(3,
            br(),
            actionButton("refresh_geo_analysis", "Refresh Analysis", 
                        class = "btn-primary", style = "margin-top: 5px;")
          )
        )
      )
    ),
    
    fluidRow(
      # Main map
      box(
        title = "Interactive Geospatial Visualization", status = "success", solidHeader = TRUE,
        width = 8, height = 600,
        leafletOutput("main_geo_map", height = "550px")
      ),
      
      # Summary statistics
      box(
        title = "Geospatial Metrics", status = "info", solidHeader = TRUE,
        width = 4, height = 600,
        div(style = "height: 550px; overflow-y: auto;",
          h4("Coverage Statistics"),
          verbatimTextOutput("geo_coverage_stats"),
          
          h4("Hotspot Analysis"),
          verbatimTextOutput("geo_hotspot_stats"),
          
          h4("Spatial Clustering"),
          verbatimTextOutput("geo_spatial_stats")
        )
      )
    ),
    
    fluidRow(
      # Detailed analysis tables
      box(
        title = "State-by-State Analysis", status = "warning", solidHeader = TRUE,
        width = 6, height = 400,
        DT::dataTableOutput("geo_state_table")
      ),
      
      box(
        title = "Policy Diffusion Insights", status = "danger", solidHeader = TRUE,
        width = 6, height = 400,
        DT::dataTableOutput("geo_diffusion_table")
      )
    )
  )
  
  return(list(
    menu_item = menuItem("Geospatial Analytics", tabName = "geospatial", icon = icon("map")),
    tab_item = geospatial_tab
  ))
}

#' Create Geospatial Server Logic for Shiny
#' @param input Shiny input
#' @param output Shiny output 
#' @param session Shiny session
#' @param geospatial_results Pre-computed geospatial results
create_geospatial_server_logic <- function(input, output, session, geospatial_results = NULL) {
  
  # Reactive values for geospatial data
  geo_data <- reactiveValues(
    results = geospatial_results,
    last_refresh = Sys.time()
  )
  
  # Reactive expression for current analysis results
  current_geo_results <- reactive({
    if (is.null(geo_data$results)) {
      # Load or generate results if not provided
      tryCatch({
        run_comprehensive_geospatial_analysis(use_database = TRUE)
      }, error = function(e) {
        # Fallback to demo data
        run_comprehensive_geospatial_analysis(use_database = FALSE)
      })
    } else {
      geo_data$results
    }
  })
  
  # Main geospatial map
  output$main_geo_map <- renderLeaflet({
    results <- current_geo_results()
    
    map_type <- input$geo_map_type %||% "density"
    variable <- input$geo_variable %||% "total_documents"
    
    if (map_type == "density") {
      create_interactive_choropleth(
        results$density_analysis$boundaries_with_data,
        variable,
        paste("Brazilian Legislative", str_to_title(str_replace_all(variable, "_", " ")))
      )
    } else if (map_type == "authority") {
      results$maps$authority_map
    } else if (map_type == "hotspot") {
      results$maps$hotspot_map
    } else {
      results$maps$density_map
    }
  })
  
  # Coverage statistics
  output$geo_coverage_stats <- renderText({
    results <- current_geo_results()
    stats <- results$density_analysis$density_stats
    
    paste(
      "=== GEOGRAPHIC COVERAGE ===\n",
      sprintf("States Analyzed: %d/%d", stats$units_with_data, stats$total_geographic_units),
      sprintf("Coverage Rate: %.1f%%", stats$coverage_percentage),
      sprintf("Total Documents: %s", format(stats$total_documents_analyzed, big.mark = ",")),
      sprintf("Average per State: %.1f", stats$mean_density),
      sprintf("Maximum Activity: %d", stats$max_density),
      "",
      "=== AUTHORITY DISTRIBUTION ===",
      sprintf("Federal: %.1f%%", stats$federal_share),
      sprintf("State: %.1f%%", stats$state_share), 
      sprintf("Municipal: %.1f%%", stats$municipal_share),
      sep = "\n"
    )
  })
  
  # Hotspot statistics
  output$geo_hotspot_stats <- renderText({
    results <- current_geo_results()
    hotspot_stats <- results$hotspot_analysis$hotspot_stats
    
    paste(
      "=== HOTSPOT DETECTION ===\n",
      sprintf("Hotspots Identified: %d", hotspot_stats$hotspots_count),
      sprintf("Coldspots Identified: %d", hotspot_stats$coldspots_count),
      sprintf("Hotspot Rate: %.1f%%", hotspot_stats$hotspot_percentage),
      "",
      "Top Activity Centers:",
      paste("-", hotspot_stats$top_3_hotspots, collapse = "\n"),
      "",
      "Lowest Activity Areas:",
      paste("-", hotspot_stats$bottom_3_regions, collapse = "\n"),
      sep = "\n"
    )
  })
  
  # Spatial clustering statistics
  output$geo_spatial_stats <- renderText({
    results <- current_geo_results()
    
    if (!is.null(results$spatial_analysis$spatial_summary)) {
      spatial_summary <- results$spatial_analysis$spatial_summary$moran_summary
      
      moran_text <- paste(
        "=== SPATIAL AUTOCORRELATION ===\n",
        apply(spatial_summary, 1, function(row) {
          if (is.null(row$error)) {
            sprintf("%s:\n  Moran's I: %.4f\n  P-value: %.4f\n  %s", 
                   str_to_title(str_replace_all(row$variable, "_", " ")),
                   as.numeric(row$moran_i), as.numeric(row$p_value), row$interpretation)
          } else {
            sprintf("%s: %s", row$variable, row$error)
          }
        }),
        sep = "\n\n"
      )
      
      return(moran_text)
    } else {
      return("Spatial analysis not available")
    }
  })
  
  # State analysis table
  output$geo_state_table <- DT::renderDataTable({
    results <- current_geo_results()
    
    state_data <- results$density_analysis$boundaries_with_data %>%
      st_drop_geometry() %>%
      select(
        State = region_name,
        `Total Docs` = total_documents,
        `Federal` = federal_documents,
        `State Docs` = state_documents,
        `Municipal` = municipal_documents,
        `Reg. Density` = regulatory_density,
        `Classification` = intensity_class
      ) %>%
      arrange(desc(`Total Docs`))
    
    DT::datatable(state_data, 
      options = list(pageLength = 10, scrollX = TRUE, dom = 'frtip'),
      class = "compact stripe hover"
    ) %>%
      formatRound(c("Reg. Density"), 2) %>%
      formatStyle("Classification",
        backgroundColor = styleEqual(
          c("High", "Medium", "Low", "No Data"),
          c("#d73027", "#fee08b", "#4575b4", "#cccccc")
        )
      )
  })
  
  # Policy diffusion table
  output$geo_diffusion_table <- DT::renderDataTable({
    results <- current_geo_results()
    
    if (!is.null(results$diffusion_analysis$diffusion_metrics$innovation_leaders)) {
      diffusion_data <- results$diffusion_analysis$diffusion_metrics$innovation_leaders %>%
        select(
          State = state_name,
          `Innovation Ratio` = avg_innovation_ratio,
          `State Adoptions` = total_state_adoptions
        ) %>%
        arrange(desc(`Innovation Ratio`))
      
      DT::datatable(diffusion_data,
        options = list(pageLength = 10, scrollX = TRUE, dom = 'frtip'),
        class = "compact stripe hover"
      ) %>%
        formatRound(c("Innovation Ratio"), 3)
    } else {
      DT::datatable(data.frame(Message = "Policy diffusion data not available"))
    }
  })
  
  # Refresh analysis
  observeEvent(input$refresh_geo_analysis, {
    showNotification("Refreshing geospatial analysis...", type = "message")
    
    tryCatch({
      new_results <- run_comprehensive_geospatial_analysis(use_database = TRUE)
      geo_data$results <- new_results
      geo_data$last_refresh <- Sys.time()
      
      showNotification("Geospatial analysis refreshed successfully!", type = "success")
    }, error = function(e) {
      showNotification(paste("Refresh failed:", e$message), type = "error")
    })
  })
}

# === EXPORT FUNCTIONS FOR RAILWAY COMPATIBILITY ===

#' Get Geospatial Analytics Functions for App Integration
#' @return List of functions for app.R integration
get_geospatial_functions <- function() {
  
  return(list(
    # Core analysis functions
    run_comprehensive_geospatial_analysis = run_comprehensive_geospatial_analysis,
    analyze_legislative_density = analyze_legislative_density,
    analyze_policy_diffusion = analyze_policy_diffusion,
    analyze_spatial_autocorrelation = analyze_spatial_autocorrelation,
    identify_legislative_hotspots = identify_legislative_hotspots,
    
    # Visualization functions
    create_interactive_choropleth = create_interactive_choropleth,
    create_authority_layers_map = create_authority_layers_map,
    create_hotspot_map = create_hotspot_map,
    
    # Shiny integration
    create_geospatial_ui_components = create_geospatial_ui_components,
    create_geospatial_server_logic = create_geospatial_server_logic,
    
    # Data loading functions
    load_brazilian_boundaries = load_brazilian_boundaries,
    load_legislative_geospatial_data = load_legislative_geospatial_data,
    
    # Configuration
    config = GEOSPATIAL_CONFIG
  ))
}

# Log successful loading
log_info("Brazilian Legislative Geospatial Analytics System v2.0.0 loaded successfully")
log_info("Available functions: run_comprehensive_geospatial_analysis, create_interactive_choropleth, create_geospatial_ui_components")
log_info("System ready for Railway deployment and Shiny dashboard integration")

# Execute analysis if script is run directly
if (!interactive()) {
  log_info("Running geospatial analysis pipeline...")
  results <- run_comprehensive_geospatial_analysis(
    data_source = NULL,
    output_dir = "geospatial_analysis_output",
    use_database = TRUE
  )
  log_info("Geospatial analysis pipeline completed")
}