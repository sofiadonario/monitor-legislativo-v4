# Advanced Spatial Analysis for Monitor Legislativo v4
# IBGE data integration with spatial models and coordinate systems

library(sf)
library(geobr)
library(dplyr)
library(leaflet)
library(tmap)
library(sp)
library(rgdal)
library(raster)
library(lwgeom)

# Spatial analysis configuration
SPATIAL_CONFIG <- list(
  default_crs = "EPSG:4674",  # SIRGAS 2000 - Brazilian standard
  utm_zones = list(
    "18S" = "EPSG:31978",  # North/Northeast
    "19S" = "EPSG:31979",  # Northeast
    "20S" = "EPSG:31980",  # Southeast
    "21S" = "EPSG:31981",  # Southeast/South
    "22S" = "EPSG:31982",  # South
    "23S" = "EPSG:31983",  # South/Southwest
    "24S" = "EPSG:31984"   # Southwest
  ),
  clustering_radius = 50000,  # 50km for document clustering
  analysis_buffer = 25000,    # 25km buffer for spatial analysis
  min_points_cluster = 3      # Minimum documents for cluster
)

#' Enhanced IBGE data loader with spatial models
#' @param year Data year (default: 2020)
#' @param level Geographic level ("state", "municipality", "region")
#' @param simplified Use simplified geometries
#' @return SF object with enhanced spatial data
load_enhanced_ibge_data <- function(year = 2020, level = "state", simplified = TRUE) {
  
  log_event(paste("Loading enhanced IBGE data:", level, "level for", year))
  
  tryCatch({
    
    # Load appropriate geographic level
    geo_data <- switch(level,
      "state" = geobr::read_state(year = year, simplified = simplified, showProgress = FALSE),
      "municipality" = geobr::read_municipality(year = year, simplified = simplified, showProgress = FALSE),
      "region" = geobr::read_region(year = year, simplified = simplified, showProgress = FALSE),
      "country" = geobr::read_country(year = year, simplified = simplified, showProgress = FALSE),
      stop("Invalid geographic level")
    )
    
    # Ensure proper CRS
    if (is.null(st_crs(geo_data))) {
      geo_data <- st_set_crs(geo_data, SPATIAL_CONFIG$default_crs)
    } else {
      geo_data <- st_transform(geo_data, SPATIAL_CONFIG$default_crs)
    }
    
    # Enhance with spatial attributes
    enhanced_data <- enhance_spatial_attributes(geo_data, level)
    
    # Add population data if available
    if (level %in% c("state", "municipality")) {
      enhanced_data <- add_population_data(enhanced_data, year, level)
    }
    
    # Add economic indicators
    if (level %in% c("state", "municipality")) {
      enhanced_data <- add_economic_indicators(enhanced_data, year, level)
    }
    
    log_event(paste("Enhanced IBGE data loaded:", nrow(enhanced_data), "features"))
    return(enhanced_data)
    
  }, error = function(e) {
    log_event(paste("Error loading IBGE data:", e$message), "ERROR")
    return(create_fallback_spatial_data(level))
  })
}

#' Enhance spatial attributes for geographic data
#' @param geo_data SF object with geographic data
#' @param level Geographic level
#' @return Enhanced SF object
enhance_spatial_attributes <- function(geo_data, level) {
  
  log_event("Enhancing spatial attributes")
  
  # Calculate basic geometric properties
  enhanced <- geo_data %>%
    mutate(
      # Area calculations
      area_km2 = as.numeric(st_area(geom)) / 1000000,
      
      # Centroid coordinates
      centroid = st_centroid(geom),
      centroid_lat = st_coordinates(centroid)[, 2],
      centroid_lng = st_coordinates(centroid)[, 1],
      
      # Bounding box
      bbox = st_bbox(geom),
      
      # Perimeter length
      perimeter_km = as.numeric(st_length(st_cast(geom, "MULTILINESTRING"))) / 1000,
      
      # Compactness index (area/perimeter ratio)
      compactness = area_km2 / (perimeter_km^2),
      
      # Geographic region classification
      region_code = case_when(
        level == "state" ~ classify_state_region(code_state %||% abbrev_state),
        level == "municipality" ~ classify_municipality_region(code_state %||% abbrev_state),
        TRUE ~ NA_character_
      ),
      
      # Urban classification (simplified)
      urban_classification = classify_urban_level(area_km2, name_state %||% name_muni),
      
      # Legislative importance score
      legislative_importance = calculate_legislative_importance(level, area_km2, name_state %||% name_muni)
    ) %>%
    select(-centroid)  # Remove temporary centroid column
  
  return(enhanced)
}

#' Classify state/municipality region
#' @param state_codes Vector of state codes
#' @return Vector of region classifications
classify_state_region <- function(state_codes) {
  
  region_mapping <- list(
    "Norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
    "Nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
    "Centro-Oeste" = c("DF", "GO", "MT", "MS"),
    "Sudeste" = c("ES", "MG", "RJ", "SP"),
    "Sul" = c("PR", "RS", "SC")
  )
  
  sapply(state_codes, function(code) {
    for (region in names(region_mapping)) {
      if (code %in% region_mapping[[region]]) {
        return(region)
      }
    }
    return("Não Classificado")
  })
}

#' Classify municipality region
#' @param state_codes Vector of state codes
#' @return Vector of region classifications
classify_municipality_region <- function(state_codes) {
  classify_state_region(state_codes)
}

#' Classify urban development level
#' @param areas Vector of areas in km²
#' @param names Vector of location names
#' @return Vector of urban classifications
classify_urban_level <- function(areas, names) {
  
  mapply(function(area, name) {
    
    # Metropolitan areas (major capitals)
    major_metros <- c("São Paulo", "Rio de Janeiro", "Salvador", "Brasília", 
                     "Fortaleza", "Belo Horizonte", "Manaus", "Curitiba", 
                     "Recife", "Porto Alegre")
    
    if (any(sapply(major_metros, function(metro) str_detect(name, metro)))) {
      return("Metropolitana")
    }
    
    # Large urban areas
    if (area <= 300 && str_detect(name, "Capital|Grande")) {
      return("Grande Urbana")
    }
    
    # Medium urban areas
    if (area <= 1000) {
      return("Média Urbana")
    }
    
    # Small urban areas
    if (area <= 5000) {
      return("Pequena Urbana")
    }
    
    # Rural areas
    return("Rural")
    
  }, areas, names)
}

#' Calculate legislative importance score
#' @param level Geographic level
#' @param areas Vector of areas
#' @param names Vector of names
#' @return Vector of importance scores
calculate_legislative_importance <- function(level, areas, names) {
  
  mapply(function(area, name) {
    
    score <- 0
    
    # Base score by level
    if (level == "state") score <- score + 50
    else if (level == "municipality") score <- score + 20
    
    # Population proxy (inverse of area for urban areas)
    if (area <= 500) score <- score + 30
    else if (area <= 2000) score <- score + 20
    else if (area <= 10000) score <- score + 10
    
    # Capital/major city bonus
    capitals <- c("São Paulo", "Rio de Janeiro", "Salvador", "Brasília", 
                 "Fortaleza", "Belo Horizonte", "Manaus", "Curitiba", 
                 "Recife", "Porto Alegre", "Goiânia", "Belém")
    
    if (any(sapply(capitals, function(cap) str_detect(name, cap)))) {
      score <- score + 40
    }
    
    return(min(score, 100))
    
  }, areas, names)
}

#' Add population data to geographic features
#' @param geo_data SF object
#' @param year Data year
#' @param level Geographic level
#' @return Enhanced SF object with population
add_population_data <- function(geo_data, year, level) {
  
  log_event("Adding population data")
  
  tryCatch({
    
    # Load population estimates from geobr
    if (level == "state") {
      pop_data <- geobr::read_pop_arrangements(year = year, showProgress = FALSE)
    } else {
      # For municipalities, use simplified population model
      geo_data$pop_estimate <- estimate_population_from_area(geo_data$area_km2, geo_data$urban_classification)
      return(geo_data)
    }
    
    # Join population data
    if (!is.null(pop_data)) {
      enhanced <- geo_data %>%
        left_join(
          pop_data %>% select(code_state, pop_2020 = pop),
          by = "code_state"
        ) %>%
        mutate(
          population = coalesce(pop_2020, 0),
          pop_density = population / area_km2
        ) %>%
        select(-pop_2020)
    } else {
      geo_data$population <- estimate_population_from_area(geo_data$area_km2, geo_data$urban_classification)
      geo_data$pop_density <- geo_data$population / geo_data$area_km2
      enhanced <- geo_data
    }
    
    return(enhanced)
    
  }, error = function(e) {
    log_event(paste("Error adding population data:", e$message), "WARN")
    geo_data$population <- estimate_population_from_area(geo_data$area_km2, geo_data$urban_classification)
    geo_data$pop_density <- geo_data$population / geo_data$area_km2
    return(geo_data)
  })
}

#' Estimate population from area and urban classification
#' @param areas Vector of areas
#' @param urban_types Vector of urban classifications
#' @return Vector of population estimates
estimate_population_from_area <- function(areas, urban_types) {
  
  mapply(function(area, urban_type) {
    
    # Density estimates by urban classification (people per km²)
    density_estimates <- list(
      "Metropolitana" = 7000,
      "Grande Urbana" = 3000,
      "Média Urbana" = 1500,
      "Pequena Urbana" = 500,
      "Rural" = 50
    )
    
    density <- density_estimates[[urban_type]] %||% 200
    
    # Apply area factor (smaller areas have higher density)
    if (area <= 100) density <- density * 1.5
    else if (area <= 500) density <- density * 1.2
    else if (area >= 50000) density <- density * 0.3
    
    return(round(area * density))
    
  }, areas, urban_types)
}

#' Add economic indicators to geographic features
#' @param geo_data SF object
#' @param year Data year
#' @param level Geographic level
#' @return Enhanced SF object with economic data
add_economic_indicators <- function(geo_data, year, level) {
  
  log_event("Adding economic indicators")
  
  # Simplified economic indicators based on geographic characteristics
  enhanced <- geo_data %>%
    mutate(
      # GDP per capita estimate (simplified model)
      gdp_per_capita_estimate = estimate_gdp_per_capita(
        urban_classification, region_code, area_km2
      ),
      
      # Economic development index
      development_index = calculate_development_index(
        urban_classification, legislative_importance, area_km2
      ),
      
      # Transport infrastructure score
      transport_score = estimate_transport_infrastructure(
        urban_classification, area_km2, legislative_importance
      ),
      
      # Legislative activity potential
      legislative_potential = calculate_legislative_potential(
        legislative_importance, development_index, transport_score
      )
    )
  
  return(enhanced)
}

#' Estimate GDP per capita based on geographic characteristics
#' @param urban_types Vector of urban classifications
#' @param regions Vector of regions
#' @param areas Vector of areas
#' @return Vector of GDP estimates
estimate_gdp_per_capita <- function(urban_types, regions, areas) {
  
  mapply(function(urban_type, region, area) {
    
    # Base GDP by region (simplified Brazilian averages)
    regional_base <- list(
      "Sudeste" = 45000,
      "Sul" = 42000,
      "Centro-Oeste" = 38000,
      "Nordeste" = 25000,
      "Norte" = 28000
    )
    
    base_gdp <- regional_base[[region]] %||% 30000
    
    # Urban development multiplier
    urban_multiplier <- switch(urban_type,
      "Metropolitana" = 1.8,
      "Grande Urbana" = 1.5,
      "Média Urbana" = 1.2,
      "Pequena Urbana" = 1.0,
      "Rural" = 0.7,
      1.0
    )
    
    # Area factor (very large rural areas have lower GDP)
    area_factor <- if (area > 50000) 0.8 else if (area < 100) 1.3 else 1.0
    
    return(round(base_gdp * urban_multiplier * area_factor))
    
  }, urban_types, regions, areas)
}

#' Calculate development index
#' @param urban_types Vector of urban classifications
#' @param importance Vector of legislative importance scores
#' @param areas Vector of areas
#' @return Vector of development indices (0-1)
calculate_development_index <- function(urban_types, importance, areas) {
  
  mapply(function(urban_type, imp, area) {
    
    score <- 0
    
    # Urban development component
    urban_score <- switch(urban_type,
      "Metropolitana" = 0.9,
      "Grande Urbana" = 0.8,
      "Média Urbana" = 0.6,
      "Pequena Urbana" = 0.4,
      "Rural" = 0.2,
      0.5
    )
    
    # Legislative importance component
    importance_score <- imp / 100
    
    # Area efficiency component (compact areas score higher)
    area_score <- if (area <= 500) 0.8 
                 else if (area <= 2000) 0.6
                 else if (area <= 10000) 0.4
                 else 0.2
    
    # Weighted average
    final_score <- (urban_score * 0.5) + (importance_score * 0.3) + (area_score * 0.2)
    
    return(round(final_score, 2))
    
  }, urban_types, importance, areas)
}

#' Estimate transport infrastructure score
#' @param urban_types Vector of urban classifications
#' @param areas Vector of areas
#' @param importance Vector of importance scores
#' @return Vector of transport scores (0-100)
estimate_transport_infrastructure <- function(urban_types, areas, importance) {
  
  mapply(function(urban_type, area, imp) {
    
    # Base score by urban type
    base_score <- switch(urban_type,
      "Metropolitana" = 85,
      "Grande Urbana" = 70,
      "Média Urbana" = 55,
      "Pequena Urbana" = 40,
      "Rural" = 25,
      50
    )
    
    # Area penalty for very large areas
    area_penalty <- if (area > 50000) -15 
                   else if (area > 20000) -10
                   else if (area > 10000) -5
                   else 0
    
    # Importance bonus
    importance_bonus <- (imp - 50) * 0.3
    
    final_score <- base_score + area_penalty + importance_bonus
    
    return(round(max(0, min(100, final_score))))
    
  }, urban_types, areas, importance)
}

#' Calculate legislative potential
#' @param importance Vector of importance scores
#' @param development Vector of development indices
#' @param transport Vector of transport scores
#' @return Vector of legislative potential scores (0-100)
calculate_legislative_potential <- function(importance, development, transport) {
  
  mapply(function(imp, dev, trans) {
    
    # Weighted combination
    potential <- (imp * 0.4) + (dev * 100 * 0.35) + (trans * 0.25)
    
    return(round(max(0, min(100, potential))))
    
  }, importance, development, transport)
}

#' Perform spatial clustering of legislative documents
#' @param documents Data frame with legislative documents
#' @param geo_data SF object with geographic boundaries
#' @return Enhanced documents with cluster information
spatial_cluster_documents <- function(documents, geo_data) {
  
  if (is.null(documents) || nrow(documents) == 0) {
    log_event("No documents for spatial clustering", "WARN")
    return(documents)
  }
  
  log_event(paste("Performing spatial clustering for", nrow(documents), "documents"))
  
  tryCatch({
    
    # Create spatial points from documents
    doc_points <- create_document_spatial_points(documents, geo_data)
    
    if (is.null(doc_points) || nrow(doc_points) == 0) {
      log_event("No valid spatial points created", "WARN")
      return(documents)
    }
    
    # Perform clustering analysis
    clusters <- perform_spatial_clustering(doc_points)
    
    # Add cluster information to documents
    enhanced_docs <- documents %>%
      mutate(
        spatial_cluster = clusters$cluster_id,
        cluster_size = clusters$cluster_size,
        cluster_density = clusters$cluster_density,
        nearest_urban_center = find_nearest_urban_center(estado, geo_data),
        geographic_influence = calculate_geographic_influence(estado, tipo, geo_data)
      )
    
    log_event(paste("Spatial clustering completed:", max(clusters$cluster_id, na.rm = TRUE), "clusters found"))
    
    return(enhanced_docs)
    
  }, error = function(e) {
    log_event(paste("Error in spatial clustering:", e$message), "ERROR")
    return(documents)
  })
}

#' Create spatial points from document locations
#' @param documents Legislative documents
#' @param geo_data Geographic boundaries
#' @return SF points object
create_document_spatial_points <- function(documents, geo_data) {
  
  # Filter documents with valid state information
  valid_docs <- documents %>%
    filter(!is.na(estado), estado != "")
  
  if (nrow(valid_docs) == 0) {
    return(NULL)
  }
  
  # Get centroids for each state
  state_centroids <- geo_data %>%
    filter(!is.na(abbrev_state %||% code_state)) %>%
    mutate(
      state_code = abbrev_state %||% code_state,
      centroid = st_centroid(geom),
      lat = st_coordinates(centroid)[, 2],
      lng = st_coordinates(centroid)[, 1]
    ) %>%
    st_drop_geometry() %>%
    select(state_code, lat, lng)
  
  # Join documents with state coordinates
  doc_coords <- valid_docs %>%
    left_join(state_centroids, by = c("estado" = "state_code")) %>%
    filter(!is.na(lat), !is.na(lng))
  
  if (nrow(doc_coords) == 0) {
    return(NULL)
  }
  
  # Create SF points
  doc_points <- st_as_sf(
    doc_coords,
    coords = c("lng", "lat"),
    crs = SPATIAL_CONFIG$default_crs
  )
  
  return(doc_points)
}

#' Perform spatial clustering using density-based methods
#' @param doc_points SF points object
#' @return List with cluster assignments
perform_spatial_clustering <- function(doc_points) {
  
  n_points <- nrow(doc_points)
  
  if (n_points < SPATIAL_CONFIG$min_points_cluster) {
    # Not enough points for clustering
    return(list(
      cluster_id = rep(1, n_points),
      cluster_size = rep(n_points, n_points),
      cluster_density = rep(1, n_points)
    ))
  }
  
  # Calculate distance matrix
  coords <- st_coordinates(doc_points)
  distances <- dist(coords)
  
  # Simple clustering based on distance threshold
  cluster_radius <- SPATIAL_CONFIG$clustering_radius / 111000  # Convert to degrees (approximate)
  
  # Initialize clusters
  clusters <- rep(0, n_points)
  cluster_id <- 1
  
  for (i in 1:n_points) {
    if (clusters[i] == 0) {  # Unassigned point
      
      # Find nearby points
      nearby_indices <- which(as.matrix(distances)[i, ] <= cluster_radius)
      
      if (length(nearby_indices) >= SPATIAL_CONFIG$min_points_cluster) {
        # Create new cluster
        clusters[nearby_indices] <- cluster_id
        cluster_id <- cluster_id + 1
      } else {
        # Assign to noise cluster
        clusters[i] <- -1
      }
    }
  }
  
  # Calculate cluster statistics
  cluster_sizes <- table(clusters[clusters > 0])
  cluster_densities <- sapply(1:n_points, function(i) {
    if (clusters[i] > 0) {
      cluster_sizes[as.character(clusters[i])]
    } else {
      1
    }
  })
  
  return(list(
    cluster_id = ifelse(clusters <= 0, 1, clusters),
    cluster_size = as.numeric(cluster_densities),
    cluster_density = round(as.numeric(cluster_densities) / max(cluster_densities, 1), 2)
  ))
}

#' Find nearest urban center for each state
#' @param states Vector of state codes
#' @param geo_data Geographic data
#' @return Vector of nearest urban centers
find_nearest_urban_center <- function(states, geo_data) {
  
  # Major urban centers by region
  urban_centers <- list(
    "SP" = "São Paulo", "RJ" = "Rio de Janeiro", "MG" = "Belo Horizonte",
    "ES" = "Vitória", "BA" = "Salvador", "PE" = "Recife", "CE" = "Fortaleza",
    "RN" = "Natal", "PB" = "João Pessoa", "AL" = "Maceió", "SE" = "Aracaju",
    "PI" = "Teresina", "MA" = "São Luís", "PA" = "Belém", "AM" = "Manaus",
    "AC" = "Rio Branco", "RO" = "Porto Velho", "RR" = "Boa Vista",
    "AP" = "Macapá", "TO" = "Palmas", "GO" = "Goiânia", "DF" = "Brasília",
    "MT" = "Cuiabá", "MS" = "Campo Grande", "PR" = "Curitiba",
    "SC" = "Florianópolis", "RS" = "Porto Alegre"
  )
  
  sapply(states, function(state) {
    urban_centers[[state]] %||% "Centro Regional"
  })
}

#' Calculate geographic influence score
#' @param states Vector of state codes
#' @param types Vector of document types
#' @param geo_data Geographic data
#' @return Vector of influence scores
calculate_geographic_influence <- function(states, types, geo_data) {
  
  mapply(function(state, type) {
    
    # Base influence by state (population/economic proxy)
    state_influence <- list(
      "SP" = 100, "RJ" = 95, "MG" = 85, "BA" = 80, "PR" = 75,
      "RS" = 75, "PE" = 70, "CE" = 65, "GO" = 60, "SC" = 60,
      "PA" = 55, "MA" = 50, "ES" = 50, "PB" = 45, "AM" = 45,
      "MT" = 45, "AL" = 40, "RN" = 40, "MS" = 40, "PI" = 35,
      "DF" = 90, "TO" = 35, "SE" = 35, "RO" = 30, "AC" = 25,
      "RR" = 25, "AP" = 25
    )
    
    base_score <- state_influence[[state]] %||% 40
    
    # Document type multiplier
    type_multiplier <- if (str_detect(str_to_lower(type), "lei")) 1.2
                     else if (str_detect(str_to_lower(type), "decreto")) 1.1
                     else 1.0
    
    return(round(base_score * type_multiplier))
    
  }, states, types)
}

#' Create spatial statistics for geographic regions
#' @param documents Legislative documents
#' @param geo_data Geographic boundaries
#' @return List with spatial statistics
calculate_spatial_statistics <- function(documents, geo_data) {
  
  log_event("Calculating spatial statistics")
  
  if (is.null(documents) || nrow(documents) == 0) {
    return(create_empty_spatial_stats())
  }
  
  # Document distribution by state
  state_distribution <- documents %>%
    filter(!is.na(estado)) %>%
    count(estado, sort = TRUE) %>%
    rename(state = estado, document_count = n)
  
  # Join with geographic data for enhanced statistics
  if (!is.null(geo_data)) {
    enhanced_stats <- geo_data %>%
      st_drop_geometry() %>%
      left_join(state_distribution, by = c("abbrev_state" = "state")) %>%
      mutate(
        document_count = coalesce(document_count, 0),
        doc_density = document_count / area_km2,
        doc_per_capita = document_count / (population %||% 1000000)
      ) %>%
      arrange(desc(document_count))
  } else {
    enhanced_stats <- state_distribution
  }
  
  # Calculate regional aggregations
  regional_stats <- if (!is.null(geo_data)) {
    enhanced_stats %>%
      group_by(region_code) %>%
      summarise(
        states_count = n(),
        total_documents = sum(document_count, na.rm = TRUE),
        avg_doc_density = mean(doc_density, na.rm = TRUE),
        total_area = sum(area_km2, na.rm = TRUE),
        .groups = "drop"
      )
  } else {
    data.frame()
  }
  
  # Temporal patterns
  temporal_stats <- if ("data" %in% names(documents)) {
    documents %>%
      filter(!is.na(data)) %>%
      mutate(
        year = year(data),
        month = month(data)
      ) %>%
      group_by(year) %>%
      summarise(
        documents = n(),
        states_active = length(unique(estado[!is.na(estado)])),
        .groups = "drop"
      )
  } else {
    data.frame()
  }
  
  return(list(
    state_distribution = enhanced_stats,
    regional_aggregation = regional_stats,
    temporal_patterns = temporal_stats,
    total_documents = nrow(documents),
    covered_states = length(unique(documents$estado[!is.na(documents$estado)])),
    geographic_coverage = round((length(unique(documents$estado[!is.na(documents$estado)])) / 27) * 100, 1)
  ))
}

#' Create fallback spatial data when IBGE is unavailable
#' @param level Geographic level
#' @return Fallback spatial data
create_fallback_spatial_data <- function(level = "state") {
  
  log_event("Creating fallback spatial data", "WARN")
  
  if (level == "state") {
    # Create simplified state boundaries
    states_data <- data.frame(
      code_state = c("11", "12", "13", "14", "15", "16", "17", "21", "22", "23", "24", "25", "26", "27", "28", "29", "31", "32", "33", "35", "41", "42", "43", "50", "51", "52", "53"),
      abbrev_state = c("RO", "AC", "AM", "RR", "PA", "AP", "TO", "MA", "PI", "CE", "RN", "PB", "PE", "AL", "SE", "BA", "MG", "ES", "RJ", "SP", "PR", "SC", "RS", "MS", "MT", "GO", "DF"),
      name_state = c("Rondônia", "Acre", "Amazonas", "Roraima", "Pará", "Amapá", "Tocantins", "Maranhão", "Piauí", "Ceará", "Rio Grande do Norte", "Paraíba", "Pernambuco", "Alagoas", "Sergipe", "Bahia", "Minas Gerais", "Espírito Santo", "Rio de Janeiro", "São Paulo", "Paraná", "Santa Catarina", "Rio Grande do Sul", "Mato Grosso do Sul", "Mato Grosso", "Goiás", "Distrito Federal"),
      centroid_lat = c(-11.22, -8.77, -3.07, 1.89, -5.53, 1.41, -10.25, -2.55, -8.28, -5.20, -5.22, -7.06, -8.28, -9.71, -10.90, -12.96, -18.10, -19.19, -22.84, -23.55, -24.89, -27.33, -30.01, -20.51, -12.64, -16.64, -15.83),
      centroid_lng = c(-61.95, -70.55, -61.66, -61.22, -52.29, -51.77, -48.25, -44.30, -43.68, -39.53, -36.52, -35.55, -35.07, -36.82, -37.07, -38.51, -44.38, -40.34, -43.15, -46.64, -51.55, -49.44, -51.22, -54.54, -55.42, -49.31, -47.86),
      area_km2 = c(237576, 164123, 1559168, 224299, 1247955, 142815, 277620, 331937, 251529, 148886, 52797, 56440, 98938, 27848, 21915, 564693, 586522, 46095, 43777, 248219, 199307, 95985, 281748, 357125, 903357, 340111, 5760),
      stringsAsFactors = FALSE
    )
    
    # Add enhanced attributes
    enhanced_states <- states_data %>%
      mutate(
        region_code = classify_state_region(abbrev_state),
        urban_classification = classify_urban_level(area_km2, name_state),
        legislative_importance = calculate_legislative_importance("state", area_km2, name_state),
        population = estimate_population_from_area(area_km2, urban_classification),
        pop_density = population / area_km2,
        gdp_per_capita_estimate = estimate_gdp_per_capita(urban_classification, region_code, area_km2),
        development_index = calculate_development_index(urban_classification, legislative_importance, area_km2),
        transport_score = estimate_transport_infrastructure(urban_classification, area_km2, legislative_importance),
        legislative_potential = calculate_legislative_potential(legislative_importance, development_index, transport_score)
      )
    
    return(enhanced_states)
  }
  
  # For other levels, return empty data frame
  return(data.frame())
}

#' Create empty spatial statistics
#' @return Empty spatial statistics structure
create_empty_spatial_stats <- function() {
  list(
    state_distribution = data.frame(),
    regional_aggregation = data.frame(),
    temporal_patterns = data.frame(),
    total_documents = 0,
    covered_states = 0,
    geographic_coverage = 0
  )
}

#' Get optimal UTM zone for coordinates
#' @param lng Longitude
#' @param lat Latitude
#' @return UTM zone EPSG code
get_optimal_utm_zone <- function(lng, lat) {
  
  # Calculate UTM zone number
  zone_num <- floor((lng + 180) / 6) + 1
  
  # Determine hemisphere
  hemisphere <- if (lat >= 0) "N" else "S"
  
  # Brazilian UTM zones (simplified)
  if (lng >= -75 && lng < -69) return(SPATIAL_CONFIG$utm_zones[["18S"]])
  if (lng >= -69 && lng < -63) return(SPATIAL_CONFIG$utm_zones[["19S"]])
  if (lng >= -63 && lng < -57) return(SPATIAL_CONFIG$utm_zones[["20S"]])
  if (lng >= -57 && lng < -51) return(SPATIAL_CONFIG$utm_zones[["21S"]])
  if (lng >= -51 && lng < -45) return(SPATIAL_CONFIG$utm_zones[["22S"]])
  if (lng >= -45 && lng < -39) return(SPATIAL_CONFIG$utm_zones[["23S"]])
  if (lng >= -39 && lng < -33) return(SPATIAL_CONFIG$utm_zones[["24S"]])
  
  # Default to SIRGAS 2000
  return(SPATIAL_CONFIG$default_crs)
}

#' Helper function for null coalescing
`%||%` <- function(x, y) {
  if (is.null(x) || length(x) == 0 || all(is.na(x))) y else x
}