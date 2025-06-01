#!/usr/bin/env Rscript
#' Enhanced Spatial Analytics for Brazilian Legislative Dataset
#' 
#' Advanced municipality-level spatial analysis framework for 134k+ Brazilian legislative documents.
#' Implements research-grade spatial statistics, hotspot analysis, and government decision-support
#' capabilities with performance optimization for Railway deployment.
#' 
#' Features:
#' - Statistical analysis at municipality level for 134k+ documents
#' - Hotspot analysis using spatial statistics (Moran's I, Getis-Ord)
#' - Cluster analysis for legislative activity patterns
#' - Cross-jurisdictional correlation analysis
#' - Time series analysis by administrative regions
#' - Publication-ready analytical methodologies
#' 
#' @author Brazilian Legislative Analytics Framework - Enhanced Spatial Module
#' @date 2025-09-01
#' @version 2.0.0

# Load required libraries with enhanced spatial capabilities
suppressPackageStartupMessages({
  # Core spatial libraries
  library(sf)
  library(spdep)
  library(spatstat)
  library(geobr)
  
  # Advanced spatial statistics
  library(CARBayes)
  library(spatialEco)
  library(adespatial)
  library(vegan)
  
  # Data processing and analysis
  library(dplyr)
  library(tidyr)
  library(purrr)
  library(stringr)
  library(lubridate)
  library(arrow)
  
  # Statistical analysis
  library(broom)
  library(corrr)
  library(mgcv)
  library(nlme)
  library(survival)
  
  # Visualization
  library(ggplot2)
  library(plotly)
  library(leaflet)
  library(tmap)
  library(viridis)
  library(RColorBrewer)
  library(mapview)
  
  # Performance optimization
  library(data.table)
  library(furrr)
  library(future)
  library(memoise)
  library(logger)
})

# Set up logging and performance
log_threshold(INFO)
plan(multisession, workers = min(4, parallel::detectCores() - 1))

#' Enhanced Spatial Analytics Core Functions
#' ==========================================

#' Initialize Enhanced Spatial Analytics System
#' @param cache_dir Directory for spatial data caching
#' @param parallel_workers Number of parallel processing workers
#' @return Initialized spatial analytics system
initialize_enhanced_spatial_system <- function(cache_dir = "cache/spatial_enhanced", parallel_workers = NULL) {
  
  log_info("=== INITIALIZING ENHANCED SPATIAL ANALYTICS SYSTEM ===")
  
  # Create cache structure
  dir.create(file.path(cache_dir, "municipalities"), recursive = TRUE, showWarnings = FALSE)
  dir.create(file.path(cache_dir, "spatial_weights"), recursive = TRUE, showWarnings = FALSE)
  dir.create(file.path(cache_dir, "hotspots"), recursive = TRUE, showWarnings = FALSE)
  dir.create(file.path(cache_dir, "temporal"), recursive = TRUE, showWarnings = FALSE)
  
  # Set parallel processing
  if (!is.null(parallel_workers)) {
    plan(multisession, workers = parallel_workers)
  }
  
  spatial_system <- list(
    cache_dir = cache_dir,
    municipality_boundaries = NULL,
    spatial_weights = NULL,
    analytical_cache = list(),
    
    # Core functions
    load_municipality_data = function(states = NULL) {
      load_enhanced_municipality_data(cache_dir, states)
    },
    
    create_spatial_weights = function(method = "queen") {
      create_enhanced_spatial_weights(cache_dir, method)
    },
    
    analyze_spatial_autocorrelation = function(data, variables) {
      analyze_enhanced_spatial_autocorrelation(cache_dir, data, variables)
    },
    
    perform_hotspot_analysis = function(data, variable) {
      perform_enhanced_hotspot_analysis(cache_dir, data, variable)
    },
    
    analyze_policy_diffusion = function(data, policy_type) {
      analyze_enhanced_policy_diffusion(cache_dir, data, policy_type)
    },
    
    conduct_cluster_analysis = function(data, variables) {
      conduct_enhanced_cluster_analysis(cache_dir, data, variables)
    },
    
    perform_temporal_analysis = function(data) {
      perform_enhanced_temporal_analysis(cache_dir, data)
    },
    
    generate_research_outputs = function(results, output_dir) {
      generate_enhanced_research_outputs(results, output_dir)
    }
  )
  
  log_info("Enhanced spatial analytics system initialized")
  return(spatial_system)
}

#' Load Enhanced Municipality Data with IBGE Integration
#' @param cache_dir Cache directory
#' @param states Optional state filter
#' @return Enhanced municipality dataset with IBGE data
load_enhanced_municipality_data <- function(cache_dir, states = NULL) {
  
  log_info("Loading enhanced municipality data with IBGE integration...")
  
  cache_file <- file.path(cache_dir, "enhanced_municipality_data.rds")
  
  # Check cache
  if (file.exists(cache_file)) {
    cached_data <- readRDS(cache_file)
    if (validate_enhanced_cache(cached_data)) {
      log_info("Using cached enhanced municipality data: {nrow(cached_data$boundaries)} municipalities")
      return(cached_data)
    }
  }
  
  tryCatch({
    # Load all Brazilian municipalities
    log_info("Downloading complete municipality boundaries from IBGE...")
    municipalities <- read_municipality(year = 2020, simplified = FALSE, showProgress = FALSE)
    
    # Load additional IBGE data
    population_data <- get_municipality_population_data()
    economic_data <- get_municipality_economic_data()
    infrastructure_data <- get_municipality_infrastructure_data()
    
    # Enhance with centroids and geometric properties
    centroids <- st_centroid(municipalities$geometry)
    coords <- st_coordinates(centroids)
    municipalities$centroid_lon <- coords[, 1]
    municipalities$centroid_lat <- coords[, 2]
    
    # Calculate geometric properties
    municipalities$area_km2 <- as.numeric(st_area(municipalities)) / 1e6
    municipalities$perimeter_km <- as.numeric(st_length(st_boundary(municipalities))) / 1000
    municipalities$shape_index <- municipalities$perimeter_km / (2 * sqrt(pi * municipalities$area_km2))
    
    # Merge with additional data
    enhanced_data <- municipalities %>%
      left_join(population_data, by = c("code_muni" = "municipality_code")) %>%
      left_join(economic_data, by = c("code_muni" = "municipality_code")) %>%
      left_join(infrastructure_data, by = c("code_muni" = "municipality_code"))
    
    # Add regional classifications
    enhanced_data <- enhanced_data %>%
      mutate(
        # Metropolitan regions
        metropolitan_region = classify_metropolitan_regions(name_muni, abbrev_state),
        # Urban hierarchy
        urban_hierarchy = classify_urban_hierarchy(population, area_km2),
        # Distance to state capital
        distance_to_capital = calculate_distance_to_capitals(centroid_lon, centroid_lat, abbrev_state),
        # Transport accessibility
        transport_accessibility = calculate_transport_accessibility(centroid_lon, centroid_lat),
        # Economic development level
        development_level = classify_development_level(gdp_per_capita, human_development_index)
      )
    
    # Create spatial features for ML
    spatial_features <- create_spatial_features(enhanced_data)
    enhanced_data <- cbind(enhanced_data, spatial_features)
    
    # Cache results
    enhanced_municipality_data <- list(
      boundaries = enhanced_data,
      total_municipalities = nrow(enhanced_data),
      data_quality = assess_data_quality(enhanced_data),
      cached_at = Sys.time(),
      version = "2.0.0"
    )
    
    saveRDS(enhanced_municipality_data, cache_file)
    log_info("Enhanced municipality data cached: {nrow(enhanced_data)} municipalities")
    
    return(enhanced_municipality_data)
    
  }, error = function(e) {
    log_warn("Failed to load enhanced municipality data: {e$message}")
    return(create_fallback_municipality_data(cache_dir))
  })
}

#' Create Enhanced Spatial Weights Matrices
#' @param cache_dir Cache directory
#' @param method Spatial weights method ("queen", "rook", "distance", "knn")
#' @return List of spatial weights matrices
create_enhanced_spatial_weights <- function(cache_dir, method = "queen") {
  
  log_info("Creating enhanced spatial weights matrices...")
  
  cache_file <- file.path(cache_dir, "spatial_weights", paste0("weights_", method, ".rds"))
  
  if (file.exists(cache_file)) {
    cached_weights <- readRDS(cache_file)
    if (validate_weights_cache(cached_weights)) {
      log_info("Using cached spatial weights: {method}")
      return(cached_weights)
    }
  }
  
  # Load municipality data
  municipality_data <- load_enhanced_municipality_data(cache_dir)
  boundaries <- municipality_data$boundaries
  
  # Convert to sp for spdep compatibility
  boundaries_sp <- as(st_geometry(boundaries), "Spatial")
  
  weights_list <- list()
  
  tryCatch({
    # Queen contiguity
    if (method %in% c("queen", "all")) {
      log_info("Creating Queen contiguity weights...")
      queen_nb <- poly2nb(boundaries_sp, queen = TRUE)
      weights_list$queen <- nb2listw(queen_nb, style = "W", zero.policy = TRUE)
    }
    
    # Rook contiguity
    if (method %in% c("rook", "all")) {
      log_info("Creating Rook contiguity weights...")
      rook_nb <- poly2nb(boundaries_sp, queen = FALSE)
      weights_list$rook <- nb2listw(rook_nb, style = "W", zero.policy = TRUE)
    }
    
    # Distance-based weights
    if (method %in% c("distance", "all")) {
      log_info("Creating distance-based weights...")
      coords <- st_coordinates(st_centroid(boundaries$geometry))
      distance_nb <- dnearneigh(coords, 0, 50000)  # 50km threshold
      weights_list$distance <- nb2listw(distance_nb, style = "W", zero.policy = TRUE)
    }
    
    # K-nearest neighbors
    if (method %in% c("knn", "all")) {
      log_info("Creating k-nearest neighbor weights...")
      coords <- st_coordinates(st_centroid(boundaries$geometry))
      knn_nb <- knn2nb(knearneigh(coords, k = 6))
      weights_list$knn <- nb2listw(knn_nb, style = "W", zero.policy = TRUE)
    }
    
    # Economic distance weights
    if (method %in% c("economic", "all")) {
      log_info("Creating economic distance weights...")
      economic_weights <- create_economic_distance_weights(boundaries)
      weights_list$economic <- economic_weights
    }
    
    # Cache results
    weights_cache <- list(
      weights = weights_list,
      method = method,
      municipality_count = nrow(boundaries),
      cached_at = Sys.time()
    )
    
    saveRDS(weights_cache, cache_file)
    log_info("Spatial weights cached: {length(weights_list)} weight matrices")
    
    return(weights_cache)
    
  }, error = function(e) {
    log_warn("Failed to create spatial weights: {e$message}")
    return(list(weights = list(), method = method))
  })
}

#' Analyze Enhanced Spatial Autocorrelation
#' @param cache_dir Cache directory
#' @param data Legislative data with municipality information
#' @param variables Variables to analyze
#' @return Comprehensive spatial autocorrelation results
analyze_enhanced_spatial_autocorrelation <- function(cache_dir, data, variables) {
  
  log_info("Performing enhanced spatial autocorrelation analysis...")
  
  # Load spatial components
  municipality_data <- load_enhanced_municipality_data(cache_dir)
  weights_data <- create_enhanced_spatial_weights(cache_dir, "all")
  
  boundaries <- municipality_data$boundaries
  weights_list <- weights_data$weights
  
  # Aggregate data by municipality
  municipal_stats <- aggregate_data_by_municipality(data, boundaries)
  
  autocorr_results <- list()
  
  for (var in variables) {
    log_info("Analyzing spatial autocorrelation for: {var}")
    
    var_results <- list()
    
    if (var %in% names(municipal_stats) && var(municipal_stats[[var]], na.rm = TRUE) > 0) {
      
      # Global Moran's I for different weight matrices
      global_moran <- map(weights_list, ~{
        tryCatch({
          moran_test <- moran.test(municipal_stats[[var]], ., zero.policy = TRUE, na.action = na.omit)
          list(
            statistic = moran_test$statistic[[1]],
            p_value = moran_test$p.value,
            expected = moran_test$estimate[[2]],
            variance = moran_test$estimate[[3]],
            interpretation = classify_spatial_autocorrelation(moran_test$statistic[[1]], moran_test$p.value)
          )
        }, error = function(e) {
          log_warn("Moran's I failed for {var}: {e$message}")
          return(NULL)
        })
      })
      
      # Local Indicators of Spatial Association (LISA)
      if (!is.null(weights_list$queen)) {
        lisa_results <- tryCatch({
          lisa <- localmoran(municipal_stats[[var]], weights_list$queen, zero.policy = TRUE, na.action = na.omit)
          
          # Classify LISA clusters
          municipal_stats$lisa_cluster <- classify_lisa_clusters(lisa, municipal_stats[[var]])
          municipal_stats$lisa_p_value <- lisa[, 5]
          municipal_stats$lisa_statistic <- lisa[, 1]
          
          list(
            clusters = table(municipal_stats$lisa_cluster),
            significant_clusters = sum(municipal_stats$lisa_p_value < 0.05, na.rm = TRUE),
            hotspots = sum(municipal_stats$lisa_cluster == "High-High", na.rm = TRUE),
            coldspots = sum(municipal_stats$lisa_cluster == "Low-Low", na.rm = TRUE)
          )
        }, error = function(e) {
          log_warn("LISA analysis failed for {var}: {e$message}")
          return(NULL)
        })
      }
      
      # Getis-Ord Gi* statistics
      getis_ord_results <- tryCatch({
        if (!is.null(weights_list$distance)) {
          gi_star <- localG(municipal_stats[[var]], weights_list$distance, zero.policy = TRUE)
          
          # Classify hotspots and coldspots
          gi_classification <- classify_getis_ord(gi_star)
          
          list(
            hotspots_99 = sum(gi_star > qnorm(0.995), na.rm = TRUE),
            hotspots_95 = sum(gi_star > qnorm(0.975), na.rm = TRUE),
            coldspots_99 = sum(gi_star < qnorm(0.005), na.rm = TRUE),
            coldspots_95 = sum(gi_star < qnorm(0.025), na.rm = TRUE),
            mean_gi_star = mean(gi_star, na.rm = TRUE),
            classification = gi_classification
          )
        }
      }, error = function(e) {
        log_warn("Getis-Ord analysis failed for {var}: {e$message}")
        return(NULL)
      })
      
      var_results <- list(
        variable = var,
        global_moran = global_moran,
        lisa = lisa_results,
        getis_ord = getis_ord_results,
        descriptive_stats = list(
          mean = mean(municipal_stats[[var]], na.rm = TRUE),
          sd = sd(municipal_stats[[var]], na.rm = TRUE),
          min = min(municipal_stats[[var]], na.rm = TRUE),
          max = max(municipal_stats[[var]], na.rm = TRUE),
          municipalities_with_data = sum(!is.na(municipal_stats[[var]]))
        )
      )
    }
    
    autocorr_results[[var]] <- var_results
  }
  
  # Statistical significance summary
  significance_summary <- create_spatial_significance_summary(autocorr_results)
  
  final_results <- list(
    results_by_variable = autocorr_results,
    municipal_data_with_clusters = municipal_stats,
    significance_summary = significance_summary,
    metadata = list(
      total_municipalities = nrow(boundaries),
      variables_analyzed = variables,
      analysis_date = Sys.time(),
      weight_matrices_used = names(weights_list)
    )
  )
  
  log_info("Spatial autocorrelation analysis completed for {length(variables)} variables")
  return(final_results)
}

#' Perform Enhanced Hotspot Analysis
#' @param cache_dir Cache directory
#' @param data Legislative data
#' @param variable Variable for hotspot analysis
#' @return Comprehensive hotspot analysis results
perform_enhanced_hotspot_analysis <- function(cache_dir, data, variable) {
  
  log_info("Performing enhanced hotspot analysis for: {variable}")
  
  cache_file <- file.path(cache_dir, "hotspots", paste0("hotspots_", variable, ".rds"))
  
  # Load spatial components
  municipality_data <- load_enhanced_municipality_data(cache_dir)
  weights_data <- create_enhanced_spatial_weights(cache_dir, "all")
  
  boundaries <- municipality_data$boundaries
  municipal_stats <- aggregate_data_by_municipality(data, boundaries)
  
  hotspot_results <- list()
  
  # Multi-scale hotspot analysis
  scales <- c(10000, 25000, 50000, 100000)  # Different distance thresholds in meters
  
  for (scale in scales) {
    log_info("Analyzing hotspots at {scale/1000}km scale...")
    
    scale_results <- tryCatch({
      # Create distance-based weights for this scale
      coords <- st_coordinates(st_centroid(boundaries$geometry))
      scale_nb <- dnearneigh(coords, 0, scale)
      scale_weights <- nb2listw(scale_nb, style = "W", zero.policy = TRUE)
      
      # Getis-Ord Gi* at this scale
      gi_star <- localG(municipal_stats[[variable]], scale_weights, zero.policy = TRUE)
      
      # Enhanced classification
      hotspot_classification <- classify_enhanced_hotspots(gi_star, scale)
      
      # Statistical validation
      validation_results <- validate_hotspots(gi_star, municipal_stats[[variable]], scale_weights)
      
      list(
        scale_km = scale / 1000,
        gi_statistics = gi_star,
        classification = hotspot_classification,
        validation = validation_results,
        summary_stats = list(
          significant_hotspots = sum(gi_star > qnorm(0.975), na.rm = TRUE),
          significant_coldspots = sum(gi_star < qnorm(0.025), na.rm = TRUE),
          mean_gi = mean(gi_star, na.rm = TRUE),
          sd_gi = sd(gi_star, na.rm = TRUE)
        )
      )
    }, error = function(e) {
      log_warn("Hotspot analysis failed at {scale/1000}km scale: {e$message}")
      return(NULL)
    })
    
    hotspot_results[[paste0("scale_", scale/1000, "km")]] <- scale_results
  }
  
  # Temporal hotspot analysis
  temporal_hotspots <- analyze_temporal_hotspots(data, boundaries, variable)
  
  # Cross-jurisdictional hotspot analysis
  jurisdictional_hotspots <- analyze_jurisdictional_hotspots(data, boundaries, variable)
  
  # Combine results
  final_hotspot_results <- list(
    multi_scale_analysis = hotspot_results,
    temporal_analysis = temporal_hotspots,
    jurisdictional_analysis = jurisdictional_hotspots,
    variable = variable,
    analysis_metadata = list(
      total_municipalities = nrow(boundaries),
      municipalities_with_data = sum(!is.na(municipal_stats[[variable]])),
      analysis_date = Sys.time(),
      scales_analyzed = scales
    )
  )
  
  # Cache results
  saveRDS(final_hotspot_results, cache_file)
  
  log_info("Enhanced hotspot analysis completed")
  return(final_hotspot_results)
}

#' Analyze Enhanced Policy Diffusion
#' @param cache_dir Cache directory
#' @param data Legislative data
#' @param policy_type Type of policy to analyze
#' @return Policy diffusion analysis results
analyze_enhanced_policy_diffusion <- function(cache_dir, data, policy_type) {
  
  log_info("Analyzing policy diffusion for: {policy_type}")
  
  # Load spatial components
  municipality_data <- load_enhanced_municipality_data(cache_dir)
  weights_data <- create_enhanced_spatial_weights(cache_dir, "queen")
  
  boundaries <- municipality_data$boundaries
  
  # Filter data for specific policy type
  policy_data <- data %>%
    filter(str_detect(tolower(tipo %||% categoria %||% assuntos), tolower(policy_type))) %>%
    arrange(data)
  
  # Spatial diffusion analysis
  diffusion_results <- analyze_spatial_policy_diffusion(policy_data, boundaries, weights_data$weights$queen)
  
  # Temporal diffusion patterns
  temporal_diffusion <- analyze_temporal_policy_diffusion(policy_data, boundaries)
  
  # Innovation vs. Imitation analysis
  innovation_analysis <- analyze_policy_innovation_patterns(policy_data, boundaries)
  
  # Network diffusion analysis
  network_diffusion <- analyze_policy_network_diffusion(policy_data, boundaries)
  
  final_diffusion_results <- list(
    spatial_diffusion = diffusion_results,
    temporal_patterns = temporal_diffusion,
    innovation_analysis = innovation_analysis,
    network_analysis = network_diffusion,
    policy_type = policy_type,
    total_adoptions = nrow(policy_data),
    analysis_metadata = list(
      analysis_date = Sys.time(),
      time_period = list(
        start = min(policy_data$data, na.rm = TRUE),
        end = max(policy_data$data, na.rm = TRUE)
      )
    )
  )
  
  log_info("Policy diffusion analysis completed: {nrow(policy_data)} policy adoptions")
  return(final_diffusion_results)
}

#' Conduct Enhanced Cluster Analysis
#' @param cache_dir Cache directory
#' @param data Legislative data
#' @param variables Variables for clustering
#' @return Comprehensive cluster analysis results
conduct_enhanced_cluster_analysis <- function(cache_dir, data, variables) {
  
  log_info("Conducting enhanced cluster analysis...")
  
  # Load spatial components
  municipality_data <- load_enhanced_municipality_data(cache_dir)
  boundaries <- municipality_data$boundaries
  
  # Aggregate data by municipality
  municipal_stats <- aggregate_data_by_municipality(data, boundaries)
  
  # Prepare clustering data
  cluster_data <- municipal_stats[variables]
  cluster_data <- cluster_data[complete.cases(cluster_data), ]
  
  cluster_results <- list()
  
  # Spatially constrained clustering
  spatial_clusters <- perform_spatial_clustering(cluster_data, boundaries)
  cluster_results$spatial_clustering = spatial_clusters
  
  # Traditional clustering for comparison
  traditional_clusters <- perform_traditional_clustering(cluster_data)
  cluster_results$traditional_clustering = traditional_clusters
  
  # Mixed-effects clustering (incorporating spatial effects)
  mixed_clusters <- perform_mixed_effects_clustering(cluster_data, boundaries)
  cluster_results$mixed_effects_clustering = mixed_clusters
  
  # Cluster validation
  validation_results <- validate_clustering_results(cluster_results, cluster_data)
  
  final_cluster_results <- list(
    clustering_results = cluster_results,
    validation = validation_results,
    cluster_characteristics = analyze_cluster_characteristics(cluster_results, municipal_stats),
    variables_used = variables,
    municipalities_clustered = nrow(cluster_data),
    analysis_metadata = list(
      analysis_date = Sys.time(),
      clustering_methods = names(cluster_results)
    )
  )
  
  log_info("Enhanced cluster analysis completed")
  return(final_cluster_results)
}

# Helper Functions for Enhanced Analysis
# =====================================

aggregate_data_by_municipality <- function(data, boundaries) {
  # Implementation for aggregating legislative data by municipality
  # This is a complex function that would need specific data structure knowledge
  
  # Sample implementation structure
  municipal_aggregates <- data %>%
    group_by(municipio, estado) %>%
    summarise(
      document_count = n(),
      lei_count = sum(str_detect(tolower(tipo %||% ""), "lei"), na.rm = TRUE),
      decreto_count = sum(str_detect(tolower(tipo %||% ""), "decreto"), na.rm = TRUE),
      avg_year = mean(year(data), na.rm = TRUE),
      policy_diversity = n_distinct(categoria, na.rm = TRUE),
      .groups = "drop"
    ) %>%
    filter(!is.na(municipio), municipio != "")
  
  # Join with boundaries
  enhanced_municipal_data <- boundaries %>%
    left_join(municipal_aggregates, by = c("name_muni" = "municipio")) %>%
    replace_na(list(document_count = 0, lei_count = 0, decreto_count = 0))
  
  return(as.data.frame(enhanced_municipal_data))
}

classify_spatial_autocorrelation <- function(moran_i, p_value) {
  if (p_value >= 0.05) return("No significant spatial pattern")
  if (moran_i > 0.3) return("Strong positive spatial clustering")
  if (moran_i > 0.1) return("Moderate positive spatial clustering")
  if (moran_i > -0.1) return("Weak spatial pattern")
  if (moran_i > -0.3) return("Moderate negative spatial clustering")
  return("Strong negative spatial clustering")
}

classify_lisa_clusters <- function(lisa_results, variable_values) {
  # Implementation for LISA cluster classification
  clusters <- character(length(variable_values))
  clusters[lisa_results[, 5] >= 0.05] <- "Not significant"
  
  significant_idx <- lisa_results[, 5] < 0.05
  high_values <- variable_values > median(variable_values, na.rm = TRUE)
  
  clusters[significant_idx & high_values & lisa_results[significant_idx, 1] > 0] <- "High-High"
  clusters[significant_idx & !high_values & lisa_results[significant_idx, 1] > 0] <- "Low-Low"
  clusters[significant_idx & high_values & lisa_results[significant_idx, 1] < 0] <- "High-Low"
  clusters[significant_idx & !high_values & lisa_results[significant_idx, 1] < 0] <- "Low-High"
  
  return(clusters)
}

# Additional helper functions would be implemented here...
# (Due to length constraints, showing structure and key functions)

validate_enhanced_cache <- function(cached_data) {
  required_fields <- c("boundaries", "total_municipalities", "cached_at", "version")
  return(all(required_fields %in% names(cached_data)) && 
         cached_data$version == "2.0.0" &&
         difftime(Sys.time(), cached_data$cached_at, units = "days") < 7)
}

#' Main Enhanced Spatial Analysis Pipeline
#' @param data_source Path to legislative data
#' @param output_dir Output directory
#' @param analysis_scope Scope of analysis ("full", "sample", "state_focus")
#' @return Comprehensive spatial analysis results
run_enhanced_spatial_analysis <- function(data_source, output_dir, analysis_scope = "full") {
  
  log_info("=== STARTING ENHANCED SPATIAL ANALYSIS PIPELINE ===")
  
  # Initialize system
  cache_dir <- file.path(dirname(output_dir), "cache", "enhanced_spatial")
  spatial_system <- initialize_enhanced_spatial_system(cache_dir)
  
  # Load data
  if (is.character(data_source)) {
    legislative_data <- read_parquet(data_source)
  } else {
    legislative_data <- data_source
  }
  
  log_info("Loaded {nrow(legislative_data)} legislative documents")
  
  # Define analysis variables
  analysis_variables <- c("document_count", "lei_count", "decreto_count", "policy_diversity")
  
  # Run enhanced analyses
  results <- list()
  
  # 1. Enhanced spatial autocorrelation
  results$autocorrelation <- spatial_system$analyze_spatial_autocorrelation(
    legislative_data, analysis_variables
  )
  
  # 2. Multi-scale hotspot analysis
  results$hotspots <- map(analysis_variables, ~{
    spatial_system$perform_hotspot_analysis(legislative_data, .x)
  })
  names(results$hotspots) <- analysis_variables
  
  # 3. Policy diffusion analysis
  key_policies <- c("sustentabilidade", "transporte", "digital", "educação")
  results$diffusion <- map(key_policies, ~{
    spatial_system$analyze_policy_diffusion(legislative_data, .x)
  })
  names(results$diffusion) <- key_policies
  
  # 4. Enhanced clustering
  results$clustering <- spatial_system$conduct_cluster_analysis(
    legislative_data, analysis_variables
  )
  
  # 5. Temporal spatial analysis
  results$temporal <- spatial_system$perform_temporal_analysis(legislative_data)
  
  # Generate research outputs
  research_outputs <- spatial_system$generate_research_outputs(results, output_dir)
  
  # Final results package
  final_results <- list(
    spatial_analysis = results,
    research_outputs = research_outputs,
    metadata = list(
      total_documents = nrow(legislative_data),
      analysis_scope = analysis_scope,
      analysis_date = Sys.time(),
      variables_analyzed = analysis_variables,
      policies_analyzed = key_policies
    )
  )
  
  # Save comprehensive results
  saveRDS(final_results, file.path(output_dir, "enhanced_spatial_analysis_results.rds"))
  
  log_info("=== ENHANCED SPATIAL ANALYSIS COMPLETED ===")
  return(final_results)
}

# Execute if run as script
if (!interactive()) {
  # Configuration
  parquet_file <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/parquet_dataset/combined_legislative_dataset.parquet"
  output_dir <- file.path(dirname(dirname(parquet_file)), "enhanced_spatial_analysis")
  
  if (file.exists(parquet_file)) {
    results <- run_enhanced_spatial_analysis(parquet_file, output_dir, "full")
    cat("Enhanced spatial analysis completed. Results saved to:", output_dir, "\n")
  } else {
    cat("Data file not found:", parquet_file, "\n")
  }
}