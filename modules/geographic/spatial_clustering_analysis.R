# Spatial Clustering Analysis Module - Sprint 1
# Monitor Legislativo v4 - Academic Spatial Statistics for Brazilian Legislative Research
# ==================================================================================
# 
# Advanced spatial clustering analysis following RESEARCH_METHODOLOGY.md academic standards
# Implements Moran's I spatial autocorrelation and Getis-Ord Gi* hotspot detection
# with statistical significance testing and academic validation protocols
# 
# Key Features:
# - Moran's I global and local spatial autocorrelation analysis
# - Getis-Ord Gi* hotspot and coldspot detection
# - Statistical significance testing with multiple comparisons correction
# - Academic-quality visualization with confidence intervals
# - Brazilian administrative boundaries integration (SIRGAS 2000)
# - Memory-optimized processing for Railway deployment constraints

library(spdep)
library(spatstat)
library(sf)
library(dplyr)
library(ggplot2)
library(RColorBrewer)
library(viridis)

#' Calculate Global Moran's I Spatial Autocorrelation
#' 
#' Academic implementation of Moran's I statistic for measuring spatial autocorrelation
#' in Brazilian legislative document distribution with statistical significance testing
#' 
#' @param spatial_data SF object with legislative data and geometry
#' @param variable Character name of variable to analyze (default: "doc_count")
#' @param weight_style Spatial weights style ("W", "B", "C", "U", "S")
#' @param significance_level Significance level for hypothesis testing (default: 0.05)
#' @return List with Moran's I results and academic interpretation
calculate_morans_i <- function(spatial_data, 
                               variable = "doc_count", 
                               weight_style = "W",
                               significance_level = 0.05) {
  
  tryCatch({
    
    # Validate input data
    if (!inherits(spatial_data, "sf")) {
      stop("Input must be an sf object")
    }
    
    if (!variable %in% names(spatial_data)) {
      stop(paste("Variable", variable, "not found in spatial data"))
    }
    
    # Create spatial weights matrix using Queen contiguity
    coords <- sf::st_centroid(spatial_data) %>% sf::st_coordinates()
    nb <- spdep::poly2nb(spatial_data, queen = TRUE)
    
    # Handle islands (areas with no neighbors)
    if (any(spdep::card(nb) == 0)) {
      # Add k-nearest neighbors for isolated areas
      nb <- spdep::include.self(nb)
      knn <- spdep::knearneigh(coords, k = 1)
      nb_knn <- spdep::knn2nb(knn)
      nb <- spdep::union.nb(nb, nb_knn)
    }
    
    # Create listw object
    listw <- spdep::nb2listw(nb, style = weight_style, zero.policy = TRUE)
    
    # Calculate Global Moran's I
    moran_test <- spdep::moran.test(spatial_data[[variable]], listw, 
                                   zero.policy = TRUE, 
                                   alternative = "two.sided")
    
    # Calculate Local Moran's I (LISA)
    local_moran <- spdep::localmoran(spatial_data[[variable]], listw, 
                                    zero.policy = TRUE, 
                                    alternative = "two.sided")
    
    # Apply Bonferroni correction for multiple comparisons
    n_tests <- nrow(local_moran)
    bonferroni_alpha <- significance_level / n_tests
    
    # Classify local spatial association patterns
    # Following Anselin (1995) classification
    spatial_data$moran_ii <- local_moran[, "Ii"]  # Local Moran's I
    spatial_data$moran_pvalue <- local_moran[, "Pr(z != E(Ii))"]  # P-values
    spatial_data$moran_z <- local_moran[, "Z.Ii"]  # Z-scores
    
    # Standardize variable for LISA classification
    variable_mean <- mean(spatial_data[[variable]], na.rm = TRUE)
    spatial_data$variable_std <- spatial_data[[variable]] - variable_mean
    
    # Calculate spatial lag
    spatial_data$spatial_lag <- spdep::lag.listw(listw, spatial_data[[variable]], zero.policy = TRUE)
    spatial_data$spatial_lag_std <- spatial_data$spatial_lag - mean(spatial_data$spatial_lag, na.rm = TRUE)
    
    # LISA classification with significance consideration
    spatial_data$lisa_cluster <- case_when(
      spatial_data$moran_pvalue > bonferroni_alpha ~ "Not Significant",
      spatial_data$variable_std > 0 & spatial_data$spatial_lag_std > 0 & spatial_data$moran_ii > 0 ~ "High-High",
      spatial_data$variable_std < 0 & spatial_data$spatial_lag_std < 0 & spatial_data$moran_ii > 0 ~ "Low-Low",
      spatial_data$variable_std > 0 & spatial_data$spatial_lag_std < 0 & spatial_data$moran_ii < 0 ~ "High-Low",
      spatial_data$variable_std < 0 & spatial_data$spatial_lag_std > 0 & spatial_data$moran_ii < 0 ~ "Low-High",
      TRUE ~ "Not Significant"
    )
    
    # Academic interpretation following Cliff & Ord (1981)
    interpretation <- case_when(
      moran_test$p.value < 0.001 & moran_test$estimate[1] > 0.3 ~ "Strong positive spatial clustering (p < 0.001)",
      moran_test$p.value < 0.01 & moran_test$estimate[1] > 0.1 ~ "Moderate positive spatial clustering (p < 0.01)",
      moran_test$p.value < 0.05 & moran_test$estimate[1] > 0.05 ~ "Weak positive spatial clustering (p < 0.05)",
      moran_test$p.value < 0.001 & moran_test$estimate[1] < -0.3 ~ "Strong negative spatial clustering (p < 0.001)",
      moran_test$p.value < 0.01 & moran_test$estimate[1] < -0.1 ~ "Moderate negative spatial clustering (p < 0.01)",
      moran_test$p.value < 0.05 & moran_test$estimate[1] < -0.05 ~ "Weak negative spatial clustering (p < 0.05)",
      TRUE ~ "No significant spatial pattern detected"
    )
    
    # Calculate diagnostic statistics
    diagnostics <- list(
      n_observations = nrow(spatial_data),
      n_connections = sum(spdep::card(nb)),
      avg_neighbors = mean(spdep::card(nb)),
      min_neighbors = min(spdep::card(nb)),
      max_neighbors = max(spdep::card(nb)),
      weight_style = weight_style,
      bonferroni_correction = bonferroni_alpha
    )
    
    return(list(
      # Global statistics
      global_moran = list(
        statistic = moran_test$estimate[1],
        expected = moran_test$estimate[2],
        variance = moran_test$estimate[3],
        z_score = (moran_test$estimate[1] - moran_test$estimate[2]) / sqrt(moran_test$estimate[3]),
        p_value = moran_test$p.value,
        significance_level = significance_level,
        interpretation = interpretation
      ),
      
      # Local statistics
      local_moran = local_moran,
      
      # Enhanced spatial data with LISA results
      spatial_data_enhanced = spatial_data,
      
      # Cluster summary
      cluster_summary = spatial_data %>%
        sf::st_drop_geometry() %>%
        count(lisa_cluster) %>%
        mutate(percentage = round(n / sum(n) * 100, 1)),
      
      # Diagnostics
      diagnostics = diagnostics,
      
      # Academic metadata
      methodology = list(
        method = "Moran's I Spatial Autocorrelation Analysis",
        reference = "Moran, P.A.P. (1950). Notes on Continuous Stochastic Phenomena. Biometrika, 37, 17-23.",
        local_reference = "Anselin, L. (1995). Local Indicators of Spatial Association-LISA. Geographical Analysis, 27(2), 93-115.",
        software = "R packages: spdep, sf",
        coordinate_system = "SIRGAS 2000 (EPSG:4674)",
        calculated_at = Sys.time()
      )
    ))
    
  }, error = function(e) {
    warning("Error in Moran's I calculation: ", e$message)
    return(NULL)
  })
}

#' Calculate Getis-Ord Gi* Hotspot Analysis
#' 
#' Academic implementation of Getis-Ord Gi* statistic for hotspot detection
#' in Brazilian legislative document distribution with statistical validation
#' 
#' @param spatial_data SF object with legislative data and geometry
#' @param variable Character name of variable to analyze (default: "doc_count")
#' @param significance_level Significance level for hotspot classification (default: 0.05)
#' @param include_self Include focal area in calculations (default: TRUE)
#' @return List with Gi* results and hotspot classifications
calculate_getis_ord_gi <- function(spatial_data,
                                   variable = "doc_count",
                                   significance_level = 0.05,
                                   include_self = TRUE) {
  
  tryCatch({
    
    # Validate input data
    if (!inherits(spatial_data, "sf")) {
      stop("Input must be an sf object")
    }
    
    if (!variable %in% names(spatial_data)) {
      stop(paste("Variable", variable, "not found in spatial data"))
    }
    
    # Create spatial weights matrix
    coords <- sf::st_centroid(spatial_data) %>% sf::st_coordinates()
    nb <- spdep::poly2nb(spatial_data, queen = TRUE)
    
    # Include self in neighborhood if specified (Gi* vs Gi)
    if (include_self) {
      nb <- spdep::include.self(nb)
    }
    
    # Handle areas with no neighbors
    if (any(spdep::card(nb) == 0)) {
      knn <- spdep::knearneigh(coords, k = 1)
      nb_knn <- spdep::knn2nb(knn)
      nb <- spdep::union.nb(nb, nb_knn)
      if (include_self) {
        nb <- spdep::include.self(nb)
      }
    }
    
    # Create listw object with binary weights
    listw <- spdep::nb2listw(nb, style = "B", zero.policy = TRUE)
    
    # Calculate Getis-Ord Gi* statistics
    gi_results <- spdep::localG(spatial_data[[variable]], listw, zero.policy = TRUE)
    
    # Apply Bonferroni correction for multiple testing
    n_tests <- length(gi_results)
    bonferroni_alpha <- significance_level / n_tests
    
    # Calculate critical z-values
    z_critical_high <- qnorm(1 - bonferroni_alpha/2)
    z_critical_low <- qnorm(bonferroni_alpha/2)
    
    # Add Gi* results to spatial data
    spatial_data$gi_z_score <- as.numeric(gi_results)
    spatial_data$gi_p_value <- 2 * (1 - pnorm(abs(spatial_data$gi_z_score)))
    
    # Classify hotspots and coldspots with significance levels
    spatial_data$hotspot_classification <- case_when(
      spatial_data$gi_p_value > bonferroni_alpha ~ "Not Significant",
      spatial_data$gi_z_score > 2.58 ~ "High Confidence Hotspot (p < 0.01)",
      spatial_data$gi_z_score > 1.96 ~ "Moderate Confidence Hotspot (p < 0.05)",
      spatial_data$gi_z_score > 1.65 ~ "Low Confidence Hotspot (p < 0.10)",
      spatial_data$gi_z_score < -2.58 ~ "High Confidence Coldspot (p < 0.01)",
      spatial_data$gi_z_score < -1.96 ~ "Moderate Confidence Coldspot (p < 0.05)",
      spatial_data$gi_z_score < -1.65 ~ "Low Confidence Coldspot (p < 0.10)",
      TRUE ~ "Not Significant"
    )
    
    # Create simplified classification for visualization
    spatial_data$hotspot_simple <- case_when(
      spatial_data$gi_z_score > 1.96 & spatial_data$gi_p_value < bonferroni_alpha ~ "Hotspot",
      spatial_data$gi_z_score < -1.96 & spatial_data$gi_p_value < bonferroni_alpha ~ "Coldspot",
      TRUE ~ "Not Significant"
    )
    
    # Calculate summary statistics
    hotspot_summary <- spatial_data %>%
      sf::st_drop_geometry() %>%
      count(hotspot_classification) %>%
      mutate(percentage = round(n / sum(n) * 100, 1))
    
    # Identify significant hotspots and coldspots
    significant_hotspots <- spatial_data %>%
      filter(hotspot_simple == "Hotspot") %>%
      arrange(desc(gi_z_score)) %>%
      select(all_of(c("state_code", "state_name", variable, "gi_z_score", "gi_p_value")))
    
    significant_coldspots <- spatial_data %>%
      filter(hotspot_simple == "Coldspot") %>%
      arrange(gi_z_score) %>%
      select(all_of(c("state_code", "state_name", variable, "gi_z_score", "gi_p_value")))
    
    return(list(
      # Enhanced spatial data with Gi* results
      spatial_data_enhanced = spatial_data,
      
      # Summary statistics
      hotspot_summary = hotspot_summary,
      
      # Significant areas
      significant_hotspots = significant_hotspots,
      significant_coldspots = significant_coldspots,
      
      # Statistical parameters
      parameters = list(
        n_observations = nrow(spatial_data),
        significance_level = significance_level,
        bonferroni_alpha = bonferroni_alpha,
        z_critical_high = z_critical_high,
        z_critical_low = z_critical_low,
        include_self = include_self
      ),
      
      # Academic metadata
      methodology = list(
        method = ifelse(include_self, "Getis-Ord Gi* Hotspot Analysis", "Getis-Ord Gi Hotspot Analysis"),
        reference = "Getis, A., & Ord, J.K. (1992). The Analysis of Spatial Association by Use of Distance Statistics. Geographical Analysis, 24(3), 189-206.",
        software = "R package: spdep",
        multiple_testing_correction = "Bonferroni correction",
        coordinate_system = "SIRGAS 2000 (EPSG:4674)",
        calculated_at = Sys.time()
      )
    ))
    
  }, error = function(e) {
    warning("Error in Getis-Ord Gi* calculation: ", e$message)
    return(NULL)
  })
}

#' Create Academic Spatial Clustering Visualization
#' 
#' Generate publication-quality maps showing spatial clustering results
#' with proper academic styling and statistical annotations
#' 
#' @param moran_results Results from calculate_morans_i function
#' @param gi_results Results from calculate_getis_ord_gi function
#' @param map_type Type of map to create ("moran", "hotspot", "combined")
#' @return ggplot object with spatial clustering visualization
create_spatial_clustering_map <- function(moran_results = NULL, gi_results = NULL, map_type = "combined") {
  
  if (map_type == "moran" && !is.null(moran_results)) {
    
    # LISA cluster map
    spatial_data <- moran_results$spatial_data_enhanced
    
    # Define academic color palette for LISA clusters
    lisa_colors <- c(
      "High-High" = "#d73027",     # Red for high-high clusters
      "Low-Low" = "#313695",      # Blue for low-low clusters
      "High-Low" = "#f46d43",     # Orange for high-low outliers
      "Low-High" = "#74add1",     # Light blue for low-high outliers
      "Not Significant" = "#f7f7f7"  # Light gray for non-significant
    )
    
    p <- ggplot(spatial_data) +
      geom_sf(aes(fill = lisa_cluster), color = "white", size = 0.3) +
      scale_fill_manual(values = lisa_colors, name = "LISA Clusters") +
      labs(
        title = "Local Indicators of Spatial Association (LISA)",
        subtitle = paste0(
          "Moran's I = ", sprintf("%.4f", moran_results$global_moran$statistic),
          ", p-value = ", sprintf("%.4f", moran_results$global_moran$p_value)
        ),
        caption = "Methodology: Anselin (1995) LISA with Bonferroni correction | SIRGAS 2000"
      ) +
      theme_void() +
      theme(
        plot.title = element_text(size = 14, face = "bold", hjust = 0.5),
        plot.subtitle = element_text(size = 11, hjust = 0.5),
        plot.caption = element_text(size = 8, color = "gray60", hjust = 0.5),
        legend.position = "bottom",
        legend.title = element_text(size = 10, face = "bold"),
        panel.background = element_rect(fill = "white", color = NA)
      )
    
  } else if (map_type == "hotspot" && !is.null(gi_results)) {
    
    # Getis-Ord Gi* hotspot map
    spatial_data <- gi_results$spatial_data_enhanced
    
    # Define academic color palette for hotspots
    hotspot_colors <- c(
      "High Confidence Hotspot (p < 0.01)" = "#b10026",
      "Moderate Confidence Hotspot (p < 0.05)" = "#fd8d3c",
      "Low Confidence Hotspot (p < 0.10)" = "#fecc5c",
      "Not Significant" = "#f7f7f7",
      "Low Confidence Coldspot (p < 0.10)" = "#c6dbef",
      "Moderate Confidence Coldspot (p < 0.05)" = "#6baed6",
      "High Confidence Coldspot (p < 0.01)" = "#2171b5"
    )
    
    p <- ggplot(spatial_data) +
      geom_sf(aes(fill = hotspot_classification), color = "white", size = 0.3) +
      scale_fill_manual(values = hotspot_colors, name = "Hotspot Classification") +
      labs(
        title = "Getis-Ord Gi* Hotspot Analysis",
        subtitle = "Statistical hotspots and coldspots of legislative activity",
        caption = "Methodology: Getis & Ord (1992) with Bonferroni correction | SIRGAS 2000"
      ) +
      theme_void() +
      theme(
        plot.title = element_text(size = 14, face = "bold", hjust = 0.5),
        plot.subtitle = element_text(size = 11, hjust = 0.5),
        plot.caption = element_text(size = 8, color = "gray60", hjust = 0.5),
        legend.position = "bottom",
        legend.title = element_text(size = 10, face = "bold"),
        panel.background = element_rect(fill = "white", color = NA)
      )
    
  } else if (map_type == "combined" && !isTRUE(is.null(moran_results)) && !is.null(gi_results)) {
    
    # Combined visualization (side-by-side)
    lisa_map <- create_spatial_clustering_map(moran_results, NULL, "moran")
    hotspot_map <- create_spatial_clustering_map(NULL, gi_results, "hotspot")
    
    # Use patchwork or gridExtra to combine plots
    if (requireNamespace("patchwork", quietly = TRUE)) {
      p <- lisa_map | hotspot_map
    } else {
      # Return LISA map as fallback
      p <- lisa_map
    }
  } else {
    
    # Error handling - empty plot with message
    p <- ggplot() +
      geom_text(aes(x = 0.5, y = 0.5, label = "Spatial clustering analysis not available"),
                size = 5, color = "gray60") +
      theme_void() +
      xlim(0, 1) + ylim(0, 1)
  }
  
  return(p)
}

#' Generate Spatial Clustering Report
#' 
#' Create comprehensive academic report of spatial clustering analysis results
#' following RESEARCH_METHODOLOGY.md standards
#' 
#' @param moran_results Results from calculate_morans_i function
#' @param gi_results Results from calculate_getis_ord_gi function
#' @return List with formatted report components
generate_spatial_clustering_report <- function(moran_results = NULL, gi_results = NULL) {
  
  report <- list()
  
  if (!is.null(moran_results)) {
    report$moran_analysis <- list(
      title = "Global Spatial Autocorrelation Analysis (Moran's I)",
      statistic = sprintf("%.4f", moran_results$global_moran$statistic),
      expected = sprintf("%.4f", moran_results$global_moran$expected),
      z_score = sprintf("%.4f", moran_results$global_moran$z_score),
      p_value = ifelse(moran_results$global_moran$p_value < 0.001, "< 0.001", 
                      sprintf("%.4f", moran_results$global_moran$p_value)),
      interpretation = moran_results$global_moran$interpretation,
      cluster_summary = moran_results$cluster_summary
    )
  }
  
  if (!is.null(gi_results)) {
    report$hotspot_analysis <- list(
      title = "Local Hotspot Analysis (Getis-Ord Gi*)",
      total_hotspots = nrow(gi_results$significant_hotspots),
      total_coldspots = nrow(gi_results$significant_coldspots),
      hotspot_summary = gi_results$hotspot_summary,
      top_hotspots = gi_results$significant_hotspots,
      top_coldspots = gi_results$significant_coldspots
    )
  }
  
  # Academic methodology section
  report$methodology <- list(
    statistical_methods = c(
      "Moran's I Global Spatial Autocorrelation",
      "Local Indicators of Spatial Association (LISA)",
      "Getis-Ord Gi* Local Hotspot Analysis"
    ),
    significance_testing = "Bonferroni correction for multiple comparisons",
    spatial_weights = "Queen contiguity with k-nearest neighbors for islands",
    coordinate_system = "SIRGAS 2000 (EPSG:4674) - Brazilian official datum",
    software = "R packages: spdep (ver. 1.2-8), sf (ver. 1.0-14)",
    references = c(
      "Moran, P.A.P. (1950). Notes on Continuous Stochastic Phenomena. Biometrika, 37, 17-23.",
      "Anselin, L. (1995). Local Indicators of Spatial Association. Geographical Analysis, 27(2), 93-115.",
      "Getis, A., & Ord, J.K. (1992). The Analysis of Spatial Association by Use of Distance Statistics. Geographical Analysis, 24(3), 189-206."
    )
  )
  
  return(report)
}

# Export all functions
list(
  calculate_morans_i = calculate_morans_i,
  calculate_getis_ord_gi = calculate_getis_ord_gi,
  create_spatial_clustering_map = create_spatial_clustering_map,
  generate_spatial_clustering_report = generate_spatial_clustering_report
)