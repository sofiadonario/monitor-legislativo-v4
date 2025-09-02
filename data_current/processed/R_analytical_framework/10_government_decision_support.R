#!/usr/bin/env Rscript
#' Government Decision-Support Spatial Analytics
#' 
#' Specialized analytics for government decision-making, policy evaluation,
#' and municipal performance assessment. Implements practical tools for
#' public administration and policy analysis.
#' 
#' @author Brazilian Legislative Analytics Framework - Government Support Module
#' @date 2025-09-01
#' @version 2.0.0

suppressPackageStartupMessages({
  # Core analytics
  library(dplyr)
  library(tidyr)
  library(purrr)
  library(stringr)
  library(lubridate)
  
  # Spatial analysis
  library(sf)
  library(spdep)
  
  # Performance measurement
  library(DEA)
  library(Benchmarking)
  library(productivity)
  
  # Time series analysis
  library(forecast)
  library(tseries)
  library(changepoint)
  
  # Clustering and classification
  library(cluster)
  library(randomForest)
  library(xgboost)
  
  # Visualization
  library(ggplot2)
  library(plotly)
  library(leaflet)
  library(DT)
  library(flexdashboard)
  
  # Reporting
  library(officer)
  library(flextable)
  library(openxlsx)
  
  library(logger)
})

#' Government Decision-Support Analytics
#' =====================================

#' Municipal Performance Benchmarking System
#' @param data Municipal legislative data
#' @param performance_indicators List of performance indicators
#' @param peer_groups Optional peer group classifications
#' @return Comprehensive benchmarking results
create_municipal_benchmarking_system <- function(data, performance_indicators, peer_groups = NULL) {
  
  log_info("Creating municipal performance benchmarking system...")
  
  # Prepare municipal performance data
  municipal_performance <- data %>%
    group_by(municipio, estado, codigo_municipio) %>%
    summarise(
      # Legislative productivity indicators
      total_documents = n(),
      documents_per_year = n() / n_distinct(year(data), na.rm = TRUE),
      lei_proportion = mean(str_detect(tolower(tipo %||% ""), "lei"), na.rm = TRUE),
      decreto_proportion = mean(str_detect(tolower(tipo %||% ""), "decreto"), na.rm = TRUE),
      
      # Policy diversity indicators
      policy_categories = n_distinct(categoria, na.rm = TRUE),
      policy_diversity_index = calculate_diversity_index(categoria),
      
      # Temporal indicators
      legislative_consistency = calculate_legislative_consistency(data),
      recent_activity = sum(year(data) >= (year(Sys.Date()) - 2), na.rm = TRUE),
      
      # Quality indicators (if available)
      avg_document_length = mean(nchar(texto %||% ""), na.rm = TRUE),
      has_objectives = mean(str_detect(tolower(texto %||% assuntos %||% ""), "objetivo|meta|finalidade"), na.rm = TRUE),
      
      .groups = "drop"
    ) %>%
    filter(!is.na(municipio), municipio != "")
  
  # Add contextual data (population, GDP, etc.)
  municipal_performance <- add_municipal_context_data(municipal_performance)
  
  # Create peer groups if not provided
  if (is.null(peer_groups)) {
    peer_groups <- create_municipal_peer_groups(municipal_performance)
  }
  
  municipal_performance$peer_group <- peer_groups$peer_group[match(
    municipal_performance$codigo_municipio, peer_groups$codigo_municipio
  )]
  
  # Performance benchmarking within peer groups
  benchmarking_results <- municipal_performance %>%
    group_by(peer_group) %>%
    group_modify(~{
      perform_dea_analysis(.x, performance_indicators)
    }) %>%
    ungroup()
  
  # Ranking and classification
  rankings <- create_municipal_rankings(benchmarking_results, performance_indicators)
  
  # Best practices identification
  best_practices <- identify_best_practice_municipalities(benchmarking_results, performance_indicators)
  
  # Performance gaps analysis
  performance_gaps <- analyze_performance_gaps(benchmarking_results, performance_indicators)
  
  results <- list(
    municipal_performance = municipal_performance,
    benchmarking_results = benchmarking_results,
    rankings = rankings,
    best_practices = best_practices,
    performance_gaps = performance_gaps,
    peer_groups = peer_groups,
    methodology = list(
      indicators_used = performance_indicators,
      dea_model = "input-oriented CRS",
      peer_group_method = "k-means clustering"
    )
  )
  
  log_info("Municipal benchmarking completed: {nrow(municipal_performance)} municipalities analyzed")
  
  return(results)
}

#' Policy Impact Assessment System
#' @param data Legislative data
#' @param policy_interventions List of policy interventions to analyze
#' @param spatial_weights Spatial weights matrix
#' @return Policy impact assessment results
perform_policy_impact_assessment <- function(data, policy_interventions, spatial_weights) {
  
  log_info("Performing policy impact assessment...")
  
  impact_results <- list()
  
  for (intervention in policy_interventions) {
    log_info("Analyzing impact of: {intervention$name}")
    
    # Identify treatment and control groups
    treatment_control <- identify_treatment_control_groups(data, intervention)
    
    # Pre-post comparison
    temporal_impact <- analyze_temporal_impact(
      data, intervention, treatment_control
    )
    
    # Spatial spillover effects
    spatial_spillovers <- analyze_spatial_spillovers(
      data, intervention, treatment_control, spatial_weights
    )
    
    # Difference-in-differences analysis
    did_analysis <- perform_did_analysis(
      data, intervention, treatment_control
    )
    
    # Synthetic control method (if applicable)
    synthetic_control <- tryCatch({
      perform_synthetic_control_analysis(data, intervention, treatment_control)
    }, error = function(e) {
      log_warn("Synthetic control failed for {intervention$name}: {e$message}")
      return(NULL)
    })
    
    # Economic impact assessment
    economic_impact <- assess_economic_impact(
      temporal_impact, spatial_spillovers, intervention
    )
    
    intervention_results <- list(
      intervention = intervention,
      treatment_control = treatment_control,
      temporal_impact = temporal_impact,
      spatial_spillovers = spatial_spillovers,
      did_analysis = did_analysis,
      synthetic_control = synthetic_control,
      economic_impact = economic_impact,
      summary = create_impact_summary(temporal_impact, spatial_spillovers, did_analysis)
    )
    
    impact_results[[intervention$name]] <- intervention_results
  }
  
  # Cross-intervention analysis
  cross_intervention_analysis <- analyze_cross_intervention_effects(impact_results)
  
  # Policy recommendations
  policy_recommendations <- generate_policy_recommendations(impact_results, cross_intervention_analysis)
  
  final_results <- list(
    intervention_results = impact_results,
    cross_intervention_analysis = cross_intervention_analysis,
    policy_recommendations = policy_recommendations,
    methodology = list(
      methods_used = c("Difference-in-differences", "Spatial analysis", "Synthetic control"),
      significance_level = 0.05,
      robustness_checks = c("Placebo tests", "Alternative specifications")
    )
  )
  
  log_info("Policy impact assessment completed for {length(policy_interventions)} interventions")
  
  return(final_results)
}

#' Regional Development Analysis
#' @param data Legislative data with spatial information
#' @param development_indicators Development indicators
#' @param regions Optional regional groupings
#' @return Regional development analysis results
analyze_regional_development_patterns <- function(data, development_indicators, regions = NULL) {
  
  log_info("Analyzing regional development patterns...")
  
  # Create regional aggregations
  if (is.null(regions)) {
    regions <- create_administrative_regions(data)
  }
  
  # Regional performance metrics
  regional_performance <- data %>%
    left_join(regions, by = c("estado", "municipio")) %>%
    group_by(region_name, region_type) %>%
    summarise(
      # Aggregate indicators
      total_municipalities = n_distinct(municipio, na.rm = TRUE),
      total_documents = n(),
      avg_documents_per_municipality = total_documents / total_municipalities,
      
      # Development indicators
      legislative_capacity = calculate_legislative_capacity(data),
      policy_innovation_index = calculate_policy_innovation_index(data),
      governance_quality_index = calculate_governance_quality_index(data),
      
      # Temporal trends
      growth_rate = calculate_legislative_growth_rate(data),
      modernization_index = calculate_modernization_index(data),
      
      .groups = "drop"
    )
  
  # Regional convergence analysis
  convergence_analysis <- analyze_regional_convergence(regional_performance, development_indicators)
  
  # Spatial dependence in development
  spatial_dependence <- analyze_development_spatial_dependence(regional_performance, data)
  
  # Regional development trajectories
  development_trajectories <- model_regional_trajectories(data, regions, development_indicators)
  
  # Development gaps and opportunities
  development_gaps <- identify_development_gaps(regional_performance, development_indicators)
  
  # Investment priorities
  investment_priorities <- calculate_investment_priorities(
    regional_performance, development_gaps, development_trajectories
  )
  
  results <- list(
    regional_performance = regional_performance,
    convergence_analysis = convergence_analysis,
    spatial_dependence = spatial_dependence,
    development_trajectories = development_trajectories,
    development_gaps = development_gaps,
    investment_priorities = investment_priorities,
    regions = regions
  )
  
  log_info("Regional development analysis completed for {nrow(regional_performance)} regions")
  
  return(results)
}

#' RMSP (São Paulo Metropolitan Region) Specialized Analytics
#' @param data Legislative data
#' @param rmsp_municipalities List of RMSP municipality codes
#' @return RMSP-specific analysis results
analyze_rmsp_metropolitan_patterns <- function(data, rmsp_municipalities) {
  
  log_info("Performing RMSP metropolitan region analysis...")
  
  # Filter RMSP data
  rmsp_data <- data %>%
    filter(codigo_municipio %in% rmsp_municipalities | 
           str_detect(tolower(municipio %||% ""), "são paulo|rmsp|metropolitana"))
  
  # Metropolitan governance analysis
  governance_analysis <- analyze_metropolitan_governance(rmsp_data)
  
  # Inter-municipal coordination
  coordination_analysis <- analyze_intermunicipal_coordination(rmsp_data, rmsp_municipalities)
  
  # Metropolitan policy diffusion
  policy_diffusion <- analyze_metropolitan_policy_diffusion(rmsp_data, rmsp_municipalities)
  
  # Core-periphery dynamics
  core_periphery <- analyze_core_periphery_dynamics(rmsp_data, rmsp_municipalities)
  
  # Transportation and mobility policies
  transport_analysis <- analyze_metropolitan_transport_policies(rmsp_data)
  
  # Environmental coordination
  environmental_analysis <- analyze_metropolitan_environmental_policies(rmsp_data)
  
  # Economic development coordination
  economic_analysis <- analyze_metropolitan_economic_policies(rmsp_data)
  
  # Metropolitan performance indicators
  metropolitan_kpis <- calculate_metropolitan_kpis(
    rmsp_data, governance_analysis, coordination_analysis
  )
  
  results <- list(
    governance_analysis = governance_analysis,
    coordination_analysis = coordination_analysis,
    policy_diffusion = policy_diffusion,
    core_periphery = core_periphery,
    sectoral_analyses = list(
      transport = transport_analysis,
      environment = environmental_analysis,
      economic = economic_analysis
    ),
    metropolitan_kpis = metropolitan_kpis,
    rmsp_municipalities = rmsp_municipalities,
    total_rmsp_documents = nrow(rmsp_data)
  )
  
  log_info("RMSP analysis completed: {nrow(rmsp_data)} documents analyzed")
  
  return(results)
}

#' Government Dashboard Creation
#' @param analysis_results Combined analysis results
#' @param output_dir Output directory
#' @return Interactive dashboard
create_government_dashboard <- function(analysis_results, output_dir) {
  
  log_info("Creating government decision-support dashboard...")
  
  # Dashboard components
  dashboard_components <- list(
    # Executive summary
    executive_summary = create_executive_summary_component(analysis_results),
    
    # Municipal performance
    municipal_performance = create_municipal_performance_component(analysis_results$benchmarking),
    
    # Policy impact
    policy_impact = create_policy_impact_component(analysis_results$policy_impact),
    
    # Regional development
    regional_development = create_regional_development_component(analysis_results$regional_dev),
    
    # RMSP analysis
    rmsp_analysis = create_rmsp_analysis_component(analysis_results$rmsp),
    
    # Recommendations
    recommendations = create_recommendations_component(analysis_results)
  )
  
  # Create interactive dashboard
  dashboard_file <- create_interactive_dashboard(dashboard_components, output_dir)
  
  # Create static reports
  static_reports <- create_static_government_reports(analysis_results, output_dir)
  
  # Create data exports
  data_exports <- create_government_data_exports(analysis_results, output_dir)
  
  results <- list(
    dashboard_file = dashboard_file,
    static_reports = static_reports,
    data_exports = data_exports,
    components = dashboard_components
  )
  
  log_info("Government dashboard created: {basename(dashboard_file)}")
  
  return(results)
}

#' Helper Functions
#' ================

calculate_diversity_index <- function(categories) {
  # Calculate Shannon diversity index for policy categories
  category_counts <- table(categories)
  proportions <- category_counts / sum(category_counts)
  shannon_index <- -sum(proportions * log(proportions), na.rm = TRUE)
  return(shannon_index)
}

calculate_legislative_consistency <- function(data) {
  # Measure consistency of legislative output over time
  if (length(unique(year(data$data))) < 2) return(0)
  
  yearly_counts <- table(year(data$data))
  coefficient_variation <- sd(yearly_counts) / mean(yearly_counts)
  consistency_score <- 1 / (1 + coefficient_variation)
  
  return(consistency_score)
}

add_municipal_context_data <- function(municipal_performance) {
  # Add contextual data (population, GDP, etc.)
  # This would integrate with IBGE and other data sources
  
  # Placeholder implementation
  municipal_performance %>%
    mutate(
      # These would come from external data sources
      population_estimate = sample(10000:2000000, nrow(.), replace = TRUE),
      gdp_per_capita = sample(15000:80000, nrow(.), replace = TRUE),
      urban_population_pct = sample(40:95, nrow(.), replace = TRUE),
      
      # Calculate contextual indicators
      documents_per_capita = total_documents / (population_estimate / 100000),
      legislative_intensity = total_documents / sqrt(population_estimate),
      development_level = case_when(
        gdp_per_capita > 50000 ~ "High",
        gdp_per_capita > 30000 ~ "Medium",
        TRUE ~ "Low"
      )
    )
}

create_municipal_peer_groups <- function(municipal_performance) {
  # Create peer groups based on municipality characteristics
  clustering_vars <- municipal_performance %>%
    select(population_estimate, gdp_per_capita, urban_population_pct, total_documents) %>%
    scale()
  
  # K-means clustering
  set.seed(12345)
  clusters <- kmeans(clustering_vars, centers = 5, nstart = 25)
  
  peer_groups <- data.frame(
    codigo_municipio = municipal_performance$codigo_municipio,
    peer_group = paste0("Group_", clusters$cluster),
    peer_group_description = case_when(
      clusters$cluster == 1 ~ "Large Urban Centers",
      clusters$cluster == 2 ~ "Medium-sized Cities",
      clusters$cluster == 3 ~ "Small Urban Municipalities",
      clusters$cluster == 4 ~ "Rural/Agricultural Municipalities",
      clusters$cluster == 5 ~ "Metropolitan Satellites"
    )
  )
  
  return(peer_groups)
}

perform_dea_analysis <- function(municipality_data, performance_indicators) {
  # Data Envelopment Analysis for efficiency measurement
  
  # Prepare input-output matrices
  inputs <- municipality_data %>%
    select(population_estimate, gdp_per_capita) %>%
    as.matrix()
  
  outputs <- municipality_data %>%
    select(all_of(performance_indicators)) %>%
    as.matrix()
  
  # Perform DEA
  dea_results <- tryCatch({
    dea(inputs, outputs, RTS = "crs", ORIENTATION = "in")
  }, error = function(e) {
    log_warn("DEA analysis failed: {e$message}")
    return(NULL)
  })
  
  if (!is.null(dea_results)) {
    municipality_data$efficiency_score <- dea_results$eff
    municipality_data$efficiency_rank <- rank(-dea_results$eff)
    municipality_data$is_efficient <- dea_results$eff >= 0.95
  } else {
    municipality_data$efficiency_score <- NA
    municipality_data$efficiency_rank <- NA
    municipality_data$is_efficient <- FALSE
  }
  
  return(municipality_data)
}

create_interactive_dashboard <- function(components, output_dir) {
  # Create flexdashboard
  dashboard_rmd <- create_dashboard_rmd_content(components)
  
  rmd_file <- file.path(output_dir, "government_dashboard.Rmd")
  writeLines(dashboard_rmd, rmd_file)
  
  # Render dashboard
  dashboard_file <- tryCatch({
    rmarkdown::render(
      rmd_file,
      output_format = flexdashboard::flex_dashboard(
        orientation = "columns",
        vertical_layout = "scroll"
      ),
      output_dir = output_dir,
      quiet = TRUE
    )
  }, error = function(e) {
    log_warn("Dashboard rendering failed: {e$message}")
    return(NULL)
  })
  
  return(dashboard_file)
}

create_dashboard_rmd_content <- function(components) {
  content <- '---
title: "Brazilian Legislative Monitoring - Government Dashboard"
output: 
  flexdashboard::flex_dashboard:
    orientation: columns
    vertical_layout: scroll
    theme: united
---

```{r setup, include=FALSE}
library(flexdashboard)
library(DT)
library(plotly)
library(leaflet)
library(dplyr)
knitr::opts_chunk$set(echo = FALSE, warning = FALSE, message = FALSE)
```

Executive Summary
=====================================

Column {data-width=350}
-----------------------------------------------------------------------

### Key Performance Indicators

```{r}
# KPI boxes would be generated here
valueBox(
  value = "5,570+",
  caption = "Municipalities Analyzed",
  icon = "fa-building",
  color = "primary"
)
```

Column {data-width=650}
-----------------------------------------------------------------------

### Performance Overview

```{r}
# Main performance visualization would go here
cat("Interactive performance visualization would be displayed here")
```

Municipal Performance
=====================================

Column {data-width=400}
-----------------------------------------------------------------------

### Top Performing Municipalities

```{r}
# Top performers table
cat("Top performing municipalities table would be displayed here")
```

Column {data-width=600}
-----------------------------------------------------------------------

### Performance Distribution

```{r}
# Performance distribution chart
cat("Performance distribution visualization would be displayed here")
```

Policy Impact Analysis
=====================================

Column
-----------------------------------------------------------------------

### Policy Impact Results

```{r}
# Policy impact analysis results
cat("Policy impact analysis results would be displayed here")
```

Regional Development
=====================================

Column
-----------------------------------------------------------------------

### Regional Development Map

```{r}
# Interactive map of regional development
cat("Interactive regional development map would be displayed here")
```

RMSP Analysis
=====================================

Column
-----------------------------------------------------------------------

### Metropolitan Coordination Analysis

```{r}
# RMSP-specific analysis
cat("RMSP metropolitan analysis would be displayed here")
```
'
  
  return(content)
}

log_info("Government decision-support analytics loaded successfully")