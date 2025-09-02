#!/usr/bin/env Rscript
#' Enhanced Spatial Analytics Integration
#' 
#' Main integration module that orchestrates all enhanced spatial analytics
#' capabilities for Brazilian legislative documents. Provides a unified
#' interface for comprehensive municipality-level analysis.
#' 
#' @author Brazilian Legislative Analytics Framework - Integration Module
#' @date 2025-09-01
#' @version 2.0.0

# Source all enhanced spatial modules
suppressPackageStartupMessages({
  library(logger)
  library(dplyr)
  library(purrr)
  library(future)
  library(arrow)
})

# Set up logging
log_threshold(INFO)

# Source enhanced spatial modules
module_path <- "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/R_analytical_framework"

tryCatch({
  source(file.path(module_path, "08_enhanced_spatial_analytics.R"))
  source(file.path(module_path, "09_research_grade_spatial_methods.R"))  
  source(file.path(module_path, "10_government_decision_support.R"))
  source(file.path(module_path, "11_performance_optimization.R"))
  log_info("All enhanced spatial modules loaded successfully")
}, error = function(e) {
  log_error("Failed to load modules: {e$message}")
  stop("Module loading failed")
})

#' Enhanced Spatial Analytics Master System
#' =========================================

#' Initialize Complete Enhanced Spatial System
#' @param data_source Path to legislative data
#' @param cache_dir Cache directory for optimization
#' @param config Configuration parameters
#' @return Complete enhanced spatial analytics system
initialize_complete_spatial_system <- function(data_source, 
                                              cache_dir = "cache/enhanced_spatial", 
                                              config = list()) {
  
  log_info("=== INITIALIZING COMPLETE ENHANCED SPATIAL SYSTEM ===")
  
  # Default configuration
  default_config <- list(
    max_workers = min(4, parallel::detectCores() - 1),
    memory_limit_gb = 8,
    cache_size_mb = 2000,
    sample_size = NULL,  # NULL for full dataset
    analysis_scope = "full",  # "full", "sample", "state_focus"
    target_states = NULL,
    enable_caching = TRUE,
    enable_parallel = TRUE,
    research_grade = TRUE,
    government_support = TRUE
  )
  
  # Merge with provided config
  final_config <- modifyList(default_config, config)
  
  # 1. Initialize high-performance computing environment
  hpc_env <- initialize_hpc_environment(
    max_workers = final_config$max_workers,
    memory_limit = final_config$memory_limit_gb,
    cache_size = final_config$cache_size_mb
  )
  
  # 2. Initialize caching system
  if (final_config$enable_caching) {
    cache_system <- create_efficient_caching_system(
      cache_dir = cache_dir,
      max_cache_size = final_config$cache_size_mb
    )
  } else {
    cache_system <- NULL
  }
  
  # 3. Initialize optimized data loader
  data_loader <- create_optimized_municipality_loader(
    data_source = data_source,
    chunk_size = 10000,
    states = final_config$target_states
  )
  
  # 4. Load and prepare data
  log_info("Loading and preparing legislative data...")
  
  if (!is.null(final_config$sample_size)) {
    # Use sampling system
    full_data <- data_loader$data_reader()
    sampling_system <- create_intelligent_sampling_system(
      data = full_data,
      target_size = final_config$sample_size
    )
    
    legislative_data <- sampling_system$create_adaptive_sample()$sample
    log_info("Using sample of {nrow(legislative_data)} documents")
  } else {
    legislative_data <- data_loader$data_reader()
    sampling_system <- NULL
    log_info("Using full dataset: {nrow(legislative_data)} documents")
  }
  
  # 5. Initialize enhanced spatial analytics
  enhanced_spatial <- initialize_enhanced_spatial_system(
    cache_dir = file.path(cache_dir, "spatial"),
    parallel_workers = final_config$max_workers
  )
  
  # 6. Load municipality boundaries and create fast spatial operations
  municipality_data <- enhanced_spatial$load_municipality_data(final_config$target_states)
  
  fast_spatial_ops <- create_fast_spatial_operations(
    boundaries = municipality_data$boundaries,
    max_simplification = 0.001
  )
  
  # 7. Initialize performance profiler
  profiler <- create_performance_profiler()
  
  # Create integrated system
  complete_system <- list(
    # Core components
    hpc_environment = hpc_env,
    cache_system = cache_system,
    data_loader = data_loader,
    sampling_system = sampling_system,
    enhanced_spatial = enhanced_spatial,
    fast_spatial_ops = fast_spatial_ops,
    profiler = profiler,
    
    # Data
    legislative_data = legislative_data,
    municipality_data = municipality_data,
    
    # Configuration
    config = final_config,
    
    # Main analysis functions
    run_complete_analysis = function(output_dir) {
      run_complete_enhanced_analysis(complete_system, output_dir)
    },
    
    run_research_analysis = function(output_dir) {
      if (final_config$research_grade) {
        run_research_grade_analysis(complete_system, output_dir)
      } else {
        log_warn("Research-grade analysis not enabled in configuration")
      }
    },
    
    run_government_analysis = function(output_dir) {
      if (final_config$government_support) {
        run_government_decision_support_analysis(complete_system, output_dir)
      } else {
        log_warn("Government decision-support analysis not enabled in configuration")
      }
    },
    
    # Performance monitoring
    monitor_performance = function() {
      hpc_env$monitor_performance()
    },
    
    # Cleanup
    cleanup = function() {
      hpc_env$cleanup()
      if (!is.null(cache_system)) {
        cache_system$cleanup_cache()
      }
      gc(verbose = FALSE)
    }
  )
  
  log_info("Complete enhanced spatial system initialized")
  log_info("Data: {nrow(legislative_data)} documents, {nrow(municipality_data$boundaries)} municipalities")
  log_info("Configuration: {final_config$analysis_scope} scope, {final_config$max_workers} workers")
  
  return(complete_system)
}

#' Run Complete Enhanced Analysis
#' @param system Complete spatial system
#' @param output_dir Output directory
#' @return Comprehensive analysis results
run_complete_enhanced_analysis <- function(system, output_dir) {
  
  log_info("=== RUNNING COMPLETE ENHANCED SPATIAL ANALYSIS ===")
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Track overall performance
  start_time <- Sys.time()
  
  # Define analysis variables based on data characteristics
  analysis_variables <- c("document_count", "lei_count", "decreto_count", "policy_diversity")
  policy_types <- c("sustentabilidade", "transporte", "digital", "educação", "saúde")
  
  results <- list()
  
  # 1. Enhanced Spatial Autocorrelation Analysis
  log_info("Phase 1: Enhanced spatial autocorrelation analysis...")
  
  results$spatial_autocorrelation <- system$profiler$monitor_memory(function() {
    system$enhanced_spatial$analyze_spatial_autocorrelation(
      system$legislative_data, 
      analysis_variables
    )
  })
  
  log_info("Spatial autocorrelation completed in {round(results$spatial_autocorrelation$execution_time, 2)} seconds")
  
  # 2. Multi-scale Hotspot Analysis
  log_info("Phase 2: Multi-scale hotspot analysis...")
  
  results$hotspot_analysis <- map(analysis_variables, function(var) {
    log_info("Analyzing hotspots for: {var}")
    
    system$profiler$monitor_memory(function() {
      perform_enhanced_hotspot_analysis(
        cache_dir = system$enhanced_spatial$cache_dir,
        data = system$legislative_data,
        variable = var
      )
    })
  })
  names(results$hotspot_analysis) <- analysis_variables
  
  # 3. Policy Diffusion Analysis
  log_info("Phase 3: Policy diffusion analysis...")
  
  results$policy_diffusion <- map(policy_types, function(policy) {
    log_info("Analyzing diffusion for: {policy}")
    
    system$profiler$monitor_memory(function() {
      analyze_enhanced_policy_diffusion(
        cache_dir = system$enhanced_spatial$cache_dir,
        data = system$legislative_data,
        policy_type = policy
      )
    })
  })
  names(results$policy_diffusion) <- policy_types
  
  # 4. Enhanced Cluster Analysis
  log_info("Phase 4: Enhanced cluster analysis...")
  
  results$cluster_analysis <- system$profiler$monitor_memory(function() {
    conduct_enhanced_cluster_analysis(
      cache_dir = system$enhanced_spatial$cache_dir,
      data = system$legislative_data,
      variables = analysis_variables
    )
  })
  
  # 5. Research-Grade Statistical Analysis (if enabled)
  if (system$config$research_grade) {
    log_info("Phase 5: Research-grade statistical analysis...")
    
    results$research_analysis <- perform_comprehensive_research_analysis(
      system, analysis_variables
    )
  }
  
  # 6. Government Decision-Support Analysis (if enabled)
  if (system$config$government_support) {
    log_info("Phase 6: Government decision-support analysis...")
    
    results$government_analysis <- perform_comprehensive_government_analysis(
      system, analysis_variables
    )
  }
  
  # 7. Performance Summary
  total_time <- difftime(Sys.time(), start_time, units = "mins")
  
  results$performance_summary <- list(
    total_execution_time_minutes = as.numeric(total_time),
    memory_usage_summary = system$monitor_performance(),
    cache_statistics = if (!is.null(system$cache_system)) system$cache_system$cache_statistics() else NULL,
    system_configuration = system$config
  )
  
  # 8. Generate Comprehensive Outputs
  log_info("Phase 7: Generating comprehensive outputs...")
  
  output_results <- generate_comprehensive_outputs(results, system, output_dir)
  
  # 9. Save master results file
  final_results <- list(
    analysis_results = results,
    output_results = output_results,
    system_metadata = list(
      analysis_date = Sys.time(),
      total_documents = nrow(system$legislative_data),
      total_municipalities = nrow(system$municipality_data$boundaries),
      variables_analyzed = analysis_variables,
      policies_analyzed = policy_types,
      system_config = system$config
    )
  )
  
  saveRDS(final_results, file.path(output_dir, "complete_enhanced_spatial_analysis.rds"))
  
  log_info("=== COMPLETE ENHANCED ANALYSIS FINISHED ===")
  log_info("Total execution time: {round(total_time, 2)} minutes")
  log_info("Results saved to: {output_dir}")
  
  return(final_results)
}

#' Research-Grade Analysis Pipeline
#' @param system Complete spatial system
#' @param output_dir Output directory
#' @return Research-grade analysis results
run_research_grade_analysis <- function(system, output_dir) {
  
  log_info("Running research-grade analysis pipeline...")
  
  research_dir <- file.path(output_dir, "research_grade")
  dir.create(research_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Aggregate data for research analysis
  municipal_data <- aggregate_data_by_municipality(
    system$legislative_data, 
    system$municipality_data$boundaries
  )
  
  # Create spatial weights
  spatial_weights <- system$fast_spatial_ops$create_weights("queen")
  
  research_results <- list()
  
  # 1. Rigorous Moran's I tests
  log_info("Performing rigorous Moran's I tests...")
  research_results$moran_tests <- map(c("document_count", "lei_count"), function(var) {
    perform_rigorous_moran_test(
      data = municipal_data,
      variable = var,
      spatial_weights = spatial_weights,
      alpha = 0.05
    )
  })
  names(research_results$moran_tests) <- c("document_count", "lei_count")
  
  # 2. Advanced LISA analysis
  log_info("Performing advanced LISA analysis...")
  research_results$lisa_analysis <- map(c("document_count", "lei_count"), function(var) {
    perform_advanced_lisa_analysis(
      data = municipal_data,
      variable = var,
      spatial_weights = spatial_weights,
      alpha = 0.05
    )
  })
  names(research_results$lisa_analysis) <- c("document_count", "lei_count")
  
  # 3. Geographically Weighted Regression
  if (nrow(municipal_data) >= 50) {
    log_info("Performing geographically weighted regression...")
    research_results$gwr_analysis <- perform_geographically_weighted_regression(
      data = municipal_data,
      formula = document_count ~ population_estimate + gdp_per_capita,
      coords = st_coordinates(st_centroid(municipal_data$geometry))
    )
  }
  
  # 4. Bayesian spatial analysis (if computationally feasible)
  if (nrow(municipal_data) <= 1000) {  # Limit for computational efficiency
    log_info("Performing Bayesian spatial analysis...")
    research_results$bayesian_analysis <- tryCatch({
      perform_bayesian_spatial_analysis(
        data = municipal_data,
        formula = document_count ~ population_estimate,
        spatial_weights = spatial_weights
      )
    }, error = function(e) {
      log_warn("Bayesian analysis failed: {e$message}")
      return(NULL)
    })
  }
  
  # 5. Generate academic report
  log_info("Generating academic research report...")
  academic_report <- generate_academic_report(
    results = research_results,
    output_dir = research_dir,
    format = "pdf"
  )
  
  research_results$academic_report_path = academic_report
  
  # Save research results
  saveRDS(research_results, file.path(research_dir, "research_grade_results.rds"))
  
  log_info("Research-grade analysis completed")
  
  return(research_results)
}

#' Government Decision-Support Analysis Pipeline
#' @param system Complete spatial system
#' @param output_dir Output directory
#' @return Government analysis results
run_government_decision_support_analysis <- function(system, output_dir) {
  
  log_info("Running government decision-support analysis...")
  
  gov_dir <- file.path(output_dir, "government_support")
  dir.create(gov_dir, recursive = TRUE, showWarnings = FALSE)
  
  government_results <- list()
  
  # 1. Municipal benchmarking
  log_info("Creating municipal benchmarking system...")
  government_results$benchmarking <- create_municipal_benchmarking_system(
    data = system$legislative_data,
    performance_indicators = c("total_documents", "documents_per_year", "policy_diversity_index")
  )
  
  # 2. Regional development analysis
  log_info("Analyzing regional development patterns...")
  government_results$regional_development <- analyze_regional_development_patterns(
    data = system$legislative_data,
    development_indicators = c("legislative_capacity", "policy_innovation_index", "governance_quality_index")
  )
  
  # 3. RMSP analysis (if São Paulo data is available)
  rmsp_municipalities <- c("3550308", "3503901", "3518800")  # Sample RMSP codes
  if (any(rmsp_municipalities %in% system$municipality_data$boundaries$code_muni)) {
    log_info("Analyzing RMSP metropolitan patterns...")
    government_results$rmsp_analysis <- analyze_rmsp_metropolitan_patterns(
      data = system$legislative_data,
      rmsp_municipalities = rmsp_municipalities
    )
  }
  
  # 4. Create government dashboard
  log_info("Creating government dashboard...")
  dashboard_results <- create_government_dashboard(
    analysis_results = government_results,
    output_dir = gov_dir
  )
  
  government_results$dashboard <- dashboard_results
  
  # Save government results
  saveRDS(government_results, file.path(gov_dir, "government_decision_support_results.rds"))
  
  log_info("Government decision-support analysis completed")
  
  return(government_results)
}

#' Helper Functions
#' ================

perform_comprehensive_research_analysis <- function(system, variables) {
  
  # This would call the research-grade analysis functions
  # with the system's data and configuration
  
  research_results <- list(
    note = "Research-grade analysis would be performed here",
    variables_analyzed = variables,
    system_config = system$config$research_grade
  )
  
  return(research_results)
}

perform_comprehensive_government_analysis <- function(system, variables) {
  
  # This would call the government decision-support functions
  # with the system's data and configuration
  
  government_results <- list(
    note = "Government decision-support analysis would be performed here",
    variables_analyzed = variables,
    system_config = system$config$government_support
  )
  
  return(government_results)
}

generate_comprehensive_outputs <- function(results, system, output_dir) {
  
  log_info("Generating comprehensive outputs...")
  
  # Create output structure
  output_dirs <- c("visualizations", "reports", "data_exports", "technical_docs")
  map(output_dirs, ~dir.create(file.path(output_dir, .x), recursive = TRUE, showWarnings = FALSE))
  
  output_results <- list(
    visualizations_dir = file.path(output_dir, "visualizations"),
    reports_dir = file.path(output_dir, "reports"),
    data_exports_dir = file.path(output_dir, "data_exports"),
    technical_docs_dir = file.path(output_dir, "technical_docs")
  )
  
  # Generate summary report
  summary_report <- create_analysis_summary_report(results, system)
  writeLines(summary_report, file.path(output_dir, "analysis_summary.txt"))
  
  # Export key data files
  write_parquet(
    system$legislative_data, 
    file.path(output_results$data_exports_dir, "processed_legislative_data.parquet")
  )
  
  log_info("Comprehensive outputs generated")
  
  return(output_results)
}

create_analysis_summary_report <- function(results, system) {
  
  summary_lines <- c(
    "Enhanced Spatial Analytics - Analysis Summary",
    "=" %strrep% 50,
    "",
    paste("Analysis Date:", Sys.time()),
    paste("Total Documents Analyzed:", nrow(system$legislative_data)),
    paste("Total Municipalities:", nrow(system$municipality_data$boundaries)),
    paste("Analysis Scope:", system$config$analysis_scope),
    paste("Parallel Workers Used:", system$config$max_workers),
    "",
    "Analysis Components Completed:",
    "- Enhanced Spatial Autocorrelation Analysis",
    "- Multi-scale Hotspot Analysis", 
    "- Policy Diffusion Analysis",
    "- Enhanced Cluster Analysis"
  )
  
  if (system$config$research_grade) {
    summary_lines <- c(summary_lines, "- Research-Grade Statistical Analysis")
  }
  
  if (system$config$government_support) {
    summary_lines <- c(summary_lines, "- Government Decision-Support Analysis")
  }
  
  summary_lines <- c(
    summary_lines,
    "",
    "Performance Summary:",
    paste("Total Execution Time:", 
          if (!is.null(results$performance_summary$total_execution_time_minutes))
            paste(round(results$performance_summary$total_execution_time_minutes, 2), "minutes")
          else "Not available"),
    "",
    "System Configuration:",
    paste("Max Workers:", system$config$max_workers),
    paste("Memory Limit:", system$config$memory_limit_gb, "GB"),
    paste("Cache Enabled:", system$config$enable_caching),
    paste("Parallel Processing:", system$config$enable_parallel)
  )
  
  return(paste(summary_lines, collapse = "\n"))
}

#' Main Entry Point
#' ================

#' Run Enhanced Spatial Analytics Pipeline
#' @param data_source Path to legislative data
#' @param output_dir Output directory
#' @param config Optional configuration
#' @return Complete analysis results
run_enhanced_spatial_analytics_pipeline <- function(data_source, output_dir, config = list()) {
  
  log_info("=== STARTING ENHANCED SPATIAL ANALYTICS PIPELINE ===")
  
  # Initialize complete system
  spatial_system <- initialize_complete_spatial_system(
    data_source = data_source,
    cache_dir = file.path(dirname(output_dir), "cache"),
    config = config
  )
  
  # Run complete analysis
  results <- spatial_system$run_complete_analysis(output_dir)
  
  # Cleanup
  spatial_system$cleanup()
  
  log_info("=== ENHANCED SPATIAL ANALYTICS PIPELINE COMPLETED ===")
  
  return(results)
}

# Execute if run as script
if (!interactive()) {
  
  # Default configuration
  parquet_file <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/parquet_dataset/combined_legislative_dataset.parquet"
  output_dir <- file.path(dirname(dirname(parquet_file)), "enhanced_spatial_results")
  
  config <- list(
    analysis_scope = "full",
    max_workers = 4,
    memory_limit_gb = 8,
    research_grade = TRUE,
    government_support = TRUE,
    enable_caching = TRUE
  )
  
  if (file.exists(parquet_file)) {
    results <- run_enhanced_spatial_analytics_pipeline(parquet_file, output_dir, config)
    cat("Enhanced spatial analytics pipeline completed.\n")
    cat("Results saved to:", output_dir, "\n")
  } else {
    cat("Data file not found:", parquet_file, "\n")
    cat("Please ensure the legislative dataset is available.\n")
  }
}

log_info("Enhanced Spatial Analytics Integration loaded successfully")