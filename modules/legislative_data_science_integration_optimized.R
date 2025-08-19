# OPTIMIZED LEGISLATIVE DATA SCIENCE INTEGRATION MODULE
# =====================================================
# Memory-optimized version for Railway deployment (<1500MB)
# Loads modules on-demand and uses lazy loading strategies

cat("Loading Optimized Legislative Data Science Integration Module...\n")

# Lazy Module Loading Strategy
# ============================

# Track which modules are available but not yet loaded
available_modules <- list(
  nlp = "modules/nlp/brazilian_legal_nlp.R",
  citations = "modules/citations/citation_network_analysis.R", 
  transport = "modules/transport/transport_policy_intelligence.R",
  constitutional = "modules/constitutional/constitutional_evolution_tracker.R",
  productivity = "modules/productivity/legislative_productivity_analytics.R",
  ml = "modules/ml/machine_learning_models.R"
)

# Track which modules are currently loaded
loaded_modules <- list()

# Module status for UI display
module_status <- list(
  nlp = FALSE,
  citations = FALSE,
  transport = FALSE,
  constitutional = FALSE,
  productivity = FALSE,
  ml = FALSE
)

#' Lazy Load Module
#' @param module_name Name of module to load
#' @return TRUE if successful, FALSE otherwise
lazy_load_module <- function(module_name) {
  if (module_name %in% names(loaded_modules) && loaded_modules[[module_name]]) {
    return(TRUE)  # Already loaded
  }
  
  if (!module_name %in% names(available_modules)) {
    warning("Unknown module: ", module_name)
    return(FALSE)
  }
  
  tryCatch({
    # Force garbage collection before loading
    gc()
    
    source(available_modules[[module_name]])
    loaded_modules[[module_name]] <<- TRUE
    module_status[[module_name]] <<- TRUE
    
    cat("✅ Lazy loaded:", toupper(module_name), "module\n")
    return(TRUE)
  }, error = function(e) {
    cat("❌ Failed to load", toupper(module_name), ":", e$message, "\n")
    loaded_modules[[module_name]] <<- FALSE
    module_status[[module_name]] <<- FALSE
    return(FALSE)
  })
}

#' Unload Module to Free Memory
#' @param module_name Name of module to unload
unload_module <- function(module_name) {
  if (module_name %in% names(loaded_modules) && loaded_modules[[module_name]]) {
    # Remove module-specific objects from global environment
    module_patterns <- list(
      nlp = "BRAZILIAN_.*|NLP_.*",
      citations = "CITATION_.*|BRAZILIAN_CITATION_.*",
      transport = "TRANSPORT_.*|REGULATORY_.*",
      constitutional = "CONSTITUTIONAL_.*",
      productivity = "PRODUCTIVITY_.*|LEGISLATIVE_.*",
      ml = "ML_.*|DOCUMENT_.*"
    )
    
    if (module_name %in% names(module_patterns)) {
      pattern <- module_patterns[[module_name]]
      objects_to_remove <- ls(envir = .GlobalEnv, pattern = pattern)
      rm(list = objects_to_remove, envir = .GlobalEnv)
    }
    
    loaded_modules[[module_name]] <<- FALSE
    module_status[[module_name]] <<- FALSE
    
    # Force garbage collection
    gc()
    
    cat("🗑️ Unloaded:", toupper(module_name), "module\n")
  }
}

#' Memory-Optimized Legislative Analysis
#' @param connection Database connection (optional)
#' @param analysis_modules Vector of modules to run
#' @param sample_size Maximum documents to process
#' @return Analysis results with memory management
run_optimized_legislative_analysis <- function(connection = NULL,
                                              analysis_modules = c("nlp"),
                                              sample_size = 500) {
  
  cat("🚀 Starting Memory-Optimized Legislative Analysis\n")
  cat("📊 Sample size:", sample_size, "\n")
  cat("🔧 Modules requested:", paste(analysis_modules, collapse = ", "), "\n")
  
  # Initialize results
  results <- list(
    metadata = list(
      start_time = Sys.time(),
      sample_size = sample_size,
      modules_requested = analysis_modules,
      memory_optimized = TRUE
    ),
    analyses = list()
  )
  
  # Monitor memory throughout process
  initial_memory <- gc()
  
  # Process one module at a time to minimize memory usage
  for (module_name in analysis_modules) {
    
    cat("\n📊 Processing", toupper(module_name), "module...\n")
    
    # Load module on demand
    if (!lazy_load_module(module_name)) {
      results$analyses[[module_name]] <- list(
        status = "error",
        message = "Failed to load module"
      )
      next
    }
    
    # Run module-specific analysis
    module_result <- tryCatch({
      switch(module_name,
        "nlp" = if (exists("railway_efficient_nlp_analysis")) {
          railway_efficient_nlp_analysis(connection, batch_size = min(sample_size, 100))
        } else {
          list(status = "function_not_found")
        },
        "citations" = if (exists("railway_citation_analysis")) {
          railway_citation_analysis(connection, batch_size = min(sample_size, 100))
        } else {
          list(status = "function_not_found")
        },
        "transport" = if (exists("railway_transport_policy_analysis")) {
          railway_transport_policy_analysis(connection, batch_size = min(sample_size, 100))
        } else {
          list(status = "function_not_found")
        },
        "constitutional" = if (exists("railway_constitutional_analysis")) {
          railway_constitutional_analysis(connection, batch_size = min(sample_size, 100))
        } else {
          list(status = "function_not_found")
        },
        "productivity" = if (exists("railway_productivity_analysis")) {
          railway_productivity_analysis(connection, batch_size = min(sample_size, 100))
        } else {
          list(status = "function_not_found")
        },
        "ml" = if (exists("railway_ml_analysis")) {
          railway_ml_analysis(connection, batch_size = min(sample_size, 100))
        } else {
          list(status = "function_not_found")
        },
        list(status = "unknown_module")
      )
    }, error = function(e) {
      list(status = "error", message = e$message)
    })
    
    results$analyses[[module_name]] <- module_result
    
    # Unload module after processing to free memory (except the last one)
    if (module_name != analysis_modules[length(analysis_modules)]) {
      unload_module(module_name)
    }
    
    # Force garbage collection between modules
    gc()
  }
  
  # Generate lightweight insights
  results$insights <- generate_lightweight_insights(results$analyses)
  
  # Complete metadata
  results$metadata$end_time <- Sys.time()
  results$metadata$duration <- difftime(
    results$metadata$end_time,
    results$metadata$start_time,
    units = "secs"
  )
  results$metadata$modules_completed <- length(results$analyses)
  
  final_memory <- gc()
  results$metadata$memory_usage <- list(
    initial = initial_memory,
    final = final_memory,
    optimized = TRUE
  )
  
  cat("\n✅ Memory-Optimized Analysis completed!\n")
  cat("⏱️ Duration:", round(as.numeric(results$metadata$duration), 2), "seconds\n")
  
  return(results)
}

#' Generate Lightweight Insights
#' @param analyses Analysis results from modules
#' @return Simplified insights structure
generate_lightweight_insights <- function(analyses) {
  insights <- list(
    summary = list(),
    key_metrics = list()
  )
  
  # Count successful analyses
  successful_modules <- sum(sapply(analyses, function(x) {
    x$status %in% c("complete", "fallback_complete")
  }))
  
  insights$summary <- list(
    modules_run = length(analyses),
    successful_modules = successful_modules,
    success_rate = if (length(analyses) > 0) successful_modules / length(analyses) else 0
  )
  
  # Extract key metrics
  for (module_name in names(analyses)) {
    analysis <- analyses[[module_name]]
    
    if (analysis$status %in% c("complete", "fallback_complete")) {
      insights$key_metrics[[module_name]] <- switch(module_name,
        "nlp" = list(
          entities = analysis$summary$entities_found %||% 0,
          sentiment = analysis$summary$avg_sentiment %||% 0
        ),
        "citations" = list(
          citations = analysis$total_citations_found %||% 0,
          density = analysis$network_density %||% 0
        ),
        "transport" = list(
          decarb_docs = analysis$summary$decarbonization_docs %||% 0,
          modal_docs = analysis$summary$modal_integration_docs %||% 0
        ),
        "constitutional" = list(
          const_docs = analysis$summary$constitutional_documents %||% 0,
          federal_docs = analysis$summary$federal_system_documents %||% 0
        ),
        "productivity" = list(
          efficient_docs = analysis$summary$high_efficiency_documents %||% 0,
          mature_docs = analysis$summary$mature_policy_documents %||% 0
        ),
        "ml" = list(
          classified_docs = analysis$summary$documents_classified %||% 0,
          features = analysis$summary$features_extracted %||% 0
        ),
        list(status = "processed")
      )
    }
  }
  
  return(insights)
}

#' Get Lightweight Dashboard Data
#' @param connection Database connection (optional)
#' @param modules Vector of modules to include
#' @return Dashboard-ready data with minimal memory footprint
get_lightweight_dashboard_data <- function(connection = NULL, modules = c("nlp", "transport")) {
  tryCatch({
    cat("📊 Preparing lightweight dashboard data...\n")
    
    # Limit to 2 modules and small sample size for memory efficiency
    modules <- head(modules, 2)
    
    dashboard_results <- run_optimized_legislative_analysis(
      connection = connection,
      analysis_modules = modules,
      sample_size = 200  # Very small sample for dashboard
    )
    
    # Prepare minimal dashboard data
    dashboard_data <- list(
      summary = list(
        modules_completed = dashboard_results$metadata$modules_completed,
        duration_seconds = round(as.numeric(dashboard_results$metadata$duration), 2),
        memory_optimized = TRUE
      ),
      metrics = dashboard_results$insights$key_metrics,
      status = "ready",
      last_updated = Sys.time()
    )
    
    cat("✅ Lightweight dashboard data ready!\n")
    return(dashboard_data)
    
  }, error = function(e) {
    warning("Dashboard data preparation failed: ", e$message)
    return(list(
      status = "error",
      message = e$message,
      last_updated = Sys.time()
    ))
  })
}

#' Get Module Status for UI
#' @return Current module loading status
get_module_status <- function() {
  return(module_status)
}

#' Check Memory Usage
#' @return Current memory information
check_memory_usage <- function() {
  gc_info <- gc()
  memory_mb <- round(sum(gc_info[, "used"]) * 8 / 1024, 2)
  
  list(
    current_memory_mb = memory_mb,
    railway_limit_mb = 1500,
    within_limits = memory_mb < 1200,  # Safety margin
    usage_percentage = round((memory_mb / 1500) * 100, 1)
  )
}

# Utility function
`%||%` <- function(a, b) if (is.null(a)) b else a

cat("✅ Optimized Legislative Data Science Integration loaded\n")
cat("   🔧 Lazy module loading: ENABLED\n")
cat("   💾 Memory optimization: ENABLED\n")
cat("   🗑️ Dynamic module unloading: ENABLED\n")
cat("   📊 Lightweight analysis: ENABLED\n")
cat("   ⚡ Railway deployment ready: ENABLED\n")

# Export optimized functions
OPTIMIZED_FUNCTIONS <- list(
  run_optimized_legislative_analysis = run_optimized_legislative_analysis,
  get_lightweight_dashboard_data = get_lightweight_dashboard_data,
  get_module_status = get_module_status,
  check_memory_usage = check_memory_usage,
  lazy_load_module = lazy_load_module,
  unload_module = unload_module
)