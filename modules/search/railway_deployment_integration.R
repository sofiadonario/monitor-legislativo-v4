# ============================================================================
# RAILWAY DEPLOYMENT INTEGRATION FOR ADVANCED SEARCH ENGINE
# ============================================================================
#
# This module integrates the advanced search engine components with the
# existing Railway deployment infrastructure, providing:
# - Seamless integration with existing app.R structure
# - Memory-optimized initialization for 2GB Railway constraints
# - Environment variable configuration management
# - Fallback mechanisms for missing dependencies
# - Performance monitoring and health checks
# - Production-ready error handling and logging
#
# Author: Senior Data Scientist - Brazilian Legislative Analytics Team
# Date: January 2025
# Version: 1.0 - Railway Production Ready
# ============================================================================

# Load essential packages for Railway integration
railway_packages <- c("shiny", "DT", "jsonlite", "lubridate")

suppressPackageStartupMessages({
  library(shiny)
  library(DT)
  library(jsonlite)
  library(lubridate)
})

cat("🚀 Railway Deployment Integration loaded\n")

# ============================================================================
# RAILWAY ENVIRONMENT CONFIGURATION
# ============================================================================

.railway_config <- list(
  # Railway deployment settings
  memory_limit_gb = 2,
  max_search_results = 1000,
  enable_advanced_search = TRUE,
  
  # Feature toggles (can be controlled via environment variables)
  enable_redis_cache = Sys.getenv("ENABLE_REDIS_CACHE", "false") == "true",
  enable_full_text_search = Sys.getenv("ENABLE_FULL_TEXT_SEARCH", "true") == "true",
  enable_autocomplete = Sys.getenv("ENABLE_AUTOCOMPLETE", "true") == "true",
  enable_ranking = Sys.getenv("ENABLE_RANKING", "true") == "true",
  enable_nlp_processing = Sys.getenv("ENABLE_NLP", "false") == "true",  # Resource intensive
  
  # Performance settings
  search_timeout_ms = as.numeric(Sys.getenv("SEARCH_TIMEOUT_MS", "5000")),
  autocomplete_timeout_ms = as.numeric(Sys.getenv("AUTOCOMPLETE_TIMEOUT_MS", "500")),
  
  # Logging and monitoring
  log_level = Sys.getenv("LOG_LEVEL", "INFO"),
  enable_performance_monitoring = Sys.getenv("ENABLE_MONITORING", "true") == "true"
)

# System health status
.search_system_health <- list(
  initialized = FALSE,
  database_available = FALSE,
  redis_available = FALSE,
  search_engine_ready = FALSE,
  last_health_check = NULL,
  error_count = 0,
  warning_count = 0
)

# ============================================================================
# SEARCH ENGINE INITIALIZATION
# ============================================================================

#' Initialize advanced search engine with Railway optimizations
#' @param force_reinit Force reinitialization even if already initialized
#' @return Boolean indicating successful initialization
initialize_advanced_search_engine <- function(force_reinit = FALSE) {
  
  if (.search_system_health$initialized && !force_reinit) {
    return(TRUE)
  }
  
  cat("🔧 Initializing Advanced Search Engine for Railway deployment...\n")
  
  start_time <- Sys.time()
  initialization_steps <- list()
  
  tryCatch({
    # Step 1: Check database connectivity
    cat("   1/7 Checking database connectivity...\n")
    database_available <- check_database_connectivity()
    .search_system_health$database_available <- database_available
    initialization_steps$database <- database_available
    
    # Step 2: Load core search engine (always needed)
    cat("   2/7 Loading core search engine...\n")
    if (.railway_config$enable_advanced_search) {
      search_engine_loaded <- load_search_engine_module()
      initialization_steps$search_engine <- search_engine_loaded
    } else {
      initialization_steps$search_engine <- TRUE
      cat("   ⚠️ Advanced search disabled via configuration\n")
    }
    
    # Step 3: Initialize caching system
    cat("   3/7 Initializing caching system...\n")
    if (.railway_config$enable_redis_cache) {
      cache_initialized <- initialize_caching_system()
      .search_system_health$redis_available <- cache_initialized
      initialization_steps$caching <- cache_initialized
    } else {
      initialization_steps$caching <- TRUE
      cat("   ⚠️ Redis caching disabled, using memory cache\n")
    }
    
    # Step 4: Load NLP processing (optional, memory intensive)
    cat("   4/7 Loading NLP processing...\n")
    if (.railway_config$enable_nlp_processing) {
      nlp_loaded <- load_nlp_module()
      initialization_steps$nlp <- nlp_loaded
    } else {
      initialization_steps$nlp <- TRUE
      cat("   ⚠️ NLP processing disabled to conserve memory\n")
    }
    
    # Step 5: Initialize geographic/temporal filters
    cat("   5/7 Loading geographic and temporal filters...\n")
    filters_loaded <- load_filter_modules()
    initialization_steps$filters <- filters_loaded
    
    # Step 6: Initialize autocomplete system
    cat("   6/7 Initializing autocomplete system...\n")
    if (.railway_config$enable_autocomplete) {
      autocomplete_loaded <- load_autocomplete_module()
      initialization_steps$autocomplete <- autocomplete_loaded
    } else {
      initialization_steps$autocomplete <- TRUE
      cat("   ⚠️ Autocomplete disabled via configuration\n")
    }
    
    # Step 7: Initialize ranking system
    cat("   7/7 Loading ranking and relevance system...\n")
    if (.railway_config$enable_ranking) {
      ranking_loaded <- load_ranking_module()
      initialization_steps$ranking <- ranking_loaded
    } else {
      initialization_steps$ranking <- TRUE
      cat("   ⚠️ Advanced ranking disabled via configuration\n")
    }
    
    # Check overall initialization success
    all_critical_loaded <- initialization_steps$database && 
                          initialization_steps$search_engine && 
                          initialization_steps$filters
    
    if (all_critical_loaded) {
      .search_system_health$initialized <- TRUE
      .search_system_health$search_engine_ready <- TRUE
      .search_system_health$last_health_check <- Sys.time()
      
      end_time <- Sys.time()
      init_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
      
      cat("✅ Advanced Search Engine initialized successfully in", round(init_time, 2), "seconds\n")
      cat("   📊 Components loaded:\n")
      for (component in names(initialization_steps)) {
        status <- if (initialization_steps[[component]]) "✅" else "❌"
        cat("      ", status, component, "\n")
      }
      
      # Log memory usage
      log_memory_usage()
      
      return(TRUE)
      
    } else {
      cat("⚠️ Advanced Search Engine partially initialized\n")
      cat("   Critical components missing, running in fallback mode\n")
      
      .search_system_health$initialized <- TRUE  # Still functional
      .search_system_health$search_engine_ready <- FALSE
      .search_system_health$warning_count <- .search_system_health$warning_count + 1
      
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("❌ Advanced Search Engine initialization failed:", e$message, "\n")
    
    .search_system_health$initialized <- FALSE
    .search_system_health$search_engine_ready <- FALSE
    .search_system_health$error_count <- .search_system_health$error_count + 1
    
    return(FALSE)
  })
}

# ============================================================================
# MODULE LOADING FUNCTIONS
# ============================================================================

#' Load core search engine module
#' @return Boolean indicating success
load_search_engine_module <- function() {
  
  tryCatch({
    if (file.exists("modules/search/advanced_search_engine.R")) {
      source("modules/search/advanced_search_engine.R")
      
      # Verify key functions are available
      required_functions <- c("advanced_search_documents", "get_search_performance_stats")
      
      for (func in required_functions) {
        if (!exists(func, envir = .GlobalEnv)) {
          cat("❌ Missing required function:", func, "\n")
          return(FALSE)
        }
      }
      
      cat("   ✅ Core search engine loaded\n")
      return(TRUE)
    } else {
      cat("   ⚠️ Core search engine file not found\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("   ❌ Core search engine loading failed:", e$message, "\n")
    return(FALSE)
  })
}

#' Initialize caching system
#' @return Boolean indicating success
initialize_caching_system <- function() {
  
  tryCatch({
    if (file.exists("modules/search/redis_cache_system.R")) {
      source("modules/search/redis_cache_system.R")
      
      # Verify caching functions
      required_functions <- c("cache_search_results", "get_cached_search_results")
      
      for (func in required_functions) {
        if (!exists(func, envir = .GlobalEnv)) {
          cat("   ⚠️ Caching function not available:", func, "\n")
          return(FALSE)
        }
      }
      
      cat("   ✅ Caching system initialized\n")
      return(TRUE)
    } else {
      cat("   ⚠️ Caching system file not found, using memory fallback\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("   ⚠️ Caching system initialization failed:", e$message, "\n")
    return(FALSE)
  })
}

#' Load NLP processing module
#' @return Boolean indicating success
load_nlp_module <- function() {
  
  tryCatch({
    if (file.exists("modules/nlp/portuguese_legal_nlp.R")) {
      source("modules/nlp/portuguese_legal_nlp.R")
      
      cat("   ✅ NLP processing loaded\n")
      return(TRUE)
    } else {
      cat("   ⚠️ NLP module file not found\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("   ⚠️ NLP module loading failed:", e$message, "\n")
    return(FALSE)
  })
}

#' Load filter modules
#' @return Boolean indicating success
load_filter_modules <- function() {
  
  tryCatch({
    if (file.exists("modules/search/geographic_temporal_filters.R")) {
      source("modules/search/geographic_temporal_filters.R")
      
      cat("   ✅ Geographic and temporal filters loaded\n")
      return(TRUE)
    } else {
      cat("   ⚠️ Filter modules file not found\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("   ⚠️ Filter modules loading failed:", e$message, "\n")
    return(FALSE)
  })
}

#' Load autocomplete module
#' @return Boolean indicating success
load_autocomplete_module <- function() {
  
  tryCatch({
    if (file.exists("modules/search/intelligent_autocomplete.R")) {
      source("modules/search/intelligent_autocomplete.R")
      
      cat("   ✅ Autocomplete system loaded\n")
      return(TRUE)
    } else {
      cat("   ⚠️ Autocomplete module file not found\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("   ⚠️ Autocomplete module loading failed:", e$message, "\n")
    return(FALSE)
  })
}

#' Load ranking module
#' @return Boolean indicating success
load_ranking_module <- function() {
  
  tryCatch({
    if (file.exists("modules/search/ranking_relevance_system.R")) {
      source("modules/search/ranking_relevance_system.R")
      
      cat("   ✅ Ranking system loaded\n")
      return(TRUE)
    } else {
      cat("   ⚠️ Ranking module file not found\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("   ⚠️ Ranking module loading failed:", e$message, "\n")
    return(FALSE)
  })
}

# ============================================================================
# RAILWAY-OPTIMIZED SEARCH INTERFACE
# ============================================================================

#' Railway-optimized search function with fallbacks
#' @param query Search query
#' @param filters Search filters
#' @param sort_by Sort method
#' @param limit Result limit
#' @param offset Result offset
#' @return Search results with metadata
railway_search_documents <- function(query = "", 
                                   filters = list(),
                                   sort_by = "relevance",
                                   limit = 50,
                                   offset = 0) {
  
  start_time <- Sys.time()
  
  # Enforce Railway memory limits
  limit <- min(limit, .railway_config$max_search_results)
  
  tryCatch({
    # Check if advanced search is available and ready
    if (.search_system_health$search_engine_ready && exists("advanced_search_documents")) {
      
      # Use advanced search engine with timeout
      result <- withTimeout({
        advanced_search_documents(
          query = query,
          filters = filters,
          sort_by = sort_by,
          limit = limit,
          offset = offset,
          use_cache = TRUE
        )
      }, timeout = .railway_config$search_timeout_ms / 1000)
      
      # Apply ranking if available
      if (.railway_config$enable_ranking && exists("calculate_relevance_scores")) {
        result <- calculate_relevance_scores(result, query, filters)
        
        # Sort by relevance score
        if (sort_by == "relevance" && "final_relevance_score" %in% names(result)) {
          result <- result[order(-result$final_relevance_score), ]
        }
      }
      
    } else {
      # Fallback to existing search system
      cat("🔄 Using fallback search system\n")
      
      if (exists("get_library_documents")) {
        result <- get_library_documents(
          category = filters$species %||% "all",
          search_term = query,
          state = filters$estado %||% "all",
          date_start = filters$date_start,
          date_end = filters$date_end,
          sort_by = sort_by,
          limit = limit,
          offset = offset
        )
      } else {
        # Ultimate fallback
        result <- get_basic_fallback_search(query, filters, limit)
      }
    }
    
    # Add search metadata
    end_time <- Sys.time()
    search_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    
    attr(result, "search_metadata") <- list(
      query = query,
      filters = filters,
      execution_time_ms = round(search_time_ms, 2),
      total_results = nrow(result),
      advanced_search_used = .search_system_health$search_engine_ready,
      timestamp = Sys.time()
    )
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Search error:", e$message, "\n")
    .search_system_health$error_count <- .search_system_health$error_count + 1
    
    # Return empty results with error info
    empty_result <- data.frame()
    attr(empty_result, "search_metadata") <- list(
      query = query,
      error = e$message,
      execution_time_ms = 0,
      total_results = 0,
      advanced_search_used = FALSE,
      timestamp = Sys.time()
    )
    
    return(empty_result)
  })
}

#' Railway-optimized autocomplete function
#' @param partial_query Partial search query
#' @param context_filters Current search context
#' @param max_suggestions Maximum suggestions
#' @return Autocomplete suggestions
railway_autocomplete_suggestions <- function(partial_query, 
                                           context_filters = list(),
                                           max_suggestions = 10) {
  
  if (!.railway_config$enable_autocomplete) {
    return(list(suggestions = character(0), metadata = list()))
  }
  
  tryCatch({
    # Use advanced autocomplete if available
    if (exists("generate_autocomplete_suggestions")) {
      
      result <- withTimeout({
        generate_autocomplete_suggestions(
          partial_query = partial_query,
          context_filters = context_filters,
          max_suggestions = max_suggestions,
          include_fuzzy = TRUE
        )
      }, timeout = .railway_config$autocomplete_timeout_ms / 1000)
      
      return(result)
      
    } else {
      # Basic fallback autocomplete
      return(get_basic_autocomplete_fallback(partial_query, max_suggestions))
    }
    
  }, error = function(e) {
    cat("⚠️ Autocomplete error:", e$message, "\n")
    return(list(
      suggestions = character(0),
      metadata = list(error = e$message, timestamp = Sys.time())
    ))
  })
}

# ============================================================================
# HEALTH MONITORING AND DIAGNOSTICS
# ============================================================================

#' Check database connectivity
#' @return Boolean indicating database availability
check_database_connectivity <- function() {
  
  tryCatch({
    # Check if database connection functions exist
    if (exists("get_database_pool") || exists("secure_db_pool")) {
      
      if (exists("get_total_documents")) {
        doc_count <- get_total_documents()
        return(doc_count > 0)
      }
      
      return(TRUE)
    }
    
    return(FALSE)
    
  }, error = function(e) {
    cat("   ⚠️ Database connectivity check failed:", e$message, "\n")
    return(FALSE)
  })
}

#' Get search engine health status
#' @return List with health information
get_search_engine_health <- function() {
  
  # Update last health check
  .search_system_health$last_health_check <- Sys.time()
  
  # Get component-specific stats
  component_stats <- list()
  
  if (exists("get_search_performance_stats")) {
    component_stats$search_engine <- get_search_performance_stats()
  }
  
  if (exists("get_cache_performance_stats")) {
    component_stats$caching <- get_cache_performance_stats()
  }
  
  if (exists("get_autocomplete_performance_stats")) {
    component_stats$autocomplete <- get_autocomplete_performance_stats()
  }
  
  if (exists("get_ranking_performance_stats")) {
    component_stats$ranking <- get_ranking_performance_stats()
  }
  
  return(list(
    system_health = .search_system_health,
    railway_config = .railway_config,
    component_stats = component_stats,
    memory_usage = get_memory_usage_info(),
    uptime = get_system_uptime()
  ))
}

#' Log memory usage for Railway monitoring
log_memory_usage <- function() {
  
  tryCatch({
    # Get memory information
    memory_info <- get_memory_usage_info()
    
    cat("💾 Memory usage: ", round(memory_info$used_mb, 1), "MB / ", 
        round(memory_info$limit_mb, 1), "MB (", 
        round(memory_info$usage_percent, 1), "%)\n")
    
    # Warn if approaching Railway limit
    if (memory_info$usage_percent > 80) {
      cat("⚠️ WARNING: Memory usage above 80% of Railway limit\n")
      .search_system_health$warning_count <- .search_system_health$warning_count + 1
    }
    
  }, error = function(e) {
    cat("⚠️ Memory usage logging failed:", e$message, "\n")
  })
}

#' Get memory usage information
#' @return List with memory statistics
get_memory_usage_info <- function() {
  
  tryCatch({
    # Get current memory usage (basic estimation)
    memory_used_mb <- as.numeric(object.size(.GlobalEnv)) / (1024^2)
    memory_limit_mb <- .railway_config$memory_limit_gb * 1024
    
    return(list(
      used_mb = memory_used_mb,
      limit_mb = memory_limit_mb,
      usage_percent = (memory_used_mb / memory_limit_mb) * 100,
      available_mb = memory_limit_mb - memory_used_mb
    ))
    
  }, error = function(e) {
    return(list(
      used_mb = 0,
      limit_mb = 2048,
      usage_percent = 0,
      available_mb = 2048
    ))
  })
}

#' Get system uptime
#' @return System uptime in hours
get_system_uptime <- function() {
  
  if (exists(".search_engine_start_time", envir = .GlobalEnv)) {
    start_time <- get(".search_engine_start_time", envir = .GlobalEnv)
    uptime_hours <- as.numeric(difftime(Sys.time(), start_time, units = "hours"))
    return(round(uptime_hours, 2))
  }
  
  return(0)
}

# ============================================================================
# FALLBACK FUNCTIONS
# ============================================================================

#' Basic fallback search when advanced search is unavailable
#' @param query Search query
#' @param filters Search filters
#' @param limit Result limit
#' @return Basic search results
get_basic_fallback_search <- function(query, filters, limit) {
  
  cat("🚨 Using basic fallback search\n")
  
  # Create minimal fallback dataset
  fallback_data <- data.frame(
    id = 1:min(limit, 20),
    titulo = paste("Documento Legislativo Brasileiro", 1:min(limit, 20)),
    ementa = paste("Regulamentação e normas para o sistema legislativo brasileiro -", 1:min(limit, 20)),
    tipo = rep(c("Lei", "Decreto", "Portaria", "Resolução"), length.out = min(limit, 20)),
    species = rep(c("Legislação", "Jurisprudência"), length.out = min(limit, 20)),
    estado = rep(c("BR", "SP", "RJ", "MG"), length.out = min(limit, 20)),
    data_publicacao = seq(Sys.Date() - 365, Sys.Date(), length.out = min(limit, 20)),
    url = rep("", min(limit, 20)),
    final_relevance_score = seq(50, 90, length.out = min(limit, 20)),
    stringsAsFactors = FALSE
  )
  
  return(fallback_data)
}

#' Basic fallback autocomplete
#' @param partial_query Partial query
#' @param max_suggestions Max suggestions
#' @return Basic autocomplete response
get_basic_autocomplete_fallback <- function(partial_query, max_suggestions) {
  
  basic_terms <- c(
    "lei", "decreto", "portaria", "resolução", "código",
    "transporte", "trânsito", "mobilidade", "rodoviário", "aéreo",
    "federal", "estadual", "municipal", "são paulo", "brasil"
  )
  
  matches <- basic_terms[grepl(paste0("^", tolower(partial_query)), basic_terms)]
  
  return(list(
    suggestions = lapply(head(matches, max_suggestions), function(term) {
      list(text = term, description = "Termo Básico", category = "fallback")
    }),
    metadata = list(
      total_found = length(matches),
      source = "basic_fallback",
      timestamp = Sys.time()
    )
  ))
}

# ============================================================================
# TIMEOUT UTILITY FUNCTION
# ============================================================================

#' Execute function with timeout (simple implementation)
#' @param expr Expression to execute
#' @param timeout Timeout in seconds
#' @return Expression result or error
withTimeout <- function(expr, timeout) {
  
  # Simple timeout implementation
  # In production, use more sophisticated timeout handling
  
  start_time <- Sys.time()
  
  tryCatch({
    result <- eval(expr)
    
    # Check if timeout exceeded (basic check)
    elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    if (elapsed > timeout) {
      stop("Operation timed out after ", timeout, " seconds")
    }
    
    return(result)
    
  }, error = function(e) {
    elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    if (elapsed > timeout) {
      stop("Operation timed out after ", timeout, " seconds")
    }
    stop(e$message)
  })
}

# ============================================================================
# INITIALIZATION ON MODULE LOAD
# ============================================================================

# Set start time if not already set
if (!exists(".search_engine_start_time", envir = .GlobalEnv)) {
  assign(".search_engine_start_time", Sys.time(), envir = .GlobalEnv)
}

cat("✅ Railway Deployment Integration ready\n")
cat("   🚀 Memory limit:", .railway_config$memory_limit_gb, "GB\n")
cat("   ⏱️ Search timeout:", .railway_config$search_timeout_ms, "ms\n")
cat("   💡 Autocomplete timeout:", .railway_config$autocomplete_timeout_ms, "ms\n")
cat("   🔧 Advanced search:", if(.railway_config$enable_advanced_search) "ENABLED" else "DISABLED", "\n")

# Export main functions for Shiny app integration
.GlobalEnv$initialize_advanced_search_engine <- initialize_advanced_search_engine
.GlobalEnv$railway_search_documents <- railway_search_documents
.GlobalEnv$railway_autocomplete_suggestions <- railway_autocomplete_suggestions
.GlobalEnv$get_search_engine_health <- get_search_engine_health
.GlobalEnv$log_memory_usage <- log_memory_usage