# Geographic Integration Module - Sprint 5B
# Brazilian Legislative Monitoring System - Main App Integration
# ================================================================
# 
# Central integration module that connects the IBGE geographic system
# with the main Shiny application, providing seamless geographic
# capabilities for the Brazilian Legislative Dashboard
# 
# FEATURES:
# - Seamless integration with existing app architecture
# - Lazy loading of geographic data with progress feedback
# - Memory-optimized initialization for Railway deployment
# - Robust error handling and graceful degradation
# - Academic-grade data validation and quality assurance
# - Real-time geographic analytics integration
# 
# INTEGRATION POINTS:
# - Database connection pool integration
# - UI component initialization
# - Server-side reactive functions
# - Data loading optimization
# - Cache management integration
# ================================================================

library(shiny)
library(shinydashboard)
library(leaflet)
library(sf)
library(dplyr)
library(DBI)
library(pool)

# Load all geographic modules
source_files <- c(
  "modules/geographic/ibge_integration.R",
  "modules/geographic/geographic_data_loader.R", 
  "modules/geographic/geographic_aggregation.R"
)

for (file in source_files) {
  if (file.exists(file)) {
    tryCatch({
      source(file)
      cat("✅ Loaded:", basename(file), "\n")
    }, error = function(e) {
      cat("⚠️ Failed to load", basename(file), ":", e$message, "\n")
    })
  }
}

# Geographic System Configuration
# ==============================

GEOGRAPHIC_INTEGRATION_CONFIG <- list(
  
  # Initialization settings
  initialization = list(
    lazy_loading = TRUE,
    auto_initialize = FALSE,  # Manual initialization for Railway memory control
    initialization_timeout = 60,  # seconds
    show_progress = TRUE
  ),
  
  # Memory management
  memory = list(
    max_memory_mb = 1400,  # Railway constraint
    gc_frequency = 5,  # Trigger GC every 5 operations
    cache_limit_mb = 300,
    monitoring_enabled = TRUE
  ),
  
  # Performance settings
  performance = list(
    parallel_processing = FALSE,  # Disabled for Railway
    chunk_processing = TRUE,
    batch_size = 50,
    cache_enabled = TRUE,
    preload_priority_states = c("SP", "MG", "RJ", "DF")
  ),
  
  # UI integration
  ui = list(
    show_loading_modal = TRUE,
    progress_updates = TRUE,
    error_notifications = TRUE,
    fallback_mode = TRUE
  )
)

# Main Geographic System Class
# ============================

#' GeographicIntegrationSystem
#' 
#' Main coordinator class for geographic system integration
GeographicIntegrationSystem <- if (requireNamespace("R6", quietly = TRUE)) {
  
  R6::R6Class("GeographicIntegrationSystem",
    
    public = list(
      
      # Core components
      db_pool = NULL,
      ibge_system = NULL,
      data_loader = NULL,
      aggregator = NULL,
      
      # Status tracking
      initialized = FALSE,
      initialization_error = NULL,
      components_status = list(),
      
      # Constructor
      initialize = function(db_pool = NULL) {
        
        cat("🌐 Initializing Geographic Integration System...\n")
        
        self$db_pool <- db_pool
        self$initialized <- FALSE
        self$components_status <- list(
          ibge_system = "not_initialized",
          data_loader = "not_initialized", 
          aggregator = "not_initialized",
          database = ifelse(is.null(db_pool), "disconnected", "connected")
        )
        
        cat("🏗️ Geographic Integration System ready for initialization\n")
      },
      
      # Main initialization method
      initialize_system = function(progress_callback = NULL) {
        
        tryCatch({
          
          if (self$initialized) {
            cat("✅ Geographic system already initialized\n")
            return(list(success = TRUE, status = "already_initialized"))
          }
          
          cat("🚀 Starting geographic system initialization...\n")
          
          # Step 1: Initialize IBGE system
          if (!is.null(progress_callback)) {
            progress_callback(0.1, "Initializing IBGE integration...")
          }
          
          tryCatch({
            self$ibge_system <- initialize_ibge_system(
              db_pool = self$db_pool,
              force_refresh = FALSE
            )
            
            if (!is.null(self$ibge_system) && self$ibge_system$status %in% c("operational", "partial")) {
              self$components_status$ibge_system <- "initialized"
              cat("✅ IBGE system initialized\n")
            } else {
              self$components_status$ibge_system <- "failed"
              cat("❌ IBGE system initialization failed\n")
            }
          }, error = function(e) {
            self$components_status$ibge_system <- paste("error:", e$message)
            cat("❌ IBGE system error:", e$message, "\n")
          })
          
          # Step 2: Initialize data loader
          if (!is.null(progress_callback)) {
            progress_callback(0.3, "Setting up geographic data loader...")
          }
          
          tryCatch({
            self$data_loader <- create_geographic_loader(self$db_pool)
            
            if (!is.null(self$data_loader)) {
              self$components_status$data_loader <- "initialized"
              cat("✅ Data loader initialized\n")
            } else {
              self$components_status$data_loader <- "failed"
              cat("❌ Data loader initialization failed\n")
            }
          }, error = function(e) {
            self$components_status$data_loader <- paste("error:", e$message)
            cat("❌ Data loader error:", e$message, "\n")
          })
          
          # Step 3: Initialize aggregator
          if (!is.null(progress_callback)) {
            progress_callback(0.5, "Setting up geographic aggregation system...")
          }
          
          tryCatch({
            self$aggregator <- create_geographic_aggregator(
              db_pool = self$db_pool,
              geographic_loader = self$data_loader
            )
            
            if (!is.null(self$aggregator)) {
              self$components_status$aggregator <- "initialized"
              cat("✅ Aggregator initialized\n")
            } else {
              self$components_status$aggregator <- "failed"
              cat("❌ Aggregator initialization failed\n")
            }
          }, error = function(e) {
            self$components_status$aggregator <- paste("error:", e$message)
            cat("❌ Aggregator error:", e$message, "\n")
          })
          
          # Step 4: Load priority geographic data
          if (!is.null(progress_callback)) {
            progress_callback(0.7, "Loading priority geographic data...")
          }
          
          self$load_priority_data(progress_callback)
          
          # Step 5: Validate system
          if (!is.null(progress_callback)) {
            progress_callback(0.9, "Validating geographic system...")
          }
          
          validation_result <- self$validate_system()
          
          if (validation_result$valid) {
            self$initialized <- TRUE
            self$initialization_error <- NULL
            
            if (!is.null(progress_callback)) {
              progress_callback(1.0, "Geographic system ready!")
            }
            
            cat("🎉 Geographic Integration System fully initialized\n")
            return(list(
              success = TRUE, 
              status = "initialized",
              components = self$components_status,
              validation = validation_result
            ))
            
          } else {
            self$initialization_error <- validation_result$errors
            
            cat("⚠️ Geographic system partially initialized with issues\n")
            return(list(
              success = FALSE,
              status = "partial",
              components = self$components_status,
              validation = validation_result,
              errors = validation_result$errors
            ))
          }
          
        }, error = function(e) {
          self$initialization_error <- e$message
          cat("❌ Geographic system initialization failed:", e$message, "\n")
          
          return(list(
            success = FALSE,
            status = "failed",
            error = e$message,
            components = self$components_status
          ))
        })
      },
      
      # Load priority data for immediate use
      load_priority_data = function(progress_callback = NULL) {
        
        if (is.null(self$data_loader)) {
          return(FALSE)
        }
        
        tryCatch({
          
          # Load Brazilian states first (essential for all maps)
          if (!is.null(progress_callback)) {
            progress_callback(0.75, "Loading Brazilian states...")
          }
          
          if ("load_states" %in% names(self$data_loader)) {
            states_data <- self$data_loader$load_states(force_refresh = FALSE)
          } else {
            states_data <- self$data_loader(force_refresh = FALSE)  # Functional approach
          }
          
          if (!is.null(states_data)) {
            cat("✅ Loaded", nrow(states_data), "Brazilian states\n")
          }
          
          # Load municipalities for priority states only
          if (!is.null(progress_callback)) {
            progress_callback(0.85, "Loading priority municipalities...")
          }
          
          priority_states <- GEOGRAPHIC_INTEGRATION_CONFIG$performance$preload_priority_states
          
          if ("load_municipalities" %in% names(self$data_loader)) {
            municipalities_data <- self$data_loader$load_municipalities(
              state_codes = priority_states,
              priority_only = TRUE
            )
          } else {
            municipalities_data <- NULL  # Skip for functional approach
          }
          
          if (!is.null(municipalities_data)) {
            cat("✅ Loaded", nrow(municipalities_data), "priority municipalities\n")
          }
          
          # Memory cleanup
          gc(verbose = FALSE)
          
          return(TRUE)
          
        }, error = function(e) {
          cat("⚠️ Error loading priority data:", e$message, "\n")
          return(FALSE)
        })
      },
      
      # System validation
      validate_system = function() {
        
        validation_result <- list(
          valid = TRUE,
          errors = c(),
          warnings = c(),
          component_status = self$components_status
        )
        
        # Check critical components
        if (is.null(self$data_loader)) {
          validation_result$errors <- c(validation_result$errors, "Data loader not initialized")
          validation_result$valid <- FALSE
        }
        
        if (is.null(self$aggregator)) {
          validation_result$errors <- c(validation_result$errors, "Aggregator not initialized")
          validation_result$valid <- FALSE
        }
        
        if (is.null(self$db_pool)) {
          validation_result$warnings <- c(validation_result$warnings, "No database connection")
        }
        
        # Test basic functionality
        tryCatch({
          if (!is.null(self$data_loader)) {
            if ("get_summary" %in% names(self$data_loader)) {
              loader_summary <- self$data_loader$get_summary()
            } else {
              loader_summary <- self$data_loader()  # Functional approach
            }
            
            if (is.null(loader_summary)) {
              validation_result$warnings <- c(validation_result$warnings, "Data loader summary unavailable")
            }
          }
        }, error = function(e) {
          validation_result$warnings <- c(validation_result$warnings, paste("Loader test failed:", e$message))
        })
        
        return(validation_result)
      },
      
      # Get system status and summary
      get_system_status = function() {
        
        status <- list(
          timestamp = Sys.time(),
          initialized = self$initialized,
          components = self$components_status,
          memory_usage = round(sum(gc(verbose = FALSE)[, "(Mb)"]), 2)
        )
        
        # Add component summaries if available
        if (!is.null(self$data_loader)) {
          tryCatch({
            if ("get_summary" %in% names(self$data_loader)) {
              status$data_loader_summary <- self$data_loader$get_summary()
            }
          }, error = function(e) {
            status$data_loader_error <- e$message
          })
        }
        
        if (!is.null(self$aggregator)) {
          tryCatch({
            if ("get_aggregation_summary" %in% names(self$aggregator)) {
              status$aggregator_summary <- self$aggregator$get_aggregation_summary()
            }
          }, error = function(e) {
            status$aggregator_error <- e$message
          })
        }
        
        return(status)
      },
      
      # Get geographic data for UI components
      get_states_data = function(include_geometry = TRUE) {
        
        if (!self$initialized || is.null(self$data_loader)) {
          return(NULL)
        }
        
        tryCatch({
          if ("load_states" %in% names(self$data_loader)) {
            return(self$data_loader$load_states(force_refresh = FALSE))
          } else {
            return(self$data_loader(force_refresh = FALSE))  # Functional
          }
        }, error = function(e) {
          cat("❌ Error getting states data:", e$message, "\n")
          return(NULL)
        })
      },
      
      get_municipalities_data = function(state_codes = NULL) {
        
        if (!self$initialized || is.null(self$data_loader)) {
          return(NULL)
        }
        
        tryCatch({
          if ("load_municipalities" %in% names(self$data_loader)) {
            return(self$data_loader$load_municipalities(
              state_codes = state_codes %||% GEOGRAPHIC_INTEGRATION_CONFIG$performance$preload_priority_states,
              priority_only = TRUE
            ))
          } else {
            return(NULL)  # Not available in functional approach
          }
        }, error = function(e) {
          cat("❌ Error getting municipalities data:", e$message, "\n")
          return(NULL)
        })
      },
      
      # Get aggregated data for visualizations
      get_state_aggregation = function(include_geometry = TRUE) {
        
        if (!self$initialized || is.null(self$aggregator)) {
          return(NULL)
        }
        
        tryCatch({
          if ("aggregate_by_state" %in% names(self$aggregator)) {
            return(self$aggregator$aggregate_by_state(
              filters = NULL,
              include_geometry = include_geometry,
              use_cache = TRUE
            ))
          } else {
            return(self$aggregator(include_geometry = include_geometry))  # Functional
          }
        }, error = function(e) {
          cat("❌ Error getting state aggregation:", e$message, "\n")
          return(NULL)
        })
      },
      
      get_municipality_aggregation = function(state_filter = NULL, top_n = 50) {
        
        if (!self$initialized || is.null(self$aggregator)) {
          return(NULL)
        }
        
        tryCatch({
          if ("aggregate_by_municipality" %in% names(self$aggregator)) {
            return(self$aggregator$aggregate_by_municipality(
              state_filter = state_filter,
              top_n = top_n,
              include_geometry = FALSE  # Keep light for performance
            ))
          } else {
            return(NULL)  # Not available in functional approach
          }
        }, error = function(e) {
          cat("❌ Error getting municipality aggregation:", e$message, "\n")
          return(NULL)
        })
      },
      
      # Cleanup method
      cleanup = function() {
        
        cat("🧹 Cleaning up Geographic Integration System...\n")
        
        # Cleanup components
        if (!is.null(self$data_loader) && "cleanup" %in% names(self$data_loader)) {
          tryCatch({
            self$data_loader$cleanup()
          }, error = function(e) {
            cat("⚠️ Data loader cleanup error:", e$message, "\n")
          })
        }
        
        if (!is.null(self$aggregator) && "clear_cache" %in% names(self$aggregator)) {
          tryCatch({
            self$aggregator$clear_cache()
          }, error = function(e) {
            cat("⚠️ Aggregator cleanup error:", e$message, "\n")
          })
        }
        
        # Reset status
        self$initialized <- FALSE
        self$components_status <- list()
        
        # Force garbage collection
        gc(verbose = FALSE)
        
        cat("✅ Geographic system cleanup completed\n")
      }
    )
  )
  
} else {
  # Fallback for when R6 is not available
  NULL
}

# Factory and Utility Functions
# =============================

#' Create Geographic Integration System
#' 
#' Factory function to create the main geographic integration system
#' 
#' @param db_pool Database connection pool
#' @param auto_initialize Automatically initialize the system
#' @return GeographicIntegrationSystem instance or functional equivalent
create_geographic_integration <- function(db_pool = NULL, auto_initialize = FALSE) {
  
  if (!is.null(GeographicIntegrationSystem)) {
    
    # R6 class approach
    system <- GeographicIntegrationSystem$new(db_pool)
    
    if (auto_initialize) {
      init_result <- system$initialize_system()
      cat("🔧 Auto-initialization result:", init_result$status, "\n")
    }
    
    return(system)
    
  } else {
    
    # Functional fallback approach
    cat("⚠️ Using functional geographic integration (R6 not available)\n")
    return(create_functional_geographic_integration(db_pool))
  }
}

#' Functional Geographic Integration (Fallback)
#' 
#' Provides basic geographic functionality when R6 is not available
#' 
#' @param db_pool Database connection pool
#' @return List of geographic functions
create_functional_geographic_integration <- function(db_pool = NULL) {
  
  # Create environment for state
  geo_env <- new.env()
  geo_env$db_pool <- db_pool
  geo_env$initialized <- FALSE
  geo_env$data_loader <- NULL
  geo_env$aggregator <- NULL
  
  list(
    
    initialize_system = function(progress_callback = NULL) {
      
      tryCatch({
        
        if (!is.null(progress_callback)) {
          progress_callback(0.3, "Setting up geographic components...")
        }
        
        # Initialize data loader
        geo_env$data_loader <- create_functional_loader(geo_env$db_pool)
        
        # Initialize aggregator  
        geo_env$aggregator <- create_functional_aggregator(geo_env$db_pool, geo_env$data_loader)
        
        if (!is.null(progress_callback)) {
          progress_callback(0.8, "Loading basic geographic data...")
        }
        
        # Test basic functionality
        states_data <- geo_env$data_loader$load_states()
        
        if (!is.null(states_data)) {
          geo_env$initialized <- TRUE
          
          if (!is.null(progress_callback)) {
            progress_callback(1.0, "Geographic system ready!")
          }
          
          return(list(success = TRUE, status = "initialized"))
        } else {
          return(list(success = FALSE, status = "failed", error = "No states data"))
        }
        
      }, error = function(e) {
        return(list(success = FALSE, status = "failed", error = e$message))
      })
    },
    
    get_system_status = function() {
      list(
        timestamp = Sys.time(),
        initialized = geo_env$initialized,
        memory_usage = round(sum(gc(verbose = FALSE)[, "(Mb)"]), 2),
        components = list(
          data_loader = !is.null(geo_env$data_loader),
          aggregator = !is.null(geo_env$aggregator)
        )
      )
    },
    
    get_states_data = function() {
      if (geo_env$initialized && !is.null(geo_env$data_loader)) {
        return(geo_env$data_loader$load_states())
      }
      return(NULL)
    },
    
    get_state_aggregation = function() {
      if (geo_env$initialized && !is.null(geo_env$aggregator)) {
        return(geo_env$aggregator$aggregate_by_state())
      }
      return(NULL)
    },
    
    cleanup = function() {
      if (!is.null(geo_env$data_loader)) {
        geo_env$data_loader$cleanup()
      }
      if (!is.null(geo_env$aggregator)) {
        geo_env$aggregator$clear_cache()
      }
      geo_env$initialized <- FALSE
      gc(verbose = FALSE)
    }
  )
}

#' Initialize Geographic System with Progress
#' 
#' Initialize the geographic system with progress feedback for UI
#' 
#' @param geo_system Geographic integration system instance
#' @param session Shiny session for progress updates
#' @return Initialization result
initialize_geographic_with_progress <- function(geo_system, session = NULL) {
  
  # Progress callback function
  progress_callback <- if (!is.null(session)) {
    function(value, message) {
      session$sendCustomMessage(
        type = "geographic-progress",
        message = list(
          progress = value,
          message = message
        )
      )
    }
  } else {
    function(value, message) {
      cat(sprintf("[%3.0f%%] %s\n", value * 100, message))
    }
  }
  
  # Initialize with progress
  if ("initialize_system" %in% names(geo_system)) {
    return(geo_system$initialize_system(progress_callback))
  } else {
    return(geo_system$initialize_system(progress_callback))  # Functional approach
  }
}

#' Get Geographic Summary for Dashboard
#' 
#' Provides a comprehensive summary for dashboard display
#' 
#' @param geo_system Geographic integration system
#' @return Summary data for dashboard widgets
get_geographic_dashboard_summary <- function(geo_system) {
  
  if (is.null(geo_system)) {
    return(list(
      available = FALSE,
      message = "Geographic system not available"
    ))
  }
  
  tryCatch({
    
    # Get system status
    if ("get_system_status" %in% names(geo_system)) {
      status <- geo_system$get_system_status()
    } else {
      status <- geo_system$get_system_status()  # Functional
    }
    
    # Get basic data counts
    states_data <- if ("get_states_data" %in% names(geo_system)) {
      geo_system$get_states_data(include_geometry = FALSE)
    } else {
      geo_system$get_states_data()  # Functional
    }
    
    summary <- list(
      available = TRUE,
      initialized = status$initialized %||% FALSE,
      timestamp = Sys.time(),
      
      # Data availability
      states_available = !is.null(states_data),
      states_count = ifelse(!is.null(states_data), nrow(states_data), 0),
      
      # System health
      memory_usage_mb = status$memory_usage %||% 0,
      components_operational = length(status$components %||% list()),
      
      # Quick statistics
      last_update = status$timestamp %||% Sys.time()
    )
    
    return(summary)
    
  }, error = function(e) {
    return(list(
      available = FALSE,
      error = e$message,
      timestamp = Sys.time()
    ))
  })
}

# Export main integration functions
list(
  create_geographic_integration = create_geographic_integration,
  create_functional_geographic_integration = create_functional_geographic_integration,
  initialize_geographic_with_progress = initialize_geographic_with_progress,
  get_geographic_dashboard_summary = get_geographic_dashboard_summary,
  GEOGRAPHIC_INTEGRATION_CONFIG = GEOGRAPHIC_INTEGRATION_CONFIG
)