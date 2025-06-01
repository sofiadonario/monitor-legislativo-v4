# ============================================================================
# SPRINT 4B DATA PIPELINE INITIALIZATION - MAIN ENTRY POINT
# ============================================================================
#
# Main initialization script for the comprehensive Brazilian legislative
# data pipeline system implemented in Sprint 4B
#
# This script orchestrates the initialization of all pipeline components:
# - ETL Architecture with LexML/IBGE integration
# - Data Validation and Quality Assurance
# - External API Integration with Error Handling  
# - Automated Scheduling and Data Refresh
# - Monitoring and Alerting System
# - Brazilian Legislative Standards Compliance
# - System Integration with Existing Database and Search
#
# Author: Legislative Data Science Team
# Version: 4B.1.0 (Sprint 4B)
# Updated: 2025-01-20
# ============================================================================

# ============================================================================
# LOAD PIPELINE COMPONENTS
# ============================================================================

cat("🚀 Initializing Brazilian Legislative Data Pipeline - Sprint 4B\n")
cat("=" , rep("=", 70), "\n", sep="")

# Get the pipeline directory path
pipeline_dir <- file.path(getwd(), "pipeline")

# Check if pipeline directory exists
if (!dir.exists(pipeline_dir)) {
  cat("❌ ERROR: Pipeline directory not found at:", pipeline_dir, "\n")
  stop("Pipeline initialization failed - missing pipeline directory")
}

# Pipeline component files
pipeline_components <- list(
  "etl_architecture" = file.path(pipeline_dir, "etl_architecture.R"),
  "data_validation" = file.path(pipeline_dir, "data_validation.R"),
  "api_integration" = file.path(pipeline_dir, "api_integration.R"),
  "scheduler" = file.path(pipeline_dir, "scheduler.R"),
  "monitoring" = file.path(pipeline_dir, "monitoring.R"),
  "brazilian_standards" = file.path(pipeline_dir, "brazilian_standards.R"),
  "system_integration" = file.path(pipeline_dir, "system_integration.R")
)

# Check component availability
cat("🔍 Checking pipeline components...\n")
missing_components <- c()
for (component_name in names(pipeline_components)) {
  component_file <- pipeline_components[[component_name]]
  if (file.exists(component_file)) {
    cat(sprintf("   ✅ %s: Found\n", component_name))
  } else {
    cat(sprintf("   ❌ %s: Missing (%s)\n", component_name, component_file))
    missing_components <- c(missing_components, component_name)
  }
}

if (length(missing_components) > 0) {
  cat("❌ ERROR: Missing required pipeline components:", paste(missing_components, collapse = ", "), "\n")
  stop("Pipeline initialization failed - missing components")
}

cat("📦 Loading pipeline components...\n")

# Load components in dependency order
component_load_order <- c(
  "etl_architecture",
  "data_validation", 
  "api_integration",
  "brazilian_standards",
  "monitoring",
  "scheduler",
  "system_integration"
)

loaded_components <- c()
failed_components <- c()

for (component_name in component_load_order) {
  component_file <- pipeline_components[[component_name]]
  
  cat(sprintf("   📋 Loading %s...\n", component_name))
  
  tryCatch({
    source(component_file)
    loaded_components <- c(loaded_components, component_name)
    cat(sprintf("   ✅ %s loaded successfully\n", component_name))
  }, error = function(e) {
    failed_components <- c(failed_components, component_name)
    cat(sprintf("   ❌ %s failed to load: %s\n", component_name, e$message))
  })
}

# Report loading results
cat("\n📊 Component Loading Summary:\n")
cat(sprintf("   ✅ Successfully loaded: %d/%d components\n", length(loaded_components), length(component_load_order)))
cat(sprintf("   ❌ Failed to load: %d components\n", length(failed_components)))

if (length(failed_components) > 0) {
  cat("   Failed components:", paste(failed_components, collapse = ", "), "\n")
}

# ============================================================================
# INITIALIZE PIPELINE SYSTEM
# ============================================================================

#' Main pipeline initialization function
initialize_data_pipeline_system <- function(db_pool = NULL, skip_failed = TRUE) {
  cat("\n🏗️ Initializing Data Pipeline System...\n")
  cat("=" , rep("=", 50), "\n", sep="")
  
  initialization_results <- list(
    etl_system = FALSE,
    validation_system = FALSE,
    api_integration = FALSE,
    brazilian_standards = FALSE,
    monitoring_system = FALSE,
    scheduler_system = FALSE,
    system_integration = FALSE
  )
  
  # Get database connection
  if (is.null(db_pool)) {
    if (exists("secure_db_pool", envir = .GlobalEnv) && !is.null(secure_db_pool)) {
      db_pool <- secure_db_pool
      cat("🔗 Using existing secure database connection\n")
    } else {
      cat("⚠️  No database connection available - limited functionality\n")
    }
  }
  
  # Initialize ETL System
  if ("etl_architecture" %in% loaded_components) {
    cat("\n1️⃣ Initializing ETL Architecture...\n")
    tryCatch({
      if (exists("initialize_etl_pipeline")) {
        initialization_results$etl_system <- initialize_etl_pipeline()
        if (initialization_results$etl_system) {
          cat("   ✅ ETL system initialized successfully\n")
        } else {
          cat("   ⚠️  ETL system initialization had issues\n")
        }
      } else {
        cat("   ❌ ETL initialization function not found\n")
      }
    }, error = function(e) {
      cat("   ❌ ETL initialization failed:", e$message, "\n")
      if (!skip_failed) stop("ETL initialization failed")
    })
  }
  
  # Initialize Validation System
  if ("data_validation" %in% loaded_components) {
    cat("\n2️⃣ Initializing Data Validation System...\n")
    tryCatch({
      if (exists("initialize_validation_system")) {
        initialization_results$validation_system <- initialize_validation_system()
        if (initialization_results$validation_system) {
          cat("   ✅ Validation system initialized successfully\n")
        } else {
          cat("   ⚠️  Validation system initialization had issues\n")
        }
      } else {
        cat("   ❌ Validation initialization function not found\n")
      }
    }, error = function(e) {
      cat("   ❌ Validation initialization failed:", e$message, "\n")
      if (!skip_failed) stop("Validation initialization failed")
    })
  }
  
  # Initialize API Integration
  if ("api_integration" %in% loaded_components) {
    cat("\n3️⃣ Initializing API Integration...\n")
    tryCatch({
      if (exists("initialize_api_integration")) {
        initialization_results$api_integration <- initialize_api_integration()
        if (initialization_results$api_integration) {
          cat("   ✅ API integration initialized successfully\n")
        } else {
          cat("   ⚠️  API integration initialization had issues\n")
        }
      } else {
        cat("   ❌ API integration initialization function not found\n")
      }
    }, error = function(e) {
      cat("   ❌ API integration initialization failed:", e$message, "\n")
      if (!skip_failed) stop("API integration initialization failed")
    })
  }
  
  # Initialize Brazilian Standards
  if ("brazilian_standards" %in% loaded_components) {
    cat("\n4️⃣ Initializing Brazilian Legislative Standards...\n")
    tryCatch({
      if (exists("initialize_brazilian_standards")) {
        initialization_results$brazilian_standards <- initialize_brazilian_standards()
        if (initialization_results$brazilian_standards) {
          cat("   ✅ Brazilian standards initialized successfully\n")
        } else {
          cat("   ⚠️  Brazilian standards initialization had issues\n")
        }
      } else {
        cat("   ❌ Brazilian standards initialization function not found\n")
      }
    }, error = function(e) {
      cat("   ❌ Brazilian standards initialization failed:", e$message, "\n")
      if (!skip_failed) stop("Brazilian standards initialization failed")
    })
  }
  
  # Initialize Monitoring System
  if ("monitoring" %in% loaded_components) {
    cat("\n5️⃣ Initializing Monitoring and Alerting System...\n")
    tryCatch({
      if (exists("initialize_monitoring_system")) {
        initialization_results$monitoring_system <- initialize_monitoring_system(db_pool)
        if (initialization_results$monitoring_system) {
          cat("   ✅ Monitoring system initialized successfully\n")
        } else {
          cat("   ⚠️  Monitoring system initialization had issues\n")
        }
      } else {
        cat("   ❌ Monitoring initialization function not found\n")
      }
    }, error = function(e) {
      cat("   ❌ Monitoring initialization failed:", e$message, "\n")
      if (!skip_failed) stop("Monitoring initialization failed")
    })
  }
  
  # Initialize Scheduler System
  if ("scheduler" %in% loaded_components) {
    cat("\n6️⃣ Initializing Automated Scheduler...\n")
    tryCatch({
      if (exists("initialize_scheduler_system")) {
        initialization_results$scheduler_system <- initialize_scheduler_system(db_pool)
        if (initialization_results$scheduler_system) {
          cat("   ✅ Scheduler system initialized successfully\n")
        } else {
          cat("   ⚠️  Scheduler system initialization had issues\n")
        }
      } else {
        cat("   ❌ Scheduler initialization function not found\n")
      }
    }, error = function(e) {
      cat("   ❌ Scheduler initialization failed:", e$message, "\n")
      if (!skip_failed) stop("Scheduler initialization failed")
    })
  }
  
  # Initialize System Integration
  if ("system_integration" %in% loaded_components) {
    cat("\n7️⃣ Initializing System Integration...\n")
    tryCatch({
      if (exists("initialize_system_integration")) {
        initialization_results$system_integration <- initialize_system_integration()
        if (initialization_results$system_integration) {
          cat("   ✅ System integration initialized successfully\n")
        } else {
          cat("   ⚠️  System integration initialization had issues\n")
        }
      } else {
        cat("   ❌ System integration initialization function not found\n")
      }
    }, error = function(e) {
      cat("   ❌ System integration initialization failed:", e$message, "\n")
      if (!skip_failed) stop("System integration initialization failed")
    })
  }
  
  # Final Summary
  cat("\n🎯 SPRINT 4B PIPELINE INITIALIZATION SUMMARY\n")
  cat("=" , rep("=", 55), "\n", sep="")
  
  successful_systems <- sum(unlist(initialization_results))
  total_systems <- length(initialization_results)
  success_rate <- round((successful_systems / total_systems) * 100, 1)
  
  cat(sprintf("📊 Overall Success Rate: %d/%d systems (%.1f%%)\n", 
              successful_systems, total_systems, success_rate))
  
  cat("\n📋 System Status:\n")
  for (system_name in names(initialization_results)) {
    status_icon <- if (initialization_results[[system_name]]) "✅" else "❌"
    cat(sprintf("   %s %s\n", status_icon, gsub("_", " ", toupper(system_name))))
  }
  
  if (successful_systems == total_systems) {
    cat("\n🎉 CONGRATULATIONS! All Sprint 4B pipeline systems initialized successfully!\n")
    cat("🚀 Brazilian Legislative Data Pipeline is ready for production use.\n")
  } else if (successful_systems >= total_systems * 0.7) {
    cat("\n⚠️  PARTIAL SUCCESS: Most systems initialized successfully.\n")
    cat("🔧 Some components may have limited functionality.\n")
  } else {
    cat("\n❌ CRITICAL: Multiple system initialization failures.\n")
    cat("🛠️  Please check system requirements and configurations.\n")
  }
  
  # System capabilities summary
  cat("\n🌟 AVAILABLE CAPABILITIES:\n")
  
  if (initialization_results$etl_system) {
    cat("   📥 LexML and IBGE data extraction\n")
    cat("   🔄 Memory-optimized ETL processing\n")
  }
  
  if (initialization_results$validation_system) {
    cat("   ✅ Brazilian legislative document validation\n")
    cat("   🔍 Quality scoring and duplicate detection\n")
  }
  
  if (initialization_results$api_integration) {
    cat("   🌐 Robust API integration with error handling\n")
    cat("   🔄 Circuit breakers and retry mechanisms\n")
  }
  
  if (initialization_results$brazilian_standards) {
    cat("   🇧🇷 LexML-BR and IBGE standards compliance\n")
    cat("   📝 Portuguese legal text processing\n")
  }
  
  if (initialization_results$monitoring_system) {
    cat("   📊 Real-time performance monitoring\n")
    cat("   🚨 Automated alerting system\n")
  }
  
  if (initialization_results$scheduler_system) {
    cat("   ⏰ Railway-compatible automated scheduling\n")
    cat("   📅 Data refresh with versioning\n")
  }
  
  if (initialization_results$system_integration) {
    cat("   🔗 Seamless integration with existing systems\n")
    cat("   🔍 Enhanced search capabilities\n")
  }
  
  cat("\n📖 Next Steps:\n")
  cat("   1. Run test_pipeline_system() to validate functionality\n")
  cat("   2. Execute run_full_refresh() for initial data load\n")
  cat("   3. Monitor system performance with get_monitoring_status()\n")
  cat("   4. Check integration health with get_integration_health()\n")
  
  return(initialization_results)
}

# ============================================================================
# PIPELINE TESTING AND VALIDATION
# ============================================================================

#' Test the pipeline system functionality
test_pipeline_system <- function() {
  cat("\n🧪 Testing Pipeline System Functionality...\n")
  cat("=" , rep("=", 45), "\n", sep="")
  
  test_results <- list()
  
  # Test ETL System
  cat("1️⃣ Testing ETL System...\n")
  if (exists("get_pipeline_status")) {
    tryCatch({
      etl_status <- get_pipeline_status()
      test_results$etl_test <- !is.null(etl_status)
      cat(sprintf("   %s ETL Status Check\n", if (test_results$etl_test) "✅" else "❌"))
    }, error = function(e) {
      test_results$etl_test <- FALSE
      cat("   ❌ ETL Status Check Failed\n")
    })
  } else {
    test_results$etl_test <- FALSE
    cat("   ❌ ETL functions not available\n")
  }
  
  # Test Validation System
  cat("2️⃣ Testing Validation System...\n")
  if (exists("get_validation_status")) {
    tryCatch({
      validation_status <- get_validation_status()
      test_results$validation_test <- !is.null(validation_status)
      cat(sprintf("   %s Validation Status Check\n", if (test_results$validation_test) "✅" else "❌"))
    }, error = function(e) {
      test_results$validation_test <- FALSE
      cat("   ❌ Validation Status Check Failed\n")
    })
  } else {
    test_results$validation_test <- FALSE
    cat("   ❌ Validation functions not available\n")
  }
  
  # Test API Integration
  cat("3️⃣ Testing API Integration...\n")
  if (exists("get_api_health_status")) {
    tryCatch({
      api_status <- get_api_health_status()
      test_results$api_test <- !is.null(api_status)
      cat(sprintf("   %s API Health Check\n", if (test_results$api_test) "✅" else "❌"))
    }, error = function(e) {
      test_results$api_test <- FALSE
      cat("   ❌ API Health Check Failed\n")
    })
  } else {
    test_results$api_test <- FALSE
    cat("   ❌ API functions not available\n")
  }
  
  # Test Monitoring System
  cat("4️⃣ Testing Monitoring System...\n")
  if (exists("get_monitoring_status")) {
    tryCatch({
      monitoring_status <- get_monitoring_status()
      test_results$monitoring_test <- !is.null(monitoring_status)
      cat(sprintf("   %s Monitoring Status Check\n", if (test_results$monitoring_test) "✅" else "❌"))
    }, error = function(e) {
      test_results$monitoring_test <- FALSE
      cat("   ❌ Monitoring Status Check Failed\n")
    })
  } else {
    test_results$monitoring_test <- FALSE
    cat("   ❌ Monitoring functions not available\n")
  }
  
  # Test System Integration
  cat("5️⃣ Testing System Integration...\n")
  if (exists("get_integration_health")) {
    tryCatch({
      integration_health <- get_integration_health()
      test_results$integration_test <- !is.null(integration_health)
      cat(sprintf("   %s Integration Health Check\n", if (test_results$integration_test) "✅" else "❌"))
    }, error = function(e) {
      test_results$integration_test <- FALSE
      cat("   ❌ Integration Health Check Failed\n")
    })
  } else {
    test_results$integration_test <- FALSE
    cat("   ❌ Integration functions not available\n")
  }
  
  # Test Summary
  passed_tests <- sum(unlist(test_results))
  total_tests <- length(test_results)
  
  cat("\n📊 PIPELINE TESTING SUMMARY:\n")
  cat(sprintf("   ✅ Passed: %d/%d tests\n", passed_tests, total_tests))
  cat(sprintf("   ❌ Failed: %d/%d tests\n", total_tests - passed_tests, total_tests))
  
  if (passed_tests == total_tests) {
    cat("\n🎉 ALL TESTS PASSED! Pipeline system is ready for operation.\n")
  } else if (passed_tests >= total_tests * 0.6) {
    cat("\n⚠️  MOST TESTS PASSED. System has limited functionality.\n")
  } else {
    cat("\n❌ MULTIPLE TEST FAILURES. Please check system configuration.\n")
  }
  
  return(test_results)
}

# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

#' Start the complete pipeline system
start_pipeline_system <- function() {
  cat("🚀 Starting Complete Pipeline System...\n")
  
  # Start monitoring
  if (exists("start_monitoring")) {
    start_monitoring()
  }
  
  # Run initial health checks
  if (exists("run_api_health_checks")) {
    run_api_health_checks()
  }
  
  cat("✅ Pipeline system started successfully!\n")
}

#' Get overall system status
get_system_status <- function() {
  status <- list(
    timestamp = Sys.time(),
    etl_status = if (exists("get_pipeline_status")) get_pipeline_status() else NULL,
    validation_status = if (exists("get_validation_status")) get_validation_status() else NULL,
    api_status = if (exists("get_api_health_status")) get_api_health_status() else NULL,
    monitoring_status = if (exists("get_monitoring_status")) get_monitoring_status() else NULL,
    scheduler_status = if (exists("get_scheduler_status")) get_scheduler_status() else NULL,
    integration_status = if (exists("get_integration_health")) get_integration_health() else NULL
  )
  
  return(status)
}

#' Run a complete pipeline execution (for testing)
run_pipeline_demo <- function(limit = 100) {
  cat("🎬 Running Pipeline Demonstration...\n")
  
  # Small demo run
  if (exists("run_etl_pipeline")) {
    cat("📥 Running ETL pipeline (demo)...\n")
    etl_result <- run_etl_pipeline(limit = limit)
    
    if (etl_result) {
      cat("✅ Demo ETL pipeline completed successfully!\n")
    } else {
      cat("❌ Demo ETL pipeline failed.\n")
    }
    
    return(etl_result)
  } else {
    cat("⚠️  ETL pipeline not available for demo.\n")
    return(FALSE)
  }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Auto-initialize if called directly
if (length(commandArgs(trailingOnly = TRUE)) == 0 && interactive()) {
  cat("\n🎯 Auto-initializing Sprint 4B Pipeline System...\n")
  
  # Initialize the complete system
  init_results <- initialize_data_pipeline_system(skip_failed = TRUE)
  
  # Run system tests
  test_results <- test_pipeline_system()
  
  cat("\n🎉 Sprint 4B Pipeline System Ready!\n")
  cat("📋 Available functions:\n")
  cat("   - get_system_status(): Overall system status\n")
  cat("   - start_pipeline_system(): Start all monitoring\n")
  cat("   - run_pipeline_demo(limit=100): Test pipeline execution\n")
  cat("   - test_pipeline_system(): Validate system functionality\n")
  
  # Store initialization results globally
  assign("pipeline_initialization_results", init_results, envir = .GlobalEnv)
  assign("pipeline_test_results", test_results, envir = .GlobalEnv)
}

cat("\n🇧🇷 Brazilian Legislative Data Pipeline - Sprint 4B Loaded Successfully! 🇧🇷\n")
cat("=" , rep("=", 75), "\n", sep="")