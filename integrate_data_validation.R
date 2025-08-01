# Data Validation Pipeline Integration
# This file integrates the data quality monitoring framework into the app

cat("🔍 INTEGRATING DATA VALIDATION PIPELINE...\n")

# Source the data quality monitoring framework
if (file.exists("data_quality_monitoring_framework.R")) {
  source("data_quality_monitoring_framework.R")
  cat("✅ Data Quality Monitoring Framework loaded\n")
} else {
  cat("⚠️ data_quality_monitoring_framework.R not found\n")
}

# Initialize data validation system
init_data_validation <- function() {
  tryCatch({
    if (exists(".db_pool") && inherits(.db_pool, "Pool")) {
      # Initialize data quality metrics calculator
      .data_quality_metrics <<- DataQualityMetrics$new(.db_pool)
      
      # Initialize data quality monitor
      .data_quality_monitor <<- DataQualityMonitor$new(.db_pool)
      
      # Set up validation thresholds
      .validation_thresholds <<- list(
        completeness_threshold = 0.95,
        consistency_threshold = 0.98,
        accuracy_threshold = 0.90,
        max_duplicate_percentage = 0.05
      )
      
      cat("✅ Data validation system initialized\n")
      return(TRUE)
    } else {
      cat("⚠️ No database pool available for validation\n")
      return(FALSE)
    }
  }, error = function(e) {
    cat("❌ Error initializing data validation:", e$message, "\n")
    return(FALSE)
  })
}

# Simple validation function for dashboard consistency
validate_dashboard_consistency <- function() {
  cat("🔄 Validating dashboard consistency...\n")
  
  tryCatch({
    # Get metrics from different sources
    unified_metrics <- get_unified_dashboard_metrics()
    lexml_metrics <- get_lexml_dashboard_metrics()
    
    # Check consistency
    issues <- list()
    
    # Compare total documents
    if (abs(unified_metrics$total_documents - lexml_metrics$total_documents) > 100) {
      issues <- append(issues, sprintf(
        "Document count mismatch: Unified=%d, LexML=%d",
        unified_metrics$total_documents,
        lexml_metrics$total_documents
      ))
    }
    
    # Check for zero values (likely errors)
    if (lexml_metrics$total_documents == 0) {
      issues <- append(issues, "LexML shows 0 documents - likely data access error")
    }
    
    if (unified_metrics$states_with_docs == 0) {
      issues <- append(issues, "No states with documents - likely query error")
    }
    
    # Check date ranges
    if (unified_metrics$date_range_years == 0) {
      issues <- append(issues, "Date range is 0 years - likely date parsing error")
    }
    
    # Return validation results
    validation_result <- list(
      timestamp = Sys.time(),
      is_consistent = length(issues) == 0,
      issues = issues,
      metrics_comparison = list(
        unified = unified_metrics,
        lexml = lexml_metrics
      )
    )
    
    if (length(issues) == 0) {
      cat("✅ Dashboard consistency validation passed\n")
    } else {
      cat("❌ Dashboard consistency issues found:\n")
      for (issue in issues) {
        cat("  -", issue, "\n")
      }
    }
    
    return(validation_result)
    
  }, error = function(e) {
    cat("❌ Error in dashboard validation:", e$message, "\n")
    return(list(
      timestamp = Sys.time(),
      is_consistent = FALSE,
      issues = list(paste("Validation error:", e$message)),
      metrics_comparison = NULL
    ))
  })
}

# Override lexml_metrics function to include validation
lexml_metrics_with_validation <- function() {
  # Get original metrics
  metrics <- get_lexml_dashboard_metrics()
  
  # Add validation status
  validation <- validate_dashboard_consistency()
  metrics$validation_status <- validation$is_consistent
  metrics$validation_issues <- validation$issues
  metrics$last_validated <- validation$timestamp
  
  return(metrics)
}

# Background validation scheduler (simple version)
start_validation_scheduler <- function(interval_minutes = 15) {
  if (!exists(".validation_scheduler_active")) {
    .validation_scheduler_active <<- TRUE
    
    # Simple scheduler using later package if available
    if (requireNamespace("later", quietly = TRUE)) {
      later::later(function() {
        if (exists(".validation_scheduler_active") && .validation_scheduler_active) {
          validate_dashboard_consistency()
          # Schedule next validation
          start_validation_scheduler(interval_minutes)
        }
      }, delay = interval_minutes * 60)
      
      cat(sprintf("✅ Validation scheduler started (every %d minutes)\n", interval_minutes))
    } else {
      cat("⚠️ later package not available - manual validation only\n")
    }
  }
}

# Stop validation scheduler
stop_validation_scheduler <- function() {
  if (exists(".validation_scheduler_active")) {
    .validation_scheduler_active <<- FALSE
    cat("✅ Validation scheduler stopped\n")
  }
}

# Helper function to get validation summary for UI display
get_validation_summary <- function() {
  tryCatch({
    validation <- validate_dashboard_consistency()
    
    if (validation$is_consistent) {
      return(list(
        status = "healthy",
        message = "All dashboard components show consistent data",
        color = "green",
        icon = "check-circle"
      ))
    } else {
      return(list(
        status = "warning",
        message = paste("Issues found:", length(validation$issues), "inconsistencies"),
        color = "orange",
        icon = "exclamation-triangle",
        details = validation$issues
      ))
    }
  }, error = function(e) {
    return(list(
      status = "error",
      message = paste("Validation error:", e$message),
      color = "red",
      icon = "times-circle"
    ))
  })
}

# Initialize validation if database is available
if (exists("database_connected") && database_connected) {
  init_data_validation()
  
  # Start background validation
  start_validation_scheduler(15)
} else {
  cat("⚠️ Database not connected - validation will be initialized later\n")
}

cat("✅ DATA VALIDATION PIPELINE INTEGRATION COMPLETE\n")