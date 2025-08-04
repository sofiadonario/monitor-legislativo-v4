# RAILWAY ERROR HANDLER - PRODUCTION DIAGNOSTICS
# ===============================================
# Comprehensive error handling and diagnostic system for Railway deployment
# Provides clear feedback on system status and issues

cat("🛡️ Railway Error Handler - Loading diagnostic system...\n")

# Global error tracking
.error_log <- list()
.system_health <- list(
  database = FALSE,
  analytics = FALSE,
  last_check = Sys.time(),
  errors = list()
)

# Enhanced error logging function
log_error <- function(component, error_message, severity = "ERROR") {
  timestamp <- Sys.time()
  error_entry <- list(
    timestamp = timestamp,
    component = component,
    message = error_message,
    severity = severity,
    user_friendly = translate_error(error_message)
  )
  
  .error_log[[length(.error_log) + 1]] <<- error_entry
  .system_health$errors[[component]] <<- error_entry
  .system_health$last_check <<- timestamp
  
  # Print to console for immediate feedback
  cat(sprintf("[%s] %s - %s: %s\n", 
              format(timestamp, "%H:%M:%S"), 
              severity, 
              component, 
              error_message))
}

# Translate technical errors to user-friendly messages
translate_error <- function(error_message) {
  error_msg <- tolower(error_message)
  
  if (grepl("connection|connect", error_msg)) {
    return("Database connection issue - Railway service may be restarting")
  } else if (grepl("timeout", error_msg)) {
    return("Request timeout - Database query took too long")
  } else if (grepl("column.*does not exist", error_msg)) {
    return("Database schema mismatch - Column names have changed")
  } else if (grepl("package|library", error_msg)) {
    return("Missing R package - Installation needed")
  } else if (grepl("memory|allocation", error_msg)) {
    return("Memory limit reached - Railway resource constraints")
  } else if (grepl("network|host", error_msg)) {
    return("Network connectivity issue - Check Railway network")
  } else {
    return("Technical error - Check logs for details")
  }
}

# System health checker
check_system_health <- function() {
  health_report <- list(
    timestamp = Sys.time(),
    overall_status = "checking"
  )
  
  # Check database connection
  tryCatch({
    if (exists(".railway_db_conn") && !is.null(.railway_db_conn)) {
      test_query <- dbGetQuery(.railway_db_conn, "SELECT 1 as test_connection")
      if (nrow(test_query) > 0) {
        health_report$database <- "✅ Connected"
        .system_health$database <<- TRUE
      } else {
        health_report$database <- "❌ Query Failed"
        .system_health$database <<- FALSE
      }
    } else {
      health_report$database <- "❌ Not Connected"
      .system_health$database <<- FALSE
    }
  }, error = function(e) {
    health_report$database <- paste("❌", translate_error(e$message))
    .system_health$database <<- FALSE
    log_error("Database", e$message)
  })
  
  # Check analytics functions
  analytics_status <- c()
  
  # Test text mining
  tryCatch({
    test_result <- get_text_mining_metrics()
    if (!is.null(test_result) && length(test_result) > 0) {
      analytics_status <- c(analytics_status, "Text Mining: ✅")
    } else {
      analytics_status <- c(analytics_status, "Text Mining: ⚠️")
    }
  }, error = function(e) {
    analytics_status <- c(analytics_status, "Text Mining: ❌")
    log_error("Text Mining", e$message, "WARNING")
  })
  
  # Test ML analytics
  tryCatch({
    test_result <- get_ml_analytics_metrics()
    if (!is.null(test_result) && length(test_result) > 0) {
      analytics_status <- c(analytics_status, "ML Analytics: ✅")
    } else {
      analytics_status <- c(analytics_status, "ML Analytics: ⚠️")
    }
  }, error = function(e) {
    analytics_status <- c(analytics_status, "ML Analytics: ❌")
    log_error("ML Analytics", e$message, "WARNING")
  })
  
  # Test geospatial
  tryCatch({
    test_result <- get_geospatial_stats()
    if (!is.null(test_result) && length(test_result) > 0) {
      analytics_status <- c(analytics_status, "Geospatial: ✅")
    } else {
      analytics_status <- c(analytics_status, "Geospatial: ⚠️")
    }
  }, error = function(e) {
    analytics_status <- c(analytics_status, "Geospatial: ❌")
    log_error("Geospatial", e$message, "WARNING")
  })
  
  # Test temporal
  tryCatch({
    test_result <- get_temporal_metrics()
    if (!is.null(test_result) && length(test_result) > 0) {
      analytics_status <- c(analytics_status, "Temporal: ✅")
    } else {
      analytics_status <- c(analytics_status, "Temporal: ⚠️")
    }
  }, error = function(e) {
    analytics_status <- c(analytics_status, "Temporal: ❌")
    log_error("Temporal", e$message, "WARNING")
  })
  
  health_report$analytics <- analytics_status
  
  # Determine overall status
  if (.system_health$database && length(analytics_status) > 0) {
    if (all(grepl("✅", analytics_status))) {
      health_report$overall_status <- "✅ All Systems Operational"
    } else if (any(grepl("✅", analytics_status))) {
      health_report$overall_status <- "⚠️ Partial System Operation"
    } else {
      health_report$overall_status <- "❌ System Issues Detected"
    }
  } else {
    health_report$overall_status <- "❌ Critical System Failure"
  }
  
  .system_health$last_check <<- Sys.time()
  return(health_report)
}

# Get formatted error report
get_error_report <- function() {
  if (length(.error_log) == 0) {
    return("No errors recorded.")
  }
  
  report <- "=== ERROR REPORT ===\n"
  
  # Recent errors (last 10)
  recent_errors <- tail(.error_log, 10)
  
  for (i in seq_along(recent_errors)) {
    error <- recent_errors[[i]]
    report <- paste0(report, 
                    sprintf("[%s] %s - %s\n%s\n\n",
                           format(error$timestamp, "%Y-%m-%d %H:%M:%S"),
                           error$severity,
                           error$component,
                           error$user_friendly))
  }
  
  return(report)
}

# Enhanced safe function wrapper
safe_execute <- function(func, component_name, fallback_value = NULL, ...) {
  tryCatch({
    result <- func(...)
    return(result)
  }, error = function(e) {
    log_error(component_name, e$message)
    cat(sprintf("⚠️ %s failed, using fallback\n", component_name))
    return(fallback_value)
  })
}

# Railway-specific diagnostics
railway_diagnostics <- function() {
  cat("\n🚂 RAILWAY DEPLOYMENT DIAGNOSTICS\n")
  cat(paste(rep("=", 50), collapse = ""), "\n")
  
  # Check environment variables
  env_vars <- c("PORT", "DATABASE_URL", "RAILWAY_STATIC_URL", "RAILWAY_GIT_COMMIT_SHA")
  
  cat("🔧 Environment Variables:\n")
  for (var in env_vars) {
    value <- Sys.getenv(var, "NOT_SET")
    if (value == "NOT_SET") {
      cat(sprintf("   ❌ %s: Not set\n", var))
    } else {
      # Hide sensitive info
      if (grepl("PASSWORD|SECRET|KEY", var)) {
        cat(sprintf("   ✅ %s: ***HIDDEN***\n", var))
      } else if (nchar(value) > 50) {
        cat(sprintf("   ✅ %s: %s...\n", var, substr(value, 1, 30)))
      } else {
        cat(sprintf("   ✅ %s: %s\n", var, value))
      }
    }
  }
  
  # Check R packages
  cat("\n📦 Critical R Packages:\n")
  critical_packages <- c("shiny", "shinydashboard", "DBI", "RPostgres", "dplyr", "ggplot2", "leaflet")
  
  for (pkg in critical_packages) {
    if (requireNamespace(pkg, quietly = TRUE)) {
      version <- tryCatch({
        as.character(packageVersion(pkg))
      }, error = function(e) "unknown")
      cat(sprintf("   ✅ %s: %s\n", pkg, version))
    } else {
      cat(sprintf("   ❌ %s: Not available\n", pkg))
    }
  }
  
  # Check memory usage
  cat("\n💾 Memory Usage:\n")
  tryCatch({
    mem_info <- system("free -h", intern = TRUE)
    cat("   System Memory Info:\n")
    for (line in mem_info) {
      cat(sprintf("   %s\n", line))
    }
  }, error = function(e) {
    cat("   ⚠️ Memory info not available\n")
  })
  
  # Check disk usage
  cat("\n💿 Disk Usage:\n")
  tryCatch({
    disk_info <- system("df -h .", intern = TRUE)
    cat("   Current Directory Disk Usage:\n")
    for (line in disk_info) {
      cat(sprintf("   %s\n", line))
    }
  }, error = function(e) {
    cat("   ⚠️ Disk info not available\n")
  })
  
  cat("\n", paste(rep("=", 50), collapse = ""), "\n")
}

# Startup diagnostic
startup_diagnostic <- function() {
  cat("\n🚀 RAILWAY STARTUP DIAGNOSTIC\n")
  cat(paste(rep("=", 40), collapse = ""), "\n")
  
  # Log startup time
  startup_time <- Sys.time()
  cat("⏰ Startup Time:", format(startup_time, "%Y-%m-%d %H:%M:%S %Z"), "\n")
  
  # Check system health
  health <- check_system_health()
  cat("🏥 System Health:", health$overall_status, "\n")
  
  # Database status
  cat("🗄️ Database:", health$database, "\n")
  
  # Analytics status
  cat("📊 Analytics Systems:\n")
  for (status in health$analytics) {
    cat("   ", status, "\n")
  }
  
  # Error summary
  if (length(.error_log) > 0) {
    cat("⚠️ Errors detected during startup:", length(.error_log), "\n")
  } else {
    cat("✅ No errors detected during startup\n")
  }
  
  cat(paste(rep("=", 40), collapse = ""), "\n")
  
  return(health)
}

# Global error handler for uncaught errors
options(error = function() {
  error_msg <- geterrmessage()
  log_error("System", error_msg, "CRITICAL")
  cat("💥 CRITICAL ERROR DETECTED!\n")
  cat("Error:", error_msg, "\n")
  cat("Check error log for details.\n")
})

# Create system status function for dashboard
get_system_status_detailed <- function() {
  health <- check_system_health()
  
  status_text <- paste(
    "=== RAILWAY SYSTEM STATUS ===\n",
    sprintf("Last Check: %s", format(health$timestamp, "%Y-%m-%d %H:%M:%S")),
    sprintf("Overall Status: %s", health$overall_status),
    sprintf("Database: %s", health$database),
    "",
    "=== ANALYTICS SYSTEMS ===",
    paste(health$analytics, collapse = "\n"),
    "",
    "=== RECENT ERRORS ===",
    if (length(.error_log) > 0) {
      paste("Last", min(3, length(.error_log)), "errors recorded")
    } else {
      "No recent errors"
    },
    "",
    "=== RAILWAY ENVIRONMENT ===",
    sprintf("Port: %s", Sys.getenv("PORT", "3838")),
    sprintf("Git Commit: %s", substr(Sys.getenv("RAILWAY_GIT_COMMIT_SHA", "unknown"), 1, 8)),
    sprintf("Deploy Time: %s", format(Sys.time(), "%H:%M UTC")),
    "",
    if (.system_health$database) {
      "✅ Ready for production traffic"
    } else {
      "⚠️ Database connectivity issues detected"
    },
    sep = "\n"
  )
  
  return(status_text)
}

cat("✅ Railway Error Handler loaded successfully\n")
cat("🛡️ Enhanced error tracking and diagnostics active\n")

# Run startup diagnostic
startup_diagnostic()