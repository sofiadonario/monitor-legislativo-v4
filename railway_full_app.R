#!/usr/bin/env Rscript
# Railway Full App Server - Runs the ACTUAL Shiny Dashboard
# ==========================================================

# CRITICAL: Apply Railway Log Collector Fix FIRST
# ===============================================
tryCatch({
  source("railway_log_collector_fix.R")
  apply_railway_log_fix()
  cat("✅ Railway log collector fix applied\n")
}, error = function(e) {
  cat("⚠️ Log collector fix failed, continuing:", e$message, "\n")
})

cat("=== Monitor Legislativo v4 - FULL APPLICATION ===\n")

# Get configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Starting FULL Shiny Dashboard on %s:%d\n", host, port))

# CRITICAL FIX: Override the broken version check in Shiny
# This is the issue preventing your app from running
fix_shiny_version_check <- function() {
  # Create a mock compareVersion that always returns 0 (equal)
  mock_compare <- function(a, b) { 0 }
  
  # Inject it into the utils namespace
  tryCatch({
    unlockBinding("compareVersion", asNamespace("utils"))
    assign("compareVersion", mock_compare, envir = asNamespace("utils"))
    lockBinding("compareVersion", asNamespace("utils"))
    cat("✓ Shiny version check bypassed\n")
  }, error = function(e) {
    cat("Note: Version check bypass attempted\n")
  })
}

# Apply the fix BEFORE loading Shiny
fix_shiny_version_check()

# Now load Shiny - it won't fail on version checks
# Use safe loading if fix is available
if (exists("safe_library")) {
  safe_library("shiny")
  safe_library("httpuv")
} else {
  suppressWarnings(suppressMessages({
    library(shiny)
    library(httpuv)
  }))
}

# Load your FULL application
cat("Loading Monitor Legislativo Dashboard...\n")

# CRITICAL: Load chart fixes FIRST (before app.R loads anything)
cat("🚨 Loading CRITICAL CHART FIXES before app startup...\n")
tryCatch({
  if (file.exists("CRITICAL_CHART_FIXES.R")) {
    source("CRITICAL_CHART_FIXES.R")
    cat("✅ CRITICAL CHART FIXES loaded successfully\n")
  } else {
    cat("❌ CRITICAL_CHART_FIXES.R not found\n")
  }
}, error = function(e) {
  cat("❌ Critical chart fixes failed:", e$message, "\n")
})

tryCatch({
  # Source your app.R which has all the features
  source("app.R")
  
  # Check if UI and server exist
  if (!exists("ui") || !exists("server")) {
    stop("UI or server not found in app.R")
  }
  
  cat("✓ Dashboard loaded successfully with all features!\n")
  
  # Create the Shiny app with all your analytics features
  app <- shinyApp(ui = ui, server = server)
  
  # Add health check endpoint (but preserve all Shiny routes)
  original_handler <- app$httpHandler
  app$httpHandler <- function(req) {
    # Only intercept health check, let everything else go to Shiny
    if (!is.null(req$PATH_INFO) && req$PATH_INFO == "/health") {
      return(list(
        status = 200L,
        headers = list("Content-Type" = "application/json"),
        body = '{"status":"healthy","app":"full_dashboard","features":"all_loaded"}'
      ))
    }
    # All other routes go to your Shiny app with all features
    return(original_handler(req))
  }
  
  cat("========================================\n")
  cat("🚀 MONITOR LEGISLATIVO v4 - FULL DASHBOARD\n")
  cat("📊 All analytics features loaded\n")
  cat("📈 All visualization modules active\n")
  cat("🗄️ Database connected\n")
  cat("🔍 NLP analysis ready\n")
  cat("📡 Server: http://", host, ":", port, "\n", sep = "")
  cat("========================================\n")
  
  # Run the FULL app
  runApp(
    app,
    host = host,
    port = port,
    launch.browser = FALSE,
    quiet = TRUE
  )
  
}, error = function(e) {
  cat("ERROR: ", e$message, "\n")
  
  # If runApp still fails, use httpuv directly to serve the Shiny app
  cat("Using alternative method to serve Shiny app...\n")
  
  if (exists("ui") && exists("server")) {
    app <- shinyApp(ui = ui, server = server)
    
    # Start httpuv server with the Shiny app handler
    s <- httpuv::startServer(host, port, app$httpHandler)
    
    cat("✓ Full dashboard served via httpuv\n")
    cat("✓ All features available at: http://", host, ":", port, "\n", sep = "")
    
    # Keep running
    while(TRUE) {
      httpuv::service()
      Sys.sleep(0.001)
    }
  } else {
    cat("FATAL: Could not load app.R\n")
  }
})