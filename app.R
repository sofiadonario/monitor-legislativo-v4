# ==============================================================================
# MONITOR LEGISLATIVO V4 - INTEGRATED APP
# ==============================================================================
# v61: Migrated to bslib framework (fixes extent=0 error definitively)
# Uses your modules + data service + optimized architecture
# ==============================================================================

# Note: shinydashboard fully removed in v61 (migrated to bslib)
# bslib provides modern Bootstrap 5 UI without extent=0 compatibility issues
options(
  shiny.fullstacktrace = TRUE,
  shiny.trace = TRUE,
  error = quote({
    cat("\n========================================\n")
    cat("🚨 ERROR IN R SESSION:\n")
    print(geterrmessage())
    cat("Traceback:\n")
    traceback(max.lines = 50)
    cat("========================================\n")
  })
)

# Health check endpoint (Railway requirement)
if (is.null(getOption("shiny.http.response.filter"))) {
  options(shiny.http.response.filter = function(req, res) {
    if (identical(req$PATH_INFO, "/health")) {
      res$status <- 200L
      res$headers[["Content-Type"]] <- "text/plain"
      res$body <- charToRaw("ok")
      return(res)
    }
    NULL
  })
}

# Bind to environment-specified port (e.g., from Cloud Run)
options(
  shiny.host = "0.0.0.0",
  shiny.port = as.integer(Sys.getenv("PORT", "3838"))
)

cat("========================================\n")
cat("🚀 MONITOR LEGISLATIVO V4\n")
cat("   Integrated Architecture\n")
cat("========================================\n\n")

# CRITICAL: Verify required packages are available at runtime
cat("🔍 Verifying package availability...\n")
required_pkgs <- c('shiny', 'bslib', 'DT', 'leaflet', 'DBI', 'RPostgres', 'dplyr')
missing_pkgs <- setdiff(required_pkgs, rownames(installed.packages()))

if (length(missing_pkgs) > 0) {
  cat("❌ FATAL ERROR: Missing required packages at runtime:\n")
  cat("   ", paste(missing_pkgs, collapse=", "), "\n\n")
  cat("Likely causes:\n")
  cat("  1. renv activated (.Rprofile) but packages not in renv.lock\n")
  cat("  2. Wrong Dockerfile built (check Railway uses main Dockerfile)\n")
  cat("  3. Package installation failed during build\n\n")
  cat("Solution: Set ENV RENV_CONFIG_ACTIVATE_ON_LOAD=FALSE in Dockerfile\n\n")
  stop("Missing packages: ", paste(missing_pkgs, collapse=", "))
}
cat("✅ All required packages available\n\n")

# Load optimized global setup (DB pool, cached functions, preloaded data)
# FIX v56: SKIP sourcing global_integrated.R + use FULL ui.R/server.R from git
# Define minimal variables needed by app
# DB_AVAILABLE <- FALSE # REMOVED - This is now set dynamically after connection attempt
cat("⚠️  SKIPPING global_integrated.R (v56 - with full UI/server)\n")
# tryCatch({
#   source("global_integrated.R", local = TRUE)
#   cat("✅ Global configuration loaded\n")
# }, error = function(e) {
#   cat("❌ FATAL: global_integrated.R failed:", conditionMessage(e), "\n")
#   stop(e)
# })
tryCatch({
  source("db/connection.R", local = TRUE)
  status <- get_connection_status()
  DB_AVAILABLE <<- status$status == "connected" # Set global DB_AVAILABLE status
  cat("✅ Global configuration loaded. DB Available:", DB_AVAILABLE, "\n")
}, error = function(e) {
  cat("❌ FATAL: db/connection.R failed:", conditionMessage(e), "\n")
  DB_AVAILABLE <<- FALSE
  stop(e)
})

# Load your existing UI (keep your comprehensive UI as-is)
tryCatch({
  source("ui.R", local = TRUE)
  cat("✅ UI loaded\n")
}, error = function(e) {
  cat("❌ FATAL: ui.R failed:", conditionMessage(e), "\n")
  stop(e)
})

# Load your existing server (with all your modules)
tryCatch({
  source("server.R", local = TRUE)
  cat("✅ Server loaded\n")
}, error = function(e) {
  cat("❌ FATAL: server.R failed:", conditionMessage(e), "\n")
  stop(e)
})

# Launch
cat("\n========================================\n")
cat("✅ APPLICATION READY\n")
cat("   Port: ", getOption("shiny.port"), "\n")
cat("   Health: /health\n")
cat("   Database: ", if (isTRUE(DB_AVAILABLE)) "Connected" else "Fallback", "\n")
cat("========================================\n\n")

shinyApp(ui = ui, server = server)
