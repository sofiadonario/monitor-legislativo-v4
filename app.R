# ==============================================================================
# MONITOR LEGISLATIVO V4 - INTEGRATED APP
# ==============================================================================
# Combines your existing app.R with optimization patterns
# Uses your modules + data service + optimized architecture
# ==============================================================================

# Note: shinydashboard is preloaded via R/000_load_shinydashboard.R
# and will be loaded again by global_integrated.R below
options(shiny.fullstacktrace = TRUE)

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

# Bind to Railway port
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
required_pkgs <- c('shiny', 'shinydashboard', 'DT', 'leaflet', 'DBI', 'RPostgres', 'pool', 'dplyr')
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
tryCatch({
  source("global_integrated.R", local = TRUE)
  cat("✅ Global configuration loaded\n")
}, error = function(e) {
  cat("❌ FATAL: global_integrated.R failed:", conditionMessage(e), "\n")
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
cat("   Database: ", if (DB_AVAILABLE) "Connected" else "Fallback", "\n")
cat("========================================\n\n")

shinyApp(ui = ui, server = server)
