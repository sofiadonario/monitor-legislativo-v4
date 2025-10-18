# ==============================================================================
# MONITOR LEGISLATIVO V4 - OPTIMIZED APP
# ==============================================================================
# Production-Ready Shiny Application
# Railway Optimized | Clean Architecture
#
# KEY IMPROVEMENTS:
# - Tiny app.R (just wires UI + server)
# - Heavy logic in global.R (preloaded, shared across sessions)
# - Modules for organization
# - Async for blocking work
# - Cache for expensive operations
# - Early req() to prevent reactive storms
# ==============================================================================

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

# Load global setup (packages, DB pool, cached data)
cat("========================================\n")
cat("🚀 MONITOR LEGISLATIVO V4 - STARTING\n")
cat("========================================\n\n")

tryCatch({
  source("global_optimized.R", local = TRUE)
}, error = function(e) {
  cat("❌ FATAL: global.R failed to load:", conditionMessage(e), "\n")
  stop(e)
})

# Load UI
tryCatch({
  source("ui_optimized.R", local = TRUE)
}, error = function(e) {
  cat("❌ FATAL: ui.R failed to load:", conditionMessage(e), "\n")
  stop(e)
})

# Load server
tryCatch({
  source("server_optimized.R", local = TRUE)
}, error = function(e) {
  cat("❌ FATAL: server.R failed to load:", conditionMessage(e), "\n")
  stop(e)
})

# Launch
cat("\n========================================\n")
cat("✅ APPLICATION READY\n")
cat("   Port: ", getOption("shiny.port"), "\n")
cat("   Health: /health\n")
cat("========================================\n\n")

shinyApp(ui = ui, server = server)
