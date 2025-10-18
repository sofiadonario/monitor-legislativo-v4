# ==============================================================================
# MONITOR LEGISLATIVO V4 - INTEGRATED APP
# ==============================================================================
# Combines your existing app.R with optimization patterns
# Uses your modules + data service + optimized architecture
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

cat("========================================\n")
cat("🚀 MONITOR LEGISLATIVO V4\n")
cat("   Integrated Architecture\n")
cat("========================================\n\n")

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
