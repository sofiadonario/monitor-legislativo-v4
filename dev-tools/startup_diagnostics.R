# Startup Diagnostics for Railway Deployment
# This file helps diagnose hanging issues

cat("\n=== STARTUP DIAGNOSTICS ===\n")
cat("Timestamp:", as.character(Sys.time()), "\n")
cat("Working Directory:", getwd(), "\n")
cat("R Version:", R.version.string, "\n")

# Environment variables
cat("\nEnvironment Variables:\n")
cat("  PORT:", Sys.getenv("PORT", "not set"), "\n")
cat("  DATABASE_URL present:", nchar(Sys.getenv("DATABASE_URL")) > 0, "\n")
cat("  ENABLE_DATABASE:", Sys.getenv("ENABLE_DATABASE", "not set"), "\n")
cat("  R_CONFIG_ACTIVE:", Sys.getenv("R_CONFIG_ACTIVE", "not set"), "\n")

# Check required directories
cat("\nDirectory Check:\n")
  dirs_to_check <- c("R", "data_current/cache", "www", "logs")
for (dir in dirs_to_check) {
  cat("  ", dir, ":", ifelse(dir.exists(dir), "✓ exists", "✗ missing"), "\n")
}

# Check required files
cat("\nFile Check:\n")
files_to_check <- c("app.R", "config.yml", "R/database_connection.R", "R/cache_utils.R")
for (file in files_to_check) {
  cat("  ", file, ":", ifelse(file.exists(file), "✓ exists", "✗ missing"), "\n")
}

# Network check
cat("\nNetwork Check:\n")
tryCatch({
  con <- url("https://www.google.com", "r", timeout = 5)
  close(con)
  cat("  Internet connectivity: ✓ OK\n")
}, error = function(e) {
  cat("  Internet connectivity: ✗ Failed -", e$message, "\n")
})

# Memory check
cat("\nMemory Info:\n")
cat("  Memory limit:", memory.limit(), "MB\n")
cat("  Memory used:", round(memory.size(), 2), "MB\n")

cat("\n=== END DIAGNOSTICS ===\n\n")

# Add a startup delay to ensure everything is ready
cat("Waiting 2 seconds before starting app...\n")
Sys.sleep(2)