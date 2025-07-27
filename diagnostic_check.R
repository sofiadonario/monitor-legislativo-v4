# Diagnostic script to check Railway deployment environment

cat("=== RAILWAY DEPLOYMENT DIAGNOSTIC ===\n")
cat("Current working directory:", getwd(), "\n")
cat("R version:", R.version.string, "\n")
cat("\n")

# List all files in current directory
cat("Files in current directory:\n")
files <- list.files(".", all.files = TRUE, recursive = FALSE)
for (f in files) {
  info <- file.info(f)
  cat(sprintf("  %s (size: %d bytes)\n", f, info$size))
}
cat("\n")

# Check for database.R specifically
if (file.exists("database.R")) {
  cat("✓ database.R EXISTS\n")
  cat("  File size:", file.info("database.R")$size, "bytes\n")
  cat("  Can read:", file.access("database.R", 4) == 0, "\n")
} else {
  cat("✗ database.R NOT FOUND\n")
}
cat("\n")

# Check for app.R
if (file.exists("app.R")) {
  cat("✓ app.R EXISTS\n")
  cat("  File size:", file.info("app.R")$size, "bytes\n")
} else {
  cat("✗ app.R NOT FOUND\n")
}
cat("\n")

# Environment variables
cat("Environment variables:\n")
cat("  PORT:", Sys.getenv("PORT", "not set"), "\n")
cat("  R_CONFIG_ACTIVE:", Sys.getenv("R_CONFIG_ACTIVE", "not set"), "\n")
cat("  DATABASE_URL:", if(nchar(Sys.getenv("DATABASE_URL")) > 0) "***SET***" else "not set", "\n")
cat("\n")

# Try to source database.R
cat("Attempting to source database.R...\n")
tryCatch({
  source("database.R")
  cat("✓ Successfully sourced database.R\n")
}, error = function(e) {
  cat("✗ Error sourcing database.R:\n")
  cat("  ", e$message, "\n")
})

cat("\n=== END DIAGNOSTIC ===\n") 