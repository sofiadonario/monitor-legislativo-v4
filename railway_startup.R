# Railway Startup Script
# ======================
# Enhanced startup script for Railway deployment with comprehensive diagnostics

cat("🚀 Railway Startup Script - Initializing...\n")
cat("⏰ Startup Time:", format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"), "\n")

# Check Railway environment
railway_env <- Sys.getenv("RAILWAY_ENVIRONMENT", "")
if (railway_env != "") {
  cat("🚂 Railway Environment:", railway_env, "\n")
} else {
  cat("⚠️ Not running in Railway environment\n")
}

# Check essential environment variables
essential_vars <- c("DATABASE_URL", "PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD")
cat("🔍 Environment Variables Check:\n")
all_vars_present <- TRUE
for (var in essential_vars) {
  value <- Sys.getenv(var, "")
  if (value != "") {
    if (var %in% c("PGPASSWORD", "DATABASE_URL")) {
      cat("  ✅", var, ": [SET - length:", nchar(value), "]\n")
    } else {
      cat("  ✅", var, ":", value, "\n")
    }
  } else {
    cat("  ❌", var, ": [NOT SET]\n")
    all_vars_present <- FALSE
  }
}

# Check system resources
cat("\n💻 System Information:\n")
cat("  Platform:", R.version$platform, "\n")
cat("  R Version:", R.version.string, "\n")
cat("  Working Directory:", getwd(), "\n")

# Check required packages
required_packages <- c("shiny", "shinydashboard", "DBI", "RPostgres", "dplyr", "DT", "plotly")
cat("\n📦 Package Check:\n")
for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat("  ✅", pkg, "\n")
  } else {
    cat("  ❌", pkg, "- MISSING\n")
  }
}

# Load Railway database connection
cat("\n🔌 Loading Railway Database Connection...\n")
tryCatch({
  source("RAILWAY_PRODUCTION_DB_FIX.R")
  cat("✅ Railway database connection loaded successfully\n")
  
  # Test connection
  status <- get_connection_status()
  cat("📊 Database Status:", status$status, "\n")
  cat("🔗 Connection Method:", status$connection_method, "\n")
  
  if (status$status == "connected") {
    cat("🎉 Database connection is ready!\n")
    doc_count <- get_total_documents()
    cat("📄 Total Documents:", format(doc_count, big.mark = ","), "\n")
  } else {
    cat("⚠️ Database connection issue detected\n")
    if (!is.null(status$error)) {
      cat("🚨 Error:", status$error, "\n")
    }
  }
  
}, error = function(e) {
  cat("❌ Failed to load Railway database connection:", e$message, "\n")
})

cat("\n🚀 Railway Startup Script - Complete!\n")
cat("Ready to start Shiny application...\n")