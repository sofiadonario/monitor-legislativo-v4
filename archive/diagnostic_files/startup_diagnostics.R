# RAILWAY STARTUP DIAGNOSTICS - ENHANCED
# =======================================
# Enhanced startup diagnostic check for Railway deployment

cat("\n🚀 RAILWAY STARTUP DIAGNOSTICS - ENHANCED\n")
cat(paste(rep("=", 50), collapse = ""), "\n")

# Run comprehensive environment diagnostics first
tryCatch({
  source("railway_env_diagnostics.R")
}, error = function(e) {
  cat("⚠️ Could not run environment diagnostics:", e$message, "\n")
})

# Check environment
cat("\n📍 ENVIRONMENT CHECK:\n")
cat("PORT:", Sys.getenv("PORT", "Not set"), "\n")
cat("RAILWAY_ENVIRONMENT:", Sys.getenv("RAILWAY_ENVIRONMENT", "Not set"), "\n")
cat("DATABASE_URL:", ifelse(Sys.getenv("DATABASE_URL") != "", "Set", "Not set"), "\n")

# Check Railway-specific database environment variables
railway_vars <- c("PGDATABASE", "PGHOST", "PGPASSWORD", "PGPORT", "PGUSER", "DATABASE_URL")
cat("\n🔧 RAILWAY DATABASE VARIABLES:\n")
for (var in railway_vars) {
  val <- Sys.getenv(var)
  if (val != "") {
    if (var %in% c("PGPASSWORD", "DATABASE_URL")) {
      cat(var, ": ***REDACTED***\n")
    } else {
      cat(var, ":", val, "\n")
    }
  }
}

# Parse DATABASE_URL if available
db_url <- Sys.getenv("DATABASE_URL")
if (db_url != "") {
  cat("\n📊 PARSING DATABASE_URL...\n")
  # Extract components from postgres://user:pass@host:port/dbname format
  if (grepl("^postgres://", db_url)) {
    cat("✅ Found PostgreSQL URL\n")
  }
}

# Test database connection with multiple approaches
cat("\n🔌 TESTING DATABASE CONNECTIONS:\n")

# Method 1: Direct connection with hardcoded values
cat("\nMethod 1: Hardcoded credentials...\n")
tryCatch({
  library(DBI)
  library(RPostgres)
  
  con1 <- dbConnect(
    RPostgres::Postgres(),
    host = "nozomi.proxy.rlwy.net",
    port = 44844,
    dbname = "railway",
    user = "postgres",
    password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
  )
  
  count <- dbGetQuery(con1, "SELECT COUNT(*) FROM documents")$count[1]
  cat("✅ SUCCESS! Documents found:", format(count, big.mark = ","), "\n")
  dbDisconnect(con1)
  
}, error = function(e) {
  cat("❌ FAILED:", e$message, "\n")
})

# Method 2: Using Railway environment variables
if (Sys.getenv("PGHOST") != "") {
  cat("\nMethod 2: Railway environment variables...\n")
  tryCatch({
    con2 <- dbConnect(
      RPostgres::Postgres(),
      host = Sys.getenv("PGHOST"),
      port = as.integer(Sys.getenv("PGPORT", "5432")),
      dbname = Sys.getenv("PGDATABASE"),
      user = Sys.getenv("PGUSER"),
      password = Sys.getenv("PGPASSWORD")
    )
    
    count <- dbGetQuery(con2, "SELECT COUNT(*) FROM documents")$count[1]
    cat("✅ SUCCESS! Documents found:", format(count, big.mark = ","), "\n")
    dbDisconnect(con2)
    
  }, error = function(e) {
    cat("❌ FAILED:", e$message, "\n")
  })
}

# Method 3: Using DATABASE_URL
if (db_url != "") {
  cat("\nMethod 3: DATABASE_URL connection string...\n")
  tryCatch({
    con3 <- dbConnect(RPostgres::Postgres(), dbname = db_url)
    
    count <- dbGetQuery(con3, "SELECT COUNT(*) FROM documents")$count[1]
    cat("✅ SUCCESS! Documents found:", format(count, big.mark = ","), "\n")
    dbDisconnect(con3)
    
  }, error = function(e) {
    cat("❌ FAILED:", e$message, "\n")
  })
}

cat("\n\n")
cat(paste(rep("=", 50), collapse = ""), "\n")
cat("🏁 DIAGNOSTICS COMPLETE\n\n")

# Write results to a file for later inspection
results <- list(
  timestamp = Sys.time(),
  environment = as.list(Sys.getenv()),
  database_test = "Complete"
)

tryCatch({
  saveRDS(results, "startup_diagnostics_results.rds")
  cat("📝 Results saved to startup_diagnostics_results.rds\n")
}, error = function(e) {
  cat("⚠️ Could not save results:", e$message, "\n")
})