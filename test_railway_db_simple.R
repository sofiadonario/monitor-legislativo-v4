# SIMPLE RAILWAY DATABASE CONNECTION TEST
# =======================================

cat("🧪 Simple Railway DB Test\n")

# Load required packages
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
})

# Test Railway environment variables
cat("📋 Environment Variables:\n")
vars <- c("DATABASE_URL", "PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD")
for (v in vars) {
  val <- Sys.getenv(v, "")
  if (nchar(val) > 0) {
    if (v %in% c("PGPASSWORD", "DATABASE_URL")) {
      cat("  ✅", v, ": [SET]\n")
    } else {
      cat("  ✅", v, ":", val, "\n") 
    }
  } else {
    cat("  ❌", v, ": [MISSING]\n")
  }
}

# Test connection
tryCatch({
  cat("🔌 Testing connection...\n")
  
  # Use DATABASE_URL if available
  database_url <- Sys.getenv("DATABASE_URL", "")
  if (nchar(database_url) > 0) {
    cat("📡 Using DATABASE_URL\n")
    conn <- dbConnect(RPostgres::Postgres(), database_url)
  } else {
    cat("📡 Using individual variables\n")
    conn <- dbConnect(
      RPostgres::Postgres(),
      host = Sys.getenv("PGHOST"),
      port = as.integer(Sys.getenv("PGPORT")),
      dbname = Sys.getenv("PGDATABASE"),
      user = Sys.getenv("PGUSER"),
      password = Sys.getenv("PGPASSWORD")
    )
  }
  
  result <- dbGetQuery(conn, "SELECT 1 as test")
  cat("✅ CONNECTION SUCCESS!\n")
  
  # Check for tables
  tables <- dbGetQuery(conn, "SELECT count(*) as table_count FROM information_schema.tables WHERE table_schema = 'public'")
  cat("📊 Tables in database:", tables$table_count[1], "\n")
  
  dbDisconnect(conn)
  
}, error = function(e) {
  cat("❌ CONNECTION FAILED:", e$message, "\n")
  
  if (grepl("socket", e$message)) {
    cat("🚨 SOCKET ERROR - Environment variables not working!\n")
  }
})

cat("✅ Test complete\n")