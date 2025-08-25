# Railway Database Connection Fix
# ================================

library(DBI)
library(RPostgres)
library(pool)

# Function to get Railway database connection
get_railway_connection <- function() {
  cat("\n=== Railway Database Connection Debug ===\n")
  
  # Check all possible environment variables
  cat("Checking environment variables:\n")
  cat("DATABASE_URL:", if(nchar(Sys.getenv("DATABASE_URL")) > 0) "SET" else "NOT SET", "\n")
  cat("PGHOST:", Sys.getenv("PGHOST"), "\n")
  cat("PGPORT:", Sys.getenv("PGPORT"), "\n")
  cat("PGDATABASE:", Sys.getenv("PGDATABASE"), "\n")
  cat("PGUSER:", Sys.getenv("PGUSER"), "\n")
  cat("RAILWAY_ENVIRONMENT:", Sys.getenv("RAILWAY_ENVIRONMENT"), "\n")
  
  # Railway PostgreSQL connection - USE ENVIRONMENT VARIABLES ONLY
  # SECURITY: Never use hardcoded credentials in production
  cat("⚠️ DEPRECATED: This connection method is insecure\n")
  cat("🔒 Use db/connection.R with proper environment variables instead\n")
  
  railway_config <- list(
    host = Sys.getenv("PGHOST", "postgres"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE", "railway"),
    user = Sys.getenv("PGUSER", "postgres"),
    password = Sys.getenv("PGPASSWORD", "")
  )
  
  # Try to connect using environment variables first
  db_url <- Sys.getenv("DATABASE_URL")
  
  if (nchar(db_url) > 0) {
    cat("Using DATABASE_URL from environment\n")
    tryCatch({
      con <- dbConnect(RPostgres::Postgres(), db_url)
      cat("✓ Connected via DATABASE_URL\n")
      return(con)
    }, error = function(e) {
      cat("✗ DATABASE_URL connection failed:", e$message, "\n")
    })
  }
  
  # Try individual environment variables
  if (nchar(Sys.getenv("PGHOST")) > 0) {
    cat("Using individual PG* environment variables\n")
    tryCatch({
      con <- dbConnect(
        RPostgres::Postgres(),
        host = Sys.getenv("PGHOST"),
        port = as.integer(Sys.getenv("PGPORT", "5432")),
        dbname = Sys.getenv("PGDATABASE"),
        user = Sys.getenv("PGUSER"),
        password = Sys.getenv("PGPASSWORD")
      )
      cat("✓ Connected via PG* variables\n")
      return(con)
    }, error = function(e) {
      cat("✗ PG* variables connection failed:", e$message, "\n")
    })
  }
  
  # Fallback to known Railway configuration
  cat("Using fallback Railway configuration\n")
  tryCatch({
    con <- dbConnect(
      RPostgres::Postgres(),
      host = railway_config$host,
      port = railway_config$port,
      dbname = railway_config$dbname,
      user = railway_config$user,
      password = railway_config$password,
      sslmode = "require"
    )
    cat("✓ Connected via fallback configuration\n")
    
    # Test the connection
    test <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents")
    cat("✓ Database test successful:", test$count, "documents found\n")
    
    return(con)
  }, error = function(e) {
    cat("✗ Fallback connection failed:", e$message, "\n")
    return(NULL)
  })
}

# Function to create connection pool for Railway
create_railway_pool <- function() {
  cat("Creating Railway database pool...\n")
  
  # Railway PostgreSQL configuration - DO NOT USE HARDCODED CREDENTIALS
  # This is a SECURITY RISK and should be replaced with environment variables
  cat("⚠️ WARNING: This file contains hardcoded credentials and should not be used\n")
  cat("💡 Use the secure connection module in db/connection.R instead\n")
  cat("🔒 Ensure DATABASE_URL environment variable is properly set in Railway\n")
  
  # DEPRECATED - Use environment variables instead
  railway_config <- list(
    host = Sys.getenv("PGHOST", "postgres"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE", "railway"),
    user = Sys.getenv("PGUSER", "postgres"),
    password = Sys.getenv("PGPASSWORD", "")
  )
  
  tryCatch({
    pool <- dbPool(
      RPostgres::Postgres(),
      host = railway_config$host,
      port = railway_config$port,
      dbname = railway_config$dbname,
      user = railway_config$user,
      password = railway_config$password,
      sslmode = "require",
      minSize = 1,
      maxSize = 10,
      idleTimeout = 300000
    )
    
    cat("✓ Database pool created successfully\n")
    
    # Test the pool
    test <- pool %>% tbl("documents") %>% summarise(n = n()) %>% collect()
    cat("✓ Pool test successful:", test$n, "documents accessible\n")
    
    return(pool)
  }, error = function(e) {
    cat("✗ Pool creation failed:", e$message, "\n")
    return(NULL)
  })
}

# Export functions
railway_db_connection <- get_railway_connection()
railway_db_pool <- create_railway_pool()