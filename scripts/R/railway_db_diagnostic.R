#!/usr/bin/env Rscript

# Railway Database Connection Diagnostic Script
# This script helps diagnose why the database connection is failing

cat("=== RAILWAY DATABASE CONNECTION DIAGNOSTIC ===\n")
cat("Timestamp:", as.character(Sys.time()), "\n\n")

# 1. Check environment variables
cat("1. ENVIRONMENT VARIABLES CHECK:\n")
cat("DATABASE_URL present:", Sys.getenv("DATABASE_URL") != "", "\n")
cat("DATABASE_URL length:", nchar(Sys.getenv("DATABASE_URL")), "chars\n")
cat("R_CONFIG_ACTIVE:", Sys.getenv("R_CONFIG_ACTIVE", "not set"), "\n")
cat("RAILWAY_ENVIRONMENT:", Sys.getenv("RAILWAY_ENVIRONMENT", "not set"), "\n")
cat("PORT:", Sys.getenv("PORT", "not set"), "\n\n")

# 2. Test DATABASE_URL parsing
cat("2. DATABASE_URL PARSING TEST:\n")
database_url <- Sys.getenv("DATABASE_URL", "")
if (database_url != "") {
  # Mask password for security
  masked_url <- gsub("(postgresql://[^:]+:)([^@]+)(@.*)", "\\1[MASKED]\\3", database_url)
  cat("Masked URL:", masked_url, "\n")
  
  # Parse URL
  url_pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)"
  parsed <- regmatches(database_url, regexec(url_pattern, database_url))[[1]]
  
  if (length(parsed) == 6) {
    cat("✅ URL parsed successfully\n")
    cat("  User:", parsed[2], "\n")
    cat("  Host:", parsed[4], "\n")
    cat("  Port:", parsed[5], "\n")
    cat("  Database:", parsed[6], "\n")
  } else {
    cat("❌ Failed to parse DATABASE_URL\n")
    cat("  Expected format: postgresql://user:password@host:port/dbname\n")
  }
} else {
  cat("❌ No DATABASE_URL found\n")
}
cat("\n")

# 3. Test direct PostgreSQL connection
cat("3. POSTGRESQL CONNECTION TEST:\n")
if (database_url != "") {
  suppressPackageStartupMessages({
    library(DBI)
    library(RPostgres)
  })
  
  tryCatch({
    cat("Attempting to connect to PostgreSQL...\n")
    con <- dbConnect(RPostgres::Postgres(), database_url)
    cat("✅ Connection successful!\n")
    
    # Get PostgreSQL version
    version <- dbGetQuery(con, "SELECT version()")
    cat("PostgreSQL version:", substr(version$version[1], 1, 50), "...\n")
    
    # List tables
    tables <- dbListTables(con)
    cat("\nAvailable tables (", length(tables), "):\n")
    for (table in tables) {
      cat("  -", table)
      # Get row count for each table
      tryCatch({
        count <- dbGetQuery(con, paste("SELECT COUNT(*) as count FROM", table))$count[1]
        cat(" (", count, "rows)\n")
      }, error = function(e) {
        cat(" (error counting rows)\n")
      })
    }
    
    # Check for main data tables
    cat("\nChecking main data tables:\n")
    main_tables <- c("lexml_documents", "documents", "lexml_parsed_enhanced_fixed")
    for (table in main_tables) {
      if (table %in% tables) {
        cat("  ✅", table, "exists\n")
        # Get sample data
        tryCatch({
          sample <- dbGetQuery(con, paste("SELECT * FROM", table, "LIMIT 1"))
          cat("    Columns:", paste(names(sample), collapse = ", "), "\n")
        }, error = function(e) {
          cat("    Error reading sample:", e$message, "\n")
        })
      } else {
        cat("  ❌", table, "not found\n")
      }
    }
    
    dbDisconnect(con)
    
  }, error = function(e) {
    cat("❌ Connection failed!\n")
    cat("Error:", e$message, "\n")
    cat("\nPossible causes:\n")
    cat("  1. DATABASE_URL is incorrect\n")
    cat("  2. Database is not accessible from Railway\n")
    cat("  3. Network/firewall issues\n")
    cat("  4. Database service is down\n")
  })
} else {
  cat("❌ Cannot test connection without DATABASE_URL\n")
}
cat("\n")

# 4. Test connection pool creation
cat("4. CONNECTION POOL TEST:\n")
if (database_url != "") {
  suppressPackageStartupMessages(library(pool))
  
  tryCatch({
    cat("Creating connection pool...\n")
    
    # Parse URL for pool creation
    parsed <- regmatches(database_url, regexec("postgresql://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)", database_url))[[1]]
    
    if (length(parsed) == 6) {
      db_pool <- dbPool(
        drv = RPostgres::Postgres(),
        host = parsed[4],
        port = as.numeric(parsed[5]),
        dbname = parsed[6],
        user = parsed[2],
        password = parsed[3],
        minSize = 1,
        maxSize = 3
      )
      
      cat("✅ Pool created successfully\n")
      
      # Test pool query
      result <- dbGetQuery(db_pool, "SELECT 1 as test")
      cat("✅ Pool query successful\n")
      
      poolClose(db_pool)
      cat("✅ Pool closed cleanly\n")
      
    } else {
      cat("❌ Failed to parse DATABASE_URL for pool creation\n")
    }
    
  }, error = function(e) {
    cat("❌ Pool creation failed!\n")
    cat("Error:", e$message, "\n")
  })
}
cat("\n")

# 5. Check data access layer
cat("5. DATA ACCESS LAYER CHECK:\n")
files_to_check <- c(
  "database_pool_manager.R",
  "data_access_layer.R",
  "database.R",
  "data_loader_robust.R"
)

for (file in files_to_check) {
  if (file.exists(file)) {
    cat("  ✅", file, "exists\n")
  } else {
    cat("  ❌", file, "missing\n")
  }
}
cat("\n")

# 6. Recommendations
cat("6. RECOMMENDATIONS:\n")
if (database_url == "") {
  cat("❌ DATABASE_URL is not set in Railway environment variables\n")
  cat("   Action: Add DATABASE_URL to Railway service variables\n")
} else if (length(parsed) != 6) {
  cat("❌ DATABASE_URL format is incorrect\n")
  cat("   Action: Verify DATABASE_URL follows postgresql://user:password@host:port/dbname format\n")
} else {
  cat("✅ DATABASE_URL is properly configured\n")
  cat("   If connection still fails, check:\n")
  cat("   - Database service is running in Railway\n")
  cat("   - Network connectivity between services\n")
  cat("   - Database credentials are correct\n")
}

cat("\n=== END DIAGNOSTIC ===\n")