# RAILWAY DATABASE DIAGNOSTIC AND FIX
# Comprehensive diagnosis of database connection issues on Railway
# Author: Senior DevOps Engineer

cat("🚀 RAILWAY DATABASE DIAGNOSTIC STARTING...\n")
cat("📊 Timestamp:", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "\n")

# ================================
# SECTION 1: ENVIRONMENT DIAGNOSIS
# ================================

cat("\n=== ENVIRONMENT DIAGNOSIS ===\n")

# Check Railway environment variables
database_url <- Sys.getenv("DATABASE_URL", "")
cat("DATABASE_URL present:", nchar(database_url) > 0, "\n")
cat("DATABASE_URL length:", nchar(database_url), "\n")

if (nchar(database_url) > 0) {
  # Mask password for security
  url_masked <- gsub(":[^:@]+@", ":***@", database_url)
  cat("DATABASE_URL (masked):", url_masked, "\n")
  
  # Parse DATABASE_URL
  url_pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)"
  parsed <- regmatches(database_url, regexec(url_pattern, database_url))[[1]]
  
  if (length(parsed) == 6) {
    cat("✅ DATABASE_URL parsing successful\n")
    cat("  Host:", parsed[4], "\n")
    cat("  Port:", parsed[5], "\n")
    cat("  Database:", parsed[6], "\n")
    cat("  User:", parsed[2], "\n")
  } else {
    cat("❌ DATABASE_URL parsing failed\n")
  }
} else {
  cat("❌ No DATABASE_URL found in environment\n")
}

# Check required packages
cat("\n=== PACKAGE AVAILABILITY ===\n")
required_packages <- c("DBI", "RPostgres", "pool", "dplyr")
for (pkg in required_packages) {
  available <- require(pkg, character.only = TRUE, quietly = TRUE)
  cat(pkg, ":", if(available) "✅ AVAILABLE" else "❌ MISSING", "\n")
}

# ================================
# SECTION 2: EXISTING POOL DIAGNOSIS
# ================================

cat("\n=== EXISTING POOL DIAGNOSIS ===\n")

# Check for existing pool variables
pool_vars <- c(".db_pool", "db_pool", "pool", ".pool")
for (var in pool_vars) {
  if (exists(var, envir = .GlobalEnv)) {
    val <- get(var, envir = .GlobalEnv)
    cat(var, "exists:", class(val), "-", if(is.character(val)) paste0("'", val, "'") else "object", "\n")
  } else {
    cat(var, ": NOT FOUND\n")
  }
}

# ================================
# SECTION 3: CREATE REAL DATABASE CONNECTION
# ================================

cat("\n=== CREATING REAL DATABASE CONNECTION ===\n")

real_db_pool <- NULL

if (nchar(database_url) > 0) {
  tryCatch({
    # Load required libraries
    suppressPackageStartupMessages({
      library(DBI)
      library(RPostgres)
      library(pool)
    })
    
    # Parse connection details
    url_pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)"
    parsed <- regmatches(database_url, regexec(url_pattern, database_url))[[1]]
    
    if (length(parsed) == 6) {
      db_user <- parsed[2]
      db_password <- parsed[3]
      db_host <- parsed[4]
      db_port <- as.numeric(parsed[5])
      db_name <- parsed[6]
      
      cat("🔄 Creating PostgreSQL connection pool...\n")
      
      # Create connection pool
      real_db_pool <- dbPool(
        drv = RPostgres::Postgres(),
        host = db_host,
        port = db_port,
        dbname = db_name,
        user = db_user,
        password = db_password,
        minSize = 1,
        maxSize = 3,
        idleTimeout = 1800,
        validateQuery = "SELECT 1"
      )
      
      cat("✅ Connection pool created successfully\n")
      
      # Test the connection
      cat("🔍 Testing connection...\n")
      test_result <- dbGetQuery(real_db_pool, "SELECT version() as version")
      cat("✅ Connection test successful\n")
      cat("  PostgreSQL version:", substr(test_result$version[1], 1, 50), "...\n")
      
      # List tables
      tables <- dbListTables(real_db_pool)
      cat("📊 Available tables (", length(tables), "):", paste(tables[1:min(5, length(tables))], collapse = ", "), 
          if(length(tables) > 5) "..." else "", "\n")
      
      # Find main document table and count
      document_count <- 0
      main_table <- NULL
      table_candidates <- c("documents", "lexml_documents", "lexml_parsed_enhanced_fixed")
      
      for (table_name in table_candidates) {
        if (table_name %in% tables) {
          tryCatch({
            count_result <- dbGetQuery(real_db_pool, paste("SELECT COUNT(*) as count FROM", table_name))
            document_count <- count_result$count[1]
            main_table <- table_name
            cat("📊 Found main table '", table_name, "' with ", document_count, " documents\n")
            break
          }, error = function(e) {
            cat("⚠️ Error accessing table", table_name, ":", e$message, "\n")
          })
        }
      }
      
      if (!is.null(main_table) && document_count > 0) {
        cat("✅ REAL DATABASE CONNECTION SUCCESSFUL\n")
        cat("  Main table:", main_table, "\n")
        cat("  Document count:", format(document_count, big.mark = ","), "\n")
        
        # Test sample query
        sample_query <- paste("SELECT titulo, tipo, estado FROM", main_table, "LIMIT 3")
        sample_data <- dbGetQuery(real_db_pool, sample_query)
        cat("  Sample data rows:", nrow(sample_data), "\n")
        if (nrow(sample_data) > 0) {
          cat("  Sample titles:", paste(substr(sample_data$titulo[1:min(2, nrow(sample_data))], 1, 30), collapse = ", "), "\n")
        }
      }
      
    } else {
      cat("❌ Failed to parse DATABASE_URL\n")
    }
    
  }, error = function(e) {
    cat("❌ Database connection error:", e$message, "\n")
    real_db_pool <- NULL
  })
} else {
  cat("❌ Cannot create connection: no DATABASE_URL\n")
}

# ================================
# SECTION 4: FUNCTION TESTING
# ================================

cat("\n=== FUNCTION TESTING ===\n")

if (!is.null(real_db_pool)) {
  cat("🔍 Testing dashboard functions with real database...\n")
  
  # Test get_lexml_dashboard_metrics function
  if (exists("get_lexml_dashboard_metrics")) {
    cat("Testing get_lexml_dashboard_metrics...\n")
    tryCatch({
      # Set global pool variable
      .db_pool <<- real_db_pool
      
      metrics <- get_lexml_dashboard_metrics()
      cat("✅ get_lexml_dashboard_metrics result:\n")
      cat("  Total documents:", metrics$total_documents, "\n")
      cat("  States percentage:", metrics$states_percentage, "\n")
    }, error = function(e) {
      cat("❌ get_lexml_dashboard_metrics error:", e$message, "\n")
    })
  } else {
    cat("⚠️ get_lexml_dashboard_metrics function not found\n")
  }
  
  # Test get_search_analytics function
  if (exists("get_search_analytics")) {
    cat("Testing get_search_analytics...\n")
    tryCatch({
      analytics <- get_search_analytics()
      cat("✅ get_search_analytics result:\n")
      cat("  Total documents:", analytics$total_documents, "\n")
      cat("  Data source:", analytics$data_source, "\n")
    }, error = function(e) {
      cat("❌ get_search_analytics error:", e$message, "\n")
    })
  } else {
    cat("⚠️ get_search_analytics function not found\n")
  }
  
} else {
  cat("❌ Cannot test functions: no database connection\n")
}

# ================================
# SECTION 5: RECOMMENDATIONS
# ================================

cat("\n=== DIAGNOSTIC COMPLETE - RECOMMENDATIONS ===\n")

if (!is.null(real_db_pool)) {
  cat("✅ DIAGNOSIS: Database connection is working!\n")
  cat("📋 RECOMMENDATIONS:\n")
  cat("  1. Source the database_pool_manager.R file in app.R\n")
  cat("  2. Remove all fake pool override files\n")
  cat("  3. Ensure FINAL_DATABASE_OVERRIDE.R is sourced LAST\n")
  cat("  4. Set .db_pool to the real pool object, not a string\n")
  cat("  5. Remove NUCLEAR_POOL_FIX.R (it's interfering)\n")
  
  # Set the real pool globally for immediate fix
  .db_pool <<- real_db_pool
  db_pool <<- real_db_pool
  
  cat("\n🚀 IMMEDIATE FIX APPLIED:\n")
  cat("  .db_pool and db_pool set to real database pool\n")
  cat("  You should now see correct document counts!\n")
  
} else {
  cat("❌ DIAGNOSIS: Database connection failed\n")
  cat("📋 TROUBLESHOOTING STEPS:\n")
  cat("  1. Verify DATABASE_URL is set correctly in Railway\n")
  cat("  2. Check Railway PostgreSQL service is running\n")
  cat("  3. Verify network connectivity to database\n")
  cat("  4. Check database credentials and permissions\n")
}

cat("\n🏁 RAILWAY DATABASE DIAGNOSTIC COMPLETED\n")