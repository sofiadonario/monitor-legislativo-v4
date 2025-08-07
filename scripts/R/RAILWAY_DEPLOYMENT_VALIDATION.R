# RAILWAY DEPLOYMENT VALIDATION
# Final validation script for Railway PostgreSQL integration
# Tests all aspects of the database connection and function overrides

cat("🚀 RAILWAY DEPLOYMENT VALIDATION\n")
cat("=" * 50, "\n")
cat("📊 Timestamp:", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "\n")
cat("🎯 Target: Validate 144,138 documents from Railway PostgreSQL\n\n")

# ================================
# TEST 1: ENVIRONMENT VALIDATION
# ================================

cat("TEST 1: ENVIRONMENT VALIDATION\n")
cat("-" * 30, "\n")

database_url <- Sys.getenv("DATABASE_URL", "")
if (nchar(database_url) > 0) {
  cat("✅ DATABASE_URL is present (", nchar(database_url), " chars)\n")
  
  # Parse and validate URL structure
  url_pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)"
  parsed <- regmatches(database_url, regexec(url_pattern, database_url))[[1]]
  
  if (length(parsed) == 6) {
    cat("✅ DATABASE_URL format is valid\n")
    cat("   Host:", parsed[4], "\n")
    cat("   Port:", parsed[5], "\n")
    cat("   Database:", parsed[6], "\n")
  } else {
    cat("❌ DATABASE_URL format is invalid\n")
  }
} else {
  cat("❌ DATABASE_URL is missing\n")
  cat("   This is required for Railway PostgreSQL connection\n")
}

# Check required packages
required_packages <- c("DBI", "RPostgres", "pool", "dplyr", "shiny")
all_packages_available <- TRUE

for (pkg in required_packages) {
  available <- require(pkg, character.only = TRUE, quietly = TRUE)
  if (available) {
    cat("✅", pkg, "package is available\n")
  } else {
    cat("❌", pkg, "package is MISSING\n")
    all_packages_available <- FALSE
  }
}

if (!all_packages_available) {
  cat("⚠️ Some required packages are missing - this will cause failures\n")
}

cat("\n")

# ================================
# TEST 2: DATABASE CONNECTION
# ================================

cat("TEST 2: DATABASE CONNECTION\n")
cat("-" * 30, "\n")

connection_successful <- FALSE
document_count <- 0
main_table <- NULL

if (nchar(database_url) > 0 && all_packages_available) {
  
  tryCatch({
    # Parse connection details
    url_pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)"
    parsed <- regmatches(database_url, regexec(url_pattern, database_url))[[1]]
    
    if (length(parsed) == 6) {
      # Create test connection
      test_pool <- dbPool(
        drv = RPostgres::Postgres(),
        host = parsed[4],
        port = as.numeric(parsed[5]),
        dbname = parsed[6],
        user = parsed[2],
        password = parsed[3],
        minSize = 1,
        maxSize = 2,
        validateQuery = "SELECT 1"
      )
      
      cat("✅ Database connection pool created\n")
      
      # Test basic connectivity
      version_result <- dbGetQuery(test_pool, "SELECT version() as version")
      cat("✅ PostgreSQL connection successful\n")
      cat("   Version:", substr(version_result$version[1], 1, 50), "...\n")
      
      # List tables
      tables <- dbListTables(test_pool)
      cat("✅ Tables retrieved:", length(tables), "tables found\n")
      
      # Find main document table
      table_candidates <- c("documents", "lexml_documents", "lexml_parsed_enhanced_fixed")
      
      for (table_name in table_candidates) {
        if (table_name %in% tables) {
          tryCatch({
            count_result <- dbGetQuery(test_pool, paste("SELECT COUNT(*) as count FROM", table_name))
            document_count <- count_result$count[1]
            main_table <- table_name
            cat("✅ Main table found:", table_name, "with", format(document_count, big.mark = ","), "documents\n")
            connection_successful <- TRUE
            break
          }, error = function(e) {
            cat("⚠️ Error accessing table", table_name, ":", e$message, "\n")
          })
        }
      }
      
      if (connection_successful) {
        # Test sample data retrieval
        sample_query <- paste("SELECT titulo, tipo, estado FROM", main_table, "LIMIT 3")
        sample_data <- dbGetQuery(test_pool, sample_query)
        cat("✅ Sample data retrieved:", nrow(sample_data), "rows\n")
        
        if (nrow(sample_data) > 0) {
          cat("   Sample titles:\n")
          for (i in 1:min(2, nrow(sample_data))) {
            cat("   -", substr(sample_data$titulo[i], 1, 50), "...\n")
          }
        }
      }
      
      # Clean up test connection
      poolClose(test_pool)
      
    } else {
      cat("❌ Failed to parse DATABASE_URL\n")
    }
    
  }, error = function(e) {
    cat("❌ Database connection failed:", e$message, "\n")
  })
  
} else {
  cat("⚠️ Skipping database test - missing prerequisites\n")
}

cat("\n")

# ================================
# TEST 3: FUNCTION AVAILABILITY
# ================================

cat("TEST 3: FUNCTION AVAILABILITY\n")
cat("-" * 30, "\n")

# Test for key dashboard functions
key_functions <- c("get_lexml_dashboard_metrics", "get_search_analytics", "get_database_stats")

for (func_name in key_functions) {
  if (exists(func_name)) {
    cat("✅", func_name, "function is available\n")
  } else {
    cat("❌", func_name, "function is MISSING\n")
  }
}

# Check if RAILWAY_POSTGRESQL_FIX.R exists
if (file.exists("RAILWAY_POSTGRESQL_FIX.R")) {
  cat("✅ RAILWAY_POSTGRESQL_FIX.R file exists\n")
} else {
  cat("❌ RAILWAY_POSTGRESQL_FIX.R file is MISSING\n")
}

cat("\n")

# ================================
# TEST 4: FUNCTION EXECUTION TEST
# ================================

cat("TEST 4: FUNCTION EXECUTION TEST\n")
cat("-" * 30, "\n")

if (connection_successful) {
  cat("🔄 Loading Railway PostgreSQL fix...\n")
  
  tryCatch({
    source("RAILWAY_POSTGRESQL_FIX.R")
    cat("✅ Railway PostgreSQL fix loaded successfully\n")
    
    # Test dashboard metrics function
    if (exists("get_lexml_dashboard_metrics")) {
      cat("🔄 Testing get_lexml_dashboard_metrics...\n")
      metrics <- get_lexml_dashboard_metrics()
      cat("✅ Dashboard metrics result:\n")
      cat("   Total documents:", format(metrics$total_documents, big.mark = ","), "\n")
      cat("   States percentage:", metrics$states_percentage, "%\n")
      cat("   Date range:", metrics$date_range_years, "years\n")
      
      # Validate expected document count
      if (metrics$total_documents >= 140000) {
        cat("✅ Document count looks correct (>= 140,000)\n")
      } else {
        cat("⚠️ Document count seems low:", format(metrics$total_documents, big.mark = ","), "\n")
      }
    }
    
    # Test analytics function
    if (exists("get_search_analytics")) {
      cat("🔄 Testing get_search_analytics...\n")
      analytics <- get_search_analytics()
      cat("✅ Analytics result:\n")
      cat("   Total documents:", format(analytics$total_documents, big.mark = ","), "\n")
      cat("   Data source:", analytics$data_source, "\n")
      cat("   Year data points:", nrow(analytics$documents_by_year), "\n")
      cat("   State data points:", nrow(analytics$documents_by_state), "\n")
    }
    
  }, error = function(e) {
    cat("❌ Function execution test failed:", e$message, "\n")
  })
  
} else {
  cat("⚠️ Skipping function test - no database connection\n")
}

cat("\n")

# ================================
# TEST 5: DEPLOYMENT READINESS
# ================================

cat("TEST 5: DEPLOYMENT READINESS\n")
cat("-" * 30, "\n")

deployment_ready <- TRUE

# Check critical files
critical_files <- c("app.R", "RAILWAY_POSTGRESQL_FIX.R")
for (file in critical_files) {
  if (file.exists(file)) {
    cat("✅", file, "exists\n")
  } else {
    cat("❌", file, "is MISSING\n")
    deployment_ready <- FALSE
  }
}

# Check if app.R sources the fix
if (file.exists("app.R")) {
  app_content <- readLines("app.R")
  if (any(grepl("RAILWAY_POSTGRESQL_FIX.R", app_content))) {
    cat("✅ app.R sources Railway PostgreSQL fix\n")
  } else {
    cat("❌ app.R does NOT source Railway PostgreSQL fix\n")
    deployment_ready <- FALSE
  }
}

# Check environment readiness
if (nchar(database_url) > 0) {
  cat("✅ DATABASE_URL is configured\n")
} else {
  cat("❌ DATABASE_URL is not configured\n")
  deployment_ready <- FALSE
}

# Port configuration
port <- as.integer(Sys.getenv("PORT", "3838"))
cat("✅ Port configured:", port, "\n")

cat("\n")

# ================================
# FINAL SUMMARY
# ================================

cat("FINAL SUMMARY\n")
cat("=" * 50, "\n")

if (deployment_ready && connection_successful && document_count > 0) {
  cat("🎉 VALIDATION SUCCESSFUL! 🎉\n")
  cat("✅ All systems ready for Railway deployment\n")
  cat("📊 Database contains", format(document_count, big.mark = ","), "documents\n")
  cat("🚀 Your Shiny app should now display correct document counts\n")
  cat("\n")
  cat("Next steps:\n")
  cat("1. Commit and push these changes to your repository\n")
  cat("2. Railway will automatically redeploy\n")
  cat("3. Monitor the Railway deployment logs\n")
  cat("4. Check your app at the Railway URL\n")
  
} else {
  cat("❌ VALIDATION FAILED\n")
  cat("🔧 Issues that need to be resolved:\n")
  
  if (!all_packages_available) {
    cat("- Install missing R packages\n")
  }
  if (nchar(database_url) == 0) {
    cat("- Configure DATABASE_URL in Railway environment\n")
  }
  if (!connection_successful) {
    cat("- Fix database connection issues\n")
  }
  if (!deployment_ready) {
    cat("- Ensure all required files are present\n")
  }
  
  cat("\n")
  cat("Run this validation script again after fixing the issues.\n")
}

cat("\n")
cat("🏁 RAILWAY DEPLOYMENT VALIDATION COMPLETED\n")
cat("📊 Timestamp:", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "\n")