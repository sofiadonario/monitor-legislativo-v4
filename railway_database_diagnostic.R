# RAILWAY DATABASE DIAGNOSTIC SCRIPT
# ===================================
# Comprehensive diagnostic tool for Railway PostgreSQL connectivity
# Tests connection, database schema, data integrity, and system readiness

cat("🔍 RAILWAY DATABASE DIAGNOSTIC STARTING...\n")
cat(paste(rep("=", 60), collapse = ""), "\n")

# Load required packages
required_packages <- c("DBI", "RPostgres", "dplyr")
missing_packages <- c()

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("❌ CRITICAL: Missing required packages:", paste(missing_packages, collapse = ", "), "\n")
  cat("💡 Install with: install.packages(c(", paste0("'", missing_packages, "'", collapse = ", "), "))\n")
  stop("Cannot proceed without required packages")
}

# Load packages
suppressPackageStartupMessages(library(DBI))
suppressPackageStartupMessages(library(RPostgres))
suppressPackageStartupMessages(library(dplyr))

# Railway database configuration
RAILWAY_CONFIG <- list(
  host = "nozomi.proxy.rlwy.net",
  port = 44844,
  dbname = "railway",
  user = "postgres",  
  password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
)

# Diagnostic results storage
diagnostic_results <- list()

# =============================================================================
# 1. CONNECTION TESTS
# =============================================================================

cat("\n1️⃣ TESTING DATABASE CONNECTION\n")
cat(paste(rep("-", 40), collapse = ""), "\n")

test_connection <- function() {
  conn <- NULL
  
  tryCatch({
    # Test basic connection
    conn <- dbConnect(
      RPostgres::Postgres(),
      host = RAILWAY_CONFIG$host,
      port = RAILWAY_CONFIG$port,
      dbname = RAILWAY_CONFIG$dbname,
      user = RAILWAY_CONFIG$user,
      password = RAILWAY_CONFIG$password,
      connect_timeout = 10
    )
    
    # Test simple query
    result <- dbGetQuery(conn, "SELECT version() as postgres_version")
    
    cat("✅ Connection successful!\n")
    cat("📊 PostgreSQL Version:", result$postgres_version[1], "\n")
    
    diagnostic_results$connection <<- TRUE
    diagnostic_results$postgres_version <<- result$postgres_version[1]
    
    return(conn)
    
  }, error = function(e) {
    cat("❌ Connection failed:", e$message, "\n")
    diagnostic_results$connection <<- FALSE
    diagnostic_results$connection_error <<- e$message
    return(NULL)
  })
}

conn <- test_connection()

if (is.null(conn)) {
  cat("\n❌ CRITICAL FAILURE: Cannot proceed without database connection\n")
  cat("🔧 Troubleshooting steps:\n")
  cat("   1. Check Railway service status\n")
  cat("   2. Verify database credentials\n")
  cat("   3. Check network connectivity\n")
  stop("Database connection failed")
}

# =============================================================================
# 2. SCHEMA VERIFICATION  
# =============================================================================

cat("\n2️⃣ VERIFYING DATABASE SCHEMA\n")
cat(paste(rep("-", 40), collapse = ""), "\n")

# Check for essential tables
essential_tables <- c("documents", "document_categories")
optional_tables <- c("dashboard_metrics", "documents_by_state", "documents_by_category")

check_tables <- function(conn) {
  all_tables <- dbListTables(conn)
  
  cat("📋 Available tables:", length(all_tables), "\n")
  
  # Check essential tables
  missing_essential <- c()
  for (table in essential_tables) {
    if (table %in% all_tables) {
      cat("✅", table, "- EXISTS\n")
    } else {
      cat("❌", table, "- MISSING\n")
      missing_essential <- c(missing_essential, table)
    }
  }
  
  # Check optional tables (views/aggregated tables)  
  missing_optional <- c()
  for (table in optional_tables) {
    if (table %in% all_tables) {
      cat("✅", table, "- EXISTS\n")
    } else {
      cat("⚠️", table, "- MISSING (optional)\n")
      missing_optional <- c(missing_optional, table)
    }
  }
  
  diagnostic_results$all_tables <<- all_tables
  diagnostic_results$missing_essential <<- missing_essential
  diagnostic_results$missing_optional <<- missing_optional
  
  return(length(missing_essential) == 0)
}

schema_ok <- check_tables(conn)

# =============================================================================
# 3. DATA INTEGRITY CHECKS
# =============================================================================

cat("\n3️⃣ CHECKING DATA INTEGRITY\n")
cat(paste(rep("-", 40), collapse = ""), "\n")

check_data_integrity <- function(conn) {
  results <- list()
  
  # Check documents table
  if ("documents" %in% dbListTables(conn)) {
    tryCatch({
      total_docs <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")$count[1]
      cat("📊 Total documents:", format(total_docs, big.mark = ","), "\n")
      results$total_documents <- total_docs
      
      # Check for null values in key columns
      columns_to_check <- c("titulo", "categoria", "ano")
      for (col in columns_to_check) {
        null_count <- tryCatch({
          dbGetQuery(conn, paste0("SELECT COUNT(*) as count FROM documents WHERE ", col, " IS NULL"))$count[1]
        }, error = function(e) 0)
        
        cat("🔍", col, "- NULL values:", null_count, "\n")
        results[[paste0(col, "_nulls")]] <- null_count
      }
      
      # Check year distribution
      year_stats <- tryCatch({
        dbGetQuery(conn, "SELECT MIN(ano) as min_year, MAX(ano) as max_year FROM documents WHERE ano IS NOT NULL")
      }, error = function(e) data.frame(min_year = NA, max_year = NA))
      
      if (!is.na(year_stats$min_year[1])) {
        cat("📅 Year range:", year_stats$min_year[1], "-", year_stats$max_year[1], "\n")
        results$year_range <- paste(year_stats$min_year[1], year_stats$max_year[1], sep = "-")
      }
      
      # Check state distribution
      state_count <- tryCatch({
        dbGetQuery(conn, "SELECT COUNT(DISTINCT estado) as count FROM documents WHERE estado IS NOT NULL AND estado != ''")$count[1]
      }, error = function(e) 0)
      
      cat("🗺️ Unique states:", state_count, "\n")
      results$unique_states <- state_count
      
    }, error = function(e) {
      cat("❌ Error checking documents table:", e$message, "\n")
      results$documents_error <- e$message
    })
  }
  
  diagnostic_results$data_integrity <<- results
  return(results)
}

data_integrity <- check_data_integrity(conn)

# =============================================================================
# 4. PERFORMANCE TESTS
# =============================================================================

cat("\n4️⃣ TESTING QUERY PERFORMANCE\n")
cat(paste(rep("-", 40), collapse = ""), "\n")

test_performance <- function(conn) {
  performance_results <- list()
  
  # Test 1: Simple count query
  start_time <- Sys.time()
  tryCatch({
    result <- dbGetQuery(conn, "SELECT COUNT(*) FROM documents")
    end_time <- Sys.time()
    duration <- as.numeric(difftime(end_time, start_time, units = "secs"))
    cat("⏱️ Count query:", round(duration, 3), "seconds\n")
    performance_results$count_query_time <- duration
  }, error = function(e) {
    cat("❌ Count query failed:", e$message, "\n")
    performance_results$count_query_error <- e$message
  })
  
  # Test 2: Aggregation query
  start_time <- Sys.time()
  tryCatch({
    result <- dbGetQuery(conn, "SELECT estado, COUNT(*) as count FROM documents WHERE estado IS NOT NULL GROUP BY estado LIMIT 10")
    end_time <- Sys.time()
    duration <- as.numeric(difftime(end_time, start_time, units = "secs"))
    cat("⏱️ Aggregation query:", round(duration, 3), "seconds\n")
    performance_results$aggregation_query_time <- duration
  }, error = function(e) {
    cat("❌ Aggregation query failed:", e$message, "\n")
    performance_results$aggregation_query_error <- e$message
  })
  
  # Test 3: Complex join (if categories table exists)
  if ("document_categories" %in% dbListTables(conn)) {
    start_time <- Sys.time()
    tryCatch({
      result <- dbGetQuery(conn, "SELECT d.categoria, COUNT(*) as count FROM documents d LEFT JOIN document_categories dc ON d.categoria = dc.name GROUP BY d.categoria LIMIT 10")
      end_time <- Sys.time()
      duration <- as.numeric(difftime(end_time, start_time, units = "secs"))
      cat("⏱️ Join query:", round(duration, 3), "seconds\n")
      performance_results$join_query_time <- duration
    }, error = function(e) {
      cat("❌ Join query failed:", e$message, "\n")
      performance_results$join_query_error <- e$message
    })
  }
  
  diagnostic_results$performance <<- performance_results
  return(performance_results)
}

performance_tests <- test_performance(conn)

# =============================================================================
# 5. ANALYTICS SYSTEM READINESS
# =============================================================================

cat("\n5️⃣ TESTING ANALYTICS SYSTEM READINESS\n")
cat(paste(rep("-", 40), collapse = ""), "\n")

test_analytics_readiness <- function(conn) {
  readiness <- list()
  
  # Test dashboard metrics query
  tryCatch({
    metrics_query <- "
      SELECT 
        COUNT(*) as total_documents,
        COUNT(DISTINCT estado) as states_with_documents,
        MIN(ano) as earliest_year,
        MAX(ano) as latest_year
      FROM documents 
      WHERE estado IS NOT NULL AND ano IS NOT NULL
    "
    result <- dbGetQuery(conn, metrics_query)
    cat("✅ Dashboard metrics calculation - SUCCESS\n")
    cat("   📊 Total docs:", format(result$total_documents[1], big.mark = ","), "\n")
    cat("   🗺️ States:", result$states_with_documents[1], "\n")
    cat("   📅 Years:", result$earliest_year[1], "-", result$latest_year[1], "\n")
    
    readiness$dashboard_metrics <- TRUE
    readiness$metrics_data <- result
    
  }, error = function(e) {
    cat("❌ Dashboard metrics calculation - FAILED:", e$message, "\n")
    readiness$dashboard_metrics <- FALSE
    readiness$dashboard_error <- e$message
  })
  
  # Test state aggregation
  tryCatch({
    state_query <- "SELECT estado, COUNT(*) as count FROM documents WHERE estado IS NOT NULL AND estado != '' GROUP BY estado ORDER BY count DESC LIMIT 5"
    result <- dbGetQuery(conn, state_query)
    cat("✅ State aggregation - SUCCESS (", nrow(result), "states)\n")
    readiness$state_aggregation <- TRUE
  }, error = function(e) {
    cat("❌ State aggregation - FAILED:", e$message, "\n")
    readiness$state_aggregation <- FALSE
  })
  
  # Test category aggregation  
  tryCatch({
    category_query <- "SELECT categoria, COUNT(*) as count FROM documents WHERE categoria IS NOT NULL GROUP BY categoria ORDER BY count DESC LIMIT 5"
    result <- dbGetQuery(conn, category_query)
    cat("✅ Category aggregation - SUCCESS (", nrow(result), "categories)\n")
    readiness$category_aggregation <- TRUE
  }, error = function(e) {
    cat("❌ Category aggregation - FAILED:", e$message, "\n")
    readiness$category_aggregation <- FALSE
  })
  
  diagnostic_results$analytics_readiness <<- readiness
  return(readiness)
}

analytics_readiness <- test_analytics_readiness(conn)

# =============================================================================
# 6. SYSTEM HEALTH SUMMARY
# =============================================================================

cat("\n6️⃣ SYSTEM HEALTH SUMMARY\n")
cat(paste(rep("=", 60), collapse = ""), "\n")

generate_health_report <- function() {
  cat("🏥 RAILWAY DATABASE HEALTH REPORT\n")
  cat(paste(rep("-", 40), collapse = ""), "\n")
  
  # Connection status
  if (diagnostic_results$connection) {
    cat("✅ Database Connection: HEALTHY\n")
  } else {
    cat("❌ Database Connection: FAILED\n")
  }
  
  # Schema status
  if (length(diagnostic_results$missing_essential) == 0) {
    cat("✅ Database Schema: COMPLETE\n")
  } else {
    cat("❌ Database Schema: INCOMPLETE (missing:", paste(diagnostic_results$missing_essential, collapse = ", "), ")\n")
  }
  
  # Data integrity
  if ("total_documents" %in% names(diagnostic_results$data_integrity)) {
    total_docs <- diagnostic_results$data_integrity$total_documents
    if (total_docs > 0) {
      cat("✅ Data Integrity: HEALTHY (", format(total_docs, big.mark = ","), "documents)\n")
    } else {
      cat("⚠️ Data Integrity: EMPTY DATABASE\n")
    }
  } else {
    cat("❌ Data Integrity: UNKNOWN\n")
  }
  
  # Performance status
  if ("count_query_time" %in% names(diagnostic_results$performance)) {
    avg_time <- diagnostic_results$performance$count_query_time
    if (avg_time < 2) {
      cat("✅ Performance: GOOD (", round(avg_time, 3), "s)\n")
    } else {
      cat("⚠️ Performance: SLOW (", round(avg_time, 3), "s)\n")
    }
  } else {
    cat("❌ Performance: UNTESTED\n")
  }
  
  # Analytics readiness
  if (diagnostic_results$analytics_readiness$dashboard_metrics) {
    cat("✅ Analytics System: READY\n")
  } else {
    cat("❌ Analytics System: NOT READY\n")
  }
  
  cat("\n")
  
  # Overall status
  overall_healthy <- (
    diagnostic_results$connection &&
    length(diagnostic_results$missing_essential) == 0 &&
    "total_documents" %in% names(diagnostic_results$data_integrity) &&
    diagnostic_results$data_integrity$total_documents > 0 &&
    diagnostic_results$analytics_readiness$dashboard_metrics
  )
  
  if (overall_healthy) {
    cat("🎉 OVERALL STATUS: SYSTEM HEALTHY - READY FOR PRODUCTION\n")
  } else {
    cat("⚠️ OVERALL STATUS: SYSTEM ISSUES DETECTED - NEEDS ATTENTION\n")
  }
  
  return(overall_healthy)
}

system_healthy <- generate_health_report()

# =============================================================================
# 7. RECOMMENDATIONS & NEXT STEPS
# =============================================================================

cat("\n7️⃣ RECOMMENDATIONS & NEXT STEPS\n")
cat(paste(rep("-", 40), collapse = ""), "\n")

if (system_healthy) {
  cat("🚀 SYSTEM IS READY FOR PRODUCTION!\n")
  cat("\n💡 Optimization recommendations:\n")
  cat("   1. Create database indexes for better performance\n")
  cat("   2. Set up connection pooling for high traffic\n")
  cat("   3. Implement database monitoring and alerting\n")
  cat("   4. Regular backup verification\n")
} else {
  cat("🔧 ISSUES DETECTED - ACTIONS REQUIRED:\n")
  
  if (!diagnostic_results$connection) {
    cat("\n❌ CONNECTION ISSUES:\n")
    cat("   1. Verify Railway service is running\n")
    cat("   2. Check database credentials\n")
    cat("   3. Test network connectivity\n")
    cat("   4. Contact Railway support if persistent\n")
  }
  
  if (length(diagnostic_results$missing_essential) > 0) {
    cat("\n❌ MISSING ESSENTIAL TABLES:\n")
    cat("   Required tables:", paste(diagnostic_results$missing_essential, collapse = ", "), "\n")
    cat("   1. Run database migration scripts\n")
    cat("   2. Import data from CSV files\n")
    cat("   3. Verify data loading completed successfully\n")
  }
  
  if (!"total_documents" %in% names(diagnostic_results$data_integrity) || 
      diagnostic_results$data_integrity$total_documents == 0) {
    cat("\n❌ DATA ISSUES:\n")
    cat("   1. Import legislative documents data\n")
    cat("   2. Verify data format and encoding\n")
    cat("   3. Check for data loading errors\n")
  }
  
  if (!diagnostic_results$analytics_readiness$dashboard_metrics) {
    cat("\n❌ ANALYTICS SYSTEM ISSUES:\n")
    cat("   1. Fix database query errors\n")
    cat("   2. Create necessary database views\n")
    cat("   3. Test analytics functions individually\n")
  }
}

# Clean up connection
tryCatch({
  dbDisconnect(conn)
  cat("\n🔌 Database connection closed\n")
}, error = function(e) {
  cat("\n⚠️ Warning: Could not close database connection properly\n")
})

cat("\n🏁 DIAGNOSTIC COMPLETE!\n")
cat(paste(rep("=", 60), collapse = ""), "\n")

# Return diagnostic results for further use
return(diagnostic_results)