# RAILWAY CONNECTION DIAGNOSTICS
# ==============================
# Comprehensive diagnostics for Railway PostgreSQL connection issues

cat("🔍 RAILWAY CONNECTION DIAGNOSTICS - Starting...\n")
cat(paste(rep("=", 60), collapse = ""), "\n")

# Function to safely test a database connection
test_connection_method <- function(method_name, connection_func) {
  cat("\n", method_name, ":\n")
  cat(paste(rep("-", 40), collapse = ""), "\n")
  
  start_time <- Sys.time()
  tryCatch({
    result <- connection_func()
    end_time <- Sys.time()
    duration <- round(as.numeric(difftime(end_time, start_time, units = "secs")), 2)
    
    if (is.logical(result) && result) {
      cat("✅ SUCCESS (", duration, "s)\n")
      return(list(success = TRUE, duration = duration, error = NULL))
    } else if (is.numeric(result)) {
      cat("✅ SUCCESS - Documents found:", format(result, big.mark = ","), "(", duration, "s)\n")
      return(list(success = TRUE, duration = duration, error = NULL, count = result))
    } else {
      cat("❌ FAILED - Unknown result type\n")
      return(list(success = FALSE, duration = duration, error = "Unknown result"))
    }
    
  }, error = function(e) {
    end_time <- Sys.time()
    duration <- round(as.numeric(difftime(end_time, start_time, units = "secs")), 2)
    cat("❌ FAILED (", duration, "s):", e$message, "\n")
    
    # Analyze error type
    if (grepl("could not connect to server", e$message, ignore.case = TRUE)) {
      cat("💡 Analysis: Network connectivity issue - Railway service may be down\n")
    } else if (grepl("socket", e$message, ignore.case = TRUE)) {
      cat("💡 Analysis: Socket error - PostgreSQL client trying local connection instead of TCP\n")
    } else if (grepl("authentication failed", e$message, ignore.case = TRUE)) {
      cat("💡 Analysis: Authentication failed - check credentials\n")
    } else if (grepl("database.*does not exist", e$message, ignore.case = TRUE)) {
      cat("💡 Analysis: Database does not exist - check database name\n")
    } else if (grepl("timeout", e$message, ignore.case = TRUE)) {
      cat("💡 Analysis: Connection timeout - Railway may be slow to respond\n")
    }
    
    return(list(success = FALSE, duration = duration, error = e$message))
  })
}

# Method 1: Railway Environment Variables
test_env_vars <- function() {
  if (!requireNamespace("DBI", quietly = TRUE) || !requireNamespace("RPostgres", quietly = TRUE)) {
    return(FALSE)
  }
  
  library(DBI)
  library(RPostgres)
  
  # Check if variables exist
  required_vars <- c("PGHOST", "PGDATABASE", "PGUSER", "PGPASSWORD")
  missing_vars <- c()
  
  for (var in required_vars) {
    if (Sys.getenv(var) == "") {
      missing_vars <- c(missing_vars, var)
    }
  }
  
  if (length(missing_vars) > 0) {
    cat("Missing environment variables:", paste(missing_vars, collapse = ", "), "\n")
    return(FALSE)
  }
  
  conn <- dbConnect(
    RPostgres::Postgres(),
    host = Sys.getenv("PGHOST"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE"),
    user = Sys.getenv("PGUSER"),
    password = Sys.getenv("PGPASSWORD"),
    connect_timeout = 10
  )
  
  count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")$count[1]
  dbDisconnect(conn)
  return(as.numeric(count))
}

# Method 2: DATABASE_URL
test_database_url <- function() {
  if (!requireNamespace("DBI", quietly = TRUE) || !requireNamespace("RPostgres", quietly = TRUE)) {
    return(FALSE)
  }
  
  library(DBI)
  library(RPostgres)
  
  db_url <- Sys.getenv("DATABASE_URL")
  if (db_url == "" || !grepl("^postgres://", db_url)) {
    cat("DATABASE_URL not set or invalid format\n")
    return(FALSE)
  }
  
  conn <- dbConnect(RPostgres::Postgres(), dbname = db_url)
  count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")$count[1]
  dbDisconnect(conn)
  return(as.numeric(count))
}

# Method 3: Hardcoded credentials (fallback)
test_hardcoded <- function() {
  if (!requireNamespace("DBI", quietly = TRUE) || !requireNamespace("RPostgres", quietly = TRUE)) {
    return(FALSE)
  }
  
  library(DBI)
  library(RPostgres)
  
  conn <- dbConnect(
    RPostgres::Postgres(),
    host = "nozomi.proxy.rlwy.net",
    port = 44844,
    dbname = "railway",
    user = "postgres",
    password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY",
    connect_timeout = 10,
    sslmode = "prefer"
  )
  
  count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")$count[1]
  dbDisconnect(conn)
  return(as.numeric(count))
}

# Environment Analysis
cat("\n📍 ENVIRONMENT ANALYSIS:\n")
cat(paste(rep("-", 40), collapse = ""), "\n")

# Check Railway-specific variables
railway_vars <- c("RAILWAY_ENVIRONMENT", "RAILWAY_PROJECT_ID", "RAILWAY_SERVICE_ID")
for (var in railway_vars) {
  val <- Sys.getenv(var)
  if (val != "") {
    cat("✅", var, ":", val, "\n")
  } else {
    cat("❌", var, ": NOT SET\n")
  }
}

# Check PostgreSQL variables
pg_vars <- c("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "DATABASE_URL")
cat("\n🔧 DATABASE ENVIRONMENT VARIABLES:\n")
for (var in pg_vars) {
  val <- Sys.getenv(var)
  if (val != "") {
    if (var %in% c("PGPASSWORD", "DATABASE_URL")) {
      cat("✅", var, ": ***SET*** (", nchar(val), "chars)\n")
    } else {
      cat("✅", var, ":", val, "\n")
    }
  } else {
    cat("❌", var, ": NOT SET\n")
  }
}

# Check package availability
cat("\n📦 PACKAGE AVAILABILITY:\n")
required_packages <- c("DBI", "RPostgres", "dplyr")
for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat("✅", pkg, ": Available\n")
  } else {
    cat("❌", pkg, ": NOT AVAILABLE\n")
  }
}

# Test all connection methods
cat("\n🔌 CONNECTION METHOD TESTS:\n")

results <- list()
results$env_vars <- test_connection_method("Method 1: Railway Environment Variables", test_env_vars)
results$database_url <- test_connection_method("Method 2: DATABASE_URL", test_database_url)
results$hardcoded <- test_connection_method("Method 3: Hardcoded Credentials", test_hardcoded)

# Summary
cat("\n📊 DIAGNOSTIC SUMMARY:\n")
cat(paste(rep("=", 60), collapse = ""), "\n")

successful_methods <- c()
failed_methods <- c()

for (method_name in names(results)) {
  if (results[[method_name]]$success) {
    successful_methods <- c(successful_methods, method_name)
  } else {
    failed_methods <- c(failed_methods, method_name)
  }
}

if (length(successful_methods) > 0) {
  cat("✅ SUCCESSFUL METHODS:\n")
  for (method in successful_methods) {
    result <- results[[method]]
    duration_text <- paste0(result$duration, "s")
    count_text <- if (!is.null(result$count)) paste0(" (", format(result$count, big.mark = ","), " docs)") else ""
    cat("  -", method, ":", duration_text, count_text, "\n")
  }
} else {
  cat("❌ NO SUCCESSFUL CONNECTIONS\n")
}

if (length(failed_methods) > 0) {
  cat("\n❌ FAILED METHODS:\n")
  for (method in failed_methods) {
    result <- results[[method]]
    cat("  -", method, ":", result$error, "\n")
  }
}

# Recommendations
cat("\n💡 RECOMMENDATIONS:\n")
cat(paste(rep("-", 40), collapse = ""), "\n")

if (length(successful_methods) == 0) {
  cat("🚨 CRITICAL: No database connection methods work!\n")
  cat("  1. Check Railway service status\n")
  cat("  2. Verify database is attached to Railway deployment\n")
  cat("  3. Check Railway environment variables are set\n")
  cat("  4. Verify network connectivity from Railway to database\n")
} else {
  best_method <- successful_methods[1]
  cat("✅ WORKING: Use", best_method, "as primary connection method\n")
  
  if ("env_vars" %in% successful_methods) {
    cat("  1. Railway environment variables are working - use this method\n")
  } else if ("database_url" %in% successful_methods) {
    cat("  1. DATABASE_URL is working - use this method\n")
  } else if ("hardcoded" %in% successful_methods) {
    cat("  1. Hardcoded credentials work but Railway env vars don't\n")
    cat("  2. Check Railway database environment variable configuration\n")
  }
  
  if (length(failed_methods) > 0) {
    cat("  3. Fix failed methods for redundancy\n")
  }
}

# Test the fixed connection system if available
if (file.exists("RAILWAY_DATABASE_CONNECTION_FIX.R")) {
  cat("\n🧪 TESTING FIXED CONNECTION SYSTEM:\n")
  cat(paste(rep("-", 40), collapse = ""), "\n")
  
  tryCatch({
    source("RAILWAY_DATABASE_CONNECTION_FIX.R", echo = FALSE)
    
    # Test functions
    total_docs <- get_total_documents()
    metrics <- get_lexml_dashboard_metrics()
    status <- get_connection_status()
    
    cat("✅ Fixed system loaded successfully\n")
    cat("📊 Total documents:", format(total_docs, big.mark = ","), "\n")
    cat("🔌 Connection status:", status$status, "\n")
    cat("🔧 Connection method:", status$connection_method, "\n")
    
  }, error = function(e) {
    cat("❌ Fixed system failed:", e$message, "\n")
  })
}

cat("\n🏁 DIAGNOSTICS COMPLETE\n")
cat(paste(rep("=", 60), collapse = ""), "\n")

# Save results for later analysis
diagnostic_results <- list(
  timestamp = Sys.time(),
  environment = as.list(Sys.getenv()),
  connection_tests = results,
  successful_methods = successful_methods,
  failed_methods = failed_methods
)

tryCatch({
  saveRDS(diagnostic_results, "railway_diagnostics_results.rds")
  cat("📝 Results saved to railway_diagnostics_results.rds\n")
}, error = function(e) {
  cat("⚠️ Could not save results:", e$message, "\n")
})