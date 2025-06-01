# RAILWAY DATABASE CONNECTION TEST
# =====================================
# Comprehensive test to verify Railway environment variables and PostgreSQL connection

cat("🧪 RAILWAY DATABASE CONNECTION TEST\n")
cat("====================================\n")
cat("⏰ Test Time:", format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"), "\n\n")

# Test 1: Environment Variable Detection
cat("📋 TEST 1: Environment Variable Detection\n")
cat("------------------------------------------\n")

essential_vars <- c(
  "DATABASE_URL", "PGHOST", "PGPORT", "PGDATABASE", 
  "PGUSER", "PGPASSWORD", "POSTGRES_DB", "POSTGRES_USER", 
  "POSTGRES_PASSWORD", "DATABASE_PUBLIC_URL"
)

detected_vars <- list()
for (var in essential_vars) {
  value <- Sys.getenv(var, "")
  detected_vars[[var]] <- value
  
  if (nchar(value) > 0) {
    if (var %in% c("PGPASSWORD", "POSTGRES_PASSWORD", "DATABASE_URL", "DATABASE_PUBLIC_URL")) {
      cat("  ✅", var, ": [SET - length:", nchar(value), "]\n")
    } else {
      cat("  ✅", var, ":", value, "\n")
    }
  } else {
    cat("  ❌", var, ": [NOT SET]\n")
  }
}

# Test 2: Railway Environment Detection
cat("\n🚂 TEST 2: Railway Environment Detection\n")
cat("----------------------------------------\n")

railway_indicators <- c(
  "RAILWAY_ENVIRONMENT" = Sys.getenv("RAILWAY_ENVIRONMENT", ""),
  "PORT" = Sys.getenv("PORT", ""),
  "RAILWAY_DEPLOYMENT_DRAINING_SECONDS" = Sys.getenv("RAILWAY_DEPLOYMENT_DRAINING_SECONDS", "")
)

for (name in names(railway_indicators)) {
  value <- railway_indicators[[name]]
  if (nchar(value) > 0) {
    cat("  ✅", name, ":", value, "\n")
  } else {
    cat("  ❌", name, ": [NOT SET]\n")
  }
}

# Test 3: Create Optimal Connection Configuration
cat("\n🔧 TEST 3: Connection Configuration Creation\n")
cat("--------------------------------------------\n")

create_railway_config <- function() {
  # Priority 1: Use DATABASE_URL if available
  database_url <- detected_vars[["DATABASE_URL"]]
  if (nchar(database_url) > 0) {
    cat("✅ Using DATABASE_URL for connection\n")
    return(list(
      method = "DATABASE_URL",
      connection_string = database_url
    ))
  }
  
  # Priority 2: Use individual PG variables
  pghost <- detected_vars[["PGHOST"]]
  pgport <- detected_vars[["PGPORT"]]
  pgdatabase <- detected_vars[["PGDATABASE"]]
  pguser <- detected_vars[["PGUSER"]]
  pgpassword <- detected_vars[["PGPASSWORD"]]
  
  if (all(c(nchar(pghost), nchar(pgport), nchar(pgdatabase), nchar(pguser), nchar(pgpassword)) > 0)) {
    cat("✅ Using individual PostgreSQL environment variables\n")
    return(list(
      method = "PG_ENV_VARS",
      host = pghost,
      port = as.integer(pgport),
      dbname = pgdatabase,
      user = pguser,
      password = pgpassword
    ))
  }
  
  # Priority 3: Use POSTGRES_ prefixed variables
  postgres_db <- detected_vars[["POSTGRES_DB"]]
  postgres_user <- detected_vars[["POSTGRES_USER"]]
  postgres_password <- detected_vars[["POSTGRES_PASSWORD"]]
  
  if (all(c(nchar(pghost), nchar(pgport), nchar(postgres_db), nchar(postgres_user), nchar(postgres_password)) > 0)) {
    cat("✅ Using POSTGRES_ prefixed environment variables\n")
    return(list(
      method = "POSTGRES_ENV_VARS",
      host = pghost,
      port = as.integer(pgport),
      dbname = postgres_db,
      user = postgres_user,
      password = postgres_password
    ))
  }
  
  cat("❌ No usable environment variables found\n")
  return(NULL)
}

config <- create_railway_config()
if (!is.null(config)) {
  cat("📋 Configuration created successfully:\n")
  cat("   Method:", config$method, "\n")
  if (!is.null(config$connection_string)) {
    cat("   Connection String: [length:", nchar(config$connection_string), "]\n")
  } else {
    cat("   Host:", config$host, "\n")
    cat("   Port:", config$port, "\n")
    cat("   Database:", config$dbname, "\n")
    cat("   User:", config$user, "\n")
  }
}

# Test 4: Package Availability Check
cat("\n📦 TEST 4: Required Package Check\n")
cat("----------------------------------\n")

required_packages <- c("DBI", "RPostgres")
packages_available <- TRUE

for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat("  ✅", pkg, ": Available\n")
  } else {
    cat("  ❌", pkg, ": MISSING - attempting installation\n")
    packages_available <- FALSE
    tryCatch({
      install.packages(pkg, repos = "https://cran.rstudio.com/", quiet = TRUE)
      cat("  ✅", pkg, ": Installed successfully\n")
    }, error = function(e) {
      cat("  ❌", pkg, ": Installation failed -", e$message, "\n")
    })
  }
}

# Test 5: Actual Connection Test (if packages are available)
if (packages_available && !is.null(config)) {
  cat("\n🔌 TEST 5: Database Connection Test\n")
  cat("-----------------------------------\n")
  
  library(DBI)
  library(RPostgres)
  
  tryCatch({
    cat("🔄 Attempting connection...\n")
    
    if (config$method == "DATABASE_URL") {
      conn <- dbConnect(
        RPostgres::Postgres(),
        config$connection_string,
        connect_timeout = 30,
        sslmode = "prefer"
      )
    } else {
      conn <- dbConnect(
        RPostgres::Postgres(),
        host = config$host,
        port = config$port,
        dbname = config$dbname,
        user = config$user,
        password = config$password,
        connect_timeout = 30,
        sslmode = "prefer"
      )
    }
    
    # Test basic connectivity
    result <- dbGetQuery(conn, "SELECT 1 as test")
    if (nrow(result) == 1) {
      cat("✅ Connection successful!\n")
      
      # Test for documents table
      tables_result <- dbGetQuery(conn, "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
      cat("📋 Available tables:", nrow(tables_result), "\n")
      
      if ("documents" %in% tables_result$tablename) {
        doc_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
        cat("📄 Documents in database:", format(doc_count$count[1], big.mark = ","), "\n")
      } else {
        cat("⚠️ Documents table not found - database may be empty\n")
      }
      
      # Cleanup
      dbDisconnect(conn)
      cat("✅ Connection test completed successfully\n")
      
    } else {
      cat("❌ Connection test query failed\n")
    }
    
  }, error = function(e) {
    cat("❌ Connection failed:", e$message, "\n")
    
    # Enhanced error diagnosis
    if (grepl("socket|/var/run/postgresql", e$message)) {
      cat("\n🚨 SOCKET ERROR ANALYSIS:\n")
      cat("   - R is trying to connect to local PostgreSQL socket\n")
      cat("   - This means connection parameters are not being used properly\n")
      cat("   - Likely cause: Environment variables not accessible to R process\n")
      cat("   - Solution: Use hardcoded credentials or fix environment passing\n")
    } else if (grepl("connection refused|timeout", e$message)) {
      cat("\n🚨 NETWORK ERROR ANALYSIS:\n")
      cat("   - Cannot reach the database server\n")
      cat("   - Check Railway service status\n")
      cat("   - Verify internal networking configuration\n")
    } else if (grepl("authentication|password", e$message)) {
      cat("\n🚨 AUTHENTICATION ERROR ANALYSIS:\n")
      cat("   - Database credentials are incorrect\n")
      cat("   - Check Railway database service configuration\n")
    }
  })
}

cat("\n📊 TEST SUMMARY\n")
cat("===============\n")
cat("⏰ Test completed at:", format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"), "\n")
cat("🔍 Check the output above for any issues\n")
cat("📋 If all tests pass, the connection should work in the main application\n")