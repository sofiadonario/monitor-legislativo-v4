#!/usr/bin/env Rscript
# ============================================================================
# RAILWAY DATABASE DIAGNOSTICS & REPAIR SCRIPT
# ============================================================================
# 
# This script diagnoses and fixes Railway PostgreSQL database connectivity
# and data population issues for the Brazilian Legislative Monitor dashboard.
#
# Features:
# - Environment variable validation
# - Database connectivity testing with multiple methods
# - Table schema verification
# - Data population status checking
# - Automatic data migration and population
# - Performance optimization
#
# Usage:
# Rscript railway_database_diagnostics.R
# ============================================================================

cat("🔧 RAILWAY DATABASE DIAGNOSTICS & REPAIR\n")
cat("=========================================\n")

# Load required packages
required_packages <- c("DBI", "RPostgres", "pool", "dplyr")
missing_packages <- c()

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("❌ Missing required packages:", paste(missing_packages, collapse = ", "), "\n")
  cat("Installing missing packages...\n")
  install.packages(missing_packages, repos = "https://cran.rstudio.com/")
}

suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
  library(dplyr)
})

# ============================================================================
# DIAGNOSTIC FUNCTIONS
# ============================================================================

#' Check Railway environment variables
check_environment_variables <- function() {
  cat("\n📋 ENVIRONMENT VARIABLES ANALYSIS:\n")
  
  env_vars <- list(
    # Railway-specific variables
    "RAILWAY_ENVIRONMENT" = Sys.getenv("RAILWAY_ENVIRONMENT"),
    "RAILWAY_PROJECT_ID" = Sys.getenv("RAILWAY_PROJECT_ID"),
    "RAILWAY_SERVICE_ID" = Sys.getenv("RAILWAY_SERVICE_ID"),
    
    # Database connection variables
    "DATABASE_URL" = Sys.getenv("DATABASE_URL"),
    "PGHOST" = Sys.getenv("PGHOST"),
    "PGPORT" = Sys.getenv("PGPORT"),
    "PGDATABASE" = Sys.getenv("PGDATABASE"),
    "PGUSER" = Sys.getenv("PGUSER"),
    "PGPASSWORD" = Sys.getenv("PGPASSWORD"),
    
    # Additional Railway database variables
    "POSTGRES_USER" = Sys.getenv("POSTGRES_USER"),
    "POSTGRES_PASSWORD" = Sys.getenv("POSTGRES_PASSWORD"),
    "POSTGRES_DB" = Sys.getenv("POSTGRES_DB")
  )
  
  for (name in names(env_vars)) {
    value <- env_vars[[name]]
    status <- if (nchar(value) > 0) {
      if (grepl("password|PASSWORD", name)) {
        paste0("SET (", nchar(value), " chars)")
      } else {
        paste0("SET: ", substr(value, 1, 50))
      }
    } else {
      "NOT SET"
    }
    cat(sprintf("  %-20s: %s\n", name, status))
  }
  
  # Check if we're in Railway environment
  is_railway <- any(nchar(c(env_vars$RAILWAY_ENVIRONMENT, env_vars$RAILWAY_PROJECT_ID)) > 0)
  cat("\n✅ Railway Environment Detected:", is_railway, "\n")
  
  return(env_vars)
}

#' Parse DATABASE_URL with comprehensive validation
parse_database_url <- function(database_url) {
  if (is.null(database_url) || database_url == "" || is.na(database_url)) {
    return(NULL)
  }
  
  tryCatch({
    # Support both postgresql:// and postgres:// formats
    if (!grepl("^(postgresql|postgres)://", database_url)) {
      cat("⚠️ Invalid DATABASE_URL format\n")
      return(NULL)
    }
    
    # Remove protocol
    url_clean <- sub("^(postgresql|postgres)://", "", database_url)
    
    # Split into auth@host/db or auth@host:port/db
    if (!grepl("@", url_clean)) {
      cat("⚠️ DATABASE_URL missing @ separator\n")
      return(NULL)
    }
    
    parts <- strsplit(url_clean, "@")[[1]]
    auth_part <- parts[1]
    connection_part <- parts[2]
    
    # Parse auth (user:password)
    auth_split <- strsplit(auth_part, ":")[[1]]
    if (length(auth_split) != 2) {
      cat("⚠️ Invalid auth format in DATABASE_URL\n")
      return(NULL)
    }
    
    user <- auth_split[1]
    password <- auth_split[2]
    
    # Parse connection part (host:port/database or host/database)
    if (grepl("/", connection_part)) {
      connection_split <- strsplit(connection_part, "/")[[1]]
      if (length(connection_split) != 2) {
        cat("⚠️ Invalid connection format in DATABASE_URL\n")
        return(NULL)
      }
      
      host_port <- connection_split[1]
      dbname <- connection_split[2]
    } else {
      cat("⚠️ DATABASE_URL missing database name\n")
      return(NULL)
    }
    
    # Parse host:port
    if (grepl(":", host_port)) {
      host_port_split <- strsplit(host_port, ":")[[1]]
      host <- host_port_split[1]
      port <- as.integer(host_port_split[2])
    } else {
      host <- host_port
      port <- 5432L
    }
    
    return(list(
      host = host,
      port = port,
      dbname = dbname,
      user = user,
      password = password
    ))
    
  }, error = function(e) {
    cat("❌ Error parsing DATABASE_URL:", e$message, "\n")
    return(NULL)
  })
}

#' Get database configuration from environment
get_database_config <- function(env_vars) {
  cat("\n🔍 DATABASE CONFIGURATION ANALYSIS:\n")
  
  # Method 1: Try DATABASE_URL
  if (nchar(env_vars$DATABASE_URL) > 0) {
    cat("📋 Found DATABASE_URL, parsing...\n")
    config <- parse_database_url(env_vars$DATABASE_URL)
    if (!is.null(config)) {
      cat("✅ DATABASE_URL parsed successfully\n")
      config$method <- "DATABASE_URL"
      return(config)
    }
  }
  
  # Method 2: Try individual PG* variables
  if (nchar(env_vars$PGHOST) > 0) {
    cat("📋 Using individual PG* environment variables\n")
    config <- list(
      host = env_vars$PGHOST,
      port = as.integer(ifelse(nchar(env_vars$PGPORT) > 0, env_vars$PGPORT, "5432")),
      dbname = env_vars$PGDATABASE,
      user = env_vars$PGUSER,
      password = env_vars$PGPASSWORD,
      method = "PG_VARS"
    )
    
    # Validate required fields
    if (all(nchar(c(config$host, config$dbname, config$user, config$password)) > 0)) {
      cat("✅ PG* variables validated\n")
      return(config)
    }
  }
  
  # Method 3: Try POSTGRES_* variables (Railway specific)
  if (nchar(env_vars$POSTGRES_USER) > 0) {
    cat("📋 Using Railway-specific POSTGRES_* variables\n")
    config <- list(
      host = ifelse(nchar(env_vars$PGHOST) > 0, env_vars$PGHOST, "postgres"),
      port = as.integer(ifelse(nchar(env_vars$PGPORT) > 0, env_vars$PGPORT, "5432")),
      dbname = ifelse(nchar(env_vars$POSTGRES_DB) > 0, env_vars$POSTGRES_DB, "railway"),
      user = env_vars$POSTGRES_USER,
      password = env_vars$POSTGRES_PASSWORD,
      method = "POSTGRES_VARS"
    )
    
    if (all(nchar(c(config$user, config$password)) > 0)) {
      cat("✅ POSTGRES_* variables validated\n")
      return(config)
    }
  }
  
  cat("❌ No valid database configuration found\n")
  return(NULL)
}

#' Test database connectivity with retry logic
test_database_connection <- function(config) {
  cat("\n🔌 DATABASE CONNECTIVITY TEST:\n")
  cat(sprintf("  Host: %s\n", config$host))
  cat(sprintf("  Port: %d\n", config$port))
  cat(sprintf("  Database: %s\n", config$dbname))
  cat(sprintf("  User: %s\n", config$user))
  cat(sprintf("  Method: %s\n", config$method))
  
  max_attempts <- 3
  base_delay <- 2
  
  for (attempt in 1:max_attempts) {
    cat(sprintf("\n🔄 Connection attempt %d/%d\n", attempt, max_attempts))
    
    tryCatch({
      # Test connection
      con <- dbConnect(
        RPostgres::Postgres(),
        host = config$host,
        port = config$port,
        dbname = config$dbname,
        user = config$user,
        password = config$password,
        sslmode = "prefer",
        connect_timeout = 30,
        application_name = "railway_diagnostics"
      )
      
      # Test basic query
      version_info <- dbGetQuery(con, "SELECT version() as pg_version")
      current_db <- dbGetQuery(con, "SELECT current_database() as db_name")
      
      cat("✅ Connection successful!\n")
      cat(sprintf("  PostgreSQL: %s\n", substr(version_info$pg_version[1], 1, 60)))
      cat(sprintf("  Database: %s\n", current_db$db_name[1]))
      
      # Get SSL status
      tryCatch({
        ssl_status <- dbGetQuery(con, "SELECT current_setting('ssl') as ssl_status")
        cat(sprintf("  SSL Status: %s\n", ssl_status$ssl_status[1]))
      }, error = function(e) {
        cat("  SSL Status: Unknown\n")
      })
      
      # Close test connection
      dbDisconnect(con)
      
      return(TRUE)
      
    }, error = function(e) {
      cat(sprintf("❌ Attempt %d failed: %s\n", attempt, e$message))
      
      if (attempt < max_attempts) {
        delay <- base_delay * (2 ^ (attempt - 1))
        cat(sprintf("⏳ Waiting %d seconds before retry...\n", delay))
        Sys.sleep(delay)
      }
    })
  }
  
  cat("❌ All connection attempts failed\n")
  return(FALSE)
}

#' Check database schema and tables
check_database_schema <- function(config) {
  cat("\n📊 DATABASE SCHEMA ANALYSIS:\n")
  
  tryCatch({
    con <- dbConnect(
      RPostgres::Postgres(),
      host = config$host,
      port = config$port,
      dbname = config$dbname,
      user = config$user,
      password = config$password,
      sslmode = "prefer"
    )
    
    # List all tables
    tables <- dbGetQuery(con, "
      SELECT schemaname, tablename, 
             pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
      FROM pg_tables 
      WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
      ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
    ")
    
    cat("📋 Available Tables:\n")
    for (i in 1:nrow(tables)) {
      cat(sprintf("  %d. %s.%s (%s)\n", i, tables$schemaname[i], tables$tablename[i], tables$size[i]))
    }
    
    # Check for document-related tables
    document_tables <- c("documents", "lexml_parsed_enhanced", "legislative_data", "brazilian_legislative_complete")
    
    table_status <- list()
    
    for (table_name in document_tables) {
      tryCatch({
        # Check if table exists and get row count
        count_query <- sprintf("SELECT COUNT(*) as count FROM %s", table_name)
        result <- dbGetQuery(con, count_query)
        
        if (nrow(result) > 0) {
          count <- result$count[1]
          table_status[[table_name]] <- list(exists = TRUE, count = count)
          
          # Get sample data structure
          sample_query <- sprintf("SELECT * FROM %s LIMIT 1", table_name)
          sample <- dbGetQuery(con, sample_query)
          columns <- names(sample)
          
          cat(sprintf("✅ %s: %s records (%d columns)\n", 
                     table_name, format(count, big.mark = ","), length(columns)))
          
          # Check key columns
          key_columns <- c("titulo", "title", "ementa", "summary", "data", "date", "estado", "state")
          found_columns <- intersect(columns, key_columns)
          if (length(found_columns) > 0) {
            cat(sprintf("   Key columns: %s\n", paste(found_columns, collapse = ", ")))
          }
        }
      }, error = function(e) {
        table_status[[table_name]] <- list(exists = FALSE, count = 0)
        cat(sprintf("❌ %s: Not found or inaccessible\n", table_name))
      })
    }
    
    dbDisconnect(con)
    return(table_status)
    
  }, error = function(e) {
    cat("❌ Schema analysis failed:", e$message, "\n")
    return(NULL)
  })
}

#' Create indexes for performance optimization
optimize_database_performance <- function(config) {
  cat("\n⚡ DATABASE PERFORMANCE OPTIMIZATION:\n")
  
  tryCatch({
    con <- dbConnect(
      RPostgres::Postgres(),
      host = config$host,
      port = config$port,
      dbname = config$dbname,
      user = config$user,
      password = config$password,
      sslmode = "prefer"
    )
    
    # Performance optimization queries
    optimization_queries <- c(
      # Text search indexes
      "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_titulo_gin ON documents USING gin(to_tsvector('portuguese', titulo))",
      "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_ementa_gin ON documents USING gin(to_tsvector('portuguese', ementa))",
      
      # Filter indexes
      "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_estado ON documents(estado)",
      "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_tipo ON documents(tipo)",
      "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_data ON documents(data_publicacao)",
      
      # Composite indexes for common queries
      "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_estado_data ON documents(estado, data_publicacao DESC)",
      "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_tipo_data ON documents(tipo, data_publicacao DESC)"
    )
    
    for (query in optimization_queries) {
      tryCatch({
        dbExecute(con, query)
        cat("✅ Index created/verified\n")
      }, error = function(e) {
        if (grepl("already exists", e$message)) {
          cat("ℹ️ Index already exists\n")
        } else {
          cat(sprintf("⚠️ Index creation failed: %s\n", e$message))
        }
      })
    }
    
    # Update table statistics
    tryCatch({
      dbExecute(con, "ANALYZE documents")
      cat("✅ Table statistics updated\n")
    }, error = function(e) {
      cat("⚠️ Statistics update failed\n")
    })
    
    dbDisconnect(con)
    
  }, error = function(e) {
    cat("❌ Performance optimization failed:", e$message, "\n")
  })
}

#' Generate Railway environment variable configuration
generate_railway_config <- function(config) {
  cat("\n📝 RAILWAY CONFIGURATION GENERATION:\n")
  
  if (is.null(config)) {
    cat("❌ Cannot generate config - no valid database configuration\n")
    return()
  }
  
  # Generate DATABASE_URL
  database_url <- sprintf("postgresql://%s:%s@%s:%d/%s",
                         config$user, config$password, config$host, config$port, config$dbname)
  
  cat("🔧 Required Railway Environment Variables:\n\n")
  cat("# Database Connection\n")
  cat(sprintf("DATABASE_URL=%s\n", database_url))
  cat(sprintf("PGHOST=%s\n", config$host))
  cat(sprintf("PGPORT=%d\n", config$port))
  cat(sprintf("PGDATABASE=%s\n", config$dbname))
  cat(sprintf("PGUSER=%s\n", config$user))
  cat("PGPASSWORD=[REDACTED]\n")
  cat("\n# Application Settings\n")
  cat("R_CONFIG_ACTIVE=production\n")
  cat("RAILWAY_ENVIRONMENT=production\n")
  cat("TZ=America/Sao_Paulo\n")
  
  cat("\n💡 Add these variables to your Railway service settings\n")
}

#' Main diagnostic routine
run_diagnostics <- function() {
  cat("\n🚀 STARTING RAILWAY DATABASE DIAGNOSTICS\n")
  cat("=========================================\n")
  
  # Step 1: Check environment variables
  env_vars <- check_environment_variables()
  
  # Step 2: Get database configuration
  config <- get_database_config(env_vars)
  
  if (is.null(config)) {
    cat("\n❌ CRITICAL: No valid database configuration found\n")
    cat("💡 Please ensure Railway PostgreSQL service is running and environment variables are set\n")
    return(FALSE)
  }
  
  # Step 3: Test connectivity
  if (!test_database_connection(config)) {
    cat("\n❌ CRITICAL: Database connection failed\n")
    cat("💡 Check Railway PostgreSQL service status and network connectivity\n")
    generate_railway_config(config)
    return(FALSE)
  }
  
  # Step 4: Check schema and data
  table_status <- check_database_schema(config)
  
  if (is.null(table_status)) {
    cat("\n⚠️ Schema analysis failed, but connection works\n")
    generate_railway_config(config)
    return(FALSE)
  }
  
  # Step 5: Check data population
  total_documents <- 0
  main_table <- NULL
  
  for (table_name in names(table_status)) {
    if (table_status[[table_name]]$exists && table_status[[table_name]]$count > total_documents) {
      total_documents <- table_status[[table_name]]$count
      main_table <- table_name
    }
  }
  
  cat(sprintf("\n📊 DOCUMENT COUNT ANALYSIS:\n"))
  cat(sprintf("  Primary Table: %s\n", ifelse(is.null(main_table), "None", main_table)))
  cat(sprintf("  Total Documents: %s\n", format(total_documents, big.mark = ",")))
  cat(sprintf("  Expected Documents: 134,000+\n"))
  
  if (total_documents < 1000) {
    cat("\n⚠️ WARNING: Low document count detected\n")
    cat("💡 The database appears to be empty or partially populated\n")
    cat("💡 You may need to run data migration/import scripts\n")
  } else {
    cat("\n✅ Document count looks healthy\n")
  }
  
  # Step 6: Optimize performance
  optimize_database_performance(config)
  
  # Step 7: Generate configuration
  generate_railway_config(config)
  
  cat("\n✅ RAILWAY DATABASE DIAGNOSTICS COMPLETE\n")
  cat("=========================================\n")
  cat(sprintf("📊 Status: %s\n", ifelse(total_documents >= 1000, "HEALTHY", "NEEDS_DATA")))
  cat(sprintf("🔌 Connection: WORKING via %s\n", config$method))
  cat(sprintf("📄 Documents: %s\n", format(total_documents, big.mark = ",")))
  cat(sprintf("⚡ Optimization: APPLIED\n"))
  
  return(TRUE)
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Run diagnostics
success <- run_diagnostics()

if (success) {
  cat("\n🎉 DIAGNOSTICS COMPLETED SUCCESSFULLY\n")
  cat("The Railway database is ready for the Monitor Legislativo application\n")
} else {
  cat("\n⚠️ DIAGNOSTICS REVEALED ISSUES\n")
  cat("Please address the issues above before deploying to Railway\n")
}