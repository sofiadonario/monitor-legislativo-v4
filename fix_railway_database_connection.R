#!/usr/bin/env Rscript
# ============================================================================
# RAILWAY DATABASE CONNECTION FIX SCRIPT
# ============================================================================
# 
# This script diagnoses and fixes database connectivity issues for the
# Brazilian Legislative Monitor dashboard deployed on Railway.
#
# This script:
# 1. Tests current database connectivity
# 2. Validates environment variables 
# 3. Checks data population status
# 4. Applies fixes for common Railway issues
# 5. Optimizes database performance
# 6. Provides deployment recommendations
#
# Usage: Rscript fix_railway_database_connection.R
# ============================================================================

cat("🔧 RAILWAY DATABASE CONNECTION FIX\n")
cat("===================================\n")

# Load required packages
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
})

# ============================================================================
# DIAGNOSTIC FUNCTIONS
# ============================================================================

#' Test current database connection
test_current_connection <- function() {
  cat("\n🔍 TESTING CURRENT DATABASE CONNECTION\n")
  cat("======================================\n")
  
  # Try to source the existing connection module
  connection_works <- FALSE
  document_count <- 0
  
  tryCatch({
    source("db/connection.R")
    
    # Check if connection was established
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      cat("✅ Database connection pool exists\n")
      
      # Test with a simple query
      test_result <- dbGetQuery(secure_db_pool, "SELECT 1 as test")
      if (nrow(test_result) == 1) {
        cat("✅ Database query test passed\n")
        connection_works <- TRUE
        
        # Get document count
        tryCatch({
          doc_result <- dbGetQuery(secure_db_pool, "SELECT COUNT(*) as count FROM documents")
          document_count <- doc_result$count[1]
          cat(sprintf("📊 Documents found: %s\n", format(document_count, big.mark = ",")))
        }, error = function(e) {
          cat("⚠️ Could not get document count:", e$message, "\n")
        })
      }
    }
  }, error = function(e) {
    cat("❌ Connection module failed:", e$message, "\n")
  })
  
  return(list(works = connection_works, document_count = document_count))
}

#' Check environment variables
check_environment_variables <- function() {
  cat("\n📋 ENVIRONMENT VARIABLES CHECK\n")
  cat("==============================\n")
  
  env_vars <- c(
    "DATABASE_URL", "PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD",
    "RAILWAY_ENVIRONMENT", "PORT"
  )
  
  env_status <- list()
  
  for (var in env_vars) {
    value <- Sys.getenv(var)
    if (nchar(value) > 0) {
      if (grepl("PASSWORD|password", var)) {
        cat(sprintf("✅ %s: SET (%d chars)\n", var, nchar(value)))
        env_status[[var]] <- "SET_HIDDEN"
      } else if (var == "DATABASE_URL") {
        cat(sprintf("✅ %s: SET (%s...)\n", var, substr(value, 1, 20)))
        env_status[[var]] <- value
      } else {
        cat(sprintf("✅ %s: %s\n", var, value))
        env_status[[var]] <- value
      }
    } else {
      cat(sprintf("❌ %s: NOT SET\n", var))
      env_status[[var]] <- NULL
    }
  }
  
  return(env_status)
}

#' Parse Railway DATABASE_URL
parse_railway_database_url <- function(database_url) {
  if (is.null(database_url) || nchar(database_url) == 0) {
    return(NULL)
  }
  
  tryCatch({
    # Handle both postgresql:// and postgres:// formats
    if (grepl("^(postgresql|postgres)://", database_url)) {
      # Remove protocol
      url_clean <- sub("^(postgresql|postgres)://", "", database_url)
      
      # Split auth@host/database
      if (grepl("@", url_clean)) {
        parts <- strsplit(url_clean, "@")[[1]]
        auth_part <- parts[1]
        connection_part <- parts[2]
        
        # Parse auth
        if (grepl(":", auth_part)) {
          auth_split <- strsplit(auth_part, ":")[[1]]
          user <- auth_split[1]
          password <- auth_split[2]
        } else {
          user <- auth_part
          password <- ""
        }
        
        # Parse connection
        if (grepl("/", connection_part)) {
          connection_split <- strsplit(connection_part, "/")[[1]]
          host_port <- connection_split[1]
          database <- connection_split[2]
          
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
            database = database,
            user = user,
            password = password
          ))
        }
      }
    }
    
    cat("⚠️ Could not parse DATABASE_URL format\n")
    return(NULL)
    
  }, error = function(e) {
    cat("❌ Error parsing DATABASE_URL:", e$message, "\n")
    return(NULL)
  })
}

#' Create optimized connection for Railway
create_railway_connection <- function(config) {
  cat("\n🔌 CREATING OPTIMIZED RAILWAY CONNECTION\n")
  cat("========================================\n")
  
  if (is.null(config)) {
    cat("❌ No database configuration provided\n")
    return(NULL)
  }
  
  cat(sprintf("📡 Connecting to: %s:%d/%s\n", config$host, config$port, config$database))
  cat(sprintf("👤 User: %s\n", config$user))
  
  # Try different connection methods
  connection_methods <- list(
    list(name = "Standard Connection", sslmode = "prefer"),
    list(name = "SSL Disabled", sslmode = "disable"),
    list(name = "SSL Required", sslmode = "require")
  )
  
  for (method in connection_methods) {
    cat(sprintf("\n🔄 Trying: %s (SSL: %s)\n", method$name, method$sslmode))
    
    tryCatch({
      con <- dbConnect(
        RPostgres::Postgres(),
        host = config$host,
        port = config$port,
        dbname = config$database,
        user = config$user,
        password = config$password,
        sslmode = method$sslmode,
        connect_timeout = 30,
        application_name = "railway_fix_test"
      )
      
      # Test the connection
      version_result <- dbGetQuery(con, "SELECT version() as version")
      cat("✅ Connection successful!\n")
      cat(sprintf("📊 PostgreSQL: %s\n", substr(version_result$version[1], 1, 60)))
      
      # Check SSL status
      tryCatch({
        ssl_result <- dbGetQuery(con, "SELECT current_setting('ssl') as ssl_status")
        cat(sprintf("🔒 SSL Status: %s\n", ssl_result$ssl_status[1]))
      }, error = function(e) {})
      
      return(con)
      
    }, error = function(e) {
      cat(sprintf("❌ %s failed: %s\n", method$name, e$message))
    })
  }
  
  cat("❌ All connection methods failed\n")
  return(NULL)
}

#' Check database schema and tables
check_database_schema <- function(con) {
  cat("\n📊 DATABASE SCHEMA ANALYSIS\n")
  cat("============================\n")
  
  if (is.null(con)) {
    cat("❌ No database connection available\n")
    return(NULL)
  }
  
  tryCatch({
    # List all tables in public schema
    tables_query <- "
      SELECT 
        tablename,
        schemaname,
        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
      FROM pg_tables 
      WHERE schemaname = 'public'
      ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
    "
    
    tables <- dbGetQuery(con, tables_query)
    
    cat(sprintf("📋 Found %d tables in public schema:\n", nrow(tables)))
    
    if (nrow(tables) > 0) {
      for (i in 1:nrow(tables)) {
        cat(sprintf("  %d. %s (%s)\n", i, tables$tablename[i], tables$size[i]))
      }
    } else {
      cat("⚠️ No tables found in public schema\n")
    }
    
    # Check for document tables specifically
    document_tables <- c("documents", "lexml_parsed_enhanced", "legislative_data", "brazilian_legislative_complete")
    
    table_status <- list()
    max_documents <- 0
    primary_table <- NULL
    
    for (table_name in document_tables) {
      tryCatch({
        count_query <- sprintf("SELECT COUNT(*) as count FROM %s", table_name)
        count_result <- dbGetQuery(con, count_query)
        
        if (nrow(count_result) > 0) {
          count <- count_result$count[1]
          table_status[[table_name]] <- count
          
          cat(sprintf("✅ %s: %s records\n", table_name, format(count, big.mark = ",")))
          
          if (count > max_documents) {
            max_documents <- count
            primary_table <- table_name
          }
          
          # Get column info
          columns_query <- sprintf("
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = '%s' AND table_schema = 'public'
            ORDER BY ordinal_position
          ", table_name)
          
          columns <- dbGetQuery(con, columns_query)
          key_columns <- c("titulo", "title", "ementa", "summary", "data", "date")
          found_key_columns <- intersect(columns$column_name, key_columns)
          
          if (length(found_key_columns) > 0) {
            cat(sprintf("   📋 Key columns: %s\n", paste(found_key_columns, collapse = ", ")))
          }
        }
        
      }, error = function(e) {
        cat(sprintf("❌ %s: Not accessible (%s)\n", table_name, e$message))
        table_status[[table_name]] <- 0
      })
    }
    
    cat(sprintf("\n📈 SUMMARY:\n"))
    cat(sprintf("  Primary table: %s\n", if(is.null(primary_table)) "None" else primary_table))
    cat(sprintf("  Max documents: %s\n", format(max_documents, big.mark = ",")))
    cat(sprintf("  Expected: 134,000+\n"))
    
    if (max_documents < 1000) {
      cat(sprintf("⚠️ WARNING: Document count is very low (%d)\n", max_documents))
      cat("💡 The database may need to be populated with data\n")
    } else {
      cat("✅ Document count looks reasonable\n")
    }
    
    return(list(
      tables = tables,
      document_counts = table_status,
      primary_table = primary_table,
      max_documents = max_documents
    ))
    
  }, error = function(e) {
    cat("❌ Schema analysis failed:", e$message, "\n")
    return(NULL)
  })
}

#' Apply performance optimizations
optimize_database_performance <- function(con) {
  cat("\n⚡ APPLYING PERFORMANCE OPTIMIZATIONS\n")
  cat("=====================================\n")
  
  if (is.null(con)) {
    cat("❌ No database connection available\n")
    return(FALSE)
  }
  
  # Performance optimization queries
  optimizations <- list(
    list(
      name = "Full-text search index on titulo",
      sql = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_titulo_gin ON documents USING gin(to_tsvector('portuguese', titulo))"
    ),
    list(
      name = "Full-text search index on ementa",
      sql = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_ementa_gin ON documents USING gin(to_tsvector('portuguese', ementa))"
    ),
    list(
      name = "Estado filter index",
      sql = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_estado ON documents(estado)"
    ),
    list(
      name = "Data publication index",
      sql = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_data ON documents(data_publicacao DESC)"
    ),
    list(
      name = "Composite estado+data index",
      sql = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_estado_data ON documents(estado, data_publicacao DESC)"
    ),
    list(
      name = "Document type index",
      sql = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_tipo ON documents(tipo)"
    )
  )
  
  applied_count <- 0
  
  for (opt in optimizations) {
    tryCatch({
      cat(sprintf("🔧 Applying: %s... ", opt$name))
      dbExecute(con, opt$sql)
      cat("✅ SUCCESS\n")
      applied_count <- applied_count + 1
    }, error = function(e) {
      if (grepl("already exists", e$message, ignore.case = TRUE)) {
        cat("ℹ️ Already exists\n")
        applied_count <- applied_count + 1
      } else {
        cat(sprintf("❌ FAILED: %s\n", e$message))
      }
    })
  }
  
  # Update table statistics
  tryCatch({
    cat("📊 Updating table statistics... ")
    dbExecute(con, "ANALYZE documents")
    cat("✅ SUCCESS\n")
  }, error = function(e) {
    cat(sprintf("❌ FAILED: %s\n", e$message))
  })
  
  cat(sprintf("🎯 Applied %d/%d optimizations successfully\n", applied_count, length(optimizations)))
  return(applied_count > 0)
}

#' Generate Railway deployment recommendations
generate_deployment_recommendations <- function(schema_info, env_status) {
  cat("\n📝 DEPLOYMENT RECOMMENDATIONS\n")
  cat("=============================\n")
  
  recommendations <- c()
  
  # Check document count
  if (!is.null(schema_info) && schema_info$max_documents < 1000) {
    recommendations <- c(recommendations, 
      "🔴 CRITICAL: Database has very few documents. Run migration script to populate data.")
  }
  
  # Check environment variables
  if (is.null(env_status$DATABASE_URL)) {
    recommendations <- c(recommendations,
      "🟡 DATABASE_URL not set. Ensure Railway PostgreSQL service is properly linked.")
  }
  
  if (is.null(env_status$RAILWAY_ENVIRONMENT)) {
    recommendations <- c(recommendations,
      "🟡 RAILWAY_ENVIRONMENT not set. Set to 'production' for Railway deployment.")
  }
  
  # Performance recommendations
  recommendations <- c(recommendations,
    "🔵 Run 'Rscript railway_database_migration.R' to populate the database with full dataset.",
    "🔵 Run 'Rscript railway_database_diagnostics.R' for comprehensive health check.",
    "🔵 Monitor Railway logs for connection issues and memory usage.",
    "🔵 Consider upgrading Railway plan if experiencing memory limitations."
  )
  
  cat("📋 Action Items:\n")
  for (i in seq_along(recommendations)) {
    cat(sprintf("  %d. %s\n", i, recommendations[i]))
  }
  
  return(recommendations)
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

#' Main fix routine
main_fix <- function() {
  cat("🚀 Starting Railway database connection fix...\n")
  
  # Step 1: Test current connection
  current_status <- test_current_connection()
  
  # Step 2: Check environment variables
  env_status <- check_environment_variables()
  
  # Step 3: Try to establish new connection
  database_url <- env_status$DATABASE_URL
  config <- NULL
  
  if (!is.null(database_url)) {
    config <- parse_railway_database_url(database_url)
  }
  
  # If no DATABASE_URL, try individual variables
  if (is.null(config)) {
    if (!is.null(env_status$PGHOST) && !is.null(env_status$PGUSER)) {
      config <- list(
        host = env_status$PGHOST,
        port = as.integer(if(is.null(env_status$PGPORT)) "5432" else env_status$PGPORT),
        database = if(is.null(env_status$PGDATABASE)) "railway" else env_status$PGDATABASE,
        user = env_status$PGUSER,
        password = if(is.null(env_status$PGPASSWORD)) "" else env_status$PGPASSWORD
      )
    }
  }
  
  # Step 4: Test connection with optimized settings
  con <- create_railway_connection(config)
  
  # Step 5: Analyze database schema
  schema_info <- NULL
  if (!is.null(con)) {
    schema_info <- check_database_schema(con)
    
    # Step 6: Apply optimizations
    optimize_database_performance(con)
  }
  
  # Step 7: Generate recommendations
  recommendations <- generate_deployment_recommendations(schema_info, env_status)
  
  # Step 8: Cleanup
  if (!is.null(con)) {
    tryCatch({
      dbDisconnect(con)
      cat("🔌 Test connection closed\n")
    }, error = function(e) {})
  }
  
  # Step 9: Final summary
  cat("\n🎯 FIX SUMMARY\n")
  cat("==============\n")
  
  if (current_status$works && current_status$document_count >= 1000) {
    cat("✅ DATABASE STATUS: HEALTHY\n")
    cat(sprintf("📊 Documents available: %s\n", format(current_status$document_count, big.mark = ",")))
    cat("🎉 Your Railway deployment should work correctly!\n")
  } else if (current_status$works && current_status$document_count < 1000) {
    cat("🟡 DATABASE STATUS: CONNECTED BUT LOW DATA\n") 
    cat(sprintf("📊 Documents available: %s (expected 134,000+)\n", format(current_status$document_count, big.mark = ",")))
    cat("💡 Run data migration to populate the database\n")
  } else {
    cat("🔴 DATABASE STATUS: CONNECTION ISSUES\n")
    cat("💡 Follow the recommendations above to resolve connection issues\n")
  }
  
  cat("\n📚 Next Steps:\n")
  cat("1. Address any critical recommendations above\n")
  cat("2. Run: Rscript railway_database_migration.R (if data is missing)\n")
  cat("3. Run: Rscript railway_database_diagnostics.R (for health check)\n")
  cat("4. Deploy to Railway and monitor logs\n")
  cat("5. Test the deployed application\n")
}

# Execute main fix
main_fix()