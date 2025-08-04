#!/usr/bin/env Rscript
# ============================================================================
# RAILWAY LIBRARY DIAGNOSTIC SCRIPT
# ============================================================================
# This script diagnoses why only 5 documents are showing in the library
# despite 134k documents being loaded successfully.

cat("🔍 STARTING RAILWAY LIBRARY DIAGNOSTIC\n")
cat("=====================================\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(dplyr)
})

# Railway connection configuration (same as production)
RAILWAY_DB_CONFIG <- list(
  host = "postgres.railway.internal",
  port = 5432L,
  dbname = "railway", 
  user = "postgres",
  password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY",
  connect_timeout = 30L
)

cat("🔌 Connecting to Railway PostgreSQL...\n")

# Establish connection
tryCatch({
  conn <- dbConnect(
    RPostgres::Postgres(),
    host = RAILWAY_DB_CONFIG$host,
    port = RAILWAY_DB_CONFIG$port,
    dbname = RAILWAY_DB_CONFIG$dbname,
    user = RAILWAY_DB_CONFIG$user,
    password = RAILWAY_DB_CONFIG$password,
    connect_timeout = RAILWAY_DB_CONFIG$connect_timeout
  )
  
  cat("✅ Connected to Railway database successfully\n\n")
  
  # 1. Check what tables exist
  cat("📋 CHECKING AVAILABLE TABLES:\n")
  cat("=============================\n")
  
  tables_query <- "
    SELECT table_name, 
           pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
    FROM pg_tables 
    WHERE schemaname = 'public' 
    ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
  "
  
  tables <- dbGetQuery(conn, tables_query)
  print(tables)
  
  # 2. Check document counts in each table
  cat("\n📊 DOCUMENT COUNTS BY TABLE:\n")
  cat("============================\n")
  
  for(table in tables$table_name) {
    tryCatch({
      count_query <- sprintf("SELECT COUNT(*) as count FROM %s", table)
      result <- dbGetQuery(conn, count_query)
      cat(sprintf("%-30s: %s rows\n", table, format(result$count, big.mark = ",")))
    }, error = function(e) {
      cat(sprintf("%-30s: ERROR - %s\n", table, e$message))
    })
  }
  
  # 3. Check the specific query used by get_library_documents
  cat("\n🔍 TESTING LIBRARY QUERY LOGIC:\n")
  cat("===============================\n")
  
  # Test the exact query from the production code
  library_query <- "
    SELECT 
      COALESCE(titulo, title, '') as title,
      COALESCE(categoria, category, tipo, 'Unknown') as category,
      COALESCE(estado, state, 'Unknown') as state, 
      COALESCE(data_publicacao, data, created_at::date) as date,
      COALESCE(url, '') as url,
      COALESCE(ementa, summary, resumo, '') as summary,
      COALESCE(urn, '') as urn,
      COALESCE(municipio, municipality, '') as municipality,
      COALESCE(tipo, document_type, 'Document') as document_type
    FROM (
      SELECT * FROM documents
      UNION ALL 
      SELECT titulo, categoria, estado, data_publicacao, url, ementa, urn, municipio, tipo FROM lexml_parsed_enhanced
      UNION ALL
      SELECT titulo, categoria, estado, data, url, resumo, urn, municipio, tipo FROM legislative_data
    ) combined_docs
    WHERE titulo IS NOT NULL AND titulo != ''
    ORDER BY date DESC NULLS LAST
    LIMIT 100
  "
  
  tryCatch({
    cat("Testing full library query...\n")
    library_result <- dbGetQuery(conn, library_query)
    cat(sprintf("✅ Library query returned: %d documents\n", nrow(library_result)))
    
    if(nrow(library_result) > 0) {
      cat("\n📄 Sample documents from library query:\n")
      for(i in 1:min(5, nrow(library_result))) {
        cat(sprintf("  %d. %s (%s)\n", i, 
                    substr(library_result$title[i], 1, 60), 
                    library_result$category[i]))
      }
    }
  }, error = function(e) {
    cat(sprintf("❌ Library query failed: %s\n", e$message))
    
    # Try each table individually
    cat("\n🔍 Testing individual tables:\n")
    
    # Test documents table
    tryCatch({
      doc_test <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents WHERE titulo IS NOT NULL AND titulo != '' LIMIT 5")
      cat(sprintf("documents table: %d documents\n", doc_test$count))
    }, error = function(e) {
      cat(sprintf("documents table: ERROR - %s\n", e$message))
    })
    
    # Test lexml_parsed_enhanced table
    tryCatch({
      lexml_test <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM lexml_parsed_enhanced WHERE titulo IS NOT NULL AND titulo != '' LIMIT 5")
      cat(sprintf("lexml_parsed_enhanced table: %d documents\n", lexml_test$count))
    }, error = function(e) {
      cat(sprintf("lexml_parsed_enhanced table: ERROR - %s\n", e$message))
    })
    
    # Test legislative_data table
    tryCatch({
      leg_test <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM legislative_data WHERE titulo IS NOT NULL AND titulo != '' LIMIT 5")
      cat(sprintf("legislative_data table: %d documents\n", leg_test$count))
    }, error = function(e) {
      cat(sprintf("legislative_data table: ERROR - %s\n", e$message))
    })
  })
  
  # 4. Check for the main table with 134k documents
  cat("\n🎯 FINDING THE MAIN DATA TABLE:\n")
  cat("===============================\n")
  
  main_tables <- c("lexml_parsed_enhanced", "documents", "legislative_data", "brazilian_legislative_complete")
  
  for(table in main_tables) {
    tryCatch({
      # Check if table exists and has data
      exists_query <- sprintf("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '%s')", table)
      table_exists <- dbGetQuery(conn, exists_query)$exists
      
      if(table_exists) {
        count_query <- sprintf("SELECT COUNT(*) as count FROM %s", table)
        result <- dbGetQuery(conn, count_query)
        
        cat(sprintf("%-30s: %s rows", table, format(result$count, big.mark = ",")))
        
        if(result$count > 100000) {
          cat(" ⭐ MAIN TABLE CANDIDATE")
          
          # Check column structure
          cols_query <- sprintf("SELECT column_name FROM information_schema.columns WHERE table_name = '%s' ORDER BY ordinal_position", table)
          cols <- dbGetQuery(conn, cols_query)
          cat(sprintf("\n  Columns: %s", paste(cols$column_name, collapse = ", ")))
          
          # Test a simple select
          test_query <- sprintf("SELECT * FROM %s WHERE titulo IS NOT NULL AND titulo != '' LIMIT 5", table)
          tryCatch({
            test_result <- dbGetQuery(conn, test_query)
            cat(sprintf("\n  Sample query returned: %d rows", nrow(test_result)))
            if(nrow(test_result) > 0) {
              cat(sprintf("\n  First title: %s", substr(test_result$titulo[1], 1, 50)))
            }
          }, error = function(e) {
            cat(sprintf("\n  Sample query error: %s", e$message))
          })
        }
        cat("\n")
      } else {
        cat(sprintf("%-30s: TABLE DOES NOT EXIST\n", table))
      }
    }, error = function(e) {
      cat(sprintf("%-30s: ERROR - %s\n", table, e$message))
    })
  }
  
  # 5. Check if there's a LIMIT issue in the query
  cat("\n🚨 CHECKING FOR QUERY LIMITS:\n")
  cat("=============================\n")
  
  # Find the table with the most data
  max_count <- 0
  main_table <- NULL
  
  for(table in main_tables) {
    tryCatch({
      exists_query <- sprintf("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '%s')", table)
      table_exists <- dbGetQuery(conn, exists_query)$exists
      
      if(table_exists) {
        count_query <- sprintf("SELECT COUNT(*) as count FROM %s", table)
        result <- dbGetQuery(conn, count_query)
        
        if(result$count > max_count) {
          max_count <- result$count
          main_table <- table
        }
      }
    }, error = function(e) {
      # Skip table on error
    })
  }
  
  if(!is.null(main_table) && max_count > 0) {
    cat(sprintf("Main table identified: %s with %s rows\n", main_table, format(max_count, big.mark = ",")))
    
    # Test different limits
    for(limit in c(5, 10, 25, 100, 1000)) {
      tryCatch({
        test_query <- sprintf("SELECT titulo FROM %s WHERE titulo IS NOT NULL AND titulo != '' LIMIT %d", main_table, limit)
        result <- dbGetQuery(conn, test_query)
        cat(sprintf("  LIMIT %4d: %d rows returned\n", limit, nrow(result)))
      }, error = function(e) {
        cat(sprintf("  LIMIT %4d: ERROR - %s\n", limit, e$message))
      })
    }
  }
  
  # 6. Investigate the exact issue with the library function
  cat("\n🔧 LIBRARY FUNCTION DEBUGGING:\n")
  cat("==============================\n")
  
  # Recreate the exact conditions from the app
  cat("Testing with default parameters (category='all', search_term='', state='all', limit=100)...\n")
  
  if(!is.null(main_table)) {
    # Test direct query on main table
    direct_query <- sprintf("
      SELECT titulo as title, 
             categoria as category, 
             estado as state,
             data_publicacao as date,
             url,
             ementa as summary,
             urn,
             municipio as municipality,
             tipo as document_type
      FROM %s 
      WHERE titulo IS NOT NULL AND titulo != ''
      ORDER BY data_publicacao DESC NULLS LAST
      LIMIT 100
    ", main_table)
    
    tryCatch({
      direct_result <- dbGetQuery(conn, direct_query)
      cat(sprintf("✅ Direct query on %s returned: %d documents\n", main_table, nrow(direct_result)))
      
      if(nrow(direct_result) == 5) {
        cat("🚨 FOUND THE ISSUE: Query is returning exactly 5 rows!\n")
        cat("This suggests there might be a LIMIT 5 hardcoded somewhere or a data filtering issue.\n")
        
        # Check if there are more rows without the WHERE clause
        count_query <- sprintf("SELECT COUNT(*) as count FROM %s", main_table)
        total_result <- dbGetQuery(conn, count_query)
        cat(sprintf("Total rows in table: %s\n", format(total_result$count, big.mark = ",")))
        
        # Check how many have non-null titles
        valid_query <- sprintf("SELECT COUNT(*) as count FROM %s WHERE titulo IS NOT NULL AND titulo != ''", main_table)
        valid_result <- dbGetQuery(conn, valid_query)
        cat(sprintf("Rows with valid titles: %s\n", format(valid_result$count, big.mark = ",")))
        
      }
    }, error = function(e) {
      cat(sprintf("❌ Direct query failed: %s\n", e$message))
    })
  }
  
  cat("\n✅ DIAGNOSTIC COMPLETE\n")
  cat("======================\n")
  
  # Close connection
  dbDisconnect(conn)
  
}, error = function(e) {
  cat(sprintf("❌ Failed to connect to Railway database: %s\n", e$message))
  cat("Check that Railway service is running and credentials are correct.\n")
})

cat("\n🎯 DIAGNOSTIC FINISHED\n")