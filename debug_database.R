# Debug Database Connection and Force Refresh
# This script tests the database connection and forces a refresh to ensure we get updated data

cat("=== DATABASE DEBUG AND FORCE REFRESH ===\n")
cat("Time:", Sys.time(), "\n\n")

# Load required libraries
library(DBI)
library(RPostgres)
library(pool)
library(dplyr)

# Load database connection module
source("R/database_connection.R")

cat("1. Testing initial database connection...\n")
database_connected <- init_database()

if (database_connected) {
  cat("✅ Initial connection successful\n")
  
  # Test direct queries to see what's in the database
  cat("\n2. Testing direct database queries...\n")
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Check documents table
    cat("   Checking documents table...\n")
    doc_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")$count
    cat("   Total documents:", doc_count, "\n")
    
    # Check for Amazonas specifically
    amazonas_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents WHERE estado = 'Amazonas'")$count
    cat("   Amazonas documents:", amazonas_count, "\n")
    
    # Check for documents with titles
    title_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents WHERE titulo IS NOT NULL")$count
    cat("   Documents with titles:", title_count, "\n")
    
    # Check for the corrected table/view
    cat("   Checking corrected table...\n")
    corrected_count <- tryCatch({
      dbGetQuery(conn, "SELECT COUNT(*) as count FROM lexml_parsed_enhanced_fixed")$count
    }, error = function(e) {
      cat("   ❌ Corrected table not found:", e$message, "\n")
      return("Table not found")
    })
    cat("   Corrected table count:", corrected_count, "\n")
    
    # Sample some documents
    cat("   Sampling documents...\n")
    sample_docs <- dbGetQuery(conn, "
      SELECT id, titulo, estado, data_publicacao 
      FROM documents 
      WHERE titulo IS NOT NULL 
      ORDER BY id DESC 
      LIMIT 5
    ")
    cat("   Sample documents:\n")
    print(sample_docs)
    
  }, error = function(e) {
    cat("❌ Error in direct queries:", e$message, "\n")
  })
  
  # Test the get_documents function
  cat("\n3. Testing get_documents() function...\n")
  tryCatch({
    documents <- get_documents(limit = 10)
    if (!is.null(documents)) {
      cat("   get_documents() returned", nrow(documents), "documents\n")
      cat("   Sample from get_documents():\n")
      print(head(documents, 3))
    } else {
      cat("   ❌ get_documents() returned NULL\n")
    }
  }, error = function(e) {
    cat("❌ Error in get_documents():", e$message, "\n")
  })
  
  # Test force refresh
  cat("\n4. Testing force refresh...\n")
  tryCatch({
    refresh_result <- force_refresh_database()
    if (refresh_result) {
      cat("✅ Force refresh successful\n")
      
      # Test get_documents again after refresh
      cat("   Testing get_documents() after refresh...\n")
      documents_after <- get_documents(limit = 10)
      if (!is.null(documents_after)) {
        cat("   get_documents() after refresh returned", nrow(documents_after), "documents\n")
      }
    } else {
      cat("❌ Force refresh failed\n")
    }
  }, error = function(e) {
    cat("❌ Error in force refresh:", e$message, "\n")
  })
  
} else {
  cat("❌ Initial connection failed\n")
}

cat("\n=== DEBUG COMPLETE ===\n")
cat("Final time:", Sys.time(), "\n") 