# Dashboard Debug Fix - Enhanced logging and fallback functions
# This file provides debug-enabled versions of dashboard functions

# Enhanced function to get document count with extensive logging
get_debug_document_count <- function() {
  cat("🔍 DEBUG: get_debug_document_count() called\n")
  cat("🔍 DEBUG: database_connected =", database_connected, "\n")
  cat("🔍 DEBUG: db_pool is null =", is.null(db_pool), "\n")
  
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      cat("🔍 DEBUG: Attempting to checkout connection from pool\n")
      conn <- poolCheckout(db_pool)
      on.exit({
        cat("🔍 DEBUG: Returning connection to pool\n")
        poolReturn(conn)
      })
      
      cat("🔍 DEBUG: Executing count query\n")
      result <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
      cat("🔍 DEBUG: Query result:", str(result), "\n")
      
      count <- as.numeric(result$count)
      cat("🔍 DEBUG: Final count:", count, "\n")
      return(count)
    }, error = function(e) {
      cat("❌ DEBUG: Error in get_debug_document_count:", e$message, "\n")
      cat("❌ DEBUG: Error class:", class(e), "\n")
      return(0)
    })
  } else {
    cat("🔍 DEBUG: Database not connected or pool is null\n")
    return(0)
  }
}

# Enhanced function to get jurisdiction count with extensive logging
get_debug_jurisdiction_count <- function() {
  cat("🔍 DEBUG: get_debug_jurisdiction_count() called\n")
  cat("🔍 DEBUG: database_connected =", database_connected, "\n")
  cat("🔍 DEBUG: db_pool is null =", is.null(db_pool), "\n")
  
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      cat("🔍 DEBUG: Attempting to checkout connection from pool\n")
      conn <- poolCheckout(db_pool)
      on.exit({
        cat("🔍 DEBUG: Returning connection to pool\n")
        poolReturn(conn)
      })
      
      cat("🔍 DEBUG: Executing jurisdiction count query\n")
      result <- dbGetQuery(conn, "SELECT COUNT(DISTINCT estado) as count FROM documents WHERE estado IS NOT NULL")
      cat("🔍 DEBUG: Jurisdiction query result:", str(result), "\n")
      
      # Also get the actual jurisdiction values for debugging
      jurisdictions <- dbGetQuery(conn, "SELECT DISTINCT estado FROM documents WHERE estado IS NOT NULL ORDER BY estado")
      cat("🔍 DEBUG: Available jurisdictions:", paste(jurisdictions$estado, collapse = ", "), "\n")
      
      count <- as.numeric(result$count)
      cat("🔍 DEBUG: Final jurisdiction count:", count, "\n")
      return(count)
    }, error = function(e) {
      cat("❌ DEBUG: Error in get_debug_jurisdiction_count:", e$message, "\n")
      cat("❌ DEBUG: Error class:", class(e), "\n")
      return(0)
    })
  } else {
    cat("🔍 DEBUG: Database not connected or pool is null\n")
    return(0)
  }
}

# Enhanced function to get document type count with extensive logging
get_debug_type_count <- function() {
  cat("🔍 DEBUG: get_debug_type_count() called\n")
  cat("🔍 DEBUG: database_connected =", database_connected, "\n")
  cat("🔍 DEBUG: db_pool is null =", is.null(db_pool), "\n")
  
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      cat("🔍 DEBUG: Attempting to checkout connection from pool\n")
      conn <- poolCheckout(db_pool)
      on.exit({
        cat("🔍 DEBUG: Returning connection to pool\n")
        poolReturn(conn)
      })
      
      cat("🔍 DEBUG: Executing type count query\n")
      result <- dbGetQuery(conn, "SELECT COUNT(DISTINCT tipo) as count FROM documents WHERE tipo IS NOT NULL AND tipo != ''")
      cat("🔍 DEBUG: Type query result:", str(result), "\n")
      
      # Also get the actual document types for debugging
      types <- dbGetQuery(conn, "SELECT DISTINCT tipo, COUNT(*) as count FROM documents WHERE tipo IS NOT NULL AND tipo != '' GROUP BY tipo ORDER BY COUNT(*) DESC LIMIT 10")
      cat("🔍 DEBUG: Top document types:\n")
      for(i in 1:min(nrow(types), 10)) {
        cat("  ", types$tipo[i], ":", types$count[i], "\n")
      }
      
      count <- as.numeric(result$count)
      cat("🔍 DEBUG: Final type count:", count, "\n")
      return(count)
    }, error = function(e) {
      cat("❌ DEBUG: Error in get_debug_type_count:", e$message, "\n")
      cat("❌ DEBUG: Error class:", class(e), "\n")
      return(0)
    })
  } else {
    cat("🔍 DEBUG: Database not connected or pool is null\n")
    return(0)
  }
}

# Enhanced function to get map data with extensive logging
get_debug_map_data <- function() {
  cat("🔍 DEBUG: get_debug_map_data() called\n")
  cat("🔍 DEBUG: database_connected =", database_connected, "\n")
  cat("🔍 DEBUG: db_pool is null =", is.null(db_pool), "\n")
  
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      cat("🔍 DEBUG: Attempting to checkout connection from pool\n")
      conn <- poolCheckout(db_pool)
      on.exit({
        cat("🔍 DEBUG: Returning connection to pool\n")
        poolReturn(conn)
      })
      
      cat("🔍 DEBUG: Executing map data query\n")
      result <- dbGetQuery(conn, "
        SELECT 
          estado,
          estado as estado_codigo,
          COUNT(*) as count
        FROM documents 
        WHERE estado IS NOT NULL 
        GROUP BY estado 
        ORDER BY COUNT(*) DESC
      ")
      
      cat("🔍 DEBUG: Map data query result - rows:", nrow(result), "\n")
      if (nrow(result) > 0) {
        cat("🔍 DEBUG: Map data sample:\n")
        print(head(result))
        cat("🔍 DEBUG: Total documents in map:", sum(result$count), "\n")
      }
      
      return(result)
    }, error = function(e) {
      cat("❌ DEBUG: Error in get_debug_map_data:", e$message, "\n")
      cat("❌ DEBUG: Error class:", class(e), "\n")
      return(data.frame())
    })
  } else {
    cat("🔍 DEBUG: Database not connected or pool is null\n")
    return(data.frame())
  }
}

# Test database connection function
test_database_connection <- function() {
  cat("🔍 DEBUG: Testing database connection...\n")
  cat("🔍 DEBUG: DATABASE_URL env var length:", nchar(Sys.getenv("DATABASE_URL")), "\n")
  
  if (exists("db_pool") && !is.null(db_pool)) {
    tryCatch({
      cat("🔍 DEBUG: Pool exists, testing with simple query\n")
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      
      # Test basic connection
      test_result <- dbGetQuery(conn, "SELECT 1 as test")
      cat("✅ DEBUG: Basic connection test passed:", test_result$test, "\n")
      
      # Test documents table exists
      table_check <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM information_schema.tables WHERE table_name = 'documents'")
      cat("🔍 DEBUG: Documents table exists:", table_check$count > 0, "\n")
      
      if (table_check$count > 0) {
        # Test documents table has data
        doc_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
        cat("🔍 DEBUG: Documents table row count:", doc_count$count, "\n")
        
        # Sample some data
        sample_data <- dbGetQuery(conn, "SELECT titulo, estado, tipo FROM documents LIMIT 3")
        cat("🔍 DEBUG: Sample documents:\n")
        print(sample_data)
      }
      
      return(TRUE)
    }, error = function(e) {
      cat("❌ DEBUG: Database connection test failed:", e$message, "\n")
      return(FALSE)
    })
  } else {
    cat("❌ DEBUG: db_pool does not exist or is null\n")
    return(FALSE)
  }
}

cat("✅ Dashboard debug functions loaded\n")