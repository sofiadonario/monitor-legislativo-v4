# Simple Dashboard Fix - Replace complex functions with direct database queries

# Simple function to get document count
get_simple_document_count <- function() {
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      result <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
      return(as.numeric(result$count))
    }, error = function(e) {
      cat("Error getting document count:", e$message, "\n")
      return(0)
    })
  }
  return(0)
}

# Simple function to get jurisdiction count
get_simple_jurisdiction_count <- function() {
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      result <- dbGetQuery(conn, "SELECT COUNT(DISTINCT estado) as count FROM documents WHERE estado IS NOT NULL")
      return(as.numeric(result$count))
    }, error = function(e) {
      cat("Error getting jurisdiction count:", e$message, "\n")
      return(0)
    })
  }
  return(0)
}

# Simple function to get document type count
get_simple_type_count <- function() {
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      result <- dbGetQuery(conn, "SELECT COUNT(DISTINCT tipo) as count FROM documents WHERE tipo IS NOT NULL")
      return(as.numeric(result$count))
    }, error = function(e) {
      cat("Error getting type count:", e$message, "\n")
      return(0)
    })
  }
  return(0)
}

# Simple function to get map data
get_simple_map_data <- function() {
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      result <- dbGetQuery(conn, "
        SELECT 
          estado,
          COUNT(*) as count
        FROM documents 
        WHERE estado IS NOT NULL 
        GROUP BY estado 
        ORDER BY COUNT(*) DESC
      ")
      return(result)
    }, error = function(e) {
      cat("Error getting map data:", e$message, "\n")
      return(data.frame())
    })
  }
  return(data.frame())
}

cat("✅ Simple dashboard functions loaded\n")