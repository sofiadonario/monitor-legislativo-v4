# Database-Only Data Loader
# Senior engineer approach: Use what exists - the real lexml_* database tables
# No CSV files, no compatibility layers, just direct database queries

load_database_only_data <- function() {
  cat("🔄 Loading data directly from database tables (senior engineer approach)\n")
  
  if (!database_connected || is.null(db_pool)) {
    cat("❌ Database not connected\n")
    return(FALSE)
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Get real data from the unified documents view (built from actual lexml_* tables)
    documents_data <- dbGetQuery(conn, "SELECT * FROM documents LIMIT 1000")
    cat("✅ Loaded", nrow(documents_data), "documents from database\n")
    
    # Create dashboard stats from real database data
    stats_query <- "
      SELECT 
        COUNT(*) as total_documents,
        COUNT(DISTINCT species) as document_types,
        COUNT(DISTINCT estado) as jurisdictions,
        COUNT(DISTINCT municipality) as municipalities,
        MIN(data_publicacao) as min_date,
        MAX(data_publicacao) as max_date
      FROM documents
    "
    
    stats_result <- dbGetQuery(conn, stats_query)
    
    final_dashboard_stats <- list(
      total_documents = as.numeric(stats_result$total_documents),
      document_types = as.numeric(stats_result$document_types), 
      jurisdictions = as.numeric(stats_result$jurisdictions),
      municipalities = as.numeric(stats_result$municipalities),
      date_range = list(
        min = as.Date(stats_result$min_date),
        max = as.Date(stats_result$max_date)
      ),
      documents_by_species = dbGetQuery(conn, "SELECT species, COUNT(*) as count FROM documents GROUP BY species"),
      documents_by_state = dbGetQuery(conn, "SELECT estado, COUNT(*) as count FROM documents WHERE estado IS NOT NULL GROUP BY estado")
    )
    
    cat("📊 Real database stats:\n")
    cat("  - Total documents:", final_dashboard_stats$total_documents, "\n")
    cat("  - Document types:", final_dashboard_stats$document_types, "\n")
    cat("  - Jurisdictions:", final_dashboard_stats$jurisdictions, "\n") 
    cat("  - Date range:", final_dashboard_stats$date_range$min, "to", final_dashboard_stats$date_range$max, "\n")
    
    # Make available globally (what app expects)
    assign("final_dashboard_stats", final_dashboard_stats, envir = .GlobalEnv)
    assign("documents_data", documents_data, envir = .GlobalEnv)
    
    cat("✅ Database-only data loading complete - no CSV files needed\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error loading database-only data:", e$message, "\n")
    return(FALSE)
  })
}

# Function to get documents directly from database (replaces CSV loading)
get_database_documents <- function(limit = NULL) {
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    query <- "SELECT * FROM documents ORDER BY data_publicacao DESC"
    if (!is.null(limit)) {
      query <- paste(query, "LIMIT", limit)
    }
    
    result <- dbGetQuery(conn, query)
    cat("📊 Retrieved", nrow(result), "documents from database\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error getting database documents:", e$message, "\n")
    return(data.frame())
  })
}

cat("✅ Database-only loader ready - uses real lexml_* tables\n")