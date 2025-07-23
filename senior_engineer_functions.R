# Senior Engineer Functions - Use specific tables for specific purposes
# No complexity, just direct queries to the right tables

# Dashboard metrics from lexml_documents (129,328 records)
get_main_dashboard_stats <- function() {
  if (!database_connected || is.null(db_pool)) {
    return(list(total_documents = 0, jurisdictions = 0, municipalities = 0))
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Document count from main table
    total_docs <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM lexml_documents")$count
    
    # Jurisdiction count from main table  
    jurisdictions <- dbGetQuery(conn, "SELECT COUNT(DISTINCT jurisdicao) as count FROM lexml_documents WHERE jurisdicao IS NOT NULL")$count
    
    # Municipality count from main table
    municipalities <- dbGetQuery(conn, "SELECT COUNT(DISTINCT localidade) as count FROM lexml_documents WHERE localidade IS NOT NULL AND localidade != ''")$count
    
    # Date range from main table
    date_range <- dbGetQuery(conn, "SELECT MIN(data) as min_date, MAX(data) as max_date FROM lexml_documents WHERE data IS NOT NULL")
    
    cat("📊 Main dashboard stats from lexml_documents:\n")
    cat("  - Total documents:", total_docs, "\n")
    cat("  - Jurisdictions:", jurisdictions, "\n")
    cat("  - Municipalities:", municipalities, "\n")
    cat("  - Date range:", date_range$min_date, "to", date_range$max_date, "\n")
    
    return(list(
      total_documents = as.numeric(total_docs),
      jurisdictions = as.numeric(jurisdictions),
      municipalities = as.numeric(municipalities),
      date_range = list(
        min = as.Date(date_range$min_date),
        max = as.Date(date_range$max_date)
      )
    ))
    
  }, error = function(e) {
    cat("❌ Error getting main dashboard stats:", e$message, "\n")
    return(list(total_documents = 0, jurisdictions = 0, municipalities = 0))
  })
}

# Interactive Map 1 data - from lexml_documents
get_map1_data <- function() {
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    result <- dbGetQuery(conn, "
      SELECT 
        jurisdicao as estado,
        COUNT(*) as count
      FROM lexml_documents 
      WHERE jurisdicao IS NOT NULL 
      GROUP BY jurisdicao 
      ORDER BY count DESC
    ")
    
    cat("📊 Map 1 data from lexml_documents:", nrow(result), "jurisdictions\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error getting map 1 data:", e$message, "\n")
    return(data.frame())
  })
}

# Interactive Map 2 data - from legislative tables
get_map2_data <- function() {
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    result <- dbGetQuery(conn, "
      SELECT 
        estado,
        modal,
        COUNT(*) as count
      FROM legislative_documents 
      WHERE estado IS NOT NULL 
      GROUP BY estado, modal 
      ORDER BY count DESC
    ")
    
    cat("📊 Map 2 data from legislative tables:", nrow(result), "rows\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error getting map 2 data:", e$message, "\n")
    return(data.frame())
  })
}

# Interactive Map 3 data - from jurisprudence tables
get_map3_data <- function() {
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    result <- dbGetQuery(conn, "
      SELECT 
        estado,
        modal,
        COUNT(*) as count
      FROM jurisprudence_documents 
      WHERE estado IS NOT NULL 
      GROUP BY estado, modal 
      ORDER BY count DESC
    ")
    
    cat("📊 Map 3 data from jurisprudence tables:", nrow(result), "rows\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error getting map 3 data:", e$message, "\n")
    return(data.frame())
  })
}

# Initialize dashboard with senior engineer approach
initialize_senior_dashboard <- function() {
  cat("🔄 Initializing dashboard with senior engineer approach\n")
  
  # Get main stats from lexml_documents
  main_stats <- get_main_dashboard_stats()
  
  # Create the global object the app expects
  final_dashboard_stats <- list(
    total_documents = main_stats$total_documents,
    document_types = 3, # We have 3 main categories
    jurisdictions = main_stats$jurisdictions,
    municipalities = main_stats$municipalities,
    date_range = main_stats$date_range
  )
  
  # Make it globally available
  assign("final_dashboard_stats", final_dashboard_stats, envir = .GlobalEnv)
  
  cat("✅ Senior engineer dashboard initialized\n")
  cat("📊 Documents:", final_dashboard_stats$total_documents, "\n")
  cat("📊 Jurisdictions:", final_dashboard_stats$jurisdictions, "\n")
  
  return(TRUE)
}

cat("✅ Senior engineer functions loaded - table-specific queries ready\n")