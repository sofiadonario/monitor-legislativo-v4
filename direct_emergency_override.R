# Direct Emergency Override
# Directly overrides the functions that are actually being called in the app

cat("🚨 DIRECT EMERGENCY OVERRIDE - Replacing actual called functions\n")

# ============================================================================
# 1. OVERRIDE THE ACTUAL FUNCTIONS BEING CALLED
# ============================================================================

#' Override get_lexml_dashboard_metrics with emergency version
#' This is the function actually being called in the value boxes
get_lexml_dashboard_metrics <- function(db_pool = NULL) {
  cat("🔄 get_lexml_dashboard_metrics called - using emergency override\n")
  
  if (!database_connected || is.null(db_pool)) {
    cat("⚠️ Database not connected in get_lexml_dashboard_metrics\n")
    return(list(
      total_documents = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      date_range = "Database not connected"
    ))
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Use unified documents view instead of broken lexml_* tables
    result <- dbGetQuery(conn, "
      SELECT 
        COUNT(*) as total_docs,
        COUNT(DISTINCT estado) as states_with_docs,
        COUNT(DISTINCT municipality) as municipalities_with_docs,
        MIN(data_publicacao) as min_date,
        MAX(data_publicacao) as max_date
      FROM documents 
      WHERE estado IS NOT NULL
    ")
    
    # Calculate date range
    date_range <- "No date range"
    if (!is.na(result$min_date) && !is.na(result$max_date)) {
      date_range <- paste0(
        format(as.Date(result$min_date), "%Y-%m-%d"), 
        " to ", 
        format(as.Date(result$max_date), "%Y-%m-%d")
      )
    }
    
    metrics <- list(
      total_documents = as.numeric(result$total_docs),
      states_with_docs = as.numeric(result$states_with_docs),
      municipalities_with_docs = as.numeric(result$municipalities_with_docs),
      date_range = date_range
    )
    
    cat("✅ get_lexml_dashboard_metrics emergency override:", metrics$total_documents, "documents\n")
    return(metrics)
    
  }, error = function(e) {
    cat("❌ Error in get_lexml_dashboard_metrics emergency override:", e$message, "\n")
    return(list(
      total_documents = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      date_range = "Error loading data"
    ))
  })
}

#' Override get_map1_data with emergency version
#' This is the function actually being called in the total documents map
get_map1_data <- function() {
  cat("🔄 get_map1_data called - using emergency override\n")
  
  if (!database_connected || is.null(db_pool)) {
    cat("⚠️ Database not connected in get_map1_data\n")
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Use unified documents view with proper state mapping
    result <- dbGetQuery(conn, "
      SELECT 
        COALESCE(estado, 'BR') as jurisdicao,
        COUNT(*) as count
      FROM documents 
      GROUP BY estado
      ORDER BY count DESC
    ")
    
    if (nrow(result) == 0) {
      cat("⚠️ No map data found in documents view\n")
      return(data.frame())
    }
    
    # Map 'BR' to 'DF' for federal documents
    result$jurisdicao[result$jurisdicao == 'BR'] <- 'DF'
    
    cat("✅ get_map1_data emergency override:", nrow(result), "jurisdictions\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error in get_map1_data emergency override:", e$message, "\n")
    return(data.frame())
  })
}

#' Override get_simple_map_data with emergency version
#' This is the function actually being called in the legislation and jurisprudence maps
get_simple_map_data <- function() {
  cat("🔄 get_simple_map_data called - using emergency override\n")
  
  if (!database_connected || is.null(db_pool)) {
    cat("⚠️ Database not connected in get_simple_map_data\n")
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Use unified documents view with proper state mapping
    result <- dbGetQuery(conn, "
      SELECT 
        COALESCE(estado, 'BR') as estado,
        COUNT(*) as total_docs,
        SUM(CASE WHEN tipo IN ('lei', 'decreto', 'portaria', 'resolucao') THEN 1 ELSE 0 END) as legislacao,
        SUM(CASE WHEN tipo IN ('jurisprudencia', 'acordao', 'sentenca') THEN 1 ELSE 0 END) as jurisprudencia,
        SUM(CASE WHEN tipo IN ('doutrina', 'artigo', 'livro') THEN 1 ELSE 0 END) as doutrina
      FROM documents 
      GROUP BY estado
      ORDER BY total_docs DESC
    ")
    
    if (nrow(result) == 0) {
      cat("⚠️ No map data found in documents view\n")
      return(data.frame())
    }
    
    # Map 'BR' to 'DF' for federal documents
    result$estado[result$estado == 'BR'] <- 'DF'
    
    cat("✅ get_simple_map_data emergency override:", nrow(result), "states\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error in get_simple_map_data emergency override:", e$message, "\n")
    return(data.frame())
  })
}

# ============================================================================
# 2. OVERRIDE DEBUG FUNCTIONS
# ============================================================================

#' Override get_debug_jurisdiction_count with emergency version
get_debug_jurisdiction_count <- function() {
  cat("🔄 get_debug_jurisdiction_count called - using emergency override\n")
  
  tryCatch({
    metrics <- get_lexml_dashboard_metrics()
    return(metrics$states_with_docs)
  }, error = function(e) {
    cat("❌ Error in get_debug_jurisdiction_count emergency override:", e$message, "\n")
    return(0)
  })
}

#' Override get_debug_type_count with emergency version
get_debug_type_count <- function() {
  cat("🔄 get_debug_type_count called - using emergency override\n")
  
  tryCatch({
    metrics <- get_lexml_dashboard_metrics()
    return(metrics$municipalities_with_docs)
  }, error = function(e) {
    cat("❌ Error in get_debug_type_count emergency override:", e$message, "\n")
    return(0)
  })
}

# ============================================================================
# 3. OVERRIDE DOCUMENT STATS FUNCTIONS
# ============================================================================

#' Override get_document_stats with emergency version
get_document_stats <- function() {
  cat("🔄 get_document_stats called - using emergency override\n")
  
  if (!database_connected || is.null(db_pool)) {
    cat("⚠️ Database not connected in get_document_stats\n")
    return(list(document_types = data.frame()))
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Get document type statistics
    result <- dbGetQuery(conn, "
      SELECT 
        tipo as Type,
        COUNT(*) as Count
      FROM documents 
      WHERE tipo IS NOT NULL
      GROUP BY tipo
      ORDER BY Count DESC
    ")
    
    cat("✅ get_document_stats emergency override:", nrow(result), "document types\n")
    return(list(document_types = result))
    
  }, error = function(e) {
    cat("❌ Error in get_document_stats emergency override:", e$message, "\n")
    return(list(document_types = data.frame()))
  })
}

# ============================================================================
# 4. FORCE OVERRIDE IN GLOBAL ENVIRONMENT
# ============================================================================

# Force override the functions in the global environment
assign("get_lexml_dashboard_metrics", get_lexml_dashboard_metrics, envir = .GlobalEnv)
assign("get_map1_data", get_map1_data, envir = .GlobalEnv)
assign("get_simple_map_data", get_simple_map_data, envir = .GlobalEnv)
assign("get_debug_jurisdiction_count", get_debug_jurisdiction_count, envir = .GlobalEnv)
assign("get_debug_type_count", get_debug_type_count, envir = .GlobalEnv)
assign("get_document_stats", get_document_stats, envir = .GlobalEnv)

cat("✅ Direct emergency override loaded\n")
cat("📊 Functions overridden:\n")
cat("  - get_lexml_dashboard_metrics() → Emergency version\n")
cat("  - get_map1_data() → Emergency version\n")
cat("  - get_simple_map_data() → Emergency version\n")
cat("  - get_debug_jurisdiction_count() → Emergency version\n")
cat("  - get_debug_type_count() → Emergency version\n")
cat("  - get_document_stats() → Emergency version\n")
cat("\n")
cat("🚨 These are the actual functions being called in the app\n")
cat("📝 The dashboard should now show real data instead of NULL/zeros\n") 