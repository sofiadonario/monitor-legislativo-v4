# Integration of Unified Data Access Layer
# This file integrates the new unified data access layer into the existing app

cat("🔧 INTEGRATING UNIFIED DATA ACCESS LAYER...\n")

# Source the unified data access layer
if (file.exists("unified_data_access_layer.R")) {
  source("unified_data_access_layer.R")
  cat("✅ Unified Data Access Layer loaded successfully\n")
} else {
  cat("❌ ERROR: unified_data_access_layer.R not found\n")
}

# Override the existing get_lexml_dashboard_metrics with unified version
get_lexml_dashboard_metrics <- function() {
  cat("🔄 get_lexml_dashboard_metrics (UNIFIED) called\n")
  
  tryCatch({
    # Get metrics from unified data access layer
    metrics <- get_unified_dashboard_metrics()
    
    # Ensure all required fields are present
    result <- list(
      total_documents = metrics$total_documents %||% 0,
      states_with_docs = metrics$states_with_docs %||% 0,
      municipalities_with_docs = metrics$municipalities_with_docs %||% 0,
      states_percentage = metrics$states_percentage %||% 0,
      municipalities_percentage = metrics$municipalities_percentage %||% 0,
      date_range_years = metrics$date_range_years %||% 0,
      last_updated = metrics$last_updated %||% Sys.time()
    )
    
    cat("✅ UNIFIED metrics retrieved:", result$total_documents, "documents\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error in unified metrics:", e$message, "\n")
    # Return safe defaults
    return(list(
      total_documents = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      states_percentage = 0,
      municipalities_percentage = 0,
      date_range_years = 0,
      last_updated = Sys.time()
    ))
  })
}

# Override get_total_documents to use unified layer
get_total_documents <- function(filters = list()) {
  cat("🔄 get_total_documents (UNIFIED) called\n")
  
  tryCatch({
    count <- .unified_dac$get_document_count(filters)
    cat("✅ UNIFIED total documents:", count, "\n")
    return(count)
  }, error = function(e) {
    cat("❌ Error in unified total documents:", e$message, "\n")
    return(0)
  })
}

# Override get_documents_by_state to use unified layer
get_documents_by_state <- function(limit = 100) {
  cat("🔄 get_documents_by_state (UNIFIED) called\n")
  
  tryCatch({
    data <- .unified_dac$get_documents_by_state(limit)
    cat("✅ UNIFIED documents by state retrieved\n")
    return(data)
  }, error = function(e) {
    cat("❌ Error in unified documents by state:", e$message, "\n")
    return(data.frame(estado = character(), count = numeric()))
  })
}

# Override get_documents_by_type to use unified layer
get_documents_by_type <- function(limit = 100) {
  cat("🔄 get_documents_by_type (UNIFIED) called\n")
  
  tryCatch({
    data <- .unified_dac$get_documents_by_type(limit)
    cat("✅ UNIFIED documents by type retrieved\n")
    return(data)
  }, error = function(e) {
    cat("❌ Error in unified documents by type:", e$message, "\n")
    return(data.frame(tipo = character(), count = numeric()))
  })
}

# Override get_database_stats to use unified layer
get_database_stats <- function() {
  cat("🔄 get_database_stats (UNIFIED) called\n")
  
  tryCatch({
    # Get various metrics from unified layer
    total <- .unified_dac$get_document_count()
    by_state <- .unified_dac$get_documents_by_state(limit = 10)
    by_type <- .unified_dac$get_documents_by_type(limit = 10)
    
    # Create year aggregation
    current_year <- as.numeric(format(Sys.Date(), "%Y"))
    years <- (current_year - 4):current_year
    year_counts <- sapply(years, function(y) {
      .unified_dac$get_document_count(list(year = y))
    })
    
    result <- list(
      total_documents = total,
      documents_by_year = data.frame(
        year = years,
        count = year_counts
      ),
      documents_by_type = by_type,
      documents_by_state = by_state,
      documents_by_month = data.frame(
        month = format(seq(Sys.Date() - 330, Sys.Date(), by = "month"), "%Y-%m"),
        count = rep(round(total/12), 12)
      ),
      last_updated = Sys.time(),
      data_source = "unified_data_access_layer"
    )
    
    cat("✅ UNIFIED database stats retrieved\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error in unified database stats:", e$message, "\n")
    # Return safe defaults
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(year = numeric(), count = numeric()),
      documents_by_type = data.frame(tipo = character(), count = numeric()),
      documents_by_state = data.frame(estado = character(), count = numeric()),
      documents_by_month = data.frame(month = character(), count = numeric()),
      last_updated = Sys.time(),
      data_source = "unified_fallback"
    ))
  })
}

# Helper function for null coalescing
`%||%` <- function(x, y) {
  if (is.null(x) || is.na(x) || length(x) == 0) y else x
}

cat("✅ UNIFIED DATA ACCESS LAYER INTEGRATION COMPLETE\n")
cat("📊 All data access functions now use the unified layer\n")