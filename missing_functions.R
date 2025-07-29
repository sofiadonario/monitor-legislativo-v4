# Missing functions for Railway deployment
# These functions bridge the gap between database.R and app.R

# Add essential data access functions
get_documents <- function(limit = 1000) {
  cat("🔄 get_documents called with limit:", limit, "\n")
  result <- load_legislative_data(limit = limit)
  cat("🔄 get_documents returning", ifelse(is.null(result), 0, nrow(result)), "documents\n")
  return(result)
}

get_documents_data <- function(filters = NULL, limit = 1000) {
  cat("🔄 get_documents_data called with filters and limit:", limit, "\n")
  result <- load_legislative_data(filters = filters, limit = limit)
  cat("🔄 get_documents_data returning", ifelse(is.null(result), 0, nrow(result)), "documents\n")
  return(result)
}

get_total_documents <- function() {
  cat("🔄 get_total_documents called\n")
  stats <- get_database_stats()
  if (!is.null(stats)) {
    total <- stats$total_documents
    cat("🔄 get_total_documents returning:", total, "\n")
    return(total)
  }
  cat("🔄 get_total_documents returning: 0 (no stats)\n")
  return(0)
}

get_document_types <- function() {
  cat("🔄 get_document_types called\n")
  if (is.null(.db_pool)) {
    cat("🔄 get_document_types: No database connection\n")
    return(c())
  }
  
  tryCatch({
    result <- dbGetQuery(.db_pool, "SELECT DISTINCT tipo FROM lexml_documents WHERE tipo IS NOT NULL ORDER BY tipo")$tipo
    cat("🔄 get_document_types returning", length(result), "types\n")
    return(result)
  }, error = function(e) {
    cat("🔄 get_document_types error:", e$message, "\n")
    return(c())
  })
}

get_states <- function() {
  cat("🔄 get_states called\n")
  if (is.null(.db_pool)) {
    cat("🔄 get_states: No database connection\n")
    return(c())
  }
  
  tryCatch({
    result <- dbGetQuery(.db_pool, "SELECT DISTINCT estado FROM lexml_documents WHERE estado IS NOT NULL ORDER BY estado")$estado
    cat("🔄 get_states returning", length(result), "states\n")
    return(result)
  }, error = function(e) {
    cat("🔄 get_states error:", e$message, "\n")
    return(c())
  })
}

cat("✓ Missing functions loaded successfully\n")