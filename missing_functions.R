# Missing functions for Railway deployment
# These functions bridge the gap between database.R and app.R

# Create sample data when database is not available
create_sample_data <- function(limit = 1000) {
  # Brazilian states for realistic data
  states <- c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE", "PA", "MT", "MS", "DF", "MA", "RO", "AM", "AL", "RN", "PB", "ES", "PI", "AC", "SE", "RR", "AP", "TO")
  types <- c("Lei", "Decreto", "Portaria", "Resolução", "Instrução Normativa", "Medida Provisória", "Emenda", "Projeto de Lei")
  
  sample_data <- data.frame(
    titulo = paste("Document", 1:limit, "-", sample(c("Federal Budget", "Health Policy", "Education Reform", "Environmental Protection", "Tax Regulation"), limit, replace = TRUE)),
    tipo = sample(types, limit, replace = TRUE),
    numero = paste(sample(1:9999, limit, replace = TRUE), "/", sample(2020:2024, limit, replace = TRUE), sep = ""),
    data = seq(as.Date("2020-01-01"), as.Date("2024-12-31"), length.out = limit),
    estado = sample(states, limit, replace = TRUE),
    municipio = paste("Municipality", sample(1:500, limit, replace = TRUE)),
    autor = paste("Author", sample(1:100, limit, replace = TRUE)),
    fonte = sample(c("Federal", "State", "Municipal"), limit, replace = TRUE),
    ementa = paste("Legislative summary for document", 1:limit, "covering important policy matters"),
    url = paste("https://example.com/doc/", 1:limit, sep = ""),
    data_coleta = Sys.time(),
    stringsAsFactors = FALSE
  )
  
  return(sample_data)
}

# Add essential data access functions
get_documents <- function(limit = 1000) {
  cat("🔄 get_documents called with limit:", limit, "\n")
  
  # Try database first
  if (exists("load_legislative_data") && !is.null(.db_pool)) {
    result <- load_legislative_data(limit = limit)
    if (!is.null(result) && nrow(result) > 0) {
      cat("🔄 get_documents returning", nrow(result), "documents from database\n")
      return(result)
    }
  }
  
  # Fallback to sample data
  cat("🔄 Database not available, creating sample data\n")
  result <- create_sample_data(limit = limit)
  cat("🔄 get_documents returning", nrow(result), "sample documents\n")
  return(result)
}

get_documents_data <- function(filters = NULL, limit = 1000) {
  cat("🔄 get_documents_data called with filters and limit:", limit, "\n")
  
  # Try database first
  if (exists("load_legislative_data") && !is.null(.db_pool)) {
    result <- load_legislative_data(filters = filters, limit = limit)
    if (!is.null(result) && nrow(result) > 0) {
      cat("🔄 get_documents_data returning", nrow(result), "documents from database\n")
      return(result)
    }
  }
  
  # Fallback to sample data
  result <- create_sample_data(limit = limit)
  cat("🔄 get_documents_data returning", nrow(result), "sample documents\n")
  return(result)
}

get_total_documents <- function() {
  cat("🔄 get_total_documents called\n")
  
  # Try database first
  if (exists("get_database_stats") && !is.null(.db_pool)) {
    stats <- get_database_stats()
    if (!is.null(stats)) {
      total <- stats$total_documents
      cat("🔄 get_total_documents returning:", total, "from database\n")
      return(total)
    }
  }
  
  # Fallback to sample data count
  cat("🔄 get_total_documents returning: 1000 (sample data)\n")
  return(1000)
}

get_document_types <- function() {
  cat("🔄 get_document_types called\n")
  
  # Try database first
  if (!is.null(.db_pool)) {
    tryCatch({
      result <- dbGetQuery(.db_pool, "SELECT DISTINCT tipo FROM lexml_documents WHERE tipo IS NOT NULL ORDER BY tipo")$tipo
      cat("🔄 get_document_types returning", length(result), "types from database\n")
      return(result)
    }, error = function(e) {
      cat("🔄 get_document_types database error:", e$message, "\n")
    })
  }
  
  # Fallback to sample types
  cat("🔄 get_document_types: No database connection, using sample types\n")
  sample_types <- c("Lei", "Decreto", "Portaria", "Resolução", "Instrução Normativa", "Medida Provisória", "Emenda", "Projeto de Lei")
  cat("🔄 get_document_types returning", length(sample_types), "sample types\n")
  return(sample_types)
}

get_states <- function() {
  cat("🔄 get_states called\n")
  
  # Try database first
  if (!is.null(.db_pool)) {
    tryCatch({
      result <- dbGetQuery(.db_pool, "SELECT DISTINCT estado FROM lexml_documents WHERE estado IS NOT NULL ORDER BY estado")$estado
      cat("🔄 get_states returning", length(result), "states from database\n")
      return(result)
    }, error = function(e) {
      cat("🔄 get_states database error:", e$message, "\n")
    })
  }
  
  # Fallback to sample states
  cat("🔄 get_states: No database connection, using sample states\n")
  sample_states <- c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE", "PA", "MT", "MS", "DF", "MA", "RO", "AM", "AL", "RN", "PB", "ES", "PI", "AC", "SE", "RR", "AP", "TO")
  cat("🔄 get_states returning", length(sample_states), "sample states\n")
  return(sample_states)
}

cat("✓ Missing functions loaded successfully - v2\n")