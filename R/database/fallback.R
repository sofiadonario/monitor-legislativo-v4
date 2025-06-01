# Database Fallback Module
# Monitor Legislativo v4 - CSV Fallback System
# =============================================

#' Enhanced CSV Fallback System
#' 
#' Provides robust fallback functionality when database is unavailable
#' Maintains full application functionality with CSV data sources
#' 
#' @export
initialize_csv_fallback <- function() {
  
  cat("🔄 Initializing CSV fallback system...\n")
  
  # Check available CSV files
  csv_sources <- list(
    primary = "data/monitor_legislativo_cleaned.csv",
    current = "data_current/monitor_legislativo_cleaned.csv",
    sample = "data/sample_data.csv",
    backup = "archive/data_backup.csv"
  )
  
  available_sources <- list()
  total_documents <- 0
  
  for (source_name in names(csv_sources)) {
    csv_file <- csv_sources[[source_name]]
    
    if (file.exists(csv_file)) {
      tryCatch({
        # Quick file validation
        file_info <- file.info(csv_file)
        if (file_info$size > 0) {
          # Count rows efficiently
          n_lines <- length(readLines(csv_file, n = 1000))  # Sample to estimate
          row_count <- if (n_lines == 1000) {
            # Large file, estimate based on file size
            estimated_rows <- round(file_info$size / 500)  # Rough estimate
            estimated_rows
          } else {
            n_lines - 1  # Subtract header
          }
          
          available_sources[[source_name]] <- list(
            file = csv_file,
            size_mb = round(file_info$size / 1024 / 1024, 2),
            estimated_rows = row_count,
            last_modified = file_info$mtime
          )
          
          total_documents <- total_documents + row_count
          
          cat("✅", source_name, "CSV found:", format(row_count, big.mark = ","), "documents\n")
        }
      }, error = function(e) {
        cat("⚠️ Issue with", source_name, "CSV:", e$message, "\n")
      })
    }
  }
  
  if (length(available_sources) == 0) {
    cat("❌ No valid CSV sources found\n")
    return(list(
      status = "no_sources",
      total_documents = 0,
      sources = list()
    ))
  }
  
  cat("✅ CSV fallback system initialized\n")
  cat("📊 Total estimated documents:", format(total_documents, big.mark = ","), "\n")
  cat("📁 Available sources:", length(available_sources), "\n")
  
  return(list(
    status = "ready",
    total_documents = total_documents,
    sources = available_sources
  ))
}

#' Load CSV Data with Optimization
#' 
#' Efficiently loads CSV data with memory management and error handling
#' 
#' @param source_priority Vector of source names in order of preference
#' @param max_rows Maximum rows to load (for memory management)
#' @param required_columns Vector of required column names
#' @return Data frame of loaded documents
#' @export
load_csv_data <- function(source_priority = c("primary", "current", "sample"), 
                          max_rows = 10000, 
                          required_columns = c("id", "titulo", "content", "tipo", "ano", "estado")) {
  
  fallback_info <- initialize_csv_fallback()
  
  if (fallback_info$status != "ready") {
    stop("CSV fallback system not ready")
  }
  
  # Try sources in priority order
  for (source_name in source_priority) {
    if (source_name %in% names(fallback_info$sources)) {
      
      csv_file <- fallback_info$sources[[source_name]]$file
      cat("📁 Attempting to load:", source_name, "source\n")
      
      tryCatch({
        # Load data efficiently
        data <- read.csv(csv_file, 
                        stringsAsFactors = FALSE,
                        nrows = max_rows,
                        fileEncoding = "UTF-8")
        
        # Validate required columns
        missing_columns <- required_columns[!required_columns %in% names(data)]
        
        if (length(missing_columns) > 0) {
          cat("⚠️ Missing required columns:", paste(missing_columns, collapse = ", "), "\n")
          
          # Add missing columns with default values
          for (col in missing_columns) {
            if (col %in% c("id", "ano")) {
              data[[col]] <- 1:nrow(data)  # Generate sequential IDs
            } else {
              data[[col]] <- ""  # Empty string for text columns
            }
          }
        }
        
        # Data quality validation
        data <- validate_csv_data(data)
        
        cat("✅ Successfully loaded", nrow(data), "documents from", source_name, "source\n")
        return(data)
        
      }, error = function(e) {
        cat("❌ Failed to load", source_name, "source:", e$message, "\n")
      })
    }
  }
  
  # If all sources failed, return empty data frame with correct structure
  empty_df <- data.frame(
    id = integer(0),
    titulo = character(0),
    content = character(0),
    tipo = character(0),
    ano = integer(0),
    estado = character(0),
    municipio = character(0),
    stringsAsFactors = FALSE
  )
  
  warning("All CSV sources failed to load")
  return(empty_df)
}

#' Validate and Clean CSV Data
#' 
#' Performs data quality checks and cleaning on loaded CSV data
#' 
#' @param data Data frame to validate
#' @return Cleaned data frame
validate_csv_data <- function(data) {
  
  original_rows <- nrow(data)
  
  # Remove completely empty rows
  data <- data[!apply(data, 1, function(x) all(is.na(x) | x == "")), ]
  
  # Clean text columns
  text_columns <- c("titulo", "content", "tipo", "estado", "municipio", "orgao_emissor")
  
  for (col in text_columns) {
    if (col %in% names(data)) {
      # Convert to character and clean
      data[[col]] <- as.character(data[[col]])
      data[[col]][is.na(data[[col]])] <- ""
      
      # Remove excessive whitespace
      data[[col]] <- gsub("\\s+", " ", data[[col]])
      data[[col]] <- trimws(data[[col]])
    }
  }
  
  # Validate numeric columns
  if ("ano" %in% names(data)) {
    data$ano <- as.numeric(data$ano)
    # Set reasonable year bounds
    data$ano[data$ano < 1900 | data$ano > 2030] <- NA
  }
  
  if ("id" %in% names(data)) {
    data$id <- as.numeric(data$id)
    # Generate sequential IDs for missing values
    missing_ids <- is.na(data$id)
    if (any(missing_ids)) {
      data$id[missing_ids] <- seq(max(data$id, na.rm = TRUE) + 1, 
                                  length.out = sum(missing_ids))
    }
  }
  
  cleaned_rows <- nrow(data)
  
  if (cleaned_rows < original_rows) {
    cat("🧹 Data cleaning: removed", original_rows - cleaned_rows, "invalid rows\n")
  }
  
  return(data)
}

#' Create Fallback Summary Statistics
#' 
#' Generates summary statistics for fallback data
#' 
#' @param data Data frame of documents
#' @return List of summary statistics
#' @export
create_fallback_summary <- function(data) {
  
  if (nrow(data) == 0) {
    return(list(
      total_documents = 0,
      years_covered = c(),
      states_covered = c(),
      document_types = c(),
      status = "empty"
    ))
  }
  
  summary_stats <- list(
    total_documents = nrow(data),
    status = "active"
  )
  
  # Year coverage
  if ("ano" %in% names(data) && any(!is.na(data$ano))) {
    valid_years <- data$ano[!is.na(data$ano)]
    summary_stats$years_covered <- range(valid_years)
    summary_stats$year_distribution <- table(valid_years)
  }
  
  # Geographic coverage
  if ("estado" %in% names(data)) {
    valid_states <- data$estado[!is.na(data$estado) & data$estado != ""]
    summary_stats$states_covered <- unique(valid_states)
    summary_stats$state_distribution <- table(valid_states)
  }
  
  # Document types
  if ("tipo" %in% names(data)) {
    valid_types <- data$tipo[!is.na(data$tipo) & data$tipo != ""]
    summary_stats$document_types <- unique(valid_types)
    summary_stats$type_distribution <- table(valid_types)
  }
  
  return(summary_stats)
}

#' Get Enhanced Fallback Status
#' 
#' Provides comprehensive status information for the fallback system
#' 
#' @return List with detailed fallback system status
#' @export
get_fallback_status <- function() {
  
  fallback_info <- initialize_csv_fallback()
  
  if (fallback_info$status != "ready") {
    return(list(
      status = "unavailable",
      message = "CSV fallback system not available",
      sources = list(),
      total_documents = 0
    ))
  }
  
  # Load sample data to get actual statistics
  sample_data <- tryCatch({
    load_csv_data(max_rows = 1000)
  }, error = function(e) {
    data.frame()
  })
  
  summary_stats <- create_fallback_summary(sample_data)
  
  return(list(
    status = "active",
    message = "CSV fallback system operational",
    sources = fallback_info$sources,
    total_documents = fallback_info$total_documents,
    sample_stats = summary_stats,
    last_updated = Sys.time()
  ))
}

cat("✅ Database fallback module loaded\n")