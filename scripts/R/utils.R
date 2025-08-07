# Utility functions for Monitor Legislativo v4
# Minimal implementations for Railway deployment

# Load required packages
suppressPackageStartupMessages({
  library(dplyr)
})

#' Log event messages
#' @param message The message to log
#' @param level Log level (INFO, WARN, ERROR)
log_event <- function(message, level = "INFO") {
  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  cat(sprintf("[%s] %s: %s\n", timestamp, level, message))
  
  # In production, you might want to write to a file or external logging service
  # For now, just output to console which Railway will capture
}

#' Check if a package is available and optionally load it
#' @param package_name Name of the package to check
#' @param quiet Whether to suppress messages
#' @return TRUE if package is available, FALSE otherwise
require_package <- function(package_name, quiet = TRUE) {
  if (requireNamespace(package_name, quietly = quiet)) {
    if (!quiet) {
      log_event(paste("Package", package_name, "is available"))
    }
    return(TRUE)
  } else {
    if (!quiet) {
      log_event(paste("Package", package_name, "is not available"), "WARN")
    }
    return(FALSE)
  }
}

#' Null coalescing operator
#' @param lhs Left hand side value
#' @param rhs Right hand side value (default)
#' @return lhs if not null, otherwise rhs
`%||%` <- function(lhs, rhs) {
  if (!is.null(lhs)) {
    lhs
  } else {
    rhs
  }
}

#' Standardize column names and data types
#' @param data Data frame to standardize
#' @return Standardized data frame
standardize_columns <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(NULL)
  }
  
  # Define column mapping
  column_mapping <- list(
    titulo = c("titulo", "title", "ementa", "description"),
    tipo = c("tipo", "type", "siglaTipo", "tipoProposicao"),
    numero = c("numero", "number", "numeroProposicao"),
    data = c("data", "date", "dataApresentacao", "dataPublicacao"),
    estado = c("estado", "state", "uf", "siglaUf"),
    municipio = c("municipio", "municipality", "cidade"),
    autor = c("autor", "author", "nomeAutor", "proponente"),
    fonte = c("fonte", "source", "api_source"),
    url = c("url", "link", "urlInteiroTeor"),
    ementa = c("ementa", "summary", "explicacao")
  )
  
  # Standardize columns
  for (target_col in names(column_mapping)) {
    possible_cols <- column_mapping[[target_col]]
    found_col <- intersect(possible_cols, names(data))[1]
    
    if (!is.na(found_col)) {
      data[[target_col]] <- data[[found_col]]
    } else if (!target_col %in% names(data)) {
      data[[target_col]] <- NA
    }
  }
  
  # Ensure required columns exist
  required_cols <- c("titulo", "tipo", "data", "fonte")
  for (col in required_cols) {
    if (!col %in% names(data)) {
      data[[col]] <- NA
    }
  }
  
  # Data type conversions
  if ("data" %in% names(data)) {
    data$data <- as.Date(data$data)
  }
  
  # Clean and standardize text fields
  text_cols <- c("titulo", "tipo", "autor", "ementa")
  for (col in text_cols) {
    if (col %in% names(data)) {
      # Simple text cleaning without stringr
      data[[col]] <- trimws(gsub("\\s+", " ", as.character(data[[col]])))
    }
  }
  
  return(data)
}

#' Validate legislative data quality
#' @param data Data frame to validate
#' @return Data frame with quality_score column
validate_data_quality <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(data)
  }
  
  # Calculate quality score for each record
  data$quality_score <- 0
  
  # Add points for complete fields
  if ("titulo" %in% names(data)) {
    data$quality_score <- data$quality_score + ifelse(!is.na(data$titulo) & nchar(data$titulo) > 5, 20, 0)
  }
  
  if ("tipo" %in% names(data)) {
    data$quality_score <- data$quality_score + ifelse(!is.na(data$tipo), 15, 0)
  }
  
  if ("data" %in% names(data)) {
    data$quality_score <- data$quality_score + ifelse(!is.na(data$data), 15, 0)
  }
  
  if ("numero" %in% names(data)) {
    data$quality_score <- data$quality_score + ifelse(!is.na(data$numero), 10, 0)
  }
  
  if ("autor" %in% names(data)) {
    data$quality_score <- data$quality_score + ifelse(!is.na(data$autor), 10, 0)
  }
  
  if ("ementa" %in% names(data)) {
    data$quality_score <- data$quality_score + ifelse(!is.na(data$ementa) & nchar(data$ementa) > 20, 15, 0)
  }
  
  if ("estado" %in% names(data)) {
    data$quality_score <- data$quality_score + ifelse(!is.na(data$estado), 10, 0)
  }
  
  if ("url" %in% names(data)) {
    data$quality_score <- data$quality_score + ifelse(!is.na(data$url), 5, 0)
  }
  
  # Filter out very low quality records
  data <- data %>%
    filter(quality_score >= 30)  # Minimum quality threshold
  
  return(data)
}