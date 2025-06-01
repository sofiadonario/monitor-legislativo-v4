# Utility Functions for Monitor Legislativo v4
# Supporting functions for data processing and application management

library(dplyr)
library(stringr)
library(lubridate)

#' Get list of Brazilian states
#' @return Named vector of Brazilian states
get_brazilian_states <- function() {
  states <- c(
    "Acre" = "AC", "Alagoas" = "AL", "Amapá" = "AP", "Amazonas" = "AM",
    "Bahia" = "BA", "Ceará" = "CE", "Distrito Federal" = "DF", 
    "Espírito Santo" = "ES", "Goiás" = "GO", "Maranhão" = "MA",
    "Mato Grosso" = "MT", "Mato Grosso do Sul" = "MS", 
    "Minas Gerais" = "MG", "Pará" = "PA", "Paraíba" = "PB",
    "Paraná" = "PR", "Pernambuco" = "PE", "Piauí" = "PI",
    "Rio de Janeiro" = "RJ", "Rio Grande do Norte" = "RN",
    "Rio Grande do Sul" = "RS", "Rondônia" = "RO", "Roraima" = "RR",
    "Santa Catarina" = "SC", "São Paulo" = "SP", "Sergipe" = "SE",
    "Tocantins" = "TO"
  )
  return(states)
}

#' Validate and sanitize search query
#' @param query User input query
#' @return Sanitized query string
sanitize_query <- function(query) {
  if (is.null(query) || query == "") {
    return(NULL)
  }
  
  # Remove potentially dangerous characters
  query <- str_replace_all(query, "[<>\"'&;]", "")
  
  # Limit length
  if (nchar(query) > 500) {
    query <- str_sub(query, 1, 500)
  }
  
  # Remove extra whitespace
  query <- str_trim(str_squish(query))
  
  return(query)
}

#' Validate date input
#' @param date_input Date to validate
#' @param param_name Parameter name for error messages
#' @return Validated date or NULL
validate_date <- function(date_input, param_name = "date") {
  if (is.null(date_input)) {
    return(NULL)
  }
  
  tryCatch({
    validated_date <- as.Date(date_input)
    
    # Check if date is reasonable
    min_date <- as.Date("1988-10-05")  # Brazilian Constitution date
    max_date <- Sys.Date() + 365       # One year in future
    
    if (validated_date < min_date) {
      message(paste("Date", validated_date, "is before Brazilian Constitution, using", min_date))
      return(min_date)
    }
    
    if (validated_date > max_date) {
      message(paste("Date", validated_date, "is too far in future, using", Sys.Date()))
      return(Sys.Date())
    }
    
    return(validated_date)
    
  }, error = function(e) {
    warning(paste("Invalid", param_name, "format:", date_input))
    return(NULL)
  })
}

#' Format large numbers with thousands separator
#' @param number Number to format
#' @return Formatted string
format_number <- function(number) {
  if (is.null(number) || !is.numeric(number)) {
    return("0")
  }
  format(number, big.mark = ".", decimal.mark = ",", scientific = FALSE)
}

#' Create citation text for academic use
#' @param data Legislative data
#' @param style Citation style (ABNT, APA, etc.)
#' @return Citation string
create_citation <- function(data = NULL, style = "ABNT") {
  current_date <- format(Sys.Date(), "%d de %B de %Y")
  
  base_citation <- paste0(
    "Monitor Legislativo v4. Dados legislativos brasileiros. ",
    "Consultado em ", current_date, ". ",
    "Plataforma acadêmica de pesquisa legislativa."
  )
  
  if (!is.null(data) && nrow(data) > 0) {
    total_docs <- nrow(data)
    date_range <- range(as.Date(data$data), na.rm = TRUE)
    
    base_citation <- paste0(
      base_citation, " ",
      "Conjunto de dados: ", total_docs, " documentos, ",
      "período de ", format(date_range[1], "%Y"), " a ", format(date_range[2], "%Y"), "."
    )
  }
  
  return(base_citation)
}

#' Standardize legislative data columns
#' @param data Raw data from APIs
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
      data[[col]] <- str_trim(str_squish(as.character(data[[col]])))
    }
  }
  
  return(data)
}

#' Remove duplicate documents
#' @param data Legislative data
#' @return Deduplicated data
remove_duplicates <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(data)
  }
  
  # Remove duplicates based on key fields
  data %>%
    distinct(titulo, numero, data, fonte, .keep_all = TRUE) %>%
    arrange(desc(data))
}

#' Validate legislative data quality
#' @param data Legislative data to validate
#' @return Validated data with quality scores
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

#' Create summary statistics for data
#' @param data Legislative data
#' @return List of summary statistics
create_summary_stats <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(list(
      total_documents = 0,
      unique_states = 0,
      unique_types = 0,
      date_range = "N/A",
      sources = "N/A"
    ))
  }
  
  stats <- list(
    total_documents = nrow(data),
    unique_states = length(unique(data$estado[!is.na(data$estado)])),
    unique_types = length(unique(data$tipo[!is.na(data$tipo)])),
    unique_sources = length(unique(data$fonte[!is.na(data$fonte)])),
    average_quality = round(mean(data$quality_score, na.rm = TRUE), 1)
  )
  
  # Date range
  if ("data" %in% names(data)) {
    date_range <- range(as.Date(data$data), na.rm = TRUE)
    if (!any(is.na(date_range))) {
      stats$date_range <- paste(format(date_range[1], "%d/%m/%Y"), 
                               "a", 
                               format(date_range[2], "%d/%m/%Y"))
    } else {
      stats$date_range <- "N/A"
    }
  }
  
  # Top document types
  if ("tipo" %in% names(data)) {
    top_types <- data %>%
      count(tipo, sort = TRUE) %>%
      slice_head(n = 5) %>%
      pull(tipo)
    stats$top_types <- paste(top_types, collapse = ", ")
  }
  
  # Top states
  if ("estado" %in% names(data)) {
    top_states <- data %>%
      count(estado, sort = TRUE) %>%
      slice_head(n = 5) %>%
      pull(estado)
    stats$top_states <- paste(top_states, collapse = ", ")
  }
  
  return(stats)
}

#' Log application events
#' @param message Log message
#' @param level Log level (INFO, WARN, ERROR)
log_event <- function(message, level = "INFO") {
  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  log_entry <- paste0("[", timestamp, "] [", level, "] ", message)
  
  # Print to console
  cat(log_entry, "\n")
  
  # In production, also write to file
  if (Sys.getenv("R_CONFIG_ACTIVE") == "production") {
    log_file <- "logs/app.log"
    
    # Create logs directory if it doesn't exist
    if (!dir.exists("logs")) {
      dir.create("logs", recursive = TRUE)
    }
    
    # Write to log file
    tryCatch({
      cat(log_entry, "\n", file = log_file, append = TRUE)
    }, error = function(e) {
      # If logging fails, just continue
    })
  }
}

#' Convert data to specific format for export
#' @param data Legislative data
#' @param format Export format (csv, xlsx, json, etc.)
#' @return File path of exported data
convert_data_format <- function(data, format = "csv") {
  if (is.null(data) || nrow(data) == 0) {
    return(NULL)
  }
  
  # Create exports directory if it doesn't exist
  if (!dir.exists("exports")) {
    dir.create("exports", recursive = TRUE)
  }
  
  # Generate filename
  timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
  filename <- paste0("exports/monitor_legislativo_", timestamp, ".", format)
  
  tryCatch({
    switch(format,
      "csv" = {
        write.csv(data, filename, row.names = FALSE, fileEncoding = "UTF-8")
      },
      "xlsx" = {
        if (requireNamespace("openxlsx", quietly = TRUE)) {
          openxlsx::write.xlsx(data, filename, asTable = TRUE)
        } else {
          stop("Package openxlsx not available for Excel export")
        }
      },
      "json" = {
        jsonlite::write_json(data, filename, pretty = TRUE, auto_unbox = TRUE)
      },
      {
        stop("Unsupported format: ", format)
      }
    )
    
    log_event(paste("Data exported to", filename))
    return(filename)
    
  }, error = function(e) {
    log_event(paste("Export failed:", e$message), "ERROR")
    return(NULL)
  })
}

#' Check if a package is available and load it
#' @param package_name Name of the package
#' @param quiet Whether to suppress messages
#' @return TRUE if package is available, FALSE otherwise
require_package <- function(package_name, quiet = TRUE) {
  if (requireNamespace(package_name, quietly = quiet)) {
    library(package_name, character.only = TRUE, quietly = quiet)
    return(TRUE)
  } else {
    if (!quiet) {
      message("Package ", package_name, " is not available")
    }
    return(FALSE)
  }
}