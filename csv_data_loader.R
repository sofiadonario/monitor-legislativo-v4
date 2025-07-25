# CSV Data Loader for Analytics Implementation
# MackMonitor v4 - Load data from ./data_current/processed
# Author: Analytics Implementation
# Date: 2025-01-25

library(dplyr)
library(readr)
library(stringr)
library(lubridate)

# ============================================================================
# 1. DATA LOADING FUNCTIONS
# ============================================================================

#' Load all CSV files from processed data directory
#' @param data_dir Path to processed data directory
#' @return Combined data frame
load_processed_data <- function(data_dir = "data_current/processed/lexml_dataset_individual_com_localizacao") {
  
  cat("Loading processed LexML data from CSV files...\n")
  
  # Get all CSV files
  csv_files <- list.files(data_dir, pattern = "\\.csv$", full.names = TRUE)
  csv_files <- csv_files[!grepl("README", csv_files)]
  
  cat(sprintf("Found %d CSV files to process\n", length(csv_files)))
  
  # Load and combine all files
  all_data <- list()
  
  for (i in seq_along(csv_files)) {
    file_path <- csv_files[i]
    file_name <- basename(file_path)
    
    cat(sprintf("Loading %s (%d/%d)...\n", file_name, i, length(csv_files)))
    
    # Read with error handling
    tryCatch({
      # Use read_csv with flexible parsing
      data <- read_csv(file_path, 
                      locale = locale(encoding = "UTF-8"),
                      col_types = cols(.default = col_character()),
                      show_col_types = FALSE)
      
      # Add source file info
      data$source_file <- file_name
      
      # Extract category and modal from filename
      if (grepl("doutrina", file_name)) {
        data$categoria_file <- "doutrina"
      } else if (grepl("jurisprudencia", file_name)) {
        data$categoria_file <- "jurisprudencia"
      } else if (grepl("legislacao", file_name)) {
        data$categoria_file <- "legislacao"
      } else if (grepl("outros", file_name)) {
        data$categoria_file <- "outros"
      } else if (grepl("proposicoes", file_name)) {
        data$categoria_file <- "proposicoes"
      } else {
        data$categoria_file <- "geral"
      }
      
      if (grepl("aereo", file_name)) {
        data$modal_file <- "aereo"
      } else if (grepl("maritimo", file_name)) {
        data$modal_file <- "maritimo"
      } else if (grepl("rodoviario", file_name)) {
        data$modal_file <- "rodoviario"
      } else {
        data$modal_file <- "geral"
      }
      
      all_data[[i]] <- data
      
    }, error = function(e) {
      cat(sprintf("Error loading %s: %s\n", file_name, e$message))
    })
  }
  
  # Combine all data
  combined_data <- bind_rows(all_data)
  
  cat(sprintf("Combined data: %d records from %d files\n", 
              nrow(combined_data), length(all_data)))
  
  return(combined_data)
}

#' Clean and standardize loaded data
#' @param data Raw loaded data
#' @return Cleaned data frame
clean_loaded_data <- function(data) {
  
  cat("Cleaning and standardizing data...\n")
  
  cleaned <- data %>%
    # Standardize column names
    rename_with(~ tolower(gsub("[^a-zA-Z0-9_]", "_", .))) %>%
    
    # Parse dates
    mutate(
      data_publicacao = case_when(
        !is.na(data) & data != "" & data != "NA" ~ tryCatch(as.Date(data), error = function(e) NA_Date_),
        !is.na(ano) & ano != "" & ano != "NA" & !is.na(as.numeric(ano)) ~ 
          tryCatch(as.Date(paste0(ano, "-01-01")), error = function(e) NA_Date_),
        TRUE ~ NA_Date_
      ),
      
      # Clean and standardize authority levels
      authority_level = case_when(
        tolower(jurisdicao) %in% c("federal", "união") ~ "federal",
        tolower(jurisdicao) %in% c("estadual", "estado") ~ "estadual", 
        tolower(jurisdicao) %in% c("municipal", "município") ~ "municipal",
        !is.na(jurisdicao) ~ tolower(jurisdicao),
        TRUE ~ "federal"  # Default assumption
      ),
      
      # Standardize document types
      tipo_doc = case_when(
        !is.na(categoria) ~ tolower(categoria),
        !is.na(categoria_file) ~ tolower(categoria_file),
        grepl("lei|decreto|portaria|resolução", tolower(tipo), na.rm = TRUE) ~ "legislacao",
        grepl("jurisprudência|decisão|acórdão", tolower(tipo), na.rm = TRUE) ~ "jurisprudencia",
        grepl("doutrina|livro|artigo", tolower(tipo), na.rm = TRUE) ~ "doutrina",
        TRUE ~ "outros"
      ),
      
      # Clean state information
      estado_clean = case_when(
        !is.na(estado) & estado != "" ~ toupper(str_trim(estado)),
        authority_level == "federal" ~ "BR",
        !is.na(pais) & pais == "Brasil" ~ "BR",
        TRUE ~ "BR"
      ),
      
      # Clean municipality
      municipio_clean = case_when(
        !is.na(municipio) & municipio != "" ~ str_trim(municipio),
        !is.na(localidade) & localidade != "" ~ str_trim(localidade),
        TRUE ~ ""
      ),
      
      # Create content field
      conteudo = case_when(
        !is.na(ementa) & ementa != "" ~ ementa,
        !is.na(assuntos) & assuntos != "" ~ assuntos,
        !is.na(titulo) & titulo != "" ~ titulo,
        TRUE ~ ""
      ),
      
      # Create unique identifier
      id = row_number(),
      
      # Set source
      fonte = "LexML"
    ) %>%
    
    # Filter out records with insufficient content
    filter(
      !is.na(titulo) & titulo != "",
      nchar(conteudo) >= 10
    ) %>%
    
    # Select and rename key columns for analytics
    select(
      id,
      titulo,
      tipo = tipo_doc,
      authority_level,
      data_publicacao,
      estado = estado_clean,
      municipality = municipio_clean,
      conteudo,
      urn,
      url,
      autor,
      fonte,
      created_at = data_coleta,
      modal = modal_file,
      source_file
    )
  
  cat(sprintf("Data cleaned: %d records remaining\n", nrow(cleaned)))
  
  return(cleaned)
}

#' Create analytics-compatible data structure
#' @param data Cleaned data
#' @return Analytics-ready data frame
prepare_for_analytics <- function(data) {
  
  cat("Preparing data for analytics modules...\n")
  
  # Ensure required columns exist
  analytics_data <- data %>%
    mutate(
      # Document metadata
      document_type_full = paste(tipo, modal, sep = " - "),
      locality = municipality,
      authority = case_when(
        authority_level == "federal" ~ "Federal",
        authority_level == "estadual" ~ paste("Estado", estado),
        authority_level == "municipal" ~ paste("Município", municipality),
        TRUE ~ "Não especificado"
      ),
      
      # Geographic standardization
      localidade = municipality,
      jurisdicao = authority_level,
      
      # Date handling
      ano = year(data_publicacao),
      created_at = if_else(is.na(created_at), 
                          as.character(Sys.time()), 
                          as.character(created_at)),
      updated_at = created_at,
      
      # Content preparation
      document_summary = str_sub(conteudo, 1, 500),
      document_description = conteudo,
      
      # Additional metadata
      metadata = "{}",
      transport_category = modal,
      classificacao = tipo,
      
      # Ensure text fields are not NA
      conteudo = if_else(is.na(conteudo) | conteudo == "", titulo, conteudo),
      titulo = if_else(is.na(titulo) | titulo == "", "Documento sem título", titulo)
    ) %>%
    
    # Filter for data quality
    filter(
      !is.na(data_publicacao),
      nchar(conteudo) >= 20,
      ano >= 1990 & ano <= year(Sys.Date())
    )
  
  cat(sprintf("Analytics preparation complete: %d records ready\n", nrow(analytics_data)))
  
  return(analytics_data)
}

# ============================================================================
# 2. MAIN DATA LOADING PIPELINE
# ============================================================================

#' Complete data loading pipeline for analytics
#' @param data_dir Directory containing processed CSV files
#' @return Analytics-ready data frame
load_data_for_analytics <- function(data_dir = "data_current/processed/lexml_dataset_individual_com_localizacao") {
  
  cat("\n=== LOADING DATA FOR ANALYTICS ===\n")
  
  # 1. Load raw data
  raw_data <- load_processed_data(data_dir)
  
  # 2. Clean data
  cleaned_data <- clean_loaded_data(raw_data)
  
  # 3. Prepare for analytics
  analytics_data <- prepare_for_analytics(cleaned_data)
  
  # 4. Data summary
  cat("\n=== DATA SUMMARY ===\n")
  cat(sprintf("Total documents: %d\n", nrow(analytics_data)))
  cat(sprintf("Date range: %s to %s\n", 
              min(analytics_data$data_publicacao, na.rm = TRUE),
              max(analytics_data$data_publicacao, na.rm = TRUE)))
  
  # Document types
  cat("\nDocument types:\n")
  type_summary <- table(analytics_data$tipo)
  print(type_summary)
  
  # Authority levels
  cat("\nAuthority levels:\n")
  authority_summary <- table(analytics_data$authority_level)
  print(authority_summary)
  
  # Modal distribution
  cat("\nModal distribution:\n")
  modal_summary <- table(analytics_data$modal)
  print(modal_summary)
  
  # Geographic coverage
  cat(sprintf("\nGeographic coverage: %d states, %d municipalities\n",
              n_distinct(analytics_data$estado[analytics_data$estado != ""]),
              n_distinct(analytics_data$municipality[analytics_data$municipality != ""])))
  
  return(analytics_data)
}

# ============================================================================
# 3. SAVE PREPARED DATA
# ============================================================================

#' Save prepared data for analytics modules
#' @param data Analytics-ready data
#' @param output_file Output file path
save_analytics_data <- function(data, output_file = "analytics_ready_data.rds") {
  
  cat(sprintf("Saving analytics-ready data to %s...\n", output_file))
  
  saveRDS(data, output_file)
  
  # Also save as CSV for inspection
  csv_file <- gsub("\\.rds$", ".csv", output_file)
  write.csv(data, csv_file, row.names = FALSE, fileEncoding = "UTF-8")
  
  cat("Data saved successfully!\n")
}

# ============================================================================
# 4. EXECUTION
# ============================================================================

# Load data if script is run directly
if (!interactive()) {
  # Load and prepare data
  analytics_data <- load_data_for_analytics()
  
  # Save for use by analytics modules
  save_analytics_data(analytics_data, "analytics_ready_data.rds")
  
  cat("\nData loading complete! Ready for analytics implementation.\n")
}