#!/usr/bin/env Rscript
#' Brazilian Legislative Dataset - Phase 1: CSV to Parquet Conversion
#' 
#' This script converts the Brazilian legislative dataset from CSV to Parquet format
#' using R's arrow package with optimal compression settings. Includes both single-file
#' and partitioned options by authority level.
#' 
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-07-26
#' @version 1.0.0

# Load required libraries
suppressPackageStartupMessages({
  library(arrow)
  library(dplyr)
  library(data.table)
  library(stringr)
  library(lubridate)
  library(fs)
  library(glue)
  library(logger)
  library(tictoc)
})

# Set up logging
log_threshold(INFO)

#' Parquet Conversion Functions
#' ============================

#' Prepare data for Parquet conversion with proper data types
#' @param data Raw data frame from CSV
#' @return Data frame with optimized data types
prepare_data_types <- function(data) {
  
  log_info("Preparing data types for Parquet conversion...")
  
  prepared_data <- data %>%
    mutate(
      # Convert dates
      data = as.Date(data),
      data_coleta = as_datetime(data_coleta),
      
      # Convert numeric fields
      numero = as.numeric(numero),
      ano = as.numeric(ano),
      
      # Convert categorical fields to factors for better compression
      tipo = as.factor(tipo),
      jurisdicao = as.factor(jurisdicao),
      autoridade = as.factor(autoridade),
      categoria = as.factor(categoria),
      modal = as.factor(modal),
      pais = as.factor(pais),
      estado = as.factor(estado),
      origem = as.factor(origem),
      termo_busca = as.factor(termo_busca),
      
      # Ensure text fields are UTF-8
      titulo = enc2utf8(titulo),
      urn = enc2utf8(urn),
      autor = enc2utf8(autor),
      assuntos = enc2utf8(assuntos),
      classificacao = enc2utf8(classificacao),
      ementa = enc2utf8(ementa),
      url = enc2utf8(url),
      localidade = enc2utf8(localidade),
      municipio = enc2utf8(municipio),
      fontes_localizacao = enc2utf8(fontes_localizacao),
      
      # Add derived columns for partitioning
      authority_level = case_when(
        str_detect(tolower(autoridade %||% ""), "federal") | jurisdicao == "Federal" ~ "Federal",
        str_detect(tolower(autoridade %||% ""), "estadual|estado") | !is.na(estado) & estado != "" ~ "State",
        str_detect(tolower(autoridade %||% ""), "municipal|prefeitura") | !is.na(municipio) & municipio != "" ~ "Municipal",
        TRUE ~ "Unknown"
      ),
      
      year_partition = year(data),
      category_partition = coalesce(categoria, "Unknown")
    )
  
  log_info("Data type conversion completed")
  return(prepared_data)
}

#' Convert single CSV file to Parquet
#' @param csv_file Path to CSV file
#' @param output_dir Output directory for Parquet files
#' @param compression Compression algorithm (default: "snappy")
#' @return Path to created Parquet file
convert_csv_to_parquet <- function(csv_file, output_dir, compression = "snappy") {
  
  log_info("Converting {basename(csv_file)} to Parquet...")
  
  tic()
  
  # Read CSV with proper encoding
  data <- fread(csv_file, encoding = "UTF-8", fill = TRUE, blank.lines.skip = TRUE)
  
  # Prepare data types
  prepared_data <- prepare_data_types(data)
  
  # Create output filename
  output_file <- file.path(output_dir, 
                          str_replace(basename(csv_file), "\\.csv$", ".parquet"))
  
  # Convert to Arrow table and write Parquet
  arrow_table <- arrow_table(prepared_data)
  
  write_parquet(arrow_table, 
                output_file,
                compression = compression,
                use_dictionary = TRUE,
                write_statistics = TRUE)
  
  conversion_time <- toc(quiet = TRUE)
  
  # Get file sizes for comparison
  csv_size <- file.size(csv_file)
  parquet_size <- file.size(output_file)
  compression_ratio <- round((1 - parquet_size/csv_size) * 100, 2)
  
  log_info("Conversion completed in {round(conversion_time$toc - conversion_time$tic, 2)} seconds")
  log_info("File size: {scales::number_bytes(csv_size)} -> {scales::number_bytes(parquet_size)} ({compression_ratio}% reduction)")
  
  return(list(
    output_file = output_file,
    csv_size = csv_size,
    parquet_size = parquet_size,
    compression_ratio = compression_ratio,
    conversion_time = conversion_time$toc - conversion_time$tic,
    record_count = nrow(prepared_data)
  ))
}

#' Create partitioned Parquet dataset
#' @param data Prepared data frame
#' @param output_dir Output directory for partitioned dataset
#' @param partition_cols Columns to partition by
#' @param compression Compression algorithm
create_partitioned_dataset <- function(data, output_dir, 
                                     partition_cols = c("authority_level", "year_partition"),
                                     compression = "snappy") {
  
  log_info("Creating partitioned Parquet dataset...")
  
  tic()
  
  # Create Arrow dataset
  dataset_dir <- file.path(output_dir, "partitioned_dataset")
  dir_create(dataset_dir, recurse = TRUE)
  
  # Write partitioned dataset
  data %>%
    group_by(!!!syms(partition_cols)) %>%
    write_dataset(dataset_dir,
                  format = "parquet",
                  compression = compression,
                  use_dictionary = TRUE,
                  write_statistics = TRUE)
  
  partition_time <- toc(quiet = TRUE)
  
  # Calculate dataset statistics
  partition_stats <- data %>%
    group_by(!!!syms(partition_cols)) %>%
    summarise(
      record_count = n(),
      avg_record_size = mean(nchar(paste(titulo, assuntos, ementa, sep = " ")), na.rm = TRUE),
      .groups = "drop"
    )
  
  log_info("Partitioned dataset created in {round(partition_time$toc - partition_time$tic, 2)} seconds")
  log_info("Dataset partitioned by: {paste(partition_cols, collapse = ', ')}")
  log_info("Number of partitions: {nrow(partition_stats)}")
  
  return(list(
    dataset_dir = dataset_dir,
    partition_stats = partition_stats,
    partition_time = partition_time$toc - partition_time$tic
  ))
}

#' Create indexed SQLite database as alternative
#' @param data Prepared data frame
#' @param output_dir Output directory
create_sqlite_database <- function(data, output_dir) {
  
  log_info("Creating indexed SQLite database...")
  
  tic()
  
  library(DBI)
  library(RSQLite)
  
  db_file <- file.path(output_dir, "legislative_dataset.sqlite")
  
  # Create connection
  con <- dbConnect(SQLite(), db_file)
  
  # Write main table
  dbWriteTable(con, "legislative_data", data, overwrite = TRUE)
  
  # Create indexes for common query patterns
  indexes <- list(
    "idx_authority_level" = "CREATE INDEX idx_authority_level ON legislative_data(authority_level)",
    "idx_year" = "CREATE INDEX idx_year ON legislative_data(year_partition)", 
    "idx_category" = "CREATE INDEX idx_category ON legislative_data(categoria)",
    "idx_modal" = "CREATE INDEX idx_modal ON legislative_data(modal)",
    "idx_jurisdicao" = "CREATE INDEX idx_jurisdicao ON legislative_data(jurisdicao)",
    "idx_date" = "CREATE INDEX idx_date ON legislative_data(data)",
    "idx_urn" = "CREATE INDEX idx_urn ON legislative_data(urn)",
    "idx_composite_authority_year" = "CREATE INDEX idx_composite_authority_year ON legislative_data(authority_level, year_partition)",
    "idx_composite_category_modal" = "CREATE INDEX idx_composite_category_modal ON legislative_data(categoria, modal)"
  )
  
  # Create indexes
  for (idx_name in names(indexes)) {
    tryCatch({
      dbExecute(con, indexes[[idx_name]])
      log_info("Created index: {idx_name}")
    }, error = function(e) {
      log_warn("Failed to create index {idx_name}: {e$message}")
    })
  }
  
  # Create metadata table
  metadata <- data.frame(
    table_name = "legislative_data",
    record_count = nrow(data),
    created_date = Sys.time(),
    columns = ncol(data),
    indexes_created = length(indexes)
  )
  
  dbWriteTable(con, "dataset_metadata", metadata, overwrite = TRUE)
  
  # Close connection
  dbDisconnect(con)
  
  sqlite_time <- toc(quiet = TRUE)
  db_size <- file.size(db_file)
  
  log_info("SQLite database created in {round(sqlite_time$toc - sqlite_time$tic, 2)} seconds")
  log_info("Database size: {scales::number_bytes(db_size)}")
  
  return(list(
    db_file = db_file,
    db_size = db_size,
    creation_time = sqlite_time$toc - sqlite_time$tic,
    indexes_created = length(indexes)
  ))
}

#' Convert all CSV files in directory
#' @param input_dir Directory containing CSV files
#' @param output_dir Output directory for converted files
#' @param create_partitioned Whether to create partitioned dataset
#' @param create_sqlite Whether to create SQLite database
convert_all_csv_files <- function(input_dir, output_dir, 
                                create_partitioned = TRUE,
                                create_sqlite = TRUE) {
  
  log_info("=== STARTING CSV TO PARQUET CONVERSION ===")
  log_info("Input directory: {input_dir}")
  log_info("Output directory: {output_dir}")
  
  # Create output directories
  dir_create(output_dir, recurse = TRUE)
  individual_dir <- file.path(output_dir, "individual_files")
  dir_create(individual_dir, recurse = TRUE)
  
  # Get CSV files (exclude cleaned files to work with originals)
  csv_files <- list.files(input_dir, pattern = "\\.csv$", full.names = TRUE)
  csv_files <- csv_files[!grepl("_cleaned\\.csv$", csv_files)]
  
  log_info("Found {length(csv_files)} CSV files to convert")
  
  # Convert individual files
  conversion_results <- map(csv_files, function(csv_file) {
    convert_csv_to_parquet(csv_file, individual_dir)
  })
  
  names(conversion_results) <- basename(csv_files)
  
  # Load all data for combined operations
  log_info("Loading all data for combined dataset operations...")
  
  all_data <- map_dfr(csv_files, function(file) {
    data <- fread(file, encoding = "UTF-8", fill = TRUE, blank.lines.skip = TRUE)
    data$source_file <- basename(file)
    return(data)
  })
  
  prepared_all_data <- prepare_data_types(all_data)
  
  # Create single combined Parquet file
  log_info("Creating combined Parquet file...")
  combined_file <- file.path(output_dir, "combined_legislative_dataset.parquet")
  write_parquet(prepared_all_data, combined_file, compression = "snappy")
  
  # Create partitioned dataset if requested
  partitioned_results <- NULL
  if (create_partitioned) {
    partitioned_results <- create_partitioned_dataset(prepared_all_data, output_dir)
  }
  
  # Create SQLite database if requested
  sqlite_results <- NULL
  if (create_sqlite) {
    sqlite_results <- create_sqlite_database(prepared_all_data, output_dir)
  }
  
  # Generate conversion summary
  total_csv_size <- sum(map_dbl(conversion_results, "csv_size"))
  total_parquet_size <- sum(map_dbl(conversion_results, "parquet_size"))
  overall_compression <- round((1 - total_parquet_size/total_csv_size) * 100, 2)
  total_records <- sum(map_dbl(conversion_results, "record_count"))
  
  summary_stats <- list(
    total_files_converted = length(csv_files),
    total_records = total_records,
    total_csv_size = total_csv_size,
    total_parquet_size = total_parquet_size,
    overall_compression_ratio = overall_compression,
    individual_conversions = conversion_results,
    partitioned_dataset = partitioned_results,
    sqlite_database = sqlite_results,
    combined_file = combined_file,
    combined_file_size = file.size(combined_file)
  )
  
  # Save conversion report
  saveRDS(summary_stats, file.path(output_dir, "conversion_summary.rds"))
  
  log_info("=== CONVERSION COMPLETED ===")
  log_info("Total files converted: {length(csv_files)}")
  log_info("Total records: {scales::number(total_records)}")
  log_info("Overall compression: {overall_compression}%")
  log_info("Combined file: {scales::number_bytes(file.size(combined_file))}")
  
  return(summary_stats)
}

#' Main execution function
main_conversion <- function(input_dir, output_dir) {
  
  # Validate input directory
  if (!dir.exists(input_dir)) {
    stop("Input directory does not exist: ", input_dir)
  }
  
  # Run conversion
  results <- convert_all_csv_files(input_dir, output_dir)
  
  return(results)
}

# Execute if run as script
if (!interactive()) {
  # Set paths
  input_dir <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao"
  output_dir <- file.path(dirname(input_dir), "parquet_dataset")
  
  # Run conversion
  results <- main_conversion(input_dir, output_dir)
  
  cat("Conversion completed. Results saved to:", output_dir, "\n")
}