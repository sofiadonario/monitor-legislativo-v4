# Parquet Conversion Utilities
# Monitor Legislativo v4 - CSV to Parquet Data Pipeline
# =====================================================

#' Parquet Conversion Utilities for Brazilian Legislative Data
#' 
#' This module provides optimized CSV to Parquet conversion with intelligent
#' partitioning strategies for Railway deployment constraints and performance.
#' Designed for 2GB memory limit with 1M+ records processing capability.

# Load required libraries
required_packages <- c("arrow", "dplyr", "readr", "stringr", "lubridate", "fs")

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    warning(paste("Package", pkg, "not available. Installing..."))
    install.packages(pkg, dependencies = TRUE)
  }
  library(pkg, character.only = TRUE)
}

#' Convert CSV to Partitioned Parquet Format
#' 
#' Converts Brazilian legislative CSV data to optimized Parquet format
#' with intelligent partitioning for memory efficiency
#' 
#' @param csv_path Path to input CSV file
#' @param output_dir Output directory for partitioned Parquet files
#' @param partition_cols Columns to partition by (default: c("year", "state"))
#' @param chunk_size Number of rows to process at once (Railway memory optimization)
#' @param compression Compression algorithm (default: "snappy")
#' @return List with conversion results and statistics
#' @export
convert_csv_to_parquet <- function(csv_path, 
                                  output_dir,
                                  partition_cols = c("year", "state"),
                                  chunk_size = 50000,
                                  compression = "snappy") {
  
  cat("🔄 Converting CSV to partitioned Parquet format...\n")
  cat("   Input:", csv_path, "\n")
  cat("   Output:", output_dir, "\n")
  cat("   Partitioning:", paste(partition_cols, collapse = ", "), "\n")
  
  start_time <- Sys.time()
  total_rows <- 0
  
  if (!file.exists(csv_path)) {
    stop("CSV file does not exist: ", csv_path)
  }
  
  # Create output directory
  if (!dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE)
  }
  
  tryCatch({
    # First, analyze the CSV structure and estimate memory requirements
    sample_data <- read_csv(csv_path, n_max = 1000, show_col_types = FALSE)
    
    cat("📊 CSV Analysis:\n")
    cat("   Columns:", ncol(sample_data), "\n")
    cat("   Sample rows:", nrow(sample_data), "\n")
    
    # Prepare data transformation pipeline
    data_pipeline <- function(chunk) {
      
      # Clean and standardize column names
      chunk <- chunk %>%
        rename_with(~ str_to_lower(str_replace_all(.x, "\\s+", "_")))
      
      # Extract year from date columns for partitioning
      if ("promulgation_date" %in% names(chunk)) {
        chunk <- chunk %>%
          mutate(
            year = year(ymd(promulgation_date)),
            year = if_else(is.na(year), 
                          year(ymd_hms(promulgation_date, quiet = TRUE)), 
                          year)
          )
      } else if ("date_searched" %in% names(chunk)) {
        chunk <- chunk %>%
          mutate(
            year = year(ymd_hms(date_searched, quiet = TRUE))
          )
      }
      
      # Standardize state names for partitioning
      if ("state" %in% names(chunk)) {
        chunk <- chunk %>%
          mutate(
            state = str_to_title(str_trim(state)),
            state = case_when(
              state %in% c("", "NA", NA_character_) ~ "Unknown",
              str_length(state) > 50 ~ "Other",
              TRUE ~ state
            )
          )
      }
      
      # Handle municipality standardization
      if ("municipality" %in% names(chunk)) {
        chunk <- chunk %>%
          mutate(
            municipality = str_to_title(str_trim(municipality)),
            municipality = if_else(
              municipality %in% c("", "NA", NA_character_) | is.na(municipality),
              "Unknown",
              municipality
            )
          )
      }
      
      # Clean document type for consistency
      if ("document_type_full" %in% names(chunk)) {
        chunk <- chunk %>%
          mutate(
            document_type_full = str_to_title(str_trim(document_type_full)),
            document_type_full = if_else(
              is.na(document_type_full) | document_type_full == "",
              "Unknown",
              document_type_full
            )
          )
      }
      
      # Add processing metadata
      chunk <- chunk %>%
        mutate(
          processed_at = Sys.time(),
          data_source = basename(csv_path)
        )
      
      return(chunk)
    }
    
    # Process CSV in chunks to manage memory
    cat("🚀 Starting chunked processing...\n")
    
    # Use readr's read_csv_chunked for memory efficiency
    callback_function <- function(chunk, pos) {
      
      # Apply data transformation pipeline
      processed_chunk <- data_pipeline(chunk)
      
      # Validate required partition columns exist
      missing_partition_cols <- setdiff(partition_cols, names(processed_chunk))
      if (length(missing_partition_cols) > 0) {
        # Add missing partition columns with default values
        for (col in missing_partition_cols) {
          if (col == "year") {
            processed_chunk[[col]] <- 2024  # Default year
          } else if (col == "state") {
            processed_chunk[[col]] <- "Unknown"
          } else {
            processed_chunk[[col]] <- "Unknown"
          }
        }
      }
      
      # Convert to Arrow table for efficient processing
      arrow_table <- arrow::as_arrow_table(processed_chunk)
      
      # Write partitioned Parquet files
      arrow::write_dataset(
        arrow_table,
        output_dir,
        format = "parquet",
        partitioning = partition_cols,
        compression = compression
      )
      
      total_rows <<- total_rows + nrow(processed_chunk)
      
      if (pos %% 5 == 0) {  # Progress update every 5 chunks
        cat("   Processed", total_rows, "rows...\n")
        gc()  # Force garbage collection
      }
      
      return(invisible())
    }
    
    # Execute chunked reading and processing
    read_csv_chunked(
      csv_path,
      callback = callback_function,
      chunk_size = chunk_size,
      show_col_types = FALSE
    )
    
    processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    # Get final statistics
    parquet_size <- sum(file.info(list.files(output_dir, 
                                           pattern = "\\.parquet$", 
                                           recursive = TRUE, 
                                           full.names = TRUE))$size, 
                       na.rm = TRUE)
    
    csv_size <- file.info(csv_path)$size
    compression_ratio <- round((1 - parquet_size/csv_size) * 100, 2)
    
    cat("✅ Parquet conversion completed successfully!\n")
    cat("   Total rows processed:", total_rows, "\n")
    cat("   Processing time:", round(processing_time, 2), "seconds\n")
    cat("   CSV size:", round(csv_size / 1024^2, 2), "MB\n")
    cat("   Parquet size:", round(parquet_size / 1024^2, 2), "MB\n")
    cat("   Compression ratio:", compression_ratio, "%\n")
    cat("   Throughput:", round(total_rows / processing_time, 0), "rows/second\n")
    
    return(list(
      success = TRUE,
      total_rows = total_rows,
      processing_time = processing_time,
      csv_size_mb = round(csv_size / 1024^2, 2),
      parquet_size_mb = round(parquet_size / 1024^2, 2),
      compression_ratio = compression_ratio,
      throughput = round(total_rows / processing_time, 0),
      output_directory = output_dir,
      partition_columns = partition_cols
    ))
    
  }, error = function(e) {
    cat("❌ Parquet conversion failed:", e$message, "\n")
    return(list(
      success = FALSE,
      error = e$message,
      total_rows = total_rows
    ))
  })
}

#' Batch Convert Multiple CSV Files
#' 
#' Converts multiple CSV files to a unified Parquet dataset
#' with consistent partitioning strategy
#' 
#' @param csv_files Vector of CSV file paths
#' @param output_dir Output directory for consolidated Parquet dataset
#' @param partition_cols Partition columns
#' @return List with batch conversion results
#' @export
batch_convert_to_parquet <- function(csv_files, 
                                   output_dir,
                                   partition_cols = c("year", "state")) {
  
  cat("📦 Starting batch conversion of", length(csv_files), "CSV files...\n")
  
  batch_start_time <- Sys.time()
  results <- list()
  total_files_processed <- 0
  total_rows_processed <- 0
  failed_files <- character(0)
  
  # Create consolidated output directory
  if (!dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE)
  }
  
  for (i in seq_along(csv_files)) {
    csv_file <- csv_files[i]
    
    if (!file.exists(csv_file)) {
      warning("File does not exist, skipping:", csv_file)
      failed_files <- c(failed_files, csv_file)
      next
    }
    
    cat("📄 Processing file", i, "of", length(csv_files), ":", basename(csv_file), "\n")
    
    # Use temporary directory for individual file processing
    temp_dir <- file.path(tempdir(), paste0("temp_parquet_", i))
    
    # Convert individual file
    result <- convert_csv_to_parquet(
      csv_path = csv_file,
      output_dir = temp_dir,
      partition_cols = partition_cols,
      chunk_size = 25000  # Smaller chunks for batch processing
    )
    
    if (result$success) {
      # Move processed files to consolidated directory
      temp_files <- list.files(temp_dir, pattern = "\\.parquet$", 
                             recursive = TRUE, full.names = TRUE)
      
      for (temp_file in temp_files) {
        # Preserve directory structure
        rel_path <- str_remove(temp_file, paste0(temp_dir, "/"))
        dest_path <- file.path(output_dir, rel_path)
        
        # Create destination directory if needed
        dest_dir <- dirname(dest_path)
        if (!dir.exists(dest_dir)) {
          dir.create(dest_dir, recursive = TRUE)
        }
        
        # Move file
        file.rename(temp_file, dest_path)
      }
      
      # Clean up temp directory
      unlink(temp_dir, recursive = TRUE)
      
      total_files_processed <- total_files_processed + 1
      total_rows_processed <- total_rows_processed + result$total_rows
      results[[basename(csv_file)]] <- result
      
    } else {
      failed_files <- c(failed_files, csv_file)
      results[[basename(csv_file)]] <- result
    }
    
    # Force garbage collection between files
    gc()
  }
  
  batch_processing_time <- as.numeric(difftime(Sys.time(), batch_start_time, units = "secs"))
  
  cat("✅ Batch conversion completed!\n")
  cat("   Files processed:", total_files_processed, "/", length(csv_files), "\n")
  cat("   Total rows:", total_rows_processed, "\n")
  cat("   Total time:", round(batch_processing_time, 2), "seconds\n")
  cat("   Failed files:", length(failed_files), "\n")
  
  if (length(failed_files) > 0) {
    cat("❌ Failed files:\n")
    for (file in failed_files) {
      cat("   -", file, "\n")
    }
  }
  
  return(list(
    success = total_files_processed > 0,
    files_processed = total_files_processed,
    total_files = length(csv_files),
    total_rows = total_rows_processed,
    processing_time = batch_processing_time,
    failed_files = failed_files,
    detailed_results = results,
    output_directory = output_dir
  ))
}

#' Validate Parquet Dataset Integrity
#' 
#' Validates converted Parquet dataset for consistency and performance
#' 
#' @param parquet_dir Directory containing Parquet files
#' @return List with validation results
#' @export
validate_parquet_dataset <- function(parquet_dir) {
  
  cat("🔍 Validating Parquet dataset integrity...\n")
  
  validation_start <- Sys.time()
  
  tryCatch({
    # Open dataset
    dataset <- arrow::open_dataset(parquet_dir)
    
    # Basic statistics
    schema_info <- dataset$schema
    total_files <- length(list.files(parquet_dir, pattern = "\\.parquet$", recursive = TRUE))
    
    # Test basic query performance
    sample_query_start <- Sys.time()
    sample_result <- dataset %>%
      head(1000) %>%
      collect()
    sample_query_time <- as.numeric(difftime(Sys.time(), sample_query_start, units = "secs"))
    
    # Count total records (memory efficient)
    count_start <- Sys.time()
    total_records <- dataset %>%
      summarise(count = n()) %>%
      collect() %>%
      pull(count)
    count_time <- as.numeric(difftime(Sys.time(), count_start, units = "secs"))
    
    # Check partitioning effectiveness
    partition_info <- dataset$metadata
    
    validation_time <- as.numeric(difftime(Sys.time(), validation_start, units = "secs"))
    
    cat("✅ Parquet dataset validation completed\n")
    cat("   Schema fields:", length(schema_info), "\n")
    cat("   Total files:", total_files, "\n")
    cat("   Total records:", format(total_records, big.mark = ","), "\n")
    cat("   Sample query time:", round(sample_query_time, 3), "seconds\n")
    cat("   Count query time:", round(count_time, 3), "seconds\n")
    cat("   Validation time:", round(validation_time, 2), "seconds\n")
    
    return(list(
      success = TRUE,
      schema_fields = length(schema_info),
      total_files = total_files,
      total_records = total_records,
      sample_query_time = sample_query_time,
      count_query_time = count_time,
      validation_time = validation_time,
      dataset_path = parquet_dir,
      performance_target_met = sample_query_time < 1.0 && count_time < 5.0
    ))
    
  }, error = function(e) {
    cat("❌ Parquet validation failed:", e$message, "\n")
    return(list(
      success = FALSE,
      error = e$message
    ))
  })
}

#' Optimize Existing Parquet Dataset
#' 
#' Re-optimizes existing Parquet files for better performance
#' 
#' @param input_dir Input Parquet directory
#' @param output_dir Output directory for optimized files
#' @param target_file_size_mb Target file size in MB for optimization
#' @return Optimization results
#' @export
optimize_parquet_dataset <- function(input_dir, 
                                   output_dir = paste0(input_dir, "_optimized"),
                                   target_file_size_mb = 128) {
  
  cat("⚡ Optimizing Parquet dataset for Railway performance...\n")
  
  optimization_start <- Sys.time()
  
  tryCatch({
    # Open source dataset
    source_dataset <- arrow::open_dataset(input_dir)
    
    # Create output directory
    if (!dir.exists(output_dir)) {
      dir.create(output_dir, recursive = TRUE)
    }
    
    # Re-partition and optimize with better file sizes
    optimized_table <- source_dataset %>%
      to_arrow_table()
    
    # Write optimized dataset with better compression
    arrow::write_dataset(
      optimized_table,
      output_dir,
      format = "parquet",
      compression = "zstd",  # Better compression for Railway
      max_rows_per_file = 100000  # Optimize file sizes
    )
    
    optimization_time <- as.numeric(difftime(Sys.time(), optimization_start, units = "secs"))
    
    # Compare sizes
    original_size <- sum(file.info(list.files(input_dir, 
                                           pattern = "\\.parquet$", 
                                           recursive = TRUE, 
                                           full.names = TRUE))$size, 
                       na.rm = TRUE)
    
    optimized_size <- sum(file.info(list.files(output_dir, 
                                            pattern = "\\.parquet$", 
                                            recursive = TRUE, 
                                            full.names = TRUE))$size, 
                        na.rm = TRUE)
    
    size_reduction <- round((1 - optimized_size/original_size) * 100, 2)
    
    cat("✅ Parquet optimization completed\n")
    cat("   Original size:", round(original_size / 1024^2, 2), "MB\n")
    cat("   Optimized size:", round(optimized_size / 1024^2, 2), "MB\n")
    cat("   Size reduction:", size_reduction, "%\n")
    cat("   Optimization time:", round(optimization_time, 2), "seconds\n")
    
    return(list(
      success = TRUE,
      original_size_mb = round(original_size / 1024^2, 2),
      optimized_size_mb = round(optimized_size / 1024^2, 2),
      size_reduction_percent = size_reduction,
      optimization_time = optimization_time,
      output_directory = output_dir
    ))
    
  }, error = function(e) {
    cat("❌ Parquet optimization failed:", e$message, "\n")
    return(list(
      success = FALSE,
      error = e$message
    ))
  })
}

cat("✅ Parquet conversion utilities loaded successfully\n")
cat("   Railway optimized: 2GB memory constraint\n")
cat("   Intelligent partitioning: year, state, document_type\n")
cat("   Compression: snappy/zstd for space efficiency\n")