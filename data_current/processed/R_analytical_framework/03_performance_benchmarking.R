#!/usr/bin/env Rscript
#' Brazilian Legislative Dataset - Phase 1: Performance Benchmarking
#' 
#' This script compares read/write performance between CSV and Parquet formats
#' for typical analytical queries on the Brazilian legislative dataset.
#' 
#' @author Brazilian Legislative Analytics Framework  
#' @date 2025-07-26
#' @version 1.0.0

# Load required libraries
suppressPackageStartupMessages({
  library(arrow)
  library(dplyr)
  library(data.table)
  library(readr)
  library(tictoc)
  library(bench)
  library(ggplot2)
  library(DBI)
  library(RSQLite)
  library(stringr)
  library(lubridate)
  library(purrr)
  library(logger)
})

# Set up logging
log_threshold(INFO)

#' Performance Benchmarking Functions
#' ===================================

#' Benchmark file reading performance
#' @param csv_file Path to CSV file
#' @param parquet_file Path to Parquet file
#' @param sqlite_file Path to SQLite file (optional)
#' @return Benchmark results
benchmark_file_reading <- function(csv_file, parquet_file, sqlite_file = NULL) {
  
  log_info("Benchmarking file reading performance...")
  
  # Define reading functions
  read_functions <- list(
    "CSV (data.table)" = function() fread(csv_file),
    "CSV (readr)" = function() read_csv(csv_file, locale = locale(encoding = "UTF-8")),
    "Parquet (arrow)" = function() read_parquet(parquet_file)
  )
  
  # Add SQLite if available
  if (!is.null(sqlite_file) && file.exists(sqlite_file)) {
    read_functions[["SQLite"]] <- function() {
      con <- dbConnect(SQLite(), sqlite_file)
      data <- dbReadTable(con, "legislative_data")
      dbDisconnect(con)
      return(data)
    }
  }
  
  # Run benchmarks
  benchmark_results <- bench::mark(
    `CSV (data.table)` = read_functions[["CSV (data.table)"]](),
    `CSV (readr)` = read_functions[["CSV (readr)"]](),
    `Parquet (arrow)` = read_functions[["Parquet (arrow)"]](),
    iterations = 3,
    check = FALSE  # Data types may differ slightly
  )
  
  # Add SQLite separately if available (different data structure)
  sqlite_benchmark <- NULL
  if (!is.null(sqlite_file) && file.exists(sqlite_file)) {
    sqlite_benchmark <- bench::mark(
      `SQLite` = read_functions[["SQLite"]](),
      iterations = 3
    )
  }
  
  return(list(
    main_benchmark = benchmark_results,
    sqlite_benchmark = sqlite_benchmark
  ))
}

#' Benchmark analytical queries
#' @param data_csv Data frame from CSV
#' @param parquet_file Path to Parquet file  
#' @param sqlite_file Path to SQLite file
#' @return Query benchmark results
benchmark_analytical_queries <- function(data_csv, parquet_file, sqlite_file = NULL) {
  
  log_info("Benchmarking analytical queries...")
  
  # Query 1: Aggregation by authority and year
  query1_results <- bench::mark(
    `CSV - Authority Year Agg` = {
      data_csv %>%
        filter(!is.na(data)) %>%
        mutate(year = year(as.Date(data))) %>%
        group_by(autoridade, year) %>%
        summarise(count = n(), .groups = "drop")
    },
    `Parquet - Authority Year Agg` = {
      read_parquet(parquet_file) %>%
        filter(!is.na(data)) %>%
        mutate(year = year(data)) %>%
        group_by(autoridade, year) %>%
        summarise(count = n(), .groups = "drop")
    },
    iterations = 3,
    check = FALSE
  )
  
  # Query 2: Text search and filtering
  query2_results <- bench::mark(
    `CSV - Text Search` = {
      data_csv %>%
        filter(str_detect(tolower(titulo %||% ""), "transport|regulação|agência")) %>%
        select(titulo, data, autoridade, categoria)
    },
    `Parquet - Text Search` = {
      read_parquet(parquet_file) %>%
        filter(str_detect(tolower(titulo %||% ""), "transport|regulação|agência")) %>%
        select(titulo, data, autoridade, categoria)
    },
    iterations = 3,
    check = FALSE
  )
  
  # Query 3: Complex join-like operation (temporal analysis)
  query3_results <- bench::mark(
    `CSV - Temporal Analysis` = {
      data_csv %>%
        filter(!is.na(data)) %>%
        mutate(
          year = year(as.Date(data)),
          decade = floor(year/10)*10
        ) %>%
        group_by(categoria, modal, decade) %>%
        summarise(
          count = n(),
          avg_title_length = mean(nchar(titulo %||% ""), na.rm = TRUE),
          .groups = "drop"
        ) %>%
        arrange(categoria, modal, decade)
    },
    `Parquet - Temporal Analysis` = {
      read_parquet(parquet_file) %>%
        filter(!is.na(data)) %>%
        mutate(
          year = year(data),
          decade = floor(year/10)*10
        ) %>%
        group_by(categoria, modal, decade) %>%
        summarise(
          count = n(),
          avg_title_length = mean(nchar(titulo %||% ""), na.rm = TRUE),
          .groups = "drop"
        ) %>%
        arrange(categoria, modal, decade)
    },
    iterations = 3,
    check = FALSE
  )
  
  # SQLite queries if available
  sqlite_queries <- NULL
  if (!is.null(sqlite_file) && file.exists(sqlite_file)) {
    
    sqlite_queries <- list()
    
    # SQLite Query 1
    sqlite_queries$query1 <- bench::mark(
      `SQLite - Authority Year Agg` = {
        con <- dbConnect(SQLite(), sqlite_file)
        result <- dbGetQuery(con, "
          SELECT autoridade, 
                 CAST(strftime('%Y', data) AS INTEGER) as year,
                 COUNT(*) as count
          FROM legislative_data 
          WHERE data IS NOT NULL
          GROUP BY autoridade, year
        ")
        dbDisconnect(con)
        result
      },
      iterations = 3
    )
    
    # SQLite Query 2 (simplified - SQLite doesn't have regex easily)
    sqlite_queries$query2 <- bench::mark(
      `SQLite - Text Search` = {
        con <- dbConnect(SQLite(), sqlite_file)
        result <- dbGetQuery(con, "
          SELECT titulo, data, autoridade, categoria
          FROM legislative_data 
          WHERE LOWER(titulo) LIKE '%transport%' 
             OR LOWER(titulo) LIKE '%regulação%'
             OR LOWER(titulo) LIKE '%agência%'
        ")
        dbDisconnect(con)
        result
      },
      iterations = 3
    )
  }
  
  return(list(
    query1_aggregation = query1_results,
    query2_text_search = query2_results,
    query3_temporal = query3_results,
    sqlite_queries = sqlite_queries
  ))
}

#' Benchmark partitioned dataset queries
#' @param partitioned_dir Path to partitioned dataset directory
#' @return Partitioned query benchmark results
benchmark_partitioned_queries <- function(partitioned_dir) {
  
  log_info("Benchmarking partitioned dataset queries...")
  
  if (!dir.exists(partitioned_dir)) {
    log_warn("Partitioned directory not found: {partitioned_dir}")
    return(NULL)
  }
  
  # Open partitioned dataset
  dataset <- open_dataset(partitioned_dir)
  
  # Query 1: Filter by partition (should be very fast)
  partition_query1 <- bench::mark(
    `Partitioned - Federal Only` = {
      dataset %>%
        filter(authority_level == "Federal") %>%
        collect()
    },
    iterations = 3
  )
  
  # Query 2: Cross-partition aggregation
  partition_query2 <- bench::mark(
    `Partitioned - Cross Authority Agg` = {
      dataset %>%
        group_by(authority_level, categoria) %>%
        summarise(count = n()) %>%
        collect()
    },
    iterations = 3
  )
  
  # Query 3: Temporal filter with partitions
  partition_query3 <- bench::mark(
    `Partitioned - Recent Years` = {
      dataset %>%
        filter(year_partition >= 2010) %>%
        group_by(year_partition, authority_level) %>%
        summarise(count = n()) %>%
        collect()
    },
    iterations = 3
  )
  
  return(list(
    partition_filter = partition_query1,
    cross_partition_agg = partition_query2,
    temporal_partition = partition_query3
  ))
}

#' Generate performance comparison report
#' @param benchmark_results All benchmark results
#' @param output_dir Output directory for reports
generate_performance_report <- function(benchmark_results, output_dir) {
  
  log_info("Generating performance comparison report...")
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Extract timing information
  file_reading_times <- benchmark_results$file_reading$main_benchmark %>%
    select(expression, median, mem_alloc) %>%
    mutate(
      median_seconds = as.numeric(median),
      memory_mb = as.numeric(mem_alloc) / 1024^2
    )
  
  # Create performance comparison plots
  
  # 1. File reading performance
  reading_plot <- file_reading_times %>%
    ggplot(aes(x = reorder(expression, median_seconds), y = median_seconds)) +
    geom_col(fill = "steelblue") +
    coord_flip() +
    scale_y_continuous(labels = scales::number_format(suffix = "s")) +
    labs(
      title = "File Reading Performance Comparison",
      subtitle = "Median time to read complete dataset",
      x = "Format", y = "Time (seconds)"
    ) +
    theme_minimal()
  
  # 2. Memory usage comparison
  memory_plot <- file_reading_times %>%
    ggplot(aes(x = reorder(expression, memory_mb), y = memory_mb)) +
    geom_col(fill = "darkgreen") +
    coord_flip() +
    scale_y_continuous(labels = scales::number_format(suffix = " MB")) +
    labs(
      title = "Memory Usage Comparison",
      subtitle = "Peak memory allocation during reading",
      x = "Format", y = "Memory (MB)"
    ) +
    theme_minimal()
  
  # 3. Query performance comparison
  query_performance <- list()
  
  for (query_name in names(benchmark_results$analytical_queries)) {
    if (!is.null(benchmark_results$analytical_queries[[query_name]])) {
      query_data <- benchmark_results$analytical_queries[[query_name]] %>%
        select(expression, median) %>%
        mutate(
          query_type = query_name,
          median_seconds = as.numeric(median)
        )
      query_performance[[query_name]] <- query_data
    }
  }
  
  if (length(query_performance) > 0) {
    combined_query_data <- bind_rows(query_performance)
    
    query_plot <- combined_query_data %>%
      ggplot(aes(x = expression, y = median_seconds, fill = query_type)) +
      geom_col(position = "dodge") +
      coord_flip() +
      scale_y_continuous(labels = scales::number_format(suffix = "s")) +
      labs(
        title = "Analytical Query Performance",
        subtitle = "Median execution time by format and query type",
        x = "Query", y = "Time (seconds)", fill = "Query Type"
      ) +
      theme_minimal() +
      theme(legend.position = "bottom")
  }
  
  # Save plots
  ggsave(file.path(output_dir, "reading_performance.png"), reading_plot, 
         width = 10, height = 6, dpi = 300)
  ggsave(file.path(output_dir, "memory_usage.png"), memory_plot, 
         width = 10, height = 6, dpi = 300)
  if (exists("query_plot")) {
    ggsave(file.path(output_dir, "query_performance.png"), query_plot, 
           width = 12, height = 8, dpi = 300)
  }
  
  # Create summary statistics
  performance_summary <- list(
    file_reading = file_reading_times,
    fastest_format = file_reading_times$expression[which.min(file_reading_times$median_seconds)],
    most_memory_efficient = file_reading_times$expression[which.min(file_reading_times$memory_mb)],
    parquet_vs_csv_speedup = file_reading_times$median_seconds[file_reading_times$expression == "CSV (data.table)"] / 
                            file_reading_times$median_seconds[file_reading_times$expression == "Parquet (arrow)"],
    benchmark_results = benchmark_results
  )
  
  # Save detailed results
  saveRDS(performance_summary, file.path(output_dir, "performance_summary.rds"))
  write_csv(file_reading_times, file.path(output_dir, "file_reading_performance.csv"))
  
  # Generate text summary
  summary_text <- glue::glue("
    PERFORMANCE BENCHMARKING SUMMARY
    ================================
    
    Fastest Format: {performance_summary$fastest_format}
    Most Memory Efficient: {performance_summary$most_memory_efficient}
    Parquet vs CSV Speedup: {round(performance_summary$parquet_vs_csv_speedup, 2)}x
    
    File Reading Performance (median time):
    {paste(file_reading_times$expression, ': ', round(file_reading_times$median_seconds, 3), 's', collapse = '\n')}
    
    Memory Usage (peak allocation):
    {paste(file_reading_times$expression, ': ', round(file_reading_times$memory_mb, 1), ' MB', collapse = '\n')}
  ")
  
  writeLines(summary_text, file.path(output_dir, "performance_summary.txt"))
  
  return(performance_summary)
}

#' Main benchmarking function
#' @param csv_dir Directory with CSV files
#' @param parquet_dir Directory with Parquet files
#' @param output_dir Output directory for results
run_performance_benchmarking <- function(csv_dir, parquet_dir, output_dir) {
  
  log_info("=== STARTING PERFORMANCE BENCHMARKING ===")
  
  # Find main files for benchmarking
  main_csv <- file.path(csv_dir, "lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv")
  combined_parquet <- file.path(parquet_dir, "combined_legislative_dataset.parquet")
  sqlite_file <- file.path(parquet_dir, "legislative_dataset.sqlite")
  partitioned_dir <- file.path(parquet_dir, "partitioned_dataset")
  
  # Verify files exist
  if (!file.exists(main_csv)) {
    stop("Main CSV file not found: ", main_csv)
  }
  if (!file.exists(combined_parquet)) {
    stop("Combined Parquet file not found: ", combined_parquet)
  }
  
  # 1. Benchmark file reading
  log_info("1. Benchmarking file reading performance...")
  file_reading_results <- benchmark_file_reading(main_csv, combined_parquet, sqlite_file)
  
  # 2. Load data for analytical queries
  log_info("2. Loading data for analytical benchmarks...")
  csv_data <- fread(main_csv, encoding = "UTF-8")
  
  # 3. Benchmark analytical queries
  log_info("3. Benchmarking analytical queries...")
  analytical_results <- benchmark_analytical_queries(csv_data, combined_parquet, sqlite_file)
  
  # 4. Benchmark partitioned queries if available
  partitioned_results <- NULL
  if (dir.exists(partitioned_dir)) {
    log_info("4. Benchmarking partitioned dataset queries...")
    partitioned_results <- benchmark_partitioned_queries(partitioned_dir)
  }
  
  # Combine all results
  all_results <- list(
    file_reading = file_reading_results,
    analytical_queries = analytical_results,
    partitioned_queries = partitioned_results
  )
  
  # 5. Generate performance report
  log_info("5. Generating performance report...")
  performance_summary <- generate_performance_report(all_results, output_dir)
  
  log_info("=== BENCHMARKING COMPLETED ===")
  
  return(performance_summary)
}

# Execute if run as script
if (!interactive()) {
  # Set paths
  csv_dir <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao"
  parquet_dir <- file.path(dirname(csv_dir), "parquet_dataset")
  output_dir <- file.path(dirname(csv_dir), "performance_benchmarks")
  
  # Check if Parquet files exist (need to run conversion first)
  if (!dir.exists(parquet_dir)) {
    cat("Parquet directory not found. Please run CSV to Parquet conversion first.\n")
    cat("Run: Rscript 02_csv_to_parquet_conversion.R\n")
    quit(status = 1)
  }
  
  # Run benchmarking
  results <- run_performance_benchmarking(csv_dir, parquet_dir, output_dir)
  
  cat("Performance benchmarking completed. Results saved to:", output_dir, "\n")
}