#!/usr/bin/env Rscript
#' Brazilian Legislative Dataset - Phase 1: Data Quality Assessment
#' 
#' This script performs comprehensive data quality assessment for the Brazilian
#' legislative dataset from LexML portal, examining CSV structure, identifying
#' column types, checking for missing values, malformed URNs, invalid dates,
#' and authority-jurisdiction inconsistencies.
#' 
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-07-26
#' @version 1.0.0

# Load required libraries
suppressPackageStartupMessages({
  library(tidyverse)
  library(data.table)
  library(stringr)
  library(lubridate)
  library(VIM)
  library(visdat)
  library(DT)
  library(plotly)
  library(knitr)
  library(kableExtra)
  library(corrplot)
  library(janitor)
  library(skimr)
})

# Set global options
options(stringsAsFactors = FALSE)
Sys.setlocale("LC_ALL", "Portuguese_Brazil.UTF-8")

#' Data Quality Assessment Functions
#' ================================

#' Load and combine all CSV files
#' @param data_dir Directory containing CSV files
#' @return Combined data frame with source file information
load_legislative_data <- function(data_dir) {
  
  cat("Loading legislative data from:", data_dir, "\n")
  
  # Get all CSV files
  csv_files <- list.files(data_dir, pattern = "\\.csv$", full.names = TRUE)
  csv_files <- csv_files[!grepl("_cleaned\\.csv$", csv_files)]  # Exclude cleaned files
  
  cat("Found", length(csv_files), "CSV files\n")
  
  # Load and combine data
  combined_data <- map_dfr(csv_files, function(file) {
    cat("Loading:", basename(file), "\n")
    
    tryCatch({
      # Use fread for better handling of problematic CSV files
      data <- fread(file, encoding = "UTF-8", fill = TRUE, blank.lines.skip = TRUE)
      
      # Add source file information
      data$source_file <- basename(file)
      data$file_category <- str_extract(basename(file), "lexml_([^_]+)", group = 1)
      data$file_modal <- str_extract(basename(file), "lexml_[^_]+_([^_]+)", group = 1)
      
      return(data)
    }, error = function(e) {
      cat("Error loading", basename(file), ":", e$message, "\n")
      return(NULL)
    })
  })
  
  cat("Total records loaded:", nrow(combined_data), "\n")
  return(combined_data)
}

#' Validate URN format compliance
#' @param urn_vector Vector of URN strings
#' @return Data frame with validation results
validate_urns <- function(urn_vector) {
  
  # Brazilian URN pattern: urn:lex:br:federal|estado|municipal:type:date;number
  valid_pattern <- "^urn:lex:br:(federal|[a-z]{2}|municipal):[a-z]+:[0-9]{4}-[0-9]{2}-[0-9]{2};[0-9]+.*$"
  
  validation_results <- tibble(
    urn = urn_vector,
    is_valid = str_detect(urn, valid_pattern),
    is_empty = is.na(urn) | urn == "",
    authority_level = case_when(
      str_detect(urn, ":federal:") ~ "Federal",
      str_detect(urn, ":[a-z]{2}:") ~ "State", 
      str_detect(urn, ":municipal:") ~ "Municipal",
      TRUE ~ "Unknown"
    ),
    document_type = str_extract(urn, ":([a-z]+):[0-9]{4}", group = 1),
    date_from_urn = str_extract(urn, "([0-9]{4}-[0-9]{2}-[0-9]{2})", group = 1)
  )
  
  return(validation_results)
}

#' Check authority-jurisdiction consistency
#' @param data Data frame with autoridade and jurisdicao columns
#' @return Summary of inconsistencies
check_authority_jurisdiction_consistency <- function(data) {
  
  consistency_check <- data %>%
    filter(!is.na(autoridade) & !is.na(jurisdicao)) %>%
    group_by(autoridade, jurisdicao) %>%
    summarise(count = n(), .groups = "drop") %>%
    arrange(autoridade, desc(count))
  
  # Flag potential inconsistencies
  inconsistencies <- data %>%
    mutate(
      potential_inconsistency = case_when(
        str_detect(tolower(autoridade), "federal") & jurisdicao != "Federal" ~ "Authority suggests federal but jurisdiction differs",
        str_detect(tolower(autoridade), "estadual|estado") & jurisdicao == "Federal" ~ "Authority suggests state but jurisdiction is federal",
        str_detect(tolower(autoridade), "municipal|prefeitura") & jurisdicao == "Federal" ~ "Authority suggests municipal but jurisdiction is federal",
        TRUE ~ "No obvious inconsistency"
      )
    ) %>%
    filter(potential_inconsistency != "No obvious inconsistency") %>%
    group_by(potential_inconsistency) %>%
    summarise(count = n(), .groups = "drop")
  
  return(list(
    consistency_summary = consistency_check,
    inconsistencies = inconsistencies
  ))
}

#' Generate comprehensive data quality report
#' @param data Combined legislative dataset
#' @param output_dir Directory to save reports
generate_quality_report <- function(data, output_dir) {
  
  cat("Generating comprehensive data quality report...\n")
  
  # Create output directory
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # 1. Basic data overview
  cat("1. Basic data overview...\n")
  basic_stats <- data %>%
    summarise(
      total_records = n(),
      total_columns = ncol(.),
      date_range_start = min(data, na.rm = TRUE),
      date_range_end = max(data, na.rm = TRUE),
      unique_authorities = n_distinct(autoridade, na.rm = TRUE),
      unique_jurisdictions = n_distinct(jurisdicao, na.rm = TRUE),
      unique_categories = n_distinct(categoria, na.rm = TRUE),
      unique_modals = n_distinct(modal, na.rm = TRUE)
    )
  
  # 2. Missing data analysis
  cat("2. Missing data analysis...\n")
  missing_analysis <- data %>%
    summarise_all(~sum(is.na(.) | . == "")) %>%
    pivot_longer(everything(), names_to = "column", values_to = "missing_count") %>%
    mutate(
      missing_percentage = round(missing_count / nrow(data) * 100, 2),
      completeness = 100 - missing_percentage
    ) %>%
    arrange(desc(missing_percentage))
  
  # 3. URN validation
  cat("3. URN validation...\n")
  urn_validation <- validate_urns(data$urn)
  urn_summary <- urn_validation %>%
    summarise(
      total_urns = n(),
      valid_urns = sum(is_valid, na.rm = TRUE),
      empty_urns = sum(is_empty, na.rm = TRUE),
      invalid_urns = sum(!is_valid & !is_empty, na.rm = TRUE),
      validation_rate = round(valid_urns / (total_urns - empty_urns) * 100, 2)
    )
  
  # 4. Date validation
  cat("4. Date validation...\n")
  date_validation <- data %>%
    mutate(
      data_parsed = ymd(data),
      data_coleta_parsed = ymd_hms(data_coleta),
      is_valid_data = !is.na(data_parsed),
      is_valid_data_coleta = !is.na(data_coleta_parsed),
      year_from_date = year(data_parsed),
      data_in_future = data_parsed > Sys.Date(),
      data_before_1900 = data_parsed < as.Date("1900-01-01")
    )
  
  date_summary <- date_validation %>%
    summarise(
      valid_data_dates = sum(is_valid_data, na.rm = TRUE),
      valid_coleta_dates = sum(is_valid_data_coleta, na.rm = TRUE),
      dates_in_future = sum(data_in_future, na.rm = TRUE),
      dates_before_1900 = sum(data_before_1900, na.rm = TRUE),
      earliest_date = min(data_parsed, na.rm = TRUE),
      latest_date = max(data_parsed, na.rm = TRUE)
    )
  
  # 5. Authority-jurisdiction consistency
  cat("5. Authority-jurisdiction consistency...\n")
  consistency_check <- check_authority_jurisdiction_consistency(data)
  
  # 6. Text field analysis
  cat("6. Text field analysis...\n")
  text_analysis <- data %>%
    summarise(
      avg_titulo_length = mean(nchar(titulo), na.rm = TRUE),
      avg_assuntos_length = mean(nchar(assuntos), na.rm = TRUE),
      avg_ementa_length = mean(nchar(ementa), na.rm = TRUE),
      max_titulo_length = max(nchar(titulo), na.rm = TRUE),
      max_assuntos_length = max(nchar(assuntos), na.rm = TRUE),
      max_ementa_length = max(nchar(ementa), na.rm = TRUE)
    )
  
  # 7. Temporal coverage analysis
  cat("7. Temporal coverage analysis...\n")
  temporal_coverage <- date_validation %>%
    filter(is_valid_data) %>%
    group_by(year_from_date, categoria, modal) %>%
    summarise(count = n(), .groups = "drop") %>%
    arrange(year_from_date)
  
  # 8. Category and modal distribution
  cat("8. Category and modal distribution...\n")
  category_distribution <- data %>%
    group_by(categoria, modal) %>%
    summarise(
      count = n(),
      avg_completeness = mean(rowSums(!is.na(select(., -categoria, -modal))) / (ncol(.) - 2) * 100),
      .groups = "drop"
    ) %>%
    arrange(desc(count))
  
  # Create visualizations
  cat("9. Creating visualizations...\n")
  
  # Missing data heatmap
  missing_plot <- VIM::aggr(data, col = c('navyblue','red'), 
                            numbers = TRUE, sortVars = TRUE)
  
  # Temporal coverage plot
  temporal_plot <- temporal_coverage %>%
    ggplot(aes(x = year_from_date, y = count, fill = categoria)) +
    geom_col() +
    facet_wrap(~modal, scales = "free_y") +
    theme_minimal() +
    labs(title = "Temporal Coverage by Category and Modal",
         x = "Year", y = "Number of Records") +
    theme(axis.text.x = element_text(angle = 45, hjust = 1))
  
  # Completeness by field
  completeness_plot <- missing_analysis %>%
    ggplot(aes(x = reorder(column, completeness), y = completeness)) +
    geom_col(fill = "steelblue") +
    coord_flip() +
    theme_minimal() +
    labs(title = "Data Completeness by Field",
         x = "Field", y = "Completeness Percentage") +
    geom_text(aes(label = paste0(completeness, "%")), hjust = -0.1, size = 3)
  
  # Save visualizations
  ggsave(file.path(output_dir, "temporal_coverage.png"), temporal_plot, 
         width = 12, height = 8, dpi = 300)
  ggsave(file.path(output_dir, "completeness_by_field.png"), completeness_plot, 
         width = 10, height = 8, dpi = 300)
  
  # Generate HTML report
  cat("10. Generating HTML report...\n")
  
  report_data <- list(
    basic_stats = basic_stats,
    missing_analysis = missing_analysis,
    urn_summary = urn_summary,
    date_summary = date_summary,
    consistency_check = consistency_check,
    text_analysis = text_analysis,
    temporal_coverage = temporal_coverage,
    category_distribution = category_distribution
  )
  
  # Save detailed results
  saveRDS(report_data, file.path(output_dir, "quality_assessment_detailed.rds"))
  write_csv(missing_analysis, file.path(output_dir, "missing_data_analysis.csv"))
  write_csv(urn_validation, file.path(output_dir, "urn_validation_results.csv"))
  write_csv(temporal_coverage, file.path(output_dir, "temporal_coverage.csv"))
  write_csv(category_distribution, file.path(output_dir, "category_distribution.csv"))
  
  cat("Data quality assessment complete. Results saved to:", output_dir, "\n")
  
  return(report_data)
}

#' Main execution function
#' @param data_dir Directory containing CSV files
#' @param output_dir Directory to save results
main_quality_assessment <- function(data_dir, output_dir = "quality_reports") {
  
  cat("=== BRAZILIAN LEGISLATIVE DATASET - QUALITY ASSESSMENT ===\n")
  cat("Start time:", Sys.time(), "\n\n")
  
  # Load data
  legislative_data <- load_legislative_data(data_dir)
  
  if (is.null(legislative_data) || nrow(legislative_data) == 0) {
    stop("No data loaded. Please check the data directory.")
  }
  
  # Generate quality report
  quality_results <- generate_quality_report(legislative_data, output_dir)
  
  cat("\n=== QUALITY ASSESSMENT SUMMARY ===\n")
  cat("Total records processed:", nrow(legislative_data), "\n")
  cat("Data completeness range:", 
      round(min(quality_results$missing_analysis$completeness), 2), "% to",
      round(max(quality_results$missing_analysis$completeness), 2), "%\n")
  cat("URN validation rate:", quality_results$urn_summary$validation_rate, "%\n")
  cat("Date range:", quality_results$date_summary$earliest_date, "to", 
      quality_results$date_summary$latest_date, "\n")
  
  cat("\nEnd time:", Sys.time(), "\n")
  cat("Reports saved to:", output_dir, "\n")
  
  return(quality_results)
}

# Execute if run as script
if (!interactive()) {
  # Set paths
  data_dir <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao"
  output_dir <- file.path(dirname(data_dir), "quality_reports")
  
  # Run assessment
  results <- main_quality_assessment(data_dir, output_dir)
}