#!/usr/bin/env Rscript
#' Simplified Brazilian Legislative Analytics Pipeline
#' 
#' This script runs a simplified version of the analytics pipeline using
#' only base R and commonly available packages.

# Check and load essential packages
required_packages <- c("dplyr", "stringr", "ggplot2", "data.table")
missing_packages <- required_packages[!sapply(required_packages, requireNamespace, quietly = TRUE)]

if (length(missing_packages) > 0) {
  cat("Missing packages:", paste(missing_packages, collapse = ", "), "\n")
  cat("Attempting to install...\n")
  
  # Try to install missing packages
  for (pkg in missing_packages) {
    tryCatch({
      install.packages(pkg, repos = "https://cran.r-project.org", dependencies = FALSE)
    }, error = function(e) {
      cat("Failed to install", pkg, ":", e$message, "\n")
    })
  }
}

# Load packages
suppressWarnings({
  library(dplyr)
  library(stringr)
  library(ggplot2)
  library(data.table)
})

cat("=== SIMPLIFIED BRAZILIAN LEGISLATIVE ANALYTICS PIPELINE ===\n")
cat("Start time:", as.character(Sys.time()), "\n\n")

# Set paths
base_dir <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed"
input_dir <- file.path(base_dir, "lexml_dataset_individual_com_localizacao")
output_dir <- file.path(base_dir, "simplified_analytical_results")

# Create output directory
dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)

cat("Input directory:", input_dir, "\n")
cat("Output directory:", output_dir, "\n\n")

# Phase 1: Basic Data Assessment
cat("PHASE 1: BASIC DATA ASSESSMENT\n")
cat("="*40, "\n")

# Find CSV files
csv_files <- list.files(input_dir, pattern = "\\.csv$", full.names = TRUE)
csv_files <- csv_files[!grepl("_cleaned\\.csv$", csv_files)]

cat("Found", length(csv_files), "CSV files\n")

# Load and combine data
cat("Loading and combining data...\n")
combined_data <- data.frame()

for (file in csv_files[1:min(5, length(csv_files))]) {  # Process first 5 files for demo
  cat("Loading:", basename(file), "\n")
  
  tryCatch({
    data <- fread(file, encoding = "UTF-8", fill = TRUE, nrows = 1000)  # Limit rows for demo
    data$source_file <- basename(file)
    combined_data <- rbind(combined_data, data, fill = TRUE)
  }, error = function(e) {
    cat("Error loading", basename(file), ":", e$message, "\n")
  })
}

cat("Total records loaded:", nrow(combined_data), "\n")
cat("Total columns:", ncol(combined_data), "\n\n")

# Basic data quality assessment
cat("BASIC DATA QUALITY ASSESSMENT\n")
cat("-"*30, "\n")

# Missing data analysis
missing_analysis <- combined_data %>%
  summarise_all(function(x) sum(is.na(x) | x == "")) %>%
  tidyr::pivot_longer(everything(), names_to = "column", values_to = "missing_count") %>%
  mutate(
    missing_percentage = round(missing_count / nrow(combined_data) * 100, 2),
    completeness = 100 - missing_percentage
  ) %>%
  arrange(desc(missing_percentage))

cat("Data completeness by field:\n")
print(head(missing_analysis, 10))

# Save missing data analysis
write.csv(missing_analysis, file.path(output_dir, "missing_data_analysis.csv"), row.names = FALSE)

# Basic statistics
basic_stats <- list(
  total_records = nrow(combined_data),
  total_columns = ncol(combined_data),
  date_range = if("data" %in% names(combined_data)) {
    range(as.Date(combined_data$data), na.rm = TRUE)
  } else c(NA, NA),
  categories = if("categoria" %in% names(combined_data)) {
    table(combined_data$categoria, useNA = "ifany")
  } else NULL,
  authorities = if("autoridade" %in% names(combined_data)) {
    length(unique(combined_data$autoridade[!is.na(combined_data$autoridade)]))
  } else 0
)

cat("\nBasic Statistics:\n")
cat("Total records:", basic_stats$total_records, "\n")
cat("Total columns:", basic_stats$total_columns, "\n")
cat("Unique authorities:", basic_stats$authorities, "\n")
if (!all(is.na(basic_stats$date_range))) {
  cat("Date range:", paste(basic_stats$date_range, collapse = " to "), "\n")
}

# Phase 2: Simple Text Analysis
cat("\nPHASE 2: SIMPLE TEXT ANALYSIS\n")
cat("="*40, "\n")

if ("titulo" %in% names(combined_data)) {
  # Basic text statistics
  text_stats <- combined_data %>%
    filter(!is.na(titulo), titulo != "") %>%
    mutate(
      title_length = nchar(titulo),
      word_count = str_count(titulo, "\\S+")
    ) %>%
    summarise(
      documents_with_title = n(),
      avg_title_length = round(mean(title_length, na.rm = TRUE), 2),
      avg_word_count = round(mean(word_count, na.rm = TRUE), 2),
      max_title_length = max(title_length, na.rm = TRUE)
    )
  
  cat("Text Analysis Results:\n")
  cat("Documents with titles:", text_stats$documents_with_title, "\n")
  cat("Average title length:", text_stats$avg_title_length, "characters\n")
  cat("Average word count:", text_stats$avg_word_count, "words\n")
  
  # Simple word frequency analysis
  if (text_stats$documents_with_title > 0) {
    cat("\nExtracting common terms...\n")
    
    # Extract words from titles
    words <- combined_data %>%
      filter(!is.na(titulo), titulo != "") %>%
      select(titulo) %>%
      mutate(titulo = str_to_lower(titulo)) %>%
      mutate(words = str_extract_all(titulo, "\\b[a-záêçõâ]{3,}\\b")) %>%
      tidyr::unnest(words) %>%
      filter(!words %in% c("lei", "decreto", "sobre", "para", "com", "por", "em", "de", "da", "do", "das", "dos"))
    
    if (nrow(words) > 0) {
      word_freq <- words %>%
        count(words, sort = TRUE) %>%
        head(20)
      
      cat("Top 20 most common terms:\n")
      print(word_freq)
      
      # Save word frequencies
      write.csv(word_freq, file.path(output_dir, "word_frequencies.csv"), row.names = FALSE)
    }
  }
}

# Phase 3: Simple Temporal Analysis
cat("\nPHASE 3: SIMPLE TEMPORAL ANALYSIS\n")
cat("="*40, "\n")

if ("data" %in% names(combined_data)) {
  # Temporal distribution
  temporal_data <- combined_data %>%
    filter(!is.na(data)) %>%
    mutate(
      date_parsed = as.Date(data),
      year = as.numeric(format(date_parsed, "%Y"))
    ) %>%
    filter(!is.na(year), year >= 1900, year <= 2025)
  
  if (nrow(temporal_data) > 0) {
    yearly_counts <- temporal_data %>%
      count(year, sort = TRUE) %>%
      arrange(year)
    
    cat("Temporal distribution:\n")
    cat("Earliest year:", min(yearly_counts$year), "\n")
    cat("Latest year:", max(yearly_counts$year), "\n")
    cat("Most active year:", yearly_counts$year[which.max(yearly_counts$n)], 
        "with", max(yearly_counts$n), "documents\n")
    
    # Save temporal data
    write.csv(yearly_counts, file.path(output_dir, "yearly_document_counts.csv"), row.names = FALSE)
    
    # Create simple temporal plot
    if (requireNamespace("ggplot2", quietly = TRUE)) {
      temporal_plot <- ggplot(yearly_counts, aes(x = year, y = n)) +
        geom_line(color = "blue") +
        geom_point(color = "red", size = 0.5) +
        labs(title = "Legislative Documents Over Time",
             x = "Year", y = "Number of Documents") +
        theme_minimal()
      
      ggsave(file.path(output_dir, "temporal_distribution.png"), 
             temporal_plot, width = 10, height = 6, dpi = 150)
      cat("Temporal plot saved to: temporal_distribution.png\n")
    }
  }
}

# Phase 4: Simple Category Analysis
cat("\nPHASE 4: CATEGORY ANALYSIS\n")
cat("="*40, "\n")

if ("categoria" %in% names(combined_data)) {
  category_analysis <- combined_data %>%
    filter(!is.na(categoria), categoria != "") %>%
    count(categoria, sort = TRUE) %>%
    mutate(percentage = round(n / sum(n) * 100, 2))
  
  cat("Document categories:\n")
  print(category_analysis)
  
  # Save category analysis
  write.csv(category_analysis, file.path(output_dir, "category_distribution.csv"), row.names = FALSE)
  
  # Create category plot
  if (requireNamespace("ggplot2", quietly = TRUE) && nrow(category_analysis) > 0) {
    category_plot <- ggplot(category_analysis, aes(x = reorder(categoria, n), y = n)) +
      geom_col(fill = "steelblue") +
      coord_flip() +
      labs(title = "Distribution of Document Categories",
           x = "Category", y = "Number of Documents") +
      theme_minimal()
    
    ggsave(file.path(output_dir, "category_distribution.png"), 
           category_plot, width = 8, height = 6, dpi = 150)
    cat("Category plot saved to: category_distribution.png\n")
  }
}

# Generate executive summary
cat("\nGENERATING EXECUTIVE SUMMARY\n")
cat("="*40, "\n")

summary_text <- paste0(
  "SIMPLIFIED BRAZILIAN LEGISLATIVE ANALYTICS - EXECUTIVE SUMMARY\n",
  "=============================================================\n\n",
  "DATASET OVERVIEW:\n",
  "- Total Records Processed: ", format(basic_stats$total_records, big.mark = ","), "\n",
  "- Total Columns: ", basic_stats$total_columns, "\n",
  "- Unique Authorities: ", basic_stats$authorities, "\n",
  if (!all(is.na(basic_stats$date_range))) {
    paste0("- Date Range: ", paste(basic_stats$date_range, collapse = " to "), "\n")
  } else "",
  "\nDATA QUALITY:\n",
  "- Most Complete Field: ", missing_analysis$column[which.max(missing_analysis$completeness)], 
  " (", max(missing_analysis$completeness), "% complete)\n",
  "- Least Complete Field: ", missing_analysis$column[which.min(missing_analysis$completeness)], 
  " (", min(missing_analysis$completeness), "% complete)\n",
  "\nFILES GENERATED:\n",
  "- missing_data_analysis.csv\n",
  "- category_distribution.csv\n",
  "- yearly_document_counts.csv\n",
  "- word_frequencies.csv\n",
  "- temporal_distribution.png\n",
  "- category_distribution.png\n",
  "\nProcessing completed at: ", as.character(Sys.time()), "\n"
)

# Save executive summary
writeLines(summary_text, file.path(output_dir, "executive_summary.txt"))

# Save R object with all results
results <- list(
  basic_stats = basic_stats,
  missing_analysis = missing_analysis,
  combined_data_sample = head(combined_data, 100),  # Save sample for inspection
  processing_info = list(
    files_processed = length(csv_files),
    processing_time = Sys.time(),
    r_version = R.version.string
  )
)

saveRDS(results, file.path(output_dir, "analysis_results.rds"))

cat("\n")
cat("="*60, "\n")
cat("SIMPLIFIED ANALYSIS COMPLETED SUCCESSFULLY!\n")
cat("="*60, "\n")
cat("Results saved to:", output_dir, "\n")
cat("Total records analyzed:", nrow(combined_data), "\n")
cat("Files generated: 6-8 analysis files\n")
cat("="*60, "\n")

# Print summary to console
cat(summary_text)