#!/usr/bin/env Rscript
#' Working Brazilian Legislative Analytics Pipeline
#' 
#' This script runs a working version of the analytics pipeline

# Load essential packages
suppressWarnings({
  library(dplyr)
  library(stringr)  
  library(ggplot2)
  library(data.table)
})

cat("=== BRAZILIAN LEGISLATIVE ANALYTICS PIPELINE ===\n")
cat("Start time:", as.character(Sys.time()), "\n\n")

# Set paths
base_dir <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed"
input_dir <- file.path(base_dir, "lexml_dataset_individual_com_localizacao")
output_dir <- file.path(base_dir, "analytical_results")

# Create output directory
dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)

cat("Input directory:", input_dir, "\n")
cat("Output directory:", output_dir, "\n\n")

# Phase 1: Basic Data Assessment
cat("PHASE 1: BASIC DATA ASSESSMENT\n")
cat(paste(rep("=", 40), collapse = ""), "\n")

# Find CSV files
csv_files <- list.files(input_dir, pattern = "\\.csv$", full.names = TRUE)
csv_files <- csv_files[!grepl("_cleaned\\.csv$", csv_files)]

cat("Found", length(csv_files), "CSV files\n")

# Load main dataset
main_file <- csv_files[grepl("dataset_limpo_classificado", csv_files)]
if (length(main_file) > 0) {
  cat("Loading main dataset:", basename(main_file[1]), "\n")
  
  # Load with data.table for efficiency
  main_data <- fread(main_file[1], encoding = "UTF-8", fill = TRUE, nrows = 5000)
  cat("Loaded", nrow(main_data), "records for analysis\n")
  
} else {
  # Load first available file
  cat("Loading first available file:", basename(csv_files[1]), "\n")
  main_data <- fread(csv_files[1], encoding = "UTF-8", fill = TRUE, nrows = 5000)
  cat("Loaded", nrow(main_data), "records for analysis\n")
}

cat("Columns:", ncol(main_data), "\n")
cat("Column names:", paste(head(names(main_data), 10), collapse = ", "), "...\n\n")

# Basic data quality assessment
cat("DATA QUALITY ASSESSMENT\n")
cat(paste(rep("-", 30), collapse = ""), "\n")

# Missing data analysis
missing_counts <- sapply(main_data, function(x) sum(is.na(x) | x == ""))
missing_df <- data.frame(
  column = names(missing_counts),
  missing_count = missing_counts,
  total_records = nrow(main_data)
)
missing_df$missing_percentage <- round(missing_df$missing_count / missing_df$total_records * 100, 2)
missing_df$completeness <- 100 - missing_df$missing_percentage
missing_df <- missing_df[order(-missing_df$missing_percentage), ]

cat("Top 10 fields with missing data:\n")
print(head(missing_df[, c("column", "missing_percentage", "completeness")], 10))

# Save missing data analysis
write.csv(missing_df, file.path(output_dir, "missing_data_analysis.csv"), row.names = FALSE)

# Basic statistics
total_records <- nrow(main_data)
total_columns <- ncol(main_data)

# Date analysis if data column exists
date_analysis <- NULL
if ("data" %in% names(main_data)) {
  valid_dates <- !is.na(as.Date(main_data$data))
  date_range <- range(as.Date(main_data$data), na.rm = TRUE)
  date_analysis <- list(
    valid_dates = sum(valid_dates),
    date_range = date_range,
    earliest = min(date_range),
    latest = max(date_range)
  )
}

# Category analysis
category_analysis <- NULL
if ("categoria" %in% names(main_data)) {
  category_counts <- table(main_data$categoria, useNA = "ifany")
  category_analysis <- data.frame(
    categoria = names(category_counts),
    count = as.numeric(category_counts)
  )
  category_analysis$percentage <- round(category_analysis$count / sum(category_analysis$count) * 100, 2)
}

# Authority analysis
authority_analysis <- NULL
if ("autoridade" %in% names(main_data)) {
  unique_authorities <- length(unique(main_data$autoridade[!is.na(main_data$autoridade) & main_data$autoridade != ""]))
  authority_analysis <- list(unique_authorities = unique_authorities)
}

cat("\nBASIC STATISTICS:\n")
cat("Total records:", total_records, "\n")
cat("Total columns:", total_columns, "\n")
if (!is.null(authority_analysis)) {
  cat("Unique authorities:", authority_analysis$unique_authorities, "\n")
}
if (!is.null(date_analysis)) {
  cat("Valid dates:", date_analysis$valid_dates, "\n")
  cat("Date range:", as.character(date_analysis$earliest), "to", as.character(date_analysis$latest), "\n")
}

# Phase 2: Text Analysis
cat("\nPHASE 2: TEXT ANALYSIS\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

text_analysis <- NULL
if ("titulo" %in% names(main_data)) {
  # Basic text statistics
  valid_titles <- main_data[!is.na(main_data$titulo) & main_data$titulo != "", ]
  
  if (nrow(valid_titles) > 0) {
    title_lengths <- nchar(valid_titles$titulo)
    text_analysis <- list(
      documents_with_title = nrow(valid_titles),
      avg_title_length = round(mean(title_lengths), 2),
      max_title_length = max(title_lengths),
      min_title_length = min(title_lengths)
    )
    
    cat("Documents with titles:", text_analysis$documents_with_title, "\n")
    cat("Average title length:", text_analysis$avg_title_length, "characters\n")
    cat("Title length range:", text_analysis$min_title_length, "to", text_analysis$max_title_length, "\n")
    
    # Simple word extraction
    all_titles <- paste(valid_titles$titulo, collapse = " ")
    words <- unlist(strsplit(tolower(all_titles), "[^a-záêçõâ]+"))
    words <- words[nchar(words) >= 3]
    
    # Remove common Portuguese words
    stopwords <- c("lei", "decreto", "sobre", "para", "com", "por", "em", "de", "da", "do", "das", "dos", 
                   "que", "são", "uma", "como", "pelo", "pela", "aos", "nas", "nos")
    words <- words[!words %in% stopwords]
    
    if (length(words) > 0) {
      word_freq <- sort(table(words), decreasing = TRUE)
      top_words <- head(word_freq, 20)
      
      word_freq_df <- data.frame(
        word = names(top_words),
        frequency = as.numeric(top_words)
      )
      
      cat("\nTop 10 most common terms:\n")
      print(head(word_freq_df, 10))
      
      write.csv(word_freq_df, file.path(output_dir, "word_frequencies.csv"), row.names = FALSE)
    }
  }
}

# Phase 3: Temporal Analysis
cat("\nPHASE 3: TEMPORAL ANALYSIS\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

temporal_data <- NULL
if (!is.null(date_analysis) && date_analysis$valid_dates > 0) {
  # Extract years and create temporal distribution
  valid_data <- main_data[!is.na(as.Date(main_data$data)), ]
  valid_data$year <- as.numeric(format(as.Date(valid_data$data), "%Y"))
  valid_data <- valid_data[valid_data$year >= 1900 & valid_data$year <= 2025, ]
  
  if (nrow(valid_data) > 0) {
    yearly_counts <- aggregate(rep(1, nrow(valid_data)), by = list(year = valid_data$year), sum)
    names(yearly_counts) <- c("year", "count")
    yearly_counts <- yearly_counts[order(yearly_counts$year), ]
    
    temporal_data <- list(
      yearly_counts = yearly_counts,
      earliest_year = min(yearly_counts$year),
      latest_year = max(yearly_counts$year),
      peak_year = yearly_counts$year[which.max(yearly_counts$count)],
      peak_count = max(yearly_counts$count)
    )
    
    cat("Temporal span:", temporal_data$earliest_year, "to", temporal_data$latest_year, "\n")
    cat("Peak activity:", temporal_data$peak_year, "with", temporal_data$peak_count, "documents\n")
    
    write.csv(yearly_counts, file.path(output_dir, "yearly_document_counts.csv"), row.names = FALSE)
    
    # Create temporal plot
    png(file.path(output_dir, "temporal_distribution.png"), width = 800, height = 600)
    plot(yearly_counts$year, yearly_counts$count, type = "l", col = "blue", lwd = 2,
         main = "Legislative Documents Over Time", xlab = "Year", ylab = "Number of Documents")
    points(yearly_counts$year, yearly_counts$count, col = "red", pch = 16, cex = 0.5)
    dev.off()
    
    cat("Temporal plot saved\n")
  }
}

# Phase 4: Category Analysis with Visualization
cat("\nPHASE 4: CATEGORY ANALYSIS\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

if (!is.null(category_analysis)) {
  cat("Document categories:\n")
  print(category_analysis)
  
  write.csv(category_analysis, file.path(output_dir, "category_distribution.csv"), row.names = FALSE)
  
  # Create category plot
  png(file.path(output_dir, "category_distribution.png"), width = 800, height = 600)
  barplot(category_analysis$count, names.arg = category_analysis$categoria, 
          main = "Distribution of Document Categories", 
          xlab = "Category", ylab = "Number of Documents",
          col = "steelblue", las = 2)
  dev.off()
  
  cat("Category plot saved\n")
}

# Data Quality Summary
cat("\nDATA QUALITY SUMMARY\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

overall_completeness <- round(mean(missing_df$completeness), 2)
high_quality_fields <- sum(missing_df$completeness >= 80)
low_quality_fields <- sum(missing_df$completeness < 50)

quality_summary <- list(
  overall_completeness = overall_completeness,
  high_quality_fields = high_quality_fields,
  low_quality_fields = low_quality_fields,
  total_fields = nrow(missing_df)
)

cat("Overall data completeness:", quality_summary$overall_completeness, "%\n")
cat("High quality fields (>=80% complete):", quality_summary$high_quality_fields, "\n")
cat("Low quality fields (<50% complete):", quality_summary$low_quality_fields, "\n")

# Generate executive summary
cat("\nGENERATING EXECUTIVE SUMMARY\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

summary_text <- paste0(
  "BRAZILIAN LEGISLATIVE ANALYTICS - EXECUTIVE SUMMARY\n",
  paste(rep("=", 55), collapse = ""), "\n\n",
  "DATASET OVERVIEW:\n",
  "- Total Records Processed: ", format(total_records, big.mark = ","), "\n",
  "- Total Columns: ", total_columns, "\n",
  if (!is.null(authority_analysis)) paste0("- Unique Authorities: ", authority_analysis$unique_authorities, "\n") else "",
  if (!is.null(temporal_data)) paste0("- Time Span: ", temporal_data$earliest_year, " to ", temporal_data$latest_year, " (", temporal_data$latest_year - temporal_data$earliest_year + 1, " years)\n") else "",
  "\nDATA QUALITY:\n",
  "- Overall Completeness: ", quality_summary$overall_completeness, "%\n",
  "- High Quality Fields: ", quality_summary$high_quality_fields, "/", quality_summary$total_fields, "\n",
  "- Most Complete Field: ", missing_df$column[which.max(missing_df$completeness)], " (", max(missing_df$completeness), "%)\n",
  "- Least Complete Field: ", missing_df$column[which.min(missing_df$completeness)], " (", min(missing_df$completeness), "%)\n",
  "\nTEXT ANALYSIS:\n",
  if (!is.null(text_analysis)) paste0("- Documents with Titles: ", format(text_analysis$documents_with_title, big.mark = ","), "\n",
                                     "- Average Title Length: ", text_analysis$avg_title_length, " characters\n") else "- No text analysis performed\n",
  "\nTEMPORAL ANALYSIS:\n",
  if (!is.null(temporal_data)) paste0("- Peak Activity Year: ", temporal_data$peak_year, " (", temporal_data$peak_count, " documents)\n",
                                     "- Data Spans: ", temporal_data$latest_year - temporal_data$earliest_year + 1, " years\n") else "- No temporal analysis performed\n",
  "\nCATEGORY DISTRIBUTION:\n",
  if (!is.null(category_analysis)) paste0("- Number of Categories: ", nrow(category_analysis), "\n",
                                         "- Largest Category: ", category_analysis$categoria[which.max(category_analysis$count)], 
                                         " (", max(category_analysis$count), " documents)\n") else "- No category analysis performed\n",
  "\nFILES GENERATED:\n",
  "- missing_data_analysis.csv (data quality assessment)\n",
  "- category_distribution.csv (category breakdown)\n",
  "- yearly_document_counts.csv (temporal distribution)\n",
  "- word_frequencies.csv (text analysis)\n",
  "- temporal_distribution.png (time series plot)\n",
  "- category_distribution.png (category chart)\n",
  "- executive_summary.txt (this summary)\n",
  "- analysis_results.rds (complete R data)\n",
  "\nPROCESSING INFO:\n",
  "- Completed: ", as.character(Sys.time()), "\n",
  "- R Version: ", R.version.string, "\n",
  "- Sample Size: First 5,000 records from main dataset\n"
)

# Save executive summary
writeLines(summary_text, file.path(output_dir, "executive_summary.txt"))

# Save complete results
results <- list(
  basic_stats = list(
    total_records = total_records,
    total_columns = total_columns
  ),
  missing_analysis = missing_df,
  text_analysis = text_analysis,
  temporal_data = temporal_data,
  category_analysis = category_analysis,
  quality_summary = quality_summary,
  processing_info = list(
    completion_time = Sys.time(),
    r_version = R.version.string,
    input_file = if (exists("main_file")) basename(main_file[1]) else basename(csv_files[1])
  )
)

saveRDS(results, file.path(output_dir, "analysis_results.rds"))

cat("\n")
cat(paste(rep("=", 60), collapse = ""), "\n")
cat("ANALYSIS COMPLETED SUCCESSFULLY!\n")
cat(paste(rep("=", 60), collapse = ""), "\n")
cat("Results saved to:", output_dir, "\n")
cat("Total records analyzed:", format(total_records, big.mark = ","), "\n")
cat("Overall data completeness:", quality_summary$overall_completeness, "%\n")
cat("Files generated: 8 analysis files\n")
cat(paste(rep("=", 60), collapse = ""), "\n")

# Print executive summary to console
cat("\n", summary_text)