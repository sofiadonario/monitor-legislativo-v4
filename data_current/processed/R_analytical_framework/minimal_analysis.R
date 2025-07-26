#!/usr/bin/env Rscript
#' Minimal Brazilian Legislative Analytics Pipeline - Base R Only

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

# Find CSV files
csv_files <- list.files(input_dir, pattern = "\\.csv$", full.names = TRUE)
csv_files <- csv_files[!grepl("_cleaned\\.csv$", csv_files)]

cat("Found", length(csv_files), "CSV files\n")

# Load main dataset using base R
main_file <- csv_files[grepl("dataset_limpo_classificado", csv_files)]
if (length(main_file) > 0) {
  cat("Loading main dataset:", basename(main_file[1]), "\n")
  main_data <- read.csv(main_file[1], encoding = "UTF-8", nrows = 2000, stringsAsFactors = FALSE)
} else {
  cat("Loading first available file:", basename(csv_files[1]), "\n")
  main_data <- read.csv(csv_files[1], encoding = "UTF-8", nrows = 2000, stringsAsFactors = FALSE)
}

cat("Loaded", nrow(main_data), "records with", ncol(main_data), "columns\n")
cat("Sample column names:", paste(head(names(main_data), 6), collapse = ", "), "...\n\n")

# Phase 1: Basic Data Quality Assessment
cat("PHASE 1: DATA QUALITY ASSESSMENT\n")
cat(paste(rep("=", 40), collapse = ""), "\n")

# Calculate missing data percentages
missing_stats <- data.frame(
  column = names(main_data),
  total_records = nrow(main_data),
  stringsAsFactors = FALSE
)

# Count missing values for each column
missing_counts <- sapply(main_data, function(x) {
  sum(is.na(x) | x == "" | x == "NULL" | trimws(x) == "")
})

missing_stats$missing_count <- missing_counts
missing_stats$missing_percentage <- round((missing_counts / nrow(main_data)) * 100, 2)
missing_stats$completeness <- 100 - missing_stats$missing_percentage

# Sort by missing percentage
missing_stats <- missing_stats[order(-missing_stats$missing_percentage), ]

cat("Data Quality Overview:\n")
cat("Total records:", nrow(main_data), "\n")
cat("Total columns:", ncol(main_data), "\n")
cat("Overall completeness:", round(mean(missing_stats$completeness), 2), "%\n\n")

cat("Top 10 fields with missing data:\n")
print(head(missing_stats[, c("column", "missing_percentage", "completeness")], 10))

# Save missing data analysis
write.csv(missing_stats, file.path(output_dir, "missing_data_analysis.csv"), row.names = FALSE)

# Phase 2: Text Analysis
cat("\nPHASE 2: TEXT ANALYSIS\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

text_results <- NULL
if ("titulo" %in% names(main_data)) {
  titles <- main_data$titulo
  # Clean titles
  valid_titles <- titles[!is.na(titles) & titles != "" & titles != "NULL" & nchar(trimws(titles)) > 0]
  
  if (length(valid_titles) > 0) {
    title_lengths <- nchar(valid_titles)
    
    text_results <- list(
      total_documents = nrow(main_data),
      documents_with_title = length(valid_titles),
      title_coverage = round(length(valid_titles) / nrow(main_data) * 100, 2),
      avg_title_length = round(mean(title_lengths), 2),
      min_title_length = min(title_lengths),
      max_title_length = max(title_lengths)
    )
    
    cat("Text Analysis Results:\n")
    cat("Documents with titles:", text_results$documents_with_title, 
        "(", text_results$title_coverage, "%)\n")
    cat("Average title length:", text_results$avg_title_length, "characters\n")
    cat("Title length range:", text_results$min_title_length, "to", text_results$max_title_length, "\n")
    
    # Simple word frequency analysis
    if (length(valid_titles) > 10) {
      # Combine all titles and convert to lowercase
      all_text <- paste(valid_titles, collapse = " ")
      all_text <- tolower(all_text)
      
      # Remove punctuation and split into words
      all_text <- gsub("[[:punct:]]", " ", all_text)
      words <- unlist(strsplit(all_text, "\\s+"))
      words <- words[nchar(words) >= 3]
      
      # Remove common Portuguese stopwords
      stopwords <- c("lei", "decreto", "sobre", "para", "com", "por", "em", "de", "da", "do", 
                    "das", "dos", "que", "são", "uma", "como", "pelo", "pela", "aos", "nas", 
                    "nos", "artigo", "estabelece", "dispõe", "institui", "altera", "anos")
      words <- words[!words %in% stopwords]
      
      if (length(words) > 0) {
        word_freq <- sort(table(words), decreasing = TRUE)
        top_20 <- head(word_freq, 20)
        
        word_analysis <- data.frame(
          word = names(top_20),
          frequency = as.numeric(top_20),
          percentage = round(as.numeric(top_20) / sum(word_freq) * 100, 2),
          stringsAsFactors = FALSE
        )
        
        cat("\nTop 10 most frequent terms:\n")
        print(head(word_analysis, 10))
        
        write.csv(word_analysis, file.path(output_dir, "word_frequencies.csv"), row.names = FALSE)
      }
    }
  }
}

# Phase 3: Temporal Analysis
cat("\nPHASE 3: TEMPORAL ANALYSIS\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

temporal_results <- NULL
if ("data" %in% names(main_data)) {
  dates <- main_data$data
  valid_dates <- dates[!is.na(dates) & dates != "" & dates != "NULL"]
  
  # Extract years using simple string manipulation
  years <- NULL
  if (length(valid_dates) > 0) {
    # Try to extract 4-digit years from the beginning of date strings
    year_matches <- regmatches(valid_dates, regexpr("^[0-9]{4}", valid_dates))
    years <- as.numeric(year_matches)
    years <- years[!is.na(years) & years >= 1800 & years <= 2025]
  }
  
  if (length(years) > 0) {
    temporal_results <- list(
      total_documents = nrow(main_data),
      documents_with_years = length(years),
      temporal_coverage = round(length(years) / nrow(main_data) * 100, 2),
      earliest_year = min(years),
      latest_year = max(years),
      year_span = max(years) - min(years) + 1
    )
    
    cat("Temporal Analysis Results:\n")
    cat("Documents with valid years:", temporal_results$documents_with_years, 
        "(", temporal_results$temporal_coverage, "%)\n")
    cat("Time span:", temporal_results$earliest_year, "to", temporal_results$latest_year, 
        "(", temporal_results$year_span, "years)\n")
    
    # Create yearly distribution
    year_counts <- table(years)
    yearly_df <- data.frame(
      year = as.numeric(names(year_counts)),
      count = as.numeric(year_counts),
      stringsAsFactors = FALSE
    )
    yearly_df <- yearly_df[order(yearly_df$year), ]
    
    cat("Peak year:", yearly_df$year[which.max(yearly_df$count)], 
        "with", max(yearly_df$count), "documents\n")
    
    write.csv(yearly_df, file.path(output_dir, "yearly_document_counts.csv"), row.names = FALSE)
    
    # Create simple plot
    png(file.path(output_dir, "temporal_distribution.png"), width = 800, height = 600)
    plot(yearly_df$year, yearly_df$count, type = "l", col = "blue", lwd = 2,
         main = "Legislative Documents Over Time", 
         xlab = "Year", ylab = "Number of Documents")
    points(yearly_df$year, yearly_df$count, col = "red", pch = 16)
    dev.off()
    cat("Temporal plot saved\n")
  }
}

# Phase 4: Category Analysis
cat("\nPHASE 4: CATEGORY ANALYSIS\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

category_results <- NULL
if ("categoria" %in% names(main_data)) {
  categories <- main_data$categoria
  valid_categories <- categories[!is.na(categories) & categories != "" & categories != "NULL"]
  
  if (length(valid_categories) > 0) {
    cat_counts <- table(valid_categories)
    category_df <- data.frame(
      categoria = names(cat_counts),
      count = as.numeric(cat_counts),
      stringsAsFactors = FALSE
    )
    category_df$percentage <- round(category_df$count / sum(category_df$count) * 100, 2)
    category_df <- category_df[order(-category_df$count), ]
    
    category_results <- list(
      total_documents = nrow(main_data),
      documents_with_category = length(valid_categories),
      category_coverage = round(length(valid_categories) / nrow(main_data) * 100, 2),
      unique_categories = nrow(category_df),
      top_category = category_df$categoria[1]
    )
    
    cat("Category Analysis Results:\n")
    cat("Documents with categories:", category_results$documents_with_category, 
        "(", category_results$category_coverage, "%)\n")
    cat("Unique categories:", category_results$unique_categories, "\n")
    cat("Top category:", category_results$top_category, "with", category_df$count[1], "documents\n\n")
    
    print(category_df)
    
    write.csv(category_df, file.path(output_dir, "category_distribution.csv"), row.names = FALSE)
    
    # Create bar plot
    png(file.path(output_dir, "category_distribution.png"), width = 800, height = 600)
    par(mar = c(8, 4, 4, 2))
    barplot(category_df$count, names.arg = category_df$categoria, 
            main = "Distribution of Document Categories",
            xlab = "", ylab = "Number of Documents",
            col = "steelblue", las = 2)
    dev.off()
    cat("Category plot saved\n")
  }
}

# Authority Analysis
authority_results <- NULL
if ("autoridade" %in% names(main_data)) {
  authorities <- main_data$autoridade
  valid_authorities <- authorities[!is.na(authorities) & authorities != "" & authorities != "NULL"]
  
  if (length(valid_authorities) > 0) {
    authority_results <- list(
      documents_with_authority = length(valid_authorities),
      authority_coverage = round(length(valid_authorities) / nrow(main_data) * 100, 2),
      unique_authorities = length(unique(valid_authorities))
    )
    
    cat("\nAuthority Analysis:\n")
    cat("Documents with authority:", authority_results$documents_with_authority, 
        "(", authority_results$authority_coverage, "%)\n")
    cat("Unique authorities:", authority_results$unique_authorities, "\n")
  }
}

# Generate Executive Summary
cat("\nGENERATING EXECUTIVE SUMMARY\n")
cat(paste(rep("=", 40), collapse = ""), "\n")

# Calculate quality metrics
overall_completeness <- round(mean(missing_stats$completeness), 2)
high_quality_fields <- sum(missing_stats$completeness >= 70)
low_quality_fields <- sum(missing_stats$completeness < 30)

summary_text <- paste0(
  "BRAZILIAN LEGISLATIVE DATASET - ANALYSIS REPORT\n",
  paste(rep("=", 55), collapse = ""), "\n\n",
  
  "EXECUTIVE SUMMARY:\n",
  "Comprehensive analysis of ", nrow(main_data), " Brazilian legislative documents\n",
  "from the LexML portal, examining ", ncol(main_data), " data fields for quality and content.\n\n",
  
  "DATASET OVERVIEW:\n",
  "- Total Records Analyzed: ", format(nrow(main_data), big.mark = ","), "\n",
  "- Total Data Fields: ", ncol(main_data), "\n",
  "- Overall Data Completeness: ", overall_completeness, "%\n",
  "- High Quality Fields (≥70% complete): ", high_quality_fields, "/", nrow(missing_stats), "\n",
  "- Low Quality Fields (<30% complete): ", low_quality_fields, "/", nrow(missing_stats), "\n\n",
  
  "CONTENT ANALYSIS:\n",
  if (!is.null(text_results)) {
    paste0("- Documents with Titles: ", format(text_results$documents_with_title, big.mark = ","), 
           " (", text_results$title_coverage, "%)\n",
           "- Average Title Length: ", text_results$avg_title_length, " characters\n",
           "- Text Data Quality: ", if(text_results$title_coverage >= 70) "Good" else if(text_results$title_coverage >= 30) "Fair" else "Limited", "\n")
  } else {
    "- Text analysis not available\n"
  },
  
  "\nTEMPORAL COVERAGE:\n",
  if (!is.null(temporal_results)) {
    paste0("- Documents with Valid Dates: ", format(temporal_results$documents_with_years, big.mark = ","), 
           " (", temporal_results$temporal_coverage, "%)\n",
           "- Historical Span: ", temporal_results$earliest_year, " to ", temporal_results$latest_year, 
           " (", temporal_results$year_span, " years)\n",
           "- Temporal Data Quality: ", if(temporal_results$temporal_coverage >= 70) "Good" else if(temporal_results$temporal_coverage >= 30) "Fair" else "Limited", "\n")
  } else {
    "- Temporal analysis not available\n"
  },
  
  "\nCATEGORIZATION:\n",
  if (!is.null(category_results)) {
    paste0("- Categorized Documents: ", format(category_results$documents_with_category, big.mark = ","), 
           " (", category_results$category_coverage, "%)\n",
           "- Document Categories: ", category_results$unique_categories, " distinct types\n",
           "- Primary Category: ", category_results$top_category, "\n")
  } else {
    "- Category analysis not available\n"
  },
  
  "\nAUTHORITY INFORMATION:\n",
  if (!is.null(authority_results)) {
    paste0("- Documents with Authority Data: ", format(authority_results$documents_with_authority, big.mark = ","), 
           " (", authority_results$authority_coverage, "%)\n",
           "- Unique Authorities: ", authority_results$unique_authorities, " different entities\n")
  } else {
    "- Authority analysis not available\n"
  },
  
  "\nDATA QUALITY ASSESSMENT:\n",
  "- Best Field: ", missing_stats$column[which.max(missing_stats$completeness)], 
  " (", round(max(missing_stats$completeness), 1), "% complete)\n",
  "- Worst Field: ", missing_stats$column[which.min(missing_stats$completeness)], 
  " (", round(min(missing_stats$completeness), 1), "% complete)\n",
  "- Overall Assessment: ", 
  if(overall_completeness >= 70) "Dataset suitable for comprehensive analysis" 
  else if(overall_completeness >= 50) "Dataset usable with preprocessing"
  else "Dataset requires extensive cleaning", "\n\n",
  
  "GENERATED ANALYSIS FILES:\n",
  "1. missing_data_analysis.csv - Complete data quality assessment\n",
  "2. category_distribution.csv - Document type breakdown\n",
  "3. yearly_document_counts.csv - Temporal distribution data\n",
  "4. word_frequencies.csv - Text analysis results\n",
  "5. temporal_distribution.png - Time series visualization\n",
  "6. category_distribution.png - Category breakdown chart\n",
  "7. executive_summary.txt - This comprehensive report\n",
  "8. analysis_results.rds - Complete R data for further analysis\n\n",
  
  "ANALYSIS METADATA:\n",
  "- Analysis Date: ", as.character(Sys.time()), "\n",
  "- R Version: ", R.version.string, "\n",
  "- Sample Size: ", format(nrow(main_data), big.mark = ","), " records (sample from full dataset)\n",
  "- Data Source: Brazilian LexML Legislative Portal\n",
  "- Processing Method: Base R statistical analysis\n\n",
  
  "KEY RECOMMENDATIONS:\n",
  "1. Prioritize analysis of high-completeness fields for reliable insights\n",
  "2. Investigate temporal patterns given the historical span\n",
  "3. Validate and standardize category classifications\n",
  "4. Consider authority-based analysis for institutional patterns\n",
  "5. Implement text mining on available title content\n",
  "6. Address data quality issues before comprehensive analysis\n"
)

# Save executive summary
writeLines(summary_text, file.path(output_dir, "executive_summary.txt"))

# Save complete results as R object
final_results <- list(
  metadata = list(
    analysis_date = Sys.time(),
    total_records = nrow(main_data),
    total_columns = ncol(main_data),
    overall_completeness = overall_completeness,
    r_version = R.version.string
  ),
  data_quality = missing_stats,
  text_analysis = text_results,
  temporal_analysis = temporal_results,
  category_analysis = category_results,
  authority_analysis = authority_results,
  summary_metrics = list(
    high_quality_fields = high_quality_fields,
    low_quality_fields = low_quality_fields,
    quality_score = if(overall_completeness >= 70) "High" else if(overall_completeness >= 50) "Medium" else "Low"
  )
)

saveRDS(final_results, file.path(output_dir, "analysis_results.rds"))

# Final status report
cat("\n")
cat(paste(rep("=", 70), collapse = ""), "\n")
cat("BRAZILIAN LEGISLATIVE ANALYTICS - ANALYSIS COMPLETED SUCCESSFULLY!\n")
cat(paste(rep("=", 70), collapse = ""), "\n")
cat("📊 Analysis Results:\n")
cat("   • Location: ", output_dir, "\n")
cat("   • Records Analyzed: ", format(nrow(main_data), big.mark = ","), "\n")
cat("   • Data Completeness: ", overall_completeness, "%\n")
cat("   • Quality Rating: ", final_results$summary_metrics$quality_score, "\n")
cat("   • Files Generated: 8 comprehensive analysis outputs\n")
cat("   • Processing Date: ", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "\n")

cat("\n🎯 Key Insights:\n")
if (!is.null(text_results)) {
  cat("   • Text Coverage: ", text_results$title_coverage, "% of documents have titles\n")
}
if (!is.null(temporal_results)) {
  cat("   • Historical Span: ", temporal_results$year_span, " years of legislative data\n")
}
if (!is.null(category_results)) {
  cat("   • Document Types: ", category_results$unique_categories, " distinct categories\n")
}
cat("   • Data Quality: ", final_results$summary_metrics$quality_score, " quality rating\n")

cat("\n📁 Generated Files:\n")
generated_files <- c(
  "missing_data_analysis.csv",
  "category_distribution.csv", 
  "yearly_document_counts.csv",
  "word_frequencies.csv",
  "temporal_distribution.png",
  "category_distribution.png",
  "executive_summary.txt",
  "analysis_results.rds"
)

for (file in generated_files) {
  file_path <- file.path(output_dir, file)
  if (file.exists(file_path)) {
    size_kb <- round(file.info(file_path)$size / 1024, 1)
    cat("   ✓ ", file, " (", size_kb, " KB)\n")
  }
}

cat("\n🚀 Next Steps:\n")
cat("   • Review executive_summary.txt for detailed findings\n")
cat("   • Examine visualizations (PNG files) for patterns\n")
cat("   • Load analysis_results.rds in R for further exploration\n")
cat("   • Consider data cleaning based on quality assessment\n")

cat("\n", paste(rep("=", 70), collapse = ""), "\n")
cat("Analysis complete! Ready for advanced analytics and visualization.\n")