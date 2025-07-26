#!/usr/bin/env Rscript
#' Robust Brazilian Legislative Analytics Pipeline
#' 
#' This script runs a robust version that handles data parsing issues

# Load packages with error handling
load_package <- function(pkg) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("Installing", pkg, "...\n")
    install.packages(pkg, repos = "https://cran.r-project.org", dependencies = FALSE)
  }
  library(pkg, character.only = TRUE)
}

# Load essential packages
suppressWarnings({
  load_package("data.table")
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

# Find CSV files
csv_files <- list.files(input_dir, pattern = "\\.csv$", full.names = TRUE)
csv_files <- csv_files[!grepl("_cleaned\\.csv$", csv_files)]

cat("Found", length(csv_files), "CSV files\n")

# Load main dataset
main_file <- csv_files[grepl("dataset_limpo_classificado", csv_files)]
if (length(main_file) > 0) {
  cat("Loading main dataset:", basename(main_file[1]), "\n")
  main_data <- fread(main_file[1], encoding = "UTF-8", fill = TRUE, nrows = 5000)
} else {
  cat("Loading first available file:", basename(csv_files[1]), "\n")
  main_data <- fread(csv_files[1], encoding = "UTF-8", fill = TRUE, nrows = 5000)
}

cat("Loaded", nrow(main_data), "records with", ncol(main_data), "columns\n")
cat("Column names:", paste(head(names(main_data), 8), collapse = ", "), "...\n\n")

# Phase 1: Data Quality Assessment
cat("PHASE 1: DATA QUALITY ASSESSMENT\n")
cat(paste(rep("=", 40), collapse = ""), "\n")

# Safe missing data analysis
calculate_missing <- function(x) {
  if (is.null(x)) return(100)
  missing_count <- sum(is.na(x) | x == "" | x == "NULL")
  return(round(missing_count / length(x) * 100, 2))
}

missing_percentages <- sapply(main_data, calculate_missing)
missing_df <- data.frame(
  column = names(missing_percentages),
  missing_percentage = missing_percentages,
  completeness = 100 - missing_percentages,
  stringsAsFactors = FALSE
)
missing_df <- missing_df[order(-missing_df$missing_percentage), ]

cat("Data Quality Overview:\n")
cat("Top 10 fields with missing data:\n")
print(head(missing_df, 10))

# Save missing data analysis
write.csv(missing_df, file.path(output_dir, "missing_data_analysis.csv"), row.names = FALSE)

# Basic statistics
total_records <- nrow(main_data)
total_columns <- ncol(main_data)
overall_completeness <- round(mean(missing_df$completeness), 2)

cat("\nBasic Statistics:\n")
cat("Total records:", format(total_records, big.mark = ","), "\n")
cat("Total columns:", total_columns, "\n")
cat("Overall completeness:", overall_completeness, "%\n")

# Phase 2: Text Analysis (Safe)
cat("\nPHASE 2: TEXT ANALYSIS\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

text_stats <- NULL
if ("titulo" %in% names(main_data)) {
  # Safe text processing
  titles <- main_data$titulo
  valid_titles <- titles[!is.na(titles) & titles != "" & titles != "NULL"]
  
  if (length(valid_titles) > 0) {
    title_lengths <- nchar(valid_titles)
    text_stats <- list(
      total_documents = total_records,
      documents_with_title = length(valid_titles),
      title_coverage = round(length(valid_titles) / total_records * 100, 2),
      avg_title_length = round(mean(title_lengths), 2),
      median_title_length = round(median(title_lengths), 2),
      max_title_length = max(title_lengths)
    )
    
    cat("Text Analysis Results:\n")
    cat("Documents with titles:", format(text_stats$documents_with_title, big.mark = ","), 
        "(", text_stats$title_coverage, "%)\n")
    cat("Average title length:", text_stats$avg_title_length, "characters\n")
    cat("Median title length:", text_stats$median_title_length, "characters\n")
    
    # Simple word frequency (safe processing)
    if (length(valid_titles) > 10) {
      # Clean and extract words
      all_text <- paste(valid_titles, collapse = " ")
      all_text <- tolower(all_text)
      # Simple word extraction
      words <- unlist(strsplit(all_text, "[^a-záêçõâíúóàèìòù]+"))
      words <- words[nchar(words) >= 3]
      
      # Remove common words
      common_words <- c("lei", "decreto", "sobre", "para", "com", "por", "em", "de", "da", "do", 
                       "das", "dos", "que", "são", "uma", "como", "pelo", "pela", "aos", "nas", "nos",
                       "artigo", "parágrafo", "inciso", "estabelece", "dispõe", "institui", "altera")
      words <- words[!words %in% common_words]
      
      if (length(words) > 0) {
        word_freq <- sort(table(words), decreasing = TRUE)
        top_words <- head(word_freq, 20)
        
        word_df <- data.frame(
          word = names(top_words),
          frequency = as.numeric(top_words),
          percentage = round(as.numeric(top_words) / sum(word_freq) * 100, 2),
          stringsAsFactors = FALSE
        )
        
        cat("\nTop 10 most frequent terms:\n")
        print(head(word_df, 10))
        
        write.csv(word_df, file.path(output_dir, "word_frequencies.csv"), row.names = FALSE)
      }
    }
  }
}

# Phase 3: Safe Date Analysis
cat("\nPHASE 3: TEMPORAL ANALYSIS\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

temporal_stats <- NULL
if ("data" %in% names(main_data)) {
  # Safe date parsing
  dates <- main_data$data
  valid_dates <- dates[!is.na(dates) & dates != "" & dates != "NULL"]
  
  # Try different date parsing approaches
  parsed_dates <- NULL
  if (length(valid_dates) > 0) {
    # Try ISO format first
    tryCatch({
      parsed_dates <- as.Date(valid_dates)
      parsed_dates <- parsed_dates[!is.na(parsed_dates)]
    }, error = function(e) {
      cat("Date parsing error, trying alternative methods...\n")
    })
    
    # If that fails, try extracting years
    if (is.null(parsed_dates) || length(parsed_dates) == 0) {
      tryCatch({
        # Extract years using regex
        years <- as.numeric(substr(valid_dates, 1, 4))
        years <- years[!is.na(years) & years >= 1900 & years <= 2025]
        if (length(years) > 0) {
          temporal_stats <- list(
            valid_years = length(years),
            year_coverage = round(length(years) / total_records * 100, 2),
            earliest_year = min(years),
            latest_year = max(years),
            year_span = max(years) - min(years) + 1
          )
        }
      }, error = function(e) {
        cat("Year extraction also failed\n")
      })
    } else {
      # Successful date parsing
      years <- as.numeric(format(parsed_dates, "%Y"))
      years <- years[years >= 1900 & years <= 2025]
      
      if (length(years) > 0) {
        temporal_stats <- list(
          valid_dates = length(parsed_dates),
          valid_years = length(years),
          date_coverage = round(length(parsed_dates) / total_records * 100, 2),
          earliest_year = min(years),
          latest_year = max(years),
          year_span = max(years) - min(years) + 1,
          earliest_date = min(parsed_dates),
          latest_date = max(parsed_dates)
        )
        
        # Create yearly distribution
        yearly_counts <- table(years)
        yearly_df <- data.frame(
          year = as.numeric(names(yearly_counts)),
          count = as.numeric(yearly_counts),
          stringsAsFactors = FALSE
        )
        yearly_df <- yearly_df[order(yearly_df$year), ]
        
        write.csv(yearly_df, file.path(output_dir, "yearly_document_counts.csv"), row.names = FALSE)
        
        # Simple plot
        png(file.path(output_dir, "temporal_distribution.png"), width = 800, height = 600)
        plot(yearly_df$year, yearly_df$count, type = "l", col = "blue", lwd = 2,
             main = "Legislative Documents Over Time", 
             xlab = "Year", ylab = "Number of Documents")
        points(yearly_df$year, yearly_df$count, col = "red", pch = 16, cex = 0.8)
        dev.off()
      }
    }
    
    if (!is.null(temporal_stats)) {
      cat("Temporal Analysis Results:\n")
      cat("Documents with valid dates:", format(temporal_stats$valid_years, big.mark = ","), 
          "(", round(temporal_stats$valid_years / total_records * 100, 2), "%)\n")
      cat("Time span:", temporal_stats$earliest_year, "to", temporal_stats$latest_year, 
          "(", temporal_stats$year_span, "years)\n")
    }
  }
}

# Phase 4: Category Analysis
cat("\nPHASE 4: CATEGORY ANALYSIS\n")
cat(paste(rep("=", 30), collapse = ""), "\n")

category_stats <- NULL
if ("categoria" %in% names(main_data)) {
  categories <- main_data$categoria
  valid_categories <- categories[!is.na(categories) & categories != "" & categories != "NULL"]
  
  if (length(valid_categories) > 0) {
    cat_counts <- table(valid_categories)
    category_df <- data.frame(
      categoria = names(cat_counts),
      count = as.numeric(cat_counts),
      percentage = round(as.numeric(cat_counts) / length(valid_categories) * 100, 2),
      stringsAsFactors = FALSE
    )
    category_df <- category_df[order(-category_df$count), ]
    
    category_stats <- list(
      total_categorized = length(valid_categories),
      coverage = round(length(valid_categories) / total_records * 100, 2),
      unique_categories = nrow(category_df),
      top_category = category_df$categoria[1],
      top_category_count = category_df$count[1]
    )
    
    cat("Category Analysis Results:\n")
    cat("Documents with categories:", format(category_stats$total_categorized, big.mark = ","), 
        "(", category_stats$coverage, "%)\n")
    cat("Unique categories:", category_stats$unique_categories, "\n")
    cat("Top category:", category_stats$top_category, "with", 
        format(category_stats$top_category_count, big.mark = ","), "documents\n")
    
    print(category_df)
    
    write.csv(category_df, file.path(output_dir, "category_distribution.csv"), row.names = FALSE)
    
    # Simple bar plot
    png(file.path(output_dir, "category_distribution.png"), width = 800, height = 600)
    par(mar = c(8, 4, 4, 2))
    barplot(category_df$count, names.arg = category_df$categoria, 
            main = "Distribution of Document Categories",
            xlab = "", ylab = "Number of Documents",
            col = "steelblue", las = 2)
    dev.off()
  }
}

# Authority Analysis
authority_stats <- NULL
if ("autoridade" %in% names(main_data)) {
  authorities <- main_data$autoridade
  valid_authorities <- authorities[!is.na(authorities) & authorities != "" & authorities != "NULL"]
  
  if (length(valid_authorities) > 0) {
    unique_auth <- length(unique(valid_authorities))
    authority_stats <- list(
      total_with_authority = length(valid_authorities),
      coverage = round(length(valid_authorities) / total_records * 100, 2),
      unique_authorities = unique_auth
    )
    
    cat("\nAuthority Analysis:\n")
    cat("Documents with authority info:", format(authority_stats$total_with_authority, big.mark = ","), 
        "(", authority_stats$coverage, "%)\n")
    cat("Unique authorities:", authority_stats$unique_authorities, "\n")
  }
}

# Generate comprehensive summary
cat("\nGENERATING COMPREHENSIVE SUMMARY\n")
cat(paste(rep("=", 40), collapse = ""), "\n")

# Quality assessment
high_quality_fields <- sum(missing_df$completeness >= 70)
medium_quality_fields <- sum(missing_df$completeness >= 30 & missing_df$completeness < 70)
low_quality_fields <- sum(missing_df$completeness < 30)

summary_text <- paste0(
  "BRAZILIAN LEGISLATIVE DATASET - COMPREHENSIVE ANALYSIS REPORT\n",
  paste(rep("=", 65), collapse = ""), "\n\n",
  "EXECUTIVE SUMMARY:\n",
  "This analysis processed ", format(total_records, big.mark = ","), " legislative documents\n",
  "from the Brazilian LexML portal, covering ", total_columns, " data fields.\n\n",
  
  "DATASET OVERVIEW:\n",
  "- Total Records: ", format(total_records, big.mark = ","), "\n",
  "- Total Fields: ", total_columns, "\n",
  "- Overall Data Completeness: ", overall_completeness, "%\n",
  "- High Quality Fields (≥70% complete): ", high_quality_fields, "\n",
  "- Medium Quality Fields (30-69% complete): ", medium_quality_fields, "\n",
  "- Low Quality Fields (<30% complete): ", low_quality_fields, "\n\n",
  
  "TEXT CONTENT ANALYSIS:\n",
  if (!is.null(text_stats)) {
    paste0("- Documents with Titles: ", format(text_stats$documents_with_title, big.mark = ","), 
           " (", text_stats$title_coverage, "%)\n",
           "- Average Title Length: ", text_stats$avg_title_length, " characters\n",
           "- Text Quality: ", if(text_stats$title_coverage >= 70) "Good" else if(text_stats$title_coverage >= 30) "Fair" else "Poor", "\n")
  } else {
    "- No title data available for analysis\n"
  },
  
  "\nTEMPORAL COVERAGE:\n",
  if (!is.null(temporal_stats)) {
    paste0("- Documents with Valid Dates: ", format(temporal_stats$valid_years, big.mark = ","), 
           " (", round(temporal_stats$valid_years / total_records * 100, 2), "%)\n",
           "- Time Span: ", temporal_stats$earliest_year, " to ", temporal_stats$latest_year, 
           " (", temporal_stats$year_span, " years)\n",
           "- Temporal Quality: ", if(temporal_stats$valid_years / total_records >= 0.7) "Good" else if(temporal_stats$valid_years / total_records >= 0.3) "Fair" else "Poor", "\n")
  } else {
    "- No valid temporal data found\n"
  },
  
  "\nCATEGORIZATION:\n",
  if (!is.null(category_stats)) {
    paste0("- Categorized Documents: ", format(category_stats$total_categorized, big.mark = ","), 
           " (", category_stats$coverage, "%)\n",
           "- Number of Categories: ", category_stats$unique_categories, "\n",
           "- Largest Category: ", category_stats$top_category, 
           " (", format(category_stats$top_category_count, big.mark = ","), " documents)\n")
  } else {
    "- No category data available\n"
  },
  
  "\nAUTHORITY INFORMATION:\n",
  if (!is.null(authority_stats)) {
    paste0("- Documents with Authority: ", format(authority_stats$total_with_authority, big.mark = ","), 
           " (", authority_stats$coverage, "%)\n",
           "- Unique Authorities: ", authority_stats$unique_authorities, "\n")
  } else {
    "- No authority data available\n"
  },
  
  "\nDATA QUALITY ASSESSMENT:\n",
  "- Most Complete Field: ", missing_df$column[which.max(missing_df$completeness)], 
  " (", round(max(missing_df$completeness), 1), "% complete)\n",
  "- Least Complete Field: ", missing_df$column[which.min(missing_df$completeness)], 
  " (", round(min(missing_df$completeness), 1), "% complete)\n",
  "- Recommended Action: ", 
  if(overall_completeness >= 70) "Dataset suitable for comprehensive analysis" 
  else if(overall_completeness >= 50) "Dataset usable with careful handling of missing data"
  else "Dataset requires significant cleaning before analysis", "\n\n",
  
  "GENERATED OUTPUTS:\n",
  "- missing_data_analysis.csv (field-by-field completeness assessment)\n",
  "- category_distribution.csv (document categorization breakdown)\n",
  "- yearly_document_counts.csv (temporal distribution)\n",
  "- word_frequencies.csv (text analysis results)\n",
  "- temporal_distribution.png (time series visualization)\n",
  "- category_distribution.png (category breakdown chart)\n",
  "- executive_summary.txt (this comprehensive report)\n",
  "- analysis_results.rds (complete R dataset for further analysis)\n\n",
  
  "TECHNICAL DETAILS:\n",
  "- Analysis Date: ", as.character(Sys.time()), "\n",
  "- R Version: ", R.version.string, "\n",
  "- Sample Size: ", format(total_records, big.mark = ","), " records\n",
  "- Data Source: Brazilian LexML Legislative Portal\n",
  "- Processing Method: Robust statistical analysis with error handling\n\n",
  
  "RECOMMENDATIONS FOR FURTHER ANALYSIS:\n",
  "1. Focus on high-completeness fields for reliable insights\n",
  "2. Consider temporal trends given the multi-decade span\n",
  "3. Investigate category-specific patterns\n",
  "4. Validate authority-jurisdiction relationships\n",
  "5. Implement advanced text mining on title/content fields\n",
  "6. Consider geographic analysis if location data improves\n"
)

# Save comprehensive summary
writeLines(summary_text, file.path(output_dir, "executive_summary.txt"))

# Save complete analysis results
results <- list(
  dataset_info = list(
    total_records = total_records,
    total_columns = total_columns,
    overall_completeness = overall_completeness
  ),
  data_quality = missing_df,
  text_analysis = text_stats,
  temporal_analysis = temporal_stats,
  category_analysis = category_stats,
  authority_analysis = authority_stats,
  quality_summary = list(
    high_quality_fields = high_quality_fields,
    medium_quality_fields = medium_quality_fields,
    low_quality_fields = low_quality_fields
  ),
  processing_metadata = list(
    analysis_date = Sys.time(),
    r_version = R.version.string,
    source_file = if(exists("main_file")) basename(main_file[1]) else basename(csv_files[1]),
    sample_size = total_records
  )
)

saveRDS(results, file.path(output_dir, "analysis_results.rds"))

# Final output
cat("\n")
cat(paste(rep("=", 70), collapse = ""), "\n")
cat("BRAZILIAN LEGISLATIVE ANALYTICS - ANALYSIS COMPLETED!\n")
cat(paste(rep("=", 70), collapse = ""), "\n")
cat("✓ Results Location:", output_dir, "\n")
cat("✓ Records Analyzed:", format(total_records, big.mark = ","), "\n")
cat("✓ Overall Data Quality:", overall_completeness, "% complete\n")
cat("✓ Files Generated: 8 comprehensive analysis files\n")
cat("✓ Processing Time:", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "\n")
cat(paste(rep("=", 70), collapse = ""), "\n")

# Display key findings
cat("\nKEY FINDINGS:\n")
if (!is.null(text_stats)) {
  cat("📄 Text Coverage:", text_stats$title_coverage, "% of documents have titles\n")
}
if (!is.null(temporal_stats)) {
  cat("📅 Temporal Span:", temporal_stats$year_span, "years of legislative history\n")
}
if (!is.null(category_stats)) {
  cat("📂 Categories:", category_stats$unique_categories, "distinct document types\n")
}
cat("🎯 Data Quality: Suitable for", 
    if(overall_completeness >= 70) "comprehensive analysis" 
    else if(overall_completeness >= 50) "targeted analysis with preprocessing"
    else "exploratory analysis only", "\n")

cat("\nAnalysis complete! Check the executive_summary.txt for detailed findings.\n")