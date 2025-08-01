#!/usr/bin/env Rscript
# =============================================================================
# MackMonitor Legislative Dataset - Data Duplication Analysis (Simplified)
# =============================================================================
# 
# This script analyzes the MackMonitor legislative dataset to identify and
# understand data duplication patterns using CSV files.
#
# Author: Claude Code (Senior Data Scientist)
# Date: 2025-08-01
# =============================================================================

# Set up environment
options(stringsAsFactors = FALSE)
Sys.setlocale("LC_ALL", "C")

# Check for required packages
required_packages <- c("dplyr", "readr", "stringr")
missing_packages <- required_packages[!sapply(required_packages, requireNamespace, quietly = TRUE)]

if (length(missing_packages) > 0) {
    cat("Missing required packages:", paste(missing_packages, collapse = ", "), "\n")
    cat("Please install them using: install.packages(c(", paste(paste0("'", missing_packages, "'"), collapse = ", "), "))\n")
    quit(status = 1)
}

# Load libraries
suppressPackageStartupMessages({
    library(dplyr)
    library(readr)
    library(stringr)
})

# =============================================================================
# CONFIGURATION
# =============================================================================

# Output directory for results
OUTPUT_DIR <- "data_current/processed/duplication_analysis"
dir.create(OUTPUT_DIR, recursive = TRUE, showWarnings = FALSE)

# Data file paths
MAIN_DATA_FILE <- "data_current/processed/analytics_ready_data.csv"
CLEANED_DATA_DIR <- "data_current/processed/cleaned"

# =============================================================================
# DATA LOADING FUNCTIONS
# =============================================================================

#' Load and prepare main dataset
load_main_dataset <- function() {
    cat("Loading main dataset...\n")
    
    if (!file.exists(MAIN_DATA_FILE)) {
        cat("Main data file not found:", MAIN_DATA_FILE, "\n")
        return(NULL)
    }
    
    tryCatch({
        data <- read_csv(MAIN_DATA_FILE, locale = locale(encoding = "UTF-8"), show_col_types = FALSE)
        cat("✓ Loaded", nrow(data), "records from main dataset\n")
        
        # Standardize column names
        names(data) <- tolower(names(data))
        
        # Add source information
        data$data_source <- "main_dataset"
        
        return(data)
        
    }, error = function(e) {
        cat("Error loading main dataset:", e$message, "\n")
        return(NULL)
    })
}

#' Load individual CSV files from cleaned directory
load_individual_files <- function() {
    cat("Loading individual CSV files...\n")
    
    if (!dir.exists(CLEANED_DATA_DIR)) {
        cat("Cleaned data directory not found:", CLEANED_DATA_DIR, "\n")
        return(NULL)
    }
    
    csv_files <- list.files(CLEANED_DATA_DIR, pattern = "\\.csv$", full.names = TRUE)
    
    if (length(csv_files) == 0) {
        cat("No CSV files found in cleaned directory\n")
        return(NULL)
    }
    
    cat("Found", length(csv_files), "CSV files\n")
    
    all_data <- list()
    
    for (file in csv_files[1:min(5, length(csv_files))]) {  # Limit to first 5 files for analysis
        tryCatch({
            file_data <- read_csv(file, locale = locale(encoding = "UTF-8"), show_col_types = FALSE)
            names(file_data) <- tolower(names(file_data))
            file_data$data_source <- basename(file)
            all_data[[basename(file)]] <- file_data
            cat("  ✓ Loaded", nrow(file_data), "records from", basename(file), "\n")
        }, error = function(e) {
            cat("  ✗ Error loading", basename(file), ":", e$message, "\n")
        })
    }
    
    if (length(all_data) > 0) {
        combined_data <- bind_rows(all_data)
        cat("✓ Combined", nrow(combined_data), "records from", length(all_data), "files\n")
        return(combined_data)
    } else {
        return(NULL)
    }
}

# =============================================================================
# DUPLICATION ANALYSIS FUNCTIONS
# =============================================================================

#' Analyze duplicates by specific columns
analyze_duplicates_by_columns <- function(data, group_cols, analysis_name) {
    cat("\n--- Analyzing duplicates by", analysis_name, "---\n")
    
    # Check if required columns exist
    missing_cols <- group_cols[!group_cols %in% names(data)]
    if (length(missing_cols) > 0) {
        cat("Missing columns:", paste(missing_cols, collapse = ", "), "\n")
        return(NULL)
    }
    
    # Remove rows with NA values in grouping columns
    complete_data <- data[complete.cases(data[group_cols]), ]
    
    if (nrow(complete_data) == 0) {
        cat("No complete cases found for analysis\n")
        return(NULL)
    }
    
    # Count duplicates
    dup_analysis <- complete_data %>%
        group_by(across(all_of(group_cols))) %>%
        summarise(
            count = n(),
            sources = n_distinct(data_source),
            source_list = paste(unique(data_source), collapse = "; "),
            .groups = "drop"
        ) %>%
        arrange(desc(count))
    
    # Calculate statistics
    total_records <- nrow(complete_data)
    unique_groups <- nrow(dup_analysis)
    duplicated_groups <- sum(dup_analysis$count > 1)
    duplicated_records <- sum(dup_analysis$count[dup_analysis$count > 1])
    duplication_rate <- (duplicated_records / total_records) * 100
    
    # Print summary
    cat("Total records:", total_records, "\n")
    cat("Unique groups:", unique_groups, "\n")
    cat("Groups with duplicates:", duplicated_groups, "\n")
    cat("Duplicated records:", duplicated_records, "\n")
    cat("Duplication rate:", round(duplication_rate, 2), "%\n")
    
    # Show top duplicates
    top_dups <- head(dup_analysis[dup_analysis$count > 1, ], 10)
    if (nrow(top_dups) > 0) {
        cat("\nTop duplicates:\n")
        for (i in 1:nrow(top_dups)) {
            cat("  ", top_dups$count[i], "copies:")
            for (col in group_cols) {
                val <- as.character(top_dups[[col]][i])
                cat(" [", col, ":", substr(val, 1, 50), "]")
            }
            cat("\n")
        }
    }
    
    return(list(
        analysis_name = analysis_name,
        columns = group_cols,
        total_records = total_records,
        unique_groups = unique_groups,
        duplicated_groups = duplicated_groups,
        duplicated_records = duplicated_records,
        duplication_rate = duplication_rate,
        top_duplicates = top_dups,
        full_analysis = dup_analysis
    ))
}

#' Comprehensive duplication analysis
perform_comprehensive_analysis <- function(data) {
    cat("\n=== COMPREHENSIVE DUPLICATION ANALYSIS ===\n")
    cat("Dataset shape:", nrow(data), "rows x", ncol(data), "columns\n")
    cat("Available columns:", paste(names(data)[1:min(15, ncol(data))], collapse = ", "), "...\n")
    
    results <- list()
    
    # Define analysis criteria based on available columns
    available_cols <- names(data)
    
    # URN analysis
    if ("urn" %in% available_cols) {
        results$urn <- analyze_duplicates_by_columns(data, "urn", "URN")
    }
    
    # Title analysis
    if ("titulo" %in% available_cols) {
        results$title <- analyze_duplicates_by_columns(data, "titulo", "Title")
    }
    
    # URL analysis
    if ("url" %in% available_cols) {
        results$url <- analyze_duplicates_by_columns(data, "url", "URL")
    }
    
    # Title + Type analysis
    if (all(c("titulo", "tipo") %in% available_cols)) {
        results$title_type <- analyze_duplicates_by_columns(data, c("titulo", "tipo"), "Title + Type")
    }
    
    # URN + Title analysis
    if (all(c("urn", "titulo") %in% available_cols)) {
        results$urn_title <- analyze_duplicates_by_columns(data, c("urn", "titulo"), "URN + Title")
    }
    
    # Content hash analysis (if content available)
    if ("conteudo" %in% available_cols) {
        # Create content hash for exact content duplicates
        data$content_hash <- sapply(data$conteudo, function(x) {
            if (is.na(x) || x == "") return(NA)
            digest::digest(tolower(trimws(x)), algo = "md5")
        })
        results$content <- analyze_duplicates_by_columns(data, "content_hash", "Exact Content")
    }
    
    return(results)
}

#' Analyze temporal patterns
analyze_temporal_patterns <- function(data) {
    cat("\n=== TEMPORAL DUPLICATION PATTERNS ===\n")
    
    temporal_results <- list()
    
    # Collection date analysis
    if ("created_at" %in% names(data)) {
        cat("Analyzing collection date patterns...\n")
        
        data$collection_date <- as.Date(data$created_at)
        
        collection_pattern <- data %>%
            filter(!is.na(collection_date)) %>%
            group_by(collection_date, data_source) %>%
            summarise(
                records = n(),
                unique_urns = n_distinct(urn, na.rm = TRUE),
                unique_titles = n_distinct(titulo, na.rm = TRUE),
                .groups = "drop"
            ) %>%
            mutate(
                urn_duplication_ratio = ifelse(unique_urns > 0, records / unique_urns, NA),
                title_duplication_ratio = ifelse(unique_titles > 0, records / unique_titles, NA)
            ) %>%
            arrange(desc(urn_duplication_ratio))
        
        temporal_results$collection_patterns <- collection_pattern
        
        cat("Collection dates with highest URN duplication:\n")
        print(head(collection_pattern[!is.na(collection_pattern$urn_duplication_ratio), ], 10))
    }
    
    # Publication year analysis
    if ("data_publicacao" %in% names(data)) {
        cat("\nAnalyzing publication year patterns...\n")
        
        data$pub_year <- as.integer(format(as.Date(data$data_publicacao), "%Y"))
        
        year_pattern <- data %>%
            filter(!is.na(pub_year), pub_year >= 1900, pub_year <= 2025) %>%
            group_by(pub_year) %>%
            summarise(
                records = n(),
                unique_urns = n_distinct(urn, na.rm = TRUE),
                unique_titles = n_distinct(titulo, na.rm = TRUE),
                sources = n_distinct(data_source),
                .groups = "drop"
            ) %>%
            mutate(
                urn_duplication_ratio = ifelse(unique_urns > 0, records / unique_urns, NA),
                title_duplication_ratio = ifelse(unique_titles > 0, records / unique_titles, NA)
            ) %>%
            arrange(desc(records))
        
        temporal_results$publication_year_patterns <- year_pattern
        
        cat("Publication years with highest duplication:\n")
        print(head(year_pattern[order(-year_pattern$urn_duplication_ratio, na.last = TRUE), ], 10))
    }
    
    return(temporal_results)
}

#' Analyze source-specific patterns
analyze_source_patterns <- function(data) {
    cat("\n=== SOURCE-SPECIFIC DUPLICATION PATTERNS ===\n")
    
    if (!"data_source" %in% names(data)) {
        cat("No data_source column available\n")
        return(NULL)
    }
    
    source_analysis <- data %>%
        group_by(data_source) %>%
        summarise(
            total_records = n(),
            unique_urns = n_distinct(urn, na.rm = TRUE),
            unique_titles = n_distinct(titulo, na.rm = TRUE),
            unique_urls = n_distinct(url, na.rm = TRUE),
            na_urns = sum(is.na(urn) | urn == ""),
            na_titles = sum(is.na(titulo) | titulo == ""),
            .groups = "drop"
        ) %>%
        mutate(
            urn_duplication_rate = ifelse(unique_urns > 0, (total_records - unique_urns) / total_records * 100, 0),
            title_duplication_rate = ifelse(unique_titles > 0, (total_records - unique_titles) / total_records * 100, 0),
            url_duplication_rate = ifelse(unique_urls > 0, (total_records - unique_urls) / total_records * 100, 0),
            urn_completeness = (total_records - na_urns) / total_records * 100,
            title_completeness = (total_records - na_titles) / total_records * 100
        ) %>%
        arrange(desc(total_records))
    
    cat("Source-specific duplication analysis:\n")
    print(source_analysis)
    
    return(source_analysis)
}

# =============================================================================
# CROSS-SOURCE DUPLICATION ANALYSIS
# =============================================================================

#' Analyze duplicates across different sources
analyze_cross_source_duplicates <- function(data) {
    cat("\n=== CROSS-SOURCE DUPLICATION ANALYSIS ===\n")
    
    if (n_distinct(data$data_source) < 2) {
        cat("Only one data source available, skipping cross-source analysis\n")
        return(NULL)
    }
    
    # URN cross-source duplicates
    if ("urn" %in% names(data)) {
        urn_cross_source <- data %>%
            filter(!is.na(urn), urn != "") %>%
            group_by(urn) %>%
            summarise(
                count = n(),
                sources = n_distinct(data_source),
                source_list = paste(unique(data_source), collapse = "; "),
                .groups = "drop"
            ) %>%
            filter(sources > 1) %>%
            arrange(desc(count))
        
        cat("URNs appearing in multiple sources:", nrow(urn_cross_source), "\n")
        if (nrow(urn_cross_source) > 0) {
            cat("Top cross-source URN duplicates:\n")
            print(head(urn_cross_source, 10))
        }
    }
    
    # Title cross-source duplicates
    if ("titulo" %in% names(data)) {
        title_cross_source <- data %>%
            filter(!is.na(titulo), titulo != "") %>%
            group_by(titulo) %>%
            summarise(
                count = n(),
                sources = n_distinct(data_source),
                source_list = paste(unique(data_source), collapse = "; "),
                .groups = "drop"
            ) %>%
            filter(sources > 1) %>%
            arrange(desc(count))
        
        cat("\nTitles appearing in multiple sources:", nrow(title_cross_source), "\n")
        if (nrow(title_cross_source) > 0) {
            cat("Top cross-source title duplicates (first 50 chars):\n")
            for (i in 1:min(10, nrow(title_cross_source))) {
                cat("  ", title_cross_source$count[i], "copies:", 
                    substr(title_cross_source$titulo[i], 1, 50), "...\n")
            }
        }
    }
    
    return(list(
        urn_cross_source = if (exists("urn_cross_source")) urn_cross_source else NULL,
        title_cross_source = if (exists("title_cross_source")) title_cross_source else NULL
    ))
}

# =============================================================================
# REPORT GENERATION
# =============================================================================

#' Generate comprehensive analysis report
generate_analysis_report <- function(dup_results, temporal_results, source_results, cross_source_results, data_info) {
    report_file <- file.path(OUTPUT_DIR, "duplication_analysis_report.txt")
    
    sink(report_file)
    
    cat("===============================================================================\n")
    cat("MACKMONITOR LEGISLATIVE DATASET - DATA DUPLICATION ANALYSIS REPORT\n")
    cat("===============================================================================\n")
    cat("Generated:", as.character(Sys.time()), "\n")
    cat("Analysis performed by: Claude Code (Senior Data Scientist)\n")
    cat("Analysis scope: Brazilian Legislative Documents Dataset\n")
    cat("\n")
    
    # Executive Summary
    cat("EXECUTIVE SUMMARY\n")
    cat("=================\n")
    cat("Dataset analyzed:", data_info$total_records, "records\n")
    cat("Data sources:", data_info$total_sources, "\n")
    cat("Analysis criteria:", length(dup_results), "\n")
    
    if (length(dup_results) > 0) {
        rates <- sapply(dup_results, function(x) if (!is.null(x)) x$duplication_rate else 0)
        avg_rate <- mean(rates, na.rm = TRUE)
        max_rate <- max(rates, na.rm = TRUE)
        max_criteria <- names(rates)[which.max(rates)]
        
        cat("Average duplication rate:", round(avg_rate, 2), "%\n")
        cat("Highest duplication rate:", round(max_rate, 2), "% (", max_criteria, ")\n")
    }
    
    cat("\nKEY FINDINGS:\n")
    
    # Detailed analysis results
    cat("\n\nDETAILED DUPLICATION ANALYSIS\n")
    cat("=============================\n")
    
    for (name in names(dup_results)) {
        if (!is.null(dup_results[[name]])) {
            result <- dup_results[[name]]
            cat("\n", toupper(result$analysis_name), ":\n")
            cat("  Columns analyzed:", paste(result$columns, collapse = ", "), "\n")
            cat("  Total records:", result$total_records, "\n")
            cat("  Unique groups:", result$unique_groups, "\n")
            cat("  Duplicated groups:", result$duplicated_groups, "\n")
            cat("  Duplicated records:", result$duplicated_records, "\n")
            cat("  Duplication rate:", round(result$duplication_rate, 2), "%\n")
            
            if (!is.null(result$top_duplicates) && nrow(result$top_duplicates) > 0) {
                cat("  Sample duplicates:\n")
                for (i in 1:min(3, nrow(result$top_duplicates))) {
                    sample_val <- as.character(result$top_duplicates[i, result$columns[1]])
                    cat("    -", result$top_duplicates$count[i], "copies of:", 
                        substr(sample_val, 1, 60), "...\n")
                }
            }
        }
    }
    
    # Temporal analysis
    if (!is.null(temporal_results)) {
        cat("\n\nTEMPORAL ANALYSIS\n")
        cat("=================\n")
        
        if (!is.null(temporal_results$collection_patterns)) {
            cat("Collection patterns show variation in duplication rates over time.\n")
            max_dup_date <- temporal_results$collection_patterns[
                which.max(temporal_results$collection_patterns$urn_duplication_ratio), ]
            if (nrow(max_dup_date) > 0) {
                cat("Highest duplication detected on:", as.character(max_dup_date$collection_date), 
                    "with ratio:", round(max_dup_date$urn_duplication_ratio, 2), "\n")
            }
        }
        
        if (!is.null(temporal_results$publication_year_patterns)) {
            cat("Publication year analysis shows varying patterns across decades.\n")
        }
    }
    
    # Source analysis
    if (!is.null(source_results)) {
        cat("\n\nSOURCE ANALYSIS\n")
        cat("===============\n")
        cat("Analysis of", nrow(source_results), "data sources:\n")
        
        for (i in 1:nrow(source_results)) {
            cat("\n", source_results$data_source[i], ":\n")
            cat("  Records:", source_results$total_records[i], "\n")
            cat("  URN duplication rate:", round(source_results$urn_duplication_rate[i], 2), "%\n")
            cat("  Title duplication rate:", round(source_results$title_duplication_rate[i], 2), "%\n")
            cat("  URN completeness:", round(source_results$urn_completeness[i], 2), "%\n")
        }
    }
    
    # Cross-source analysis
    if (!is.null(cross_source_results)) {
        cat("\n\nCROSS-SOURCE DUPLICATION\n")
        cat("========================\n")
        
        if (!is.null(cross_source_results$urn_cross_source)) {
            cat("URNs appearing in multiple sources:", nrow(cross_source_results$urn_cross_source), "\n")
        }
        
        if (!is.null(cross_source_results$title_cross_source)) {
            cat("Titles appearing in multiple sources:", nrow(cross_source_results$title_cross_source), "\n")
        }
    }
    
    # Recommendations
    cat("\n\nRECOMMENDations FOR DEDUPLICATION\n")
    cat("==================================\n")
    cat("Based on the analysis, the following actions are recommended:\n\n")
    
    cat("IMMEDIATE ACTIONS:\n")
    cat("1. URN Standardization - Implement URN validation and normalization\n")
    cat("2. Collection Process Review - Examine data collection methodology\n")
    cat("3. Database Constraints - Add unique constraints where appropriate\n")
    cat("4. Data Quality Monitoring - Implement ongoing duplicate detection\n\n")
    
    cat("MEDIUM-TERM ACTIONS:\n")
    cat("1. Fuzzy Matching Implementation - For semantic duplicate detection\n")
    cat("2. Master Data Management - Establish authoritative record sources\n")
    cat("3. Data Lineage Tracking - Track data provenance and collection history\n")
    cat("4. Automated Quality Checks - Implement pre-import validation\n\n")
    
    cat("LONG-TERM STRATEGY:\n")
    cat("1. Data Governance Framework - Establish data quality standards\n")
    cat("2. Integration Architecture - Design systems to prevent duplicates\n")
    cat("3. Legal Document Ontology - Develop structured metadata standards\n")
    cat("4. Performance Optimization - Balance deduplication with query performance\n")
    
    sink()
    
    cat("✓ Comprehensive analysis report saved to:", report_file, "\n")
    
    # Save structured results
    results_file <- file.path(OUTPUT_DIR, "duplication_analysis_results.rds")
    saveRDS(list(
        duplication_results = dup_results,
        temporal_results = temporal_results,
        source_results = source_results,
        cross_source_results = cross_source_results,
        data_info = data_info,
        analysis_metadata = list(
            timestamp = Sys.time(),
            r_version = R.version.string
        )
    ), results_file)
    
    cat("✓ Structured results saved to:", results_file, "\n")
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main <- function() {
    cat("===============================================================================\n")
    cat("MACKMONITOR LEGISLATIVE DATASET - DATA DUPLICATION ANALYSIS\n")
    cat("===============================================================================\n")
    cat("Analysis started:", as.character(Sys.time()), "\n")
    cat("Focus: Brazilian Legislative Documents Duplication Patterns\n\n")
    
    # 1. Load data
    cat("1. Loading data sources...\n")
    
    # Try main dataset first
    main_data <- load_main_dataset()
    
    # If main dataset not available, try individual files
    if (is.null(main_data)) {
        cat("Main dataset not available, trying individual files...\n")
        main_data <- load_individual_files()
    }
    
    if (is.null(main_data) || nrow(main_data) == 0) {
        stop("No data could be loaded for analysis. Please check data file paths.")
    }
    
    # Data information
    data_info <- list(
        total_records = nrow(main_data),
        total_columns = ncol(main_data),
        total_sources = n_distinct(main_data$data_source),
        column_names = names(main_data)
    )
    
    cat("✓ Data loaded successfully:\n")
    cat("  Records:", data_info$total_records, "\n")
    cat("  Columns:", data_info$total_columns, "\n")
    cat("  Sources:", data_info$total_sources, "\n")
    
    # 2. Comprehensive duplication analysis
    cat("\n2. Performing comprehensive duplication analysis...\n")
    dup_results <- perform_comprehensive_analysis(main_data)
    
    # 3. Temporal pattern analysis
    cat("\n3. Analyzing temporal patterns...\n")
    temporal_results <- analyze_temporal_patterns(main_data)
    
    # 4. Source-specific analysis
    cat("\n4. Analyzing source-specific patterns...\n")
    source_results <- analyze_source_patterns(main_data)
    
    # 5. Cross-source duplicate analysis
    cat("\n5. Analyzing cross-source duplicates...\n")
    cross_source_results <- analyze_cross_source_duplicates(main_data)
    
    # 6. Generate comprehensive report
    cat("\n6. Generating comprehensive analysis report...\n")
    generate_analysis_report(dup_results, temporal_results, source_results, 
                           cross_source_results, data_info)
    
    cat("\n===============================================================================\n")
    cat("ANALYSIS COMPLETE\n")
    cat("===============================================================================\n")
    cat("Results available in:", OUTPUT_DIR, "\n")
    
    # Summary of key findings
    if (length(dup_results) > 0) {
        rates <- sapply(dup_results, function(x) if (!is.null(x)) x$duplication_rate else 0)
        valid_rates <- rates[rates > 0]
        
        if (length(valid_rates) > 0) {
            cat("\nKEY FINDINGS:\n")
            cat("- Highest duplication rate:", round(max(valid_rates), 2), "% (", 
                names(valid_rates)[which.max(valid_rates)], ")\n")
            cat("- Average duplication rate:", round(mean(valid_rates), 2), "%\n")
            cat("- Analysis criteria with results:", length(valid_rates), "/", length(dup_results), "\n")
        }
    }
    
    if (!is.null(source_results) && nrow(source_results) > 0) {
        max_source_dup <- max(source_results$urn_duplication_rate, na.rm = TRUE)
        cat("- Maximum source duplication:", round(max_source_dup, 2), "%\n")
    }
    
    cat("\nNEXT STEPS:\n")
    cat("1. Review the detailed analysis report\n")
    cat("2. Implement URN standardization and validation\n")
    cat("3. Review data collection processes\n")
    cat("4. Design and implement deduplication strategy\n")
    cat("5. Establish ongoing data quality monitoring\n")
    
    return(list(
        duplication_results = dup_results,
        temporal_results = temporal_results,
        source_results = source_results,
        cross_source_results = cross_source_results,
        data_info = data_info
    ))
}

# Execute main function
if (!interactive()) {
    results <- main()
}