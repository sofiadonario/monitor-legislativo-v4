#!/usr/bin/env Rscript
# =============================================================================
# MackMonitor Legislative Dataset - Data Duplication Analysis
# =============================================================================
# 
# This script analyzes the MackMonitor legislative dataset to identify and
# understand data duplication patterns where one logical result corresponds
# to multiple rows.
#
# Author: Claude Code (Senior Data Scientist)
# Date: 2025-08-01
# =============================================================================

# Load required libraries with error handling - focusing on essential packages
required_packages <- c("dplyr", "ggplot2", "stringr", "readr", "lubridate", "tidyr")

for (pkg in required_packages) {
    if (!require(pkg, character.only = TRUE, quietly = TRUE)) {
        cat("Installing package:", pkg, "\n")
        install.packages(pkg, dependencies = TRUE, quiet = TRUE)
        library(pkg, character.only = TRUE, quietly = TRUE)
    }
}

# Optional packages - load if available
optional_packages <- c("data.table", "gridExtra", "plotly")
for (pkg in optional_packages) {
    if (requireNamespace(pkg, quietly = TRUE)) {
        library(pkg, character.only = TRUE, quietly = TRUE)
    }
}

# =============================================================================
# CONFIGURATION
# =============================================================================

# Database connection settings (attempt to read from environment or use defaults)
DB_HOST     <- Sys.getenv("DATABASE_HOST", "localhost")
DB_PORT     <- as.integer(Sys.getenv("DATABASE_PORT", "5432"))
DB_NAME     <- Sys.getenv("DATABASE_NAME", "postgres")
DB_USER     <- Sys.getenv("DATABASE_USER", "postgres")
DB_PASSWORD <- Sys.getenv("DATABASE_PASSWORD", "")

# Alternative: Try Railway database URL if available
railway_url <- Sys.getenv("DATABASE_URL", "")
if (railway_url != "") {
    cat("Using Railway database connection\n")
    # Parse Railway URL format: postgresql://user:pass@host:port/db
    url_pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):(\\d+)/(.+)"
    if (grepl(url_pattern, railway_url)) {
        matches <- regmatches(railway_url, regexec(url_pattern, railway_url))[[1]]
        DB_USER <- matches[2]
        DB_PASSWORD <- matches[3]
        DB_HOST <- matches[4]
        DB_PORT <- as.integer(matches[5])
        DB_NAME <- matches[6]
    }
}

# Output directory for results
OUTPUT_DIR <- "data_current/processed/duplication_analysis"
dir.create(OUTPUT_DIR, recursive = TRUE, showWarnings = FALSE)

# =============================================================================
# DATABASE CONNECTION FUNCTIONS
# =============================================================================

#' Establish database connection with fallback options
#' @return DBI connection object or NULL if failed
connect_to_database <- function() {
    tryCatch({
        # Try primary connection
        con <- DBI::dbConnect(
            RPostgreSQL::PostgreSQL(),
            host = DB_HOST,
            port = DB_PORT,
            dbname = DB_NAME,
            user = DB_USER,
            password = DB_PASSWORD
        )
        
        # Test connection
        DBI::dbGetQuery(con, "SELECT 1")
        cat("✓ Database connection established successfully\n")
        return(con)
        
    }, error = function(e) {
        cat("✗ Database connection failed:", e$message, "\n")
        
        # Fallback: Try to read from CSV files
        cat("Attempting fallback to CSV data...\n")
        return(NULL)
    })
}

#' Get table names from database or fallback to CSV files
get_available_tables <- function(con = NULL) {
    if (!is.null(con)) {
        # Get tables from database
        tables <- DBI::dbListTables(con)
        lexml_tables <- tables[grepl("^lexml_", tables)]
        return(list(
            source = "database",
            lexml_tables = lexml_tables,
            all_tables = tables
        ))
    } else {
        # Fallback to CSV files
        csv_files <- list.files("data_current/processed", 
                               pattern = "\\.csv$", 
                               recursive = TRUE, 
                               full.names = TRUE)
        lexml_files <- csv_files[grepl("lexml_", basename(csv_files))]
        return(list(
            source = "csv",
            lexml_tables = lexml_files,
            all_tables = csv_files
        ))
    }
}

# =============================================================================
# DATA LOADING FUNCTIONS
# =============================================================================

#' Load data from database or CSV with consistent structure
#' @param table_name Name of table or path to CSV file
#' @param con Database connection (NULL for CSV mode)
#' @param limit Maximum rows to load (NULL for all)
load_data_source <- function(table_name, con = NULL, limit = NULL) {
    tryCatch({
        if (!is.null(con)) {
            # Load from database
            query <- paste("SELECT * FROM", table_name)
            if (!is.null(limit)) {
                query <- paste(query, "LIMIT", limit)
            }
            data <- DBI::dbGetQuery(con, query)
        } else {
            # Load from CSV
            if (file.exists(table_name)) {
                data <- readr::read_csv(table_name, 
                                      locale = readr::locale(encoding = "UTF-8"),
                                      show_col_types = FALSE)
                if (!is.null(limit) && nrow(data) > limit) {
                    data <- data[1:limit, ]
                }
            } else {
                return(NULL)
            }
        }
        
        # Standardize column names
        names(data) <- tolower(names(data))
        
        # Add source information
        data$data_source <- ifelse(!is.null(con), "database", basename(table_name))
        
        return(data)
        
    }, error = function(e) {
        cat("✗ Error loading", table_name, ":", e$message, "\n")
        return(NULL)
    })
}

# =============================================================================
# DUPLICATION ANALYSIS FUNCTIONS
# =============================================================================

#' Analyze duplicate patterns by different criteria
#' @param data Data frame to analyze
#' @param group_cols Columns to group by for duplicate detection
#' @param name Analysis name for reporting
analyze_duplicates_by_criteria <- function(data, group_cols, name) {
    cat("\n--- Analyzing duplicates by", name, "---\n")
    
    # Remove rows with all NA values in group columns
    complete_data <- data[complete.cases(data[group_cols]), ]
    
    if (nrow(complete_data) == 0) {
        cat("No complete cases found for", name, "\n")
        return(NULL)
    }
    
    # Count occurrences
    dup_counts <- complete_data %>%
        group_by(across(all_of(group_cols))) %>%
        summarise(
            count = n(),
            first_date = min(as.Date(created_at), na.rm = TRUE),
            last_date = max(as.Date(created_at), na.rm = TRUE),
            date_range_days = as.numeric(last_date - first_date),
            sources = paste(unique(data_source), collapse = ", "),
            .groups = "drop"
        ) %>%
        arrange(desc(count))
    
    # Summary statistics
    total_records <- nrow(complete_data)
    total_unique_groups <- nrow(dup_counts)
    duplicate_groups <- sum(dup_counts$count > 1)
    duplicate_records <- sum(dup_counts$count[dup_counts$count > 1])
    duplication_rate <- (duplicate_records / total_records) * 100
    
    cat("Total records:", total_records, "\n")
    cat("Unique groups:", total_unique_groups, "\n")
    cat("Groups with duplicates:", duplicate_groups, "\n")
    cat("Total duplicate records:", duplicate_records, "\n")
    cat("Duplication rate:", round(duplication_rate, 2), "%\n")
    
    # Return analysis results
    list(
        name = name,
        criteria = group_cols,
        total_records = total_records,
        unique_groups = total_unique_groups,
        duplicate_groups = duplicate_groups,
        duplicate_records = duplicate_records,
        duplication_rate = duplication_rate,
        top_duplicates = head(dup_counts[dup_counts$count > 1, ], 20),
        all_duplicates = dup_counts
    )
}

#' Generate comprehensive duplication report
generate_duplication_report <- function(data) {
    cat("\n=== COMPREHENSIVE DUPLICATION ANALYSIS ===\n")
    cat("Dataset shape:", nrow(data), "rows x", ncol(data), "columns\n")
    cat("Analysis timestamp:", Sys.time(), "\n")
    
    # Define different duplication criteria
    criteria_list <- list(
        "URN" = "urn",
        "Title" = "titulo",
        "URL" = "url",
        "Title + Type" = c("titulo", "tipo"),
        "URN + Title" = c("urn", "titulo"),
        "Title + Date" = c("titulo", "data_publicacao"),
        "URL + Title" = c("url", "titulo"),
        "Exact Content" = c("titulo", "urn", "url", "data_publicacao"),
        "Semantic Similarity" = c("titulo", "conteudo", "tipo")
    )
    
    # Run analysis for each criterion
    results <- list()
    for (name in names(criteria_list)) {
        cols <- criteria_list[[name]]
        # Only analyze if all required columns exist
        if (all(cols %in% names(data))) {
            results[[name]] <- analyze_duplicates_by_criteria(data, cols, name)
        } else {
            cat("Skipping", name, "- missing columns:", 
                paste(cols[!cols %in% names(data)], collapse = ", "), "\n")
        }
    }
    
    return(results)
}

#' Analyze temporal patterns in duplicates
analyze_temporal_duplication <- function(data) {
    cat("\n=== TEMPORAL DUPLICATION ANALYSIS ===\n")
    
    # Convert dates
    if ("data_publicacao" %in% names(data)) {
        data$pub_date <- as.Date(data$data_publicacao)
    }
    if ("created_at" %in% names(data)) {
        data$collect_date <- as.Date(data$created_at)
    }
    
    temporal_analysis <- list()
    
    # 1. Collection date patterns
    if ("collect_date" %in% names(data)) {
        collection_pattern <- data %>%
            filter(!is.na(collect_date)) %>%
            group_by(collect_date) %>%
            summarise(
                records_collected = n(),
                unique_urns = n_distinct(urn, na.rm = TRUE),
                unique_titles = n_distinct(titulo, na.rm = TRUE),
                duplication_ratio = ifelse(unique_urns > 0, records_collected / unique_urns, 1),
                .groups = "drop"
            ) %>%
            arrange(desc(records_collected))
        
        temporal_analysis$collection_patterns <- collection_pattern
        cat("Collection dates with highest duplication:\n")
        print(head(collection_pattern[order(-collection_pattern$duplication_ratio), ], 10))
    }
    
    # 2. Publication year patterns
    if ("pub_date" %in% names(data)) {
        data$pub_year <- year(data$pub_date)
        year_pattern <- data %>%
            filter(!is.na(pub_year), pub_year >= 1900, pub_year <= 2025) %>%
            group_by(pub_year) %>%
            summarise(
                records = n(),
                unique_urns = n_distinct(urn, na.rm = TRUE),
                unique_titles = n_distinct(titulo, na.rm = TRUE),
                urn_duplication = ifelse(unique_urns > 0, records / unique_urns, 1),
                title_duplication = ifelse(unique_titles > 0, records / unique_titles, 1),
                .groups = "drop"
            ) %>%
            arrange(desc(records))
        
        temporal_analysis$publication_year_patterns <- year_pattern
        cat("\nPublication years with highest duplication by URN:\n")
        print(head(year_pattern[order(-year_pattern$urn_duplication), ], 10))
    }
    
    return(temporal_analysis)
}

#' Analyze source-specific duplication patterns
analyze_source_duplication <- function(data) {
    cat("\n=== SOURCE-SPECIFIC DUPLICATION ANALYSIS ===\n")
    
    if (!"data_source" %in% names(data)) {
        cat("No data_source column found. Skipping source analysis.\n")
        return(NULL)
    }
    
    source_analysis <- data %>%
        group_by(data_source) %>%
        summarise(
            total_records = n(),
            unique_urns = n_distinct(urn, na.rm = TRUE),
            unique_titles = n_distinct(titulo, na.rm = TRUE),
            unique_urls = n_distinct(url, na.rm = TRUE),
            urn_duplication_rate = ifelse(unique_urns > 0, (total_records - unique_urns) / total_records * 100, 0),
            title_duplication_rate = ifelse(unique_titles > 0, (total_records - unique_titles) / total_records * 100, 0),
            url_duplication_rate = ifelse(unique_urls > 0, (total_records - unique_urls) / total_records * 100, 0),
            .groups = "drop"
        ) %>%
        arrange(desc(total_records))
    
    cat("Duplication rates by data source:\n")
    print(source_analysis)
    
    return(source_analysis)
}

# =============================================================================
# VISUALIZATION FUNCTIONS
# =============================================================================

#' Create comprehensive duplication visualization
create_duplication_visualizations <- function(dup_results, temporal_results, source_results) {
    plots <- list()
    
    # 1. Duplication rates by criteria
    if (length(dup_results) > 0) {
        dup_summary <- data.frame(
            criteria = names(dup_results),
            duplication_rate = sapply(dup_results, function(x) x$duplication_rate),
            duplicate_records = sapply(dup_results, function(x) x$duplicate_records),
            stringsAsFactors = FALSE
        )
        
        plots$duplication_rates <- ggplot(dup_summary, aes(x = reorder(criteria, duplication_rate), y = duplication_rate)) +
            geom_col(fill = "steelblue", alpha = 0.8) +
            geom_text(aes(label = paste0(round(duplication_rate, 1), "%")), 
                     hjust = -0.1, size = 3) +
            coord_flip() +
            labs(
                title = "Data Duplication Rates by Different Criteria",
                subtitle = "Percentage of records that have duplicates",
                x = "Duplication Criteria",
                y = "Duplication Rate (%)",
                caption = paste("Analysis date:", Sys.Date())
            ) +
            theme_minimal() +
            theme(
                plot.title = element_text(size = 14, face = "bold"),
                axis.text = element_text(size = 10)
            )
    }
    
    # 2. Temporal patterns
    if (!is.null(temporal_results$collection_patterns)) {
        plots$temporal_collection <- ggplot(temporal_results$collection_patterns, 
                                          aes(x = collect_date, y = duplication_ratio)) +
            geom_line(color = "red", size = 1) +
            geom_point(aes(size = records_collected), alpha = 0.6, color = "darkred") +
            labs(
                title = "Duplication Ratio Over Collection Time",
                subtitle = "Higher values indicate more duplicates collected on that date",
                x = "Collection Date",
                y = "Duplication Ratio (Records/Unique URNs)",
                size = "Records Collected"
            ) +
            theme_minimal() +
            theme(axis.text.x = element_text(angle = 45, hjust = 1))
    }
    
    # 3. Source comparison
    if (!is.null(source_results)) {
        plots$source_comparison <- ggplot(source_results, 
                                        aes(x = reorder(data_source, urn_duplication_rate))) +
            geom_col(aes(y = urn_duplication_rate), fill = "orange", alpha = 0.8) +
            coord_flip() +
            labs(
                title = "URN Duplication Rate by Data Source",
                x = "Data Source",
                y = "URN Duplication Rate (%)",
                caption = "Based on URN uniqueness within each source"
            ) +
            theme_minimal()
    }
    
    return(plots)
}

#' Save visualizations to files
save_visualizations <- function(plots, output_dir) {
    for (plot_name in names(plots)) {
        filename <- file.path(output_dir, paste0(plot_name, ".png"))
        ggsave(filename, plots[[plot_name]], width = 12, height = 8, dpi = 300)
        cat("Saved visualization:", filename, "\n")
    }
}

# =============================================================================
# DEDUPLICATION STRATEGY FUNCTIONS
# =============================================================================

#' Design deduplication strategy based on analysis results
design_deduplication_strategy <- function(dup_results, temporal_results, source_results) {
    cat("\n=== DEDUPLICATION STRATEGY DESIGN ===\n")
    
    strategy <- list(
        timestamp = Sys.time(),
        analysis_summary = list(),
        recommendations = list(),
        implementation_steps = list(),
        sql_queries = list()
    )
    
    # Analyze key findings
    if (length(dup_results) > 0) {
        # Find most problematic duplication type
        rates <- sapply(dup_results, function(x) x$duplication_rate)
        highest_dup <- names(rates)[which.max(rates)]
        
        strategy$analysis_summary$highest_duplication <- list(
            criteria = highest_dup,
            rate = max(rates),
            affected_records = dup_results[[highest_dup]]$duplicate_records
        )
        
        # URN-based analysis
        if ("URN" %in% names(dup_results)) {
            urn_analysis <- dup_results[["URN"]]
            strategy$analysis_summary$urn_duplicates <- list(
                rate = urn_analysis$duplication_rate,
                count = urn_analysis$duplicate_records,
                assessment = ifelse(urn_analysis$duplication_rate > 10, 
                                  "HIGH - Significant URN duplication detected",
                                  "MODERATE - Some URN duplication present")
            )
        }
    }
    
    # Generate recommendations
    strategy$recommendations <- list(
        "Priority 1: URN Standardization" = list(
            description = "Implement URN validation and normalization",
            rationale = "URNs should be unique identifiers for legal documents",
            impact = "High - Will resolve primary identification issues"
        ),
        
        "Priority 2: Collection Process Review" = list(
            description = "Review data collection methodology to prevent duplicates at source",
            rationale = "Prevention is better than post-processing cleanup",
            impact = "High - Will prevent future duplications"
        ),
        
        "Priority 3: Title Normalization" = list(
            description = "Implement fuzzy matching for similar titles",
            rationale = "Same documents may have slight title variations",
            impact = "Medium - Will catch semantic duplicates"
        ),
        
        "Priority 4: Temporal Validation" = list(
            description = "Validate document dates and collection timestamps",
            rationale = "Temporal inconsistencies indicate data quality issues",
            impact = "Medium - Will improve data integrity"
        )
    )
    
    # Implementation steps
    strategy$implementation_steps <- list(
        "Phase 1: Assessment and Planning" = c(
            "Complete detailed duplicate analysis",
            "Identify business rules for legitimate vs. duplicate documents",
            "Design database schema improvements",
            "Plan migration strategy"
        ),
        
        "Phase 2: Technical Implementation" = c(
            "Create deduplication algorithms",
            "Implement data validation rules",
            "Design merge logic for valuable duplicate information",
            "Create backup and rollback procedures"
        ),
        
        "Phase 3: Data Cleanup" = c(
            "Execute deduplication on historical data",
            "Validate results and data integrity",
            "Update application logic to handle cleaned data",
            "Monitor for regression"
        ),
        
        "Phase 4: Prevention" = c(
            "Implement collection-time duplicate detection",
            "Add database constraints and triggers",
            "Create monitoring and alerting",
            "Document processes and maintain quality standards"
        )
    )
    
    # Generate SQL queries for common deduplication tasks
    strategy$sql_queries <- list(
        find_urn_duplicates = "
            SELECT urn, COUNT(*) as duplicate_count, 
                   STRING_AGG(DISTINCT transport_category, ', ') as categories,
                   MIN(created_at) as first_seen,
                   MAX(created_at) as last_seen
            FROM documents 
            WHERE urn IS NOT NULL AND urn != ''
            GROUP BY urn 
            HAVING COUNT(*) > 1 
            ORDER BY duplicate_count DESC;",
        
        find_title_duplicates = "
            SELECT titulo, COUNT(*) as duplicate_count,
                   STRING_AGG(DISTINCT species, ', ') as document_types,
                   MIN(data_publicacao) as earliest_date,
                   MAX(data_publicacao) as latest_date
            FROM documents 
            WHERE titulo IS NOT NULL AND titulo != ''
            GROUP BY titulo 
            HAVING COUNT(*) > 1 
            ORDER BY duplicate_count DESC;",
        
        create_document_fingerprints = "
            -- Create fingerprints for fuzzy duplicate detection
            CREATE TABLE IF NOT EXISTS document_fingerprints AS
            SELECT id,
                   MD5(LOWER(TRIM(titulo))) as title_hash,
                   MD5(COALESCE(urn, '')) as urn_hash,
                   MD5(COALESCE(url, '')) as url_hash,
                   MD5(CONCAT(
                       COALESCE(LOWER(TRIM(titulo)), ''),
                       COALESCE(urn, ''),
                       COALESCE(data_publicacao::text, '')
                   )) as content_hash
            FROM documents;",
        
        merge_duplicate_metadata = "
            -- Example merge logic for URN duplicates
            WITH ranked_duplicates AS (
                SELECT *, 
                       ROW_NUMBER() OVER (
                           PARTITION BY urn 
                           ORDER BY created_at ASC, 
                                   CASE WHEN conteudo IS NOT NULL THEN 1 ELSE 2 END,
                                   LENGTH(COALESCE(conteudo, '')) DESC
                       ) as rn
                FROM documents 
                WHERE urn IS NOT NULL
            )
            SELECT * FROM ranked_duplicates WHERE rn = 1;"
    )
    
    return(strategy)
}

#' Save comprehensive analysis report
save_analysis_report <- function(dup_results, temporal_results, source_results, strategy, output_dir) {
    report_file <- file.path(output_dir, "duplication_analysis_report.txt")
    
    sink(report_file)
    
    cat("===============================================================================\n")
    cat("MACKMONITOR LEGISLATIVE DATASET - DATA DUPLICATION ANALYSIS REPORT\n")
    cat("===============================================================================\n")
    cat("Generated:", as.character(Sys.time()), "\n")
    cat("Analysis Type: Comprehensive Duplication Pattern Analysis\n")
    cat("\n")
    
    # Executive Summary
    cat("EXECUTIVE SUMMARY\n")
    cat("-----------------\n")
    if (length(dup_results) > 0) {
        total_records <- sum(sapply(dup_results, function(x) x$total_records))
        avg_dup_rate <- mean(sapply(dup_results, function(x) x$duplication_rate))
        cat("Total records analyzed:", total_records, "\n")
        cat("Average duplication rate:", round(avg_dup_rate, 2), "%\n")
        cat("Most problematic criteria:", names(which.max(sapply(dup_results, function(x) x$duplication_rate))), "\n")
    }
    cat("\n")
    
    # Detailed Results
    cat("DETAILED DUPLICATION ANALYSIS\n")
    cat("==============================\n")
    for (name in names(dup_results)) {
        result <- dup_results[[name]]
        cat("\n", name, ":\n")
        cat("  Total records:", result$total_records, "\n")
        cat("  Unique groups:", result$unique_groups, "\n")
        cat("  Duplicate groups:", result$duplicate_groups, "\n")
        cat("  Duplication rate:", round(result$duplication_rate, 2), "%\n")
        
        if (nrow(result$top_duplicates) > 0) {
            cat("  Top duplicates:\n")
            for (i in 1:min(5, nrow(result$top_duplicates))) {
                cat("    -", result$top_duplicates$count[i], "copies of:", 
                    substr(as.character(result$top_duplicates[i, result$criteria[1]]), 1, 60), "...\n")
            }
        }
    }
    
    # Temporal Analysis
    if (!is.null(temporal_results)) {
        cat("\n\nTEMPORAL ANALYSIS\n")
        cat("=================\n")
        if (!is.null(temporal_results$collection_patterns)) {
            cat("Collection patterns show varying duplication rates over time.\n")
            cat("Peak duplication periods may indicate batch collection issues.\n")
        }
    }
    
    # Source Analysis
    if (!is.null(source_results)) {
        cat("\n\nSOURCE ANALYSIS\n")
        cat("===============\n")
        cat("Duplication rates vary significantly by source:\n")
        for (i in 1:nrow(source_results)) {
            cat("  ", source_results$data_source[i], ": ", 
                round(source_results$urn_duplication_rate[i], 1), "% URN duplication\n")
        }
    }
    
    # Strategy
    cat("\n\nDEDUPLICATION STRATEGY\n")
    cat("======================\n")
    cat("Key Recommendations:\n")
    for (rec_name in names(strategy$recommendations)) {
        rec <- strategy$recommendations[[rec_name]]
        cat("\n", rec_name, ":\n")
        cat("  Description:", rec$description, "\n")
        cat("  Rationale:", rec$rationale, "\n")
        cat("  Impact:", rec$impact, "\n")
    }
    
    cat("\n\nImplementation Phases:\n")
    for (phase_name in names(strategy$implementation_steps)) {
        cat("\n", phase_name, ":\n")
        for (step in strategy$implementation_steps[[phase_name]]) {
            cat("  -", step, "\n")
        }
    }
    
    sink()
    
    cat("✓ Comprehensive analysis report saved to:", report_file, "\n")
    
    # Save structured results as RDS
    results_file <- file.path(output_dir, "duplication_analysis_results.rds")
    saveRDS(list(
        duplication_results = dup_results,
        temporal_results = temporal_results,
        source_results = source_results,
        strategy = strategy,
        analysis_metadata = list(
            timestamp = Sys.time(),
            r_version = R.version.string,
            packages_used = required_packages
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
    cat("Starting analysis at:", as.character(Sys.time()), "\n\n")
    
    # 1. Establish database connection
    cat("1. Establishing database connection...\n")
    con <- connect_to_database()
    
    # 2. Get available data sources
    cat("\n2. Identifying available data sources...\n")
    sources <- get_available_tables(con)
    cat("Data source type:", sources$source, "\n")
    cat("Available LexML sources:", length(sources$lexml_tables), "\n")
    
    # 3. Load representative sample of data
    cat("\n3. Loading data for analysis...\n")
    
    # Try to load from documents view first, then fallback to individual tables
    if (!is.null(con)) {
        # Try documents view
        sample_data <- tryCatch({
            load_data_source("documents", con, limit = 50000)
        }, error = function(e) {
            cat("Documents view not available, trying lexml_legislacao_geral...\n")
            load_data_source("lexml_legislacao_geral", con, limit = 20000)
        })
        
        # If still no data, try the first available table
        if (is.null(sample_data) && length(sources$lexml_tables) > 0) {
            sample_data <- load_data_source(sources$lexml_tables[1], con, limit = 20000)
        }
    } else {
        # CSV fallback
        csv_file <- "data_current/processed/analytics_ready_data.csv"
        if (file.exists(csv_file)) {
            sample_data <- load_data_source(csv_file, limit = 50000)
        } else {
            # Try any available CSV
            if (length(sources$lexml_tables) > 0) {
                sample_data <- load_data_source(sources$lexml_tables[1], limit = 20000)
            }
        }
    }
    
    if (is.null(sample_data) || nrow(sample_data) == 0) {
        stop("No data could be loaded for analysis. Please check database connection and data availability.")
    }
    
    cat("✓ Loaded", nrow(sample_data), "records for analysis\n")
    cat("Data columns:", paste(names(sample_data)[1:min(10, length(names(sample_data)))], collapse = ", "), "...\n")
    
    # 4. Perform comprehensive duplication analysis
    cat("\n4. Performing comprehensive duplication analysis...\n")
    dup_results <- generate_duplication_report(sample_data)
    
    # 5. Analyze temporal patterns
    cat("\n5. Analyzing temporal duplication patterns...\n")
    temporal_results <- analyze_temporal_duplication(sample_data)
    
    # 6. Analyze source-specific patterns
    cat("\n6. Analyzing source-specific duplication patterns...\n")
    source_results <- analyze_source_duplication(sample_data)
    
    # 7. Create visualizations
    cat("\n7. Creating visualizations...\n")
    plots <- create_duplication_visualizations(dup_results, temporal_results, source_results)
    save_visualizations(plots, OUTPUT_DIR)
    
    # 8. Design deduplication strategy
    cat("\n8. Designing deduplication strategy...\n")
    strategy <- design_deduplication_strategy(dup_results, temporal_results, source_results)
    
    # 9. Generate comprehensive report
    cat("\n9. Generating comprehensive analysis report...\n")
    save_analysis_report(dup_results, temporal_results, source_results, strategy, OUTPUT_DIR)
    
    # 10. Close database connection
    if (!is.null(con)) {
        DBI::dbDisconnect(con)
        cat("\n✓ Database connection closed\n")
    }
    
    cat("\n===============================================================================\n")
    cat("ANALYSIS COMPLETE\n")
    cat("===============================================================================\n")
    cat("Results saved to:", OUTPUT_DIR, "\n")
    cat("Key findings:\n")
    
    if (length(dup_results) > 0) {
        rates <- sapply(dup_results, function(x) x$duplication_rate)
        cat("- Highest duplication rate:", round(max(rates), 2), "% (", names(which.max(rates)), ")\n")
        cat("- Average duplication rate:", round(mean(rates), 2), "%\n")
        cat("- Total criteria analyzed:", length(dup_results), "\n")
    }
    
    if (!is.null(source_results)) {
        cat("- Data sources analyzed:", nrow(source_results), "\n")
        if (nrow(source_results) > 0) {
            max_source_dup <- max(source_results$urn_duplication_rate, na.rm = TRUE)
            cat("- Highest source duplication:", round(max_source_dup, 2), "%\n")
        }
    }
    
    cat("\nNext steps:\n")
    cat("1. Review the detailed analysis report\n")
    cat("2. Examine the visualizations\n")
    cat("3. Implement the recommended deduplication strategy\n")
    cat("4. Monitor data quality going forward\n")
    
    return(list(
        duplication_results = dup_results,
        temporal_results = temporal_results,
        source_results = source_results,
        strategy = strategy
    ))
}

# Execute main function if script is run directly
if (!interactive()) {
    results <- main()
}