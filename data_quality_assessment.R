# Data Quality Assessment for Brazilian Legislative Text Data
# MackMonitor v4 - Comprehensive Analysis
# Author: Analytics Module
# Date: 2025-01-25

library(DBI)
library(RPostgres)
library(dplyr)
library(tidyr)
library(ggplot2)
library(lubridate)
library(stringr)
library(knitr)
library(kableExtra)

# Database connection function
connect_to_database <- function() {
  # Try to load from existing connection scripts
  if (file.exists("scripts/R/database_connection.R")) {
    source("scripts/R/database_connection.R")
    if (exists("db_pool") && !is.null(db_pool)) {
      return(poolCheckout(db_pool))
    }
  }
  
  # Fallback to direct connection
  db_url <- Sys.getenv("DATABASE_URL", 
    "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway")
  
  # Parse connection string
  matches <- str_match(db_url, "postgresql://([^:]+):([^@]+)@([^:]+):([^/]+)/(.+)")
  
  if (!is.na(matches[1])) {
    conn <- dbConnect(
      RPostgres::Postgres(),
      dbname = matches[6],
      host = matches[4],
      port = as.numeric(matches[5]),
      user = matches[2],
      password = matches[3]
    )
    return(conn)
  }
  
  stop("Could not establish database connection")
}

# 1. DATA QUALITY ASSESSMENT FUNCTIONS

# 1.1 Correctness Checks
check_data_correctness <- function(conn) {
  cat("\n=== DATA CORRECTNESS ASSESSMENT ===\n")
  
  results <- list()
  
  # Check URN format compliance
  cat("\n1. Checking URN format compliance...\n")
  urn_check <- dbGetQuery(conn, "
    SELECT 
      COUNT(*) as total_records,
      COUNT(CASE WHEN urn IS NULL OR urn = '' THEN 1 END) as missing_urns,
      COUNT(CASE WHEN urn NOT LIKE 'urn:lex:br:%' THEN 1 END) as invalid_urn_format,
      COUNT(CASE WHEN urn ~ '^urn:lex:br:[a-z]+:[a-z]+:[a-z]+:[0-9]{4}(-[0-9]{2})?(-[0-9]{2})?:' THEN 1 END) as valid_urns
    FROM documents
  ")
  
  results$urn_compliance <- urn_check
  cat(sprintf("Total records: %d\n", urn_check$total_records))
  cat(sprintf("Missing URNs: %d (%.2f%%)\n", 
    urn_check$missing_urns, 
    urn_check$missing_urns/urn_check$total_records*100))
  cat(sprintf("Invalid URN format: %d (%.2f%%)\n", 
    urn_check$invalid_urn_format,
    urn_check$invalid_urn_format/urn_check$total_records*100))
  
  # Check date validity
  cat("\n2. Checking date validity...\n")
  date_check <- dbGetQuery(conn, "
    SELECT 
      COUNT(*) as total_records,
      COUNT(CASE WHEN data_publicacao IS NULL THEN 1 END) as missing_dates,
      COUNT(CASE WHEN data_publicacao < '1900-01-01'::date THEN 1 END) as dates_before_1900,
      COUNT(CASE WHEN data_publicacao > CURRENT_DATE THEN 1 END) as future_dates,
      MIN(data_publicacao) as earliest_date,
      MAX(data_publicacao) as latest_date
    FROM documents
  ")
  
  results$date_validity <- date_check
  cat(sprintf("Missing dates: %d (%.2f%%)\n", 
    date_check$missing_dates,
    date_check$missing_dates/date_check$total_records*100))
  cat(sprintf("Dates before 1900: %d\n", date_check$dates_before_1900))
  cat(sprintf("Future dates: %d\n", date_check$future_dates))
  cat(sprintf("Date range: %s to %s\n", date_check$earliest_date, date_check$latest_date))
  
  # Check authority-jurisdiction consistency
  cat("\n3. Checking authority-jurisdiction consistency...\n")
  authority_check <- dbGetQuery(conn, "
    SELECT 
      authority_level,
      COUNT(*) as count,
      COUNT(CASE WHEN 
        (authority_level = 'federal' AND estado != 'BR') OR
        (authority_level = 'estadual' AND estado = 'BR') OR
        (authority_level = 'municipal' AND (estado = 'BR' OR municipality = ''))
      THEN 1 END) as inconsistent
    FROM documents
    GROUP BY authority_level
    ORDER BY count DESC
  ")
  
  results$authority_consistency <- authority_check
  print(kable(authority_check, caption = "Authority-Jurisdiction Consistency"))
  
  return(results)
}

# 1.2 Completeness Checks
check_data_completeness <- function(conn) {
  cat("\n=== DATA COMPLETENESS ASSESSMENT ===\n")
  
  results <- list()
  
  # Field completeness matrix
  cat("\n1. Field completeness analysis...\n")
  field_completeness <- dbGetQuery(conn, "
    SELECT 
      COUNT(*) as total_records,
      COUNT(CASE WHEN titulo IS NOT NULL AND titulo != '' THEN 1 END) as has_titulo,
      COUNT(CASE WHEN tipo IS NOT NULL AND tipo != '' THEN 1 END) as has_tipo,
      COUNT(CASE WHEN data_publicacao IS NOT NULL THEN 1 END) as has_date,
      COUNT(CASE WHEN urn IS NOT NULL AND urn != '' THEN 1 END) as has_urn,
      COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) as has_url,
      COUNT(CASE WHEN conteudo IS NOT NULL AND conteudo != '' THEN 1 END) as has_content,
      COUNT(CASE WHEN authority IS NOT NULL AND authority != '' THEN 1 END) as has_authority,
      COUNT(CASE WHEN authority_level IS NOT NULL AND authority_level != '' THEN 1 END) as has_authority_level
    FROM documents
  ")
  
  # Convert to percentages
  completeness_pct <- field_completeness %>%
    mutate(across(-total_records, ~ round(. / total_records * 100, 2)))
  
  results$field_completeness <- completeness_pct
  
  # Temporal coverage
  cat("\n2. Temporal coverage analysis...\n")
  temporal_coverage <- dbGetQuery(conn, "
    SELECT 
      EXTRACT(YEAR FROM data_publicacao) as year,
      COUNT(*) as document_count,
      COUNT(DISTINCT tipo) as unique_types,
      COUNT(DISTINCT authority_level) as unique_levels
    FROM documents
    WHERE data_publicacao IS NOT NULL
    GROUP BY year
    ORDER BY year
  ")
  
  results$temporal_coverage <- temporal_coverage
  
  # Missing years detection
  if (nrow(temporal_coverage) > 0) {
    all_years <- seq(min(temporal_coverage$year, na.rm = TRUE), 
                     max(temporal_coverage$year, na.rm = TRUE))
    missing_years <- setdiff(all_years, temporal_coverage$year)
    
    if (length(missing_years) > 0) {
      cat(sprintf("Missing years in dataset: %s\n", paste(missing_years, collapse = ", ")))
    } else {
      cat("No missing years in temporal coverage\n")
    }
  }
  
  # Coverage by jurisdiction and type
  cat("\n3. Coverage by jurisdiction and document type...\n")
  coverage_matrix <- dbGetQuery(conn, "
    SELECT 
      authority_level,
      tipo,
      COUNT(*) as count
    FROM documents
    WHERE authority_level IS NOT NULL AND tipo IS NOT NULL
    GROUP BY authority_level, tipo
    ORDER BY authority_level, count DESC
  ")
  
  results$coverage_matrix <- coverage_matrix
  
  # Create coverage heatmap data
  coverage_pivot <- coverage_matrix %>%
    pivot_wider(names_from = tipo, values_from = count, values_fill = 0)
  
  results$coverage_pivot <- coverage_pivot
  
  return(results)
}

# 1.3 Join Integrity Checks
check_join_integrity <- function(conn) {
  cat("\n=== JOIN INTEGRITY ASSESSMENT ===\n")
  
  results <- list()
  
  # Check if we have separate metadata and full text tables
  tables <- dbGetQuery(conn, "
    SELECT table_name 
    FROM information_schema.tables 
    WHERE table_schema = 'public' 
    AND table_name LIKE 'lexml%'
  ")
  
  cat("Available tables:\n")
  print(tables$table_name)
  
  # Check for orphan records (metadata without text)
  if ("lexml_metadata" %in% tables$table_name && "lexml_fulltext" %in% tables$table_name) {
    orphan_check <- dbGetQuery(conn, "
      SELECT 
        (SELECT COUNT(*) FROM lexml_metadata) as metadata_count,
        (SELECT COUNT(*) FROM lexml_fulltext) as fulltext_count,
        (SELECT COUNT(*) 
         FROM lexml_metadata m 
         LEFT JOIN lexml_fulltext f ON m.urn = f.urn 
         WHERE f.urn IS NULL) as orphan_metadata,
        (SELECT COUNT(*) 
         FROM lexml_fulltext f 
         LEFT JOIN lexml_metadata m ON f.urn = m.urn 
         WHERE m.urn IS NULL) as orphan_fulltext
    ")
    
    results$orphan_records <- orphan_check
    print(kable(orphan_check, caption = "Join Integrity Check"))
  }
  
  # Check URN uniqueness
  cat("\n4. Checking URN uniqueness...\n")
  urn_duplicates <- dbGetQuery(conn, "
    SELECT 
      urn,
      COUNT(*) as duplicate_count
    FROM documents
    WHERE urn IS NOT NULL AND urn != ''
    GROUP BY urn
    HAVING COUNT(*) > 1
    ORDER BY duplicate_count DESC
    LIMIT 10
  ")
  
  results$urn_duplicates <- urn_duplicates
  
  if (nrow(urn_duplicates) > 0) {
    cat(sprintf("Found %d URNs with duplicates\n", nrow(urn_duplicates)))
    print(kable(head(urn_duplicates, 5), caption = "Top 5 Duplicate URNs"))
  } else {
    cat("No duplicate URNs found\n")
  }
  
  return(results)
}

# 2. CREATE VISUAL QUALITY REPORT
create_quality_visualizations <- function(results) {
  cat("\n=== CREATING QUALITY VISUALIZATIONS ===\n")
  
  plots <- list()
  
  # 1. Field Completeness Heatmap
  if (!is.null(results$completeness$field_completeness)) {
    completeness_data <- results$completeness$field_completeness %>%
      select(-total_records) %>%
      pivot_longer(everything(), names_to = "field", values_to = "completeness_pct") %>%
      mutate(field = str_replace(field, "has_", ""))
    
    p1 <- ggplot(completeness_data, aes(x = field, y = 1, fill = completeness_pct)) +
      geom_tile() +
      geom_text(aes(label = paste0(completeness_pct, "%")), color = "white") +
      scale_fill_gradient2(low = "red", mid = "yellow", high = "green", midpoint = 50) +
      theme_minimal() +
      theme(axis.text.x = element_text(angle = 45, hjust = 1)) +
      labs(title = "Field Completeness Heatmap",
           x = "Field", y = "", fill = "Completeness %")
    
    plots$field_completeness <- p1
  }
  
  # 2. Temporal Coverage
  if (!is.null(results$completeness$temporal_coverage)) {
    p2 <- ggplot(results$completeness$temporal_coverage, 
                 aes(x = year, y = document_count)) +
      geom_bar(stat = "identity", fill = "steelblue") +
      theme_minimal() +
      labs(title = "Document Distribution by Year",
           x = "Year", y = "Document Count")
    
    plots$temporal_coverage <- p2
  }
  
  # 3. Authority Level Distribution
  if (!is.null(results$correctness$authority_consistency)) {
    p3 <- ggplot(results$correctness$authority_consistency, 
                 aes(x = authority_level, y = count, fill = authority_level)) +
      geom_bar(stat = "identity") +
      geom_text(aes(label = count), vjust = -0.5) +
      theme_minimal() +
      labs(title = "Document Distribution by Authority Level",
           x = "Authority Level", y = "Count")
    
    plots$authority_distribution <- p3
  }
  
  return(plots)
}

# 3. GENERATE SUMMARY REPORT
generate_quality_report <- function(results) {
  cat("\n=== GENERATING QUALITY REPORT ===\n")
  
  report <- list()
  
  # Executive Summary
  report$summary <- data.frame(
    Metric = c("Total Documents", "Valid URNs %", "Complete Records %", 
               "Date Coverage", "Duplicate URNs"),
    Value = c(
      results$correctness$urn_compliance$total_records,
      round(results$correctness$urn_compliance$valid_urns / 
            results$correctness$urn_compliance$total_records * 100, 2),
      round(mean(as.numeric(results$completeness$field_completeness[-1])), 2),
      paste(results$correctness$date_validity$earliest_date, "to", 
            results$correctness$date_validity$latest_date),
      nrow(results$joins$urn_duplicates)
    )
  )
  
  # Critical Issues
  issues <- c()
  
  if (results$correctness$urn_compliance$missing_urns > 0) {
    issues <- c(issues, sprintf("%d records with missing URNs", 
                               results$correctness$urn_compliance$missing_urns))
  }
  
  if (results$correctness$date_validity$missing_dates > 0) {
    issues <- c(issues, sprintf("%d records with missing dates", 
                               results$correctness$date_validity$missing_dates))
  }
  
  if (nrow(results$joins$urn_duplicates) > 0) {
    issues <- c(issues, sprintf("%d duplicate URNs found", 
                               nrow(results$joins$urn_duplicates)))
  }
  
  report$critical_issues <- issues
  
  return(report)
}

# MAIN EXECUTION
main <- function() {
  cat("Starting Data Quality Assessment for MackMonitor v4\n")
  cat("=================================================\n")
  
  # Connect to database
  conn <- connect_to_database()
  on.exit(dbDisconnect(conn))
  
  # Run assessments
  results <- list()
  results$correctness <- check_data_correctness(conn)
  results$completeness <- check_data_completeness(conn)
  results$joins <- check_join_integrity(conn)
  
  # Generate visualizations
  plots <- create_quality_visualizations(results)
  
  # Generate report
  report <- generate_quality_report(results)
  
  # Save results
  cat("\n=== SAVING RESULTS ===\n")
  
  # Create output directory
  dir.create("data_quality_results", showWarnings = FALSE)
  
  # Save data
  saveRDS(results, "data_quality_results/assessment_results.rds")
  saveRDS(plots, "data_quality_results/quality_plots.rds")
  saveRDS(report, "data_quality_results/quality_report.rds")
  
  # Export summary tables
  write.csv(report$summary, "data_quality_results/quality_summary.csv", row.names = FALSE)
  write.csv(results$completeness$temporal_coverage, 
            "data_quality_results/temporal_coverage.csv", row.names = FALSE)
  write.csv(results$completeness$coverage_pivot, 
            "data_quality_results/coverage_matrix.csv", row.names = FALSE)
  
  # Save plots
  for (plot_name in names(plots)) {
    ggsave(sprintf("data_quality_results/%s.png", plot_name), 
           plots[[plot_name]], width = 10, height = 6)
  }
  
  cat("\nData quality assessment complete!\n")
  cat("Results saved to data_quality_results/\n")
  
  # Print summary
  cat("\n=== EXECUTIVE SUMMARY ===\n")
  print(kable(report$summary))
  
  if (length(report$critical_issues) > 0) {
    cat("\nCritical Issues Found:\n")
    for (issue in report$critical_issues) {
      cat(paste0("- ", issue, "\n"))
    }
  }
  
  return(list(results = results, plots = plots, report = report))
}

# Run if executed directly
if (!interactive()) {
  main()
}