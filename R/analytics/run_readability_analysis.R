#!/usr/bin/env Rscript
#' Run Readability Analysis on Monitor Legislativo Database
#'
#' This script processes all documents in the database and calculates
#' readability metrics (Flesch-Kincaid, FOG, SMOG).
#'
#' Usage:
#'   Rscript run_readability_analysis.R
#'
#' Or from R console:
#'   source("R/analytics/run_readability_analysis.R")
#'
#' Prerequisites:
#'   - Database connection configured
#'   - readability_metrics.R sourced
#'   - Required packages installed
#'
#' @author Monitor Legislativo v4
#' @date 2025-11-12

# Load required libraries
suppressPackageStartupMessages({
  library(RPostgreSQL)
  library(dplyr)
  library(stringr)
})

# Source the readability metrics module
script_dir <- dirname(sys.frame(1)$ofile)
if (length(script_dir) == 0 || script_dir == ".") {
  # Running from console or Rscript
  script_dir <- getwd()
}

source(file.path(script_dir, "readability_metrics.R"))

# ==============================================================================
# CONFIGURATION
# ==============================================================================

# Database configuration (use environment variables for security)
DB_CONFIG <- list(
  host = Sys.getenv("DB_HOST", "localhost"),
  port = as.integer(Sys.getenv("DB_PORT", "5432")),
  dbname = Sys.getenv("DB_NAME", "monitor_legislativo"),
  user = Sys.getenv("DB_USER"),
  password = Sys.getenv("DB_PASSWORD")
)

# Processing configuration
BATCH_SIZE <- as.integer(Sys.getenv("BATCH_SIZE", "1000"))
OUTPUT_TABLE <- "readability_metrics"
OUTPUT_CSV <- "readability_results.csv"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

#' Connect to Database
#'
#' Establishes connection to PostgreSQL database using configuration.
#'
#' @return Database connection object
connect_db <- function() {
  cat("Connecting to database...\n")
  cat(sprintf("  Host: %s\n", DB_CONFIG$host))
  cat(sprintf("  Database: %s\n", DB_CONFIG$dbname))
  cat(sprintf("  Port: %d\n", DB_CONFIG$port))

  tryCatch({
    con <- dbConnect(
      PostgreSQL(),
      host = DB_CONFIG$host,
      port = DB_CONFIG$port,
      dbname = DB_CONFIG$dbname,
      user = DB_CONFIG$user,
      password = DB_CONFIG$password
    )
    cat("✓ Connected successfully\n\n")
    return(con)
  }, error = function(e) {
    cat("✗ Connection failed:", e$message, "\n")
    cat("\nPlease ensure:\n")
    cat("  1. Database is running\n")
    cat("  2. Environment variables are set:\n")
    cat("     - DB_HOST\n")
    cat("     - DB_PORT\n")
    cat("     - DB_NAME\n")
    cat("     - DB_USER\n")
    cat("     - DB_PASSWORD\n")
    stop("Database connection failed")
  })
}

#' Create Readability Metrics Table
#'
#' Creates the readability_metrics table if it doesn't exist.
#'
#' @param con Database connection
create_metrics_table <- function(con) {
  cat("Checking/creating readability_metrics table...\n")

  # Check if table exists
  table_exists <- dbExistsTable(con, OUTPUT_TABLE)

  if (table_exists) {
    cat("  Table already exists\n")

    # Ask user if they want to recreate
    cat("  Do you want to drop and recreate the table? (y/n): ")
    response <- readline()

    if (tolower(response) == "y") {
      dbExecute(con, sprintf("DROP TABLE %s CASCADE", OUTPUT_TABLE))
      cat("  ✓ Dropped existing table\n")
      table_exists <- FALSE
    } else {
      cat("  Keeping existing table (will append/update data)\n")
      return(invisible(NULL))
    }
  }

  if (!table_exists) {
    # Create table
    create_sql <- sprintf("
      CREATE TABLE %s (
        id INTEGER PRIMARY KEY,
        flesch_kincaid NUMERIC(5,2),
        fog_index NUMERIC(5,2),
        smog_index NUMERIC(5,2),
        word_count INTEGER,
        sentence_count INTEGER,
        calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id) REFERENCES documents(id) ON DELETE CASCADE
      )
    ", OUTPUT_TABLE)

    dbExecute(con, create_sql)
    cat("  ✓ Table created\n")

    # Create indexes
    cat("  Creating indexes...\n")
    dbExecute(con, sprintf("CREATE INDEX idx_%s_flesch ON %s(flesch_kincaid)",
                          OUTPUT_TABLE, OUTPUT_TABLE))
    dbExecute(con, sprintf("CREATE INDEX idx_%s_fog ON %s(fog_index)",
                          OUTPUT_TABLE, OUTPUT_TABLE))
    dbExecute(con, sprintf("CREATE INDEX idx_%s_smog ON %s(smog_index)",
                          OUTPUT_TABLE, OUTPUT_TABLE))
    cat("  ✓ Indexes created\n\n")
  }
}

#' Save Results to Database
#'
#' Saves calculated metrics to the database.
#'
#' @param con Database connection
#' @param results Data frame with calculated metrics
save_to_database <- function(con, results) {
  cat("\nSaving results to database...\n")

  # Write to table
  dbWriteTable(con, OUTPUT_TABLE, results,
               overwrite = FALSE, append = TRUE, row.names = FALSE)

  cat(sprintf("✓ Saved %s records to %s table\n",
              format(nrow(results), big.mark = ","),
              OUTPUT_TABLE))
}

#' Save Results to CSV
#'
#' Exports calculated metrics to CSV file.
#'
#' @param results Data frame with calculated metrics
#' @param filename Output CSV filename
save_to_csv <- function(results, filename = OUTPUT_CSV) {
  cat("\nSaving results to CSV...\n")

  write.csv(results, filename, row.names = FALSE, fileEncoding = "UTF-8")

  cat(sprintf("✓ Saved to %s\n", filename))
  cat(sprintf("  File size: %.2f MB\n",
              file.info(filename)$size / 1024 / 1024))
}

#' Generate Summary Report
#'
#' Prints summary statistics of calculated metrics.
#'
#' @param results Data frame with calculated metrics
generate_summary <- function(results) {
  cat("\n" , rep("=", 70), "\n", sep = "")
  cat("SUMMARY STATISTICS\n")
  cat(rep("=", 70), "\n\n", sep = "")

  # Overall statistics
  cat(sprintf("Total documents analyzed: %s\n",
              format(nrow(results), big.mark = ",")))
  cat(sprintf("Documents with errors (NA): %d (%.1f%%)\n",
              sum(is.na(results$flesch_kincaid)),
              100 * sum(is.na(results$flesch_kincaid)) / nrow(results)))

  # Valid documents only
  valid_results <- results[!is.na(results$flesch_kincaid), ]

  cat(sprintf("\nValid documents: %s\n",
              format(nrow(valid_results), big.mark = ",")))

  # Flesch-Kincaid
  cat("\n--- Flesch-Kincaid Reading Ease (0-100, higher = easier) ---\n")
  cat(sprintf("  Mean:   %.2f\n", mean(valid_results$flesch_kincaid)))
  cat(sprintf("  Median: %.2f\n", median(valid_results$flesch_kincaid)))
  cat(sprintf("  SD:     %.2f\n", sd(valid_results$flesch_kincaid)))
  cat(sprintf("  Min:    %.2f\n", min(valid_results$flesch_kincaid)))
  cat(sprintf("  Max:    %.2f\n", max(valid_results$flesch_kincaid)))

  # Distribution
  flesch_breaks <- c(0, 30, 50, 60, 70, 80, 100)
  flesch_labels <- c("Muito difícil (0-30)", "Difícil (30-50)",
                     "Razoavelmente difícil (50-60)", "Padrão (60-70)",
                     "Fácil (70-80)", "Muito fácil (80-100)")
  flesch_dist <- cut(valid_results$flesch_kincaid, breaks = flesch_breaks,
                     labels = flesch_labels, include.lowest = TRUE)
  cat("\n  Distribution:\n")
  for (level in flesch_labels) {
    count <- sum(flesch_dist == level, na.rm = TRUE)
    pct <- 100 * count / nrow(valid_results)
    cat(sprintf("    %s: %s (%.1f%%)\n", level,
                format(count, big.mark = ","), pct))
  }

  # FOG Index
  cat("\n--- Gunning FOG Index (grade level) ---\n")
  cat(sprintf("  Mean:   %.2f\n", mean(valid_results$fog_index)))
  cat(sprintf("  Median: %.2f\n", median(valid_results$fog_index)))
  cat(sprintf("  SD:     %.2f\n", sd(valid_results$fog_index)))
  cat(sprintf("  Min:    %.2f\n", min(valid_results$fog_index)))
  cat(sprintf("  Max:    %.2f\n", max(valid_results$fog_index)))

  # SMOG Index
  cat("\n--- SMOG Index (grade level) ---\n")
  cat(sprintf("  Mean:   %.2f\n", mean(valid_results$smog_index)))
  cat(sprintf("  Median: %.2f\n", median(valid_results$smog_index)))
  cat(sprintf("  SD:     %.2f\n", sd(valid_results$smog_index)))
  cat(sprintf("  Min:    %.2f\n", min(valid_results$smog_index)))
  cat(sprintf("  Max:    %.2f\n", max(valid_results$smog_index)))

  # Document length statistics
  cat("\n--- Document Length Statistics ---\n")
  cat(sprintf("  Mean word count:     %.0f\n", mean(valid_results$word_count)))
  cat(sprintf("  Median word count:   %.0f\n", median(valid_results$word_count)))
  cat(sprintf("  Mean sentence count: %.0f\n", mean(valid_results$sentence_count)))
  cat(sprintf("  Median sentence count: %.0f\n", median(valid_results$sentence_count)))

  cat("\n", rep("=", 70), "\n\n", sep = "")
}

#' Top and Bottom Documents
#'
#' Shows most and least readable documents.
#'
#' @param con Database connection
#' @param results Data frame with calculated metrics
#' @param n Number of documents to show
show_extremes <- function(con, results, n = 5) {
  cat("\n--- Most Readable Documents (Highest Flesch) ---\n")

  top_ids <- results %>%
    filter(!is.na(flesch_kincaid)) %>%
    arrange(desc(flesch_kincaid)) %>%
    head(n) %>%
    pull(id)

  if (length(top_ids) > 0) {
    top_docs <- dbGetQuery(con, sprintf(
      "SELECT d.id, d.titulo, rm.flesch_kincaid, rm.fog_index
       FROM documents d
       JOIN %s rm ON d.id = rm.id
       WHERE d.id IN (%s)
       ORDER BY rm.flesch_kincaid DESC",
      OUTPUT_TABLE,
      paste(top_ids, collapse = ",")
    ))

    for (i in 1:nrow(top_docs)) {
      cat(sprintf("\n%d. [ID: %d] Flesch: %.2f, FOG: %.2f\n   %s\n",
                  i, top_docs$id[i], top_docs$flesch_kincaid[i],
                  top_docs$fog_index[i],
                  substr(top_docs$titulo[i], 1, 80)))
    }
  }

  cat("\n--- Least Readable Documents (Lowest Flesch) ---\n")

  bottom_ids <- results %>%
    filter(!is.na(flesch_kincaid)) %>%
    arrange(flesch_kincaid) %>%
    head(n) %>%
    pull(id)

  if (length(bottom_ids) > 0) {
    bottom_docs <- dbGetQuery(con, sprintf(
      "SELECT d.id, d.titulo, rm.flesch_kincaid, rm.fog_index
       FROM documents d
       JOIN %s rm ON d.id = rm.id
       WHERE d.id IN (%s)
       ORDER BY rm.flesch_kincaid ASC",
      OUTPUT_TABLE,
      paste(bottom_ids, collapse = ",")
    ))

    for (i in 1:nrow(bottom_docs)) {
      cat(sprintf("\n%d. [ID: %d] Flesch: %.2f, FOG: %.2f\n   %s\n",
                  i, bottom_docs$id[i], bottom_docs$flesch_kincaid[i],
                  bottom_docs$fog_index[i],
                  substr(bottom_docs$titulo[i], 1, 80)))
    }
  }

  cat("\n")
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

main <- function() {
  cat("\n")
  cat(rep("=", 70), "\n", sep = "")
  cat("MONITOR LEGISLATIVO v4 - READABILITY ANALYSIS\n")
  cat(rep("=", 70), "\n\n", sep = "")

  # Connect to database
  con <- connect_db()

  # Ensure cleanup on exit
  on.exit({
    if (exists("con") && dbIsValid(con)) {
      dbDisconnect(con)
      cat("\n✓ Database connection closed\n")
    }
  })

  # Create/check table
  create_metrics_table(con)

  # Check if documents table exists and has data
  doc_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents")$count

  if (doc_count == 0) {
    cat("✗ No documents found in database\n")
    cat("  Please ensure the documents table is populated\n")
    return(invisible(NULL))
  }

  cat(sprintf("Found %s documents to process\n\n",
              format(doc_count, big.mark = ",")))

  # Ask for confirmation if many documents
  if (doc_count > 10000) {
    cat(sprintf("This will process %s documents.\n", format(doc_count, big.mark = ",")))
    cat(sprintf("Estimated time: %.0f-%.0f minutes\n",
                (doc_count / 100) / 60, (doc_count / 50) / 60))
    cat("\nProceed? (y/n): ")
    response <- readline()

    if (tolower(response) != "y") {
      cat("Cancelled by user\n")
      return(invisible(NULL))
    }
  }

  # Run batch processing
  cat("\nStarting batch processing...\n")
  cat(rep("-", 70), "\n", sep = "")

  results <- batch_calculate_readability(
    con,
    table_name = "documents",
    text_column = "texto_completo",
    batch_size = BATCH_SIZE,
    verbose = TRUE
  )

  # Save results
  save_to_database(con, results)
  save_to_csv(results)

  # Generate reports
  generate_summary(results)
  show_extremes(con, results, n = 5)

  # Final message
  cat("\n", rep("=", 70), "\n", sep = "")
  cat("ANALYSIS COMPLETE\n")
  cat(rep("=", 70), "\n\n", sep = "")

  cat("Next steps:\n")
  cat("  1. Review results in CSV file:", OUTPUT_CSV, "\n")
  cat("  2. Query database table:", OUTPUT_TABLE, "\n")
  cat("  3. Integrate metrics into Shiny app\n")
  cat("  4. Create visualizations and reports\n\n")

  return(invisible(results))
}

# Run main function if script is executed directly
if (!interactive()) {
  main()
}
