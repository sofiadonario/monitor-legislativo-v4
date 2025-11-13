#' Batch LSH Indexing Script
#'
#' Process all 118k+ legislative documents to create LSH signatures and indexes
#' for efficient text reuse detection.
#'
#' @author Monitor Legislativo Analytics Team
#' @date 2025-01-13

# ============================================================================
# SETUP
# ============================================================================

library(DBI)
library(RPostgreSQL)
library(yaml)

# Source the LSH implementation
source("R/analytics/text_reuse_lsh.R")

# Load database configuration
config <- yaml::read_yaml("config/database.yml")
db_config <- config$production  # or config$development for testing

# ============================================================================
# DATABASE CONNECTION
# ============================================================================

connect_to_db <- function(db_config) {
  tryCatch({
    con <- dbConnect(
      PostgreSQL(),
      host = db_config$host,
      port = db_config$port,
      dbname = db_config$database,
      user = db_config$username,
      password = db_config$password
    )
    cat("Database connection established successfully.\n")
    return(con)
  }, error = function(e) {
    stop(paste("Failed to connect to database:", e$message))
  })
}

# ============================================================================
# PRE-INDEXING CHECKS
# ============================================================================

check_prerequisites <- function(con) {
  cat("\n=== Pre-Indexing Checks ===\n")

  # Check if tables exist
  tables <- dbGetQuery(con,
    "SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public'
     AND table_name IN ('text_reuse_signatures', 'lsh_buckets', 'text_reuse_pairs')"
  )

  required_tables <- c("text_reuse_signatures", "lsh_buckets", "text_reuse_pairs")
  missing_tables <- setdiff(required_tables, tables$table_name)

  if (length(missing_tables) > 0) {
    stop(paste("Missing required tables:", paste(missing_tables, collapse = ", "),
               "\nPlease run database/migrations/012_add_text_reuse_tables.sql first."))
  }

  cat("✓ All required tables exist\n")

  # Check document count
  doc_count <- dbGetQuery(con,
    "SELECT COUNT(*) as n FROM documents WHERE texto_completo IS NOT NULL AND texto_completo != ''"
  )$n

  cat(sprintf("✓ Found %s documents with text content\n", format(doc_count, big.mark = ",")))

  # Check existing signatures
  sig_count <- dbGetQuery(con, "SELECT COUNT(*) as n FROM text_reuse_signatures")$n

  if (sig_count > 0) {
    cat(sprintf("⚠ Warning: %s signatures already exist\n", format(sig_count, big.mark = ",")))
    cat("  These will be replaced during indexing.\n")

    response <- readline(prompt = "Continue? (yes/no): ")
    if (tolower(response) != "yes") {
      stop("Indexing cancelled by user")
    }
  }

  # Estimate disk space needed
  avg_doc_size <- dbGetQuery(con,
    "SELECT AVG(length(texto_completo)) as avg_size
     FROM documents
     WHERE texto_completo IS NOT NULL
     LIMIT 1000"
  )$avg_size

  estimated_sig_size_mb <- (doc_count * 800) / 1024 / 1024  # ~800 bytes per signature
  estimated_bucket_size_mb <- (doc_count * 20 * 50) / 1024 / 1024  # 20 bands, ~50 bytes per entry

  cat(sprintf("✓ Estimated storage: %.1f MB (signatures) + %.1f MB (buckets) = %.1f MB total\n",
              estimated_sig_size_mb, estimated_bucket_size_mb,
              estimated_sig_size_mb + estimated_bucket_size_mb))

  return(list(
    doc_count = doc_count,
    existing_signatures = sig_count,
    estimated_size_mb = estimated_sig_size_mb + estimated_bucket_size_mb
  ))
}

# ============================================================================
# MAIN INDEXING FUNCTION
# ============================================================================

run_batch_indexing <- function(
  con,
  batch_size = 1000,
  bands = 20,
  rows_per_band = 5,
  num_hashes = 100,
  k = 5,
  max_docs = NULL,
  resume = TRUE
) {

  cat("\n=== Starting Batch LSH Indexing ===\n")
  cat(sprintf("Timestamp: %s\n", Sys.time()))
  cat(sprintf("Parameters:\n"))
  cat(sprintf("  - Batch size: %d documents\n", batch_size))
  cat(sprintf("  - LSH bands: %d\n", bands))
  cat(sprintf("  - Rows per band: %d\n", rows_per_band))
  cat(sprintf("  - Hash functions: %d\n", num_hashes))
  cat(sprintf("  - Shingle size: %d\n", k))
  if (!is.null(max_docs)) {
    cat(sprintf("  - Max documents: %d (TESTING MODE)\n", max_docs))
  }
  cat("\n")

  # Check if resuming
  if (resume) {
    existing_count <- dbGetQuery(con, "SELECT COUNT(*) as n FROM text_reuse_signatures")$n
    if (existing_count > 0) {
      cat(sprintf("Resume mode: %d documents already indexed\n", existing_count))
      cat("Note: Current implementation will re-index all documents.\n")
      cat("For true resume capability, modify lsh_index_documents to skip existing signatures.\n\n")
    }
  }

  # Run indexing
  start_time <- Sys.time()

  tryCatch({
    stats <- lsh_index_documents(
      db_connection = con,
      batch_size = batch_size,
      bands = bands,
      rows_per_band = rows_per_band,
      k = k,
      num_hashes = num_hashes,
      max_docs = max_docs
    )

    end_time <- Sys.time()

    # Print summary
    cat("\n=== Indexing Complete ===\n")
    cat(sprintf("Total time: %.1f minutes\n", stats$elapsed_minutes))
    cat(sprintf("Documents processed: %s\n", format(stats$documents_processed, big.mark = ",")))
    cat(sprintf("Documents skipped: %s\n", format(stats$documents_skipped, big.mark = ",")))
    cat(sprintf("Processing rate: %.1f docs/second\n", stats$docs_per_second))
    cat(sprintf("Timestamp: %s\n", end_time))

    # Get database statistics
    cat("\n=== Database Statistics ===\n")
    db_stats <- lsh_index_stats(con)
    cat(sprintf("Total indexed documents: %s\n", format(db_stats$total_indexed, big.mark = ",")))
    cat(sprintf("Total LSH buckets: %s\n", format(db_stats$total_buckets, big.mark = ",")))
    cat(sprintf("Avg documents per bucket: %.1f\n", db_stats$avg_docs_per_bucket))
    cat("\nDatabase sizes:\n")
    print(db_stats$db_size_mb)

    # Save stats to file
    stats_file <- sprintf("logs/lsh_indexing_%s.rds", format(Sys.time(), "%Y%m%d_%H%M%S"))
    dir.create("logs", showWarnings = FALSE, recursive = TRUE)
    saveRDS(list(stats = stats, db_stats = db_stats), stats_file)
    cat(sprintf("\nStatistics saved to: %s\n", stats_file))

    return(stats)

  }, error = function(e) {
    cat("\n!!! INDEXING FAILED !!!\n")
    cat(sprintf("Error: %s\n", e$message))
    cat("Please check the error and try again.\n")
    return(NULL)
  })
}

# ============================================================================
# POST-INDEXING ANALYSIS
# ============================================================================

run_similarity_detection <- function(con, threshold = 0.7, sample_size = NULL) {

  cat("\n=== Detecting Similar Document Pairs ===\n")
  cat(sprintf("Similarity threshold: %.2f\n", threshold))

  start_time <- Sys.time()

  pairs <- detect_all_similar_pairs(
    db_connection = con,
    threshold = threshold,
    store_results = TRUE
  )

  elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))

  cat(sprintf("\n=== Similarity Detection Complete ===\n"))
  cat(sprintf("Time: %.1f minutes\n", elapsed))
  cat(sprintf("Pairs found: %s\n", format(nrow(pairs), big.mark = ",")))

  if (nrow(pairs) > 0) {
    cat(sprintf("Average similarity: %.3f\n", mean(pairs$jaccard_similarity)))
    cat(sprintf("Median similarity: %.3f\n", median(pairs$jaccard_similarity)))
    cat(sprintf("Max similarity: %.3f\n", max(pairs$jaccard_similarity)))
  }

  # Detect clusters
  cat("\n=== Detecting Clusters ===\n")
  clusters <- detect_text_reuse_clusters(con, min_cluster_size = 3, threshold = threshold)

  if (length(clusters) > 0) {
    cat(sprintf("Clusters found: %d\n", length(clusters)))
    cat(sprintf("Largest cluster: %d documents\n", max(sapply(clusters, function(x) x$size))))
    cat(sprintf("Average cluster size: %.1f documents\n", mean(sapply(clusters, function(x) x$size))))
  }

  return(list(pairs = pairs, clusters = clusters))
}

# ============================================================================
# PERFORMANCE BENCHMARKING
# ============================================================================

run_performance_benchmark <- function(con, n_queries = 100) {

  cat("\n=== Performance Benchmark ===\n")

  # Get random sample of document IDs
  sample_ids <- dbGetQuery(con,
    sprintf("SELECT id FROM text_reuse_signatures ORDER BY RANDOM() LIMIT %d", n_queries)
  )$id

  query_times <- numeric(n_queries)

  cat(sprintf("Running %d similarity queries...\n", n_queries))
  pb <- txtProgressBar(min = 0, max = n_queries, style = 3)

  for (i in 1:n_queries) {
    start <- Sys.time()
    results <- find_similar_documents(con, sample_ids[i], threshold = 0.7)
    query_times[i] <- as.numeric(difftime(Sys.time(), start, units = "secs")) * 1000  # ms
    setTxtProgressBar(pb, i)
  }
  close(pb)

  cat("\n\nQuery Performance:\n")
  cat(sprintf("  Mean: %.1f ms\n", mean(query_times)))
  cat(sprintf("  Median: %.1f ms\n", median(query_times)))
  cat(sprintf("  95th percentile: %.1f ms\n", quantile(query_times, 0.95)))
  cat(sprintf("  Max: %.1f ms\n", max(query_times)))

  if (median(query_times) > 500) {
    cat("\n⚠ Warning: Queries are slower than target (<500ms)\n")
    cat("Consider:\n")
    cat("  - Adding more indexes\n")
    cat("  - Increasing database resources\n")
    cat("  - Reducing number of bands\n")
  } else {
    cat("\n✓ Query performance meets target (<500ms median)\n")
  }

  return(query_times)
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main <- function(
  mode = "full",  # "test", "full", "detect", "benchmark"
  batch_size = 1000,
  threshold = 0.7
) {

  cat("╔═══════════════════════════════════════════════════════╗\n")
  cat("║   Monitor Legislativo - LSH Batch Indexing System    ║\n")
  cat("║             Text Reuse Detection                      ║\n")
  cat("╚═══════════════════════════════════════════════════════╝\n\n")

  # Connect to database
  con <- connect_to_db(db_config)
  on.exit(dbDisconnect(con))

  # Run pre-checks
  check_results <- check_prerequisites(con)

  if (mode == "test") {
    cat("\n>>> TEST MODE: Processing first 1000 documents <<<\n")
    stats <- run_batch_indexing(con, batch_size = batch_size, max_docs = 1000)

    if (!is.null(stats)) {
      cat("\n>>> Running test similarity detection <<<\n")
      detection_results <- run_similarity_detection(con, threshold = threshold)
    }

  } else if (mode == "full") {
    cat("\n>>> FULL MODE: Processing all documents <<<\n")

    stats <- run_batch_indexing(con, batch_size = batch_size)

    if (!is.null(stats)) {
      cat("\n>>> Running similarity detection <<<\n")
      detection_results <- run_similarity_detection(con, threshold = threshold)

      cat("\n>>> Running performance benchmark <<<\n")
      benchmark_results <- run_performance_benchmark(con, n_queries = 100)
    }

  } else if (mode == "detect") {
    cat("\n>>> DETECTION MODE: Finding similar pairs (assumes indexing complete) <<<\n")
    detection_results <- run_similarity_detection(con, threshold = threshold)

  } else if (mode == "benchmark") {
    cat("\n>>> BENCHMARK MODE: Testing query performance <<<\n")
    benchmark_results <- run_performance_benchmark(con, n_queries = 100)

  } else {
    stop(sprintf("Unknown mode: %s. Use 'test', 'full', 'detect', or 'benchmark'", mode))
  }

  cat("\n")
  cat("╔═══════════════════════════════════════════════════════╗\n")
  cat("║                  Processing Complete                  ║\n")
  cat("╚═══════════════════════════════════════════════════════╝\n\n")

  return(invisible(NULL))
}

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

if (!interactive()) {
  # Parse command line arguments
  args <- commandArgs(trailingOnly = TRUE)

  if (length(args) == 0) {
    cat("Usage: Rscript batch_lsh_indexing.R [mode] [batch_size] [threshold]\n")
    cat("\nModes:\n")
    cat("  test      - Index first 1000 documents (for testing)\n")
    cat("  full      - Index all documents (default)\n")
    cat("  detect    - Detect similar pairs (assumes indexing done)\n")
    cat("  benchmark - Run performance benchmark\n")
    cat("\nExamples:\n")
    cat("  Rscript batch_lsh_indexing.R test\n")
    cat("  Rscript batch_lsh_indexing.R full 1000 0.7\n")
    cat("  Rscript batch_lsh_indexing.R detect 1000 0.8\n")
    quit(status = 1)
  }

  mode <- args[1]
  batch_size <- if (length(args) >= 2) as.integer(args[2]) else 1000
  threshold <- if (length(args) >= 3) as.numeric(args[3]) else 0.7

  main(mode = mode, batch_size = batch_size, threshold = threshold)
}

# Interactive usage examples:
# source("R/analytics/batch_lsh_indexing.R")
# main(mode = "test")  # Test with 1000 docs
# main(mode = "full")  # Full indexing
# main(mode = "detect", threshold = 0.75)  # Detect with different threshold
# main(mode = "benchmark")  # Benchmark queries
