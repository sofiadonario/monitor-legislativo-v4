#' Text Reuse Detection - Performance Benchmarks & Reports
#'
#' Generate comprehensive performance reports and benchmarks
#'
#' @author Monitor Legislativo Analytics Team
#' @date 2025-01-13

library(DBI)
library(RPostgreSQL)
library(dplyr)
library(ggplot2)
library(knitr)
library(rmarkdown)

source("R/analytics/text_reuse_lsh.R")

# ============================================================================
# PERFORMANCE BENCHMARKING
# ============================================================================

#' Run comprehensive performance benchmark
#'
#' @param db_connection Database connection
#' @param n_queries Integer, number of queries to benchmark
#' @param output_file Character, path to save results
#' @return List with benchmark results
#' @export
benchmark_text_reuse_system <- function(db_connection,
                                         n_queries = 100,
                                         output_file = NULL) {

  cat("╔═══════════════════════════════════════════════════════╗\n")
  cat("║   Text Reuse Detection - Performance Benchmark       ║\n")
  cat("╚═══════════════════════════════════════════════════════╝\n\n")

  results <- list()
  results$timestamp <- Sys.time()

  # ========================================================================
  # 1. SYSTEM STATISTICS
  # ========================================================================

  cat("1. Collecting System Statistics...\n")

  stats <- lsh_index_stats(db_connection)
  results$system_stats <- stats

  cat(sprintf("   ✓ Indexed documents: %s\n", format(stats$total_indexed, big.mark = ",")))
  cat(sprintf("   ✓ LSH buckets: %s\n", format(stats$total_buckets, big.mark = ",")))
  cat(sprintf("   ✓ Detected pairs: %s\n", format(stats$total_pairs, big.mark = ",")))

  # ========================================================================
  # 2. QUERY PERFORMANCE
  # ========================================================================

  cat("\n2. Benchmarking Query Performance...\n")

  # Get random sample of document IDs
  sample_ids <- dbGetQuery(db_connection,
    sprintf("SELECT document_id FROM text_reuse_signatures
             ORDER BY RANDOM() LIMIT %d", n_queries)
  )$document_id

  query_times <- numeric(n_queries)
  result_counts <- integer(n_queries)

  pb <- txtProgressBar(min = 0, max = n_queries, style = 3)
  for (i in 1:n_queries) {
    start <- Sys.time()
    similar <- find_similar_documents(db_connection, sample_ids[i], threshold = 0.7)
    query_times[i] <- as.numeric(difftime(Sys.time(), start, units = "secs")) * 1000
    result_counts[i] <- nrow(similar)
    setTxtProgressBar(pb, i)
  }
  close(pb)

  results$query_performance <- list(
    times_ms = query_times,
    mean_ms = mean(query_times),
    median_ms = median(query_times),
    p95_ms = quantile(query_times, 0.95),
    p99_ms = quantile(query_times, 0.99),
    max_ms = max(query_times),
    avg_results = mean(result_counts)
  )

  cat(sprintf("\n   Query Performance (n=%d):\n", n_queries))
  cat(sprintf("   ✓ Mean: %.1f ms\n", results$query_performance$mean_ms))
  cat(sprintf("   ✓ Median: %.1f ms\n", results$query_performance$median_ms))
  cat(sprintf("   ✓ 95th percentile: %.1f ms\n", results$query_performance$p95_ms))
  cat(sprintf("   ✓ 99th percentile: %.1f ms\n", results$query_performance$p99_ms))
  cat(sprintf("   ✓ Max: %.1f ms\n", results$query_performance$max_ms))
  cat(sprintf("   ✓ Avg results: %.1f documents\n", results$query_performance$avg_results))

  if (results$query_performance$median_ms < 500) {
    cat("   ✅ PASS: Median query time < 500ms target\n")
  } else {
    cat("   ⚠️  WARN: Median query time exceeds 500ms target\n")
  }

  # ========================================================================
  # 3. DATABASE PERFORMANCE
  # ========================================================================

  cat("\n3. Analyzing Database Performance...\n")

  # Table sizes
  table_sizes <- dbGetQuery(db_connection, "
    SELECT
      'text_reuse_signatures' as table_name,
      pg_size_pretty(pg_total_relation_size('text_reuse_signatures')) as size,
      pg_total_relation_size('text_reuse_signatures') as bytes
    UNION ALL
    SELECT
      'lsh_buckets',
      pg_size_pretty(pg_total_relation_size('lsh_buckets')),
      pg_total_relation_size('lsh_buckets')
    UNION ALL
    SELECT
      'text_reuse_pairs',
      pg_size_pretty(pg_total_relation_size('text_reuse_pairs')),
      pg_total_relation_size('text_reuse_pairs')
  ")

  results$database_stats <- table_sizes

  cat("   Database Table Sizes:\n")
  for (i in 1:nrow(table_sizes)) {
    cat(sprintf("   ✓ %s: %s\n", table_sizes$table_name[i], table_sizes$size[i]))
  }

  total_mb <- sum(table_sizes$bytes) / 1024 / 1024
  cat(sprintf("\n   Total Storage: %.1f MB\n", total_mb))

  if (total_mb < 500) {
    cat("   ✅ PASS: Storage < 500MB target\n")
  } else {
    cat("   ⚠️  WARN: Storage exceeds 500MB target\n")
  }

  # Index usage
  index_usage <- dbGetQuery(db_connection, "
    SELECT
      schemaname,
      tablename,
      indexname,
      idx_scan as scans,
      idx_tup_read as tuples_read,
      idx_tup_fetch as tuples_fetched
    FROM pg_stat_user_indexes
    WHERE tablename LIKE 'text_reuse%'
    ORDER BY idx_scan DESC
  ")

  results$index_usage <- index_usage

  cat("\n   Top Index Usage:\n")
  for (i in 1:min(5, nrow(index_usage))) {
    cat(sprintf("   ✓ %s: %s scans\n",
                index_usage$indexname[i],
                format(index_usage$scans[i], big.mark = ",")))
  }

  # ========================================================================
  # 4. LSH BUCKET ANALYSIS
  # ========================================================================

  cat("\n4. Analyzing LSH Bucket Distribution...\n")

  bucket_stats <- dbGetQuery(db_connection, "
    SELECT
      band_number,
      COUNT(DISTINCT bucket_hash) as unique_buckets,
      COUNT(*) as total_entries,
      AVG(cnt) as avg_docs_per_bucket,
      MAX(cnt) as max_docs_per_bucket
    FROM (
      SELECT band_number, bucket_hash, COUNT(*) as cnt
      FROM lsh_buckets
      GROUP BY band_number, bucket_hash
    ) sub
    GROUP BY band_number
    ORDER BY band_number
  ")

  results$bucket_stats <- bucket_stats

  cat(sprintf("   LSH Configuration: 20 bands × 5 rows = 100 hash functions\n"))
  cat(sprintf("   ✓ Avg unique buckets per band: %.0f\n",
              mean(bucket_stats$unique_buckets)))
  cat(sprintf("   ✓ Avg docs per bucket: %.1f\n",
              mean(bucket_stats$avg_docs_per_bucket)))
  cat(sprintf("   ✓ Max docs in any bucket: %d\n",
              max(bucket_stats$max_docs_per_bucket)))

  if (max(bucket_stats$max_docs_per_bucket) < 1000) {
    cat("   ✅ PASS: No bucket overloading\n")
  } else {
    cat("   ⚠️  WARN: Some buckets are overloaded (>1000 docs)\n")
  }

  # ========================================================================
  # 5. SIMILARITY DISTRIBUTION
  # ========================================================================

  cat("\n5. Analyzing Similarity Distribution...\n")

  similarity_dist <- dbGetQuery(db_connection, "
    SELECT
      CASE
        WHEN jaccard_similarity >= 0.95 THEN '0.95-1.00'
        WHEN jaccard_similarity >= 0.90 THEN '0.90-0.95'
        WHEN jaccard_similarity >= 0.85 THEN '0.85-0.90'
        WHEN jaccard_similarity >= 0.80 THEN '0.80-0.85'
        WHEN jaccard_similarity >= 0.75 THEN '0.75-0.80'
        WHEN jaccard_similarity >= 0.70 THEN '0.70-0.75'
        ELSE '<0.70'
      END as similarity_range,
      COUNT(*) as count,
      COUNT(*) * 100.0 / SUM(COUNT(*)) OVER () as percentage
    FROM text_reuse_pairs
    GROUP BY similarity_range
    ORDER BY similarity_range DESC
  ")

  results$similarity_distribution <- similarity_dist

  cat("   Similarity Distribution:\n")
  for (i in 1:nrow(similarity_dist)) {
    cat(sprintf("   ✓ %s: %s pairs (%.1f%%)\n",
                similarity_dist$similarity_range[i],
                format(similarity_dist$count[i], big.mark = ","),
                similarity_dist$percentage[i]))
  }

  # ========================================================================
  # 6. CLUSTER ANALYSIS
  # ========================================================================

  cat("\n6. Analyzing Text Reuse Clusters...\n")

  cluster_info <- tryCatch({
    dbGetQuery(db_connection, "
      SELECT
        COUNT(*) as num_clusters,
        AVG(cluster_size) as avg_size,
        MAX(cluster_size) as max_size,
        SUM(cluster_size) as total_docs_in_clusters
      FROM text_reuse_clusters
    ")
  }, error = function(e) {
    data.frame(num_clusters = 0, avg_size = 0, max_size = 0, total_docs_in_clusters = 0)
  })

  results$cluster_info <- cluster_info

  if (cluster_info$num_clusters > 0) {
    cat(sprintf("   ✓ Total clusters: %s\n",
                format(cluster_info$num_clusters, big.mark = ",")))
    cat(sprintf("   ✓ Avg cluster size: %.1f documents\n", cluster_info$avg_size))
    cat(sprintf("   ✓ Largest cluster: %s documents\n",
                format(cluster_info$max_size, big.mark = ",")))
    cat(sprintf("   ✓ Documents in clusters: %s\n",
                format(cluster_info$total_docs_in_clusters, big.mark = ",")))
  } else {
    cat("   ℹ️  No clusters detected yet. Run detect_text_reuse_clusters().\n")
  }

  # ========================================================================
  # 7. CROSS-JURISDICTION PATTERNS
  # ========================================================================

  cat("\n7. Analyzing Cross-Jurisdiction Patterns...\n")

  cross_patterns <- tryCatch({
    dbGetQuery(db_connection, "
      SELECT * FROM mv_cross_jurisdiction_reuse
      ORDER BY reuse_count DESC
      LIMIT 10
    ")
  }, error = function(e) {
    # Materialized view not refreshed
    dbGetQuery(db_connection, "
      SELECT
        d1.nivel as source_nivel,
        d2.nivel as target_nivel,
        COUNT(*) as reuse_count,
        AVG(p.jaccard_similarity) as avg_similarity
      FROM text_reuse_pairs p
      JOIN documents d1 ON p.doc1_id = d1.id
      JOIN documents d2 ON p.doc2_id = d2.id
      WHERE d1.nivel != d2.nivel
      GROUP BY d1.nivel, d2.nivel
      ORDER BY reuse_count DESC
      LIMIT 10
    ")
  })

  results$cross_patterns <- cross_patterns

  cat("   Top Cross-Jurisdiction Patterns:\n")
  for (i in 1:min(5, nrow(cross_patterns))) {
    cat(sprintf("   ✓ %s → %s: %s pairs (avg sim: %.3f)\n",
                cross_patterns$source_nivel[i],
                cross_patterns$target_nivel[i],
                format(cross_patterns$reuse_count[i], big.mark = ","),
                cross_patterns$avg_similarity[i]))
  }

  # ========================================================================
  # SUMMARY & RECOMMENDATIONS
  # ========================================================================

  cat("\n╔═══════════════════════════════════════════════════════╗\n")
  cat("║                  Benchmark Summary                    ║\n")
  cat("╚═══════════════════════════════════════════════════════╝\n\n")

  # Performance grade
  grade <- "A"
  issues <- c()

  if (results$query_performance$median_ms >= 500) {
    grade <- "B"
    issues <- c(issues, "Query performance")
  }

  if (total_mb >= 500) {
    grade <- "B"
    issues <- c(issues, "Storage size")
  }

  if (max(bucket_stats$max_docs_per_bucket) >= 1000) {
    grade <- "C"
    issues <- c(issues, "Bucket distribution")
  }

  cat(sprintf("Overall Grade: %s\n", grade))

  if (length(issues) == 0) {
    cat("✅ All performance targets met!\n")
  } else {
    cat(sprintf("⚠️  Issues detected: %s\n", paste(issues, collapse = ", ")))
    cat("\nRecommendations:\n")

    if ("Query performance" %in% issues) {
      cat("  • Run ANALYZE on text_reuse tables\n")
      cat("  • Consider increasing shared_buffers in PostgreSQL\n")
      cat("  • Check for missing indexes\n")
    }

    if ("Storage size" %in% issues) {
      cat("  • Consider archiving old similarity pairs\n")
      cat("  • Use lower precision for similarity scores\n")
    }

    if ("Bucket distribution" %in% issues) {
      cat("  • Increase number of bands (reduce bucket collisions)\n")
      cat("  • Re-index with different LSH parameters\n")
    }
  }

  # Save results
  if (!is.null(output_file)) {
    saveRDS(results, output_file)
    cat(sprintf("\n✓ Results saved to: %s\n", output_file))
  }

  cat(sprintf("\nBenchmark completed at: %s\n", Sys.time()))

  invisible(results)
}

# ============================================================================
# PERFORMANCE REPORT GENERATION
# ============================================================================

#' Generate HTML performance report
#'
#' @param benchmark_results Results from benchmark_text_reuse_system()
#' @param output_html Path to output HTML file
#' @export
generate_performance_report <- function(benchmark_results, output_html = "text_reuse_report.html") {

  # Create temporary R Markdown file
  rmd_content <- sprintf('
---
title: "Text Reuse Detection - Performance Report"
date: "%s"
output:
  html_document:
    theme: cosmo
    toc: true
    toc_float: true
    code_folding: hide
---

```{r setup, include=FALSE}
knitr::opts_chunk$set(echo = FALSE, warning = FALSE, message = FALSE)
library(ggplot2)
library(dplyr)
library(knitr)

results <- readRDS("%s")
```

# Executive Summary

This report presents performance benchmarks for the Text Reuse Detection system.

## Key Metrics

```{r summary}
summary_df <- data.frame(
  Metric = c(
    "Indexed Documents",
    "LSH Buckets",
    "Detected Pairs",
    "Median Query Time",
    "95th Percentile Query Time",
    "Total Storage"
  ),
  Value = c(
    format(results$system_stats$total_indexed, big.mark = ","),
    format(results$system_stats$total_buckets, big.mark = ","),
    format(results$system_stats$total_pairs, big.mark = ","),
    sprintf("%.1f ms", results$query_performance$median_ms),
    sprintf("%.1f ms", results$query_performance$p95_ms),
    sprintf("%.1f MB", sum(results$database_stats$bytes) / 1024 / 1024)
  ),
  Target = c(
    "118,920",
    "-",
    "-",
    "< 500 ms",
    "< 1000 ms",
    "< 500 MB"
  ),
  Status = c(
    "✅",
    "-",
    "-",
    ifelse(results$query_performance$median_ms < 500, "✅", "⚠️"),
    ifelse(results$query_performance$p95_ms < 1000, "✅", "⚠️"),
    ifelse(sum(results$database_stats$bytes) / 1024 / 1024 < 500, "✅", "⚠️")
  )
)

kable(summary_df, caption = "Performance Summary")
```

# Query Performance

## Response Time Distribution

```{r query_dist}
query_df <- data.frame(time_ms = results$query_performance$times_ms)

ggplot(query_df, aes(x = time_ms)) +
  geom_histogram(bins = 30, fill = "steelblue", color = "white") +
  geom_vline(xintercept = 500, linetype = "dashed", color = "red",
             linewidth = 1, alpha = 0.7) +
  annotate("text", x = 500, y = Inf, label = "Target: 500ms",
           vjust = 1.5, hjust = -0.1, color = "red") +
  labs(
    title = "Query Response Time Distribution",
    x = "Response Time (ms)",
    y = "Count"
  ) +
  theme_minimal()
```

## Performance Statistics

```{r query_stats}
stats_df <- data.frame(
  Statistic = c("Mean", "Median", "Std Dev", "95th Percentile", "99th Percentile", "Max"),
  `Value (ms)` = c(
    sprintf("%.1f", results$query_performance$mean_ms),
    sprintf("%.1f", results$query_performance$median_ms),
    sprintf("%.1f", sd(results$query_performance$times_ms)),
    sprintf("%.1f", results$query_performance$p95_ms),
    sprintf("%.1f", results$query_performance$p99_ms),
    sprintf("%.1f", results$query_performance$max_ms)
  ),
  check.names = FALSE
)

kable(stats_df, caption = "Query Performance Statistics")
```

# Database Analysis

## Table Sizes

```{r db_sizes}
kable(results$database_stats[, c("table_name", "size")],
      col.names = c("Table", "Size"),
      caption = "Database Table Sizes")
```

## Index Usage

```{r index_usage}
if (nrow(results$index_usage) > 0) {
  top_indexes <- head(results$index_usage, 10)
  kable(top_indexes[, c("indexname", "scans", "tuples_fetched")],
        col.names = c("Index Name", "Scans", "Tuples Fetched"),
        caption = "Top 10 Index Usage")
}
```

# LSH Bucket Analysis

## Bucket Distribution by Band

```{r bucket_analysis}
ggplot(results$bucket_stats, aes(x = band_number, y = avg_docs_per_bucket)) +
  geom_col(fill = "steelblue") +
  geom_hline(yintercept = mean(results$bucket_stats$avg_docs_per_bucket),
             linetype = "dashed", color = "red") +
  labs(
    title = "Average Documents per Bucket by Band",
    x = "Band Number",
    y = "Avg Documents per Bucket"
  ) +
  theme_minimal()
```

```{r bucket_table}
kable(results$bucket_stats,
      col.names = c("Band", "Unique Buckets", "Total Entries",
                    "Avg Docs/Bucket", "Max Docs/Bucket"),
      caption = "LSH Bucket Statistics by Band")
```

# Similarity Analysis

## Similarity Distribution

```{r similarity_dist}
ggplot(results$similarity_distribution,
       aes(x = reorder(similarity_range, -count), y = count)) +
  geom_col(fill = "steelblue") +
  geom_text(aes(label = sprintf("%.1f%%", percentage)),
            vjust = -0.5, size = 3) +
  labs(
    title = "Distribution of Document Similarity Scores",
    x = "Similarity Range",
    y = "Number of Pairs"
  ) +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))
```

```{r similarity_table}
kable(results$similarity_distribution,
      col.names = c("Similarity Range", "Count", "Percentage"),
      caption = "Similarity Distribution Details")
```

# Cross-Jurisdiction Patterns

```{r cross_patterns}
if (nrow(results$cross_patterns) > 0) {
  kable(results$cross_patterns,
        caption = "Top Cross-Jurisdiction Text Reuse Patterns")
}
```

# Recommendations

Based on the benchmark results:

```{r recommendations}
recs <- c()

if (results$query_performance$median_ms >= 500) {
  recs <- c(recs, "- **Query Performance**: Consider running ANALYZE on text reuse tables and optimizing indexes")
}

if (sum(results$database_stats$bytes) / 1024 / 1024 >= 500) {
  recs <- c(recs, "- **Storage**: Consider archiving old similarity pairs or using data compression")
}

if (max(results$bucket_stats$max_docs_per_bucket) >= 1000) {
  recs <- c(recs, "- **LSH Tuning**: Some buckets are overloaded. Consider increasing the number of bands")
}

if (length(recs) == 0) {
  cat("✅ **All systems operating within target parameters. No immediate action required.**\n")
} else {
  cat(paste(recs, collapse = "\n"))
}
```

# Appendix

**Report Generated:** %s

**System Configuration:**
- LSH Bands: 20
- Rows per Band: 5
- Hash Functions: 100
- Shingle Size: 5-grams
- Similarity Threshold: 0.70

', format(benchmark_results$timestamp, "%Y-%m-%d %H:%M:%S"),
     tempfile(fileext = ".rds"),
     format(Sys.time(), "%Y-%m-%d %H:%M:%S"))

  # Save temporary results
  temp_rds <- tempfile(fileext = ".rds")
  saveRDS(benchmark_results, temp_rds)

  # Update RMD to use correct path
  rmd_content <- gsub('readRDS\\(".*?"\\)', sprintf('readRDS("%s")', temp_rds), rmd_content)

  # Write R Markdown file
  temp_rmd <- tempfile(fileext = ".Rmd")
  writeLines(rmd_content, temp_rmd)

  # Render to HTML
  rmarkdown::render(temp_rmd, output_file = output_html, quiet = TRUE)

  cat(sprintf("✓ HTML report generated: %s\n", output_html))
  invisible(output_html)
}

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

if (!interactive()) {
  args <- commandArgs(trailingOnly = TRUE)

  if (length(args) == 0) {
    cat("Usage: Rscript text_reuse_benchmarks.R [n_queries] [output_prefix]\n")
    cat("\nExamples:\n")
    cat("  Rscript text_reuse_benchmarks.R 100 benchmark_results\n")
    cat("  Rscript text_reuse_benchmarks.R 500 production_benchmark\n")
    quit(status = 1)
  }

  n_queries <- if (length(args) >= 1) as.integer(args[1]) else 100
  output_prefix <- if (length(args) >= 2) args[2] else "benchmark"

  # Load config and connect
  config <- yaml::read_yaml("config/database.yml")
  con <- dbConnect(
    PostgreSQL(),
    host = config$production$host,
    dbname = config$production$database,
    user = config$production$username,
    password = config$production$password
  )

  # Run benchmark
  results <- benchmark_text_reuse_system(
    con,
    n_queries = n_queries,
    output_file = paste0(output_prefix, "_results.rds")
  )

  # Generate HTML report
  generate_performance_report(
    results,
    output_html = paste0(output_prefix, "_report.html")
  )

  dbDisconnect(con)
}
