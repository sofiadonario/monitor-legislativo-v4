#' Example: Integrating Text Reuse Detection into Monitor Legislativo v4
#'
#' This file demonstrates how to integrate the text reuse detection system
#' into the main Shiny application.
#'
#' @author Monitor Legislativo Analytics Team
#' @date 2025-01-13

# ============================================================================
# EXAMPLE 1: MINIMAL INTEGRATION
# ============================================================================

# In your main app.R or ui.R file:

library(shiny)
library(bslib)

# Source the text reuse modules
source("modules/analytics/text_reuse_ui.R")
source("modules/analytics/text_reuse_server.R")

# UI
ui <- page_navbar(
  title = "Monitor Legislativo v4",
  theme = bs_theme(version = 5, bootswatch = "cosmo"),

  # Existing tabs...
  nav_panel("Home", "Home content..."),
  nav_panel("Documents", "Documents content..."),
  nav_panel("Analytics", "Analytics content..."),

  # Add Text Reuse tab
  nav_panel(
    "Text Reuse Detection",
    icon = icon("clone"),
    text_reuse_ui("text_reuse")
  )
)

# Server
server <- function(input, output, session) {

  # Database connection (adjust to your configuration)
  db_conn <- reactive({
    DBI::dbConnect(
      RPostgreSQL::PostgreSQL(),
      host = Sys.getenv("DB_HOST", "localhost"),
      dbname = Sys.getenv("DB_NAME", "monitor_legislativo"),
      user = Sys.getenv("DB_USER", "postgres"),
      password = Sys.getenv("DB_PASSWORD", "")
    )
  })

  # Initialize text reuse module
  text_reuse_server("text_reuse", db_conn)

  # Cleanup on session end
  session$onSessionEnded(function() {
    if (!is.null(db_conn())) {
      DBI::dbDisconnect(db_conn())
    }
  })
}

# Run the app
shinyApp(ui = ui, server = server)

# ============================================================================
# EXAMPLE 2: INTEGRATION WITH EXISTING DATABASE CONNECTION POOL
# ============================================================================

# If you already have a database connection pool in your app:

library(pool)

# Create connection pool (typically in global.R)
db_pool <- dbPool(
  RPostgreSQL::PostgreSQL(),
  host = config$db_host,
  dbname = config$db_name,
  user = config$db_user,
  password = config$db_password,
  minSize = 1,
  maxSize = 10
)

# In server function:
server <- function(input, output, session) {

  # Wrap pool in reactive
  db_conn <- reactive({
    poolCheckout(db_pool)
  })

  # Initialize module
  text_reuse_server("text_reuse", db_conn)

  # Return connection to pool on exit
  session$onSessionEnded(function() {
    poolReturn(db_conn())
  })
}

# Close pool when app stops
onStop(function() {
  poolClose(db_pool)
})

# ============================================================================
# EXAMPLE 3: INTEGRATION WITH GOLEM FRAMEWORK
# ============================================================================

# If using golem framework:

# In R/app_ui.R
app_ui <- function(request) {
  tagList(
    golem_add_external_resources(),
    page_navbar(
      title = "Monitor Legislativo v4",

      # Existing modules...
      nav_panel("Documents", mod_documents_ui("documents")),

      # Add text reuse module
      nav_panel("Text Reuse", mod_text_reuse_ui("text_reuse"))
    )
  )
}

# In R/mod_text_reuse.R
mod_text_reuse_ui <- function(id) {
  ns <- NS(id)
  source("modules/analytics/text_reuse_ui.R")
  text_reuse_ui(ns("text_reuse_module"))
}

mod_text_reuse_server <- function(id, db_conn) {
  moduleServer(id, function(input, output, session) {
    source("modules/analytics/text_reuse_server.R")
    text_reuse_server("text_reuse_module", db_conn)
  })
}

# In R/app_server.R
app_server <- function(input, output, session) {

  # Database connection
  db_conn <- golem::get_golem_options("db_conn")

  # Initialize modules
  mod_text_reuse_server("text_reuse", reactive(db_conn))
}

# ============================================================================
# EXAMPLE 4: STANDALONE ANALYSIS SCRIPT
# ============================================================================

# For running analyses outside of Shiny:

library(DBI)
library(RPostgreSQL)
library(dplyr)

source("R/analytics/text_reuse_lsh.R")

# Connect to database
con <- dbConnect(
  PostgreSQL(),
  host = "localhost",
  dbname = "monitor_legislativo",
  user = "postgres",
  password = "your_password"
)

# Example: Weekly text reuse report
weekly_report <- function(con) {

  cat("=== Weekly Text Reuse Report ===\n\n")

  # 1. New documents indexed this week
  new_docs <- dbGetQuery(con, "
    SELECT COUNT(*) as new_indexed
    FROM text_reuse_signatures
    WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
  ")$new_indexed

  cat(sprintf("New documents indexed: %d\n", new_docs))

  # 2. New similar pairs detected
  new_pairs <- dbGetQuery(con, "
    SELECT COUNT(*) as new_pairs
    FROM text_reuse_pairs
    WHERE detected_at >= CURRENT_DATE - INTERVAL '7 days'
  ")$new_pairs

  cat(sprintf("New similar pairs: %d\n\n", new_pairs))

  # 3. Top cross-jurisdiction adoptions this week
  cat("Top Cross-Jurisdiction Adoptions:\n")
  cross <- dbGetQuery(con, "
    SELECT
      d1.nivel as source,
      d1.uf as source_uf,
      d2.nivel as target,
      d2.uf as target_uf,
      COUNT(*) as count
    FROM text_reuse_pairs p
    JOIN documents d1 ON p.doc1_id = d1.id
    JOIN documents d2 ON p.doc2_id = d2.id
    WHERE p.detected_at >= CURRENT_DATE - INTERVAL '7 days'
      AND d1.nivel != d2.nivel
    GROUP BY d1.nivel, d1.uf, d2.nivel, d2.uf
    ORDER BY count DESC
    LIMIT 5
  ")

  print(cross)

  # 4. Most influential documents
  cat("\n\nMost Influential Documents:\n")
  influential <- dbGetQuery(con, "
    SELECT
      d.id,
      d.titulo,
      COUNT(*) as similar_count
    FROM documents d
    JOIN text_reuse_pairs p ON d.id IN (p.doc1_id, p.doc2_id)
    WHERE p.detected_at >= CURRENT_DATE - INTERVAL '7 days'
    GROUP BY d.id, d.titulo
    ORDER BY similar_count DESC
    LIMIT 5
  ")

  print(influential)

  # Export to CSV
  write.csv(cross, sprintf("weekly_cross_jurisdiction_%s.csv", Sys.Date()))
  write.csv(influential, sprintf("weekly_influential_%s.csv", Sys.Date()))

  cat(sprintf("\n\nReports exported to CSV files.\n"))
}

# Run weekly report
weekly_report(con)

# Cleanup
dbDisconnect(con)

# ============================================================================
# EXAMPLE 5: AUTOMATED DAILY INDEXING (CRON JOB)
# ============================================================================

# Save as: scripts/daily_text_reuse_update.R

#!/usr/bin/env Rscript

# Daily text reuse update script
# Add to crontab: 0 2 * * * /path/to/Rscript /path/to/daily_text_reuse_update.R

library(DBI)
library(RPostgreSQL)

# Setup logging
log_file <- sprintf("logs/text_reuse_daily_%s.log", Sys.Date())
dir.create("logs", showWarnings = FALSE)

sink(log_file, append = TRUE)
cat(sprintf("\n=== Daily Text Reuse Update: %s ===\n", Sys.time()))

tryCatch({

  # Load configuration
  config <- yaml::read_yaml("config/database.yml")

  # Connect
  con <- dbConnect(
    PostgreSQL(),
    host = config$production$host,
    dbname = config$production$database,
    user = config$production$username,
    password = config$production$password
  )

  # Check for unindexed documents
  unindexed <- dbGetQuery(con, "
    SELECT COUNT(*) as n
    FROM documents d
    LEFT JOIN text_reuse_signatures s ON d.id = s.document_id
    WHERE d.texto_completo IS NOT NULL
      AND d.texto_completo != ''
      AND s.id IS NULL
  ")$n

  cat(sprintf("Unindexed documents found: %d\n", unindexed))

  if (unindexed > 0) {
    cat("Starting incremental indexing...\n")

    source("R/analytics/text_reuse_lsh.R")

    # Run indexing (will skip already indexed docs with ON CONFLICT)
    stats <- lsh_index_documents(
      db_connection = con,
      batch_size = 500,
      max_docs = unindexed
    )

    cat(sprintf("Indexed %d documents in %.1f minutes\n",
                stats$documents_processed,
                stats$elapsed_minutes))

    # Detect new similar pairs
    if (stats$documents_processed > 0) {
      cat("Detecting new similar pairs...\n")
      pairs <- detect_all_similar_pairs(con, threshold = 0.7, store_results = TRUE)
      cat(sprintf("Found %d new similar pairs\n", nrow(pairs)))
    }

    # Refresh materialized views
    dbExecute(con, "SELECT refresh_text_reuse_views()")
    cat("Materialized views refreshed\n")

  } else {
    cat("No new documents to index\n")
  }

  # Get system stats
  stats <- lsh_index_stats(con)
  cat(sprintf("\nSystem Status:\n"))
  cat(sprintf("  Indexed docs: %s\n", format(stats$total_indexed, big.mark = ",")))
  cat(sprintf("  Similar pairs: %s\n", format(stats$total_pairs, big.mark = ",")))

  dbDisconnect(con)

  cat(sprintf("\nDaily update completed successfully at %s\n", Sys.time()))

}, error = function(e) {
  cat(sprintf("\nERROR: %s\n", e$message))
  cat(sprintf("Update failed at %s\n", Sys.time()))
})

sink()

# ============================================================================
# EXAMPLE 6: API ENDPOINT (PLUMBER)
# ============================================================================

# Save as: api/text_reuse_api.R
# Run with: plumber::plumb("api/text_reuse_api.R")$run(port=8000)

library(plumber)

# Initialize database connection
db_pool <- pool::dbPool(
  RPostgreSQL::PostgreSQL(),
  host = Sys.getenv("DB_HOST"),
  dbname = Sys.getenv("DB_NAME"),
  user = Sys.getenv("DB_USER"),
  password = Sys.getenv("DB_PASSWORD")
)

source("R/analytics/text_reuse_lsh.R")

#* Find similar documents
#* @param doc_id Document ID
#* @param threshold Similarity threshold (0-1)
#* @get /similar
function(doc_id, threshold = 0.7) {
  doc_id <- as.integer(doc_id)
  threshold <- as.numeric(threshold)

  con <- pool::poolCheckout(db_pool)
  on.exit(pool::poolReturn(con))

  results <- find_similar_documents(con, doc_id, threshold)

  list(
    query = list(
      document_id = doc_id,
      threshold = threshold
    ),
    results = results,
    count = nrow(results)
  )
}

#* Get cross-jurisdiction patterns
#* @get /cross-jurisdiction
function(threshold = 0.7) {
  threshold <- as.numeric(threshold)

  con <- pool::poolCheckout(db_pool)
  on.exit(pool::poolReturn(con))

  results <- cross_jurisdiction_reuse(con, threshold)

  list(
    threshold = threshold,
    results = results,
    count = nrow(results)
  )
}

#* Get system statistics
#* @get /stats
function() {
  con <- pool::poolCheckout(db_pool)
  on.exit(pool::poolReturn(con))

  stats <- lsh_index_stats(con)
  stats
}

#* Health check
#* @get /health
function() {
  list(
    status = "healthy",
    timestamp = Sys.time(),
    service = "text_reuse_detection"
  )
}

# ============================================================================
# EXAMPLE 7: CUSTOM ANALYSIS - LEGISLATIVE INFLUENCE SCORE
# ============================================================================

# Calculate influence score for each jurisdiction

calculate_influence_scores <- function(con) {

  # Get all cross-jurisdiction reuse
  cross_reuse <- cross_jurisdiction_reuse(con, threshold = 0.7)

  # Filter for temporal influence (earlier → later)
  influence <- cross_reuse %>%
    filter(temporal_direction == "Earlier→Later") %>%
    mutate(
      source_jurisdiction = paste(doc1_nivel, doc1_uf),
      target_jurisdiction = paste(doc2_nivel, doc2_uf)
    )

  # Calculate influence scores
  influence_scores <- influence %>%
    group_by(source_jurisdiction) %>%
    summarise(
      documents_influenced = n(),
      avg_similarity = mean(jaccard_similarity),
      unique_targets = n_distinct(target_jurisdiction),
      influence_score = documents_influenced * avg_similarity * unique_targets
    ) %>%
    arrange(desc(influence_score))

  # Add rank
  influence_scores <- influence_scores %>%
    mutate(rank = row_number())

  # Visualize
  library(ggplot2)

  top_20 <- head(influence_scores, 20)

  ggplot(top_20, aes(x = reorder(source_jurisdiction, influence_score),
                     y = influence_score)) +
    geom_col(fill = "steelblue") +
    coord_flip() +
    labs(
      title = "Legislative Influence Scores",
      subtitle = "Top 20 Most Influential Jurisdictions",
      x = "Jurisdiction",
      y = "Influence Score"
    ) +
    theme_minimal()

  ggsave("legislative_influence_scores.png", width = 10, height = 8, dpi = 300)

  return(influence_scores)
}

# Usage:
# con <- dbConnect(...)
# scores <- calculate_influence_scores(con)
# View(scores)

# ============================================================================
# NOTES ON PERFORMANCE TUNING
# ============================================================================

# If query performance is slow, try these optimizations:

# 1. Increase PostgreSQL shared_buffers
#    shared_buffers = 256MB  # in postgresql.conf

# 2. Increase work_mem for complex queries
#    work_mem = 16MB

# 3. Use connection pooling
#    library(pool)
#    pool <- dbPool(...)

# 4. Create additional indexes for specific query patterns
#    CREATE INDEX idx_custom ON text_reuse_pairs (doc1_id) WHERE jaccard_similarity > 0.8;

# 5. Partition large tables by year
#    CREATE TABLE text_reuse_pairs_2023 PARTITION OF text_reuse_pairs ...

# 6. Use parallel query execution (PostgreSQL 9.6+)
#    SET max_parallel_workers_per_gather = 4;

# ============================================================================
# MONITORING AND ALERTS
# ============================================================================

# Set up monitoring for:

# 1. Indexing completeness
check_indexing_completeness <- function(con) {
  result <- dbGetQuery(con, "
    SELECT
      COUNT(*) FILTER (WHERE texto_completo IS NOT NULL) as should_be_indexed,
      (SELECT COUNT(*) FROM text_reuse_signatures) as actually_indexed,
      COUNT(*) FILTER (WHERE texto_completo IS NOT NULL) -
        (SELECT COUNT(*) FROM text_reuse_signatures) as missing
    FROM documents
  ")

  if (result$missing > 100) {
    warning(sprintf("⚠️  %d documents not indexed!", result$missing))
  }

  result
}

# 2. Query performance
check_query_performance <- function(con) {
  sample_ids <- dbGetQuery(con, "
    SELECT document_id FROM text_reuse_signatures
    ORDER BY RANDOM() LIMIT 10
  ")$document_id

  times <- sapply(sample_ids, function(id) {
    start <- Sys.time()
    find_similar_documents(con, id, threshold = 0.7)
    as.numeric(difftime(Sys.time(), start, units = "secs")) * 1000
  })

  median_time <- median(times)

  if (median_time > 500) {
    warning(sprintf("⚠️  Slow queries detected! Median: %.1f ms", median_time))
  }

  median_time
}

# 3. Database size growth
check_database_size <- function(con) {
  size <- dbGetQuery(con, "
    SELECT
      pg_size_pretty(SUM(pg_total_relation_size(table_name::regclass))) as total_size,
      SUM(pg_total_relation_size(table_name::regclass)) as bytes
    FROM (
      SELECT 'text_reuse_signatures'::text as table_name
      UNION ALL SELECT 'lsh_buckets'
      UNION ALL SELECT 'text_reuse_pairs'
    ) tables
  ")

  size_mb <- size$bytes / 1024 / 1024

  if (size_mb > 500) {
    warning(sprintf("⚠️  Database size: %.1f MB (target: <500MB)", size_mb))
  }

  size
}

# ============================================================================
# EXAMPLE USAGE SUMMARY
# ============================================================================

cat("
Text Reuse Detection Integration Examples

This file contains 7 integration examples:

1. Minimal Shiny integration
2. Integration with connection pool
3. Integration with Golem framework
4. Standalone analysis script
5. Automated daily indexing (cron job)
6. API endpoint with Plumber
7. Custom analysis: Legislative influence scores

Additional sections:
- Performance tuning tips
- Monitoring and alerts
- Health checks

To get started:
1. Review the example that matches your setup
2. Adapt the database connection configuration
3. Test with your existing code
4. Refer to docs/TEXT_REUSE_QUICK_START.md for usage

For questions, see comprehensive documentation in docs/
")
