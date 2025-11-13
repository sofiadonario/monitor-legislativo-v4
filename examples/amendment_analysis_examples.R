# ============================================================================
# AMENDMENT PATTERN ANALYSIS - USAGE EXAMPLES
# ============================================================================
#
# Practical examples for using the Amendment Pattern Analysis system
# Monitor Legislativo v4
#
# ============================================================================

library(DBI)
library(RPostgres)
library(dplyr)
library(ggplot2)
library(plotly)

# Source the core functions
source("R/analytics/amendment_patterns.R")

# ============================================================================
# SETUP: Database Connection
# ============================================================================

# Connect to database
conn <- dbConnect(
  RPostgres::Postgres(),
  dbname = Sys.getenv("DB_NAME", "monitor_legislativo"),
  host = Sys.getenv("DB_HOST", "localhost"),
  user = Sys.getenv("DB_USER", "postgres"),
  password = Sys.getenv("DB_PASSWORD"),
  port = as.integer(Sys.getenv("DB_PORT", "5432"))
)

# Verify connection
if (dbIsValid(conn)) {
  cat("✅ Database connected successfully\n")
} else {
  stop("❌ Failed to connect to database")
}

# ============================================================================
# EXAMPLE 1: Basic Amendment Identification
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("EXAMPLE 1: Identifying Amendments (2015-2024)\n")
cat(rep("=", 70), "\n\n")

# Identify all amendments from 2015-2024
amendments_recent <- identify_amendments(
  db_connection = conn,
  year_range = c(2015, 2024),
  jurisdiction_filter = NULL
)

cat(sprintf("Total amendments found: %d\n", nrow(amendments_recent)))
cat("\nBy Type:\n")
print(table(amendments_recent$amendment_type))

cat("\nBy Jurisdiction:\n")
if ("nivel" %in% names(amendments_recent)) {
  print(table(amendments_recent$nivel))
}

# View top 5 recent amendments
cat("\nTop 5 Recent Amendments:\n")
print(amendments_recent %>%
  arrange(desc(ano)) %>%
  select(id, titulo, amendment_type, ano, nivel) %>%
  head(5))


# ============================================================================
# EXAMPLE 2: Federal Amendments Only
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("EXAMPLE 2: Federal Amendments (2020-2024)\n")
cat(rep("=", 70), "\n\n")

amendments_federal <- identify_amendments(
  db_connection = conn,
  year_range = c(2020, 2024),
  jurisdiction_filter = "Federal"
)

cat(sprintf("Federal amendments: %d\n", nrow(amendments_federal)))

# Visualize by type
if (nrow(amendments_federal) > 0) {
  type_counts <- amendments_federal %>%
    count(amendment_type) %>%
    arrange(desc(n))

  print(type_counts)

  # Create bar plot
  p <- ggplot(type_counts, aes(x = reorder(amendment_type, n), y = n)) +
    geom_col(fill = "steelblue") +
    coord_flip() +
    labs(
      title = "Federal Amendments by Type (2020-2024)",
      x = "Amendment Type",
      y = "Count"
    ) +
    theme_minimal()

  print(p)
}


# ============================================================================
# EXAMPLE 3: Document Timeline Analysis
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("EXAMPLE 3: Amendment Timeline for a Specific Document\n")
cat(rep("=", 70), "\n\n")

# Find a document with amendments (use first from recent amendments)
if (nrow(amendments_recent) > 0) {
  focal_id <- amendments_recent$id[1]

  cat(sprintf("Analyzing timeline for document ID: %d\n", focal_id))

  timeline_data <- build_amendment_timeline(
    db_connection = conn,
    doc_id = focal_id,
    max_depth = 10
  )

  if (!is.null(timeline_data)) {
    # Print statistics
    stats <- timeline_data$statistics
    cat("\nTimeline Statistics:\n")
    cat(sprintf("  Focal Law Number: %s\n", stats$focal_law_number))
    cat(sprintf("  Amendments TO this law: %d\n", stats$total_amendments_to))
    cat(sprintf("  Amendments FROM this law: %d\n", stats$total_amendments_from))
    cat(sprintf("  Amendment Span: %d years\n", stats$amendment_span_years))
    cat(sprintf("  Amendment Frequency: %.2f per year\n", stats$amendment_frequency))

    # Display timeline
    if (nrow(timeline_data$timeline) > 0) {
      cat("\nTimeline (first 5 events):\n")
      print(timeline_data$timeline %>%
        select(id, titulo, ano, direction) %>%
        head(5))
    }

    # Network structure
    cat("\nNetwork Structure:\n")
    cat(sprintf("  Nodes: %d\n", nrow(timeline_data$network$nodes)))
    cat(sprintf("  Edges: %d\n", nrow(timeline_data$network$edges)))
  }
} else {
  cat("⚠️ No amendments found for timeline analysis\n")
}


# ============================================================================
# EXAMPLE 4: Hotspot Detection
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("EXAMPLE 4: Detecting Amendment Hotspots\n")
cat(rep("=", 70), "\n\n")

# Find laws with at least 3 amendments
hotspots <- detect_amendment_hotspots(
  db_connection = conn,
  min_amendments = 3,
  top_n = 20
)

if (nrow(hotspots) > 0) {
  cat(sprintf("Hotspots detected: %d\n\n", nrow(hotspots)))

  cat("Top 10 Most Amended Laws:\n")
  print(hotspots %>%
    select(hotspot_rank, refs, amendment_count, hotspot_category, hotspot_score) %>%
    head(10))

  # Visualize top 10
  p <- plot_ly(
    hotspots %>% head(10),
    x = ~amendment_count,
    y = ~reorder(refs, amendment_count),
    type = "bar",
    orientation = "h",
    marker = list(
      color = ~hotspot_score,
      colorscale = "Reds",
      showscale = TRUE
    )
  ) %>%
    layout(
      title = "Top 10 Amendment Hotspots",
      xaxis = list(title = "Number of Amendments"),
      yaxis = list(title = "")
    )

  print(p)
} else {
  cat("⚠️ No hotspots detected with current criteria\n")
}


# ============================================================================
# EXAMPLE 5: Cascade Detection
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("EXAMPLE 5: Detecting Amendment Cascades\n")
cat(rep("=", 70), "\n\n")

cascades <- analyze_amendment_cascades(
  db_connection = conn,
  min_chain_length = 3
)

if (nrow(cascades) > 0) {
  cat(sprintf("Cascades detected: %d\n\n", nrow(cascades)))

  cat("Cascade Summary by Category:\n")
  print(table(cascades$category))

  cat("\nTop 5 Longest Cascades:\n")
  print(cascades %>%
    arrange(desc(chain_length)) %>%
    select(cascade_id, chain_length, category, complexity_score) %>%
    head(5))

  cat("\nExample Cascade Chain:\n")
  print(cascades$chain[1])
} else {
  cat("⚠️ No cascades detected with minimum length of 3\n")
}


# ============================================================================
# EXAMPLE 6: Amendment Velocity Analysis
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("EXAMPLE 6: Calculating Amendment Velocity\n")
cat(rep("=", 70), "\n\n")

# Overall velocity
velocity_overall <- calculate_amendment_velocity(
  db_connection = conn,
  window_years = 3,
  by_jurisdiction = FALSE
)

if (nrow(velocity_overall) > 0) {
  cat("Recent Velocity Trends (last 10 years):\n")
  print(velocity_overall %>%
    arrange(desc(ano)) %>%
    select(ano, amendment_count, rolling_avg, velocity, trend) %>%
    head(10))

  # Plot velocity
  p <- plot_ly(velocity_overall, x = ~ano, y = ~amendment_count,
               type = "scatter", mode = "lines+markers", name = "Amendments") %>%
    add_lines(y = ~rolling_avg, line = list(dash = "dash"),
              name = "3-Year Rolling Avg") %>%
    layout(
      title = "Amendment Velocity Over Time",
      xaxis = list(title = "Year"),
      yaxis = list(title = "Number of Amendments")
    )

  print(p)
}

# By jurisdiction
cat("\nVelocity by Jurisdiction:\n")
velocity_by_juris <- calculate_amendment_velocity(
  db_connection = conn,
  window_years = 3,
  by_jurisdiction = TRUE
)

if (nrow(velocity_by_juris) > 0) {
  # Recent trends by jurisdiction
  print(velocity_by_juris %>%
    filter(ano >= 2020) %>%
    select(ano, nivel, amendment_count, velocity, trend) %>%
    arrange(desc(ano), nivel))

  # Plot by jurisdiction
  p <- plot_ly(velocity_by_juris, x = ~ano, y = ~amendment_count,
               color = ~nivel, type = "scatter", mode = "lines+markers") %>%
    layout(
      title = "Amendment Velocity by Jurisdiction",
      xaxis = list(title = "Year"),
      yaxis = list(title = "Amendment Count")
    )

  print(p)
}


# ============================================================================
# EXAMPLE 7: Cross-Jurisdiction Analysis
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("EXAMPLE 7: Cross-Jurisdiction Amendment Patterns\n")
cat(rep("=", 70), "\n\n")

cross_juris <- cross_jurisdiction_amendments(
  db_connection = conn
)

if (!is.null(cross_juris) && length(cross_juris) > 0) {
  # Flow patterns
  if (nrow(cross_juris$cross_jurisdiction_patterns) > 0) {
    cat("Cross-Jurisdiction Flow Patterns:\n")
    print(cross_juris$cross_jurisdiction_patterns %>%
      select(flow_type, count, span_years, diffusion_speed) %>%
      arrange(desc(count)) %>%
      head(10))

    # Diffusion speed distribution
    p <- plot_ly(
      cross_juris$cross_jurisdiction_patterns %>% filter(diffusion_speed > 0),
      x = ~diffusion_speed,
      type = "histogram",
      nbinsx = 20
    ) %>%
      layout(
        title = "Diffusion Speed Distribution",
        xaxis = list(title = "Amendments per Year"),
        yaxis = list(title = "Count")
      )

    print(p)
  }

  # Flows by level
  if (nrow(cross_juris$flows_by_level) > 0) {
    cat("\nAmendments by Level (2020-2024):\n")
    print(cross_juris$flows_by_level %>%
      filter(ano >= 2020) %>%
      arrange(desc(ano), nivel))
  }
} else {
  cat("⚠️ No cross-jurisdiction patterns detected\n")
}


# ============================================================================
# EXAMPLE 8: Using Materialized Views
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("EXAMPLE 8: Querying Materialized Views\n")
cat(rep("=", 70), "\n\n")

# Query amendment summary view
cat("Querying mv_amendment_summary...\n")
amendments_mv <- dbGetQuery(conn, "
  SELECT
    ano,
    amendment_type,
    COUNT(*) as count
  FROM mv_amendment_summary
  WHERE ano BETWEEN 2015 AND 2024
  GROUP BY ano, amendment_type
  ORDER BY ano DESC, count DESC
")

if (nrow(amendments_mv) > 0) {
  cat("\nAmendments by Year and Type (2015-2024):\n")
  print(head(amendments_mv, 15))
}

# Query hotspots view
cat("\n\nQuerying mv_amendment_hotspots...\n")
hotspots_mv <- dbGetQuery(conn, "
  SELECT *
  FROM mv_amendment_hotspots
  WHERE hotspot_category IN ('Muito Alto', 'Alto')
  ORDER BY hotspot_rank
  LIMIT 10
")

if (nrow(hotspots_mv) > 0) {
  cat("\nTop Hotspots from Materialized View:\n")
  print(hotspots_mv %>%
    select(hotspot_rank, law_ref, amendment_count, hotspot_category))
}

# Query statistics view
cat("\n\nQuerying v_amendment_statistics...\n")
stats <- dbGetQuery(conn, "SELECT * FROM v_amendment_statistics")

if (nrow(stats) > 0) {
  cat("\nSystem Statistics:\n")
  print(t(stats))
}


# ============================================================================
# EXAMPLE 9: Export Results
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("EXAMPLE 9: Exporting Results\n")
cat(rep("=", 70), "\n\n")

# Export amendments to CSV
if (nrow(amendments_recent) > 0) {
  export_file <- "amendment_analysis_export.csv"
  write.csv(amendments_recent, export_file, row.names = FALSE, fileEncoding = "UTF-8")
  cat(sprintf("✅ Amendments exported to: %s\n", export_file))
}

# Export hotspots to CSV
if (nrow(hotspots) > 0) {
  export_file <- "amendment_hotspots_export.csv"
  write.csv(hotspots, export_file, row.names = FALSE, fileEncoding = "UTF-8")
  cat(sprintf("✅ Hotspots exported to: %s\n", export_file))
}

# Export velocity to CSV
if (nrow(velocity_overall) > 0) {
  export_file <- "amendment_velocity_export.csv"
  write.csv(velocity_overall, export_file, row.names = FALSE, fileEncoding = "UTF-8")
  cat(sprintf("✅ Velocity data exported to: %s\n", export_file))
}


# ============================================================================
# CLEANUP
# ============================================================================

cat("\n", rep("=", 70), "\n")
cat("CLEANUP\n")
cat(rep("=", 70), "\n\n")

# Close database connection
dbDisconnect(conn)
cat("✅ Database connection closed\n")

cat("\n", rep("=", 70), "\n")
cat("EXAMPLES COMPLETED SUCCESSFULLY\n")
cat(rep("=", 70), "\n\n")

cat("📊 Summary:\n")
cat("  - Identified amendments across different time periods and jurisdictions\n")
cat("  - Analyzed document timelines and modification histories\n")
cat("  - Detected amendment hotspots and frequently modified laws\n")
cat("  - Found cascade patterns in amendment chains\n")
cat("  - Calculated velocity and acceleration of legislative changes\n")
cat("  - Explored cross-jurisdictional amendment flows\n")
cat("  - Queried materialized views for optimized performance\n")
cat("  - Exported results to CSV files\n")
cat("\n")
cat("For more information, see: docs/AMENDMENT_ANALYSIS_INTEGRATION.md\n")
