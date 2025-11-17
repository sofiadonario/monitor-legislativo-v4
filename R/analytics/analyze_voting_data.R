# ==============================================================================
# VOTING DATA ANALYSIS & VISUALIZATION
# ==============================================================================
# Sprint 4: Analysis of 1000 bills across 5 themes (Transport, Energy, Cities,
# Environment, Economy) spanning 3 legislatures (2015-2027)
# ==============================================================================

library(DBI)
library(RPostgreSQL)
library(dplyr)
library(ggplot2)
library(lubridate)
library(tidyr)

# ==============================================================================
# 1. DATA EXPLORATION QUERIES
# ==============================================================================

#' Get Bill Count by Theme
#'
#' @param con Database connection
#' @return Data frame with theme counts
get_bill_count_by_theme <- function(con) {
  query <- "
    SELECT
      CASE
        WHEN LOWER(description) LIKE '%transporte%' OR
             LOWER(description) LIKE '%viação%' OR
             LOWER(description) LIKE '%mobilidade%' THEN 'Transportation'
        WHEN LOWER(description) LIKE '%energia%' OR
             LOWER(description) LIKE '%elétric%' THEN 'Energy'
        WHEN LOWER(description) LIKE '%cidade%' OR
             LOWER(description) LIKE '%urbano%' THEN 'Cities'
        WHEN LOWER(description) LIKE '%ambiente%' OR
             LOWER(description) LIKE '%ambiental%' THEN 'Environment'
        WHEN LOWER(description) LIKE '%economia%' OR
             LOWER(description) LIKE '%econômico%' THEN 'Economy'
        ELSE 'Multiple/Other'
      END as theme,
      COUNT(DISTINCT bill_id) as bill_count
    FROM bill_events
    GROUP BY theme
    ORDER BY bill_count DESC
  "

  dbGetQuery(con, query)
}

#' Get Bill Timeline by Theme
#'
#' @param con Database connection
#' @return Data frame with bills per year by theme
get_bill_timeline <- function(con) {
  query <- "
    SELECT
      EXTRACT(YEAR FROM event_date) as year,
      CASE
        WHEN LOWER(description) LIKE '%transporte%' OR
             LOWER(description) LIKE '%viação%' THEN 'Transportation'
        WHEN LOWER(description) LIKE '%energia%' OR
             LOWER(description) LIKE '%elétric%' THEN 'Energy'
        WHEN LOWER(description) LIKE '%cidade%' OR
             LOWER(description) LIKE '%urbano%' THEN 'Cities'
        WHEN LOWER(description) LIKE '%ambiente%' THEN 'Environment'
        WHEN LOWER(description) LIKE '%economia%' THEN 'Economy'
        ELSE 'Other'
      END as theme,
      COUNT(DISTINCT bill_id) as bill_count
    FROM bill_events
    WHERE event_date IS NOT NULL
    GROUP BY year, theme
    ORDER BY year, theme
  "

  dbGetQuery(con, query)
}

#' Get Legislature Distribution
#'
#' @param con Database connection
#' @return Bills per legislature
get_legislature_distribution <- function(con) {
  query <- "
    SELECT
      CASE
        WHEN EXTRACT(YEAR FROM event_date) BETWEEN 2015 AND 2018 THEN '55 (2015-2019)'
        WHEN EXTRACT(YEAR FROM event_date) BETWEEN 2019 AND 2022 THEN '56 (2019-2023)'
        WHEN EXTRACT(YEAR FROM event_date) >= 2023 THEN '57 (2023-2027)'
        ELSE 'Unknown'
      END as legislature,
      COUNT(DISTINCT bill_id) as bill_count
    FROM bill_events
    WHERE event_date IS NOT NULL
    GROUP BY legislature
    ORDER BY legislature
  "

  dbGetQuery(con, query)
}

#' Get Top Active Legislators
#'
#' @param con Database connection
#' @param limit Number of legislators to return
#' @return Data frame with legislator participation
get_top_legislators <- function(con, limit = 20) {
  query <- sprintf("
    SELECT
      l.name,
      l.party,
      COUNT(DISTINCT rcv.vote_id) as vote_count,
      COUNT(DISTINCT rcv.bill_id) as bills_voted
    FROM roll_call_votes rcv
    JOIN legislators l ON rcv.legislator_id = l.id
    GROUP BY l.id, l.name, l.party
    ORDER BY vote_count DESC
    LIMIT %d
  ", limit)

  dbGetQuery(con, query)
}

#' Get Voting Patterns by Party
#'
#' @param con Database connection
#' @return Voting distribution by party
get_party_voting_patterns <- function(con) {
  query <- "
    SELECT
      l.party,
      rcv.vote,
      COUNT(*) as vote_count
    FROM roll_call_votes rcv
    JOIN legislators l ON rcv.legislator_id = l.id
    WHERE rcv.vote IS NOT NULL
    GROUP BY l.party, rcv.vote
    ORDER BY l.party, rcv.vote
  "

  dbGetQuery(con, query)
}

# ==============================================================================
# 2. VISUALIZATION FUNCTIONS
# ==============================================================================

#' Plot Bill Distribution by Theme
#'
#' @param theme_counts Data frame from get_bill_count_by_theme()
#' @return ggplot object
plot_theme_distribution <- function(theme_counts) {
  ggplot(theme_counts, aes(x = reorder(theme, bill_count), y = bill_count, fill = theme)) +
    geom_col() +
    geom_text(aes(label = bill_count), hjust = -0.2, size = 4) +
    coord_flip() +
    scale_fill_brewer(palette = "Set3") +
    labs(
      title = "Bill Distribution Across Themes",
      subtitle = "1000 bills from 5 thematic areas (2015-2027)",
      x = "Theme",
      y = "Number of Bills",
      caption = "Source: Brazilian Chamber of Deputies Open Data API"
    ) +
    theme_minimal(base_size = 14) +
    theme(
      legend.position = "none",
      plot.title = element_text(face = "bold", size = 16),
      plot.subtitle = element_text(color = "gray40")
    )
}

#' Plot Bill Timeline
#'
#' @param timeline_data Data frame from get_bill_timeline()
#' @return ggplot object
plot_bill_timeline <- function(timeline_data) {
  ggplot(timeline_data, aes(x = year, y = bill_count, color = theme, group = theme)) +
    geom_line(size = 1.2) +
    geom_point(size = 3) +
    scale_color_brewer(palette = "Set2") +
    scale_x_continuous(breaks = seq(2015, 2027, 2)) +
    labs(
      title = "Bill Activity Timeline by Theme",
      subtitle = "Legislative activity across 3 legislatures (55, 56, 57)",
      x = "Year",
      y = "Number of Bills",
      color = "Theme",
      caption = "Source: Brazilian Chamber of Deputies Open Data API"
    ) +
    theme_minimal(base_size = 14) +
    theme(
      plot.title = element_text(face = "bold", size = 16),
      plot.subtitle = element_text(color = "gray40"),
      legend.position = "bottom"
    )
}

#' Plot Legislature Distribution
#'
#' @param legislature_data Data frame from get_legislature_distribution()
#' @return ggplot object
plot_legislature_distribution <- function(legislature_data) {
  ggplot(legislature_data, aes(x = legislature, y = bill_count, fill = legislature)) +
    geom_col() +
    geom_text(aes(label = bill_count), vjust = -0.5, size = 5, fontface = "bold") +
    scale_fill_brewer(palette = "Pastel1") +
    labs(
      title = "Bill Distribution Across Legislatures",
      subtitle = "Coverage of 3 Brazilian legislative periods",
      x = "Legislature",
      y = "Number of Bills",
      caption = "Source: Brazilian Chamber of Deputies Open Data API"
    ) +
    theme_minimal(base_size = 14) +
    theme(
      legend.position = "none",
      plot.title = element_text(face = "bold", size = 16),
      plot.subtitle = element_text(color = "gray40")
    )
}

#' Plot Party Voting Heatmap
#'
#' @param party_voting Data frame from get_party_voting_patterns()
#' @return ggplot object
plot_party_voting_heatmap <- function(party_voting) {
  # Calculate vote percentages by party
  party_totals <- party_voting %>%
    group_by(party) %>%
    summarize(total_votes = sum(vote_count))

  party_voting_pct <- party_voting %>%
    left_join(party_totals, by = "party") %>%
    mutate(percentage = (vote_count / total_votes) * 100)

  ggplot(party_voting_pct, aes(x = vote, y = reorder(party, total_votes), fill = percentage)) +
    geom_tile(color = "white", size = 0.5) +
    geom_text(aes(label = sprintf("%.1f%%", percentage)), color = "black", size = 3) +
    scale_fill_gradient2(
      low = "#d7191c",
      mid = "#ffffbf",
      high = "#1a9641",
      midpoint = 50,
      name = "Vote %"
    ) +
    labs(
      title = "Voting Patterns by Political Party",
      subtitle = "Distribution of Yes/No/Abstention votes across parties",
      x = "Vote Type",
      y = "Political Party",
      caption = "Source: Brazilian Chamber of Deputies Roll Call Votes"
    ) +
    theme_minimal(base_size = 14) +
    theme(
      plot.title = element_text(face = "bold", size = 16),
      plot.subtitle = element_text(color = "gray40"),
      axis.text.x = element_text(angle = 0)
    )
}

# ==============================================================================
# 3. COMPREHENSIVE ANALYSIS REPORT
# ==============================================================================

#' Generate Complete Voting Data Analysis
#'
#' @param con Database connection
#' @param output_dir Directory to save plots
#' @return List with all analysis results and plots
generate_voting_analysis_report <- function(con, output_dir = "analysis/voting_data") {

  cat("\n==============================================================================\n")
  cat("GENERATING VOTING DATA ANALYSIS REPORT\n")
  cat("==============================================================================\n\n")

  # Create output directory
  if (!dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE)
  }

  # Run all queries
  cat("1. Analyzing theme distribution...\n")
  theme_counts <- get_bill_count_by_theme(con)

  cat("2. Analyzing timeline...\n")
  timeline_data <- get_bill_timeline(con)

  cat("3. Analyzing legislature distribution...\n")
  legislature_data <- get_legislature_distribution(con)

  cat("4. Analyzing top legislators...\n")
  top_legislators <- get_top_legislators(con)

  cat("5. Analyzing party voting patterns...\n")
  party_voting <- get_party_voting_patterns(con)

  # Generate and save plots
  cat("\n6. Generating visualizations...\n")

  p1 <- plot_theme_distribution(theme_counts)
  ggsave(file.path(output_dir, "theme_distribution.png"), p1, width = 10, height = 6, dpi = 300)
  cat("   ✓ Theme distribution plot saved\n")

  p2 <- plot_bill_timeline(timeline_data)
  ggsave(file.path(output_dir, "bill_timeline.png"), p2, width = 12, height = 6, dpi = 300)
  cat("   ✓ Timeline plot saved\n")

  p3 <- plot_legislature_distribution(legislature_data)
  ggsave(file.path(output_dir, "legislature_distribution.png"), p3, width = 10, height = 6, dpi = 300)
  cat("   ✓ Legislature distribution plot saved\n")

  if (nrow(party_voting) > 0) {
    p4 <- plot_party_voting_heatmap(party_voting)
    ggsave(file.path(output_dir, "party_voting_heatmap.png"), p4, width = 12, height = 10, dpi = 300)
    cat("   ✓ Party voting heatmap saved\n")
  }

  # Print summary statistics
  cat("\n==============================================================================\n")
  cat("SUMMARY STATISTICS\n")
  cat("==============================================================================\n\n")

  cat("Theme Distribution:\n")
  print(theme_counts)
  cat("\n")

  cat("Legislature Coverage:\n")
  print(legislature_data)
  cat("\n")

  cat("Top 10 Most Active Legislators:\n")
  print(head(top_legislators, 10))
  cat("\n")

  cat("Total Bills Analyzed:", sum(theme_counts$bill_count), "\n")
  cat("Date Range:", min(timeline_data$year, na.rm = TRUE), "-",
      max(timeline_data$year, na.rm = TRUE), "\n")

  cat("\n✓ Analysis complete! Results saved to:", output_dir, "\n\n")

  # Return results
  list(
    theme_counts = theme_counts,
    timeline_data = timeline_data,
    legislature_data = legislature_data,
    top_legislators = top_legislators,
    party_voting = party_voting,
    plots = list(p1 = p1, p2 = p2, p3 = p3, p4 = if(exists("p4")) p4 else NULL)
  )
}

# ==============================================================================
# EXAMPLE USAGE
# ==============================================================================

# # Connect to database
# library(pool)
# pool <- dbPool(
#   drv = PostgreSQL(),
#   dbname = "monitor_legislativo",
#   host = "localhost",
#   port = 5432,
#   user = "monitor_user",
#   password = "your_password"
# )
# con <- poolCheckout(pool)
#
# # Generate complete analysis report
# results <- generate_voting_analysis_report(con, output_dir = "analysis/voting_data")
#
# # Return connection and close pool
# poolReturn(con)
# poolClose(pool)
