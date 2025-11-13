# ==============================================================================
# MULTI-JURISDICTIONAL COMPARISON - USAGE EXAMPLES
# ==============================================================================
# Practical examples demonstrating the Multi-Jurisdictional Comparison feature
# for Monitor Legislativo v4.
#
# Author: Data Science Team
# Date: 2025-11-13
# ==============================================================================

# Load required libraries
library(DBI)
library(RPostgres)
library(dplyr)
library(ggplot2)

# Source analytics functions
source("R/analytics/multi_jurisdictional_comparison.R")

# ==============================================================================
# SETUP: DATABASE CONNECTION
# ==============================================================================

# Connect to database
conn <- dbConnect(
  RPostgres::Postgres(),
  host = Sys.getenv("PGHOST", "34.39.228.246"),
  port = as.integer(Sys.getenv("PGPORT", "5432")),
  dbname = Sys.getenv("PGDATABASE", "mackmonitor-db"),
  user = Sys.getenv("PGUSER", "monitor_user"),
  password = Sys.getenv("PGPASSWORD")
)

cat("✅ Connected to database\n")

# ==============================================================================
# EXAMPLE 1: COMPARE ALL JURISDICTIONS (2020-2024)
# ==============================================================================

cat("\n=== EXAMPLE 1: All Jurisdictions Comparison ===\n")

jurisdiction_results <- compare_by_jurisdiction(
  conn,
  start_year = 2020,
  end_year = 2024
)

print(jurisdiction_results)

# Interpretation
cat("\nKey Insights:\n")
cat("- Total documents:", sum(jurisdiction_results$doc_count, na.rm = TRUE), "\n")
cat("- Highest volume:", jurisdiction_results$jurisdiction_level[1], "\n")
cat("- Most diverse:", jurisdiction_results$jurisdiction_level[
  which.max(jurisdiction_results$diversity_index)
], "\n")

# Visualization
ggplot(jurisdiction_results, aes(x = jurisdiction_level, y = doc_count, fill = jurisdiction_level)) +
  geom_col() +
  geom_text(aes(label = format(doc_count, big.mark = ",")), vjust = -0.5) +
  labs(
    title = "Legislative Documents by Jurisdiction Level (2020-2024)",
    x = "Jurisdiction Level",
    y = "Number of Documents"
  ) +
  theme_minimal() +
  theme(legend.position = "none")

# ==============================================================================
# EXAMPLE 2: COMPARE SUDESTE REGION STATES
# ==============================================================================

cat("\n=== EXAMPLE 2: Sudeste Region Comparison ===\n")

sudeste_states <- c("SP", "RJ", "MG", "ES")

sudeste_results <- compare_by_state(
  conn,
  states_vector = sudeste_states,
  start_year = 2020,
  end_year = 2024
)

print(sudeste_results)

# Visualization: Multi-metric comparison
sudeste_normalized <- sudeste_results %>%
  mutate(
    volume_norm = scales::rescale(total_documents, to = c(0, 100)),
    diversity_norm = scales::rescale(diversity_index, to = c(0, 100)),
    complexity_norm = scales::rescale(avg_length, to = c(0, 100))
  ) %>%
  select(state, volume_norm, diversity_norm, complexity_norm) %>%
  tidyr::pivot_longer(cols = -state, names_to = "metric", values_to = "value")

ggplot(sudeste_normalized, aes(x = metric, y = value, fill = state)) +
  geom_col(position = "dodge") +
  labs(
    title = "Sudeste States: Multi-Metric Comparison (Normalized)",
    x = "Metric",
    y = "Normalized Score (0-100)"
  ) +
  theme_minimal()

# ==============================================================================
# EXAMPLE 3: TOP 10 STATES BY VOLUME
# ==============================================================================

cat("\n=== EXAMPLE 3: Top 10 States by Volume ===\n")

all_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
                "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
                "RS", "RO", "RR", "SC", "SP", "SE", "TO")

all_states_results <- compare_by_state(
  conn,
  states_vector = all_states,
  start_year = 2020,
  end_year = 2024
)

top_10_states <- all_states_results %>%
  arrange(desc(total_documents)) %>%
  head(10)

print(top_10_states)

# Visualization: Top 10 ranking
ggplot(top_10_states, aes(x = reorder(state, total_documents), y = total_documents)) +
  geom_col(fill = "#667eea") +
  geom_text(aes(label = format(total_documents, big.mark = ",")), hjust = -0.2) +
  coord_flip() +
  labs(
    title = "Top 10 States by Legislative Document Volume (2020-2024)",
    x = "State",
    y = "Total Documents"
  ) +
  theme_minimal()

# ==============================================================================
# EXAMPLE 4: CROSS-LEVEL ANALYSIS - TAX LEGISLATION
# ==============================================================================

cat("\n=== EXAMPLE 4: Tax Legislation Cross-Level Analysis ===\n")

tax_keywords <- c("tributário", "imposto", "ICMS", "ISS", "IPI")

tax_analysis <- cross_level_analysis(
  conn,
  topic_keywords = tax_keywords
)

print(tax_analysis)

# Interpretation
cat("\nTax Legislation Insights:\n")
cat("- Total matching documents:", sum(tax_analysis$document_count, na.rm = TRUE), "\n")
cat("- Level with most tax docs:", tax_analysis$jurisdiction_level[
  which.max(tax_analysis$document_count)
], "\n")
cat("- States affected:", max(tax_analysis$states_affected, na.rm = TRUE), "\n")

# Visualization
ggplot(tax_analysis, aes(x = jurisdiction_level, y = document_count, fill = jurisdiction_level)) +
  geom_col() +
  geom_text(aes(label = document_count), vjust = -0.5) +
  labs(
    title = paste("Tax Legislation Distribution:", paste(tax_keywords, collapse = ", ")),
    x = "Jurisdiction Level",
    y = "Number of Documents"
  ) +
  theme_minimal() +
  theme(legend.position = "none")

# ==============================================================================
# EXAMPLE 5: STATE CLUSTERING
# ==============================================================================

cat("\n=== EXAMPLE 5: Hierarchical Clustering of States ===\n")

clustering_results <- state_clustering(
  conn,
  start_year = 2020,
  end_year = 2024
)

if (!is.null(clustering_results)) {
  cat("Optimal clusters:", clustering_results$optimal_clusters, "\n")
  cat("States analyzed:", nrow(clustering_results$cluster_data), "\n")

  # View cluster assignments
  cluster_summary <- clustering_results$cluster_data %>%
    group_by(cluster) %>%
    summarise(
      states = paste(state, collapse = ", "),
      avg_volume = mean(total_volume),
      count = n()
    )

  print(cluster_summary)

  # Plot dendrogram
  plot(clustering_results$dendrogram,
       main = "State Clustering by Legislative Patterns",
       xlab = "States",
       ylab = "Distance",
       sub = paste("Method: Ward's, Clusters:", clustering_results$optimal_clusters))

  # Add colored rectangles for clusters
  rect.hclust(clustering_results$dendrogram,
              k = clustering_results$optimal_clusters,
              border = 2:(clustering_results$optimal_clusters + 1))

} else {
  cat("⚠️ Clustering failed - insufficient data\n")
}

# ==============================================================================
# EXAMPLE 6: TEMPORAL TRENDS - DOCUMENT COUNT
# ==============================================================================

cat("\n=== EXAMPLE 6: Temporal Trends - Document Count ===\n")

temporal_trends <- temporal_jurisdiction_trends(
  conn,
  metric = "count",
  start_year = 2020,
  end_year = 2024
)

# Aggregate by year for overview
yearly_trends <- temporal_trends %>%
  group_by(jurisdiction_level, year) %>%
  summarise(
    annual_total = sum(value, na.rm = TRUE),
    .groups = "drop"
  )

print(yearly_trends)

# Visualization: Time series
ggplot(temporal_trends, aes(x = date, y = value, color = jurisdiction_level, group = jurisdiction_level)) +
  geom_line(size = 1.2) +
  geom_point(size = 2) +
  labs(
    title = "Legislative Activity Trends (2020-2024)",
    x = "Date",
    y = "Monthly Document Count",
    color = "Jurisdiction Level"
  ) +
  theme_minimal() +
  theme(legend.position = "bottom")

# ==============================================================================
# EXAMPLE 7: STATE SIMILARITY ANALYSIS
# ==============================================================================

cat("\n=== EXAMPLE 7: State Similarity (Cosine) ===\n")

# Compare similarity between major states
major_states <- c("SP", "RJ", "MG", "BA", "PR", "RS")

similarity_matrix <- calculate_state_similarity(
  conn,
  states_vector = major_states,
  method = "cosine"
)

print(round(similarity_matrix, 3))

# Find most similar state pairs
similarity_df <- as.data.frame(as.table(similarity_matrix))
colnames(similarity_df) <- c("State1", "State2", "Similarity")

# Remove diagonal and duplicates
similarity_df <- similarity_df %>%
  filter(as.character(State1) < as.character(State2)) %>%
  arrange(desc(Similarity))

cat("\nMost similar state pairs:\n")
print(head(similarity_df, 5))

# Visualization: Heatmap
library(reshape2)
melted_similarity <- melt(similarity_matrix)

ggplot(melted_similarity, aes(Var1, Var2, fill = value)) +
  geom_tile() +
  geom_text(aes(label = round(value, 2)), color = "white", size = 4) +
  scale_fill_gradient2(low = "#ffffff", mid = "#667eea", high = "#1e40af",
                       midpoint = 0.5, limit = c(0, 1)) +
  labs(
    title = "State Similarity Matrix (Cosine)",
    x = "State",
    y = "State",
    fill = "Similarity"
  ) +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

# ==============================================================================
# EXAMPLE 8: GROWTH RATE COMPARISON
# ==============================================================================

cat("\n=== EXAMPLE 8: Growth Rate Analysis ===\n")

# Compare growth rates across all states
growth_comparison <- all_states_results %>%
  select(state, total_documents, growth_rate) %>%
  arrange(desc(growth_rate)) %>%
  filter(!is.na(growth_rate))

cat("States with highest growth:\n")
print(head(growth_comparison, 5))

cat("\nStates with declining activity:\n")
print(tail(growth_comparison, 5))

# Visualization: Growth rate distribution
ggplot(growth_comparison, aes(x = reorder(state, growth_rate), y = growth_rate)) +
  geom_col(aes(fill = growth_rate > 0)) +
  geom_hline(yintercept = 0, linetype = "dashed", color = "gray50") +
  coord_flip() +
  scale_fill_manual(values = c("#f093fb", "#43e97b"),
                    labels = c("Declining", "Growing")) +
  labs(
    title = "Legislative Activity Growth Rate by State (2020-2024)",
    x = "State",
    y = "Growth Rate (%)",
    fill = "Trend"
  ) +
  theme_minimal()

# ==============================================================================
# EXAMPLE 9: DIVERSITY COMPARISON
# ==============================================================================

cat("\n=== EXAMPLE 9: Document Type Diversity ===\n")

# Analyze diversity across jurisdictions and states
diversity_comparison <- bind_rows(
  jurisdiction_results %>%
    select(entity = jurisdiction_level, diversity_index, unique_types) %>%
    mutate(type = "Jurisdiction"),
  all_states_results %>%
    select(entity = state, diversity_index, unique_types = document_types) %>%
    mutate(type = "State") %>%
    head(10)  # Top 10 states
)

print(diversity_comparison)

# Visualization: Diversity vs. Unique Types
ggplot(diversity_comparison, aes(x = unique_types, y = diversity_index, color = type, label = entity)) +
  geom_point(size = 4, alpha = 0.7) +
  geom_text(vjust = -1, hjust = 0.5, size = 3) +
  labs(
    title = "Legislative Diversity: Shannon Entropy vs. Unique Document Types",
    x = "Number of Unique Document Types",
    y = "Diversity Index (Shannon Entropy)",
    color = "Entity Type"
  ) +
  theme_minimal()

# ==============================================================================
# EXAMPLE 10: SEASONALITY ANALYSIS
# ==============================================================================

cat("\n=== EXAMPLE 10: Seasonality Patterns ===\n")

# Analyze seasonal patterns in top states
seasonal_states <- top_10_states %>%
  select(state, seasonality_index) %>%
  arrange(desc(seasonality_index))

print(seasonal_states)

# Interpretation
cat("\nSeasonality Insights:\n")
cat("- Most seasonal state:", seasonal_states$state[1],
    "(CV:", round(seasonal_states$seasonality_index[1], 2), "%)\n")
cat("- Least seasonal state:", seasonal_states$state[nrow(seasonal_states)],
    "(CV:", round(seasonal_states$seasonality_index[nrow(seasonal_states)], 2), "%)\n")

# Visualization
ggplot(seasonal_states, aes(x = reorder(state, seasonality_index), y = seasonality_index)) +
  geom_col(fill = "#4facfe") +
  geom_text(aes(label = round(seasonality_index, 1)), hjust = -0.2) +
  coord_flip() +
  labs(
    title = "Legislative Activity Seasonality by State",
    subtitle = "Coefficient of Variation (%)",
    x = "State",
    y = "Seasonality Index"
  ) +
  theme_minimal()

# ==============================================================================
# CLEANUP
# ==============================================================================

# Disconnect from database
dbDisconnect(conn)
cat("\n✅ Examples completed successfully\n")
cat("📊 Generated visualizations and analysis results\n")
