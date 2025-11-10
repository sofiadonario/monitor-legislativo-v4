#!/usr/bin/env Rscript
# Visualization of Municipal Document Distribution Findings
# Based on comprehensive analysis conducted 2025-11-09

library(ggplot2)
library(dplyr)
library(tidyr)

# Data from the comprehensive query results
municipal_data <- data.frame(
  estado = c("RS", "SP", "MG", "Federal", "RR", "SC", "SE", "MT"),
  municipal_docs = c(4542, 3177, 1768, 738, 119, 88, 60, 56),
  municipio_field_populated = c(0, 0, 0, 0, 0, 0, 0, 0),
  total_state_docs = c(4560, 8234, 6739, 66051, 121, 591, 63, 64)
)

# Add DF data separately (has municipio field populated)
df_data <- data.frame(
  estado = "DF",
  municipal_docs = 0,  # Not in URN pattern
  municipio_field_populated = 2994,
  total_state_docs = 21725
)

# Combine all data
all_data <- bind_rows(municipal_data, df_data) %>%
  mutate(
    pct_municipal = (municipal_docs + municipio_field_populated) / total_state_docs * 100,
    total_municipal = municipal_docs + municipio_field_populated
  )

# Plot 1: Municipal documents by state
p1 <- ggplot(all_data, aes(x = reorder(estado, -total_municipal), y = total_municipal)) +
  geom_col(fill = "#2E86AB", alpha = 0.8) +
  geom_text(aes(label = scales::comma(total_municipal)),
            vjust = -0.5, size = 3) +
  labs(
    title = "Municipal-Level Documents by State",
    subtitle = "Total: 10,548 documents across 8 states",
    x = "State",
    y = "Number of Municipal Documents",
    caption = "Source: monitor_legislativo database analysis (2025-11-09)"
  ) +
  theme_minimal() +
  theme(
    plot.title = element_text(face = "bold", size = 14),
    plot.subtitle = element_text(size = 10),
    axis.text.x = element_text(angle = 0, hjust = 0.5)
  )

# Plot 2: Data quality issue - municipio field vs URN pattern
data_quality <- all_data %>%
  select(estado, municipal_docs, municipio_field_populated) %>%
  pivot_longer(cols = c(municipal_docs, municipio_field_populated),
               names_to = "source",
               values_to = "count") %>%
  mutate(
    source = recode(source,
                   "municipal_docs" = "URN Pattern (not in municipio field)",
                   "municipio_field_populated" = "Municipio Field Populated")
  )

p2 <- ggplot(data_quality, aes(x = reorder(estado, -count), y = count, fill = source)) +
  geom_col(position = "stack", alpha = 0.8) +
  scale_fill_manual(values = c("#A23B72", "#2E86AB")) +
  labs(
    title = "Data Quality Issue: Municipal Data Storage",
    subtitle = "7,554 municipal documents (71.6%) missing from municipio field",
    x = "State",
    y = "Number of Documents",
    fill = "Data Source",
    caption = "DF is the only state with municipio field populated"
  ) +
  theme_minimal() +
  theme(
    plot.title = element_text(face = "bold", size = 14),
    plot.subtitle = element_text(size = 10, color = "#A23B72"),
    legend.position = "bottom"
  )

# SP Municipality breakdown
sp_municipalities <- data.frame(
  municipality = c("São Paulo State", "Campinas", "Hortolândia", "Bauru",
                  "Mococa", "Catanduva", "São João da Boa Vista", "Jundiaí",
                  "Birigui", "Bertioga", "Adamantina", "Itápolis",
                  "Indiaporã", "Bofete"),
  document_count = c(4953, 1452, 551, 293, 184, 128, 119, 90, 85, 69, 67, 48, 44, 35)
) %>%
  filter(municipality != "São Paulo State") %>%
  arrange(desc(document_count))

p3 <- ggplot(sp_municipalities, aes(x = reorder(municipality, document_count),
                                     y = document_count)) +
  geom_col(fill = "#F18F01", alpha = 0.8) +
  geom_text(aes(label = scales::comma(document_count)),
            hjust = -0.2, size = 3) +
  coord_flip() +
  labs(
    title = "São Paulo: Top Municipalities by Document Count",
    subtitle = "13 municipalities with 3,177 total municipal documents",
    x = NULL,
    y = "Number of Documents",
    caption = "Extracted from URN patterns"
  ) +
  theme_minimal() +
  theme(
    plot.title = element_text(face = "bold", size = 14),
    plot.subtitle = element_text(size = 10)
  ) +
  scale_y_continuous(expand = expansion(mult = c(0, 0.1)))

# Summary statistics
cat("\n=============================================================\n")
cat("MUNICIPAL DOCUMENT DISTRIBUTION SUMMARY\n")
cat("=============================================================\n\n")

cat("Total Municipal Documents:", sum(all_data$total_municipal), "\n")
cat("States with Municipal Data:", nrow(all_data), "\n\n")

cat("Top 5 States by Municipal Document Count:\n")
top_states <- all_data %>%
  arrange(desc(total_municipal)) %>%
  head(5) %>%
  select(estado, total_municipal, pct_municipal)
print(top_states, row.names = FALSE)

cat("\nData Quality Metrics:\n")
cat("- Documents with municipio field:", sum(all_data$municipio_field_populated), "\n")
cat("- Documents with URN pattern only:", sum(all_data$municipal_docs), "\n")
cat("- Coverage gap:",
    round(sum(all_data$municipal_docs) / sum(all_data$total_municipal) * 100, 1), "%\n")

# Save plots
ggsave("analysis/plot1_municipal_by_state.png", p1, width = 10, height = 6, dpi = 300)
ggsave("analysis/plot2_data_quality_issue.png", p2, width = 10, height = 6, dpi = 300)
ggsave("analysis/plot3_sp_municipalities.png", p3, width = 10, height = 8, dpi = 300)

cat("\nPlots saved to analysis/ directory\n")
cat("=============================================================\n\n")
