# Brazilian Legislative Monitoring System - Temporal Visualizations
# Creating comprehensive temporal analysis visualizations
# Author: Data Science Analysis
# Date: 2025-08-06

# Set library path to personal library
.libPaths('~/R/library')

# Load required libraries
suppressMessages({
  library(DBI)
  library(RPostgres)
  library(dplyr)
  library(ggplot2)
  library(lubridate)
  library(scales)
})

# Database connection
db_host <- "nozomi.proxy.rlwy.net"
db_port <- 44844
db_name <- "railway"
db_user <- "postgres"
db_password <- "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"

con <- dbConnect(RPostgres::Postgres(),
                 host = db_host, port = db_port, dbname = db_name,
                 user = db_user, password = db_password)

cat("=== CREATING TEMPORAL VISUALIZATIONS ===\n")

# 1. YEARLY DOCUMENT TIMELINE
cat("\n--- Creating yearly timeline visualization ---\n")

yearly_data <- dbGetQuery(con, "
  SELECT 
    EXTRACT(YEAR FROM data)::integer as year,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL
  GROUP BY EXTRACT(YEAR FROM data)
  ORDER BY year;
")

# Create yearly timeline plot
p1 <- ggplot(yearly_data, aes(x = year, y = document_count)) +
  geom_line(color = "steelblue", linewidth = 0.8) +
  geom_point(color = "darkblue", size = 0.5, alpha = 0.7) +
  labs(
    title = "Brazilian Legislative Documents Timeline (1829-2025)",
    subtitle = paste("Total documents analyzed:", format(sum(yearly_data$document_count), big.mark = ",")),
    x = "Year",
    y = "Number of Documents",
    caption = "Data: Brazilian Legislative Monitoring System"
  ) +
  scale_x_continuous(breaks = seq(1830, 2020, 20)) +
  scale_y_continuous(labels = comma_format()) +
  theme_minimal() +
  theme(
    plot.title = element_text(size = 14, face = "bold"),
    plot.subtitle = element_text(size = 12),
    axis.text.x = element_text(angle = 45, hjust = 1)
  )

ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/timeline_yearly.png", 
       p1, width = 12, height = 6, dpi = 300)

# 2. DECADE ANALYSIS VISUALIZATION
cat("--- Creating decade analysis visualization ---\n")

decade_data <- dbGetQuery(con, "
  SELECT 
    FLOOR(EXTRACT(YEAR FROM data) / 10) * 10 as decade,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL
  GROUP BY FLOOR(EXTRACT(YEAR FROM data) / 10) * 10
  ORDER BY decade;
")

# Add percentage and convert to numeric to avoid integer64 issues
decade_data$document_count <- as.numeric(decade_data$document_count)
total_docs <- sum(decade_data$document_count)
decade_data$percentage <- round(100 * decade_data$document_count / total_docs, 1)
decade_data$decade_label <- paste0(decade_data$decade, "s")

p2 <- ggplot(decade_data, aes(x = factor(decade), y = document_count)) +
  geom_col(fill = "darkgreen", alpha = 0.8) +
  geom_text(aes(label = paste0(format(document_count, big.mark = ","), "\n(", percentage, "%)")), 
            vjust = -0.3, size = 3) +
  labs(
    title = "Legislative Documents by Decade",
    subtitle = "Distribution of 132,685 documents across historical periods",
    x = "Decade",
    y = "Number of Documents",
    caption = "Data: Brazilian Legislative Monitoring System"
  ) +
  scale_y_continuous(labels = comma_format()) +
  theme_minimal() +
  theme(
    plot.title = element_text(size = 14, face = "bold"),
    axis.text.x = element_text(angle = 45, hjust = 1)
  )

ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/timeline_decades.png", 
       p2, width = 12, height = 6, dpi = 300)

# 3. CATEGORY TEMPORAL PATTERNS
cat("--- Creating category temporal patterns visualization ---\n")

category_yearly <- dbGetQuery(con, "
  SELECT 
    extracted_category,
    EXTRACT(YEAR FROM data)::integer as year,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL 
    AND extracted_category IS NOT NULL
    AND EXTRACT(YEAR FROM data) >= 1990
  GROUP BY extracted_category, EXTRACT(YEAR FROM data)
  ORDER BY extracted_category, year;
")

p3 <- ggplot(category_yearly, aes(x = year, y = document_count, color = extracted_category)) +
  geom_line(linewidth = 1, alpha = 0.8) +
  geom_point(size = 0.8, alpha = 0.6) +
  facet_wrap(~extracted_category, scales = "free_y", ncol = 2) +
  labs(
    title = "Legislative Document Categories Over Time (1990-2025)",
    subtitle = "Temporal evolution by document category",
    x = "Year",
    y = "Number of Documents",
    caption = "Data: Brazilian Legislative Monitoring System"
  ) +
  scale_x_continuous(breaks = seq(1990, 2025, 10)) +
  scale_y_continuous(labels = comma_format()) +
  scale_color_brewer(type = "qual", palette = "Dark2") +
  theme_minimal() +
  theme(
    plot.title = element_text(size = 14, face = "bold"),
    axis.text.x = element_text(angle = 45, hjust = 1),
    legend.position = "none",
    strip.text = element_text(size = 10, face = "bold")
  )

ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/categories_timeline.png", 
       p3, width = 14, height = 10, dpi = 300)

# 4. STATE TEMPORAL DISTRIBUTION (TOP STATES)
cat("--- Creating state temporal patterns visualization ---\n")

top_states <- dbGetQuery(con, "
  SELECT estado, COUNT(*) as total_count
  FROM documents
  WHERE data IS NOT NULL AND estado IS NOT NULL
  GROUP BY estado
  ORDER BY total_count DESC
  LIMIT 8;
")$estado

state_yearly <- dbGetQuery(con, sprintf("
  SELECT 
    estado,
    EXTRACT(YEAR FROM data)::integer as year,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL 
    AND estado IS NOT NULL
    AND estado IN ('%s')
    AND EXTRACT(YEAR FROM data) >= 1990
  GROUP BY estado, EXTRACT(YEAR FROM data)
  ORDER BY estado, year;
", paste(top_states, collapse = "', '")))

p4 <- ggplot(state_yearly, aes(x = year, y = document_count, color = estado)) +
  geom_line(linewidth = 1, alpha = 0.8) +
  geom_point(size = 0.8, alpha = 0.6) +
  facet_wrap(~estado, scales = "free_y", ncol = 2) +
  labs(
    title = "Legislative Documents by State/Jurisdiction (1990-2025)",
    subtitle = "Top 8 states by document volume",
    x = "Year",
    y = "Number of Documents",
    caption = "Data: Brazilian Legislative Monitoring System"
  ) +
  scale_x_continuous(breaks = seq(1990, 2025, 10)) +
  scale_y_continuous(labels = comma_format()) +
  scale_color_brewer(type = "qual", palette = "Set1") +
  theme_minimal() +
  theme(
    plot.title = element_text(size = 14, face = "bold"),
    axis.text.x = element_text(angle = 45, hjust = 1),
    legend.position = "none",
    strip.text = element_text(size = 10, face = "bold")
  )

ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/states_timeline.png", 
       p4, width = 14, height = 10, dpi = 300)

# 5. TRANSPORT MODE EVOLUTION
cat("--- Creating transport mode temporal visualization ---\n")

transport_yearly <- dbGetQuery(con, "
  SELECT 
    extracted_transport_mode,
    EXTRACT(YEAR FROM data)::integer as year,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL 
    AND extracted_transport_mode IS NOT NULL
    AND EXTRACT(YEAR FROM data) >= 1990
  GROUP BY extracted_transport_mode, EXTRACT(YEAR FROM data)
  ORDER BY extracted_transport_mode, year;
")

p5 <- ggplot(transport_yearly, aes(x = year, y = document_count, color = extracted_transport_mode)) +
  geom_line(linewidth = 1.2, alpha = 0.8) +
  geom_point(size = 1, alpha = 0.6) +
  labs(
    title = "Legislative Documents by Transport Mode (1990-2025)",
    subtitle = "Evolution of transport-related legislative activity",
    x = "Year",
    y = "Number of Documents",
    color = "Transport Mode",
    caption = "Data: Brazilian Legislative Monitoring System"
  ) +
  scale_x_continuous(breaks = seq(1990, 2025, 5)) +
  scale_y_continuous(labels = comma_format()) +
  scale_color_brewer(type = "qual", palette = "Dark2") +
  theme_minimal() +
  theme(
    plot.title = element_text(size = 14, face = "bold"),
    axis.text.x = element_text(angle = 45, hjust = 1),
    legend.position = "bottom"
  )

ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/transport_timeline.png", 
       p5, width = 12, height = 8, dpi = 300)

# 6. HEATMAP OF RECENT ACTIVITY (2010-2025)
cat("--- Creating activity heatmap ---\n")

recent_monthly <- dbGetQuery(con, "
  SELECT 
    EXTRACT(YEAR FROM data)::integer as year,
    EXTRACT(MONTH FROM data)::integer as month,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL 
    AND EXTRACT(YEAR FROM data) >= 2010
    AND EXTRACT(YEAR FROM data) <= 2025
  GROUP BY EXTRACT(YEAR FROM data), EXTRACT(MONTH FROM data)
  ORDER BY year, month;
")

recent_monthly$month_name <- month.abb[recent_monthly$month]
recent_monthly$month_name <- factor(recent_monthly$month_name, levels = month.abb)

p6 <- ggplot(recent_monthly, aes(x = factor(year), y = month_name, fill = document_count)) +
  geom_tile(color = "white", linewidth = 0.5) +
  scale_fill_gradient(low = "lightblue", high = "darkblue", 
                      name = "Documents", labels = comma_format()) +
  labs(
    title = "Monthly Legislative Activity Heatmap (2010-2025)",
    subtitle = "Document publication patterns by month and year",
    x = "Year",
    y = "Month",
    caption = "Data: Brazilian Legislative Monitoring System"
  ) +
  theme_minimal() +
  theme(
    plot.title = element_text(size = 14, face = "bold"),
    axis.text.x = element_text(angle = 45, hjust = 1),
    axis.text.y = element_text(size = 9),
    legend.position = "right"
  )

ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/activity_heatmap.png", 
       p6, width = 14, height = 8, dpi = 300)

cat("\nAll visualizations saved successfully!\n")
cat("Files created:\n")
cat("- timeline_yearly.png\n")
cat("- timeline_decades.png\n") 
cat("- categories_timeline.png\n")
cat("- states_timeline.png\n")
cat("- transport_timeline.png\n")
cat("- activity_heatmap.png\n")

dbDisconnect(con)