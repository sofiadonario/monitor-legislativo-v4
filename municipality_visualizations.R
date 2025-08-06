# Municipality Data Visualizations
# Author: Data Analysis Assistant
# Date: 2025-08-06

# Add user library path and load required libraries
.libPaths(c("~/R/library", .libPaths()))

library(DBI)
library(RPostgreSQL)
library(dplyr)
library(ggplot2)
library(stringr)
library(scales)

# Database connection parameters
db_host <- "nozomi.proxy.rlwy.net"
db_port <- 44844
db_name <- "railway"
db_user <- "postgres"
db_password <- "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"

# Establish database connection
con <- dbConnect(PostgreSQL(),
                 host = db_host,
                 port = db_port,
                 dbname = db_name,
                 user = db_user,
                 password = db_password)

# Function to create coverage comparison visualization
create_coverage_visualization <- function(con) {
  
  # Get coverage data
  coverage_data <- dbGetQuery(con, "
    SELECT 
      'Municipality' as field_type,
      COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as with_data,
      COUNT(*) as total,
      ROUND((COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) * 100.0 / COUNT(*)), 2) as coverage_pct
    FROM documents
    
    UNION ALL
    
    SELECT 
      'Estado' as field_type,
      COUNT(CASE WHEN estado IS NOT NULL AND TRIM(estado) != '' THEN 1 END) as with_data,
      COUNT(*) as total,
      ROUND((COUNT(CASE WHEN estado IS NOT NULL AND TRIM(estado) != '' THEN 1 END) * 100.0 / COUNT(*)), 2) as coverage_pct
    FROM documents
    
    UNION ALL
    
    SELECT 
      'Jurisdiction' as field_type,
      COUNT(CASE WHEN jurisdicao_original IS NOT NULL AND TRIM(jurisdicao_original) != '' THEN 1 END) as with_data,
      COUNT(*) as total,
      ROUND((COUNT(CASE WHEN jurisdicao_original IS NOT NULL AND TRIM(jurisdicao_original) != '' THEN 1 END) * 100.0 / COUNT(*)), 2) as coverage_pct
    FROM documents
    
    UNION ALL
    
    SELECT 
      'Localidade' as field_type,
      COUNT(CASE WHEN localidade IS NOT NULL AND TRIM(localidade) != '' THEN 1 END) as with_data,
      COUNT(*) as total,
      ROUND((COUNT(CASE WHEN localidade IS NOT NULL AND TRIM(localidade) != '' THEN 1 END) * 100.0 / COUNT(*)), 2) as coverage_pct
    FROM documents;
  ")
  
  # Create coverage comparison chart
  coverage_plot <- ggplot(coverage_data, aes(x = reorder(field_type, coverage_pct), y = coverage_pct)) +
    geom_col(fill = "steelblue", alpha = 0.8) +
    geom_text(aes(label = paste0(coverage_pct, "%")), hjust = -0.1, size = 4) +
    coord_flip() +
    labs(
      title = "Geographic Data Coverage Comparison",
      subtitle = "Percentage of documents with geographic information",
      x = "Geographic Field",
      y = "Coverage Percentage (%)",
      caption = "Source: Brazilian Legislative Monitoring System Database"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(size = 16, face = "bold"),
      plot.subtitle = element_text(size = 12, color = "gray60"),
      axis.text = element_text(size = 11),
      axis.title = element_text(size = 12)
    ) +
    ylim(0, max(coverage_data$coverage_pct) * 1.1)
  
  ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/municipality_coverage_comparison.png", 
         coverage_plot, width = 10, height = 6, dpi = 300)
  
  cat("✓ Created coverage comparison visualization\n")
  return(coverage_data)
}

# Function to create state distribution visualization
create_state_distribution <- function(con) {
  
  # Get top states data
  state_data <- dbGetQuery(con, "
    SELECT 
      estado,
      COUNT(*) as document_count,
      COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as with_municipality
    FROM documents 
    WHERE estado IS NOT NULL AND TRIM(estado) != ''
    GROUP BY estado
    ORDER BY document_count DESC
    LIMIT 15;
  ")
  
  # Reshape data for stacked bar chart
  state_data$without_municipality <- state_data$document_count - state_data$with_municipality
  
  library(tidyr)
  state_long <- state_data %>%
    select(estado, with_municipality, without_municipality) %>%
    pivot_longer(cols = c(with_municipality, without_municipality),
                 names_to = "municipality_status",
                 values_to = "count") %>%
    mutate(municipality_status = ifelse(municipality_status == "with_municipality",
                                       "With Municipality Data", "Without Municipality Data"))
  
  # Create stacked bar chart
  state_plot <- ggplot(state_long, aes(x = reorder(estado, count), y = count, fill = municipality_status)) +
    geom_col(position = "stack") +
    coord_flip() +
    scale_fill_manual(values = c("With Municipality Data" = "#2E8B57", 
                                "Without Municipality Data" = "#CD5C5C")) +
    labs(
      title = "Document Distribution by State/Level",
      subtitle = "Top 15 states showing municipality data availability",
      x = "Estado/Level",
      y = "Number of Documents",
      fill = "Municipality Data Status",
      caption = "Source: Brazilian Legislative Monitoring System Database"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(size = 16, face = "bold"),
      plot.subtitle = element_text(size = 12, color = "gray60"),
      legend.position = "bottom",
      axis.text = element_text(size = 10)
    ) +
    scale_y_continuous(labels = scales::comma_format())
  
  ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/state_distribution.png", 
         state_plot, width = 12, height = 8, dpi = 300)
  
  cat("✓ Created state distribution visualization\n")
  return(state_data)
}

# Function to create temporal analysis visualization
create_temporal_analysis <- function(con) {
  
  # Get temporal data for recent years
  temporal_data <- dbGetQuery(con, "
    SELECT 
      EXTRACT(YEAR FROM data) as year,
      COUNT(*) as total_docs,
      COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as with_municipality,
      ROUND((COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) * 100.0 / COUNT(*)), 2) as municipality_coverage_pct
    FROM documents
    WHERE data IS NOT NULL AND EXTRACT(YEAR FROM data) >= 2000
    GROUP BY EXTRACT(YEAR FROM data)
    ORDER BY year;
  ")
  
  # Create dual-axis plot
  p1 <- ggplot(temporal_data, aes(x = year)) +
    geom_col(aes(y = total_docs), fill = "lightblue", alpha = 0.7) +
    geom_line(aes(y = with_municipality * 100), color = "red", size = 1.2) +
    geom_point(aes(y = with_municipality * 100), color = "red", size = 2) +
    labs(
      title = "Municipality Data Coverage Over Time (2000-2025)",
      subtitle = "Blue bars: Total documents, Red line: Documents with municipality data (scaled x100)",
      x = "Year",
      y = "Number of Documents",
      caption = "Source: Brazilian Legislative Monitoring System Database"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(size = 14, face = "bold"),
      plot.subtitle = element_text(size = 10, color = "gray60"),
      axis.text.x = element_text(angle = 45, hjust = 1, size = 8)
    ) +
    scale_y_continuous(labels = scales::comma_format()) +
    scale_x_continuous(breaks = seq(2000, 2025, 5))
  
  ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/temporal_analysis.png", 
         p1, width = 14, height = 8, dpi = 300)
  
  # Create coverage percentage over time
  p2 <- ggplot(temporal_data, aes(x = year, y = municipality_coverage_pct)) +
    geom_line(color = "darkgreen", size = 1.2) +
    geom_point(color = "darkgreen", size = 2) +
    geom_smooth(method = "loess", se = TRUE, color = "blue", alpha = 0.3) +
    labs(
      title = "Municipality Data Coverage Percentage by Year (2000-2025)",
      subtitle = "Percentage of documents with municipality data, with trend line",
      x = "Year",
      y = "Coverage Percentage (%)",
      caption = "Source: Brazilian Legislative Monitoring System Database"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(size = 14, face = "bold"),
      plot.subtitle = element_text(size = 10, color = "gray60"),
      axis.text.x = element_text(angle = 45, hjust = 1, size = 8)
    ) +
    scale_x_continuous(breaks = seq(2000, 2025, 5)) +
    ylim(0, max(temporal_data$municipality_coverage_pct) * 1.1)
  
  ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/coverage_percentage_trend.png", 
         p2, width = 14, height = 8, dpi = 300)
  
  cat("✓ Created temporal analysis visualizations\n")
  return(temporal_data)
}

# Function to create document type analysis
create_document_type_analysis <- function(con) {
  
  # Analyze by categoria_original
  category_data <- dbGetQuery(con, "
    SELECT 
      categoria_original,
      COUNT(*) as total_docs,
      COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as with_municipio,
      ROUND((COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) * 100.0 / COUNT(*)), 2) as municipio_coverage_pct
    FROM documents
    WHERE categoria_original IS NOT NULL AND TRIM(categoria_original) != ''
    GROUP BY categoria_original
    ORDER BY total_docs DESC;
  ")
  
  # Create visualization
  category_plot <- ggplot(category_data, aes(x = reorder(categoria_original, total_docs))) +
    geom_col(aes(y = total_docs), fill = "lightcoral", alpha = 0.7) +
    geom_col(aes(y = with_municipio), fill = "darkgreen", alpha = 0.8) +
    coord_flip() +
    labs(
      title = "Municipality Data by Document Category",
      subtitle = "Light bars: Total documents, Dark bars: Documents with municipality data",
      x = "Document Category",
      y = "Number of Documents",
      caption = "Source: Brazilian Legislative Monitoring System Database"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(size = 14, face = "bold"),
      plot.subtitle = element_text(size = 10, color = "gray60")
    ) +
    scale_y_continuous(labels = scales::comma_format())
  
  ggsave("/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/document_category_analysis.png", 
         category_plot, width = 12, height = 8, dpi = 300)
  
  cat("✓ Created document category analysis visualization\n")
  return(category_data)
}

# Execute all visualizations
cat("Creating comprehensive municipality data visualizations...\n\n")

coverage_data <- create_coverage_visualization(con)
state_data <- create_state_distribution(con)
temporal_data <- create_temporal_analysis(con)
category_data <- create_document_type_analysis(con)

# Close database connection
dbDisconnect(con)

cat("\n=== VISUALIZATION SUMMARY ===\n")
cat("Generated visualizations:\n")
cat("1. municipality_coverage_comparison.png - Geographic field coverage comparison\n")
cat("2. state_distribution.png - Document distribution by state with municipality data status\n") 
cat("3. temporal_analysis.png - Municipality data coverage over time (absolute numbers)\n")
cat("4. coverage_percentage_trend.png - Municipality data coverage percentage trend\n")
cat("5. document_category_analysis.png - Municipality data by document category\n\n")

cat("All visualizations saved to the project directory.\n")
cat("Analysis complete!\n")