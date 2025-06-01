# Brazilian Legislative Monitoring System - Temporal Analysis Part 3
# Analyzing temporal patterns by categories and jurisdictions
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

cat("=== TEMPORAL PATTERNS BY CATEGORIES AND JURISDICTIONS ===\n")

# 1. TEMPORAL PATTERNS BY DOCUMENT CATEGORIES
cat("\n--- 1. TEMPORAL PATTERNS BY DOCUMENT CATEGORIES ---\n")

# Check available categories
cat("Examining category information...\n")
category_info <- dbGetQuery(con, "
  SELECT 
    categoria_original,
    extracted_category,
    COUNT(*) as count
  FROM documents
  WHERE data IS NOT NULL
  GROUP BY categoria_original, extracted_category
  ORDER BY count DESC
  LIMIT 20;
")

print("Top 20 categories by document count:")
print(category_info)

# Temporal distribution by extracted category (if available)
if (any(!is.na(category_info$extracted_category))) {
  category_temporal <- dbGetQuery(con, "
    SELECT 
      extracted_category,
      EXTRACT(YEAR FROM data)::integer as year,
      COUNT(*) as document_count
    FROM documents
    WHERE data IS NOT NULL AND extracted_category IS NOT NULL
    GROUP BY extracted_category, EXTRACT(YEAR FROM data)
    ORDER BY extracted_category, year;
  ")
  
  cat("Temporal distribution by extracted categories available.\n")
  cat("Categories found:", length(unique(category_temporal$extracted_category)), "\n")
  cat("Years covered:", min(category_temporal$year), "to", max(category_temporal$year), "\n")
  
  # Top categories by total count
  top_categories <- dbGetQuery(con, "
    SELECT 
      extracted_category,
      COUNT(*) as total_count,
      MIN(EXTRACT(YEAR FROM data)) as earliest_year,
      MAX(EXTRACT(YEAR FROM data)) as latest_year
    FROM documents
    WHERE data IS NOT NULL AND extracted_category IS NOT NULL
    GROUP BY extracted_category
    ORDER BY total_count DESC
    LIMIT 10;
  ")
  
  print("\nTop 10 categories by document count:")
  print(top_categories)
}

# Temporal distribution by document type
doc_type_temporal <- dbGetQuery(con, "
  SELECT 
    tipo,
    EXTRACT(YEAR FROM data)::integer as year,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL AND tipo IS NOT NULL
  GROUP BY tipo, EXTRACT(YEAR FROM data)
  ORDER BY tipo, year;
")

if (nrow(doc_type_temporal) > 0) {
  cat("\nDocument types temporal distribution:\n")
  cat("Types found:", length(unique(doc_type_temporal$tipo)), "\n")
  
  # Top types by count
  top_types <- dbGetQuery(con, "
    SELECT 
      tipo,
      COUNT(*) as total_count,
      MIN(EXTRACT(YEAR FROM data)) as earliest_year,
      MAX(EXTRACT(YEAR FROM data)) as latest_year
    FROM documents
    WHERE data IS NOT NULL AND tipo IS NOT NULL
    GROUP BY tipo
    ORDER BY total_count DESC
    LIMIT 10;
  ")
  
  print("Top 10 document types by count:")
  print(top_types)
}

# 2. TEMPORAL PATTERNS BY JURISDICTIONS
cat("\n--- 2. TEMPORAL PATTERNS BY JURISDICTIONS ---\n")

# Country distribution over time
country_temporal <- dbGetQuery(con, "
  SELECT 
    pais,
    EXTRACT(YEAR FROM data)::integer as year,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL AND pais IS NOT NULL
  GROUP BY pais, EXTRACT(YEAR FROM data)
  ORDER BY pais, year;
")

if (nrow(country_temporal) > 0) {
  cat("Countries temporal distribution:\n")
  
  country_summary <- dbGetQuery(con, "
    SELECT 
      pais,
      COUNT(*) as total_count,
      MIN(EXTRACT(YEAR FROM data)) as earliest_year,
      MAX(EXTRACT(YEAR FROM data)) as latest_year
    FROM documents
    WHERE data IS NOT NULL AND pais IS NOT NULL
    GROUP BY pais
    ORDER BY total_count DESC;
  ")
  
  print("Countries by document count:")
  print(country_summary)
}

# State (estado) distribution over time for Brazil
state_temporal <- dbGetQuery(con, "
  SELECT 
    estado,
    EXTRACT(YEAR FROM data)::integer as year,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL AND estado IS NOT NULL
  GROUP BY estado, EXTRACT(YEAR FROM data)
  ORDER BY estado, year;
")

if (nrow(state_temporal) > 0) {
  cat("\nBrazilian states temporal distribution:\n")
  
  state_summary <- dbGetQuery(con, "
    SELECT 
      estado,
      COUNT(*) as total_count,
      MIN(EXTRACT(YEAR FROM data)) as earliest_year,
      MAX(EXTRACT(YEAR FROM data)) as latest_year
    FROM documents
    WHERE data IS NOT NULL AND estado IS NOT NULL
    GROUP BY estado
    ORDER BY total_count DESC
    LIMIT 15;
  ")
  
  print("Top 15 states by document count:")
  print(state_summary)
}

# 3. RECENT VS HISTORICAL PATTERNS
cat("\n--- 3. RECENT VS HISTORICAL DOCUMENT PATTERNS ---\n")

# Compare different time periods
time_periods <- dbGetQuery(con, "
  SELECT 
    CASE 
      WHEN EXTRACT(YEAR FROM data) >= 2020 THEN '2020s (Current)'
      WHEN EXTRACT(YEAR FROM data) >= 2010 THEN '2010s'
      WHEN EXTRACT(YEAR FROM data) >= 2000 THEN '2000s'
      WHEN EXTRACT(YEAR FROM data) >= 1990 THEN '1990s'
      WHEN EXTRACT(YEAR FROM data) >= 1980 THEN '1980s'
      ELSE 'Pre-1980'
    END as period,
    COUNT(*) as document_count,
    COUNT(DISTINCT EXTRACT(YEAR FROM data)) as years_covered
  FROM documents
  WHERE data IS NOT NULL
  GROUP BY 
    CASE 
      WHEN EXTRACT(YEAR FROM data) >= 2020 THEN '2020s (Current)'
      WHEN EXTRACT(YEAR FROM data) >= 2010 THEN '2010s'
      WHEN EXTRACT(YEAR FROM data) >= 2000 THEN '2000s'
      WHEN EXTRACT(YEAR FROM data) >= 1990 THEN '1990s'
      WHEN EXTRACT(YEAR FROM data) >= 1980 THEN '1980s'
      ELSE 'Pre-1980'
    END
  ORDER BY document_count DESC;
")

print("Documents by time periods:")
print(time_periods)

# 4. TRANSPORT MODE TEMPORAL PATTERNS (if available)
cat("\n--- 4. TRANSPORT MODE TEMPORAL PATTERNS ---\n")

transport_check <- dbGetQuery(con, "
  SELECT COUNT(*) as count
  FROM documents
  WHERE extracted_transport_mode IS NOT NULL;
")

if (transport_check$count > 0) {
  transport_temporal <- dbGetQuery(con, "
    SELECT 
      extracted_transport_mode,
      EXTRACT(YEAR FROM data)::integer as year,
      COUNT(*) as document_count
    FROM documents
    WHERE data IS NOT NULL AND extracted_transport_mode IS NOT NULL
    GROUP BY extracted_transport_mode, EXTRACT(YEAR FROM data)
    ORDER BY extracted_transport_mode, year;
  ")
  
  transport_summary <- dbGetQuery(con, "
    SELECT 
      extracted_transport_mode,
      COUNT(*) as total_count,
      MIN(EXTRACT(YEAR FROM data)) as earliest_year,
      MAX(EXTRACT(YEAR FROM data)) as latest_year
    FROM documents
    WHERE data IS NOT NULL AND extracted_transport_mode IS NOT NULL
    GROUP BY extracted_transport_mode
    ORDER BY total_count DESC;
  ")
  
  print("Transport modes by document count:")
  print(transport_summary)
} else {
  cat("No transport mode data available.\n")
}

# 5. DATA COLLECTION PATTERNS
cat("\n--- 5. DATA COLLECTION PATTERNS ---\n")

collection_patterns <- dbGetQuery(con, "
  SELECT 
    origem,
    COUNT(*) as document_count,
    MIN(EXTRACT(YEAR FROM data)) as earliest_doc_year,
    MAX(EXTRACT(YEAR FROM data)) as latest_doc_year
  FROM documents
  WHERE data IS NOT NULL AND origem IS NOT NULL
  GROUP BY origem
  ORDER BY document_count DESC
  LIMIT 10;
")

if (nrow(collection_patterns) > 0) {
  print("Top 10 data sources (origem):")
  print(collection_patterns)
}

cat("\nTemporal patterns analysis completed.\n")

# Close connection
dbDisconnect(con)