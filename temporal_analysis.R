# Brazilian Legislative Monitoring System - Temporal Data Analysis
# Author: Data Science Analysis
# Date: 2025-08-06

# Set library path to personal library
.libPaths('~/R/library')

# Load required libraries (already installed)
suppressMessages({
  library(DBI)
  library(RPostgres)
  library(dplyr)
  library(ggplot2)
  library(lubridate)
  library(scales)
})

# Database connection parameters
db_host <- "nozomi.proxy.rlwy.net"
db_port <- 44844
db_name <- "railway"
db_user <- "postgres"
db_password <- "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"

# Establish database connection
cat("Connecting to PostgreSQL database...\n")
con <- dbConnect(RPostgres::Postgres(),
                 host = db_host,
                 port = db_port,
                 dbname = db_name,
                 user = db_user,
                 password = db_password)

# Check connection
if (dbIsValid(con)) {
  cat("Database connection successful!\n")
} else {
  stop("Failed to connect to database")
}

# First, let's examine the table structure
cat("\n=== EXAMINING TABLE STRUCTURE ===\n")
table_info <- dbGetQuery(con, "
  SELECT column_name, data_type, is_nullable
  FROM information_schema.columns 
  WHERE table_name = 'documents' 
  ORDER BY ordinal_position;
")

print(table_info)

# Check for temporal columns specifically
temporal_columns <- table_info[grep("data|ano|date|time", table_info$column_name, ignore.case = TRUE), ]
cat("\nTemporal columns found:\n")
print(temporal_columns)

# Get basic table statistics
cat("\n=== BASIC TABLE STATISTICS ===\n")
total_docs <- dbGetQuery(con, "SELECT COUNT(*) as total_documents FROM documents;")
cat("Total documents:", total_docs$total_documents, "\n")

# Examine the temporal fields
cat("\n=== EXAMINING TEMPORAL FIELDS ===\n")

# Check if data_publicacao exists
columns_exist <- dbGetQuery(con, "
  SELECT column_name 
  FROM information_schema.columns 
  WHERE table_name = 'documents' 
  AND column_name IN ('data', 'data_publicacao', 'ano')
")

print("Available temporal columns:")
print(columns_exist$column_name)

# Sample data to understand the format
cat("\nSample data from temporal fields:\n")
sample_data <- dbGetQuery(con, "
  SELECT data, ano, 
         CASE WHEN EXISTS (
           SELECT 1 FROM information_schema.columns 
           WHERE table_name = 'documents' AND column_name = 'data_publicacao'
         ) THEN data_publicacao ELSE NULL END as data_publicacao
  FROM documents 
  WHERE data IS NOT NULL 
  LIMIT 10;
")

print(sample_data)

cat("\nScript initialized. Ready for detailed temporal analysis...\n")

# ===== DETAILED TEMPORAL ANALYSIS =====

cat("\n=== COMPREHENSIVE TEMPORAL ANALYSIS ===\n")

# Fix the document count issue
correct_count <- dbGetQuery(con, "SELECT COUNT(*) as total_documents FROM documents;")
cat("Corrected total documents:", as.numeric(correct_count$total_documents), "\n")

# 1. TEMPORAL COVERAGE ANALYSIS
cat("\n--- 1. TEMPORAL COVERAGE ANALYSIS ---\n")

# Basic date range statistics
date_stats <- dbGetQuery(con, "
  SELECT 
    MIN(data) as earliest_date,
    MAX(data) as latest_date,
    COUNT(data) as valid_dates,
    COUNT(*) - COUNT(data) as null_dates,
    ROUND(100.0 * COUNT(data) / COUNT(*), 2) as date_coverage_pct
  FROM documents;
")

print("Date Coverage Statistics:")
print(date_stats)

# Year range from ano column
year_stats <- dbGetQuery(con, "
  SELECT 
    MIN(ano) as earliest_year,
    MAX(ano) as latest_year,
    COUNT(ano) as valid_years,
    COUNT(*) - COUNT(ano) as null_years,
    ROUND(100.0 * COUNT(ano) / COUNT(*), 2) as year_coverage_pct
  FROM documents
  WHERE ano IS NOT NULL;
")

print("\nYear Column Statistics:")
print(year_stats)

# Compare data vs data_publicacao
pub_date_stats <- dbGetQuery(con, "
  SELECT 
    MIN(data_publicacao) as earliest_pub_date,
    MAX(data_publicacao) as latest_pub_date,
    COUNT(data_publicacao) as valid_pub_dates,
    ROUND(100.0 * COUNT(data_publicacao) / COUNT(*), 2) as pub_date_coverage_pct
  FROM documents;
")

print("\nPublication Date Statistics:")
print(pub_date_stats)

# 2. YEAR-BY-YEAR DOCUMENT COUNTS
cat("\n--- 2. YEAR-BY-YEAR DOCUMENT COUNTS ---\n")

# Extract year from date and compare with ano column
yearly_counts <- dbGetQuery(con, "
  SELECT 
    EXTRACT(YEAR FROM data)::integer as year_from_date,
    ano as year_from_ano_col,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL
  GROUP BY EXTRACT(YEAR FROM data), ano
  ORDER BY year_from_date;
")

# Aggregate yearly counts from data field
yearly_summary <- dbGetQuery(con, "
  SELECT 
    EXTRACT(YEAR FROM data)::integer as year,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL
  GROUP BY EXTRACT(YEAR FROM data)
  ORDER BY year;
")

print("Top 10 years by document count:")
print(head(yearly_summary[order(-yearly_summary$document_count),], 10))

print("\nMost recent 10 years:")
print(tail(yearly_summary, 10))

print("\nOldest 10 years:")
print(head(yearly_summary, 10))

# 3. DECADE ANALYSIS
cat("\n--- 3. DECADE ANALYSIS ---\n")

decade_analysis <- dbGetQuery(con, "
  SELECT 
    FLOOR(EXTRACT(YEAR FROM data) / 10) * 10 as decade,
    COUNT(*) as document_count,
    ROUND(100.0 * COUNT(*) / NULLIF((SELECT COUNT(*) FROM documents WHERE data IS NOT NULL), 0), 2) as percentage
  FROM documents
  WHERE data IS NOT NULL
  GROUP BY FLOOR(EXTRACT(YEAR FROM data) / 10) * 10
  ORDER BY decade;
")

print("Documents by Decade:")
print(decade_analysis)

# 4. DATA QUALITY ISSUES
cat("\n--- 4. DATA QUALITY ISSUES ---\n")

# Future dates (after current date)
future_dates <- dbGetQuery(con, "
  SELECT COUNT(*) as future_date_count
  FROM documents
  WHERE data > CURRENT_DATE;
")

print(paste("Documents with future dates:", future_dates$future_date_count))

# Very old dates (before 1800 - unlikely for legislative documents)
very_old_dates <- dbGetQuery(con, "
  SELECT COUNT(*) as very_old_count
  FROM documents
  WHERE EXTRACT(YEAR FROM data) < 1800;
")

print(paste("Documents with dates before 1800:", very_old_dates$very_old_count))

# Inconsistency between data and ano columns
ano_data_inconsistency <- dbGetQuery(con, "
  SELECT COUNT(*) as inconsistent_count
  FROM documents
  WHERE data IS NOT NULL 
    AND ano IS NOT NULL 
    AND EXTRACT(YEAR FROM data) != ano;
")

print(paste("Documents with inconsistent year data:", ano_data_inconsistency$inconsistent_count))

# Sample of problematic dates
if (ano_data_inconsistency$inconsistent_count > 0) {
  inconsistent_sample <- dbGetQuery(con, "
    SELECT data, ano, EXTRACT(YEAR FROM data) as year_from_date, titulo
    FROM documents
    WHERE data IS NOT NULL 
      AND ano IS NOT NULL 
      AND EXTRACT(YEAR FROM data) != ano
    LIMIT 5;
  ")
  
  print("Sample of inconsistent year data:")
  print(inconsistent_sample)
}

cat("\nCompleting temporal field analysis...\n")