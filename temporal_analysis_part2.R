# Brazilian Legislative Monitoring System - Temporal Analysis Part 2
# Continuing from where part 1 left off
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

cat("Connected. Continuing temporal analysis...\n")

# ===== CONTINUING TEMPORAL ANALYSIS =====

# 2. YEAR-BY-YEAR DOCUMENT COUNTS (Safe queries)
cat("\n--- 2. YEAR-BY-YEAR DOCUMENT COUNTS ---\n")

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

cat("Total years with data:", nrow(yearly_summary), "\n")
cat("Date range:", min(yearly_summary$year), "to", max(yearly_summary$year), "\n")

print("Top 10 years by document count:")
top_years <- yearly_summary[order(-yearly_summary$document_count),]
print(head(top_years, 10))

print("\nMost recent 10 years:")
print(tail(yearly_summary, 10))

print("\nOldest 10 years:")
print(head(yearly_summary, 10))

# 3. DECADE ANALYSIS (Safer approach)
cat("\n--- 3. DECADE ANALYSIS ---\n")

# Calculate total with valid dates first
total_with_dates <- sum(yearly_summary$document_count)
cat("Total documents with valid dates:", total_with_dates, "\n")

decade_analysis <- dbGetQuery(con, "
  SELECT 
    FLOOR(EXTRACT(YEAR FROM data) / 10) * 10 as decade,
    COUNT(*) as document_count
  FROM documents
  WHERE data IS NOT NULL
  GROUP BY FLOOR(EXTRACT(YEAR FROM data) / 10) * 10
  ORDER BY decade;
")

# Add percentage calculation in R
decade_analysis$percentage <- round(100.0 * decade_analysis$document_count / total_with_dates, 2)

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

cat("Documents with future dates:", future_dates$future_date_count, "\n")

# Very old dates (before 1800 - unlikely for legislative documents)
very_old_dates <- dbGetQuery(con, "
  SELECT COUNT(*) as very_old_count
  FROM documents
  WHERE EXTRACT(YEAR FROM data) < 1800;
")

cat("Documents with dates before 1800:", very_old_dates$very_old_count, "\n")

# Sample of very old dates
if (very_old_dates$very_old_count > 0) {
  old_sample <- dbGetQuery(con, "
    SELECT data, EXTRACT(YEAR FROM data) as year, titulo
    FROM documents
    WHERE EXTRACT(YEAR FROM data) < 1800
    ORDER BY data
    LIMIT 10;
  ")
  
  print("Sample of very old dates:")
  print(old_sample)
}

# Check data_publicacao field
pub_date_stats <- dbGetQuery(con, "
  SELECT 
    MIN(data_publicacao) as earliest_pub_date,
    MAX(data_publicacao) as latest_pub_date,
    COUNT(data_publicacao) as valid_pub_dates,
    COUNT(*) - COUNT(data_publicacao) as null_pub_dates
  FROM documents;
")

print("\nPublication Date Statistics:")
print(pub_date_stats)

# Compare data vs data_publicacao where both exist
date_comparison <- dbGetQuery(con, "
  SELECT COUNT(*) as both_dates_count
  FROM documents
  WHERE data IS NOT NULL AND data_publicacao IS NOT NULL;
")

cat("\nDocuments with both data and data_publicacao:", date_comparison$both_dates_count, "\n")

if (date_comparison$both_dates_count > 0) {
  date_diff_stats <- dbGetQuery(con, "
    SELECT 
      AVG(data_publicacao - data) as avg_diff_days,
      MIN(data_publicacao - data) as min_diff_days,
      MAX(data_publicacao - data) as max_diff_days
    FROM documents
    WHERE data IS NOT NULL AND data_publicacao IS NOT NULL;
  ")
  
  print("Difference between data_publicacao and data (in days):")
  print(date_diff_stats)
}

cat("\nTemporal analysis part 2 completed.\n")