# Municipality Data Analysis for Brazilian Legislative Monitoring System
# Author: Data Analysis Assistant
# Date: 2025-08-06

# Add user library path and load required libraries
.libPaths(c("~/R/library", .libPaths()))

# Load required libraries
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
cat("Connecting to PostgreSQL database...\n")
con <- dbConnect(PostgreSQL(),
                 host = db_host,
                 port = db_port,
                 dbname = db_name,
                 user = db_user,
                 password = db_password)

# Check if connection is successful
tryCatch({
  # Test connection with a simple query
  test_query <- dbGetQuery(con, "SELECT 1 as test")
  cat("Database connection established successfully!\n")
}, error = function(e) {
  stop("Failed to connect to database: ", e$message)
})

# 1. Examine the documents table structure
cat("\n=== DOCUMENTS TABLE STRUCTURE ===\n")
table_info <- dbGetQuery(con, "
  SELECT column_name, data_type, is_nullable, column_default
  FROM information_schema.columns 
  WHERE table_name = 'documents'
  ORDER BY ordinal_position;
")

print(table_info)

# Get total number of documents
total_docs <- dbGetQuery(con, "SELECT COUNT(*) as total FROM documents")$total
cat(sprintf("\nTotal documents in table: %s\n", format(total_docs, big.mark = ",")))

# 2. Analyze municipality data in the municipio column
cat("\n=== MUNICIPALITY COLUMN ANALYSIS ===\n")

# Get basic stats about municipio column
municipio_stats <- dbGetQuery(con, "
  SELECT 
    COUNT(*) as total_rows,
    COUNT(municipio) as non_null_municipio,
    COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as non_empty_municipio,
    COUNT(CASE WHEN municipio IS NULL THEN 1 END) as null_municipio,
    COUNT(CASE WHEN TRIM(municipio) = '' THEN 1 END) as empty_string_municipio
  FROM documents;
")

print(municipio_stats)

# Calculate percentages
coverage_pct <- round((municipio_stats$non_empty_municipio / municipio_stats$total_rows) * 100, 2)
cat(sprintf("Municipality data coverage: %.2f%%\n", coverage_pct))

# 3. Get all unique municipalities
cat("\n=== UNIQUE MUNICIPALITIES ===\n")
unique_municipios <- dbGetQuery(con, "
  SELECT 
    municipio,
    COUNT(*) as document_count,
    ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents WHERE municipio IS NOT NULL AND TRIM(municipio) != '')), 2) as percentage
  FROM documents 
  WHERE municipio IS NOT NULL AND TRIM(municipio) != ''
  GROUP BY municipio
  ORDER BY document_count DESC;
")

cat(sprintf("Total unique municipalities found: %d\n", nrow(unique_municipios)))
print(head(unique_municipios, 20))

# 4. Analyze document types with municipality data
cat("\n=== DOCUMENT TYPES WITH MUNICIPALITY DATA ===\n")
doc_types_municipio <- dbGetQuery(con, "
  SELECT 
    tipo_documento,
    COUNT(*) as total_docs,
    COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as with_municipio,
    ROUND((COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) * 100.0 / COUNT(*)), 2) as municipio_coverage_pct
  FROM documents
  WHERE tipo_documento IS NOT NULL
  GROUP BY tipo_documento
  ORDER BY with_municipio DESC;
")

print(doc_types_municipio)

# 5. Check for data quality issues
cat("\n=== DATA QUALITY ASSESSMENT ===\n")

# Check for common data quality issues
quality_check <- dbGetQuery(con, "
  SELECT 
    'Total records' as issue_type,
    COUNT(*) as count
  FROM documents
  
  UNION ALL
  
  SELECT 
    'NULL municipio' as issue_type,
    COUNT(*) as count
  FROM documents
  WHERE municipio IS NULL
  
  UNION ALL
  
  SELECT 
    'Empty string municipio' as issue_type,
    COUNT(*) as count
  FROM documents
  WHERE municipio = ''
  
  UNION ALL
  
  SELECT 
    'Whitespace only municipio' as issue_type,
    COUNT(*) as count
  FROM documents
  WHERE municipio IS NOT NULL AND TRIM(municipio) = ''
  
  UNION ALL
  
  SELECT 
    'Very short municipio (1-2 chars)' as issue_type,
    COUNT(*) as count
  FROM documents
  WHERE municipio IS NOT NULL AND LENGTH(TRIM(municipio)) BETWEEN 1 AND 2
  
  UNION ALL
  
  SELECT 
    'Very long municipio (>50 chars)' as issue_type,
    COUNT(*) as count
  FROM documents
  WHERE municipio IS NOT NULL AND LENGTH(municipio) > 50;
")

print(quality_check)

# Check for potential encoding issues or special characters
encoding_check <- dbGetQuery(con, "
  SELECT 
    municipio,
    COUNT(*) as count,
    LENGTH(municipio) as length
  FROM documents
  WHERE municipio IS NOT NULL 
    AND (municipio ~ '[^a-zA-ZÀ-ÿ\\s\\-\\.]' OR LENGTH(municipio) > 50)
  GROUP BY municipio, LENGTH(municipio)
  ORDER BY count DESC
  LIMIT 20;
")

if (nrow(encoding_check) > 0) {
  cat("\n=== POTENTIAL ENCODING/SPECIAL CHARACTER ISSUES ===\n")
  print(encoding_check)
}

# 6. Investigate related location columns
cat("\n=== RELATED LOCATION COLUMNS ANALYSIS ===\n")

# Check what location-related columns exist and their coverage
location_columns <- c("localidade", "estado", "jurisdicao_original")

for (col in location_columns) {
  # Check if column exists
  col_exists <- dbGetQuery(con, paste0("
    SELECT column_name 
    FROM information_schema.columns 
    WHERE table_name = 'documents' AND column_name = '", col, "';
  "))
  
  if (nrow(col_exists) > 0) {
    cat(sprintf("\n--- %s COLUMN ---\n", toupper(col)))
    
    col_stats <- dbGetQuery(con, paste0("
      SELECT 
        COUNT(*) as total_rows,
        COUNT(", col, ") as non_null_values,
        COUNT(CASE WHEN ", col, " IS NOT NULL AND TRIM(", col, ") != '' THEN 1 END) as non_empty_values
      FROM documents;
    "))
    
    coverage <- round((col_stats$non_empty_values / col_stats$total_rows) * 100, 2)
    cat(sprintf("Coverage: %.2f%% (%s of %s documents)\n", 
                coverage, 
                format(col_stats$non_empty_values, big.mark = ","),
                format(col_stats$total_rows, big.mark = ",")))
    
    # Get top values for this column
    top_values <- dbGetQuery(con, paste0("
      SELECT 
        ", col, " as value,
        COUNT(*) as count
      FROM documents 
      WHERE ", col, " IS NOT NULL AND TRIM(", col, ") != ''
      GROUP BY ", col, "
      ORDER BY count DESC
      LIMIT 10;
    "))
    
    if (nrow(top_values) > 0) {
      cat("Top values:\n")
      print(top_values)
    }
  } else {
    cat(sprintf("Column '%s' does not exist in documents table\n", col))
  }
}

# 7. Cross-analysis: Documents with multiple location fields
cat("\n=== CROSS-LOCATION ANALYSIS ===\n")

# Check how many documents have multiple location fields populated
cross_location <- dbGetQuery(con, "
  SELECT 
    CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 ELSE 0 END +
    CASE WHEN localidade IS NOT NULL AND TRIM(localidade) != '' THEN 1 ELSE 0 END +
    CASE WHEN estado IS NOT NULL AND TRIM(estado) != '' THEN 1 ELSE 0 END +
    CASE WHEN jurisdicao_original IS NOT NULL AND TRIM(jurisdicao_original) != '' THEN 1 ELSE 0 END 
    as location_fields_count,
    COUNT(*) as document_count
  FROM documents
  GROUP BY 1
  ORDER BY 1;
")

if (nrow(cross_location) > 0) {
  cat("Distribution of documents by number of populated location fields:\n")
  print(cross_location)
}

# 8. Generate summary statistics for visualization
cat("\n=== PREPARING DATA FOR VISUALIZATIONS ===\n")

# Close database connection
dbDisconnect(con)
cat("Database connection closed.\n")

cat("\n=== ANALYSIS COMPLETE ===\n")
cat("Municipality data analysis has been completed.\n")
cat("Key findings:\n")
cat(sprintf("- Total documents: %s\n", format(total_docs, big.mark = ",")))
cat(sprintf("- Municipality coverage: %.2f%%\n", coverage_pct))
cat(sprintf("- Unique municipalities: %d\n", nrow(unique_municipios)))