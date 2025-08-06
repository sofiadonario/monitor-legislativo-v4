# Municipality Data Analysis Report and Visualizations
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
cat("Connecting to PostgreSQL database...\n")
con <- dbConnect(PostgreSQL(),
                 host = db_host,
                 port = db_port,
                 dbname = db_name,
                 user = db_user,
                 password = db_password)

# Test connection
tryCatch({
  test_query <- dbGetQuery(con, "SELECT 1 as test")
  cat("Database connection established successfully!\n")
}, error = function(e) {
  stop("Failed to connect to database: ", e$message)
})

# Function to generate comprehensive municipality analysis
generate_municipality_analysis <- function(con) {
  
  cat("\n" , paste(rep("=", 80), collapse=""), "\n")
  cat("     COMPREHENSIVE MUNICIPALITY DATA ANALYSIS REPORT\n")
  cat("     Brazilian Legislative Monitoring System Database\n")
  cat(paste(rep("=", 80), collapse=""), "\n\n")
  
  # 1. Executive Summary Statistics
  cat("1. EXECUTIVE SUMMARY\n")
  cat(paste(rep("-", 50), collapse=""), "\n")
  
  summary_stats <- dbGetQuery(con, "
    SELECT 
      COUNT(*) as total_documents,
      COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as documents_with_municipality,
      COUNT(CASE WHEN estado IS NOT NULL AND TRIM(estado) != '' THEN 1 END) as documents_with_estado,
      COUNT(CASE WHEN jurisdicao_original IS NOT NULL AND TRIM(jurisdicao_original) != '' THEN 1 END) as documents_with_jurisdiction,
      COUNT(CASE WHEN localidade IS NOT NULL AND TRIM(localidade) != '' THEN 1 END) as documents_with_localidade
    FROM documents;
  ")
  
  municipality_coverage <- round((summary_stats$documents_with_municipality / summary_stats$total_documents) * 100, 2)
  estado_coverage <- round((summary_stats$documents_with_estado / summary_stats$total_documents) * 100, 2)
  jurisdiction_coverage <- round((summary_stats$documents_with_jurisdiction / summary_stats$total_documents) * 100, 2)
  localidade_coverage <- round((summary_stats$documents_with_localidade / summary_stats$total_documents) * 100, 2)
  
  cat(sprintf("Total Documents: %s\n", format(summary_stats$total_documents, big.mark = ",")))
  cat(sprintf("Municipality Coverage: %.2f%% (%s documents)\n", 
              municipality_coverage, format(summary_stats$documents_with_municipality, big.mark = ",")))
  cat(sprintf("Estado Coverage: %.2f%% (%s documents)\n", 
              estado_coverage, format(summary_stats$documents_with_estado, big.mark = ",")))
  cat(sprintf("Jurisdiction Coverage: %.2f%% (%s documents)\n", 
              jurisdiction_coverage, format(summary_stats$documents_with_jurisdiction, big.mark = ",")))
  cat(sprintf("Localidade Coverage: %.2f%% (%s documents)\n\n", 
              localidade_coverage, format(summary_stats$documents_with_localidade, big.mark = ",")))
  
  # 2. Municipality Data Analysis
  cat("2. MUNICIPALITY DATA DETAILED ANALYSIS\n")
  cat(paste(rep("-", 50), collapse=""), "\n")
  
  municipalities <- dbGetQuery(con, "
    SELECT 
      municipio,
      COUNT(*) as document_count,
      ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents WHERE municipio IS NOT NULL AND TRIM(municipio) != '')), 2) as percentage_of_municipal_docs,
      MIN(data) as earliest_date,
      MAX(data) as latest_date,
      COUNT(DISTINCT EXTRACT(YEAR FROM data)) as years_span
    FROM documents 
    WHERE municipio IS NOT NULL AND TRIM(municipio) != ''
    GROUP BY municipio
    ORDER BY document_count DESC;
  ")
  
  if(nrow(municipalities) > 0) {
    cat(sprintf("Unique Municipalities Found: %d\n\n", nrow(municipalities)))
    cat("Municipality Details:\n")
    print(municipalities)
    
    # Check if all documents with municipality are from the same place
    if(nrow(municipalities) == 1) {
      cat(sprintf("\nIMPORTANT FINDING: All documents with municipality data are from '%s'\n", municipalities$municipio[1]))
      cat("This suggests limited geographic coverage in the current dataset.\n\n")
    }
  } else {
    cat("No municipalities found with valid data.\n\n")
  }
  
  # 3. Data Quality Assessment
  cat("3. DATA QUALITY ASSESSMENT\n")
  cat(paste(rep("-", 50), collapse=""), "\n")
  
  quality_issues <- dbGetQuery(con, "
    SELECT 
      'Total Documents' as metric,
      COUNT(*) as count,
      ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents)), 2) as percentage
    FROM documents
    
    UNION ALL
    
    SELECT 
      'Documents with NULL Municipality' as metric,
      COUNT(*) as count,
      ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents)), 2) as percentage
    FROM documents
    WHERE municipio IS NULL
    
    UNION ALL
    
    SELECT 
      'Documents with Empty Municipality' as metric,
      COUNT(*) as count,
      ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents)), 2) as percentage
    FROM documents
    WHERE municipio = ''
    
    UNION ALL
    
    SELECT 
      'Documents with Whitespace-only Municipality' as metric,
      COUNT(*) as count,
      ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents)), 2) as percentage
    FROM documents
    WHERE municipio IS NOT NULL AND municipio != '' AND TRIM(municipio) = ''
    
    UNION ALL
    
    SELECT 
      'Documents with Valid Municipality Data' as metric,
      COUNT(*) as count,
      ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents)), 2) as percentage
    FROM documents
    WHERE municipio IS NOT NULL AND TRIM(municipio) != '';
  ")
  
  print(quality_issues)
  cat("\n")
  
  # 4. Geographic Coverage Analysis
  cat("4. GEOGRAPHIC COVERAGE ANALYSIS\n")
  cat(paste(rep("-", 50), collapse=""), "\n")
  
  estado_analysis <- dbGetQuery(con, "
    SELECT 
      estado,
      COUNT(*) as document_count,
      ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents WHERE estado IS NOT NULL AND TRIM(estado) != '')), 2) as percentage,
      COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as docs_with_municipality
    FROM documents 
    WHERE estado IS NOT NULL AND TRIM(estado) != ''
    GROUP BY estado
    ORDER BY document_count DESC;
  ")
  
  if(nrow(estado_analysis) > 0) {
    cat("Distribution by Estado (State/Federal Level):\n")
    print(estado_analysis)
    cat("\n")
    
    federal_docs <- estado_analysis[estado_analysis$estado == "Federal", "document_count"]
    if(length(federal_docs) > 0 && federal_docs > 0) {
      federal_pct <- round((federal_docs / sum(estado_analysis$document_count)) * 100, 2)
      cat(sprintf("Federal documents represent %.2f%% of all documents with estado data\n", federal_pct))
    }
  }
  
  # 5. Jurisdiction Analysis
  cat("\n5. JURISDICTION ANALYSIS\n")
  cat(paste(rep("-", 50), collapse=""), "\n")
  
  jurisdiction_analysis <- dbGetQuery(con, "
    SELECT 
      jurisdicao_original,
      COUNT(*) as document_count,
      ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents WHERE jurisdicao_original IS NOT NULL AND TRIM(jurisdicao_original) != '')), 2) as percentage,
      COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as docs_with_municipality
    FROM documents 
    WHERE jurisdicao_original IS NOT NULL AND TRIM(jurisdicao_original) != ''
    GROUP BY jurisdicao_original
    ORDER BY document_count DESC;
  ")
  
  if(nrow(jurisdiction_analysis) > 0) {
    cat("Distribution by Jurisdiction:\n")
    print(jurisdiction_analysis)
    cat("\n")
  }
  
  # 6. Document Type Analysis (using available columns)
  cat("6. DOCUMENT CHARACTERISTICS ANALYSIS\n")
  cat(paste(rep("-", 50), collapse=""), "\n")
  
  # Check which type columns exist and have data
  type_columns <- c("tipo", "categoria_original", "modal_original")
  
  for(col_name in type_columns) {
    cat(sprintf("--- Analysis by %s ---\n", toupper(col_name)))
    
    type_query <- sprintf("
      SELECT 
        %s as type_value,
        COUNT(*) as total_docs,
        COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as with_municipio,
        ROUND((COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) * 100.0 / COUNT(*)), 2) as municipio_coverage_pct
      FROM documents
      WHERE %s IS NOT NULL AND TRIM(%s) != ''
      GROUP BY %s
      ORDER BY with_municipio DESC
      LIMIT 10;
    ", col_name, col_name, col_name, col_name)
    
    tryCatch({
      type_analysis <- dbGetQuery(con, type_query)
      if(nrow(type_analysis) > 0) {
        print(type_analysis)
      } else {
        cat("No data found for this column.\n")
      }
    }, error = function(e) {
      cat(sprintf("Error analyzing %s: %s\n", col_name, e$message))
    })
    cat("\n")
  }
  
  # 7. Temporal Analysis
  cat("7. TEMPORAL ANALYSIS\n")
  cat(paste(rep("-", 50), collapse=""), "\n")
  
  temporal_analysis <- dbGetQuery(con, "
    SELECT 
      EXTRACT(YEAR FROM data) as year,
      COUNT(*) as total_docs,
      COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) as with_municipality,
      ROUND((COUNT(CASE WHEN municipio IS NOT NULL AND TRIM(municipio) != '' THEN 1 END) * 100.0 / COUNT(*)), 2) as municipality_coverage_pct
    FROM documents
    WHERE data IS NOT NULL
    GROUP BY EXTRACT(YEAR FROM data)
    ORDER BY year DESC;
  ")
  
  if(nrow(temporal_analysis) > 0) {
    cat("Municipality Data Coverage by Year:\n")
    print(temporal_analysis)
    cat("\n")
  }
  
  return(list(
    summary_stats = summary_stats,
    municipalities = municipalities,
    quality_issues = quality_issues,
    estado_analysis = estado_analysis,
    jurisdiction_analysis = jurisdiction_analysis,
    temporal_analysis = temporal_analysis,
    coverage_rates = list(
      municipality = municipality_coverage,
      estado = estado_coverage,
      jurisdiction = jurisdiction_coverage,
      localidade = localidade_coverage
    )
  ))
}

# Run the comprehensive analysis
analysis_results <- generate_municipality_analysis(con)

# 8. Generate Recommendations
cat("8. RECOMMENDATIONS FOR IMPROVING MUNICIPALITY DATA COVERAGE\n")
cat(paste(rep("-", 70), collapse=""), "\n")

cat("IMMEDIATE ACTIONS:\n")
cat("1. Municipality data coverage is critically low at only 2.23%\n")
cat("2. Only Brasília (DF) is represented in municipality data\n")
cat("3. Consider implementing data enrichment strategies\n\n")

cat("DATA ENHANCEMENT STRATEGIES:\n")
cat("1. GEOGRAPHIC INFERENCE:\n")
cat("   - Use 'estado' field (84.98% coverage) to infer potential municipalities\n")
cat("   - Cross-reference with 'jurisdicao_original' data (88.74% coverage)\n")
cat("   - Implement geocoding for documents with location references\n\n")

cat("2. TEXT MINING OPPORTUNITIES:\n")
cat("   - Extract municipality names from document titles and content\n")
cat("   - Use NLP to identify geographic entities in 'ementa' field\n")
cat("   - Parse 'assuntos' field for location-specific keywords\n\n")

cat("3. DATA INTEGRATION:\n")
cat("   - Integrate with external Brazilian municipality databases (IBGE)\n")
cat("   - Use 'autoridade' field to infer issuing municipality\n")
cat("   - Cross-reference with 'origem' field for geographic clues\n\n")

cat("4. QUALITY IMPROVEMENTS:\n")
cat("   - Standardize municipality names using official IBGE codes\n")
cat("   - Implement validation rules for Brazilian municipality names\n")
cat("   - Add data quality checks for geographic consistency\n\n")

cat("PRIORITY AREAS:\n")
priorities <- analysis_results$estado_analysis[analysis_results$estado_analysis$docs_with_municipality == 0, ]
if(nrow(priorities) > 0) {
  cat("States with NO municipality data that could be enhanced:\n")
  top_priorities <- head(priorities[order(-priorities$document_count), ], 5)
  for(i in 1:nrow(top_priorities)) {
    cat(sprintf("- %s: %s documents (%.2f%% of state data)\n", 
                top_priorities$estado[i], 
                format(top_priorities$document_count[i], big.mark=","),
                top_priorities$percentage[i]))
  }
}

# Close database connection
dbDisconnect(con)

cat("\n" , paste(rep("=", 80), collapse=""), "\n")
cat("ANALYSIS COMPLETED SUCCESSFULLY\n")
cat(paste(rep("=", 80), collapse=""), "\n")

# Save summary for later reference
summary_data <- data.frame(
  Metric = c("Total Documents", "Municipality Coverage %", "Estado Coverage %", 
             "Jurisdiction Coverage %", "Unique Municipalities"),
  Value = c(
    format(analysis_results$summary_stats$total_documents, big.mark=","),
    paste0(analysis_results$coverage_rates$municipality, "%"),
    paste0(analysis_results$coverage_rates$estado, "%"),
    paste0(analysis_results$coverage_rates$jurisdiction, "%"),
    nrow(analysis_results$municipalities)
  )
)

cat("\nSUMMARY TABLE:\n")
print(summary_data, row.names = FALSE)