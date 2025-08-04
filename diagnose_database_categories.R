# ============================================================================
# DATABASE CATEGORY DIAGNOSTIC SCRIPT
# ============================================================================
# This script diagnoses the actual values in the database `tipo` and `categoria`
# columns to fix the sublibrary mapping issue where only Doctrine shows documents.

# Load required packages
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
})

cat("🔍 DATABASE CATEGORY DIAGNOSTIC SCRIPT\n")
cat("======================================\n")

# Source the database connection module
source("RAILWAY_PRODUCTION_DB_FIX.R")

# Function to run diagnostic queries
run_category_diagnostics <- function() {
  if (is.null(railway_db_pool) || connection_status$status != "connected") {
    cat("❌ Database not connected. Cannot run diagnostics.\n")
    return(FALSE)
  }
  
  cat("\n🔍 DIAGNOSTIC 1: Finding the main document table\n")
  cat("================================================\n")
  
  # Find which table has the most documents
  table_candidates <- c("lexml_parsed_enhanced", "documents", "legislative_data", "brazilian_legislative_complete")
  main_table <- NULL
  max_count <- 0
  
  for(table_name in table_candidates) {
    tryCatch({
      count_query <- sprintf("SELECT COUNT(*) as count FROM %s WHERE titulo IS NOT NULL AND titulo != ''", table_name)
      result <- dbGetQuery(railway_db_pool, count_query)
      
      if(nrow(result) > 0 && result$count > max_count) {
        max_count <- result$count  
        main_table <- table_name
        cat(sprintf("✅ Found table: %s with %s documents\n", table_name, format(result$count, big.mark = ",")))
      }
    }, error = function(e) {
      cat(sprintf("❌ Table %s: %s\n", table_name, e$message))
    })
  }
  
  if(is.null(main_table)) {
    cat("❌ No valid document table found!\n")
    return(FALSE)
  }
  
  cat(sprintf("\n🎯 Using main table: %s with %s documents\n", main_table, format(max_count, big.mark = ",")))
  
  cat("\n🔍 DIAGNOSTIC 2: Examining table structure\n")
  cat("==========================================\n")
  
  # Check table columns
  tryCatch({
    column_query <- sprintf("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '%s' ORDER BY ordinal_position", main_table)
    columns <- dbGetQuery(railway_db_pool, column_query)
    
    cat("📋 Table columns:\n")
    for(i in 1:nrow(columns)) {
      cat(sprintf("  - %s (%s)\n", columns$column_name[i], columns$data_type[i]))
    }
  }, error = function(e) {
    cat(sprintf("❌ Error getting columns: %s\n", e$message))
  })
  
  cat("\n🔍 DIAGNOSTIC 3: Analyzing 'tipo' column values\n")
  cat("===============================================\n")
  
  # Get unique values from 'tipo' column
  tryCatch({
    tipo_query <- sprintf("SELECT tipo, COUNT(*) as count FROM %s WHERE tipo IS NOT NULL GROUP BY tipo ORDER BY count DESC LIMIT 50", main_table)
    tipo_values <- dbGetQuery(railway_db_pool, tipo_query)
    
    cat("📊 Top 'tipo' values:\n")
    for(i in 1:min(nrow(tipo_values), 50)) {
      cat(sprintf("  %2d. %-40s : %s documents\n", i, tipo_values$tipo[i], format(tipo_values$count[i], big.mark = ",")))
    }
    
    cat(sprintf("\n📈 Total unique 'tipo' values: %d\n", nrow(tipo_values)))
    cat(sprintf("📊 Total documents with 'tipo': %s\n", format(sum(tipo_values$count), big.mark = ",")))
    
  }, error = function(e) {
    cat(sprintf("❌ Error analyzing 'tipo' column: %s\n", e$message))
  })
  
  cat("\n🔍 DIAGNOSTIC 4: Analyzing 'categoria' column (if exists)\n")
  cat("=========================================================\n")
  
  # Check if categoria column exists and analyze it
  tryCatch({
    # First check if categoria column exists
    col_check <- sprintf("SELECT column_name FROM information_schema.columns WHERE table_name = '%s' AND column_name = 'categoria'", main_table)
    col_exists <- dbGetQuery(railway_db_pool, col_check)
    
    if(nrow(col_exists) > 0) {
      categoria_query <- sprintf("SELECT categoria, COUNT(*) as count FROM %s WHERE categoria IS NOT NULL GROUP BY categoria ORDER BY count DESC LIMIT 50", main_table)
      categoria_values <- dbGetQuery(railway_db_pool, categoria_query)
      
      cat("📊 Top 'categoria' values:\n")
      for(i in 1:min(nrow(categoria_values), 50)) {
        cat(sprintf("  %2d. %-40s : %s documents\n", i, categoria_values$categoria[i], format(categoria_values$count[i], big.mark = ",")))
      }
      
      cat(sprintf("\n📈 Total unique 'categoria' values: %d\n", nrow(categoria_values)))
      cat(sprintf("📊 Total documents with 'categoria': %s\n", format(sum(categoria_values$count), big.mark = ",")))
      
    } else {
      cat("ℹ️ No 'categoria' column found in table\n")
    }
    
  }, error = function(e) {
    cat(sprintf("❌ Error analyzing 'categoria' column: %s\n", e$message))
  })
  
  cat("\n🔍 DIAGNOSTIC 5: Testing current category mapping logic\n")
  cat("======================================================\n")
  
  # Test current category mapping
  current_mapping <- list(
    "legislation" = c("Legislação", "Legislacao", "legislacao", "Lei", "Decreto", "Portaria", "Resolução", "Medida Provisória", "Lei Complementar", "Decreto Legislativo"),
    "jurisprudence" = c("Jurisprudência", "Jurisprudencia", "jurisprudencia", "ADPF", "ADI", "Acórdão", "Decisão", "Súmula", "Julgamento"),
    "doctrine" = c("Doutrina", "doutrina", "doctrine", "Livro", "Artigo de revista", "Tese", "Dissertação", "Monografia", "Análise", "Comentário")
  )
  
  for(category in names(current_mapping)) {
    tryCatch({
      values <- current_mapping[[category]]
      placeholders <- paste(sprintf("'%s'", values), collapse = ",")
      test_query <- sprintf("SELECT COUNT(*) as count FROM %s WHERE tipo IN (%s)", main_table, placeholders)
      result <- dbGetQuery(railway_db_pool, test_query)
      
      cat(sprintf("📊 %s: %s documents\n", 
                 toupper(category), 
                 format(result$count, big.mark = ",")))
      
    }, error = function(e) {
      cat(sprintf("❌ Error testing %s: %s\n", category, e$message))
    })
  }
  
  cat("\n🔍 DIAGNOSTIC 6: Sample document analysis\n")
  cat("=========================================\n")
  
  # Get a sample of documents to understand the data better
  tryCatch({
    sample_query <- sprintf("SELECT titulo, tipo, COALESCE(categoria, 'N/A') as categoria, estado FROM %s WHERE titulo IS NOT NULL LIMIT 20", main_table)
    sample_docs <- dbGetQuery(railway_db_pool, sample_query)
    
    cat("📋 Sample documents:\n")
    for(i in 1:nrow(sample_docs)) {
      cat(sprintf("%2d. TIPO: %-20s | CATEGORIA: %-15s | ESTADO: %-2s | TITULO: %s\n", 
                 i, 
                 substr(sample_docs$tipo[i], 1, 20),
                 substr(sample_docs$categoria[i], 1, 15),
                 sample_docs$estado[i],
                 substr(sample_docs$titulo[i], 1, 60)))
    }
    
  }, error = function(e) {
    cat(sprintf("❌ Error getting sample documents: %s\n", e$message))
  })
  
  cat("\n🔍 DIAGNOSTIC 7: Identifying patterns for better mapping\n")
  cat("=======================================================\n")
  
  # Look for patterns that might help us create better category mappings
  tryCatch({
    # Get documents that contain key legal terms
    patterns_to_test <- list(
      "Laws/Legislation" = c("lei", "decreto", "portaria", "resolução", "medida provisória"),
      "Jurisprudence" = c("acórdão", "decisão", "súmula", "julgamento", "adi", "adpf"),
      "Doctrine" = c("doutrina", "artigo", "livro", "tese", "dissertação", "comentário")
    )
    
    for(pattern_group in names(patterns_to_test)) {
      cat(sprintf("\n📋 %s patterns:\n", pattern_group))
      
      for(pattern in patterns_to_test[[pattern_group]]) {
        pattern_query <- sprintf("SELECT COUNT(*) as count FROM %s WHERE LOWER(tipo) LIKE '%%%s%%' OR LOWER(titulo) LIKE '%%%s%%'", 
                                main_table, tolower(pattern), tolower(pattern))
        result <- dbGetQuery(railway_db_pool, pattern_query)
        
        if(result$count > 0) {
          cat(sprintf("  - '%s': %s documents\n", pattern, format(result$count, big.mark = ",")))
        }
      }
    }
    
  }, error = function(e) {
    cat(sprintf("❌ Error analyzing patterns: %s\n", e$message))
  })
  
  cat("\n✅ DIAGNOSTIC COMPLETE\n")
  cat("======================\n")
  cat("Check the output above to understand:\n")
  cat("1. What values actually exist in the 'tipo' column\n")
  cat("2. How many documents match current mapping logic\n")
  cat("3. What patterns we can use for better categorization\n")
  cat("4. Sample documents to verify the mapping makes sense\n")
  
  return(TRUE)
}

# Run the diagnostics
cat("🚀 Starting database category diagnostics...\n")
success <- run_category_diagnostics()

if(!success) {
  cat("❌ Diagnostics failed. Check database connection.\n")
} else {
  cat("\n🎯 Next steps:\n")
  cat("1. Review the 'tipo' values above\n")
  cat("2. Create better category mappings based on actual data\n")
  cat("3. Update both app.R and RAILWAY_PRODUCTION_DB_FIX.R\n")
  cat("4. Test that all 3 sublibraries show documents\n")
}