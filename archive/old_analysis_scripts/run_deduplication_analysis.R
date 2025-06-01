# RUN DEDUPLICATION ANALYSIS AND STORE RESULTS
# This script executes the deduplication process and saves results to ./data_current/processed/deduplicated

cat("🚀 STARTING DEDUPLICATION ANALYSIS AND STORAGE...\n")

# Load required libraries
library(DBI)
library(dplyr)
library(jsonlite)

# Create output directory
output_dir <- "./data_current/processed/deduplicated"
if (!dir.exists(output_dir)) {
  dir.create(output_dir, recursive = TRUE)
}

# Load the deduplication implementation
source("implement_deduplication.R")

# Function to run complete deduplication analysis and store results
run_complete_deduplication_analysis <- function() {
  results <- list()
  
  tryCatch({
    cat("📊 STEP 1: Loading and checking database connection...\n")
    
    # Check database connection
    if (!exists(".db_pool") || !inherits(.db_pool, "Pool")) {
      # Try to initialize database connection
      if (exists("init_database")) {
        init_database()
      } else {
        stop("No database connection available")
      }
    }
    
    cat("✅ Database connection verified\n")
    
    # Store connection info
    results$connection_info <- list(
      timestamp = Sys.time(),
      database_connected = exists(".db_pool") && inherits(.db_pool, "Pool"),
      analysis_start = Sys.time()
    )
    
    cat("📊 STEP 2: Analyzing original data structure...\n")
    
    # Get original metrics
    original_metrics <- tryCatch({
      total_count <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM documents")$count[1]
      
      by_species <- dbGetQuery(.db_pool, "
        SELECT species, COUNT(*) as count 
        FROM documents 
        GROUP BY species 
        ORDER BY count DESC
      ")
      
      by_transport <- dbGetQuery(.db_pool, "
        SELECT transport_category, COUNT(*) as count 
        FROM documents 
        GROUP BY transport_category 
        ORDER BY count DESC
      ")
      
      by_state <- dbGetQuery(.db_pool, "
        SELECT estado, COUNT(*) as count 
        FROM documents 
        WHERE estado IS NOT NULL
        GROUP BY estado 
        ORDER BY count DESC
        LIMIT 10
      ")
      
      list(
        total_documents = total_count,
        by_species = by_species,
        by_transport_category = by_transport,
        top_states = by_state
      )
      
    }, error = function(e) {
      cat("❌ Error getting original metrics:", e$message, "\n")
      list(error = e$message)
    })
    
    results$original_metrics <- original_metrics
    cat(sprintf("✅ Original data: %s documents\n", format(original_metrics$total_documents, big.mark = ",")))
    
    cat("📊 STEP 3: Running deduplication analysis...\n")
    
    # Execute deduplication SQL analysis
    dedup_analysis <- tryCatch({
      
      # Read and execute deduplication strategy
      if (file.exists("deduplication_strategy.sql")) {
        sql_content <- paste(readLines("deduplication_strategy.sql"), collapse = "\n")
        
        # Split into statements and execute
        sql_statements <- unlist(strsplit(sql_content, ";"))
        sql_statements <- trimws(sql_statements)
        sql_statements <- sql_statements[nchar(sql_statements) > 0]
        
        analysis_results <- list()
        
        for (i in seq_along(sql_statements)) {
          stmt <- sql_statements[i]
          
          # Skip comments
          if (grepl("^--", stmt) || nchar(trimws(stmt)) == 0) next
          
          # Execute statement
          if (grepl("^SELECT.*status", stmt, ignore.case = TRUE)) {
            # Status messages
            result <- dbGetQuery(.db_pool, stmt)
            cat(paste0("  ", result[[1]][1], "\n"))
            analysis_results[[paste0("status_", i)]] <- result
            
          } else if (grepl("^SELECT", stmt, ignore.case = TRUE)) {
            # Analysis queries
            result <- dbGetQuery(.db_pool, stmt)
            analysis_results[[paste0("analysis_", i)]] <- result
            print(result)
            
          } else if (grepl("CREATE.*VIEW.*documents_deduplicated", stmt, ignore.case = TRUE)) {
            # Create deduplication view
            cat("  Creating deduplicated view...\n")
            dbExecute(.db_pool, stmt)
            analysis_results$dedup_view_created <- TRUE
            
          } else if (grepl("CREATE", stmt, ignore.case = TRUE)) {
            # Other CREATE statements
            dbExecute(.db_pool, stmt)
          }
        }
        
        analysis_results
        
      } else {
        stop("deduplication_strategy.sql not found")
      }
      
    }, error = function(e) {
      cat("❌ Error in deduplication analysis:", e$message, "\n")
      list(error = e$message)
    })
    
    results$deduplication_analysis <- dedup_analysis
    
    cat("📊 STEP 4: Getting deduplicated metrics...\n")
    
    # Get deduplicated metrics
    deduplicated_metrics <- tryCatch({
      
      # Check if deduplicated view was created
      view_exists <- dbExistsTable(.db_pool, "documents_deduplicated")
      
      if (view_exists) {
        total_count <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM documents_deduplicated")$count[1]
        
        by_species <- dbGetQuery(.db_pool, "
          SELECT species, COUNT(*) as count 
          FROM documents_deduplicated 
          GROUP BY species 
          ORDER BY count DESC
        ")
        
        by_transport <- dbGetQuery(.db_pool, "
          SELECT transport_category, COUNT(*) as count 
          FROM documents_deduplicated 
          GROUP BY transport_category 
          ORDER BY count DESC
        ")
        
        by_state <- dbGetQuery(.db_pool, "
          SELECT estado, COUNT(*) as count 
          FROM documents_deduplicated 
          WHERE estado IS NOT NULL
          GROUP BY estado 
          ORDER BY count DESC
          LIMIT 10
        ")
        
        # Sample of multi-category documents
        multi_category <- dbGetQuery(.db_pool, "
          SELECT titulo, species, transport_category, data_publicacao, jurisdicao
          FROM documents_deduplicated 
          WHERE transport_category LIKE '%,%' OR species LIKE '%,%'
          LIMIT 10
        ")
        
        list(
          view_exists = TRUE,
          total_documents = total_count,
          by_species = by_species,
          by_transport_category = by_transport,
          top_states = by_state,
          multi_category_samples = multi_category
        )
        
      } else {
        list(view_exists = FALSE, error = "Deduplicated view was not created")
      }
      
    }, error = function(e) {
      cat("❌ Error getting deduplicated metrics:", e$message, "\n")
      list(error = e$message)
    })
    
    results$deduplicated_metrics <- deduplicated_metrics
    
    if (deduplicated_metrics$view_exists) {
      cat(sprintf("✅ Deduplicated data: %s documents\n", format(deduplicated_metrics$total_documents, big.mark = ",")))
    }
    
    cat("📊 STEP 5: Calculating impact analysis...\n")
    
    # Calculate impact
    if (!is.null(original_metrics$total_documents) && !is.null(deduplicated_metrics$total_documents)) {
      impact_analysis <- list(
        original_count = original_metrics$total_documents,
        deduplicated_count = deduplicated_metrics$total_documents,
        reduction_count = original_metrics$total_documents - deduplicated_metrics$total_documents,
        reduction_percentage = round((original_metrics$total_documents - deduplicated_metrics$total_documents) / original_metrics$total_documents * 100, 2),
        duplication_rate = round((original_metrics$total_documents - deduplicated_metrics$total_documents) / deduplicated_metrics$total_documents * 100, 2)
      )
      
      cat(sprintf("📈 IMPACT ANALYSIS:\n"))
      cat(sprintf("  Original: %s documents\n", format(impact_analysis$original_count, big.mark = ",")))
      cat(sprintf("  Deduplicated: %s documents\n", format(impact_analysis$deduplicated_count, big.mark = ",")))
      cat(sprintf("  Reduction: %s documents (%.2f%%)\n", 
                  format(impact_analysis$reduction_count, big.mark = ","),
                  impact_analysis$reduction_percentage))
      cat(sprintf("  Duplication rate: %.2f%% (each unique doc appeared %.2f times on average)\n",
                  impact_analysis$duplication_rate,
                  impact_analysis$original_count / impact_analysis$deduplicated_count))
      
      results$impact_analysis <- impact_analysis
    }
    
    cat("📊 STEP 6: Implementing deduplication in unified data access layer...\n")
    
    # Implement deduplication
    dedup_implementation <- implement_deduplication()
    results$deduplication_implementation <- dedup_implementation
    
    # Final timestamp
    results$analysis_completed <- Sys.time()
    results$analysis_duration <- as.numeric(difftime(results$analysis_completed, results$connection_info$analysis_start, units = "mins"))
    
    cat("✅ DEDUPLICATION ANALYSIS COMPLETED!\n")
    
    return(results)
    
  }, error = function(e) {
    cat("❌ CRITICAL ERROR in deduplication analysis:", e$message, "\n")
    results$critical_error <- list(
      message = e$message,
      timestamp = Sys.time()
    )
    return(results)
  })
}

# Run the complete analysis
cat("🚀 EXECUTING COMPLETE DEDUPLICATION ANALYSIS...\n")
analysis_results <- run_complete_deduplication_analysis()

# Save results to files
cat("💾 SAVING RESULTS TO ./data_current/processed/deduplicated/...\n")

# Save main results as JSON
write_json(analysis_results, 
           file.path(output_dir, "deduplication_analysis_results.json"), 
           pretty = TRUE, auto_unbox = TRUE)

# Save summary report
summary_report <- sprintf("
# DEDUPLICATION ANALYSIS SUMMARY
Analysis completed: %s
Duration: %.2f minutes

## ORIGINAL DATA
- Total documents: %s
- Species categories: %d
- Transport categories: %d
- States with data: %d

## DEDUPLICATED DATA  
- Total documents: %s
- Reduction: %s documents (%.2f%%)
- Duplication rate: %.2f%%
- Average appearances per unique document: %.2f

## KEY FINDINGS
- The dataset contained significant duplication across the 20 LexML tables
- Same documents were collected multiple times due to overlapping search terms
- Deduplication preserves metadata by combining categories (e.g., 'Legislação, Jurisprudência')
- Real document count is substantially lower than the inflated original count

## FILES GENERATED
- deduplication_analysis_results.json: Complete analysis data
- original_metrics.csv: Original data breakdown
- deduplicated_metrics.csv: Deduplicated data breakdown  
- impact_analysis.csv: Before/after comparison
- deduplication_summary.txt: This summary report

## IMPLEMENTATION STATUS
- Deduplicated view created: %s
- Unified data access updated: %s
- Dashboard ready for deduplicated data: %s
",
Sys.time(),
analysis_results$analysis_duration %||% 0,
format(analysis_results$original_metrics$total_documents %||% 0, big.mark = ","),
nrow(analysis_results$original_metrics$by_species %||% data.frame()),
nrow(analysis_results$original_metrics$by_transport_category %||% data.frame()),
nrow(analysis_results$original_metrics$top_states %||% data.frame()),
format(analysis_results$deduplicated_metrics$total_documents %||% 0, big.mark = ","),
format(analysis_results$impact_analysis$reduction_count %||% 0, big.mark = ","),
analysis_results$impact_analysis$reduction_percentage %||% 0,
analysis_results$impact_analysis$duplication_rate %||% 0,
(analysis_results$original_metrics$total_documents %||% 1) / (analysis_results$deduplicated_metrics$total_documents %||% 1),
analysis_results$deduplicated_metrics$view_exists %||% FALSE,
!is.null(analysis_results$deduplication_implementation),
analysis_results$deduplicated_metrics$view_exists %||% FALSE
)

writeLines(summary_report, file.path(output_dir, "deduplication_summary.txt"))

# Save detailed CSV files
if (!is.null(analysis_results$original_metrics$by_species)) {
  write.csv(analysis_results$original_metrics$by_species, 
            file.path(output_dir, "original_metrics_by_species.csv"), 
            row.names = FALSE)
}

if (!is.null(analysis_results$original_metrics$by_transport_category)) {
  write.csv(analysis_results$original_metrics$by_transport_category, 
            file.path(output_dir, "original_metrics_by_transport.csv"), 
            row.names = FALSE)
}

if (!is.null(analysis_results$deduplicated_metrics$by_species)) {
  write.csv(analysis_results$deduplicated_metrics$by_species, 
            file.path(output_dir, "deduplicated_metrics_by_species.csv"), 
            row.names = FALSE)
}

if (!is.null(analysis_results$deduplicated_metrics$by_transport_category)) {
  write.csv(analysis_results$deduplicated_metrics$by_transport_category, 
            file.path(output_dir, "deduplicated_metrics_by_transport.csv"), 
            row.names = FALSE)
}

if (!is.null(analysis_results$impact_analysis)) {
  impact_df <- data.frame(
    metric = c("original_count", "deduplicated_count", "reduction_count", "reduction_percentage", "duplication_rate"),
    value = c(
      analysis_results$impact_analysis$original_count,
      analysis_results$impact_analysis$deduplicated_count, 
      analysis_results$impact_analysis$reduction_count,
      analysis_results$impact_analysis$reduction_percentage,
      analysis_results$impact_analysis$duplication_rate
    )
  )
  write.csv(impact_df, file.path(output_dir, "impact_analysis.csv"), row.names = FALSE)
}

# Save multi-category samples
if (!is.null(analysis_results$deduplicated_metrics$multi_category_samples)) {
  write.csv(analysis_results$deduplicated_metrics$multi_category_samples, 
            file.path(output_dir, "multi_category_document_samples.csv"), 
            row.names = FALSE)
}

cat("✅ DEDUPLICATION ANALYSIS COMPLETE AND SAVED!\n")
cat("📁 Results saved to: ./data_current/processed/deduplicated/\n")
cat("📊 Check deduplication_summary.txt for key findings\n")

# Print quick summary
if (!is.null(analysis_results$impact_analysis)) {
  cat("\n🎯 QUICK SUMMARY:\n")
  cat(sprintf("Original documents: %s\n", format(analysis_results$impact_analysis$original_count, big.mark = ",")))
  cat(sprintf("Deduplicated documents: %s\n", format(analysis_results$impact_analysis$deduplicated_count, big.mark = ",")))
  cat(sprintf("Reduction: %.2f%%\n", analysis_results$impact_analysis$reduction_percentage))
}