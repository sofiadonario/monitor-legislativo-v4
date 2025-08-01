# DEDUPLICATION IMPLEMENTATION FOR MACKMONITOR
# This R script implements the deduplication strategy and updates the unified data access layer

cat("🔧 IMPLEMENTING DEDUPLICATION SOLUTION...\n")

library(DBI)
library(dplyr)

# Function to analyze and implement deduplication
implement_deduplication <- function() {
  tryCatch({
    # Check if database connection exists
    if (!exists(".db_pool") || !inherits(.db_pool, "Pool")) {
      stop("Database pool not available")
    }
    
    cat("📊 STEP 1: Analyzing current duplication levels...\n")
    
    # Get current document count
    original_count <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM documents")$count
    cat(sprintf("Original document count: %s\n", format(original_count, big.mark = ",")))
    
    # Execute deduplication analysis
    cat("🔍 Running deduplication analysis...\n")
    
    # Read and execute the deduplication strategy SQL
    if (file.exists("deduplication_strategy.sql")) {
      sql_content <- paste(readLines("deduplication_strategy.sql"), collapse = "\n")
      
      # Split SQL into individual statements
      sql_statements <- unlist(strsplit(sql_content, ";"))
      sql_statements <- trimws(sql_statements)
      sql_statements <- sql_statements[nchar(sql_statements) > 0]
      
      for (stmt in sql_statements) {
        if (grepl("^--", stmt) || nchar(trimws(stmt)) == 0) next
        
        if (grepl("^SELECT", stmt, ignore.case = TRUE)) {
          result <- dbGetQuery(.db_pool, stmt)
          print(result)
        } else {
          dbExecute(.db_pool, stmt)
        }
      }
    }
    
    # Get deduplicated count
    dedup_count <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM documents_deduplicated")$count
    cat(sprintf("Deduplicated document count: %s\n", format(dedup_count, big.mark = ",")))
    
    reduction_percentage <- round((original_count - dedup_count) / original_count * 100, 1)
    cat(sprintf("Reduction: %s documents (%.1f%%)\n", 
                format(original_count - dedup_count, big.mark = ","), 
                reduction_percentage))
    
    cat("\n📈 STEP 2: Updating unified data access layer for deduplication...\n")
    
    # Update the unified data access layer functions to use deduplicated view
    update_unified_data_access_for_deduplication()
    
    cat("✅ DEDUPLICATION IMPLEMENTATION COMPLETE!\n")
    
    return(list(
      original_count = original_count,
      deduplicated_count = dedup_count,
      reduction_count = original_count - dedup_count,
      reduction_percentage = reduction_percentage
    ))
    
  }, error = function(e) {
    cat("❌ Error in deduplication implementation:", e$message, "\n")
    return(NULL)
  })
}

# Update unified data access layer to use deduplicated data
update_unified_data_access_for_deduplication <- function() {
  cat("🔄 Updating unified data access layer for deduplicated data...\n")
  
  # Override the document count function to use deduplicated view
  get_deduplicated_document_count <- function(filters = list()) {
    tryCatch({
      query <- "SELECT COUNT(*) as count FROM documents_deduplicated"
      where_conditions <- c()
      
      # Add filters
      if (!is.null(filters$year)) {
        where_conditions <- c(where_conditions, 
                             sprintf("EXTRACT(YEAR FROM data_publicacao) = %d", filters$year))
      }
      
      if (!is.null(filters$estado)) {
        where_conditions <- c(where_conditions, 
                             sprintf("estado = '%s'", filters$estado))
      }
      
      if (!is.null(filters$species)) {
        where_conditions <- c(where_conditions, 
                             sprintf("species LIKE '%%%s%%'", filters$species))
      }
      
      if (!is.null(filters$transport_category)) {
        where_conditions <- c(where_conditions, 
                             sprintf("transport_category LIKE '%%%s%%'", filters$transport_category))
      }
      
      if (length(where_conditions) > 0) {
        query <- paste(query, "WHERE", paste(where_conditions, collapse = " AND "))
      }
      
      result <- dbGetQuery(.db_pool, query)
      return(result$count[1])
      
    }, error = function(e) {
      cat("❌ Error getting deduplicated count:", e$message, "\n")
      return(0)
    })
  }
  
  # Override documents by state to use deduplicated view
  get_deduplicated_documents_by_state <- function(limit = 100) {
    tryCatch({
      query <- "
        SELECT 
          estado,
          COUNT(*) as count,
          COUNT(DISTINCT transport_category) as transport_categories,
          STRING_AGG(DISTINCT species, ', ') as document_types
        FROM documents_deduplicated 
        WHERE estado IS NOT NULL 
        GROUP BY estado 
        ORDER BY count DESC
      "
      
      if (!is.null(limit) && limit > 0) {
        query <- paste(query, "LIMIT", limit)
      }
      
      result <- dbGetQuery(.db_pool, query)
      return(result)
      
    }, error = function(e) {
      cat("❌ Error getting deduplicated documents by state:", e$message, "\n")
      return(data.frame(estado = character(), count = numeric()))
    })
  }
  
  # Override documents by type to use deduplicated view  
  get_deduplicated_documents_by_type <- function(limit = 100) {
    tryCatch({
      query <- "
        SELECT 
          species as tipo,
          COUNT(*) as count,
          COUNT(DISTINCT transport_category) as transport_categories
        FROM documents_deduplicated 
        GROUP BY species 
        ORDER BY count DESC
      "
      
      if (!is.null(limit) && limit > 0) {
        query <- paste(query, "LIMIT", limit)
      }
      
      result <- dbGetQuery(.db_pool, query)
      return(result)
      
    }, error = function(e) {
      cat("❌ Error getting deduplicated documents by type:", e$message, "\n")
      return(data.frame(tipo = character(), count = numeric()))
    })
  }
  
  # Create wrapper functions that can be toggled between original and deduplicated
  use_deduplicated_data <- TRUE  # Toggle this to switch between original and deduplicated
  
  get_document_count_with_dedup_option <- function(filters = list()) {
    if (use_deduplicated_data && 
        dbExistsTable(.db_pool, "documents_deduplicated")) {
      return(get_deduplicated_document_count(filters))
    } else {
      # Fall back to original unified data access
      return(.unified_dac$get_document_count(filters))
    }
  }
  
  get_documents_by_state_with_dedup_option <- function(limit = 100) {
    if (use_deduplicated_data && 
        dbExistsTable(.db_pool, "documents_deduplicated")) {
      return(get_deduplicated_documents_by_state(limit))
    } else {
      return(.unified_dac$get_documents_by_state(limit))
    }
  }
  
  get_documents_by_type_with_dedup_option <- function(limit = 100) {
    if (use_deduplicated_data && 
        dbExistsTable(.db_pool, "documents_deduplicated")) {
      return(get_deduplicated_documents_by_type(limit))
    } else {
      return(.unified_dac$get_documents_by_type(limit))
    }
  }
  
  # Override global functions to use deduplication-aware versions
  get_total_documents <<- get_document_count_with_dedup_option
  get_documents_by_state <<- get_documents_by_state_with_dedup_option  
  get_documents_by_type <<- get_documents_by_type_with_dedup_option
  
  # Update LexML dashboard metrics to use deduplicated data
  get_lexml_dashboard_metrics_deduplicated <- function() {
    tryCatch({
      total_docs <- get_document_count_with_dedup_option()
      states_data <- get_documents_by_state_with_dedup_option(50)
      
      states_with_docs <- nrow(states_data)
      
      # Estimate municipalities (rough calculation)
      municipalities_with_docs <- min(states_with_docs * 15, 1000)  # Conservative estimate
      
      # Calculate percentages
      states_percentage <- round((states_with_docs / 27) * 100, 1)
      municipalities_percentage <- round((municipalities_with_docs / 5570) * 100, 1)
      
      # Calculate date range
      date_range_query <- "
        SELECT 
          MIN(data_publicacao) as min_date,
          MAX(data_publicacao) as max_date
        FROM documents_deduplicated 
        WHERE data_publicacao IS NOT NULL
      "
      
      date_result <- dbGetQuery(.db_pool, date_range_query)
      
      if (nrow(date_result) > 0 && !is.na(date_result$min_date[1])) {
        min_year <- as.numeric(format(as.Date(date_result$min_date[1]), "%Y"))
        max_year <- as.numeric(format(as.Date(date_result$max_date[1]), "%Y"))
        date_range_years <- max_year - min_year + 1
      } else {
        date_range_years <- 0
      }
      
      result <- list(
        total_documents = total_docs,
        states_with_docs = states_with_docs,
        municipalities_with_docs = municipalities_with_docs,
        states_percentage = states_percentage,
        municipalities_percentage = municipalities_percentage,
        date_range_years = date_range_years,
        last_updated = Sys.time(),
        data_source = "deduplicated_unified_layer"
      )
      
      cat("✅ Deduplicated LexML metrics:", total_docs, "documents\n")
      return(result)
      
    }, error = function(e) {
      cat("❌ Error in deduplicated LexML metrics:", e$message, "\n")
      # Fall back to original function
      return(get_lexml_dashboard_metrics())
    })
  }
  
  # Override the LexML dashboard metrics function
  get_lexml_dashboard_metrics <<- get_lexml_dashboard_metrics_deduplicated
  
  cat("✅ Unified data access layer updated for deduplication\n")
}

# Function to compare original vs deduplicated metrics
compare_original_vs_deduplicated <- function() {
  cat("📊 COMPARING ORIGINAL VS DEDUPLICATED METRICS...\n")
  
  tryCatch({
    # Get original metrics (from documents view)
    original_total <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM documents")$count
    
    # Get deduplicated metrics (from documents_deduplicated view)
    dedup_total <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM documents_deduplicated")$count
    
    # Compare by species
    original_by_species <- dbGetQuery(.db_pool, "
      SELECT species, COUNT(*) as count 
      FROM documents 
      GROUP BY species 
      ORDER BY species
    ")
    
    dedup_by_species <- dbGetQuery(.db_pool, "
      SELECT species, COUNT(*) as count 
      FROM documents_deduplicated 
      GROUP BY species 
      ORDER BY species
    ")
    
    cat("\n📈 COMPARISON RESULTS:\n")
    cat("=" * 50, "\n")
    cat(sprintf("Original Total: %s documents\n", format(original_total, big.mark = ",")))
    cat(sprintf("Deduplicated Total: %s documents\n", format(dedup_total, big.mark = ",")))
    cat(sprintf("Reduction: %s documents (%.1f%%)\n", 
                format(original_total - dedup_total, big.mark = ","),
                round((original_total - dedup_total) / original_total * 100, 1)))
    
    cat("\nBy Document Type:\n")
    comparison <- merge(original_by_species, dedup_by_species, by = "species", suffixes = c("_original", "_dedup"))
    comparison$reduction <- comparison$count_original - comparison$count_dedup
    comparison$reduction_pct <- round((comparison$reduction / comparison$count_original) * 100, 1)
    
    print(comparison)
    
    return(list(
      original_total = original_total,
      deduplicated_total = dedup_total,
      comparison_by_species = comparison
    ))
    
  }, error = function(e) {
    cat("❌ Error comparing metrics:", e$message, "\n")
    return(NULL)
  })
}

# Function to enable/disable deduplication
toggle_deduplication <- function(enable = TRUE) {
  if (enable) {
    cat("🔄 Enabling deduplication...\n")
    use_deduplicated_data <<- TRUE
    update_unified_data_access_for_deduplication()
    cat("✅ Deduplication enabled\n")
  } else {
    cat("🔄 Disabling deduplication...\n")
    use_deduplicated_data <<- FALSE
    # Reload original unified data access functions
    if (file.exists("integrate_unified_data_access.R")) {
      source("integrate_unified_data_access.R", local = FALSE)
    }
    cat("✅ Deduplication disabled - using original data\n")
  }
}

cat("✅ DEDUPLICATION IMPLEMENTATION LOADED\n")
cat("Run implement_deduplication() to analyze and apply deduplication\n")
cat("Run compare_original_vs_deduplicated() to see the impact\n")
cat("Run toggle_deduplication(TRUE/FALSE) to enable/disable deduplication\n")