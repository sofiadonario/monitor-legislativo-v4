# Fix for document display issue - showing only 15 out of 134k documents
# This script identifies and fixes the filtering bottlenecks

# Load required libraries
library(shiny)
library(DBI)
library(dplyr)

# Function to diagnose the data filtering issue
diagnose_document_filtering <- function() {
  cat("\n=== Document Filtering Diagnosis ===\n")
  
  # Try to load data using the app's method
  documents_data <- NULL
  
  # Check for parquet file
  if (file.exists("brazilian_legislative_complete.parquet")) {
    if (require(arrow, quietly = TRUE)) {
      documents_data <- arrow::read_parquet("brazilian_legislative_complete.parquet")
      cat("Loaded from parquet file\n")
    }
  }
  
  # Check for CSV files
  csv_files <- c(
    "lexml_unified_dataset.csv",
    "lexml_enhanced_simple.csv", 
    "lexml_sample_for_railway.csv"
  )
  
  for (csv_file in csv_files) {
    if (is.null(documents_data) && file.exists(csv_file)) {
      cat(sprintf("Loading %s...\n", csv_file))
      documents_data <- read.csv(csv_file, stringsAsFactors = FALSE)
      cat(sprintf("Loaded %d rows from %s\n", nrow(documents_data), csv_file))
      break
    }
  }
  
  if (is.null(documents_data)) {
    cat("ERROR: No data files found!\n")
    cat("The application needs one of these files:\n")
    cat("- brazilian_legislative_complete.parquet\n")
    cat("- lexml_unified_dataset.csv\n")
    cat("- lexml_enhanced_simple.csv\n")
    cat("- lexml_sample_for_railway.csv\n")
    return(NULL)
  }
  
  # Analyze the data
  cat(sprintf("\nInitial dataset: %d documents\n", nrow(documents_data)))
  
  # Check for title column
  title_col <- NULL
  if ("title" %in% names(documents_data)) {
    title_col <- "title"
  } else if ("titulo" %in% names(documents_data)) {
    title_col <- "titulo"
  }
  
  if (!is.null(title_col)) {
    non_empty_titles <- sum(!is.na(documents_data[[title_col]]) & 
                            documents_data[[title_col]] != "")
    cat(sprintf("Documents with non-empty titles: %d (%.1f%%)\n", 
                non_empty_titles, 
                100 * non_empty_titles / nrow(documents_data)))
  }
  
  # Check for category/type columns
  if ("category" %in% names(documents_data)) {
    cat("\nCategory distribution:\n")
    print(table(documents_data$category, useNA = "always"))
  } else if ("tipo" %in% names(documents_data)) {
    cat("\nType (tipo) distribution:\n")
    tipo_table <- table(documents_data$tipo, useNA = "always")
    print(head(tipo_table[order(tipo_table, decreasing = TRUE)], 20))
  }
  
  # Check for state column
  if ("state" %in% names(documents_data)) {
    cat("\nState distribution:\n")
    state_table <- table(documents_data$state, useNA = "always")
    print(head(state_table[order(state_table, decreasing = TRUE)], 10))
  } else if ("estado" %in% names(documents_data)) {
    cat("\nState (estado) distribution:\n")
    estado_table <- table(documents_data$estado, useNA = "always")
    print(head(estado_table[order(estado_table, decreasing = TRUE)], 10))
  }
  
  return(documents_data)
}

# Function to create a fixed version of process_document_data
create_fixed_process_function <- function() {
  cat("\n=== Creating Fixed Processing Function ===\n")
  
  fixed_function <- '
# Fixed version of process_document_data with better filtering
process_document_data_fixed <- function(all_docs, 
                                       category = "all", 
                                       search_term = "",
                                       state = "all",
                                       limit = 999999) {  # Changed default from 100 to 999999
  
  # Debug logging
  cat(sprintf("Processing %d documents\\n", nrow(all_docs)))
  cat(sprintf("Filters - Category: %s, State: %s, Search: %s, Limit: %d\\n", 
              category, state, search_term, limit))
  
  filtered_docs <- all_docs
  
  # More lenient title filtering - keep documents with any non-empty field
  if ("title" %in% names(filtered_docs)) {
    # Keep documents that have title OR summary OR content
    has_content <- (!is.na(filtered_docs$title) & filtered_docs$title != "") |
                   (!is.na(filtered_docs$summary) & filtered_docs$summary != "") |
                   (!is.na(filtered_docs$content) & filtered_docs$content != "")
    filtered_docs <- filtered_docs[has_content, ]
    cat(sprintf("After content filter: %d documents\\n", nrow(filtered_docs)))
  }
  
  # Category filtering - more flexible
  if (!is.null(category) && category != "all" && category != "") {
    if ("category" %in% names(filtered_docs)) {
      filtered_docs <- filtered_docs[!is.na(filtered_docs$category) & 
                                     filtered_docs$category == category, ]
    } else if ("tipo" %in% names(filtered_docs)) {
      # Map tipo to category if needed
      filtered_docs <- filtered_docs[!is.na(filtered_docs$tipo), ]
    }
    cat(sprintf("After category filter: %d documents\\n", nrow(filtered_docs)))
  }
  
  # State filtering
  if (!is.null(state) && state != "all" && state != "") {
    state_col <- if("state" %in% names(filtered_docs)) "state" else "estado"
    if (state_col %in% names(filtered_docs)) {
      filtered_docs <- filtered_docs[!is.na(filtered_docs[[state_col]]) & 
                                     filtered_docs[[state_col]] == state, ]
      cat(sprintf("After state filter: %d documents\\n", nrow(filtered_docs)))
    }
  }
  
  # Search filtering
  if (!is.null(search_term) && search_term != "") {
    search_lower <- tolower(search_term)
    title_match <- grepl(search_lower, tolower(filtered_docs$title), fixed = TRUE)
    summary_match <- if("summary" %in% names(filtered_docs)) {
      grepl(search_lower, tolower(filtered_docs$summary), fixed = TRUE)
    } else {
      rep(FALSE, nrow(filtered_docs))
    }
    filtered_docs <- filtered_docs[title_match | summary_match, ]
    cat(sprintf("After search filter: %d documents\\n", nrow(filtered_docs)))
  }
  
  # Apply limit only if needed
  if (nrow(filtered_docs) > limit) {
    filtered_docs <- filtered_docs[1:limit, ]
    cat(sprintf("After limit: %d documents\\n", nrow(filtered_docs)))
  }
  
  return(filtered_docs)
}
'
  
  cat(fixed_function)
  cat("\n\nFixed function created. Copy this to replace the existing process_document_data function in app.R\n")
}

# Run diagnosis
cat("Starting document display diagnosis...\n")
data <- diagnose_document_filtering()

if (!is.null(data)) {
  # Create the fixed function
  create_fixed_process_function()
  
  cat("\n=== SUMMARY OF FIXES NEEDED ===\n")
  cat("1. Replace process_document_data function in app.R with the fixed version above\n")
  cat("2. Change default limit from 100 to 999999 in get_library_documents (line 533)\n")
  cat("3. Make title filtering more lenient (check for content in any field)\n")
  cat("4. Add debug logging to track where documents are filtered out\n")
  cat("\n")
  cat("The main issue is aggressive filtering that removes most documents.\n")
  cat("The fixed function will preserve more documents while still allowing filtering.\n")
}