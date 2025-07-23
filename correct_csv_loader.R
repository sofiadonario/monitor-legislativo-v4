# Correct CSV Loader - Uses the actual data file with proper schema
# Uses lexml_parsed_enhanced_fixed.csv which has promulgation_date column

load_correct_csv_data <- function() {
  cat("🔄 Loading correct CSV data from ./data/processed/lexml_parsed_enhanced_fixed.csv\n")
  
  csv_file <- "./data/processed/lexml_parsed_enhanced_fixed.csv"
  
  if (!file.exists(csv_file)) {
    cat("❌ lexml_parsed_enhanced_fixed.csv not found at", csv_file, "\n")
    return(NULL)
  }
  
  tryCatch({
    # Load the CSV with proper schema
    csv_data <- read.csv(csv_file, stringsAsFactors = FALSE, encoding = "UTF-8")
    
    cat("✅ Loaded CSV data:", nrow(csv_data), "rows,", ncol(csv_data), "columns\n")
    cat("📊 CSV columns:", paste(colnames(csv_data), collapse = ", "), "\n")
    
    # Create final_dashboard_stats that the app expects
    final_dashboard_stats <- list(
      total_documents = nrow(csv_data),
      document_types = length(unique(csv_data$document_type_full)),
      jurisdictions = length(unique(csv_data$state[!is.na(csv_data$state) & csv_data$state != ""])),
      municipalities = length(unique(csv_data$municipality[!is.na(csv_data$municipality) & csv_data$municipality != ""])),
      date_range = list(
        min = min(as.Date(csv_data$promulgation_date), na.rm = TRUE),
        max = max(as.Date(csv_data$promulgation_date), na.rm = TRUE)
      )
    )
    
    cat("📊 Dashboard stats created:\n")
    cat("  - Total documents:", final_dashboard_stats$total_documents, "\n")
    cat("  - Document types:", final_dashboard_stats$document_types, "\n") 
    cat("  - Jurisdictions:", final_dashboard_stats$jurisdictions, "\n")
    cat("  - Date range:", final_dashboard_stats$date_range$min, "to", final_dashboard_stats$date_range$max, "\n")
    
    # Make it available globally
    assign("final_dashboard_stats", final_dashboard_stats, envir = .GlobalEnv)
    assign("csv_enhanced_data", csv_data, envir = .GlobalEnv)
    
    return(csv_data)
    
  }, error = function(e) {
    cat("❌ Error loading correct CSV data:", e$message, "\n")
    return(NULL)
  })
}

cat("✅ Correct CSV loader functions loaded\n")