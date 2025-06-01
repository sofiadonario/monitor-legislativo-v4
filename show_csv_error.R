# Quick fix to show CSV loading errors in the UI
# Add this to app.R to see why CSV loading is failing on Railway

# Add a reactive value to store error messages
csv_load_error <- reactiveVal("")

# Modify the get_library_documents function to capture errors
get_library_documents_with_error_capture <- function(...) {
  result <- tryCatch({
    # Try loading CSV
    csv_path <- "data_current/processed/production/lexml_unified_dataset.csv"
    
    if (!file.exists(csv_path)) {
      error_msg <- paste("CSV file not found:", csv_path)
      csv_load_error(error_msg)
      return(data.frame())
    }
    
    # Try to read CSV
    data <- read.csv(csv_path, stringsAsFactors = FALSE, encoding = "UTF-8")
    csv_load_error(paste("Successfully loaded", nrow(data), "documents from CSV"))
    return(data)
    
  }, error = function(e) {
    error_msg <- paste("CSV loading error:", e$message)
    csv_load_error(error_msg)
    
    # Return minimal fallback
    return(data.frame(
      title = c("Doc 1", "Doc 2", "Doc 3"),
      category = c("Test", "Test", "Test"),
      state = c("SP", "RJ", "MG"),
      date = Sys.Date(),
      stringsAsFactors = FALSE
    ))
  })
  
  return(result)
}

# Add UI element to show the error
output$csv_load_status <- renderText({
  csv_load_error()
})

# In UI, add:
# textOutput("csv_load_status")