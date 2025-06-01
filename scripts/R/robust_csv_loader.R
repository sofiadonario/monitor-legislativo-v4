# Robust CSV Loader to handle malformed CSV data
library(dplyr)

cat("🔧 Creating robust CSV loader...\n")

# Read with more robust settings
tryCatch({
  # Try multiple approaches
  cat("📊 Attempting Method 1: read.csv with quote handling...\n")
  data <- read.csv("./data_current/processed/Geral.csv", 
                   stringsAsFactors = FALSE,
                   fileEncoding = "UTF-8-BOM",
                   quote = "\"",
                   comment.char = "",
                   check.names = FALSE)
  cat("   Result: ", nrow(data), " rows\n")
  
  if (nrow(data) < 5000) {
    cat("📊 Attempting Method 2: read.csv with different quote settings...\n")
    data <- read.csv("./data_current/processed/Geral.csv", 
                     stringsAsFactors = FALSE,
                     fileEncoding = "UTF-8-BOM",
                     quote = "",
                     comment.char = "",
                     sep = ",",
                     check.names = FALSE)
    cat("   Result: ", nrow(data), " rows\n")
  }
  
  if (nrow(data) < 5000) {
    cat("📊 Attempting Method 3: data.table approach...\n")
    if (require(data.table, quietly = TRUE)) {
      data <- as.data.frame(fread("./data_current/processed/Geral.csv", encoding = "UTF-8"))
      cat("   Result: ", nrow(data), " rows\n")
    }
  }
  
  # Clean up data
  cat("🧹 Cleaning data...\n")
  
  # Remove BOM if present in column names
  if (length(names(data)) > 0) {
    names(data)[1] <- gsub("^\\ufeff|^\\xef\\xbb\\xbf", "", names(data)[1])
  }
  
  # Basic stats
  cat("📊 Final data loaded: ", nrow(data), " documents\n")
  cat("📊 Unique states found: ", length(unique(data$State[data$State != "" & !is.na(data$State)])), " states\n")
  cat("📊 Document types:\n")
  print(table(data$Urn_type, useNA = "ifany"))
  
  # Create simplified overview for dashboard
  overview <- list(
    total_documents = nrow(data),
    states_with_data = length(unique(data$State[data$State != "" & !is.na(data$State)])),
    document_types = table(data$Urn_type),
    sample_states = head(unique(data$State[data$State != "" & !is.na(data$State)]), 10)
  )
  
  cat("✅ Dashboard overview created:\n")
  cat("   Total documents:", overview$total_documents, "\n")
  cat("   States with data:", overview$states_with_data, "\n")
  cat("   Sample states:", paste(overview$sample_states, collapse = ", "), "\n")
  
}, error = function(e) {
  cat("❌ Error loading CSV:", e$message, "\n")
})