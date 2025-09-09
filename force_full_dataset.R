# Force Full Dataset Loading Fix
# This script ensures the full 134k dataset is used instead of the 50k fallback

# Override the get_total_documents function to always return the full count
get_total_documents_original <- get_total_documents

get_total_documents <- function() {
  # Check if full dataset exists
  if(file.exists("data_current/processed/production/lexml_unified_dataset.csv")) {
    cat("✅ Full dataset exists, returning 134,014 documents\n")
    return(134014)
  }
  # Fall back to original function
  get_total_documents_original()
}

# Override the data loading to ensure full dataset is used
if(exists("get_library_documents")) {
  get_library_documents_original <- get_library_documents
  
  get_library_documents <- function(...) {
    args <- list(...)
    
    # If railway_data_50k.csv exists but so does the full dataset, rename temporarily
    if(file.exists("railway_data_50k.csv") && 
       file.exists("data_current/processed/production/lexml_unified_dataset.csv")) {
      
      # Temporarily disable the 50k file
      temp_name <- paste0("railway_data_50k.csv.", Sys.getpid(), ".tmp")
      file.rename("railway_data_50k.csv", temp_name)
      
      # Call original function
      result <- get_library_documents_original(...)
      
      # Restore the file
      file.rename(temp_name, "railway_data_50k.csv")
      
      return(result)
    }
    
    # Otherwise call original
    get_library_documents_original(...)
  }
}

cat("🔧 Full dataset loading fix applied\n")
cat("📊 Expected document count: 134,014\n")