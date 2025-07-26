# Force Comprehensive Framework Loading
# Ensures the comprehensive framework loads regardless of Railway caching
# Date: 2025-07-26

cat("🚀 FORCE LOADING COMPREHENSIVE FRAMEWORK\n")
cat("==========================================\n")

# Create debug info that always works
DEBUG_INFO <<- paste0(
  "🔍 FORCE DEBUG STATUS (", format(Sys.time(), "%H:%M:%S"), "):\n",
  "Railway Port: ", Sys.getenv("PORT", "not_set"), "\n",
  "Working Dir: ", getwd(), "\n",
  "Files check: checking...\n"
)

# Check what files actually exist
files_exist <- list(
  railway_fix = file.exists("railway_deployment_fix.R"),
  comprehensive_patch = file.exists("comprehensive_framework_patch.R"),
  app_integration = file.exists("comprehensive_app_integration.R"),
  parquet_loader = file.exists("parquet_data_loader.R"),
  debug_status = file.exists("debug_status.R")
)

DEBUG_INFO <<- paste0(
  "🔍 FORCE DEBUG STATUS (", format(Sys.time(), "%H:%M:%S"), "):\n",
  "Railway Port: ", Sys.getenv("PORT", "not_set"), "\n",
  "Working Dir: ", getwd(), "\n",
  "railway_fix: ", ifelse(files_exist$railway_fix, "✅", "❌"), "\n",
  "comprehensive_patch: ", ifelse(files_exist$comprehensive_patch, "✅", "❌"), "\n",
  "app_integration: ", ifelse(files_exist$app_integration, "✅", "❌"), "\n",
  "parquet_loader: ", ifelse(files_exist$parquet_loader, "✅", "❌"), "\n",
  "debug_status: ", ifelse(files_exist$debug_status, "✅", "❌"), "\n"
)

# Force load comprehensive framework if files exist
framework_loaded <- FALSE
total_docs <- 0

if (files_exist$comprehensive_patch) {
  tryCatch({
    source("comprehensive_framework_patch.R")
    cat("✅ Comprehensive framework patch loaded\n")
    framework_loaded <- TRUE
    
    # Test if functions work
    if (exists("get_comprehensive_dashboard_metrics")) {
      metrics <- get_comprehensive_dashboard_metrics()
      total_docs <- metrics$total_documents
      cat("✅ Framework functions working:", total_docs, "documents\n")
    }
    
  }, error = function(e) {
    cat("❌ Error loading comprehensive framework:", e$message, "\n")
    DEBUG_INFO <<- paste0(DEBUG_INFO, "Framework Error: ", e$message, "\n")
  })
}

# Override ALL database functions to use comprehensive framework
if (framework_loaded && total_docs > 0) {
  cat("🔧 Overriding database functions with comprehensive framework\n")
  
  # Force override the main database loading function
  get_total_documents <<- function() {
    cat("🚀 FORCED: get_total_documents called - using comprehensive framework\n")
    return(total_docs)
  }
  
  # Override dashboard metrics
  get_dashboard_metrics <<- function() {
    cat("🚀 FORCED: get_dashboard_metrics called - using comprehensive framework\n")
    return(get_comprehensive_dashboard_metrics())
  }
  
  # Override map data
  get_map_data <<- function() {
    cat("🚀 FORCED: get_map_data called - using comprehensive framework\n")
    return(get_map_data_enhanced("state"))
  }
  
  DEBUG_INFO <<- paste0(DEBUG_INFO, 
    "Framework Status: ✅ LOADED\n",
    "Documents: ", format(total_docs, big.mark = ","), "\n",
    "Functions: OVERRIDDEN\n")
    
} else {
  DEBUG_INFO <<- paste0(DEBUG_INFO, 
    "Framework Status: ❌ NOT LOADED\n",
    "Using: Database fallback\n")
}

# Final debug update
DEBUG_INFO <<- paste0(DEBUG_INFO, 
  "Timestamp: ", as.character(Sys.time()), "\n",
  "=== FORCE LOAD COMPLETE ===")

cat("🎯 Force comprehensive framework loading complete\n")
cat("📊 Debug info updated and available globally\n")
print(DEBUG_INFO)