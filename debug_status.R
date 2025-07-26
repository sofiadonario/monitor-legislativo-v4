# Debug Status for Railway Deployment
# Creates a visible status indicator in the app
# Date: 2025-07-26

# Global status variable that will be shown in the UI
DEPLOYMENT_STATUS <- list(
  timestamp = Sys.time(),
  railway_detected = FALSE,
  comprehensive_framework = FALSE,
  data_source = "unknown",
  total_documents = 0,
  package_status = list(),
  errors = c()
)

# Check Railway environment
railway_vars <- c("PORT", "RAILWAY_ENVIRONMENT", "RAILWAY_PROJECT_ID")
for (var in railway_vars) {
  if (Sys.getenv(var) != "") {
    DEPLOYMENT_STATUS$railway_detected <- TRUE
    break
  }
}

# Check comprehensive framework
tryCatch({
  if (file.exists("comprehensive_framework_patch.R")) {
    source("comprehensive_framework_patch.R")
    DEPLOYMENT_STATUS$comprehensive_framework <- TRUE
    
    # Test data loading
    if (exists("get_comprehensive_dashboard_metrics")) {
      metrics <- get_comprehensive_dashboard_metrics()
      DEPLOYMENT_STATUS$total_documents <- metrics$total_documents
      DEPLOYMENT_STATUS$data_source <- "comprehensive_framework"
    }
  }
}, error = function(e) {
  DEPLOYMENT_STATUS$errors <- c(DEPLOYMENT_STATUS$errors, 
                               paste("Framework error:", e$message))
})

# Check packages
key_packages <- c("shiny", "dplyr", "arrow", "data.table")
for (pkg in key_packages) {
  DEPLOYMENT_STATUS$package_status[[pkg]] <- require(pkg, quietly = TRUE, character.only = TRUE)
}

# Create debug info string for UI
DEBUG_INFO <- paste0(
  "🔍 DEBUG STATUS (", format(DEPLOYMENT_STATUS$timestamp, "%H:%M:%S"), "):\n",
  "Railway: ", ifelse(DEPLOYMENT_STATUS$railway_detected, "✅", "❌"), "\n",
  "Framework: ", ifelse(DEPLOYMENT_STATUS$comprehensive_framework, "✅", "❌"), "\n", 
  "Documents: ", format(DEPLOYMENT_STATUS$total_documents, big.mark = ","), "\n",
  "Data Source: ", DEPLOYMENT_STATUS$data_source, "\n",
  "Arrow Package: ", ifelse(DEPLOYMENT_STATUS$package_status$arrow, "✅", "❌"), "\n",
  if (length(DEPLOYMENT_STATUS$errors) > 0) paste("Errors:", paste(DEPLOYMENT_STATUS$errors, collapse = "; ")) else ""
)

cat("📊 DEPLOYMENT STATUS INITIALIZED\n")
cat(DEBUG_INFO)
cat("\n")