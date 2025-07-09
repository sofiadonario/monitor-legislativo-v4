# Debug Deployment Issues
# This script helps identify and fix common deployment problems

cat("🔍 DEPLOYMENT DEBUGGING SCRIPT\n")
cat("================================\n\n")

# Load rsconnect to check logs
if (!require(rsconnect)) {
  install.packages("rsconnect")
  library(rsconnect)
}

# 1. Check recent deployments
cat("📋 Recent Deployments:\n")
deployments <- rsconnect::deployments()
if (nrow(deployments) > 0) {
  print(head(deployments, 3))
} else {
  cat("No deployments found\n")
}

# 2. Get logs from the most recent deployment
cat("\n📝 Checking deployment logs...\n")
tryCatch({
  logs <- rsconnect::showLogs(appName = "academic-legislative-monitor")
  cat("Logs retrieved successfully - check R console for details\n")
}, error = function(e) {
  cat("Error getting logs:", e$message, "\n")
  cat("Try: rsconnect::showLogs() to see all logs\n")
})

# 3. Common fixes to try
cat("\n🔧 COMMON FIXES TO TRY:\n")
cat("=======================\n")
cat("1. Package Issues:\n")
cat("   - Some packages might not be available on Shinyapps.io\n")
cat("   - Try commenting out problematic packages in .Rprofile\n\n")

cat("2. Large File Issues:\n")
cat("   - Check if any files are too large\n")
cat("   - Shinyapps.io has file size limits\n\n")

cat("3. Dependency Issues:\n")
cat("   - Some system dependencies might be missing\n")
cat("   - Try deploying without heavy packages first\n\n")

# 4. Check app.R for common issues
cat("📄 Checking app.R for issues...\n")
if (file.exists("app.R")) {
  app_content <- readLines("app.R", warn = FALSE)
  
  # Check for potential issues
  issues <- list()
  
  # Check for system-specific paths
  if (any(grepl("C:", app_content))) {
    issues <- append(issues, "Windows-specific paths found (C:)")
  }
  
  # Check for absolute paths
  if (any(grepl("/Users/", app_content) | grepl("/home/", app_content))) {
    issues <- append(issues, "Absolute paths found")
  }
  
  # Check for problematic packages
  problematic_pkgs <- c("ROracle", "RODBC", "Cairo")
  for (pkg in problematic_pkgs) {
    if (any(grepl(pkg, app_content))) {
      issues <- append(issues, paste("Potentially problematic package:", pkg))
    }
  }
  
  if (length(issues) > 0) {
    cat("⚠️  Potential issues found:\n")
    for (issue in issues) {
      cat("   -", issue, "\n")
    }
  } else {
    cat("✅ No obvious issues in app.R\n")
  }
} else {
  cat("❌ app.R not found\n")
}

cat("\n🛠️  QUICK FIXES TO TRY:\n")
cat("======================\n")
cat("1. Redeploy with minimal packages:\n")
cat("   source('deploy_minimal.R')\n\n")
cat("2. Check logs in detail:\n")
cat("   rsconnect::showLogs()\n\n")
cat("3. Try force update:\n")
cat("   rsconnect::deployApp(forceUpdate = TRUE)\n\n")

cat("📞 If still having issues, check:\n")
cat("   - https://docs.rstudio.com/shinyapps.io/troubleshooting.html\n")
cat("   - Or try deploying a simple test app first\n")