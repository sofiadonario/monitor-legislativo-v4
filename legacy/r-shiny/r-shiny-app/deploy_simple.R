# Simple Deployment Script
# This script handles directory issues and deploys the app

cat("\n=== SIMPLE DEPLOYMENT SCRIPT ===\n")
cat("This will deploy your Academic Legislative Monitor to Shinyapps.io\n\n")

# Step 1: Check current directory and files
cat("📁 Checking files in current directory...\n")
cat("Current path:", getwd(), "\n\n")

# List all files
cat("Files found:\n")
files_found <- list.files(recursive = TRUE)
print(files_found[1:min(20, length(files_found))])  # Show first 20 files

# Check for app.R specifically
if (!file.exists("app.R")) {
  cat("\n❌ ERROR: app.R not found in current directory!\n")
  cat("Please make sure you're running this from the r-shiny-app folder.\n")
  cat("\nTry this:\n")
  cat("1. In R, run: setwd('C:/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/academic-map-app/r-shiny-app')\n")
  cat("2. Then run: source('deploy_simple.R')\n")
  stop("Not in correct directory")
}

cat("\n✅ app.R found!\n")

# Step 2: Install and load rsconnect
cat("\n📦 Loading deployment package...\n")
if (!require(rsconnect)) {
  install.packages("rsconnect")
  library(rsconnect)
}

# Step 3: Check if account is configured
cat("\n🔐 Checking Shinyapps.io configuration...\n")
accounts <- rsconnect::accounts()

if (nrow(accounts) == 0) {
  cat("\n⚠️  No Shinyapps.io account configured!\n")
  cat("\nPlease follow these steps:\n")
  cat("1. Go to https://www.shinyapps.io/\n")
  cat("2. Create a free account\n")
  cat("3. Go to Account → Tokens\n")
  cat("4. Click 'Show' on your token\n")
  cat("5. Copy the entire rsconnect::setAccountInfo(...) command\n")
  cat("6. Paste and run it in R\n")
  cat("7. Then run this script again\n")
  stop("Please configure your Shinyapps.io account first")
} else {
  cat("✅ Account found:", accounts$name[1], "\n")
}

# Step 4: Deploy the app
cat("\n🚀 Ready to deploy!\n")
cat("App name will be: academic-legislative-monitor\n")
cat("URL will be: https://", accounts$name[1], ".shinyapps.io/academic-legislative-monitor\n", sep = "")

cat("\nDeploy now? (y/n): ")
response <- readline()

if (tolower(response) == "y") {
  cat("\n🚀 Deploying... (this may take a few minutes)\n")
  
  tryCatch({
    rsconnect::deployApp(
      appDir = ".",
      appName = "academic-legislative-monitor",
      appTitle = "Monitor Legislativo Acadêmico",
      forceUpdate = TRUE,
      launch.browser = TRUE
    )
    
    cat("\n✅ DEPLOYMENT SUCCESSFUL!\n")
    cat("\n📋 Default login credentials:\n")
    cat("👨‍💼 admin / admin123\n")
    cat("👨‍🔬 researcher / research123\n")
    cat("👨‍🎓 student / student123\n")
    
  }, error = function(e) {
    cat("\n❌ Deployment error:\n")
    print(e)
    cat("\nCommon solutions:\n")
    cat("1. Check your internet connection\n")
    cat("2. Make sure all files are saved\n")
    cat("3. Try closing other R sessions\n")
    cat("4. Check if app name is already taken\n")
  })
  
} else {
  cat("\nDeployment cancelled.\n")
}

cat("\n=== END ===\n")