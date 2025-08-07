# Deployment Script for Academic Legislative Monitor
# Deploy to Shinyapps.io

cat("=== Academic Legislative Monitor - Deployment Script ===\n")
cat("📍 Target: Shinyapps.io\n")
cat("🎯 Application: R Shiny with Real Government Data\n\n")

# Load required packages
if (!require(rsconnect)) {
  cat("Installing rsconnect package...\n")
  install.packages("rsconnect")
  library(rsconnect)
}

# Function to check prerequisites
check_prerequisites <- function() {
  cat("\n📋 Checking deployment prerequisites...\n")
  
  # First, ensure we're in the correct directory
  cat("📁 Current directory:", getwd(), "\n")
  
  # Check if we need to change directory
  if (!file.exists("app.R")) {
    # Try to find the correct directory
    if (file.exists("r-shiny-app/app.R")) {
      setwd("r-shiny-app")
      cat("📁 Changed to r-shiny-app directory\n")
    } else if (file.exists("academic-map-app/r-shiny-app/app.R")) {
      setwd("academic-map-app/r-shiny-app")
      cat("📁 Changed to academic-map-app/r-shiny-app directory\n")
    }
  }
  
  cat("📁 Working directory:", getwd(), "\n\n")
  
  # Check for required files
  required_files <- c(
    "app.R",
    "config.yml",
    ".Rprofile",
    "R/auth.R",
    "R/api_client.R",
    "R/database.R",
    "R/data_processor.R",
    "R/map_generator.R",
    "R/export_utils.R"
  )
  
  missing_files <- c()
  for (file in required_files) {
    if (!file.exists(file)) {
      missing_files <- c(missing_files, file)
      cat("❌", file, "- NOT FOUND\n")
    } else {
      cat("✅", file, "- Found\n")
    }
  }
  
  if (length(missing_files) > 0) {
    cat("\n❌ DEPLOYMENT BLOCKED: Missing required files!\n")
    cat("Missing:", paste(missing_files, collapse = ", "), "\n")
    return(FALSE)
  }
  
  # Check for data directories
  if (!dir.exists("data")) {
    cat("\n📁 Creating data directory...\n")
    dir.create("data", showWarnings = FALSE)
  }
  
  if (!dir.exists("www")) {
    cat("\n📁 Creating www directory...\n")
    dir.create("www", showWarnings = FALSE)
  }
  
  cat("\n✅ All prerequisites met!\n")
  return(TRUE)
}

# Function to configure Shinyapps.io account
configure_account <- function() {
  cat("\n🔐 Configuring Shinyapps.io account...\n")
  
  # Check if account is already configured
  accounts <- rsconnect::accounts()
  
  if (nrow(accounts) == 0) {
    cat("\n⚠️  No Shinyapps.io account configured!\n")
    cat("Please configure your account:\n")
    cat("1. Sign up at https://www.shinyapps.io/\n")
    cat("2. Get your token from Account > Tokens\n")
    cat("3. Run: rsconnect::setAccountInfo(name='YOUR_ACCOUNT', token='YOUR_TOKEN', secret='YOUR_SECRET')\n")
    return(FALSE)
  }
  
  cat("✅ Account configured:", accounts$name[1], "\n")
  return(TRUE)
}

# Function to create deployment bundle
create_bundle <- function() {
  cat("\n📦 Creating deployment bundle...\n")
  
  # Create a temporary deployment directory
  deploy_dir <- "shinyapps_deploy"
  
  if (dir.exists(deploy_dir)) {
    unlink(deploy_dir, recursive = TRUE)
  }
  
  dir.create(deploy_dir)
  
  # Copy all necessary files
  files_to_copy <- list.files(".", recursive = TRUE)
  
  # Exclude unnecessary files
  exclude_patterns <- c(
    "^\\.git",
    "rsconnect",
    "shinyapps_deploy",
    "\\.Rproj$",
    "\\.Rhistory",
    "\\.RData",
    "test_",
    "_test\\.",
    "\\.bak$",
    "\\.backup$",
    "AUDIT_REPORT",
    "IMPLEMENTATION_COMPLETE"
  )
  
  for (file in files_to_copy) {
    # Check if file should be excluded
    should_exclude <- FALSE
    for (pattern in exclude_patterns) {
      if (grepl(pattern, file)) {
        should_exclude <- TRUE
        break
      }
    }
    
    if (!should_exclude) {
      # Create directory structure
      dir_path <- dirname(file)
      if (dir_path != ".") {
        dir.create(file.path(deploy_dir, dir_path), recursive = TRUE, showWarnings = FALSE)
      }
      
      # Copy file
      file.copy(file, file.path(deploy_dir, file), overwrite = TRUE)
    }
  }
  
  cat("✅ Deployment bundle created in:", deploy_dir, "\n")
  return(deploy_dir)
}

# Function to test the app locally before deployment
test_local <- function() {
  cat("\n🧪 Testing application locally...\n")
  cat("Starting local test server...\n")
  cat("Please check: http://localhost:3838\n")
  cat("Login with: admin / admin123\n")
  cat("Press Ctrl+C to stop the test and continue deployment.\n\n")
  
  # Run the app locally
  tryCatch({
    shiny::runApp(launch.browser = FALSE, port = 3838)
  }, interrupt = function(e) {
    cat("\n✅ Local test completed.\n")
  })
  
  # Ask if ready to deploy
  cat("\n❓ Did the application work correctly? (y/n): ")
  response <- readline()
  
  return(tolower(response) == "y")
}

# Function to deploy to Shinyapps.io
deploy_app <- function(app_name = "academic-legislative-monitor") {
  cat("\n🚀 Deploying to Shinyapps.io...\n")
  cat("App name:", app_name, "\n")
  
  # Deploy the application
  tryCatch({
    rsconnect::deployApp(
      appDir = ".",
      appName = app_name,
      appTitle = "Monitor Legislativo Acadêmico",
      forceUpdate = TRUE,
      launch.browser = TRUE
    )
    
    cat("\n✅ DEPLOYMENT SUCCESSFUL!\n")
    cat("🌐 Your app is available at: https://YOUR_ACCOUNT.shinyapps.io/", app_name, "\n")
    cat("\n📋 Default credentials:\n")
    cat("👨‍💼 admin / admin123\n")
    cat("👨‍🔬 researcher / research123\n")
    cat("👨‍🎓 student / student123\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("\n❌ DEPLOYMENT FAILED!\n")
    cat("Error:", e$message, "\n")
    return(FALSE)
  })
}

# Main deployment workflow
main <- function() {
  cat("\n🏁 Starting deployment process...\n")
  
  # Step 1: Check prerequisites
  if (!check_prerequisites()) {
    cat("\n❌ Deployment aborted due to missing prerequisites.\n")
    return(FALSE)
  }
  
  # Step 2: Configure account
  if (!configure_account()) {
    cat("\n❌ Deployment aborted. Please configure your Shinyapps.io account.\n")
    return(FALSE)
  }
  
  # Step 3: Test locally
  cat("\n❓ Do you want to test the app locally first? (y/n): ")
  if (tolower(readline()) == "y") {
    if (!test_local()) {
      cat("\n❌ Deployment aborted. Please fix issues before deploying.\n")
      return(FALSE)
    }
  }
  
  # Step 4: Get app name
  cat("\n📝 Enter app name for deployment (default: academic-legislative-monitor): ")
  app_name <- readline()
  if (app_name == "") {
    app_name <- "academic-legislative-monitor"
  }
  
  # Step 5: Deploy
  cat("\n🚀 Ready to deploy to Shinyapps.io!\n")
  cat("App name:", app_name, "\n")
  cat("❓ Proceed with deployment? (y/n): ")
  
  if (tolower(readline()) == "y") {
    deploy_app(app_name)
  } else {
    cat("\n❌ Deployment cancelled.\n")
  }
}

# Create deployment checklist
create_checklist <- function() {
  checklist <- "
# 📋 DEPLOYMENT CHECKLIST

## Prerequisites
- [ ] R 4.3+ installed
- [ ] All required R packages installed (.Rprofile)
- [ ] Shinyapps.io account created
- [ ] rsconnect package configured with credentials

## Pre-deployment Testing
- [ ] Run test_auth_integration.R successfully
- [ ] Test login with all three user types
- [ ] Verify map loads with real data
- [ ] Test export functionality
- [ ] Check API connectivity

## Deployment Configuration
- [ ] App name chosen
- [ ] Resource allocation planned (free tier = 25 hours/month)
- [ ] Monitoring setup planned

## Post-deployment
- [ ] Test live URL
- [ ] Verify authentication works
- [ ] Monitor logs for errors
- [ ] Share URL with academic team

## Security Reminders
- [ ] Change default passwords for production
- [ ] Review API rate limits
- [ ] Set up usage monitoring
"
  
  writeLines(checklist, "DEPLOYMENT_CHECKLIST.md")
  cat("📋 Created DEPLOYMENT_CHECKLIST.md\n")
}

# Run deployment
cat("\n=== ACADEMIC LEGISLATIVE MONITOR DEPLOYMENT ===\n")
cat("📚 Version: 1.0.0\n")
cat("🌐 Target: Shinyapps.io\n")
cat("💰 Cost: FREE tier (25 hours/month) or $9/month\n")
cat("🔒 Security: All Priority 1 fixes implemented\n")

# Create checklist
create_checklist()

# Ask to start deployment
cat("\n❓ Start deployment process? (y/n): ")
if (tolower(readline()) == "y") {
  main()
} else {
  cat("\n📌 Deployment postponed. Run this script when ready.\n")
  cat("📋 Review DEPLOYMENT_CHECKLIST.md before proceeding.\n")
}