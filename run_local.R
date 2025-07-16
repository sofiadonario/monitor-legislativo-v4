#!/usr/bin/env Rscript

# Run Academic Legislative Monitor Locally
# Quick start script for local testing

cat("\n")
cat("==================================================\n")
cat("   MONITOR LEGISLATIVO ACADÊMICO                  \n")
cat("   Academic Legislative Monitor - R Shiny         \n")
cat("==================================================\n")
cat("\n")

# Function to check if packages are installed
check_packages <- function() {
  cat("📦 Checking required packages...\n")
  
  # Source .Rprofile to ensure all packages are loaded
  if (file.exists(".Rprofile")) {
    source(".Rprofile")
    cat("✅ Environment loaded from .Rprofile\n")
  } else {
    cat("⚠️  Warning: .Rprofile not found\n")
  }
  
  return(TRUE)
}

# Function to check data directories
check_directories <- function() {
  cat("\n📁 Checking directory structure...\n")
  
  dirs_to_check <- c("data_current", "data_current/cache", "data_current/geographic", "www")
  
  for (dir in dirs_to_check) {
    if (!dir.exists(dir)) {
      dir.create(dir, recursive = TRUE, showWarnings = FALSE)
      cat("📁 Created:", dir, "\n")
    } else {
      cat("✅", dir, "exists\n")
    }
  }
  
  return(TRUE)
}

# Function to display startup information
show_info <- function() {
  cat("\n")
  cat("🌐 Application Information:\n")
  cat("───────────────────────────────────────────\n")
  cat("📍 URL: http://localhost:3838\n")
  cat("🔐 Authentication Required\n")
  cat("\n")
  cat("👥 Test Credentials:\n")
  cat("───────────────────────────────────────────\n")
  cat("👨‍💼 Administrator: admin / admin123\n")
  cat("👨‍🔬 Researcher:   researcher / research123\n")
  cat("👨‍🎓 Student:      student / student123\n")
  cat("\n")
  cat("📊 Data Sources:\n")
  cat("───────────────────────────────────────────\n")
  cat("✅ Câmara dos Deputados (Federal)\n")
  cat("✅ Senado Federal (Federal)\n")
  cat("✅ LexML Brasil (All levels)\n")
  cat("✅ State Assemblies (When available)\n")
  cat("\n")
  cat("🛑 Press Ctrl+C to stop the application\n")
  cat("==================================================\n")
  cat("\n")
}

# Main execution
main <- function() {
  # Check packages
  if (!check_packages()) {
    cat("❌ Package check failed. Please install required packages.\n")
    return(FALSE)
  }
  
  # Check directories
  if (!check_directories()) {
    cat("❌ Directory setup failed.\n")
    return(FALSE)
  }
  
  # Show information
  show_info()
  
  # Start the application
  cat("🚀 Starting Academic Legislative Monitor...\n\n")
  
  tryCatch({
    shiny::runApp(
      launch.browser = TRUE,
      port = 3838,
      host = "127.0.0.1"
    )
  }, interrupt = function(e) {
    cat("\n\n✅ Application stopped.\n")
    cat("Thank you for using Academic Legislative Monitor!\n\n")
  }, error = function(e) {
    cat("\n\n❌ Error starting application:\n")
    cat(e$message, "\n")
    cat("\nPlease check:\n")
    cat("1. All required files exist (app.R, config.yml, etc.)\n")
    cat("2. All R packages are installed\n")
    cat("3. No other application is using port 3838\n")
  })
}

# Run the application
main()