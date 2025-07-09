#!/usr/bin/env Rscript

# Academic Legislative Monitor - Complete Setup and Run Script
# This script handles the complete setup and deployment of the R Shiny application

cat("\n")
cat("==================================================\n")
cat("   MONITOR LEGISLATIVO ACADÊMICO                 \n")
cat("   Complete Setup and Deployment Script           \n")
cat("==================================================\n")
cat("\n")

# Function to check R version
check_r_version <- function() {
  cat("🔍 Checking R version...\n")
  r_version_major <- as.numeric(R.version$major)
  r_version_minor <- as.numeric(strsplit(R.version$minor, "\\.")[[1]][1])
  r_version_full <- paste(R.version$major, R.version$minor, sep = ".")
  
  if (r_version_major < 4) {
    cat("❌ R version", r_version_full, "detected. R 4.0+ is required.\n")
    cat("   Please update R from: https://cloud.r-project.org/\n")
    return(FALSE)
  }
  
  cat("✅ R version", r_version_full, "detected\n")
  return(TRUE)
}

# Function to install system dependencies
check_system_deps <- function() {
  cat("\n🔍 Checking system dependencies...\n")
  
  # Check for required system libraries based on OS
  if (Sys.info()["sysname"] == "Linux") {
    cat("📋 Linux system detected\n")
    cat("   Please ensure these packages are installed:\n")
    cat("   - libgdal-dev (for sf package)\n")
    cat("   - libudunits2-dev (for units package)\n")
    cat("   - libproj-dev (for proj4 support)\n")
    cat("   - libgeos-dev (for spatial operations)\n")
    cat("   Install with: sudo apt-get install libgdal-dev libudunits2-dev libproj-dev libgeos-dev\n")
  } else if (Sys.info()["sysname"] == "Darwin") {
    cat("📋 macOS system detected\n")
    cat("   Please ensure these packages are installed:\n")
    cat("   - gdal (for sf package)\n")
    cat("   - udunits (for units package)\n")
    cat("   - proj (for proj4 support)\n")
    cat("   - geos (for spatial operations)\n")
    cat("   Install with: brew install gdal udunits proj geos\n")
  } else if (Sys.info()["sysname"] == "Windows") {
    cat("📋 Windows system detected\n")
    cat("   R packages will handle most dependencies automatically\n")
  }
  
  return(TRUE)
}

# Function to setup directories
setup_directories <- function() {
  cat("\n📁 Setting up directory structure...\n")
  
  dirs <- list(
    "data" = "Main data directory",
    "data/cache" = "API cache storage",
    "data/geographic" = "Geographic data cache",
    "www" = "Static assets",
    "logs" = "Application logs",
    "exports" = "User exports"
  )
  
  for (dir_name in names(dirs)) {
    if (!dir.exists(dir_name)) {
      dir.create(dir_name, recursive = TRUE, showWarnings = FALSE)
      cat("✅ Created:", dir_name, "-", dirs[[dir_name]], "\n")
    } else {
      cat("📁", dir_name, "already exists\n")
    }
  }
  
  return(TRUE)
}

# Function to download geographic data
setup_geographic_data <- function() {
  cat("\n🗺️ Setting up geographic data...\n")
  
  # Check if we can load geobr
  if (!requireNamespace("geobr", quietly = TRUE)) {
    cat("⚠️  geobr package not available - skipping geographic data download\n")
    cat("   Geographic features will load data on first use\n")
    return(TRUE)
  }
  
  # Try to download Brazil states data
  tryCatch({
    cat("📥 Downloading Brazil states boundaries...\n")
    cat("   This may take a few minutes on first run...\n")
    
    # Create a simple test to see if geobr works
    test_data <- geobr::read_state(code_state = "SP", year = 2020, showProgress = FALSE)
    
    if (!is.null(test_data)) {
      cat("✅ Geographic data source is accessible\n")
      cat("   Full data will be downloaded on first use\n")
    }
  }, error = function(e) {
    cat("⚠️  Could not download geographic data now\n")
    cat("   Data will be downloaded when the app starts\n")
    cat("   Error:", e$message, "\n")
  })
  
  return(TRUE)
}

# Function to create initial database
setup_database <- function() {
  cat("\n💾 Setting up database...\n")
  
  if (!requireNamespace("DBI", quietly = TRUE) || !requireNamespace("RSQLite", quietly = TRUE)) {
    cat("⚠️  Database packages not available yet\n")
    cat("   Database will be created on first run\n")
    return(TRUE)
  }
  
  db_path <- "data/legislative.db"
  
  if (file.exists(db_path)) {
    cat("📊 Database already exists at:", db_path, "\n")
    
    # Check if we can connect
    tryCatch({
      con <- DBI::dbConnect(RSQLite::SQLite(), db_path)
      tables <- DBI::dbListTables(con)
      cat("✅ Database has", length(tables), "tables\n")
      DBI::dbDisconnect(con)
    }, error = function(e) {
      cat("⚠️  Could not connect to database\n")
    })
  } else {
    cat("📊 Database will be created on first run\n")
  }
  
  return(TRUE)
}

# Function to validate configuration
validate_config <- function() {
  cat("\n⚙️ Validating configuration...\n")
  
  # Check config.yml
  if (!file.exists("config.yml")) {
    cat("❌ config.yml not found!\n")
    return(FALSE)
  }
  
  # Check app.R
  if (!file.exists("app.R")) {
    cat("❌ app.R not found!\n")
    return(FALSE)
  }
  
  # Check R modules
  r_modules <- c("auth.R", "api_client.R", "database.R", "map_generator.R", "export_utils.R")
  missing_modules <- r_modules[!file.exists(file.path("R", r_modules))]
  
  if (length(missing_modules) > 0) {
    cat("❌ Missing R modules:", paste(missing_modules, collapse = ", "), "\n")
    return(FALSE)
  }
  
  cat("✅ All required files present\n")
  return(TRUE)
}

# Function to test API connectivity
test_api_connectivity <- function() {
  cat("\n🌐 Testing API connectivity...\n")
  
  if (!requireNamespace("httr", quietly = TRUE)) {
    cat("⚠️  httr package not available - skipping API tests\n")
    return(TRUE)
  }
  
  # Test Câmara dos Deputados API
  tryCatch({
    cat("📡 Testing Câmara dos Deputados API...\n")
    response <- httr::GET(
      "https://dadosabertos.camara.leg.br/api/v2/proposicoes",
      query = list(dataInicio = "2024-01-01", dataFim = "2024-01-01", itens = 1),
      httr::timeout(10)
    )
    
    if (httr::status_code(response) == 200) {
      cat("✅ Câmara API is accessible\n")
    } else {
      cat("⚠️  Câmara API returned status:", httr::status_code(response), "\n")
    }
  }, error = function(e) {
    cat("⚠️  Could not reach Câmara API\n")
  })
  
  return(TRUE)
}

# Function to display final instructions
show_final_instructions <- function() {
  cat("\n")
  cat("==================================================\n")
  cat("🎉 SETUP COMPLETE!                               \n")
  cat("==================================================\n")
  cat("\n")
  cat("📌 Quick Start Instructions:\n")
  cat("───────────────────────────────────────────\n")
  cat("1. The application will start automatically\n")
  cat("2. Your browser will open to: http://localhost:3838\n")
  cat("3. Login with test credentials:\n")
  cat("   👨‍💼 admin / admin123\n")
  cat("   👨‍🔬 researcher / research123\n")
  cat("   👨‍🎓 student / student123\n")
  cat("\n")
  cat("📚 Available Features:\n")
  cat("───────────────────────────────────────────\n")
  cat("✅ Search Brazilian legislation\n")
  cat("✅ Interactive maps by state\n")
  cat("✅ Export data in multiple formats\n")
  cat("✅ Real-time API integration\n")
  cat("✅ Academic citation generation\n")
  cat("\n")
  cat("🛠️ Troubleshooting:\n")
  cat("───────────────────────────────────────────\n")
  cat("- If packages fail to install: Check internet connection\n")
  cat("- If geographic data fails: The app will still work\n")
  cat("- If APIs are slow: Data is cached locally\n")
  cat("- For help: See README.md\n")
  cat("\n")
  cat("🛑 Press Ctrl+C to stop the application\n")
  cat("==================================================\n")
  cat("\n")
}

# Main setup and run function
main <- function() {
  cat("🚀 Starting complete setup process...\n")
  
  # Check R version
  if (!check_r_version()) {
    return(FALSE)
  }
  
  # Check system dependencies
  check_system_deps()
  
  # Source .Rprofile to install packages
  cat("\n📦 Installing required R packages...\n")
  cat("   This may take several minutes on first run...\n")
  source(".Rprofile")
  
  # Setup directories
  if (!setup_directories()) {
    cat("❌ Directory setup failed\n")
    return(FALSE)
  }
  
  # Validate configuration
  if (!validate_config()) {
    cat("❌ Configuration validation failed\n")
    return(FALSE)
  }
  
  # Setup geographic data
  setup_geographic_data()
  
  # Setup database
  setup_database()
  
  # Test API connectivity
  test_api_connectivity()
  
  # Show final instructions
  show_final_instructions()
  
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
    cat("\nPlease check the troubleshooting section above.\n")
  })
}

# Run the setup and application
main()