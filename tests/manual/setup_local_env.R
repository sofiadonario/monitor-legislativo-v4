#!/usr/bin/env Rscript

# ==============================================================================
# SETUP SCRIPT FOR LOCAL DEVELOPMENT
# ==============================================================================
# This script helps configure the local environment for Monitor Legislativo v4
# Run this script to set up database connections and test the application
# ==============================================================================

cat("==============================================================================\n")
cat("Monitor Legislativo v4 - Local Development Setup\n")
cat("==============================================================================\n\n")

# 1. Check required packages
cat("Step 1: Checking required packages...\n")
required_packages <- c("shiny", "DBI", "RPostgres", "DT", "leaflet", "sf", "ggplot2", "shinythemes")
missing_packages <- required_packages[!required_packages %in% installed.packages()[,"Package"]]

if(length(missing_packages) > 0) {
  cat("❌ Missing packages:", paste(missing_packages, collapse = ", "), "\n")
  cat("Installing missing packages...\n")
  install.packages(missing_packages)
} else {
  cat("✅ All required packages are installed\n")
}

# 2. Database Configuration
cat("\nStep 2: Database Configuration\n")
cat("--------------------------------\n")
cat("Please enter your database credentials:\n\n")

# Check if environment variables are already set
if(Sys.getenv("PGHOST") != "") {
  cat("Current database configuration:\n")
  cat("  Host:", Sys.getenv("PGHOST"), "\n")
  cat("  Port:", Sys.getenv("PGPORT"), "\n")
  cat("  Database:", Sys.getenv("PGDATABASE"), "\n")
  cat("  User:", Sys.getenv("PGUSER"), "\n")
  
  use_existing <- readline("Use existing configuration? (y/n): ")
  if(tolower(use_existing) != "y") {
    # Get new credentials
    pghost <- readline("Database host (e.g., localhost): ")
    pgport <- readline("Database port (default 5432): ")
    pgdatabase <- readline("Database name (e.g., monitor_legislativo): ")
    pguser <- readline("Database user: ")
    pgpassword <- readline("Database password: ")
    
    # Set environment variables
    Sys.setenv(PGHOST = pghost)
    Sys.setenv(PGPORT = ifelse(pgport == "", "5432", pgport))
    Sys.setenv(PGDATABASE = pgdatabase)
    Sys.setenv(PGUSER = pguser)
    Sys.setenv(PGPASSWORD = pgpassword)
  }
} else {
  cat("No database configuration found. Please enter credentials:\n")
  pghost <- readline("Database host (e.g., localhost): ")
  pgport <- readline("Database port (default 5432): ")
  pgdatabase <- readline("Database name (e.g., monitor_legislativo): ")
  pguser <- readline("Database user: ")
  pgpassword <- readline("Database password: ")
  
  # Set environment variables
  Sys.setenv(PGHOST = pghost)
  Sys.setenv(PGPORT = ifelse(pgport == "", "5432", pgport))
  Sys.setenv(PGDATABASE = pgdatabase)
  Sys.setenv(PGUSER = pguser)
  Sys.setenv(PGPASSWORD = pgpassword)
}

# 3. Test Database Connection
cat("\nStep 3: Testing database connection...\n")
library(DBI)
library(RPostgres)

test_connection <- function() {
  tryCatch({
    conn <- dbConnect(
      RPostgres::Postgres(),
      host = Sys.getenv("PGHOST"),
      port = as.integer(Sys.getenv("PGPORT", "5432")),
      dbname = Sys.getenv("PGDATABASE"),
      user = Sys.getenv("PGUSER"),
      password = Sys.getenv("PGPASSWORD")
    )
    
    # Test query
    result <- dbGetQuery(conn, "SELECT 1 as test")
    
    # Check if documents table exists
    tables <- dbListTables(conn)
    has_documents <- "documents" %in% tables
    
    if(has_documents) {
      doc_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
      cat("✅ Database connected successfully!\n")
      cat("   Found", doc_count$count, "documents in database\n")
    } else {
      cat("⚠️  Database connected but 'documents' table not found\n")
      cat("   Available tables:", paste(tables, collapse = ", "), "\n")
    }
    
    dbDisconnect(conn)
    return(TRUE)
  }, error = function(e) {
    cat("❌ Database connection failed:", e$message, "\n")
    return(FALSE)
  })
}

db_connected <- test_connection()

# 4. Create .Renviron file for permanent configuration
cat("\nStep 4: Saving configuration...\n")
save_config <- readline("Save configuration to .Renviron file for future sessions? (y/n): ")

if(tolower(save_config) == "y") {
  renviron_path <- file.path(getwd(), ".Renviron")
  config_lines <- c(
    paste0("PGHOST=", Sys.getenv("PGHOST")),
    paste0("PGPORT=", Sys.getenv("PGPORT")),
    paste0("PGDATABASE=", Sys.getenv("PGDATABASE")),
    paste0("PGUSER=", Sys.getenv("PGUSER")),
    paste0("PGPASSWORD=", Sys.getenv("PGPASSWORD"))
  )
  
  writeLines(config_lines, renviron_path)
  cat("✅ Configuration saved to .Renviron\n")
  cat("   This will be loaded automatically in future R sessions\n")
}

# 5. Launch Application
cat("\n==============================================================================\n")
if(db_connected) {
  cat("✅ Setup complete! Your environment is ready.\n\n")
  launch_app <- readline("Launch the application now? (y/n): ")
  
  if(tolower(launch_app) == "y") {
    cat("\nStarting Monitor Legislativo v4...\n")
    cat("The application will open in your web browser.\n")
    cat("Press Ctrl+C to stop the application.\n\n")
    
    # Source and run the app
    source("app_phoenix.R")
  } else {
    cat("\nTo start the application later, run:\n")
    cat("  R -e \"shiny::runApp('app.R')\"\n")
    cat("Or from within R:\n")
    cat("  shiny::runApp('app.R')\n")
  }
} else {
  cat("⚠️  Setup incomplete - database connection failed\n")
  cat("\nPlease check your database credentials and ensure the database server is running.\n")
  cat("Then run this setup script again.\n")
}

cat("\n==============================================================================\n")
