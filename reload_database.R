#!/usr/bin/env Rscript

# Script to reload database after municipality-state parsing fix
# This script loads the fixed CSV files from data_current/processed/ into the database

cat("🚀 Starting database reload after municipality-state parsing fix\n")
cat(paste(rep("=", 60), collapse = ""), "\n")

# Source the database connection module
source("scripts/R/database_connection.R")

# Initialize database connection
cat("🔄 Initializing database connection...\n")
init_db_connection()

# Check if connection was successful
if (is.null(db_pool)) {
  cat("❌ Failed to initialize database connection\n")
  quit(status = 1)
}

cat("✅ Database connection initialized successfully\n")

# Populate database with CSV data from data_current/processed/
cat("🔄 Starting CSV data population...\n")
result <- populate_database_with_csv_data()

if (result) {
  cat("✅ Database reload completed successfully!\n")
  cat("📊 Municipality-state parsing fix has been applied to the database\n")
} else {
  cat("❌ Database reload failed\n")
  quit(status = 1)
}

# Clean up
cat("🧹 Cleaning up database connections...\n")
close_db_connection()

cat("✅ Database reload process completed successfully!\n")