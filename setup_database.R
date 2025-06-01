#!/usr/bin/env Rscript

# Complete Database Setup Script
# ==============================
# This script installs required packages, establishes database connection,
# and populates the database with the full 134k dataset if needed.

cat("\n=== DATABASE SETUP AND POPULATION ===\n\n")

# Step 1: Install required database packages
cat("1. Installing required database packages...\n")
required_packages <- c("DBI", "RPostgres", "pool", "data.table")

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat(sprintf("   Installing %s...\n", pkg))
    tryCatch({
      install.packages(pkg, repos = "https://cran.rstudio.com/", quiet = TRUE)
      cat(sprintf("   ✅ %s installed successfully\n", pkg))
    }, error = function(e) {
      cat(sprintf("   ❌ Failed to install %s: %s\n", pkg, e$message))
    })
  } else {
    cat(sprintf("   ✅ %s already installed\n", pkg))
  }
}

# Step 2: Set up environment variables
cat("\n2. Setting up database environment...\n")
Sys.setenv(DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway")
Sys.setenv(PGHOST = "postgres.railway.internal")
Sys.setenv(PGPORT = "5432")
Sys.setenv(PGDATABASE = "railway")
Sys.setenv(PGUSER = "postgres")
Sys.setenv(PGPASSWORD = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY")
cat("   ✅ Environment variables set\n")

# Step 3: Load libraries
cat("\n3. Loading database libraries...\n")
library(DBI)
library(RPostgres)
library(pool)
library(data.table)
cat("   ✅ Libraries loaded\n")

# Step 4: Test database connection
cat("\n4. Testing database connection...\n")
tryCatch({
  # Create connection pool
  db_pool <- dbPool(
    drv = RPostgres::Postgres(),
    host = "postgres.railway.internal",
    port = 5432,
    dbname = "railway", 
    user = "postgres",
    password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY",
    sslmode = "prefer"
  )
  
  # Test query
  result <- dbGetQuery(db_pool, "SELECT version() as pg_version")
  cat("   ✅ Database connection successful\n")
  cat("   📋 PostgreSQL version:", result$pg_version[1], "\n")
  
  # Step 5: Check existing tables and data
  cat("\n5. Checking existing database tables...\n")
  
  # List all tables
  tables <- dbGetQuery(db_pool, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
  if (nrow(tables) > 0) {
    cat("   📋 Existing tables:\n")
    for (table in tables$table_name) {
      count_query <- sprintf("SELECT COUNT(*) as count FROM %s", table)
      tryCatch({
        count_result <- dbGetQuery(db_pool, count_query)
        cat(sprintf("      - %s: %s records\n", table, format(count_result$count, big.mark = ",")))
      }, error = function(e) {
        cat(sprintf("      - %s: ERROR reading count\n", table))
      })
    }
  } else {
    cat("   ⚠️ No tables found - database is empty\n")
  }
  
  # Step 6: Create table and populate with full dataset if needed
  cat("\n6. Checking for main legislative data table...\n")
  
  # Check for existing legislative data table
  main_table_exists <- FALSE
  main_table_name <- NULL
  table_names_to_check <- c("documents", "lexml_parsed_enhanced", "legislative_data", "brazilian_legislative_complete")
  
  for (table_name in table_names_to_check) {
    table_exists <- dbExistsTable(db_pool, table_name)
    if (table_exists) {
      count_result <- dbGetQuery(db_pool, sprintf("SELECT COUNT(*) as count FROM %s", table_name))
      record_count <- count_result$count
      cat(sprintf("   📋 Table '%s' exists with %s records\n", table_name, format(record_count, big.mark = ",")))
      
      if (record_count >= 100000) {  # Has substantial data
        main_table_exists <- TRUE
        main_table_name <- table_name
        cat(sprintf("   ✅ Found populated table: %s\n", table_name))
        break
      }
    }
  }
  
  # Step 7: Populate database if needed
  if (!main_table_exists) {
    cat("\n7. Database needs population - loading full dataset...\n")
    
    # Check if CSV file exists
    csv_file <- "data_current/processed/production/lexml_unified_dataset.csv"
    if (file.exists(csv_file)) {
      cat(sprintf("   📁 Loading data from: %s\n", csv_file))
      
      # Read CSV data
      cat("   📊 Reading CSV data (this may take a few minutes)...\n")
      legislative_data <- fread(csv_file, encoding = "UTF-8")
      cat(sprintf("   ✅ Loaded %s records from CSV\n", format(nrow(legislative_data), big.mark = ",")))
      
      # Create table
      table_name <- "legislative_data"
      cat(sprintf("   🔧 Creating table '%s'...\n", table_name))
      
      # Drop table if exists
      dbExecute(db_pool, sprintf("DROP TABLE IF EXISTS %s", table_name))
      
      # Write data to database
      cat("   💾 Writing data to database (this may take several minutes)...\n")
      dbWriteTable(db_pool, table_name, legislative_data, overwrite = TRUE, row.names = FALSE)
      
      # Verify insertion
      final_count <- dbGetQuery(db_pool, sprintf("SELECT COUNT(*) as count FROM %s", table_name))
      cat(sprintf("   ✅ Database populated with %s records\n", format(final_count$count, big.mark = ",")))
      
      # Create indexes for performance
      cat("   🔧 Creating database indexes...\n")
      tryCatch({
        dbExecute(db_pool, sprintf("CREATE INDEX IF NOT EXISTS idx_%s_titulo ON %s (titulo)", table_name, table_name))
        dbExecute(db_pool, sprintf("CREATE INDEX IF NOT EXISTS idx_%s_estado ON %s (estado)", table_name, table_name))
        dbExecute(db_pool, sprintf("CREATE INDEX IF NOT EXISTS idx_%s_data ON %s (data)", table_name, table_name))
        dbExecute(db_pool, sprintf("CREATE INDEX IF NOT EXISTS idx_%s_categoria ON %s (categoria)", table_name, table_name))
        cat("   ✅ Indexes created successfully\n")
      }, error = function(e) {
        cat("   ⚠️ Index creation failed:", e$message, "\n")
      })
      
    } else {
      cat(sprintf("   ❌ CSV file not found: %s\n", csv_file))
    }
  }
  
  # Step 8: Final verification
  cat("\n8. Final database verification...\n")
  tables_final <- dbGetQuery(db_pool, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
  cat("   📋 Final database state:\n")
  for (table in tables_final$table_name) {
    count_result <- dbGetQuery(db_pool, sprintf("SELECT COUNT(*) as count FROM %s", table))
    cat(sprintf("      - %s: %s records\n", table, format(count_result$count, big.mark = ",")))
  }
  
  # Close connection
  poolClose(db_pool)
  cat("\n✅ DATABASE SETUP COMPLETE!\n")
  
}, error = function(e) {
  cat("❌ Database connection failed:", e$message, "\n")
  cat("This may be due to:\n")
  cat("  - Network connectivity issues\n") 
  cat("  - Railway service being down\n")
  cat("  - Incorrect credentials\n")
  cat("  - Firewall blocking the connection\n")
})

cat("\n=== SETUP COMPLETE ===\n")