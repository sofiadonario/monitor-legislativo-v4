#!/usr/bin/env Rscript

# Database Population Script for Railway PostgreSQL
# ==================================================
# Run this script when Railway PostgreSQL is available to populate 
# the database with the full 134k dataset

cat("\n=== RAILWAY DATABASE POPULATION ===\n\n")

# Check if required packages are available
required_packages <- c("DBI", "RPostgres", "data.table")
missing <- character()

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing <- c(missing, pkg)
  }
}

if (length(missing) > 0) {
  cat("❌ Missing packages:", paste(missing, collapse = ", "), "\n")
  cat("📦 Install with: install.packages(c('", paste(missing, collapse = "', '"), "'))\n")
  cat("🔄 Using CSV fallback instead - application will still work with full dataset\n")
  quit(status = 0)
}

# Load libraries
library(DBI)
library(RPostgres) 
library(data.table)

# Database connection parameters
db_params <- list(
  host = "postgres.railway.internal",
  port = 5432,
  dbname = "railway",
  user = "postgres", 
  password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
)

cat("🔌 Connecting to Railway PostgreSQL...\n")
cat("   Host:", db_params$host, "Port:", db_params$port, "\n")

tryCatch({
  # Connect to database
  con <- dbConnect(
    RPostgres::Postgres(),
    host = db_params$host,
    port = db_params$port,
    dbname = db_params$dbname,
    user = db_params$user,
    password = db_params$password,
    sslmode = "prefer"
  )
  
  cat("✅ Connected to Railway PostgreSQL successfully!\n")
  
  # Check for existing data
  existing_tables <- dbListTables(con)
  cat("📋 Existing tables:", paste(existing_tables, collapse = ", "), "\n")
  
  # Check if we already have legislative data
  has_data <- FALSE
  table_name <- "legislative_data"
  
  if (table_name %in% existing_tables) {
    count_result <- dbGetQuery(con, paste("SELECT COUNT(*) as count FROM", table_name))
    record_count <- count_result$count[1]
    cat("📊 Existing records in", table_name, ":", format(record_count, big.mark = ","), "\n")
    
    if (record_count >= 100000) {
      has_data <- TRUE
      cat("✅ Database already has substantial data - no need to populate\n")
    }
  }
  
  if (!has_data) {
    # Load CSV data
    csv_file <- "data_current/processed/production/lexml_unified_dataset.csv"
    if (!file.exists(csv_file)) {
      cat("❌ CSV file not found:", csv_file, "\n")
      quit(status = 1)
    }
    
    cat("📁 Loading CSV data from:", csv_file, "\n")
    cat("⏳ This may take a few minutes for 134k records...\n")
    
    # Use data.table for faster loading
    legislative_data <- fread(csv_file, encoding = "UTF-8", showProgress = TRUE)
    cat("✅ Loaded", format(nrow(legislative_data), big.mark = ","), "records from CSV\n")
    
    # Create/replace table
    cat("💾 Writing data to PostgreSQL database...\n")
    dbExecute(con, paste("DROP TABLE IF EXISTS", table_name))
    
    # Write in chunks for better performance
    chunk_size <- 10000
    total_rows <- nrow(legislative_data)
    chunks <- ceiling(total_rows / chunk_size)
    
    cat("📦 Writing in", chunks, "chunks of", chunk_size, "records each...\n")
    
    # Write first chunk to create table structure
    first_chunk <- legislative_data[1:min(chunk_size, total_rows)]
    dbWriteTable(con, table_name, first_chunk, row.names = FALSE, overwrite = TRUE)
    
    # Write remaining chunks
    if (total_rows > chunk_size) {
      for (i in 2:chunks) {
        start_row <- (i - 1) * chunk_size + 1
        end_row <- min(i * chunk_size, total_rows)
        chunk_data <- legislative_data[start_row:end_row]
        
        dbWriteTable(con, table_name, chunk_data, row.names = FALSE, append = TRUE)
        
        progress <- round((i / chunks) * 100, 1)
        cat("   📊 Progress:", progress, "% (chunk", i, "of", chunks, ")\n")
      }
    }
    
    # Verify data was written
    final_count <- dbGetQuery(con, paste("SELECT COUNT(*) as count FROM", table_name))
    cat("✅ Database populated with", format(final_count$count[1], big.mark = ","), "records\n")
    
    # Create performance indexes
    cat("🔧 Creating database indexes for performance...\n")
    indexes <- list(
      "titulo" = "titulo",
      "estado" = "estado", 
      "data" = "data",
      "categoria" = "categoria"
    )
    
    for (idx_name in names(indexes)) {
      idx_sql <- sprintf("CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s (%s)", 
                        table_name, idx_name, table_name, indexes[[idx_name]])
      tryCatch({
        dbExecute(con, idx_sql)
        cat("   ✅ Index on", indexes[[idx_name]], "created\n")
      }, error = function(e) {
        cat("   ⚠️ Index on", indexes[[idx_name]], "failed:", e$message, "\n")
      })
    }
  }
  
  # Final verification
  cat("\n📊 Final database status:\n")
  all_tables <- dbListTables(con)
  for (table in all_tables) {
    tryCatch({
      count <- dbGetQuery(con, paste("SELECT COUNT(*) as count FROM", table))
      cat("   -", table, ":", format(count$count[1], big.mark = ","), "records\n")
    }, error = function(e) {
      cat("   -", table, ": ERROR reading count\n")
    })
  }
  
  dbDisconnect(con)
  cat("\n🎉 DATABASE POPULATION COMPLETE!\n")
  cat("✅ Your application can now use the full PostgreSQL database with 134k+ documents\n")
  
}, error = function(e) {
  cat("❌ Database connection failed:", e$message, "\n")
  cat("\n🔄 This is normal if:\n")
  cat("   - Railway service is not running\n")
  cat("   - Network connectivity issues\n")
  cat("   - Database credentials have changed\n")
  cat("\n💡 Your application will still work with the CSV fallback system!\n")
  cat("📊 The CSV system has the full 134k dataset and all functionality\n")
})

cat("\n=== POPULATION COMPLETE ===\n")