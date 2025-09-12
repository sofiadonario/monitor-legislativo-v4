#!/usr/bin/env Rscript

# Database Status Check Script
cat("=== DATABASE STATUS CHECK ===\n\n")

# Check if we're on Railway
is_railway <- nchar(Sys.getenv("RAILWAY_ENVIRONMENT")) > 0 || 
              nchar(Sys.getenv("DATABASE_URL")) > 0

cat("Environment: ", if(is_railway) "Railway" else "Local", "\n")

# Load packages
if(require(DBI, quietly = TRUE) && require(RPostgres, quietly = TRUE)) {
  cat("✅ Database packages available\n")
  
  # Try to connect
  db_url <- Sys.getenv("DATABASE_URL", "")
  
  if(nchar(db_url) > 0) {
    cat("DATABASE_URL is set\n")
    
    # Parse the URL
    if(grepl("postgres.railway.internal", db_url)) {
      cat("Using Railway internal URL\n")
      host <- "postgres.railway.internal"
      port <- 5432
    } else if(grepl("nozomi.proxy.rlwy.net", db_url)) {
      cat("Using Railway external URL\n")  
      host <- "nozomi.proxy.rlwy.net"
      port <- 44844
    } else {
      cat("Unknown database URL format\n")
      host <- ""
    }
    
    if(host != "") {
      tryCatch({
        con <- dbConnect(
          RPostgres::Postgres(),
          host = host,
          port = port,
          dbname = "railway",
          user = "postgres",
          password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
        )
        
        cat("\n✅ DATABASE CONNECTED!\n\n")
        
        # Check tables
        tables <- dbListTables(con)
        cat("Tables in database:\n")
        for(table in tables) {
          count <- dbGetQuery(con, paste("SELECT COUNT(*) as n FROM", table))$n
          cat("  -", table, ":", format(count, big.mark=","), "rows\n")
        }
        
        # Check documents table specifically
        if("documents" %in% tables) {
          cat("\n📊 Documents table analysis:\n")
          
          # Get column names
          cols <- dbListFields(con, "documents")
          cat("  Columns:", paste(cols, collapse=", "), "\n")
          
          # Sample data
          sample <- dbGetQuery(con, "SELECT * FROM documents LIMIT 5")
          cat("  Sample records:\n")
          print(head(sample[,c("titulo", "estado", "data")], 5))
          
          # State distribution
          states <- dbGetQuery(con, "SELECT estado, COUNT(*) as n FROM documents GROUP BY estado ORDER BY n DESC LIMIT 10")
          cat("\n  Top states:\n")
          print(states)
        } else {
          cat("\n❌ No 'documents' table found!\n")
          cat("The database needs to be populated.\n")
        }
        
        dbDisconnect(con)
        
      }, error = function(e) {
        cat("\n❌ Connection failed:", e$message, "\n")
      })
    }
    
  } else {
    cat("❌ DATABASE_URL not set\n")
  }
  
} else {
  cat("❌ Database packages not available\n")
}

# Check CSV files
cat("\n=== CSV FILES CHECK ===\n")
csv_files <- c(
  "data_current/processed/production/lexml_unified_dataset.csv",
  "railway_data_50k.csv",
  "railway_data_10k.csv"
)

for(csv in csv_files) {
  if(file.exists(csv)) {
    size_mb <- round(file.size(csv) / (1024*1024), 1)
    # Count rows quickly
    row_count <- tryCatch({
      length(readLines(csv, n = -1))
    }, error = function(e) {
      "unknown"
    })
    cat("✅", csv, ":", size_mb, "MB,", row_count, "rows\n")
  } else {
    cat("❌", csv, ": NOT FOUND\n")
  }
}

cat("\n=== CHECK COMPLETE ===\n")