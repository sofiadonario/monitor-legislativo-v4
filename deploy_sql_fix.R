# Deploy SQL Fix Script
# This script executes the IMMEDIATE_RAILWAY_FIX.sql to fix SQL type mismatches

cat("🔧 DEPLOYING SQL FIX FOR TYPE MISMATCHES...\n")

library(DBI)
library(RPostgres)

# Function to execute SQL fix
deploy_sql_fix <- function() {
  tryCatch({
    # Get database connection
    if (exists(".db_pool") && inherits(.db_pool, "Pool")) {
      cat("✅ Using existing database pool\n")
      conn <- poolCheckout(.db_pool)
      on.exit(poolReturn(conn))
    } else if (Sys.getenv("DATABASE_URL") != "") {
      cat("🔄 Creating new database connection from DATABASE_URL\n")
      conn <- dbConnect(RPostgres::Postgres(), 
                       dbname = Sys.getenv("PGDATABASE", "railway"),
                       host = Sys.getenv("PGHOST", "localhost"),
                       port = as.integer(Sys.getenv("PGPORT", 5432)),
                       user = Sys.getenv("PGUSER", "postgres"),
                       password = Sys.getenv("PGPASSWORD", ""))
      on.exit(dbDisconnect(conn))
    } else {
      stop("No database connection available")
    }
    
    # Read SQL fix file
    if (!file.exists("IMMEDIATE_RAILWAY_FIX.sql")) {
      stop("IMMEDIATE_RAILWAY_FIX.sql not found")
    }
    
    sql_content <- readLines("IMMEDIATE_RAILWAY_FIX.sql", warn = FALSE)
    sql_content <- paste(sql_content, collapse = "\n")
    
    # Split into individual statements (separated by semicolons)
    sql_statements <- unlist(strsplit(sql_content, ";"))
    sql_statements <- trimws(sql_statements)
    sql_statements <- sql_statements[nchar(sql_statements) > 0]
    
    # Execute each statement
    for (i in seq_along(sql_statements)) {
      stmt <- sql_statements[i]
      
      # Skip comments and empty lines
      if (grepl("^--", stmt) || nchar(trimws(stmt)) == 0) {
        next
      }
      
      # Check if it's a SELECT statement
      if (grepl("^SELECT", stmt, ignore.case = TRUE)) {
        cat(sprintf("📊 Executing query %d/%d...\n", i, length(sql_statements)))
        result <- dbGetQuery(conn, stmt)
        print(result)
      } else {
        cat(sprintf("🔨 Executing statement %d/%d...\n", i, length(sql_statements)))
        dbExecute(conn, stmt)
      }
    }
    
    cat("✅ SQL FIX DEPLOYED SUCCESSFULLY!\n")
    
    # Verify the fix
    cat("\n🔍 VERIFYING FIX...\n")
    
    # Test the problematic query
    test_query <- "
      SELECT 
        EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at)) as year, 
        COUNT(*) as count 
      FROM documents 
      WHERE COALESCE(data_publicacao, created_at) IS NOT NULL 
      GROUP BY year 
      ORDER BY year DESC
      LIMIT 5
    "
    
    result <- dbGetQuery(conn, test_query)
    cat("✅ Problematic query now works! Results:\n")
    print(result)
    
    # Check total document count
    total_count <- dbGetQuery(conn, "SELECT COUNT(*) as total FROM documents")
    cat(sprintf("\n📊 Total documents in view: %s\n", format(total_count$total, big.mark = ",")))
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ ERROR deploying SQL fix:", e$message, "\n")
    return(FALSE)
  })
}

# Execute the deployment
if (interactive()) {
  cat("\n⚠️  WARNING: This will DROP and RECREATE the documents view!\n")
  cat("Continue? (y/n): ")
  response <- readline()
  
  if (tolower(response) == "y") {
    success <- deploy_sql_fix()
    if (success) {
      cat("\n🎉 SQL FIX DEPLOYMENT COMPLETE!\n")
      cat("The dashboard should now show consistent data across all components.\n")
    }
  } else {
    cat("Deployment cancelled.\n")
  }
} else {
  # Non-interactive mode - just deploy
  success <- deploy_sql_fix()
  if (success) {
    cat("\n🎉 SQL FIX DEPLOYMENT COMPLETE!\n")
  }
}