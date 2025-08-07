# Database Connection Test Script for Monitor Legislativo v4
# This script tests the database connection and queries to diagnose issues

# Load required libraries
library(DBI)
library(RPostgres)
library(dplyr)

cat("\n=== DATABASE CONNECTION TEST ===\n")
cat("Time:", Sys.time(), "\n\n")

# 1. Check environment variable
cat("1. Checking DATABASE_URL environment variable...\n")
database_url <- Sys.getenv("DATABASE_URL")
cat("   DATABASE_URL present:", nchar(database_url) > 0, "\n")
cat("   DATABASE_URL length:", nchar(database_url), "\n")

if (nchar(database_url) > 0) {
  # Mask password for display
  url_masked <- gsub(":[^:@]+@", ":***@", database_url)
  cat("   DATABASE_URL (masked):", url_masked, "\n")
} else {
  cat("   ERROR: DATABASE_URL not found!\n")
  cat("   Please set DATABASE_URL environment variable\n")
  stop("DATABASE_URL not set")
}

# 2. Parse DATABASE_URL
cat("\n2. Parsing DATABASE_URL...\n")
parse_database_url <- function(url) {
  tryCatch({
    # Remove postgresql:// prefix
    url <- gsub("^postgresql://", "", url)
    
    # Split user:password@host:port/database
    if (grepl("@", url)) {
      parts <- strsplit(url, "@")[[1]]
      auth_part <- parts[1]
      host_part <- parts[2]
      
      # Extract user and password
      if (grepl(":", auth_part)) {
        auth_split <- strsplit(auth_part, ":")[[1]]
        user <- auth_split[1]
        password <- auth_split[2]
      } else {
        user <- auth_part
        password <- ""
      }
      
      # Extract host, port, and database
      if (grepl("/", host_part)) {
        host_db_split <- strsplit(host_part, "/")[[1]]
        host_port <- host_db_split[1]
        database <- host_db_split[2]
        
        if (grepl(":", host_port)) {
          host_port_split <- strsplit(host_port, ":")[[1]]
          host <- host_port_split[1]
          port <- as.integer(host_port_split[2])
        } else {
          host <- host_port
          port <- 5432L
        }
      } else {
        host <- host_part
        port <- 5432L
        database <- "postgres"
      }
      
      return(list(
        host = host,
        port = port,
        database = database,
        user = user,
        password = password
      ))
    }
    
    return(NULL)
  }, error = function(e) {
    cat("   ERROR parsing DATABASE_URL:", e$message, "\n")
    return(NULL)
  })
}

parsed_url <- parse_database_url(database_url)
if (!is.null(parsed_url)) {
  cat("   Host:", parsed_url$host, "\n")
  cat("   Port:", parsed_url$port, "\n")
  cat("   Database:", parsed_url$database, "\n")
  cat("   User:", parsed_url$user, "\n")
  cat("   Password:", if(nchar(parsed_url$password) > 0) "***" else "empty", "\n")
} else {
  stop("Failed to parse DATABASE_URL")
}

# 3. Test direct connection
cat("\n3. Testing direct database connection...\n")
conn <- NULL
tryCatch({
  conn <- dbConnect(
    RPostgres::Postgres(),
    host = parsed_url$host,
    port = parsed_url$port,
    dbname = parsed_url$database,
    user = parsed_url$user,
    password = parsed_url$password
  )
  cat("   ✅ Connection successful!\n")
  
  # 4. Check tables
  cat("\n4. Checking database tables...\n")
  tables <- dbListTables(conn)
  cat("   Found", length(tables), "tables:\n")
  for (table in tables) {
    cat("     -", table, "\n")
  }
  
  # 5. Check required tables
  cat("\n5. Checking required tables...\n")
  required_tables <- c("lexml_parsed_enhanced", "documents")
  for (table in required_tables) {
    if (table %in% tables) {
      count <- dbGetQuery(conn, paste("SELECT COUNT(*) as count FROM", table))$count
      cat("   ✅", table, "- Found with", count, "rows\n")
      
      # Show columns
      columns <- dbListFields(conn, table)
      cat("      Columns:", paste(columns, collapse = ", "), "\n")
    } else {
      cat("   ❌", table, "- NOT FOUND\n")
    }
  }
  
  # 6. Test sample queries
  cat("\n6. Testing sample queries...\n")
  
  # Test 1: Simple count query
  cat("   Test 1: Simple count from documents...\n")
  tryCatch({
    result <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
    cat("     ✅ Success: Found", result$count, "documents\n")
  }, error = function(e) {
    cat("     ❌ Error:", e$message, "\n")
  })
  
  # Test 2: Check for null data_publicacao
  cat("   Test 2: Check data_publicacao column...\n")
  tryCatch({
    result <- dbGetQuery(conn, "
      SELECT 
        COUNT(*) as total,
        COUNT(data_publicacao) as with_date,
        COUNT(*) - COUNT(data_publicacao) as null_dates
      FROM documents
    ")
    cat("     Total rows:", result$total, "\n")
    cat("     With date:", result$with_date, "\n")
    cat("     NULL dates:", result$null_dates, "\n")
  }, error = function(e) {
    cat("     ❌ Error:", e$message, "\n")
  })
  
  # Test 3: Sample data query
  cat("   Test 3: Fetching sample documents...\n")
  tryCatch({
    result <- dbGetQuery(conn, "
      SELECT 
        d.id,
        d.titulo,
        d.tipo,
        d.estado,
        d.data_publicacao,
        d.urn
      FROM documents d
      WHERE d.titulo IS NOT NULL
      ORDER BY d.data_publicacao DESC NULLS LAST
      LIMIT 5
    ")
    cat("     ✅ Success: Retrieved", nrow(result), "rows\n")
    if (nrow(result) > 0) {
      print(result)
    }
  }, error = function(e) {
    cat("     ❌ Error:", e$message, "\n")
  })
  
  # Test 4: Check analytics query
  cat("   Test 4: Testing analytics query (documents by year)...\n")
  tryCatch({
    result <- dbGetQuery(conn, "
      SELECT 
        EXTRACT(YEAR FROM data_publicacao) as year,
        COUNT(*) as count
      FROM documents 
      WHERE data_publicacao IS NOT NULL
      GROUP BY EXTRACT(YEAR FROM data_publicacao)
      ORDER BY year DESC
      LIMIT 5
    ")
    cat("     ✅ Success: Found data for", nrow(result), "years\n")
    if (nrow(result) > 0) {
      print(result)
    }
  }, error = function(e) {
    cat("     ❌ Error:", e$message, "\n")
  })
  
  # Test 5: Check distinct states
  cat("   Test 5: Checking distinct states...\n")
  tryCatch({
    result <- dbGetQuery(conn, "
      SELECT DISTINCT estado, COUNT(*) as count
      FROM documents 
      WHERE estado IS NOT NULL AND estado != ''
      GROUP BY estado
      ORDER BY count DESC
    ")
    cat("     ✅ Success: Found", nrow(result), "states\n")
    if (nrow(result) > 0) {
      print(result)
    }
  }, error = function(e) {
    cat("     ❌ Error:", e$message, "\n")
  })
  
  # Test 6: Check document types
  cat("   Test 6: Checking document types...\n")
  tryCatch({
    result <- dbGetQuery(conn, "
      SELECT tipo, COUNT(*) as count 
      FROM documents 
      WHERE tipo IS NOT NULL AND tipo != ''
      GROUP BY tipo 
      ORDER BY count DESC
    ")
    cat("     ✅ Success: Found", nrow(result), "document types\n")
    if (nrow(result) > 0) {
      print(result)
    }
  }, error = function(e) {
    cat("     ❌ Error:", e$message, "\n")
  })
  
}, error = function(e) {
  cat("   ❌ Connection failed:", e$message, "\n")
}, finally = {
  if (!is.null(conn)) {
    dbDisconnect(conn)
    cat("\n✅ Connection closed\n")
  }
})

cat("\n=== TEST COMPLETE ===\n")