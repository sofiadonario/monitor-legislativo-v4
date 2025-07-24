# Emergency Database Connection Fix
# Fixes database connection issues in Railway deployment

cat("🚨 EMERGENCY DATABASE CONNECTION FIX\n")

# ============================================================================
# 1. EMERGENCY DATABASE URL DETECTION
# ============================================================================

#' Emergency database URL detection for Railway
#' @return Database URL string
get_emergency_database_url <- function() {
  # Try multiple sources for DATABASE_URL
  sources <- list(
    # 1. Standard DATABASE_URL environment variable
    Sys.getenv("DATABASE_URL"),
    
    # 2. Railway-specific environment variables
    Sys.getenv("POSTGRES_URL"),
    Sys.getenv("DATABASE_CONNECTION_URI"),
    
    # 3. Railway internal network fallback
    "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway",
    
    # 4. External Railway URL (if available)
    "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@containers-us-west-2.railway.app:5432/railway"
  )
  
  # Find first non-empty URL
  for (i in seq_along(sources)) {
    url <- sources[[i]]
    if (nchar(url) > 0) {
      cat("✅ Found database URL from source", i, "\n")
      return(url)
    }
  }
  
  cat("❌ No database URL found in any source\n")
  return(NULL)
}

# ============================================================================
# 2. EMERGENCY DATABASE CONNECTION
# ============================================================================

#' Emergency database connection initialization
#' @return TRUE if successful, FALSE otherwise
init_emergency_database <- function() {
  tryCatch({
    cat("🔄 Emergency database connection initialization...\n")
    
    # Get database URL
    database_url <- get_emergency_database_url()
    if (is.null(database_url)) {
      cat("❌ No database URL available\n")
      return(FALSE)
    }
    
    # Mask password for logging
    masked_url <- gsub(":[^:@]+@", ":***@", database_url)
    cat("📊 Using database URL:", masked_url, "\n")
    
    # Parse URL
    parsed_url <- parse_database_url(database_url)
    if (is.null(parsed_url)) {
      cat("❌ Failed to parse database URL\n")
      return(FALSE)
    }
    
    cat("🔗 Connecting to database:\n")
    cat("   Host:", parsed_url$host, "\n")
    cat("   Port:", parsed_url$port, "\n")
    cat("   Database:", parsed_url$database, "\n")
    cat("   User:", parsed_url$user, "\n")
    
    # Create connection pool with retry logic
    max_retries <- 3
    for (attempt in 1:max_retries) {
      cat("🔄 Database connection attempt", attempt, "of", max_retries, "\n")
      
      tryCatch({
        # Create connection pool
        db_pool <<- dbPool(
          drv = RPostgres::Postgres(),
          host = parsed_url$host,
          port = parsed_url$port,
          dbname = parsed_url$database,
          user = parsed_url$user,
          password = parsed_url$password,
          minSize = 1,
          maxSize = 5,
          idleTimeout = 300000,
          connectionTimeout = 30
        )
        
        # Test connection
        conn <- poolCheckout(db_pool)
        on.exit(poolReturn(conn))
        
        # Simple test query
        test_result <- dbGetQuery(conn, "SELECT 1 as test")
        cat("✅ Database connection successful on attempt", attempt, "\n")
        
        # Check available tables
        tables <- dbListTables(conn)
        cat("📊 Available tables:", length(tables), "\n")
        cat("   Tables:", paste(head(tables, 10), collapse = ", "), "\n")
        
        # Check for key tables
        has_documents <- "documents" %in% tables
        has_lexml_tables <- any(grepl("^lexml_", tables))
        
        cat("📋 Key tables check:\n")
        cat("   documents view:", ifelse(has_documents, "✅", "❌"), "\n")
        cat("   lexml tables:", ifelse(has_lexml_tables, "✅", "❌"), "\n")
        
        # Set global connection status
        database_connected <<- TRUE
        cat("✅ Emergency database connection successful!\n")
        return(TRUE)
        
      }, error = function(e) {
        cat("❌ Database connection attempt", attempt, "failed:", e$message, "\n")
        if (attempt < max_retries) {
          cat("🔄 Retrying in 2 seconds...\n")
          Sys.sleep(2)
        }
      })
    }
    
    cat("❌ All database connection attempts failed\n")
    return(FALSE)
    
  }, error = function(e) {
    cat("❌ Emergency database initialization error:", e$message, "\n")
    return(FALSE)
  })
}

# ============================================================================
# 3. EMERGENCY DATABASE TEST
# ============================================================================

#' Emergency database test with detailed diagnostics
#' @return TRUE if successful, FALSE otherwise
test_emergency_database <- function() {
  if (is.null(db_pool)) {
    cat("❌ Database pool is NULL\n")
    return(FALSE)
  }
  
  tryCatch({
    cat("🔍 Emergency database test...\n")
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Test 1: Basic connection
    cat("   Test 1: Basic connection...\n")
    basic_test <- dbGetQuery(conn, "SELECT 1 as test")
    cat("   ✅ Basic connection successful\n")
    
    # Test 2: Check tables
    cat("   Test 2: Available tables...\n")
    tables <- dbListTables(conn)
    cat("   📊 Found", length(tables), "tables\n")
    
    # Test 3: Check documents view
    cat("   Test 3: Documents view...\n")
    if ("documents" %in% tables) {
      doc_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
      cat("   ✅ Documents view found with", doc_count$count, "records\n")
    } else {
      cat("   ❌ Documents view not found\n")
    }
    
    # Test 4: Check lexml tables
    cat("   Test 4: LexML tables...\n")
    lexml_tables <- grep("^lexml_", tables, value = TRUE)
    if (length(lexml_tables) > 0) {
      cat("   ✅ Found", length(lexml_tables), "lexml tables\n")
      for (table in head(lexml_tables, 5)) {
        count <- dbGetQuery(conn, paste0("SELECT COUNT(*) as count FROM ", table))
        cat("      ", table, ":", count$count, "records\n")
      }
    } else {
      cat("   ❌ No lexml tables found\n")
    }
    
    cat("✅ Emergency database test completed successfully\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Emergency database test error:", e$message, "\n")
    return(FALSE)
  })
}

# ============================================================================
# 4. OVERRIDE EXISTING FUNCTIONS
# ============================================================================

# Override the existing database functions with emergency versions
if (exists("init_database", envir = .GlobalEnv)) {
  assign("init_database", init_emergency_database, envir = .GlobalEnv)
  cat("✅ Overridden init_database() with emergency version\n")
}

if (exists("test_database_connection", envir = .GlobalEnv)) {
  assign("test_database_connection", test_emergency_database, envir = .GlobalEnv)
  cat("✅ Overridden test_database_connection() with emergency version\n")
}

# ============================================================================
# 5. IMMEDIATE CONNECTION ATTEMPT
# ============================================================================

cat("🚀 Attempting immediate emergency database connection...\n")
connection_success <- init_emergency_database()

if (connection_success) {
  cat("🎉 Emergency database connection successful!\n")
  cat("📊 The dashboard should now connect to the database\n")
  cat("📊 Emergency fix functions will work with real data\n")
} else {
  cat("⚠️ Emergency database connection failed\n")
  cat("📊 Dashboard will fall back to CSV data\n")
  cat("📊 Emergency fix functions will still work with fallback data\n")
}

cat("✅ Emergency database connection fix loaded\n") 