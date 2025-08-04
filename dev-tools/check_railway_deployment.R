# CHECK RAILWAY DEPLOYMENT ISSUES
# This script helps diagnose why the dashboard shows NULL

cat("🔍 CHECKING RAILWAY DEPLOYMENT ISSUES...\n")

# Test 1: Check if database connection works
cat("\n1. Testing Database Connection...\n")
tryCatch({
  library(DBI)
  library(RPostgres)
  
  conn <- dbConnect(
    RPostgres::Postgres(),
    host = "nozomi.proxy.rlwy.net",
    port = 44844,
    dbname = "railway",
    user = "postgres",
    password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
  )
  
  # Check if tables exist
  tables <- dbListTables(conn)
  cat("✅ Connected to database. Tables found:", length(tables), "\n")
  cat("   Tables:", paste(tables, collapse=", "), "\n")
  
  # Check document count
  if ("documents" %in% tables) {
    count_result <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
    cat("✅ Documents table has", count_result$count, "rows\n")
  } else {
    cat("❌ Documents table not found!\n")
  }
  
  # Check if views exist
  views_check <- dbGetQuery(conn, "
    SELECT viewname 
    FROM pg_views 
    WHERE schemaname = 'public' 
    AND viewname IN ('lexml_dashboard_view', 'dashboard_metrics', 'documents_by_category')
  ")
  cat("✅ Dashboard views found:", nrow(views_check), "\n")
  if (nrow(views_check) > 0) {
    cat("   Views:", paste(views_check$viewname, collapse=", "), "\n")
  }
  
  dbDisconnect(conn)
  
}, error = function(e) {
  cat("❌ Database connection error:", e$message, "\n")
})

# Test 2: Check data access functions
cat("\n2. Testing Data Access Functions...\n")

# Check if functions exist
functions_to_check <- c(
  "get_total_documents",
  "get_lexml_dashboard_metrics", 
  "get_documents_by_state",
  "get_documents_by_type",
  "get_database_stats"
)

for (func_name in functions_to_check) {
  if (exists(func_name)) {
    cat("✅", func_name, "exists\n")
  } else {
    cat("❌", func_name, "NOT FOUND\n")
  }
}

# Test 3: Check integration files
cat("\n3. Checking Integration Files...\n")
integration_files <- c(
  "database_dashboard_integration.R",
  "simple_deduplicated_integration.R",
  "integrate_deduplicated_data.R",
  "integrate_unified_data_access.R",
  "integrate_data_validation.R"
)

for (file in integration_files) {
  if (file.exists(file)) {
    cat("✅", file, "exists\n")
  } else {
    cat("❌", file, "not found\n")
  }
}

# Test 4: Try loading the database integration
cat("\n4. Testing Database Integration Loading...\n")
if (file.exists("database_dashboard_integration.R")) {
  tryCatch({
    source("database_dashboard_integration.R")
    cat("✅ Database integration loaded successfully\n")
    
    # Test functions
    total <- get_total_documents()
    cat("   Total documents:", total, "\n")
    
  }, error = function(e) {
    cat("❌ Error loading database integration:", e$message, "\n")
  })
}

# Test 5: Check environment variables
cat("\n5. Checking Environment Variables...\n")
env_vars <- c("DATABASE_URL", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")
for (var in env_vars) {
  if (Sys.getenv(var) != "") {
    cat("✅", var, "is set\n")
  } else {
    cat("⚠️", var, "not set\n")
  }
}

cat("\n🎯 DIAGNOSIS COMPLETE\n")
cat("Common issues that cause NULL in dashboard:\n")
cat("1. Database connection timeout (Railway specific)\n")
cat("2. Functions not being overridden properly\n")
cat("3. Integration files not loading in correct order\n")
cat("4. Missing R packages in deployment\n")