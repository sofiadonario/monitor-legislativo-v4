# TEST RAILWAY DATABASE CONNECTION
# ================================
# Simple diagnostic script to test Railway PostgreSQL connectivity

cat("\n🔍 TESTING RAILWAY DATABASE CONNECTION...\n")
cat("=" * 50, "\n\n")

# Test 1: Check if packages are available
cat("📦 PACKAGE CHECK:\n")
packages_ok <- TRUE
for (pkg in c("DBI", "RPostgres")) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat("✅", pkg, "is available\n")
  } else {
    cat("❌", pkg, "is NOT available\n")
    packages_ok <- FALSE
  }
}

if (!packages_ok) {
  cat("\n⚠️ Installing missing packages...\n")
  install.packages(c("DBI", "RPostgres"), repos = "https://cran.rstudio.com/")
}

# Load packages
library(DBI)
library(RPostgres)

# Test 2: Basic connection test
cat("\n🔌 CONNECTION TEST:\n")
cat("Host: nozomi.proxy.rlwy.net\n")
cat("Port: 44844\n")
cat("Database: railway\n")
cat("User: postgres\n")

tryCatch({
  con <- dbConnect(
    RPostgres::Postgres(),
    host = "nozomi.proxy.rlwy.net",
    port = 44844,
    dbname = "railway",
    user = "postgres",
    password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY",
    connect_timeout = 30
  )
  
  cat("✅ Connection established!\n")
  
  # Test 3: Query test
  cat("\n📊 QUERY TEST:\n")
  
  # Check if documents table exists
  tables <- dbListTables(con)
  cat("Tables found:", length(tables), "\n")
  
  if ("documents" %in% tables) {
    cat("✅ 'documents' table exists\n")
    
    # Count documents
    count_result <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents")
    cat("📄 Total documents:", format(count_result$count[1], big.mark = ","), "\n")
    
    # Check columns
    columns <- dbListFields(con, "documents")
    cat("📋 Columns found:", length(columns), "\n")
    cat("   First 10 columns:", paste(head(columns, 10), collapse = ", "), "...\n")
    
    # Check for specific columns
    important_cols <- c("categoria", "categoria_original", "estado", "municipio", "ano")
    cat("\n🔍 CHECKING IMPORTANT COLUMNS:\n")
    for (col in important_cols) {
      if (col %in% columns) {
        cat("✅", col, "exists\n")
      } else {
        cat("❌", col, "NOT FOUND\n")
      }
    }
    
    # Sample data
    cat("\n📊 SAMPLE DATA:\n")
    sample_query <- "SELECT * FROM documents LIMIT 1"
    sample <- dbGetQuery(con, sample_query)
    
    if (nrow(sample) > 0) {
      cat("✅ Successfully retrieved sample data\n")
      cat("   Column names:", paste(names(sample), collapse = ", "), "\n")
    }
    
  } else {
    cat("❌ 'documents' table NOT FOUND\n")
    cat("Available tables:", paste(tables, collapse = ", "), "\n")
  }
  
  dbDisconnect(con)
  cat("\n✅ Database test completed successfully!\n")
  
}, error = function(e) {
  cat("❌ CONNECTION FAILED!\n")
  cat("Error message:", e$message, "\n")
  
  # Additional diagnostics
  cat("\n💡 POSSIBLE ISSUES:\n")
  cat("1. Check if Railway PostgreSQL add-on is attached to your service\n")
  cat("2. Verify the database credentials are correct\n")
  cat("3. Ensure Railway deployment has network access to database\n")
  cat("4. Check Railway logs for more details\n")
})

cat("\n" * 2)
cat("=" * 50, "\n")
cat("🏁 TEST COMPLETE\n")