# Railway Database Connection Test Script
# =====================================
# Test script to verify Railway database connection works correctly

cat("🧪 Testing Railway Database Connection...\n")

# Set test environment variables to simulate Railway
Sys.setenv("RAILWAY_ENVIRONMENT" = "production")
Sys.setenv("DATABASE_URL" = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway")
Sys.setenv("PGHOST" = "postgres.railway.internal")
Sys.setenv("PGPORT" = "5432")
Sys.setenv("PGDATABASE" = "railway")
Sys.setenv("PGUSER" = "postgres")
Sys.setenv("PGPASSWORD" = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY")

# Load the Railway connection script
source("RAILWAY_PRODUCTION_DB_FIX.R")

# Test connection status
cat("\n📊 Testing connection status...\n")
status <- get_connection_status()
print(status)

# Test document count function
cat("\n📄 Testing document count...\n")
doc_count <- get_total_documents()
cat("Document count:", format(doc_count, big.mark = ","), "\n")

# Test library document function with small limit
cat("\n📚 Testing library documents (limited)...\n")
docs <- get_library_documents(limit = 5)
cat("Retrieved", nrow(docs), "documents\n")
if (nrow(docs) > 0) {
  print(head(docs))
}

cat("\n✅ Railway connection test completed!\n")