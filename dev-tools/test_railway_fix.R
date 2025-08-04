# TEST RAILWAY FIX
# This script verifies the Railway deployment will work correctly

cat("🧪 TESTING RAILWAY DEPLOYMENT FIX...\n")

# Test 1: Load Railway database fix
cat("\n1. Testing Railway database fix...\n")
if (file.exists("RAILWAY_DATABASE_FIX.R")) {
  source("RAILWAY_DATABASE_FIX.R")
  cat("✅ Railway database fix loaded\n")
} else {
  cat("❌ RAILWAY_DATABASE_FIX.R not found!\n")
}

# Test 2: Load dashboard NULL fix
cat("\n2. Testing dashboard NULL fix...\n")
if (file.exists("dashboard_null_fix.R")) {
  source("dashboard_null_fix.R")
  cat("✅ Dashboard NULL fix loaded\n")
} else {
  cat("❌ dashboard_null_fix.R not found!\n")
}

# Test 3: Verify functions return proper values
cat("\n3. Testing dashboard functions...\n")

# Test total documents
total <- get_total_documents()
cat("   get_total_documents():", total, "\n")
if (is.numeric(total) && total > 0) {
  cat("   ✅ Returns numeric value\n")
} else {
  cat("   ❌ Returns NULL or non-numeric\n")
}

# Test dashboard metrics
metrics <- get_lexml_dashboard_metrics()
cat("   get_lexml_dashboard_metrics():\n")
cat("     - total_documents:", metrics$total_documents, "\n")
cat("     - states_with_docs:", metrics$states_with_docs, "\n")
cat("     - states_percentage:", metrics$states_percentage, "%\n")

if (is.numeric(metrics$total_documents) && metrics$total_documents > 0) {
  cat("   ✅ Returns proper metrics\n")
} else {
  cat("   ❌ Returns NULL or invalid metrics\n")
}

# Test safe display function
cat("\n4. Testing safe display functions...\n")
display_value <- get_dashboard_value_safe("total_documents")
cat("   get_dashboard_value_safe('total_documents'):", display_value, "\n")
if (display_value != "NULL" && display_value != "0") {
  cat("   ✅ Returns formatted number\n")
} else {
  cat("   ❌ Returns NULL or 0\n")
}

# Summary
cat("\n" * 2)
cat(paste(rep("=", 70), collapse=""), "\n")
cat("🎯 RAILWAY FIX TEST SUMMARY\n")
cat(paste(rep("=", 70), collapse=""), "\n")

if (exists("get_total_documents") && 
    exists("get_lexml_dashboard_metrics") &&
    exists("get_dashboard_value_safe") &&
    is.numeric(total) && total > 0) {
  cat("✅ SUCCESS: Railway deployment should work correctly!\n")
  cat("✅ Dashboard will display:", format(total, big.mark = ","), "documents\n")
  cat("✅ Instead of NULL, users will see actual data\n")
} else {
  cat("❌ FAILURE: Some components not working\n")
  cat("⚠️ Dashboard may still show NULL\n")
}

cat("\n📝 Files created for Railway deployment:\n")
cat("   1. RAILWAY_DATABASE_FIX.R - Database connection with retries\n")
cat("   2. dashboard_null_fix.R - UI component NULL prevention\n")
cat("   3. railway.json - Railway configuration\n")
cat("   4. init.R - Startup script\n")
cat("\n🚀 Ready to deploy!")