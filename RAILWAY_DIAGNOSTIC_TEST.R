# RAILWAY DIAGNOSTIC TEST FILE
# ============================
# This file helps diagnose what's happening in Railway deployment

cat("🚨 RAILWAY DIAGNOSTIC TEST RUNNING\n")
cat("==================================\n")

# Test 1: Check if this file is being loaded
cat("✅ RAILWAY_DIAGNOSTIC_TEST.R file is being loaded\n")

# Test 2: Check working directory
cat("📁 Working directory:", getwd(), "\n")

# Test 3: List files in current directory
files <- list.files(".", pattern = "*.R")
cat("📂 R files found:", length(files), "\n")
for (file in files[1:min(10, length(files))]) {
  cat("   -", file, "\n")
}

# Test 4: Check if CSV files exist
csv_files <- c("railway_data_50k.csv", "railway_data_10k.csv", "railway_medium_dataset.csv")
cat("📊 CSV files check:\n")
for (csv in csv_files) {
  if (file.exists(csv)) {
    size <- file.info(csv)$size
    cat("   ✅", csv, "- Size:", format(size, units="MB", digits=2), "\n")
  } else {
    cat("   ❌", csv, "- NOT FOUND\n")
  }
}

# Test 5: Check critical fix files
fix_files <- c("CRITICAL_CHART_FIXES.R", "CRITICAL_ZERO_RESULTS_FIX.R",
               "fix_analytics_data_function.R", "fix_analytics_data_reactive.R")
cat("🔧 Critical fix files check:\n")
for (fix in fix_files) {
  if (file.exists(fix)) {
    cat("   ✅", fix, "- FOUND\n")
  } else {
    cat("   ❌", fix, "- NOT FOUND\n")
  }
}

# Test 6: Test loading one of the fix files
cat("🧪 Testing CRITICAL_CHART_FIXES.R loading:\n")
if (file.exists("CRITICAL_CHART_FIXES.R")) {
  tryCatch({
    source("CRITICAL_CHART_FIXES.R")
    cat("   ✅ CRITICAL_CHART_FIXES.R loaded successfully\n")
  }, error = function(e) {
    cat("   ❌ Error loading CRITICAL_CHART_FIXES.R:", e$message, "\n")
  })
} else {
  cat("   ❌ CRITICAL_CHART_FIXES.R not found\n")
}

# Test 7: Check function availability
cat("🔍 Function availability check:\n")
if (exists("analytics_data_fixed_csv")) {
  cat("   ✅ analytics_data_fixed_csv function available\n")
} else {
  cat("   ❌ analytics_data_fixed_csv function NOT available\n")
}

if (exists("get_library_documents")) {
  cat("   ✅ get_library_documents function available\n")
} else {
  cat("   ❌ get_library_documents function NOT available\n")
}

cat("==================================\n")
cat("🏁 RAILWAY DIAGNOSTIC TEST COMPLETED\n")
cat("==================================\n")