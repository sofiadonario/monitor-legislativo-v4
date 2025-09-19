# CRITICAL CHART RENDERING FIXES
# ===============================
# Fixes charts not loading and documents appearing incomplete
# Addresses: Column mapping, CSV fallback, function loading

cat("🚨 APPLYING CRITICAL CHART RENDERING FIXES\n")
cat("==========================================\n")

# 1. Load enhanced get_library_documents function
cat("1. Loading enhanced data loading functions...\n")
if (file.exists("fix_analytics_data_function.R")) {
  source("fix_analytics_data_function.R")
  cat("✅ Enhanced get_library_documents loaded\n")
} else {
  cat("⚠️ fix_analytics_data_function.R not found\n")
}

# 2. Load CSV-based analytics function
cat("2. Loading CSV-based analytics functions...\n")
if (file.exists("fix_analytics_data_reactive.R")) {
  source("fix_analytics_data_reactive.R")
  cat("✅ CSV-based analytics function loaded\n")
} else {
  cat("⚠️ fix_analytics_data_reactive.R not found\n")
}

# 3. Test data availability
cat("3. Testing data availability...\n")
data_available <- FALSE
for (file in c("railway_data_50k.csv", "railway_data_10k.csv", "railway_medium_dataset.csv")) {
  if (file.exists(file)) {
    tryCatch({
      test_data <- read.csv(file, nrows = 5, stringsAsFactors = FALSE)
      cat("✅", file, "available with", ncol(test_data), "columns\n")
      data_available <- TRUE
      break
    }, error = function(e) {
      cat("❌", file, "error:", e$message, "\n")
    })
  }
}

if (!data_available) {
  cat("❌ No CSV data files found\n")
}

# 4. Test function availability
cat("4. Testing function availability...\n")
if (exists("get_library_documents")) {
  cat("✅ get_library_documents function is available\n")
  tryCatch({
    test_result <- get_library_documents(limit = 5)
    cat("✅ Function test successful:", nrow(test_result), "documents returned\n")
  }, error = function(e) {
    cat("❌ Function test failed:", e$message, "\n")
  })
} else {
  cat("❌ get_library_documents function not found\n")
}

if (exists("analytics_data_fixed_csv")) {
  cat("✅ analytics_data_fixed_csv function is available\n")
} else {
  cat("❌ analytics_data_fixed_csv function not found\n")
}

# 5. Apply the fixes to global environment
cat("5. Applying fixes to global environment...\n")

# Override the problematic analytics_data function if it exists
if (exists("analytics_data_fixed_csv")) {

  # Create a fixed version of analytics_data that works as a reactive
  analytics_data_FIXED <<- function() {
    analytics_data_fixed_csv()
  }

  cat("✅ analytics_data_FIXED function created globally\n")
}

# 6. Verify visualization packages
cat("6. Verifying visualization packages...\n")
required_packages <- c("plotly", "ggplot2", "dplyr")
for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat("✅", pkg, "available\n")
  } else {
    cat("❌", pkg, "not available\n")
  }
}

# 7. Create test chart data
cat("7. Creating test chart functions...\n")

# Test function for charts
test_chart_data <<- function() {
  tryCatch({
    data <- analytics_data_fixed_csv()
    if (nrow(data) > 0) {
      cat("✅ Test chart data available:", nrow(data), "documents\n")
      return(data)
    } else {
      cat("❌ No data available for charts\n")
      return(NULL)
    }
  }, error = function(e) {
    cat("❌ Test chart data failed:", e$message, "\n")
    return(NULL)
  })
}

cat("\n==========================================\n")
cat("🏁 CRITICAL CHART FIXES COMPLETED\n")
cat("==========================================\n")

# Final test
cat("Final test - loading sample data...\n")
tryCatch({
  if (exists("analytics_data_fixed_csv")) {
    final_test <- analytics_data_fixed_csv()
    cat("✅ FINAL TEST SUCCESSFUL:", nrow(final_test), "documents available for charts\n")
  }
}, error = function(e) {
  cat("❌ FINAL TEST FAILED:", e$message, "\n")
})

cat("==========================================\n")