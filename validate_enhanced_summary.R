# ============================================================================
# ENHANCED EXECUTIVE SUMMARY VALIDATION SCRIPT
# ============================================================================
# Quick validation script for Enhanced Executive Summary components
# ============================================================================

cat("🔍 Validating Enhanced Executive Summary Components...\n")

# Check if core files exist
required_files <- c(
  "modules/executive_summary_analytics.R",
  "modules/executive_summary_ui.R", 
  "modules/executive_summary_server.R",
  "modules/executive_summary_integration.R"
)

cat("\n📁 File Validation:\n")
all_files_exist <- TRUE

for (file in required_files) {
  if (file.exists(file)) {
    cat("✅", file, "\n")
  } else {
    cat("❌", file, "- MISSING\n")
    all_files_exist <- FALSE
  }
}

if (all_files_exist) {
  cat("\n🎉 All required files are present!\n")
} else {
  cat("\n⚠️ Some files are missing. Check the file paths.\n")
  quit(status = 1)
}

# Source and validate functions
cat("\n🔧 Loading and validating functions...\n")

tryCatch({
  source("modules/executive_summary_analytics.R", local = TRUE)
  cat("✅ Analytics engine loaded\n")
}, error = function(e) {
  cat("❌ Analytics engine failed:", e$message, "\n")
})

tryCatch({
  source("modules/executive_summary_ui.R", local = TRUE)
  cat("✅ UI components loaded\n")
}, error = function(e) {
  cat("❌ UI components failed:", e$message, "\n")
})

tryCatch({
  source("modules/executive_summary_server.R", local = TRUE)
  cat("✅ Server functions loaded\n")
}, error = function(e) {
  cat("❌ Server functions failed:", e$message, "\n")
})

tryCatch({
  source("modules/executive_summary_integration.R", local = TRUE)
  cat("✅ Integration module loaded\n")
}, error = function(e) {
  cat("❌ Integration module failed:", e$message, "\n")
})

# Check key functions
cat("\n🎯 Function Validation:\n")
key_functions <- c(
  "generate_executive_summary_analytics",
  "analyze_temporal_trends_executive",
  "analyze_geographic_distribution", 
  "analyze_document_patterns",
  "generate_executive_kpis",
  "create_enhanced_executive_summary_ui",
  "initialize_enhanced_executive_summary"
)

functions_available <- 0
for (func in key_functions) {
  if (exists(func)) {
    cat("✅", func, "\n")
    functions_available <- functions_available + 1
  } else {
    cat("❌", func, "- NOT FOUND\n")
  }
}

# Test with sample data
cat("\n📊 Quick Analytics Test:\n")
if (functions_available > 5) {
  tryCatch({
    # Create tiny test dataset
    sample_data <- data.frame(
      title = c("Lei 1", "Decreto 2", "Resolução 3"),
      date = c("2024-01-01", "2024-01-02", "2024-01-03"),
      categoria = c("Legislação", "Legislação", "Jurisprudência"),
      estado = c("SP", "RJ", "MG"),
      jurisdicao = c("Federal", "Estadual", "Municipal"),
      ementa = c("Sobre transporte", "Sobre rodoviário", "Sobre logística"),
      stringsAsFactors = FALSE
    )
    
    # Test basic analytics
    if (exists("analyze_temporal_trends_executive")) {
      result <- analyze_temporal_trends_executive(sample_data, cache_enabled = FALSE)
      if (is.list(result) && !"error" %in% names(result)) {
        cat("✅ Temporal analysis working\n")
      } else {
        cat("⚠️ Temporal analysis has issues\n")
      }
    }
    
    if (exists("analyze_geographic_distribution")) {
      result <- analyze_geographic_distribution(sample_data)
      if (is.list(result) && !"error" %in% names(result)) {
        cat("✅ Geographic analysis working\n")
      } else {
        cat("⚠️ Geographic analysis has issues\n")
      }
    }
    
    if (exists("generate_executive_summary_analytics")) {
      result <- generate_executive_summary_analytics(sample_data, cache_enabled = FALSE)
      if (is.list(result) && !"error" %in% names(result)) {
        cat("✅ Comprehensive analytics working\n")
      } else {
        cat("⚠️ Comprehensive analytics has issues\n")
      }
    }
    
  }, error = function(e) {
    cat("❌ Analytics test failed:", e$message, "\n")
  })
} else {
  cat("⚠️ Too many functions missing, skipping analytics test\n")
}

# Check data availability
cat("\n📂 Data File Check:\n")
data_files <- c("railway_data_50k.csv", "railway_data_10k.csv", "railway_medium_dataset.csv")
data_available <- FALSE

for (file in data_files) {
  if (file.exists(file)) {
    file_size <- file.size(file)
    cat("✅", file, "- Size:", round(file_size / 1024 / 1024, 1), "MB\n")
    data_available <- TRUE
  } else {
    cat("⚠️", file, "- Not found\n")
  }
}

if (!data_available) {
  cat("⚠️ No large datasets found. Analytics will use fallback data.\n")
}

# Package requirements check
cat("\n📦 Package Requirements:\n")
required_packages <- c("dplyr", "tidyr", "lubridate", "ggplot2", "plotly", "DT", "shiny", "shinydashboard")
packages_available <- 0

for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat("✅", pkg, "\n")
    packages_available <- packages_available + 1
  } else {
    cat("⚠️", pkg, "- Not installed\n")
  }
}

# Final assessment
cat("\n" + "="*50 + "\n")
cat("🎯 VALIDATION SUMMARY\n")
cat("="*50 + "\n")

status_score <- 0
max_score <- 4

if (all_files_exist) {
  cat("✅ File structure: COMPLETE\n")
  status_score <- status_score + 1
} else {
  cat("❌ File structure: INCOMPLETE\n")
}

if (functions_available >= 6) {
  cat("✅ Core functions: AVAILABLE\n")
  status_score <- status_score + 1
} else {
  cat("❌ Core functions: MISSING\n")
}

if (packages_available >= 6) {
  cat("✅ Package dependencies: SATISFIED\n")
  status_score <- status_score + 1
} else {
  cat("⚠️ Package dependencies: PARTIAL\n")
}

if (data_available) {
  cat("✅ Data availability: CONFIRMED\n")
  status_score <- status_score + 1
} else {
  cat("⚠️ Data availability: LIMITED\n")
}

cat("\n📊 Overall Status:", status_score, "/", max_score, "\n")

if (status_score >= 3) {
  cat("🎉 READY FOR DEPLOYMENT\n")
  cat("💡 The Enhanced Executive Summary is ready to integrate into the main application.\n")
} else if (status_score >= 2) {
  cat("⚠️ NEEDS ATTENTION\n") 
  cat("💡 Some components need to be addressed before deployment.\n")
} else {
  cat("❌ NOT READY\n")
  cat("💡 Significant issues need to be resolved before deployment.\n")
}

cat("\n🚀 To integrate into main app, add this to app.R:\n")
cat("   source('modules/executive_summary_integration.R', local = TRUE)\n")
cat("\n🎯 Enhancement complete!\n")