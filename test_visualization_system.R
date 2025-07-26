# Test Script for Enhanced Visualization System
# Validates all components of the new visualization fix
# Author: Claude Code (Senior Frontend Engineer)
# Date: 2025-07-26

cat("🧪 Starting Enhanced Visualization System Tests...\n\n")

# ============================================================================
# TEST SETUP
# ============================================================================

# Track test results
test_results <- list()
total_tests <- 0
passed_tests <- 0

# Helper function to run tests
run_test <- function(test_name, test_function) {
  total_tests <<- total_tests + 1
  cat("🔍 Testing:", test_name, "...\n")
  
  tryCatch({
    result <- test_function()
    if (result$success) {
      passed_tests <<- passed_tests + 1
      cat("✅ PASSED:", test_name, "\n")
      test_results[[test_name]] <<- list(status = "PASSED", message = result$message)
    } else {
      cat("❌ FAILED:", test_name, "-", result$message, "\n")
      test_results[[test_name]] <<- list(status = "FAILED", message = result$message)
    }
  }, error = function(e) {
    cat("❌ ERROR:", test_name, "-", e$message, "\n")
    test_results[[test_name]] <<- list(status = "ERROR", message = e$message)
  })
  
  cat("\n")
}

# ============================================================================
# COMPONENT LOADING TESTS
# ============================================================================

test_enhanced_data_processor <- function() {
  if (file.exists("enhanced_data_processor.R")) {
    source("enhanced_data_processor.R")
    
    # Test if key functions exist
    required_functions <- c("load_processed_data_enhanced", "get_enhanced_dashboard_stats", "apply_data_quality_fixes")
    
    for (func in required_functions) {
      if (!exists(func)) {
        return(list(success = FALSE, message = paste("Function", func, "not found")))
      }
    }
    
    return(list(success = TRUE, message = "Enhanced data processor loaded successfully"))
  } else {
    return(list(success = FALSE, message = "enhanced_data_processor.R file not found"))
  }
}

test_unified_dashboard_system <- function() {
  if (file.exists("unified_dashboard_system.R")) {
    source("unified_dashboard_system.R")
    
    # Test if key functions exist
    required_functions <- c("get_unified_dashboard_metrics", "get_unified_map_data", "get_dashboard_health")
    
    for (func in required_functions) {
      if (!exists(func)) {
        return(list(success = FALSE, message = paste("Function", func, "not found")))
      }
    }
    
    return(list(success = TRUE, message = "Unified dashboard system loaded successfully"))
  } else {
    return(list(success = FALSE, message = "unified_dashboard_system.R file not found"))
  }
}

test_enhanced_map_visualization <- function() {
  if (file.exists("enhanced_map_visualization.R")) {
    source("enhanced_map_visualization.R")
    
    # Test if key functions exist
    required_functions <- c("create_enhanced_brazil_map", "create_fallback_map", "create_legislation_map")
    
    for (func in required_functions) {
      if (!exists(func)) {
        return(list(success = FALSE, message = paste("Function", func, "not found")))
      }
    }
    
    return(list(success = TRUE, message = "Enhanced map visualization loaded successfully"))
  } else {
    return(list(success = FALSE, message = "enhanced_map_visualization.R file not found"))
  }
}

# ============================================================================
# FUNCTIONALITY TESTS
# ============================================================================

test_data_loading <- function() {
  tryCatch({
    # Test enhanced data loading
    data <- load_processed_data_enhanced()
    
    if (is.null(data)) {
      return(list(success = TRUE, message = "No CSV data available (using fallback) - this is expected"))
    }
    
    if (nrow(data) > 0) {
      return(list(success = TRUE, message = paste("Data loaded successfully:", nrow(data), "records")))
    } else {
      return(list(success = FALSE, message = "Data loaded but empty"))
    }
  }, error = function(e) {
    return(list(success = FALSE, message = paste("Data loading failed:", e$message)))
  })
}

test_dashboard_metrics <- function() {
  tryCatch({
    metrics <- get_unified_dashboard_metrics()
    
    required_fields <- c("total_documents", "states_with_docs", "date_range", "data_source")
    
    for (field in required_fields) {
      if (!field %in% names(metrics)) {
        return(list(success = FALSE, message = paste("Missing field:", field)))
      }
    }
    
    if (metrics$total_documents > 0) {
      return(list(success = TRUE, message = paste("Metrics retrieved:", metrics$total_documents, "docs from", metrics$data_source)))
    } else {
      return(list(success = FALSE, message = "Zero documents returned"))
    }
  }, error = function(e) {
    return(list(success = FALSE, message = paste("Metrics retrieval failed:", e$message)))
  })
}

test_map_data <- function() {
  tryCatch({
    map_data <- get_unified_map_data()
    
    if (nrow(map_data) > 0) {
      required_cols <- c("jurisdicao", "count")
      
      for (col in required_cols) {
        if (!col %in% names(map_data)) {
          return(list(success = FALSE, message = paste("Missing column:", col)))
        }
      }
      
      return(list(success = TRUE, message = paste("Map data retrieved:", nrow(map_data), "jurisdictions")))
    } else {
      return(list(success = FALSE, message = "No map data available"))
    }
  }, error = function(e) {
    return(list(success = FALSE, message = paste("Map data retrieval failed:", e$message)))
  })
}

test_map_creation <- function() {
  tryCatch({
    # Test basic map creation
    map <- create_enhanced_brazil_map()
    
    if (!is.null(map) && inherits(map, "leaflet")) {
      return(list(success = TRUE, message = "Enhanced Brazil map created successfully"))
    } else {
      return(list(success = FALSE, message = "Map creation returned invalid object"))
    }
  }, error = function(e) {
    return(list(success = FALSE, message = paste("Map creation failed:", e$message)))
  })
}

test_fallback_map <- function() {
  tryCatch({
    # Test fallback map creation
    fallback_map <- create_fallback_map()
    
    if (!is.null(fallback_map) && inherits(fallback_map, "leaflet")) {
      return(list(success = TRUE, message = "Fallback map created successfully"))
    } else {
      return(list(success = FALSE, message = "Fallback map creation returned invalid object"))
    }
  }, error = function(e) {
    return(list(success = FALSE, message = paste("Fallback map creation failed:", e$message)))
  })
}

test_document_stats <- function() {
  tryCatch({
    stats <- get_unified_document_stats()
    
    if (!is.null(stats) && "document_types" %in% names(stats)) {
      doc_types <- stats$document_types
      
      if (nrow(doc_types) > 0) {
        return(list(success = TRUE, message = paste("Document stats retrieved:", nrow(doc_types), "types")))
      } else {
        return(list(success = FALSE, message = "Document stats empty"))
      }
    } else {
      return(list(success = FALSE, message = "Invalid document stats format"))
    }
  }, error = function(e) {
    return(list(success = FALSE, message = paste("Document stats retrieval failed:", e$message)))
  })
}

test_system_health <- function() {
  tryCatch({
    health <- get_dashboard_health()
    
    required_fields <- c("status", "data_source", "total_documents")
    
    for (field in required_fields) {
      if (!field %in% names(health)) {
        return(list(success = FALSE, message = paste("Missing health field:", field)))
      }
    }
    
    return(list(success = TRUE, message = paste("System health check passed - using", health$data_source)))
  }, error = function(e) {
    return(list(success = FALSE, message = paste("System health check failed:", e$message)))
  })
}

# ============================================================================
# RUN ALL TESTS
# ============================================================================

cat("📋 Running Enhanced Visualization System Tests\n")
cat("=" %s% 50, "\n\n")

# Component loading tests
cat("🔧 COMPONENT LOADING TESTS\n")
cat("-" %s% 30, "\n")
run_test("Enhanced Data Processor Loading", test_enhanced_data_processor)
run_test("Unified Dashboard System Loading", test_unified_dashboard_system)
run_test("Enhanced Map Visualization Loading", test_enhanced_map_visualization)

# Functionality tests
cat("⚙️ FUNCTIONALITY TESTS\n")
cat("-" %s% 20, "\n")
run_test("Data Loading", test_data_loading)
run_test("Dashboard Metrics", test_dashboard_metrics)
run_test("Map Data Retrieval", test_map_data)
run_test("Map Creation", test_map_creation)
run_test("Fallback Map Creation", test_fallback_map)
run_test("Document Statistics", test_document_stats)
run_test("System Health Check", test_system_health)

# ============================================================================
# TEST RESULTS SUMMARY
# ============================================================================

cat("📊 TEST RESULTS SUMMARY\n")
cat("=" %s% 50, "\n")

cat("Total Tests:", total_tests, "\n")
cat("Passed:", passed_tests, "\n")
cat("Failed:", total_tests - passed_tests, "\n")
cat("Success Rate:", sprintf("%.1f%%", (passed_tests / total_tests) * 100), "\n\n")

# Detailed results
cat("📋 DETAILED RESULTS\n")
cat("-" %s% 20, "\n")

for (test_name in names(test_results)) {
  result <- test_results[[test_name]]
  status_icon <- if (result$status == "PASSED") "✅" else if (result$status == "FAILED") "❌" else "⚠️"
  cat(status_icon, test_name, "-", result$message, "\n")
}

# ============================================================================
# RECOMMENDATIONS
# ============================================================================

cat("\n🔍 RECOMMENDATIONS\n")
cat("-" %s% 15, "\n")

if (passed_tests == total_tests) {
  cat("🎉 All tests passed! The enhanced visualization system is ready for production.\n")
  cat("✅ You can proceed with the implementation guide instructions.\n")
} else if (passed_tests >= (total_tests * 0.8)) {
  cat("⚠️ Most tests passed. Minor issues detected that may not affect core functionality.\n")
  cat("🔧 Review failed tests and consider implementing with monitoring.\n")
} else {
  cat("❌ Multiple critical issues detected. Implementation not recommended until issues are resolved.\n")
  cat("🛠️ Review failed tests and fix issues before proceeding.\n")
}

cat("\n📚 Next Steps:\n")
cat("1. Review failed tests (if any) and fix issues\n")
cat("2. Follow VISUALIZATION_FIX_IMPLEMENTATION_GUIDE.md\n")
cat("3. Test on Railway deployment\n")
cat("4. Monitor dashboard performance\n")

cat("\n🔗 For support, refer to the implementation guide troubleshooting section.\n")

# Return summary for programmatic use
invisible(list(
  total_tests = total_tests,
  passed_tests = passed_tests,
  success_rate = (passed_tests / total_tests) * 100,
  results = test_results
))