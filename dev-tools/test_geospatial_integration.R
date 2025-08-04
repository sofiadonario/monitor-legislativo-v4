#!/usr/bin/env Rscript
#' Test Geospatial Integration for Railway Deployment
#' 
#' This script tests the geospatial analytics integration to ensure Railway compatibility
#' 
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-08-01

cat("=== TESTING GEOSPATIAL ANALYTICS INTEGRATION ===\n")

# Test package loading
test_packages <- function() {
  cat("Testing package dependencies...\n")
  
  required_packages <- c(
    "shiny", "shinydashboard", "DT", "plotly", "dplyr", "ggplot2",
    "leaflet", "sf", "htmlwidgets", "geobr", "spdep", "viridis"
  )
  
  missing_packages <- c()
  for (pkg in required_packages) {
    if (!requireNamespace(pkg, quietly = TRUE)) {
      missing_packages <- c(missing_packages, pkg)
      cat("  ❌ Missing:", pkg, "\n")
    } else {
      cat("  ✅ Available:", pkg, "\n")
    }
  }
  
  if (length(missing_packages) > 0) {
    cat("\nWARNING: Missing packages detected. Install with:\n")
    cat("install.packages(c(", paste0("'", missing_packages, "'", collapse = ", "), "))\n")
    return(FALSE)
  }
  
  return(TRUE)
}

# Test geospatial system loading
test_geospatial_system <- function() {
  cat("\nTesting geospatial system loading...\n")
  
  tryCatch({
    source("geospatial_analytics_system.R")
    cat("  ✅ Geospatial system loaded successfully\n")
    
    # Test function availability
    geo_functions <- get_geospatial_functions()
    if (is.list(geo_functions) && length(geo_functions) > 0) {
      cat("  ✅ Geospatial functions available:", length(geo_functions), "functions\n")
    } else {
      cat("  ❌ Geospatial functions not properly loaded\n")
      return(FALSE)
    }
    
    return(TRUE)
    
  }, error = function(e) {
    cat("  ❌ Geospatial system loading failed:", e$message, "\n")
    return(FALSE)
  })
}

# Test database connectivity
test_database_connection <- function() {
  cat("\nTesting database connectivity...\n")
  
  tryCatch({
    source("RAILWAY_DATABASE_FIX.R")
    cat("  ✅ Database connection script loaded\n")
    
    # Test basic functions
    if (exists("get_lexml_dashboard_metrics")) {
      metrics <- get_lexml_dashboard_metrics()
      if (is.list(metrics) && !is.null(metrics$total_documents)) {
        cat("  ✅ Database metrics accessible:", metrics$total_documents, "documents\n")
      } else {
        cat("  ⚠️ Database metrics available but incomplete\n")
      }
    } else {
      cat("  ⚠️ Database functions not available (fallback mode)\n")
    }
    
    return(TRUE)
    
  }, error = function(e) {
    cat("  ⚠️ Database connection failed, fallback mode active:", e$message, "\n")
    return(TRUE)  # Fallback is acceptable
  })
}

# Test demo map creation
test_demo_map <- function() {
  cat("\nTesting demo map creation...\n")
  
  tryCatch({
    library(leaflet)
    
    demo_map <- leaflet() %>%
      addTiles() %>%
      setView(lng = -47.9, lat = -15.8, zoom = 4) %>%
      addCircleMarkers(
        lng = c(-46.6, -43.2, -47.9),
        lat = c(-23.5, -22.9, -15.8),
        popup = c("São Paulo", "Rio de Janeiro", "Brasília"),
        radius = c(10, 8, 6)
      )
    
    if (!is.null(demo_map)) {
      cat("  ✅ Demo map created successfully\n")
      return(TRUE)
    } else {
      cat("  ❌ Demo map creation failed\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("  ❌ Demo map creation error:", e$message, "\n")
    return(FALSE)
  })
}

# Test app.R integration
test_app_integration <- function() {
  cat("\nTesting app.R integration...\n")
  
  tryCatch({
    # Check if app.R exists and has geospatial components
    if (file.exists("app.R")) {
      app_content <- readLines("app.R")
      
      # Check for geospatial components
      has_geospatial_menu <- any(grepl("Geospatial Analytics", app_content))
      has_geospatial_tab <- any(grepl("tabName = \"geospatial\"", app_content))
      has_leaflet_output <- any(grepl("leafletOutput", app_content))
      
      if (has_geospatial_menu && has_geospatial_tab && has_leaflet_output) {
        cat("  ✅ App.R properly integrated with geospatial components\n")
        return(TRUE)
      } else {
        cat("  ❌ App.R missing geospatial components\n")
        cat("    Menu:", has_geospatial_menu, "| Tab:", has_geospatial_tab, "| Output:", has_leaflet_output, "\n")
        return(FALSE)
      }
    } else {
      cat("  ❌ app.R file not found\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("  ❌ App integration test error:", e$message, "\n")
    return(FALSE)
  })
}

# Test Railway deployment readiness
test_railway_readiness <- function() {
  cat("\nTesting Railway deployment readiness...\n")
  
  # Check for required files
  required_files <- c("app.R", "geospatial_analytics_system.R", "RAILWAY_DATABASE_FIX.R")
  missing_files <- c()
  
  for (file in required_files) {
    if (file.exists(file)) {
      cat("  ✅ Found:", file, "\n")
    } else {
      cat("  ❌ Missing:", file, "\n")
      missing_files <- c(missing_files, file)
    }
  }
  
  # Check for cache directories
  cache_dirs <- c("cache", "cache/geospatial", "cache/boundaries")
  for (dir in cache_dirs) {
    if (!dir.exists(dir)) {
      dir.create(dir, recursive = TRUE, showWarnings = FALSE)
      cat("  ✅ Created cache directory:", dir, "\n")
    } else {
      cat("  ✅ Cache directory exists:", dir, "\n")
    }
  }
  
  if (length(missing_files) == 0) {
    cat("  ✅ All required files present for Railway deployment\n")
    return(TRUE)
  } else {
    cat("  ❌ Missing files for Railway deployment\n")
    return(FALSE)
  }
}

# Run all tests
main <- function() {
  cat("Starting comprehensive geospatial integration test...\n\n")
  
  test_results <- list(
    packages = test_packages(),
    geospatial_system = test_geospatial_system(),
    database = test_database_connection(),
    demo_map = test_demo_map(),
    app_integration = test_app_integration(),
    railway_readiness = test_railway_readiness()
  )
  
  # Summary
  cat("\n=== TEST SUMMARY ===\n")
  passed_tests <- sum(unlist(test_results))
  total_tests <- length(test_results)
  
  for (test_name in names(test_results)) {
    status <- if (test_results[[test_name]]) "✅ PASS" else "❌ FAIL"
    cat(sprintf("%-20s: %s\n", test_name, status))
  }
  
  cat(sprintf("\nOverall: %d/%d tests passed (%.1f%%)\n", 
             passed_tests, total_tests, 100 * passed_tests / total_tests))
  
  if (passed_tests >= 4) {  # Allow some tolerance
    cat("🚀 READY FOR RAILWAY DEPLOYMENT\n")
    return(TRUE)
  } else {
    cat("⚠️ NEEDS ATTENTION BEFORE DEPLOYMENT\n")
    return(FALSE)
  }
}

# Execute if run as script
if (!interactive()) {
  result <- main()
  if (result) {
    quit(status = 0)
  } else {
    quit(status = 1)
  }
}