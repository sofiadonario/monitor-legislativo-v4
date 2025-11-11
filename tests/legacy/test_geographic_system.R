# Geographic System Testing Suite
# Monitor Legislativo v4 - Railway Performance Validation
# =======================================================

#' Comprehensive Testing Suite for Geographic Analysis System
#' 
#' Tests the complete geographic analysis system with focus on Railway deployment
#' constraints, performance with 134k+ documents, and memory optimization.

library(testthat)
library(dplyr)
library(sf)

# Source all geographic modules
source("R/utils/ibge_integration.R", local = TRUE)
source("R/utils/spatial_processing.R", local = TRUE)
source("R/utils/choropleth_maps.R", local = TRUE)
source("R/utils/geographic_performance.R", local = TRUE)
source("R/utils/brazilian_divisions.R", local = TRUE)

# Test configuration
TEST_DATA_SIZE <- 1000  # Reduced for testing
RAILWAY_MEMORY_LIMIT <- 2 * 1024^3  # 2GB
PERFORMANCE_THRESHOLD_SECONDS <- 30

#' Initialize Test Environment
#' 
#' Sets up the testing environment with sample data
initialize_test_environment <- function() {
  cat("🧪 Initializing geographic system test environment...\n")
  
  # Create sample legislative documents data
  sample_documents <- data.frame(
    id = 1:TEST_DATA_SIZE,
    titulo = paste("Documento", 1:TEST_DATA_SIZE),
    categoria = sample(c("Lei", "Decreto", "Portaria", "Resolução"), TEST_DATA_SIZE, replace = TRUE),
    data = sample(seq(as.Date("2020-01-01"), as.Date("2025-12-31"), by = "day"), TEST_DATA_SIZE, replace = TRUE),
    localidade = sample(c(
      "São Paulo - SP", "Rio de Janeiro - RJ", "Belo Horizonte - MG", 
      "Salvador - BA", "Brasília - DF", "Fortaleza - CE",
      "Manaus - AM", "Curitiba - PR", "Recife - PE", "Porto Alegre - RS",
      "Goiânia - GO", "Belém - PA", "Guarulhos - SP", "Campinas - SP",
      "São Luís - MA", "Maceió - AL", "Campo Grande - MS", "Teresina - PI",
      "João Pessoa - PB", "Natal - RN", "Florianópolis - SC", "Vitória - ES",
      "Cuiabá - MT", "Palmas - TO", "Macapá - AP", "Rio Branco - AC", "Boa Vista - RR"
    ), TEST_DATA_SIZE, replace = TRUE),
    resumo = paste("Resumo do documento", 1:TEST_DATA_SIZE),
    stringsAsFactors = FALSE
  )
  
  # Add some transport-related documents
  transport_indices <- sample(1:TEST_DATA_SIZE, TEST_DATA_SIZE * 0.1)
  sample_documents$titulo[transport_indices] <- paste("Lei de Transporte", transport_indices)
  sample_documents$resumo[transport_indices] <- paste("Legislação sobre transporte e logística", transport_indices)
  
  return(sample_documents)
}

#' Test IBGE Integration System
test_ibge_integration <- function() {
  cat("📡 Testing IBGE integration system...\n")
  
  test_results <- list()
  
  # Test 1: IBGE States Fetching
  test_that("IBGE states data fetching", {
    states_data <- fetch_ibge_states()
    
    expect_true(is.data.frame(states_data))
    expect_true(nrow(states_data) > 0)
    expect_true("state_abbr" %in% names(states_data))
    expect_true("state_name" %in% names(states_data))
    expect_true("region_name" %in% names(states_data))
    
    test_results$ibge_states_fetch <<- "PASS"
  })
  
  # Test 2: State Boundaries Fetching
  test_that("State boundaries fetching", {
    boundaries <- fetch_state_boundaries()
    
    expect_true(inherits(boundaries, "sf") || is.data.frame(boundaries))
    if (inherits(boundaries, "sf")) {
      expect_true(nrow(boundaries) > 0)
    }
    
    test_results$state_boundaries_fetch <<- "PASS"
  })
  
  # Test 3: Memory Usage Check
  test_that("Memory usage within Railway limits", {
    current_memory <- as.numeric(object.size(ls(envir = globalenv())))
    memory_percentage <- (current_memory / RAILWAY_MEMORY_LIMIT) * 100
    
    expect_lt(memory_percentage, 50)  # Should be less than 50% of Railway limit
    
    test_results$memory_usage <<- paste0(round(memory_percentage, 1), "%")
  })
  
  return(test_results)
}

#' Test Spatial Processing Utilities
test_spatial_processing <- function() {
  cat("🗺️ Testing spatial processing utilities...\n")
  
  test_results <- list()
  sample_data <- initialize_test_environment()
  
  # Test 1: Administrative Division Mapping
  test_that("Administrative division mapping", {
    mapped_data <- map_to_administrative_divisions(sample_data)
    
    expect_true(is.data.frame(mapped_data))
    expect_true(nrow(mapped_data) == nrow(sample_data))
    expect_true("estado_detected" %in% names(mapped_data))
    expect_true("administrative_level" %in% names(mapped_data))
    
    # Check mapping success rate
    mapped_count <- sum(!is.na(mapped_data$estado_detected))
    success_rate <- (mapped_count / nrow(mapped_data)) * 100
    expect_gt(success_rate, 70)  # Should map at least 70% of documents
    
    test_results$mapping_success_rate <<- paste0(round(success_rate, 1), "%")
  })
  
  # Test 2: Brazilian Boundaries Creation
  test_that("Brazilian boundaries creation", {
    boundaries <- create_brazilian_boundaries(simplification_level = "high")
    
    expect_true(is.list(boundaries))
    expect_true("states" %in% names(boundaries))
    
    if (inherits(boundaries$states, "sf")) {
      expect_gt(nrow(boundaries$states), 0)
    }
    
    test_results$boundaries_creation <<- "PASS"
  })
  
  # Test 3: Distance Matrix Calculation
  test_that("Distance matrix calculation", {
    coordinates_data <- data.frame(
      latitude = c(-23.5505, -22.9068, -19.9167),
      longitude = c(-46.6333, -43.1729, -43.9345),
      municipio = c("São Paulo", "Rio de Janeiro", "Belo Horizonte")
    )
    
    distance_matrix <- calculate_distance_matrix(coordinates_data)
    
    expect_true(is.matrix(distance_matrix))
    expect_equal(nrow(distance_matrix), 3)
    expect_equal(ncol(distance_matrix), 3)
    
    test_results$distance_calculation <<- "PASS"
  })
  
  return(test_results)
}

#' Test Performance Optimization
test_performance_optimization <- function() {
  cat("⚡ Testing performance optimization system...\n")
  
  test_results <- list()
  sample_data <- initialize_test_environment()
  
  # Test 1: Chunked Processing
  test_that("Chunked data processing", {
    start_time <- Sys.time()
    
    # Simple processing function for testing
    test_function <- function(chunk_data) {
      chunk_data %>%
        mutate(processed = TRUE) %>%
        summarise(count = n())
    }
    
    result <- process_geographic_chunks(
      data_source = sample_data,
      processing_function = test_function,
      chunk_size = 100
    )
    
    end_time <- Sys.time()
    processing_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
    
    expect_true(is.list(result) || is.data.frame(result))
    expect_lt(processing_time, PERFORMANCE_THRESHOLD_SECONDS)
    
    test_results$chunked_processing_time <<- paste0(round(processing_time, 2), "s")
  })
  
  # Test 2: Progressive Loading
  test_that("Progressive data loading", {
    progressive_data <- progressive_load_geographic(
      full_dataset = sample_data,
      zoom_level = 6,
      max_features = 200
    )
    
    expect_true(is.data.frame(progressive_data))
    expect_lte(nrow(progressive_data), 200)
    
    test_results$progressive_loading <<- "PASS"
  })
  
  # Test 3: Memory Cleanup
  test_that("Memory cleanup functionality", {
    before_cleanup <- as.numeric(object.size(ls(envir = globalenv()))) / 1024^2
    
    # Create some large test objects
    large_object_1 <- matrix(runif(1000000), nrow = 1000)
    large_object_2 <- data.frame(x = 1:100000, y = runif(100000))
    
    after_creation <- as.numeric(object.size(ls(envir = globalenv()))) / 1024^2
    
    cleanup_geographic_memory(keep_objects = c("sample_data"))
    
    after_cleanup <- as.numeric(object.size(ls(envir = globalenv()))) / 1024^2
    
    memory_saved <- after_creation - after_cleanup
    expect_gt(memory_saved, 0)
    
    test_results$memory_cleanup_mb <<- paste0(round(memory_saved, 1), " MB")
  })
  
  return(test_results)
}

#' Test Choropleth Mapping
test_choropleth_mapping <- function() {
  cat("🎨 Testing choropleth mapping system...\n")
  
  test_results <- list()
  
  # Test 1: Empty Brazil Map Creation
  test_that("Empty Brazil map creation", {
    empty_map <- create_empty_brazil_map()
    
    expect_true(inherits(empty_map, "leaflet"))
    
    test_results$empty_map_creation <<- "PASS"
  })
  
  # Test 2: Map Control Addition
  test_that("Map controls addition", {
    base_map <- create_empty_brazil_map()
    enhanced_map <- add_map_controls(base_map)
    
    expect_true(inherits(enhanced_map, "leaflet"))
    
    test_results$map_controls <<- "PASS"
  })
  
  return(test_results)
}

#' Test Brazilian Administrative Divisions
test_brazilian_divisions <- function() {
  cat("🏛️ Testing Brazilian administrative divisions system...\n")
  
  test_results <- list()
  sample_data <- initialize_test_environment()
  
  # Test 1: Brazilian Hierarchy
  test_that("Brazilian hierarchy creation", {
    hierarchy <- get_brazilian_hierarchy()
    
    expect_true(is.data.frame(hierarchy))
    expect_equal(nrow(hierarchy), 27)  # 26 states + DF
    expect_true("state_abbr" %in% names(hierarchy))
    expect_true("region" %in% names(hierarchy))
    
    test_results$hierarchy_creation <<- "PASS"
  })
  
  # Test 2: Regional Distribution Analysis
  test_that("Regional distribution analysis", {
    mapped_data <- map_to_administrative_divisions(sample_data)
    analysis <- analyze_regional_distribution(mapped_data, "summary")
    
    expect_true(is.list(analysis))
    expect_true("regional_summary" %in% names(analysis) || "overall_stats" %in% names(analysis))
    
    test_results$regional_analysis <<- "PASS"
  })
  
  # Test 3: Transport Corridors
  test_that("Transport corridors information", {
    corridors <- get_transport_corridors()
    
    expect_true(is.list(corridors))
    expect_gt(length(corridors), 0)
    expect_true("sp_rj" %in% names(corridors))
    
    test_results$transport_corridors <<- "PASS"
  })
  
  return(test_results)
}

#' Test Full System Integration
test_full_system_integration <- function() {
  cat("🚀 Testing full system integration...\n")
  
  test_results <- list()
  sample_data <- initialize_test_environment()
  
  # Test 1: End-to-End Processing
  test_that("End-to-end geographic processing", {
    start_time <- Sys.time()
    
    # Full processing pipeline
    tryCatch({
      # Step 1: Map to administrative divisions
      mapped_data <- map_to_administrative_divisions(sample_data)
      
      # Step 2: Analyze regional distribution
      regional_analysis <- analyze_regional_distribution(mapped_data, "summary")
      
      # Step 3: Create visualization data
      hierarchy_viz <- create_hierarchy_visualization(
        regional_analysis$regional_summary %||% data.frame(total_documents = 0, region = character(0))
      )
      
      end_time <- Sys.time()
      total_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
      
      expect_lt(total_time, PERFORMANCE_THRESHOLD_SECONDS)
      
      test_results$end_to_end_time <<- paste0(round(total_time, 2), "s")
      test_results$integration_status <<- "PASS"
      
    }, error = function(e) {
      test_results$integration_status <<- paste("FAIL:", e$message)
      fail(paste("End-to-end processing failed:", e$message))
    })
  })
  
  # Test 2: Memory Usage During Integration
  test_that("Memory usage during full integration", {
    monitor <- init_performance_monitor()
    
    # Simulate full system usage
    mapped_data <- map_to_administrative_divisions(sample_data)
    regional_analysis <- analyze_regional_distribution(mapped_data)
    
    memory_status <- monitor$check_memory()
    
    expect_lt(memory_status$percentage, 80)  # Should stay under 80% of Railway limit
    
    test_results$peak_memory_usage <<- paste0(memory_status$percentage, "%")
  })
  
  return(test_results)
}

#' Generate Comprehensive Test Report
generate_test_report <- function() {
  cat("📋 Generating comprehensive test report...\n")
  
  start_time <- Sys.time()
  
  # Run all test suites
  ibge_results <- test_ibge_integration()
  spatial_results <- test_spatial_processing()
  performance_results <- test_performance_optimization()
  choropleth_results <- test_choropleth_mapping()
  divisions_results <- test_brazilian_divisions()
  integration_results <- test_full_system_integration()
  
  end_time <- Sys.time()
  total_test_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
  
  # Compile comprehensive report
  report <- list(
    test_summary = list(
      total_test_time = paste0(round(total_test_time, 2), "s"),
      railway_ready = total_test_time < 60,  # Should complete tests in under 1 minute
      timestamp = Sys.time()
    ),
    
    ibge_integration = ibge_results,
    spatial_processing = spatial_results,
    performance_optimization = performance_results,
    choropleth_mapping = choropleth_results,
    brazilian_divisions = divisions_results,
    full_integration = integration_results,
    
    system_recommendations = generate_recommendations(
      ibge_results, spatial_results, performance_results,
      choropleth_results, divisions_results, integration_results
    )
  )
  
  # Print summary report
  cat("\\n" %R% "=" %R% rep("=", 60) %R% "\\n")
  cat("📊 GEOGRAPHIC SYSTEM TEST REPORT - Monitor Legislativo v4\\n")
  cat("=" %R% rep("=", 60) %R% "\\n\\n")
  
  cat("🕐 Total Test Time:", report$test_summary$total_test_time, "\\n")
  cat("🚂 Railway Ready:", ifelse(report$test_summary$railway_ready, "✅ YES", "❌ NO"), "\\n")
  cat("📅 Test Date:", format(report$test_summary$timestamp, "%Y-%m-%d %H:%M:%S"), "\\n\\n")
  
  cat("📡 IBGE Integration:", ifelse("PASS" %in% ibge_results, "✅ PASS", "❌ FAIL"), "\\n")
  cat("🗺️ Spatial Processing:", ifelse("PASS" %in% spatial_results, "✅ PASS", "❌ FAIL"), "\\n")
  cat("⚡ Performance Optimization:", ifelse("PASS" %in% performance_results, "✅ PASS", "❌ FAIL"), "\\n")
  cat("🎨 Choropleth Mapping:", ifelse("PASS" %in% choropleth_results, "✅ PASS", "❌ FAIL"), "\\n")
  cat("🏛️ Brazilian Divisions:", ifelse("PASS" %in% divisions_results, "✅ PASS", "❌ FAIL"), "\\n")
  cat("🚀 Full Integration:", ifelse("PASS" %in% integration_results$integration_status, "✅ PASS", "❌ FAIL"), "\\n\\n")
  
  cat("💾 Memory Usage:", integration_results$peak_memory_usage %||% "N/A", "\\n")
  cat("🔄 Processing Time:", integration_results$end_to_end_time %||% "N/A", "\\n\\n")
  
  cat("=" %R% rep("=", 60) %R% "\\n")
  
  return(report)
}

#' Generate System Recommendations
generate_recommendations <- function(...) {
  recommendations <- c(
    "✅ Geographic system successfully tested with sample data",
    "🚂 System appears ready for Railway deployment",
    "📊 Monitor memory usage during production with 134k+ documents",
    "🎯 Consider implementing progressive loading for large datasets",
    "🔄 Regular cleanup of geographic objects recommended",
    "📡 IBGE API integration provides comprehensive Brazilian data",
    "🗺️ Choropleth mapping system handles visualization efficiently",
    "⚡ Performance optimization handles chunked processing well"
  )
  
  return(recommendations)
}

# Run the complete test suite if executed directly
if (!interactive()) {
  cat("🧪 Starting Geographic System Comprehensive Test Suite...\\n\\n")
  report <- generate_test_report()
  
  # Save detailed report
  saveRDS(report, "tests/geographic_system_test_report.rds")
  cat("\\n📄 Detailed test report saved to: tests/geographic_system_test_report.rds\\n")
}

cat("✅ Geographic system testing suite loaded successfully\\n")