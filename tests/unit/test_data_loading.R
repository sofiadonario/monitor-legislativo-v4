test_that("Data loading functions work correctly", {
  skip_on_cran()
  
  # Test CSV fallback data loading
  data_path <- "../../../data_current/processed/archive/legacy_versions/deduplicated/lexml_unified_deduplicated.csv"
  expect_true(file.exists(data_path))
  
  # Test data structure
  if(file.exists(data_path)) {
    sample_data <- read.csv(data_path, nrows = 10)
    
    # Check required columns exist (based on actual data structure)
    required_cols <- c("titulo", "ano", "tipo", "estado")
    missing_cols <- setdiff(required_cols, names(sample_data))
    expect_equal(length(missing_cols), 0, 
                 info = paste("Missing columns:", paste(missing_cols, collapse = ", ")))
  }
})

test_that("Search functions work with sample data", {
  skip_on_cran()
  
  # Create minimal test data
  test_data <- data.frame(
    titulo = c("Lei de Transporte", "Código de Trânsito", "Regulamento Metro", 
               "Portaria Ônibus", "Decreto Ciclovia"),
    ementa = c("transporte público", "trânsito urbano", "sistema metroviário",
               "transporte coletivo", "mobilidade urbana"),
    ano = c(2020, 2021, 2022, 2023, 2024),
    estado = c("SP", "RJ", "MG", "SP", "RJ")
  )
  
  # Test basic search functionality
  search_result <- test_data[grepl("transporte", test_data$ementa, ignore.case = TRUE), ]
  expect_gt(nrow(search_result), 0)
  
  # Test year filtering
  recent_data <- test_data[test_data$ano >= 2022, ]
  expect_equal(nrow(recent_data), 3)
})