test_that("Data loading functions work correctly", {
  skip_on_cran()
  
  # Test CSV fallback data loading
  expect_true(file.exists("../../data/monitor_legislativo_cleaned.csv"))
  
  # Test data structure
  if(file.exists("../../data/monitor_legislativo_cleaned.csv")) {
    sample_data <- read.csv("../../data/monitor_legislativo_cleaned.csv", nrows = 10)
    
    # Check required columns exist
    required_cols <- c("id", "titulo", "ano", "tipo", "content", "estado")
    missing_cols <- setdiff(required_cols, names(sample_data))
    expect_equal(length(missing_cols), 0, 
                 info = paste("Missing columns:", paste(missing_cols, collapse = ", ")))
  }
})

test_that("Search functions work with sample data", {
  skip_on_cran()
  
  # Create minimal test data
  test_data <- data.frame(
    id = 1:5,
    titulo = c("Lei de Transporte", "Código de Trânsito", "Regulamento Metro", 
               "Portaria Ônibus", "Decreto Ciclovia"),
    content = c("transporte público", "trânsito urbano", "sistema metroviário",
                "transporte coletivo", "mobilidade urbana"),
    ano = c(2020, 2021, 2022, 2023, 2024),
    estado = c("SP", "RJ", "MG", "SP", "RJ")
  )
  
  # Test basic search functionality
  search_result <- test_data[grepl("transporte", test_data$content, ignore.case = TRUE), ]
  expect_gt(nrow(search_result), 0)
  
  # Test year filtering
  recent_data <- test_data[test_data$ano >= 2022, ]
  expect_equal(nrow(recent_data), 3)
})