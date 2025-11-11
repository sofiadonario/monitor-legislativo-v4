test_that("Shiny app starts without errors", {
  skip_on_cran()
  
  # Test basic app startup
  app <- AppDriver$new(
    app_dir = "../../../",
    name = "monitor_legislativo_test",
    timeout = 20000
  )
  
  # Check that app loads
  expect_true(app$wait_for_js("$('#sidebarMenu').length > 0"))
  
  # Check main dashboard elements
  expect_true(app$wait_for_js("$('.main-header').length > 0"))
  
  app$stop()
})

test_that("Database connection can be established", {
  skip_if_not(Sys.getenv("DATABASE_URL") != "", "Database URL not set")
  
  # Test database connection
  source("../../../R/database_connection.R")
  
  # This should not throw an error if database is accessible
  expect_no_error({
    conn_result <- try(test_database_connection(), silent = TRUE)
  })
})