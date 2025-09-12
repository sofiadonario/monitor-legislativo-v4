# Test suite for search functions
# Author: Monitor Legislativo Research Team

context("Search Functions")

# Setup mock API responses
mock_search_response <- list(
  success = TRUE,
  data = list(
    list(
      id = "doc_1",
      title = "Lei sobre Transporte Público",
      category = "Lei",
      state = "SP",
      date = "2023-01-15",
      summary = "Lei que regulamenta o transporte público na cidade.",
      relevance_score = 0.95
    ),
    list(
      id = "doc_2", 
      title = "Decreto Municipal de Mobilidade",
      category = "Decreto",
      state = "RJ",
      date = "2023-02-20",
      summary = "Decreto sobre mobilidade urbana sustentável.",
      relevance_score = 0.87
    )
  ),
  meta = list(
    total_results = 2,
    search_time = 0.123,
    query = "transporte público"
  )
)

mock_suggestions_response <- list(
  success = TRUE,
  data = list(
    list(text = "lei orgânica", frequency = 1500),
    list(text = "transporte público", frequency = 890),
    list(text = "meio ambiente", frequency = 750)
  )
)

mock_trends_response <- list(
  success = TRUE,
  data = list(
    list(term = "sustentabilidade", searches = 1200, change = "+15%"),
    list(term = "mobilidade urbana", searches = 980, change = "+8%")
  )
)

# Test basic search functionality
test_that("ml_search validates input parameters correctly", {
  # Test missing query
  expect_error(ml_search(""), "obrigatório")
  expect_error(ml_search(NULL), "obrigatório")
  expect_error(ml_search("   "), "obrigatório")
  
  # Test invalid sort_by
  expect_error(ml_search("test", sort_by = "invalid"), "sort_by deve ser")
  
  # Test limit validation
  expect_silent(ml_search("test", limit = 10))
  expect_silent(ml_search("test", limit = 1000))
  
  # Mock API call to avoid real requests
  mockery::stub(ml_search, ".ml_api_call", mock_search_response)
  
  # Test successful search
  result <- ml_search("transporte público", limit = 10)
  expect_is(result, "tbl_df")
  expect_equal(nrow(result), 2)
  expect_true("id" %in% names(result))
  expect_true("title" %in% names(result))
  expect_true("relevance_score" %in% names(result))
})

test_that("ml_search returns correct data structure", {
  # Mock API call
  mockery::stub(ml_search, ".ml_api_call", mock_search_response)
  
  # Test tibble format (default)
  result <- ml_search("transporte", as_tibble = TRUE)
  expect_is(result, "tbl_df")
  expect_equal(nrow(result), 2)
  
  # Check required columns
  required_cols <- c("id", "title", "category", "state", "date", "summary")
  expect_true(all(required_cols %in% names(result)))
  
  # Check data types
  expect_is(result$id, "character")
  expect_is(result$relevance_score, "numeric")
  
  # Test list format
  result_list <- ml_search("transporte", as_tibble = FALSE)
  expect_is(result_list, "list")
  expect_true("data" %in% names(result_list))
  expect_true("meta" %in% names(result_list))
})

test_that("ml_search handles filters correctly", {
  mockery::stub(ml_search, ".ml_api_call", mock_search_response)
  
  # Test with filters
  filters <- list(
    category = "Lei",
    state = "SP",
    date_start = "2023-01-01"
  )
  
  result <- ml_search("transporte", filters = filters)
  expect_is(result, "tbl_df")
  
  # Check that search metadata includes filters
  meta <- attr(result, "search_meta")
  expect_is(meta, "list")
})

test_that("ml_search_documents applies filters correctly", {
  mockery::stub(ml_search_documents, "ml_search", tibble::tibble(
    id = c("doc_1", "doc_2"),
    title = c("Lei SP", "Decreto RJ"),
    category = c("Lei", "Decreto"),
    state = c("SP", "RJ")
  ))
  
  # Test category filter
  result <- ml_search_documents("test", category = "Lei")
  expect_is(result, "tbl_df")
  
  # Test state filter
  result <- ml_search_documents("test", state = "sp")
  expect_is(result, "tbl_df")
  
  # Test date filters
  result <- ml_search_documents(
    "test",
    date_start = "2023-01-01",
    date_end = "2023-12-31"
  )
  expect_is(result, "tbl_df")
})

test_that("ml_search_advanced handles complex queries", {
  mockery::stub(ml_search_advanced, ".ml_api_call", mock_search_response)
  
  # Test advanced search with specific fields
  result <- ml_search_advanced(
    query = "transporte AND público",
    search_fields = c("title", "summary"),
    phrase_search = FALSE
  )
  
  expect_is(result, "tbl_df")
  expect_true("search_fields_used" %in% names(result))
  
  # Test phrase search
  result_phrase <- ml_search_advanced(
    query = "código de trânsito",
    phrase_search = TRUE
  )
  
  expect_is(result_phrase, "tbl_df")
})

test_that("ml_search_suggestions returns valid suggestions", {
  mockery::stub(ml_search_suggestions, ".ml_api_call", mock_suggestions_response)
  
  # Test basic suggestions
  suggestions <- ml_search_suggestions("lei")
  expect_is(suggestions, "character")
  expect_gt(length(suggestions), 0)
  
  # Test with limit
  suggestions_limited <- ml_search_suggestions("trans", limit = 5)
  expect_is(suggestions_limited, "character")
  expect_lte(length(suggestions_limited), 5)
  
  # Test empty query
  empty_suggestions <- ml_search_suggestions("")
  expect_is(empty_suggestions, "character")
  expect_equal(length(empty_suggestions), 0)
})

test_that("ml_search_similar validates parameters", {
  # Test missing both parameters
  expect_error(ml_search_similar(), "Deve fornecer")
  
  # Mock successful response
  similar_response <- list(
    success = TRUE,
    data = list(
      list(
        id = "sim_1",
        title = "Documento Similar",
        similarity_score = 0.89
      )
    )
  )
  
  mockery::stub(ml_search_similar, ".ml_api_call", similar_response)
  
  # Test with document ID
  result <- ml_search_similar(document_id = "doc_123")
  expect_is(result, "tbl_df")
  expect_true("similarity_score" %in% names(result))
  
  # Test with content
  result_content <- ml_search_similar(content = "Lei sobre transporte")
  expect_is(result_content, "tbl_df")
})

test_that("ml_search_trends returns trending terms", {
  mockery::stub(ml_search_trends, ".ml_api_call", mock_trends_response)
  
  # Test basic trends
  trends <- ml_search_trends()
  expect_is(trends, "tbl_df")
  expect_true("term" %in% names(trends))
  expect_true("searches" %in% names(trends))
  
  # Test with specific period
  trends_week <- ml_search_trends(period = "week", limit = 10)
  expect_is(trends_week, "tbl_df")
  
  # Test invalid period
  expect_error(ml_search_trends(period = "invalid"), "period deve ser")
})

# Test error handling
test_that("search functions handle API errors gracefully", {
  # Mock API error response
  error_response <- list(
    success = FALSE,
    message = "API Error"
  )
  
  mockery::stub(ml_search, ".ml_api_call", error_response)
  
  # Should throw error with API message
  expect_error(ml_search("test"), "API Error")
})

test_that("search functions handle empty results", {
  # Mock empty response
  empty_response <- list(
    success = TRUE,
    data = list(),
    meta = list(total_results = 0)
  )
  
  mockery::stub(ml_search, ".ml_api_call", empty_response)
  
  # Should return empty tibble with correct structure
  result <- ml_search("nonexistent_term")
  expect_is(result, "tbl_df")
  expect_equal(nrow(result), 0)
  expect_true("id" %in% names(result))
})

# Test parameter edge cases
test_that("search functions handle edge case parameters", {
  mockery::stub(ml_search, ".ml_api_call", mock_search_response)
  
  # Test maximum limit
  result <- ml_search("test", limit = 2000)  # Should be capped at 1000
  expect_is(result, "tbl_df")
  
  # Test negative offset (should be corrected to 0)
  result <- ml_search("test", offset = -5)
  expect_is(result, "tbl_df")
  
  # Test with all boolean options
  result <- ml_search(
    "test",
    highlight = FALSE,
    fuzzy = TRUE,
    verbose = TRUE
  )
  expect_is(result, "tbl_df")
})