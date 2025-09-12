# Test suite for document functions
# Author: Monitor Legislativo Research Team

context("Document Functions")

# Mock document data
mock_document <- list(
  id = "doc_123",
  title = "Lei Municipal de Transporte",
  category = "Lei",
  state = "SP",
  municipality = "São Paulo",
  date = "2023-01-15",
  author = "Prefeitura de São Paulo",
  summary = "Lei que regulamenta o sistema de transporte público municipal.",
  url = "https://example.com/lei123",
  content = "Artigo 1º - Esta lei estabelece normas para...",
  word_count = 1500,
  page_count = 5
)

mock_document_response <- list(
  success = TRUE,
  data = mock_document
)

mock_documents_response <- list(
  success = TRUE,
  data = list(mock_document, mock_document)
)

mock_metadata_response <- list(
  success = TRUE,
  data = list(
    list(
      id = "doc_123",
      title = "Lei Municipal",
      category = "Lei",
      word_count = 1500,
      stats = list(access_count = 45, download_count = 12)
    )
  )
)

# Test single document retrieval
test_that("ml_get_document validates input parameters", {
  # Test missing/invalid document ID
  expect_error(ml_get_document(""), "obrigatório")
  expect_error(ml_get_document(NULL), "obrigatório")
  expect_error(ml_get_document("   "), "obrigatório")
  
  # Test invalid format
  expect_error(ml_get_document("doc_123", format = "invalid"), "format deve ser")
})

test_that("ml_get_document returns correct format", {
  mockery::stub(ml_get_document, ".ml_api_call", mock_document_response)
  
  # Test tibble format (default)
  doc_tibble <- ml_get_document("doc_123")
  expect_is(doc_tibble, "tbl_df")
  expect_equal(nrow(doc_tibble), 1)
  expect_true("id" %in% names(doc_tibble))
  expect_true("title" %in% names(doc_tibble))
  expect_equal(doc_tibble$id[1], "doc_123")
  
  # Test list format
  doc_list <- ml_get_document("doc_123", format = "list")
  expect_is(doc_list, "list")
  expect_equal(doc_list$id, "doc_123")
  
  # Test text format
  doc_text <- ml_get_document("doc_123", format = "text")
  expect_is(doc_text, "character")
  expect_gt(nchar(doc_text), 0)
})

test_that("ml_get_document handles content and metadata options", {
  mockery::stub(ml_get_document, ".ml_api_call", mock_document_response)
  
  # Test with content
  doc_with_content <- ml_get_document("doc_123", include_content = TRUE)
  expect_is(doc_with_content, "tbl_df")
  expect_true("content" %in% names(doc_with_content))
  expect_false(is.na(doc_with_content$content[1]))
  
  # Test without content
  doc_no_content <- ml_get_document("doc_123", include_content = FALSE)
  expect_is(doc_no_content, "tbl_df")
  expect_true(is.na(doc_no_content$content[1]))
  
  # Test metadata attributes
  doc_meta <- ml_get_document("doc_123", include_metadata = TRUE)
  expect_true(!is.null(attr(doc_meta, "retrieved_at")))
  expect_true(!is.null(attr(doc_meta, "includes_content")))
})

# Test multiple documents retrieval
test_that("ml_get_documents validates input parameters", {
  # Test empty input
  result <- ml_get_documents(c())
  expect_is(result, "tbl_df")
  expect_equal(nrow(result), 0)
  
  # Test invalid on_error parameter
  expect_error(
    ml_get_documents(c("doc_1", "doc_2"), on_error = "invalid"),
    "on_error deve ser"
  )
})

test_that("ml_get_documents processes multiple documents correctly", {
  mockery::stub(ml_get_documents, ".ml_api_call", mock_documents_response)
  
  # Test basic multiple document retrieval
  docs <- ml_get_documents(c("doc_1", "doc_2"))
  expect_is(docs, "tbl_df")
  expect_gte(nrow(docs), 1)
  expect_true("id" %in% names(docs))
  
  # Test with batch size
  docs_batched <- ml_get_documents(
    c("doc_1", "doc_2", "doc_3"),
    batch_size = 2,
    progress = FALSE
  )
  expect_is(docs_batched, "tbl_df")
  
  # Check batch info attributes
  batch_info <- attr(docs_batched, "batch_info")
  expect_is(batch_info, "list")
  expect_true("total_requested" %in% names(batch_info))
  expect_true("batch_size" %in% names(batch_info))
})

test_that("ml_get_documents handles errors correctly", {
  # Mock error response
  error_response <- list(success = FALSE, message = "Document not found")
  mockery::stub(ml_get_documents, ".ml_api_call", error_response)
  
  # Test skip error mode
  expect_silent(ml_get_documents(c("invalid_id"), on_error = "skip"))
  
  # Test stop error mode - should use fallback to individual calls
  mockery::stub(ml_get_documents, "ml_get_document", function(...) {
    stop("Document not found")
  })
  
  expect_error(ml_get_documents(c("invalid_id"), on_error = "stop"))
})

# Test document filtering
test_that("ml_filter_documents validates input", {
  # Test empty data frame
  empty_df <- tibble::tibble()
  result <- ml_filter_documents(empty_df)
  expect_equal(result, empty_df)
  
  # Test non-data.frame input
  expect_silent(ml_filter_documents("not_a_df"))
})

test_that("ml_filter_documents applies filters correctly", {
  # Create test data
  test_docs <- tibble::tibble(
    id = c("doc_1", "doc_2", "doc_3", "doc_4"),
    title = c("Lei A", "Decreto B", "Lei C", "Portaria D"),
    category = c("Lei", "Decreto", "Lei", "Portaria"),
    state = c("SP", "RJ", "SP", "MG"),
    date = c("2023-01-01", "2023-02-01", "2023-03-01", "2023-04-01"),
    relevance_score = c(0.9, 0.8, 0.7, 0.6)
  )
  
  # Test category filter
  filtered_category <- ml_filter_documents(test_docs, category = c("Lei"))
  expect_equal(nrow(filtered_category), 2)
  expect_true(all(filtered_category$category == "Lei"))
  
  # Test state filter
  filtered_state <- ml_filter_documents(test_docs, state = c("SP", "RJ"))
  expect_equal(nrow(filtered_state), 3)
  expect_true(all(filtered_state$state %in% c("SP", "RJ")))
  
  # Test relevance filter
  filtered_relevance <- ml_filter_documents(test_docs, min_relevance = 0.75)
  expect_equal(nrow(filtered_relevance), 2)
  expect_true(all(filtered_relevance$relevance_score >= 0.75))
  
  # Test date range filter
  filtered_date <- ml_filter_documents(
    test_docs,
    date_range = c("2023-01-01", "2023-02-28")
  )
  expect_lte(nrow(filtered_date), nrow(test_docs))
  
  # Test combined filters
  filtered_combined <- ml_filter_documents(
    test_docs,
    category = "Lei",
    state = "SP",
    min_relevance = 0.75
  )
  expect_equal(nrow(filtered_combined), 1)
})

test_that("ml_filter_documents handles sorting", {
  test_docs <- tibble::tibble(
    id = c("doc_1", "doc_2", "doc_3"),
    title = c("C Title", "A Title", "B Title"),
    category = c("Lei", "Decreto", "Lei"),
    date = c("2023-03-01", "2023-01-01", "2023-02-01"),
    relevance_score = c(0.7, 0.9, 0.8)
  )
  
  # Test sort by relevance
  sorted_relevance <- ml_filter_documents(test_docs, sort_by = "relevance")
  expect_equal(sorted_relevance$relevance_score[1], 0.9)
  
  # Test sort by date descending
  sorted_date_desc <- ml_filter_documents(test_docs, sort_by = "date_desc")
  expect_equal(sorted_date_desc$date[1], "2023-03-01")
  
  # Test sort by title
  sorted_title <- ml_filter_documents(test_docs, sort_by = "title")
  expect_equal(sorted_title$title[1], "A Title")
  
  # Check filter info attribute
  filter_info <- attr(sorted_title, "filter_info")
  expect_is(filter_info, "list")
  expect_equal(filter_info$original_count, 3)
  expect_equal(filter_info$filtered_count, 3)
})

# Test metadata functions
test_that("ml_get_document_metadata works correctly", {
  mockery::stub(ml_get_document_metadata, ".ml_api_call", mock_metadata_response)
  
  # Test basic metadata retrieval
  metadata <- ml_get_document_metadata(c("doc_123"))
  expect_is(metadata, "tbl_df")
  expect_true("id" %in% names(metadata))
  
  # Test with specific fields
  metadata_fields <- ml_get_document_metadata(
    c("doc_123"),
    fields = c("id", "title", "word_count")
  )
  expect_is(metadata_fields, "tbl_df")
  
  # Test with stats
  metadata_stats <- ml_get_document_metadata(
    c("doc_123"),
    include_stats = TRUE
  )
  expect_is(metadata_stats, "tbl_df")
  
  # Check attributes
  expect_equal(attr(metadata_stats, "include_stats"), TRUE)
})

test_that("ml_validate_documents validates existence", {
  # Mock validation response
  validation_response <- list(
    success = TRUE,
    data = list(existing = c("doc_1", "doc_2"))
  )
  
  mockery::stub(ml_validate_documents, ".ml_api_call", validation_response)
  
  # Test basic validation
  validation <- ml_validate_documents(c("doc_1", "doc_2", "doc_3"))
  expect_is(validation, "list")
  expect_true("existing" %in% names(validation))
  expect_true("total_checked" %in% names(validation))
  expect_equal(validation$total_checked, 3)
  expect_equal(validation$found_count, 2)
  
  # Test with missing IDs
  validation_missing <- ml_validate_documents(
    c("doc_1", "doc_2", "doc_3"),
    return_missing = TRUE
  )
  expect_true("missing" %in% names(validation_missing))
  expect_true("missing_count" %in% names(validation_missing))
})

# Test error handling
test_that("document functions handle errors gracefully", {
  # Mock API error
  error_response <- list(success = FALSE, message = "Document not found")
  
  mockery::stub(ml_get_document, ".ml_api_call", error_response)
  expect_error(ml_get_document("invalid_id"), "Document not found")
  
  # Test empty metadata response
  empty_metadata_response <- list(success = TRUE, data = list())
  mockery::stub(ml_get_document_metadata, ".ml_api_call", empty_metadata_response)
  
  metadata_empty <- ml_get_document_metadata(c("nonexistent"))
  expect_is(metadata_empty, "tbl_df")
  expect_equal(nrow(metadata_empty), 0)
})

# Test edge cases
test_that("document functions handle edge cases", {
  # Test filtering with missing columns
  test_docs_minimal <- tibble::tibble(
    id = c("doc_1", "doc_2"),
    title = c("Title 1", "Title 2")
  )
  
  # Should handle missing columns gracefully
  expect_warning(
    ml_filter_documents(test_docs_minimal, category = "Lei"),
    "category.*não encontrada"
  )
  
  # Test with text filter on available columns
  test_docs_with_content <- tibble::tibble(
    id = c("doc_1", "doc_2"),
    title = c("Lei sobre transporte", "Decreto sobre saúde"),
    summary = c("Transporte público", "Sistema de saúde")
  )
  
  filtered_text <- ml_filter_documents(
    test_docs_with_content,
    text_filter = "transporte"
  )
  expect_equal(nrow(filtered_text), 1)
  expect_true(stringr::str_detect(filtered_text$title[1], "transporte"))
})