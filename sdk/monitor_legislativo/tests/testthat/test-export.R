# Test suite for export functions
# Author: Monitor Legislativo Research Team

context("Export Functions")

# Setup test data
test_data <- tibble::tibble(
  id = c("doc_1", "doc_2", "doc_3"),
  title = c("Lei A", "Decreto B", "Portaria C"),
  category = c("Lei", "Decreto", "Portaria"),
  state = c("SP", "RJ", "MG"),
  date = c("2023-01-01", "2023-02-01", "2023-03-01"),
  summary = c("Summary A", "Summary B", "Summary C")
)

# Create temporary directory for tests
temp_dir <- tempdir()

# Test data export function
test_that("ml_export_data validates input parameters", {
  # Test empty data
  expect_false(ml_export_data(tibble::tibble(), "test.csv"))
  expect_false(ml_export_data(NULL, "test.csv"))
  
  # Test invalid format
  expect_error(
    ml_export_data(test_data, "test.txt", format = "invalid"),
    "format deve ser"
  )
  
  # Test invalid compression
  expect_error(
    ml_export_data(test_data, "test.csv", compression = "invalid"),
    "compression deve ser"
  )
})

test_that("ml_export_data exports CSV correctly", {
  csv_file <- file.path(temp_dir, "test_export.csv")
  
  # Test basic CSV export
  result <- ml_export_data(test_data, csv_file, format = "csv")
  expect_true(result)
  expect_true(file.exists(csv_file))
  
  # Verify file content
  imported_data <- readr::read_csv(csv_file, show_col_types = FALSE)
  expect_equal(nrow(imported_data), nrow(test_data))
  expect_equal(names(imported_data), names(test_data))
  
  # Clean up
  if (file.exists(csv_file)) file.remove(csv_file)
})

test_that("ml_export_data exports JSON correctly", {
  json_file <- file.path(temp_dir, "test_export.json")
  
  # Test JSON export
  result <- ml_export_data(test_data, json_file, format = "json")
  expect_true(result)
  expect_true(file.exists(json_file))
  
  # Verify file content
  imported_data <- jsonlite::fromJSON(json_file)
  expect_true("data" %in% names(imported_data))
  expect_equal(nrow(imported_data$data), nrow(test_data))
  
  # Clean up
  if (file.exists(json_file)) file.remove(json_file)
})

test_that("ml_export_data handles metadata correctly", {
  csv_file <- file.path(temp_dir, "test_with_metadata.csv")
  metadata_file <- file.path(temp_dir, "test_with_metadata_metadata.json")
  
  # Add search metadata to test data
  attr(test_data, "search_meta") <- list(
    total_results = 3,
    search_time = 0.15,
    query = "test query"
  )
  
  # Export with metadata
  result <- ml_export_data(
    test_data, 
    csv_file, 
    format = "csv",
    include_metadata = TRUE
  )
  
  expect_true(result)
  expect_true(file.exists(csv_file))
  expect_true(file.exists(metadata_file))
  
  # Verify metadata file
  metadata <- jsonlite::fromJSON(metadata_file)
  expect_true("export_date" %in% names(metadata))
  expect_true("total_records" %in% names(metadata))
  expect_equal(metadata$total_records, 3)
  
  # Clean up
  if (file.exists(csv_file)) file.remove(csv_file)
  if (file.exists(metadata_file)) file.remove(metadata_file)
})

test_that("ml_export_data handles chunking for large files", {
  # Create larger test data
  large_data <- tibble::tibble(
    id = paste0("doc_", 1:150),
    title = paste("Title", 1:150),
    category = rep(c("Lei", "Decreto"), length.out = 150)
  )
  
  base_file <- file.path(temp_dir, "large_test")
  manifest_file <- file.path(temp_dir, "large_test_manifest.json")
  
  # Export with chunking
  result <- ml_export_data(
    large_data,
    paste0(base_file, ".csv"),
    format = "csv",
    chunk_size = 50
  )
  
  expect_true(result)
  expect_true(file.exists(manifest_file))
  
  # Check manifest
  manifest <- jsonlite::fromJSON(manifest_file)
  expect_equal(manifest$chunks, 3)  # 150/50 = 3 chunks
  expect_equal(manifest$total_records, 150)
  
  # Clean up chunk files
  if (file.exists(manifest_file)) {
    for (chunk_file in manifest$files) {
      chunk_path <- file.path(temp_dir, chunk_file)
      if (file.exists(chunk_path)) file.remove(chunk_path)
    }
    file.remove(manifest_file)
  }
})

# Test bulk download
test_that("ml_bulk_download validates parameters", {
  # Test empty document IDs
  expect_error(ml_bulk_download(c(), temp_dir), "não pode estar vazia")
  
  # Test invalid organize_by
  expect_error(
    ml_bulk_download(c("doc_1"), temp_dir, organize_by = "invalid"),
    "organize_by deve ser"
  )
})

test_that("ml_bulk_download creates directory structure", {
  download_dir <- file.path(temp_dir, "test_download")
  
  # Mock ml_get_documents to avoid API calls
  mockery::stub(ml_bulk_download, "ml_get_documents", test_data)
  
  # Test basic download
  stats <- ml_bulk_download(
    document_ids = c("doc_1", "doc_2"),
    output_dir = download_dir,
    include_content = FALSE,
    include_citations = FALSE,
    organize_by = "none"
  )
  
  expect_is(stats, "list")
  expect_true("total_requested" %in% names(stats))
  expect_true("successfully_downloaded" %in% names(stats))
  expect_true(dir.exists(download_dir))
  
  # Check index file
  index_file <- file.path(download_dir, "download_index.json")
  expect_true(file.exists(index_file))
  
  # Clean up
  if (dir.exists(download_dir)) {
    unlink(download_dir, recursive = TRUE)
  }
})

test_that("ml_bulk_download organizes files correctly", {
  download_dir <- file.path(temp_dir, "test_organized_download")
  
  # Mock ml_get_documents
  mockery::stub(ml_bulk_download, "ml_get_documents", test_data)
  
  # Test organization by category
  stats <- ml_bulk_download(
    document_ids = c("doc_1", "doc_2", "doc_3"),
    output_dir = download_dir,
    organize_by = "category",
    include_content = FALSE,
    include_citations = FALSE
  )
  
  expect_true(dir.exists(download_dir))
  expect_true(dir.exists(file.path(download_dir, "Lei")))
  expect_true(dir.exists(file.path(download_dir, "Decreto")))
  
  # Clean up
  if (dir.exists(download_dir)) {
    unlink(download_dir, recursive = TRUE)
  }
})

# Test dataset creation
test_that("ml_create_dataset validates parameters", {
  # Test missing required parameters
  expect_error(ml_create_dataset(), "obrigatórios")
  expect_error(
    ml_create_dataset(list(query = "test")),
    "obrigatórios"
  )
})

test_that("ml_create_dataset creates basic dataset", {
  dataset_dir <- file.path(temp_dir, "test_dataset")
  
  # Mock search function
  mockery::stub(ml_create_dataset, "ml_search", test_data)
  
  # Create basic dataset
  dataset_info <- ml_create_dataset(
    search_params = list(query = "test", limit = 10),
    dataset_name = "test_dataset",
    description = "Test dataset for unit tests",
    output_config = list(
      output_dir = dataset_dir,
      formats = "csv"
    )
  )
  
  expect_is(dataset_info, "list")
  expect_true("name" %in% names(dataset_info))
  expect_true("statistics" %in% names(dataset_info))
  expect_true("files" %in% names(dataset_info))
  expect_equal(dataset_info$name, "test_dataset")
  
  # Check files were created
  expect_true(dir.exists(dataset_dir))
  expect_true(file.exists(file.path(dataset_dir, "README.md")))
  expect_true(file.exists(file.path(dataset_dir, "dataset_metadata.json")))
  
  # Clean up
  if (dir.exists(dataset_dir)) {
    unlink(dataset_dir, recursive = TRUE)
  }
})

test_that("ml_create_dataset handles processing options", {
  dataset_dir <- file.path(temp_dir, "test_processed_dataset")
  
  # Mock required functions
  mockery::stub(ml_create_dataset, "ml_search", test_data)
  mockery::stub(ml_create_dataset, "ml_geographic_analysis", test_data)
  mockery::stub(ml_create_dataset, "ml_analyze_trends", list(
    time_series = test_data,
    statistics = list()
  ))
  
  # Create dataset with processing
  dataset_info <- ml_create_dataset(
    search_params = list(query = "test"),
    processing = list(
      include_geographic = TRUE,
      include_temporal_analysis = TRUE
    ),
    dataset_name = "processed_dataset",
    output_config = list(
      output_dir = dataset_dir,
      formats = c("csv", "json")
    )
  )
  
  expect_is(dataset_info, "list")
  expect_gt(length(dataset_info$files), 2)  # Should have multiple files
  
  # Clean up
  if (dir.exists(dataset_dir)) {
    unlink(dataset_dir, recursive = TRUE)
  }
})

# Test error handling
test_that("export functions handle errors gracefully", {
  # Test export to invalid path
  invalid_path <- "/invalid/path/file.csv"
  result <- ml_export_data(test_data, invalid_path)
  expect_false(result)
  
  # Test bulk download with API error
  mockery::stub(ml_bulk_download, "ml_get_documents", function(...) {
    stop("API Error")
  })
  
  download_dir <- file.path(temp_dir, "error_test")
  stats <- ml_bulk_download(c("invalid_id"), download_dir)
  expect_is(stats, "list")
  expect_gt(stats$failed_downloads, 0)
  
  # Clean up
  if (dir.exists(download_dir)) {
    unlink(download_dir, recursive = TRUE)
  }
})

# Test file format specifics
test_that("export functions handle different file formats", {
  # Test TSV export
  tsv_file <- file.path(temp_dir, "test.tsv")
  result <- ml_export_data(test_data, tsv_file, format = "tsv")
  expect_true(result)
  expect_true(file.exists(tsv_file))
  
  # Test RData export
  rdata_file <- file.path(temp_dir, "test.RData")
  result <- ml_export_data(test_data, rdata_file, format = "rdata")
  expect_true(result)
  expect_true(file.exists(rdata_file))
  
  # Verify RData content
  load(rdata_file)
  expect_true(exists("monitor_legislativo_data"))
  expect_equal(nrow(monitor_legislativo_data), nrow(test_data))
  
  # Clean up
  if (file.exists(tsv_file)) file.remove(tsv_file)
  if (file.exists(rdata_file)) file.remove(rdata_file)
  rm(monitor_legislativo_data)
})

# Test compression
test_that("export functions handle compression correctly", {
  csv_file <- file.path(temp_dir, "test_compressed.csv")
  
  # Test gzip compression
  result <- ml_export_data(
    test_data, 
    csv_file, 
    format = "csv",
    compression = "gzip"
  )
  
  expect_true(result)
  expect_true(file.exists(paste0(csv_file, ".gz")))
  
  # Clean up
  compressed_file <- paste0(csv_file, ".gz")
  if (file.exists(compressed_file)) file.remove(compressed_file)
})