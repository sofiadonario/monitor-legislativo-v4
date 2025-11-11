# test_search_sanitizer.R - Tests for search sanitization
# ============================================================================

library(testthat)
library(stringi)
source(test_path("..", "..", "R", "utils", "search_sanitizer.R"))

test_that("sanitize_search_query removes dangerous characters", {
  # Test XSS prevention
  query <- "<script>alert('xss')</script>"
  sanitized <- sanitize_search_query(query)
  expect_false(grepl("<", sanitized))
  expect_false(grepl(">", sanitized))

  # Test SQL injection prevention
  query2 <- "'; DROP TABLE users; --"
  sanitized2 <- sanitize_search_query(query2)
  expect_false(grepl("'", sanitized2))
  expect_false(grepl(";", sanitized2))
})

test_that("sanitize_search_query handles accents correctly", {
  # Test accent preservation
  query <- "São Paulo José"
  sanitized <- sanitize_search_query(query, preserve_accents = TRUE)
  expect_true(grepl("São", sanitized))
  expect_true(grepl("José", sanitized))

  # Test accent removal
  sanitized_no_accents <- sanitize_search_query(query, preserve_accents = FALSE)
  expect_true(grepl("Sao", sanitized_no_accents))
  expect_true(grepl("Jose", sanitized_no_accents))
})

test_that("escape_regex_chars escapes metacharacters", {
  text <- "test.* with (special) [chars] {here} $end^"
  escaped <- escape_regex_chars(text)

  expect_true(grepl("\\\\.", escaped, fixed = TRUE))
  expect_true(grepl("\\\\*", escaped, fixed = TRUE))
  expect_true(grepl("\\\\(", escaped, fixed = TRUE))
  expect_true(grepl("\\\\)", escaped, fixed = TRUE))
  expect_true(grepl("\\\\[", escaped, fixed = TRUE))
  expect_true(grepl("\\\\]", escaped, fixed = TRUE))
})

test_that("create_accent_insensitive_pattern works correctly", {
  query <- "São Paulo"
  pattern <- create_accent_insensitive_pattern(query)

  # Should match variations with different accents
  expect_true(grepl(pattern, "São Paulo"))
  expect_true(grepl(pattern, "Sao Paulo"))
  expect_true(grepl(pattern, "Sáo Paulo"))

  # Test with multiple accent types
  query2 <- "café"
  pattern2 <- create_accent_insensitive_pattern(query2)
  expect_true(grepl(pattern2, "cafe"))
  expect_true(grepl(pattern2, "café"))
})

test_that("clean_suggestions removes duplicates and HTML", {
  suggestions <- c(
    "test",
    "test",  # duplicate
    "<b>bold</b>",
    "<script>alert()</script>",
    "",  # empty
    "   spaces   "
  )

  cleaned <- clean_suggestions(suggestions)

  expect_equal(length(cleaned), 3)  # Removed duplicates and empty
  expect_false("test" %in% duplicated(cleaned))
  expect_false(any(grepl("<", cleaned)))
  expect_false(any(grepl(">", cleaned)))
})

test_that("build_sql_like_pattern adds wildcards correctly", {
  query <- "test"

  # Test different wildcard positions
  expect_equal(build_sql_like_pattern(query, "both"), "%test%")
  expect_equal(build_sql_like_pattern(query, "start"), "%test")
  expect_equal(build_sql_like_pattern(query, "end"), "test%")
  expect_equal(build_sql_like_pattern(query, "none"), "test")

  # Test escaping of SQL wildcards
  query2 <- "test_with%wildcards"
  pattern <- build_sql_like_pattern(query2, "both")
  expect_true(grepl("\\\\_", pattern))
  expect_true(grepl("\\\\%", pattern))
})

test_that("normalize_portuguese_text removes stopwords", {
  text <- "A lei de proteção ao consumidor do Brasil"
  normalized <- normalize_portuguese_text(text, remove_stopwords = TRUE)

  # Stopwords should be removed
  expect_false(grepl("\\ba\\b", normalized))
  expect_false(grepl("\\bde\\b", normalized))
  expect_false(grepl("\\bao\\b", normalized))
  expect_false(grepl("\\bdo\\b", normalized))

  # Content words should remain
  expect_true(grepl("lei", normalized))
  expect_true(grepl("proteção", normalized))
  expect_true(grepl("consumidor", normalized))
  expect_true(grepl("brasil", normalized))  # lowercase
})

test_that("normalize_portuguese_text preserves words when requested", {
  text <- "A lei de proteção"
  normalized <- normalize_portuguese_text(text, remove_stopwords = FALSE)

  expect_true(grepl("a", normalized))
  expect_true(grepl("de", normalized))
})

test_that("highlight_search_terms adds markup correctly", {
  text <- "A Lei de Proteção ao Consumidor protege os consumidores"
  terms <- c("lei", "consumidor")

  highlighted <- highlight_search_terms(text, terms)

  expect_true(grepl("<mark>Lei</mark>", highlighted))
  expect_true(grepl("<mark>Consumidor</mark>", highlighted))
  expect_true(grepl("<mark>consumidores</mark>", highlighted))

  # Test custom markup
  highlighted2 <- highlight_search_terms(text, terms, before = "<b>", after = "</b>")
  expect_true(grepl("<b>Lei</b>", highlighted2))
})

test_that("highlight_search_terms handles accents", {
  text <- "São Paulo está em São Paulo"
  terms <- c("Sao Paulo")  # Without accent

  highlighted <- highlight_search_terms(text, terms)

  # Should highlight both with and without accents
  expect_true(grepl("<mark>", highlighted))
})

test_that("functions handle NULL and empty inputs gracefully", {
  expect_equal(sanitize_search_query(NULL), "")
  expect_equal(sanitize_search_query(""), "")

  expect_equal(escape_regex_chars(""), "")

  expect_equal(length(clean_suggestions(NULL)), 0)
  expect_equal(length(clean_suggestions(character(0))), 0)

  expect_equal(highlight_search_terms(NULL, c("test")), NULL)
  expect_equal(highlight_search_terms("text", NULL), "text")
})
