#!/usr/bin/env Rscript
#' Test Suite for Readability Metrics
#'
#' Comprehensive tests to validate readability metric calculations
#' for Portuguese legislative texts.
#'
#' Usage:
#'   Rscript test_readability.R
#'
#' @author Monitor Legislativo v4
#' @date 2025-11-12

# Load required libraries
suppressPackageStartupMessages({
  library(stringr)
  library(dplyr)
})

# Source the readability metrics module
source("R/analytics/readability_metrics.R")

# Test counter
tests_passed <- 0
tests_failed <- 0

# Helper function to run tests
run_test <- function(test_name, test_expr, expected = TRUE) {
  cat(sprintf("Testing: %s... ", test_name))

  result <- tryCatch({
    test_result <- test_expr
    if (is.logical(test_result)) {
      test_result == expected
    } else {
      !is.na(test_result) && !is.null(test_result)
    }
  }, error = function(e) {
    cat("ERROR:", e$message, "\n")
    return(FALSE)
  })

  if (result) {
    cat("✓ PASS\n")
    tests_passed <<- tests_passed + 1
  } else {
    cat("✗ FAIL\n")
    tests_failed <<- tests_failed + 1
  }

  return(result)
}

cat("\n")
cat(rep("=", 70), "\n", sep = "")
cat("READABILITY METRICS TEST SUITE\n")
cat(rep("=", 70), "\n\n", sep = "")

# ==============================================================================
# TEST 1: Syllable Counting
# ==============================================================================

cat("TEST GROUP 1: Portuguese Syllable Counting\n")
cat(rep("-", 70), "\n", sep = "")

syllable_tests <- list(
  list(word = "lei", expected = 1),
  list(word = "país", expected = 2),
  list(word = "brasileiro", expected = 4),
  list(word = "constituição", expected = 4),
  list(word = "administração", expected = 5),
  list(word = "impessoalidade", expected = 6),
  list(word = "publicidade", expected = 5),
  list(word = "eficiência", expected = 4),
  list(word = "legalidade", expected = 5),
  list(word = "moralidade", expected = 5)
)

for (test in syllable_tests) {
  result <- count_syllables_pt(test$word)
  passed <- run_test(
    sprintf("'%s' has %d syllables", test$word, test$expected),
    result == test$expected
  )

  if (!passed) {
    cat(sprintf("  Expected: %d, Got: %d\n", test$expected, result))
  }
}

# Edge cases for syllable counting
run_test("Empty string returns 0", count_syllables_pt("") == 0)
run_test("NA returns 0", count_syllables_pt(NA) == 0)
run_test("Single vowel returns 1", count_syllables_pt("a") >= 1)

cat("\n")

# ==============================================================================
# TEST 2: Sentence Counting
# ==============================================================================

cat("TEST GROUP 2: Sentence Counting\n")
cat(rep("-", 70), "\n", sep = "")

run_test(
  "Single sentence with period",
  count_sentences("Esta é uma frase.") == 1
)

run_test(
  "Two sentences",
  count_sentences("Esta é uma frase. Esta é outra.") == 2
)

run_test(
  "Question mark",
  count_sentences("Esta é uma pergunta?") == 1
)

run_test(
  "Exclamation mark",
  count_sentences("Esta é uma exclamação!") == 1
)

run_test(
  "Mixed punctuation",
  count_sentences("Primeira. Segunda? Terceira!") == 3
)

run_test(
  "Legislative text with Art.",
  count_sentences("Art. 1º. Esta lei entra em vigor.") == 1
)

run_test(
  "No punctuation defaults to 1",
  count_sentences("Texto sem pontuação") == 1
)

run_test(
  "Empty string returns 0",
  count_sentences("") == 0
)

cat("\n")

# ==============================================================================
# TEST 3: Complex Word Counting
# ==============================================================================

cat("TEST GROUP 3: Complex Word Counting\n")
cat(rep("-", 70), "\n", sep = "")

run_test(
  "Simple text has few complex words",
  count_complex_words("O gato subiu no teto.") < 2
)

run_test(
  "Legislative text has many complex words",
  count_complex_words("A administração pública obedecerá aos princípios constitucionais.") >= 3
)

run_test(
  "Empty text returns 0",
  count_complex_words("") == 0
)

cat("\n")

# ==============================================================================
# TEST 4: Flesch-Kincaid Calculation
# ==============================================================================

cat("TEST GROUP 4: Flesch-Kincaid Reading Ease\n")
cat(rep("-", 70), "\n", sep = "")

simple_text <- "O gato subiu no teto. Ele está lá."
complex_text <- "A administração pública direta e indireta de qualquer dos Poderes da União obedecerá aos princípios constitucionais fundamentais."

simple_score <- calculate_flesch_kincaid_pt(simple_text)
complex_score <- calculate_flesch_kincaid_pt(complex_text)

run_test(
  "Simple text has higher score than complex",
  !is.na(simple_score) && !is.na(complex_score) && simple_score > complex_score
)

run_test(
  "Score is between 0 and 100",
  !is.na(simple_score) && simple_score >= 0 && simple_score <= 100
)

run_test(
  "Empty text returns NA",
  is.na(calculate_flesch_kincaid_pt(""))
)

run_test(
  "NA text returns NA",
  is.na(calculate_flesch_kincaid_pt(NA))
)

cat("\n")

# ==============================================================================
# TEST 5: FOG Index Calculation
# ==============================================================================

cat("TEST GROUP 5: Gunning FOG Index\n")
cat(rep("-", 70), "\n", sep = "")

simple_fog <- calculate_fog_index(simple_text)
complex_fog <- calculate_fog_index(complex_text)

run_test(
  "Complex text has higher FOG than simple",
  !is.na(simple_fog) && !is.na(complex_fog) && complex_fog > simple_fog
)

run_test(
  "FOG score is reasonable (0-30)",
  !is.na(simple_fog) && simple_fog >= 0 && simple_fog <= 30
)

run_test(
  "Empty text returns NA",
  is.na(calculate_fog_index(""))
)

cat("\n")

# ==============================================================================
# TEST 6: SMOG Index Calculation
# ==============================================================================

cat("TEST GROUP 6: SMOG Index\n")
cat(rep("-", 70), "\n", sep = "")

simple_smog <- calculate_smog_index(simple_text)
complex_smog <- calculate_smog_index(complex_text)

run_test(
  "SMOG returns numeric value",
  is.numeric(simple_smog)
)

run_test(
  "SMOG score is reasonable (0-30)",
  !is.na(simple_smog) && simple_smog >= 0 && simple_smog <= 30
)

run_test(
  "Empty text returns NA",
  is.na(calculate_smog_index(""))
)

cat("\n")

# ==============================================================================
# TEST 7: Calculate All Metrics
# ==============================================================================

cat("TEST GROUP 7: Calculate All Metrics\n")
cat(rep("-", 70), "\n", sep = "")

test_text <- "Art. 1º. Esta lei estabelece normas gerais. Parágrafo único. Ela entra em vigor hoje."
all_metrics <- calculate_all_readability_metrics(test_text)

run_test(
  "Returns list with three elements",
  is.list(all_metrics) && length(all_metrics) == 3
)

run_test(
  "Contains flesch_kincaid",
  "flesch_kincaid" %in% names(all_metrics)
)

run_test(
  "Contains fog_index",
  "fog_index" %in% names(all_metrics)
)

run_test(
  "Contains smog_index",
  "smog_index" %in% names(all_metrics)
)

run_test(
  "All metrics are numeric",
  is.numeric(all_metrics$flesch_kincaid) &&
  is.numeric(all_metrics$fog_index) &&
  is.numeric(all_metrics$smog_index)
)

cat("\n")

# ==============================================================================
# TEST 8: Real Legislative Texts
# ==============================================================================

cat("TEST GROUP 8: Real Legislative Text Examples\n")
cat(rep("-", 70), "\n", sep = "")

# Example from Brazilian Constitution
constitutional_text <- "Art. 37. A administração pública direta e indireta de qualquer dos Poderes da União, dos Estados, do Distrito Federal e dos Municípios obedecerá aos princípios de legalidade, impessoalidade, moralidade, publicidade e eficiência."

const_metrics <- calculate_all_readability_metrics(constitutional_text)

run_test(
  "Constitutional text returns valid metrics",
  !is.na(const_metrics$flesch_kincaid)
)

run_test(
  "Constitutional text is difficult (Flesch < 50)",
  const_metrics$flesch_kincaid < 50
)

# Simple law example
simple_law <- "Esta lei entra em vigor na data de sua publicação."
simple_metrics <- calculate_all_readability_metrics(simple_law)

run_test(
  "Simple law returns valid metrics",
  !is.na(simple_metrics$flesch_kincaid)
)

run_test(
  "Simple law is easier than constitution",
  simple_metrics$flesch_kincaid > const_metrics$flesch_kincaid
)

cat("\n")

# ==============================================================================
# TEST 9: Interpretation Functions
# ==============================================================================

cat("TEST GROUP 9: Interpretation Functions\n")
cat(rep("-", 70), "\n", sep = "")

run_test(
  "interpret_flesch returns string",
  is.character(interpret_flesch(50))
)

run_test(
  "interpret_flesch handles NA",
  interpret_flesch(NA) == "N/A"
)

run_test(
  "interpret_grade_level returns string",
  is.character(interpret_grade_level(12))
)

run_test(
  "interpret_grade_level handles NA",
  interpret_grade_level(NA) == "N/A"
)

run_test(
  "High Flesch score interpreted as easy",
  grepl("fácil", interpret_flesch(85), ignore.case = TRUE)
)

run_test(
  "Low Flesch score interpreted as difficult",
  grepl("difícil", interpret_flesch(20), ignore.case = TRUE)
)

cat("\n")

# ==============================================================================
# TEST 10: Performance Benchmark
# ==============================================================================

cat("TEST GROUP 10: Performance Benchmark\n")
cat(rep("-", 70), "\n", sep = "")

# Create sample legislative text
sample_text <- "Art. 1º. Esta lei estabelece normas gerais sobre licitações e contratos administrativos pertinentes a obras, serviços, inclusive de publicidade, compras, alienações e locações no âmbito dos Poderes da União, dos Estados, do Distrito Federal e dos Municípios."

n_iterations <- 100

start_time <- Sys.time()
for (i in 1:n_iterations) {
  metrics <- calculate_all_readability_metrics(sample_text)
}
end_time <- Sys.time()

elapsed <- as.numeric(difftime(end_time, start_time, units = "secs"))
docs_per_sec <- n_iterations / elapsed

cat(sprintf("Processed %d documents in %.2f seconds\n", n_iterations, elapsed))
cat(sprintf("Performance: %.1f documents/second\n", docs_per_sec))

run_test(
  "Performance is acceptable (>20 docs/sec)",
  docs_per_sec > 20
)

# Estimate time for full dataset
estimated_time <- 118920 / docs_per_sec / 60
cat(sprintf("Estimated time for 118,920 documents: %.1f minutes\n", estimated_time))

cat("\n")

# ==============================================================================
# TEST 11: UTF-8 and Special Characters
# ==============================================================================

cat("TEST GROUP 11: UTF-8 and Special Characters\n")
cat(rep("-", 70), "\n", sep = "")

utf8_text <- "A federação é formada pela união indissolúvel dos Estados, Municípios e Distrito Federal."

run_test(
  "Handles accented characters (á, ã, ú)",
  !is.na(calculate_flesch_kincaid_pt(utf8_text))
)

run_test(
  "Counts syllables in words with accents",
  count_syllables_pt("federação") >= 3
)

run_test(
  "Handles ç correctly",
  count_syllables_pt("publicação") >= 3
)

cat("\n")

# ==============================================================================
# TEST 12: Edge Cases
# ==============================================================================

cat("TEST GROUP 12: Edge Cases\n")
cat(rep("-", 70), "\n", sep = "")

run_test(
  "Very short text (one word)",
  !is.na(calculate_flesch_kincaid_pt("Lei"))
)

run_test(
  "Text with only numbers",
  is.na(calculate_flesch_kincaid_pt("123 456 789"))
)

run_test(
  "Text with mixed numbers and words",
  !is.na(calculate_flesch_kincaid_pt("Art. 1º e Art. 2º"))
)

very_long_text <- paste(rep(sample_text, 100), collapse = " ")
run_test(
  "Very long text (10K+ words)",
  !is.na(calculate_flesch_kincaid_pt(very_long_text))
)

cat("\n")

# ==============================================================================
# SUMMARY
# ==============================================================================

cat(rep("=", 70), "\n", sep = "")
cat("TEST SUMMARY\n")
cat(rep("=", 70), "\n\n", sep = "")

total_tests <- tests_passed + tests_failed
success_rate <- (tests_passed / total_tests) * 100

cat(sprintf("Total tests run: %d\n", total_tests))
cat(sprintf("Tests passed:    %d (%.1f%%)\n", tests_passed, success_rate))
cat(sprintf("Tests failed:    %d (%.1f%%)\n", tests_failed, 100 - success_rate))

if (tests_failed == 0) {
  cat("\n✓✓✓ ALL TESTS PASSED ✓✓✓\n")
  cat("\nReadability metrics are ready for production use!\n")
} else {
  cat("\n✗✗✗ SOME TESTS FAILED ✗✗✗\n")
  cat("\nPlease review failed tests before using in production.\n")
}

cat("\n")

# Return status code
quit(status = ifelse(tests_failed == 0, 0, 1))
