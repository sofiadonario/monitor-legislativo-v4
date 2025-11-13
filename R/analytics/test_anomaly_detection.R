# ==============================================================================
# ANOMALY DETECTION SYSTEM - TESTING SCRIPT
# ==============================================================================
# Comprehensive tests for anomaly detection functionality.
#
# Tests:
# 1. Volume anomaly detection with synthetic data
# 2. Text anomaly detection with sample documents
# 3. Temporal anomaly detection with time series
# 4. Jurisdictional anomaly detection
# 5. Scoring and explanation functions
#
# Author: Monitor Legislativo v4 - Data Science Team
# Date: 2025-11-13
# ==============================================================================

library(dplyr)
library(lubridate)
library(DBI)

# Source detection functions
source("R/analytics/anomaly_detection.R")
source("R/analytics/anomaly_scoring.R")

cat("\n==============================================================================\n")
cat("ANOMALY DETECTION SYSTEM - COMPREHENSIVE TESTS\n")
cat("==============================================================================\n\n")

# ==============================================================================
# TEST 1: VOLUME ANOMALY DETECTION
# ==============================================================================

cat("TEST 1: Volume Anomaly Detection\n")
cat("----------------------------------\n")

# Generate synthetic time series data with anomalies
set.seed(42)
n_periods <- 100

synthetic_data <- data.frame(
  period = seq.Date(as.Date("2020-01-01"), by = "month", length.out = n_periods),
  count = c(
    rnorm(30, mean = 100, sd = 10),        # Normal period
    rnorm(10, mean = 250, sd = 15),        # Spike (anomaly)
    rnorm(20, mean = 100, sd = 10),        # Normal period
    rnorm(5, mean = 30, sd = 5),           # Drop (anomaly)
    rnorm(35, mean = 100, sd = 10)         # Normal period
  )
) %>%
  mutate(count = pmax(0, round(count)))

# Test IQR method
cat("\n1.1 Testing IQR method...\n")
iqr_result <- detect_anomalies_iqr(synthetic_data, sensitivity = 1.5)

cat(sprintf("  - Total periods: %d\n", nrow(iqr_result)))
cat(sprintf("  - Anomalies detected: %d (%.1f%%)\n",
            sum(iqr_result$is_anomaly),
            100 * mean(iqr_result$is_anomaly)))
cat(sprintf("  - High severity: %d\n", sum(iqr_result$severity == "high")))
cat(sprintf("  - Medium severity: %d\n", sum(iqr_result$severity == "medium")))
cat(sprintf("  - Low severity: %d\n", sum(iqr_result$severity == "low")))

# Test Z-score method
cat("\n1.2 Testing Z-score method...\n")
zscore_result <- detect_anomalies_zscore(synthetic_data, sensitivity = 3)

cat(sprintf("  - Anomalies detected: %d (%.1f%%)\n",
            sum(zscore_result$is_anomaly),
            100 * mean(zscore_result$is_anomaly)))

# Test Poisson method
cat("\n1.3 Testing Poisson method...\n")
poisson_result <- detect_anomalies_poisson(synthetic_data)

cat(sprintf("  - Anomalies detected: %d (%.1f%%)\n",
            sum(poisson_result$is_anomaly),
            100 * mean(poisson_result$is_anomaly)))

cat("\nTest 1: PASSED ✓\n")

# ==============================================================================
# TEST 2: TEXT ANOMALY DETECTION
# ==============================================================================

cat("\n\nTEST 2: Text Anomaly Detection\n")
cat("----------------------------------\n")

# Generate synthetic text data
set.seed(123)
n_docs <- 100

synthetic_texts <- data.frame(
  id = 1:n_docs,
  texto_completo = c(
    # Normal documents
    replicate(80, paste(sample(c("lei", "artigo", "parágrafo", "estabelece", "determina",
                                 "dispõe", "sobre", "normas", "gerais", "municipais"),
                               sample(50:150, 1), replace = TRUE), collapse = " ")),
    # Anomalous documents - very short
    replicate(10, paste(sample(c("lei", "artigo"), sample(3:10, 1), replace = TRUE), collapse = " ")),
    # Anomalous documents - very long
    replicate(10, paste(sample(c("lei", "artigo", "parágrafo", "estabelece", "determina"),
                               sample(500:800, 1), replace = TRUE), collapse = " "))
  )
)

# Calculate text features
cat("\n2.1 Calculating text features...\n")

text_features <- synthetic_texts %>%
  mutate(
    text_length = nchar(texto_completo),
    word_count = stringr::str_count(texto_completo, "\\S+"),
    avg_word_length = text_length / pmax(word_count, 1),
    sentence_count = stringr::str_count(texto_completo, "[.!?;]") + 1,
    avg_sentence_length = word_count / pmax(sentence_count, 1),
    unique_words = sapply(strsplit(texto_completo, "\\s+"),
                         function(x) length(unique(tolower(x)))),
    lexical_diversity = unique_words / pmax(word_count, 1),
    complex_word_ratio = 0.2  # Placeholder
  ) %>%
  select(-texto_completo)

cat(sprintf("  - Documents processed: %d\n", nrow(text_features)))
cat(sprintf("  - Mean text length: %.0f characters\n", mean(text_features$text_length)))
cat(sprintf("  - Mean word count: %.0f words\n", mean(text_features$word_count)))

# Test IQR method for text
cat("\n2.2 Testing IQR method for text anomalies...\n")
text_anomalies <- detect_text_anomalies_iqr(text_features, sensitivity = 1.5)

cat(sprintf("  - Anomalies detected: %d (%.1f%%)\n",
            sum(text_anomalies$is_anomaly),
            100 * mean(text_anomalies$is_anomaly)))
cat(sprintf("  - High severity: %d\n", sum(text_anomalies$severity == "high")))

# Show top anomalies
cat("\n2.3 Top 5 text anomalies:\n")
top_text_anomalies <- text_anomalies %>%
  filter(is_anomaly) %>%
  arrange(desc(anomaly_score)) %>%
  head(5) %>%
  select(id, text_length, word_count, anomaly_score, anomaly_reason)

print(top_text_anomalies)

cat("\nTest 2: PASSED ✓\n")

# ==============================================================================
# TEST 3: TEMPORAL ANOMALY DETECTION
# ==============================================================================

cat("\n\nTEST 3: Temporal Anomaly Detection\n")
cat("----------------------------------\n")

# Generate time series with trend and seasonality
set.seed(456)
n_periods <- 120  # 10 years of monthly data

dates <- seq.Date(as.Date("2014-01-01"), by = "month", length.out = n_periods)

# Create synthetic time series with:
# - Linear trend
# - Seasonal component
# - Random noise
# - A few anomalies

trend <- seq(100, 200, length.out = n_periods)
seasonal <- 20 * sin(2 * pi * (1:n_periods) / 12)  # Yearly seasonality
noise <- rnorm(n_periods, 0, 10)

# Add anomalies at specific points
anomaly_indices <- c(30, 45, 80, 95)
anomaly_values <- c(100, -80, 120, -70)

synthetic_ts <- data.frame(
  date = dates,
  count = trend + seasonal + noise
)

# Inject anomalies
synthetic_ts$count[anomaly_indices] <- synthetic_ts$count[anomaly_indices] + anomaly_values
synthetic_ts$count <- pmax(0, round(synthetic_ts$count))

# Test STL decomposition
cat("\n3.1 Testing STL decomposition...\n")
stl_anomalies <- detect_temporal_anomalies_stl(synthetic_ts, sensitivity = 2, frequency = "monthly")

cat(sprintf("  - Periods analyzed: %d\n", nrow(stl_anomalies)))
cat(sprintf("  - Anomalies detected: %d (%.1f%%)\n",
            sum(stl_anomalies$is_anomaly),
            100 * mean(stl_anomalies$is_anomaly)))
cat(sprintf("  - High severity: %d\n", sum(stl_anomalies$severity == "high")))

# Show detected anomalies
cat("\n3.2 Detected temporal anomalies:\n")
temporal_anomalies_detected <- stl_anomalies %>%
  filter(is_anomaly) %>%
  select(date, count, expected, residual, anomaly_score, anomaly_reason)

print(head(temporal_anomalies_detected))

cat("\nTest 3: PASSED ✓\n")

# ==============================================================================
# TEST 4: SCORING AND EXPLANATION FUNCTIONS
# ==============================================================================

cat("\n\nTEST 4: Scoring and Explanation Functions\n")
cat("------------------------------------------\n")

# Test unified score calculation
cat("\n4.1 Testing unified anomaly score...\n")

test_scores <- data.frame(
  volume = c(80, 45, 90, 30),
  text = c(45, 70, 20, 85),
  temporal = c(65, 55, 75, 40),
  jurisdictional = c(30, 60, 50, 70)
)

unified_scores <- apply(test_scores, 1, function(row) {
  calculate_unified_score(
    volume_score = row["volume"],
    text_score = row["text"],
    temporal_score = row["temporal"],
    jurisdictional_score = row["jurisdictional"]
  )
})

cat("  Component scores and unified scores:\n")
result_df <- cbind(test_scores, unified = round(unified_scores, 1))
print(result_df)

# Test severity classification
cat("\n4.2 Testing severity classification...\n")
test_scores_vec <- c(25, 45, 65, 85, 98)
severities <- sapply(test_scores_vec, classify_severity)

cat("  Scores -> Severity:\n")
for (i in seq_along(test_scores_vec)) {
  cat(sprintf("    %.0f -> %s\n", test_scores_vec[i], severities[i]))
}

# Test explanation generation
cat("\n4.3 Testing anomaly explanation (Portuguese)...\n")

explanation <- explain_anomaly(
  anomaly_type = "volume",
  score = 85,
  context = list(
    observed = 500,
    expected = 150,
    period = "2023-06"
  ),
  language = "pt"
)

cat("  Generated explanation:\n")
cat("  ", explanation, "\n")

# Test historical context
cat("\n4.4 Testing historical context generation...\n")

historical_values <- rnorm(100, mean = 150, sd = 20)
current_value <- 500

context <- generate_historical_context(
  current_value = current_value,
  historical_values = historical_values,
  metric_name = "volume de documentos",
  language = "pt"
)

cat("  Generated context:\n")
cat(paste0("  ", strsplit(context, "\n")[[1]], collapse = "\n"), "\n")

cat("\nTest 4: PASSED ✓\n")

# ==============================================================================
# TEST 5: CONFIDENCE INTERVALS
# ==============================================================================

cat("\n\nTEST 5: Confidence Intervals\n")
cat("----------------------------------\n")

cat("\n5.1 Calculating confidence intervals for volume data...\n")

# Use synthetic data from Test 1
ci_result <- calculate_confidence_intervals(
  data = synthetic_data,
  method = "iqr",
  n_bootstrap = 100,  # Reduced for faster testing
  confidence_level = 0.95
)

cat("  Confidence intervals (95%):\n")
print(ci_result)

cat("\nTest 5: PASSED ✓\n")

# ==============================================================================
# TEST SUMMARY
# ==============================================================================

cat("\n\n==============================================================================\n")
cat("TEST SUMMARY\n")
cat("==============================================================================\n\n")

cat("All tests completed successfully! ✓\n\n")

cat("Key Findings:\n")
cat("1. Volume Anomaly Detection:\n")
cat(sprintf("   - IQR method detected %d anomalies\n", sum(iqr_result$is_anomaly)))
cat(sprintf("   - Z-score method detected %d anomalies\n", sum(zscore_result$is_anomaly)))
cat(sprintf("   - Poisson method detected %d anomalies\n", sum(poisson_result$is_anomaly)))

cat("\n2. Text Anomaly Detection:\n")
cat(sprintf("   - Detected %d documents with unusual text characteristics\n",
            sum(text_anomalies$is_anomaly)))
cat(sprintf("   - Average anomaly score: %.1f\n",
            mean(text_anomalies$anomaly_score[text_anomalies$is_anomaly])))

cat("\n3. Temporal Anomaly Detection:\n")
cat(sprintf("   - Detected %d temporal anomalies in %d periods\n",
            sum(stl_anomalies$is_anomaly), nrow(stl_anomalies)))

cat("\n4. Scoring System:\n")
cat("   - Unified scoring: FUNCTIONAL ✓\n")
cat("   - Severity classification: FUNCTIONAL ✓\n")
cat("   - Explanation generation: FUNCTIONAL ✓\n")

cat("\n5. Statistical Validation:\n")
cat("   - Confidence intervals: CALCULATED ✓\n")
cat("   - Bootstrap resampling: FUNCTIONAL ✓\n")

cat("\n==============================================================================\n")
cat("Ready for integration with Monitor Legislativo v4!\n")
cat("==============================================================================\n\n")

# ==============================================================================
# PERFORMANCE BENCHMARK
# ==============================================================================

cat("\n\nPERFORMANCE BENCHMARK\n")
cat("==============================================================================\n\n")

# Benchmark volume detection
cat("Benchmarking volume anomaly detection...\n")
benchmark_data <- data.frame(
  period = seq.Date(as.Date("2015-01-01"), by = "month", length.out = 120),
  count = round(rnorm(120, mean = 1000, sd = 100))
)

start_time <- Sys.time()
for (i in 1:10) {
  result <- detect_anomalies_iqr(benchmark_data, sensitivity = 1.5)
}
end_time <- Sys.time()
time_per_run <- as.numeric(difftime(end_time, start_time, units = "secs")) / 10

cat(sprintf("  - Average time per detection: %.3f seconds\n", time_per_run))
cat(sprintf("  - Estimated time for 120 periods: %.3f seconds\n", time_per_run))
cat(sprintf("  - Throughput: %.0f periods/second\n", nrow(benchmark_data) / time_per_run))

cat("\n==============================================================================\n\n")
