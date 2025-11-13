#' Test Suite for Text Reuse Detection System
#'
#' Comprehensive tests and examples for LSH-based text reuse detection
#'
#' @author Monitor Legislativo Analytics Team
#' @date 2025-01-13

library(testthat)
library(DBI)
library(RPostgreSQL)

# Source the implementation
source("R/analytics/text_reuse_lsh.R")

# ============================================================================
# UNIT TESTS
# ============================================================================

test_that("Shingling creates correct k-grams", {
  text <- "this is a simple test document"

  # 3-grams
  shingles3 <- create_shingles(text, k = 3)
  expect_equal(length(shingles3), 4)  # 6 words -> 4 unique 3-grams
  expect_true("this is a" %in% shingles3)
  expect_true("is a simple" %in% shingles3)

  # 5-grams (default)
  shingles5 <- create_shingles(text, k = 5)
  expect_equal(length(shingles5), 2)  # 6 words -> 2 5-grams

  # Empty text
  empty_shingles <- create_shingles("", k = 5)
  expect_equal(length(empty_shingles), 0)

  # Text shorter than k
  short_shingles <- create_shingles("too short", k = 5)
  expect_equal(length(short_shingles), 1)
})

test_that("MinHash signatures are consistent", {
  text <- "this is a test document for minhash testing"
  shingles <- create_shingles(text, k = 5)

  # Same text should produce same signature
  sig1 <- minhash_signature(shingles, num_hashes = 100, seed = 42)
  sig2 <- minhash_signature(shingles, num_hashes = 100, seed = 42)

  expect_equal(sig1, sig2)
  expect_equal(length(sig1), 100)

  # Different seed should produce different signature
  sig3 <- minhash_signature(shingles, num_hashes = 100, seed = 99)
  expect_false(all(sig1 == sig3))
})

test_that("Jaccard estimation works correctly", {
  # Identical sets
  sig1 <- c(1, 2, 3, 4, 5)
  sig2 <- c(1, 2, 3, 4, 5)
  expect_equal(estimate_jaccard(sig1, sig2), 1.0)

  # Completely different sets
  sig3 <- c(6, 7, 8, 9, 10)
  expect_equal(estimate_jaccard(sig1, sig3), 0.0)

  # Partially similar
  sig4 <- c(1, 2, 3, 8, 9)  # 3/5 match
  expect_equal(estimate_jaccard(sig1, sig4), 0.6)

  # Different length should error
  sig5 <- c(1, 2, 3)
  expect_error(estimate_jaccard(sig1, sig5))
})

test_that("Similar documents have high Jaccard similarity", {
  # Very similar documents
  text1 <- "Lei que estabelece normas para proteção ambiental e desenvolvimento sustentável"
  text2 <- "Lei que estabelece normas para proteção ambiental e desenvolvimento econômico"

  shingles1 <- create_shingles(text1, k = 3)
  shingles2 <- create_shingles(text2, k = 3)

  sig1 <- minhash_signature(shingles1, num_hashes = 100)
  sig2 <- minhash_signature(shingles2, num_hashes = 100)

  similarity <- estimate_jaccard(sig1, sig2)

  # Should be fairly similar (many shared 3-grams)
  expect_gt(similarity, 0.5)

  # Completely different documents
  text3 <- "Regulamento sobre trânsito e segurança viária"
  shingles3 <- create_shingles(text3, k = 3)
  sig3 <- minhash_signature(shingles3, num_hashes = 100)

  dissimilarity <- estimate_jaccard(sig1, sig3)
  expect_lt(dissimilarity, 0.3)  # Should be quite different
})

# ============================================================================
# INTEGRATION TESTS (require database connection)
# ============================================================================

# Skip if no database connection available
skip_if_no_db <- function() {
  tryCatch({
    con <- dbConnect(PostgreSQL(), host = "localhost", dbname = "monitor_legislativo_test")
    dbDisconnect(con)
  }, error = function(e) {
    skip("Database not available")
  })
}

test_that("Database tables exist", {
  skip_if_no_db()

  con <- dbConnect(PostgreSQL(), host = "localhost", dbname = "monitor_legislativo_test")
  on.exit(dbDisconnect(con))

  tables <- dbGetQuery(con,
    "SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_name LIKE 'text_reuse%'"
  )$table_name

  expect_true("text_reuse_signatures" %in% tables)
  expect_true("lsh_buckets" %in% tables)
  expect_true("text_reuse_pairs" %in% tables)
})

# ============================================================================
# EXAMPLE WORKFLOWS
# ============================================================================

cat("\n=== Text Reuse Detection Examples ===\n\n")

# Example 1: Basic similarity detection
cat("Example 1: Basic Similarity Detection\n")
cat("--------------------------------------\n")

text_a <- "O município estabelece normas para a proteção do meio ambiente e o desenvolvimento sustentável,
           visando garantir a qualidade de vida das presentes e futuras gerações, mediante a utilização
           racional dos recursos naturais disponíveis."

text_b <- "O município estabelece normas para a proteção do meio ambiente e o desenvolvimento econômico,
           visando garantir a qualidade de vida das presentes e futuras gerações, mediante o uso
           adequado dos recursos naturais disponíveis."

text_c <- "A empresa deve cumprir todas as obrigações fiscais e tributárias previstas na legislação
           vigente, sob pena de aplicação das sanções cabíveis."

shingles_a <- create_shingles(text_a, k = 5)
shingles_b <- create_shingles(text_b, k = 5)
shingles_c <- create_shingles(text_c, k = 5)

cat(sprintf("Document A: %d unique 5-grams\n", length(shingles_a)))
cat(sprintf("Document B: %d unique 5-grams\n", length(shingles_b)))
cat(sprintf("Document C: %d unique 5-grams\n", length(shingles_c)))

sig_a <- minhash_signature(shingles_a, num_hashes = 100)
sig_b <- minhash_signature(shingles_b, num_hashes = 100)
sig_c <- minhash_signature(shingles_c, num_hashes = 100)

sim_ab <- estimate_jaccard(sig_a, sig_b)
sim_ac <- estimate_jaccard(sig_a, sig_c)
sim_bc <- estimate_jaccard(sig_b, sig_c)

cat(sprintf("\nSimilarity A-B: %.3f (%.1f%% similar)\n", sim_ab, sim_ab * 100))
cat(sprintf("Similarity A-C: %.3f (%.1f%% similar)\n", sim_ac, sim_ac * 100))
cat(sprintf("Similarity B-C: %.3f (%.1f%% similar)\n", sim_bc, sim_bc * 100))

cat("\nInterpretation: Documents A and B are highly similar (likely text reuse),\n")
cat("while document C is unrelated.\n")

# Example 2: LSH probability demonstration
cat("\n\nExample 2: LSH Detection Probability\n")
cat("-------------------------------------\n")

lsh_probability <- function(similarity, bands = 20, rows = 5) {
  # Probability of being detected as candidate pair
  1 - (1 - similarity^rows)^bands
}

similarities <- seq(0.5, 1.0, by = 0.05)
probabilities <- sapply(similarities, lsh_probability)

cat("\nSimilarity | Detection Probability (b=20, r=5)\n")
cat("-----------|-----------------------------------\n")
for (i in 1:length(similarities)) {
  cat(sprintf("   %.2f    |            %.3f (%.1f%%)\n",
              similarities[i], probabilities[i], probabilities[i] * 100))
}

cat("\nInterpretation: LSH parameters are tuned for ~70% similarity threshold.\n")
cat("Pairs with 70% similarity have ~99% chance of being detected.\n")

# Example 3: Boilerplate detection simulation
cat("\n\nExample 3: Boilerplate Detection Simulation\n")
cat("--------------------------------------------\n")

# Simulate a set of documents with common boilerplate
boilerplate <- "Este documento foi elaborado em conformidade com a Lei Federal nº 12.345/2020
                e demais normas aplicáveis, visando estabelecer diretrizes para"

doc1 <- paste(boilerplate, "a gestão de resíduos sólidos no município")
doc2 <- paste(boilerplate, "o tratamento de efluentes industriais")
doc3 <- paste(boilerplate, "a proteção de mananciais hídricos")
doc4 <- "Regulamento completamente diferente sobre controle de trânsito urbano"

docs <- list(doc1, doc2, doc3, doc4)
signatures <- lapply(docs, function(d) {
  minhash_signature(create_shingles(d, k = 5), num_hashes = 100)
})

cat("Similarity matrix:\n")
cat("     Doc1  Doc2  Doc3  Doc4\n")
for (i in 1:4) {
  cat(sprintf("Doc%d ", i))
  for (j in 1:4) {
    if (i == j) {
      cat(" 1.00 ")
    } else {
      sim <- estimate_jaccard(signatures[[i]], signatures[[j]])
      cat(sprintf(" %.2f ", sim))
    }
  }
  cat("\n")
}

cat("\nInterpretation: Docs 1-3 share high similarity due to boilerplate text.\n")
cat("They would be identified as a text reuse cluster.\n")

# Example 4: Performance estimation
cat("\n\nExample 4: Performance Estimation\n")
cat("----------------------------------\n")

n_docs <- 118920
docs_per_second <- 33
indexing_time_minutes <- n_docs / docs_per_second / 60

signature_size_bytes <- 100 * 4  # 100 integers × 4 bytes
total_signature_mb <- n_docs * signature_size_bytes / 1024 / 1024

buckets_per_doc <- 20  # One per band
bucket_overhead_bytes <- 50  # Hash + doc_id + metadata
total_bucket_mb <- n_docs * buckets_per_doc * bucket_overhead_bytes / 1024 / 1024

cat(sprintf("Number of documents: %s\n", format(n_docs, big.mark = ",")))
cat(sprintf("Processing rate: %d docs/second\n", docs_per_second))
cat(sprintf("Estimated indexing time: %.1f minutes (%.1f hours)\n",
            indexing_time_minutes, indexing_time_minutes / 60))
cat(sprintf("\nStorage requirements:\n"))
cat(sprintf("  Signatures: %.1f MB\n", total_signature_mb))
cat(sprintf("  LSH buckets: %.1f MB\n", total_bucket_mb))
cat(sprintf("  Total: %.1f MB (%.1f GB)\n",
            total_signature_mb + total_bucket_mb,
            (total_signature_mb + total_bucket_mb) / 1024))

# Assume 5% of document pairs are similar
avg_similarity_pairs <- n_docs * 0.05
pairs_table_bytes <- 20  # doc1_id + doc2_id + similarity + metadata
pairs_mb <- avg_similarity_pairs * pairs_table_bytes / 1024 / 1024

cat(sprintf("\nWith ~%s similar pairs:\n",
            format(round(avg_similarity_pairs), big.mark = ",")))
cat(sprintf("  Pairs table: %.1f MB\n", pairs_mb))
cat(sprintf("  Grand total: %.1f MB\n",
            total_signature_mb + total_bucket_mb + pairs_mb))

cat("\nInterpretation: System can handle 118k+ documents with <500MB storage.\n")

# Example 5: Cross-jurisdiction analysis simulation
cat("\n\nExample 5: Cross-Jurisdiction Analysis\n")
cat("---------------------------------------\n")

# Simulate some cross-jurisdiction patterns
federal_text <- "Estabelece diretrizes nacionais para o saneamento básico e a política de
                 recursos hídricos, em consonância com os princípios constitucionais"

sp_text <- paste(federal_text, "aplicadas ao estado de São Paulo")
rj_text <- paste(federal_text, "aplicadas ao estado do Rio de Janeiro")
mg_text <- paste(federal_text, "aplicadas ao estado de Minas Gerais")

fed_sig <- minhash_signature(create_shingles(federal_text, k = 5), num_hashes = 100)
sp_sig <- minhash_signature(create_shingles(sp_text, k = 5), num_hashes = 100)
rj_sig <- minhash_signature(create_shingles(rj_text, k = 5), num_hashes = 100)
mg_sig <- minhash_signature(create_shingles(mg_text, k = 5), num_hashes = 100)

cat("Federal legislation adopted by states:\n\n")
cat(sprintf("Federal → SP: %.1f%% similarity\n", estimate_jaccard(fed_sig, sp_sig) * 100))
cat(sprintf("Federal → RJ: %.1f%% similarity\n", estimate_jaccard(fed_sig, rj_sig) * 100))
cat(sprintf("Federal → MG: %.1f%% similarity\n", estimate_jaccard(fed_sig, mg_sig) * 100))

cat("\nState-to-state similarity:\n\n")
cat(sprintf("SP ↔ RJ: %.1f%% similarity\n", estimate_jaccard(sp_sig, rj_sig) * 100))
cat(sprintf("SP ↔ MG: %.1f%% similarity\n", estimate_jaccard(sp_sig, mg_sig) * 100))
cat(sprintf("RJ ↔ MG: %.1f%% similarity\n", estimate_jaccard(rj_sig, mg_sig) * 100))

cat("\nInterpretation: This pattern indicates federal legislation being\n")
cat("adopted with minor modifications by multiple states - a common\n")
cat("legislative influence pattern.\n")

# ============================================================================
# STRESS TEST
# ============================================================================

cat("\n\nStress Test: Large-Scale Similarity Detection\n")
cat("==============================================\n")

stress_test <- function(n_docs = 1000, n_queries = 100) {
  cat(sprintf("Generating %d synthetic documents...\n", n_docs))

  # Generate synthetic documents with some overlapping content
  base_texts <- c(
    "Lei sobre proteção ambiental e desenvolvimento sustentável",
    "Normas para educação pública e formação de professores",
    "Regulamento de trânsito e segurança viária",
    "Código de obras e edificações urbanas",
    "Estatuto dos servidores públicos municipais"
  )

  # Create variations
  docs <- list()
  for (i in 1:n_docs) {
    base <- sample(base_texts, 1)
    variation <- paste(base, "artigo", i, "parágrafo único aplicado ao município")
    docs[[i]] <- variation
  }

  # Generate signatures
  cat("Creating MinHash signatures...\n")
  start_time <- Sys.time()

  signatures <- lapply(docs, function(d) {
    shingles <- create_shingles(d, k = 5)
    minhash_signature(shingles, num_hashes = 100)
  })

  indexing_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

  cat(sprintf("Indexing complete: %.2f seconds (%.1f docs/sec)\n",
              indexing_time, n_docs / indexing_time))

  # Simulate LSH bucketing
  cat("Creating LSH buckets...\n")
  bands <- 20
  rows_per_band <- 5

  buckets <- list()
  for (band in 1:bands) {
    buckets[[band]] <- list()
    for (i in 1:n_docs) {
      start_idx <- (band - 1) * rows_per_band + 1
      end_idx <- band * rows_per_band
      band_sig <- signatures[[i]][start_idx:end_idx]
      bucket_hash <- digest::digest(paste(band_sig, collapse = "_"))

      if (is.null(buckets[[band]][[bucket_hash]])) {
        buckets[[band]][[bucket_hash]] <- c()
      }
      buckets[[band]][[bucket_hash]] <- c(buckets[[band]][[bucket_hash]], i)
    }
  }

  # Bucket statistics
  bucket_sizes <- unlist(lapply(buckets, function(band) {
    sapply(band, length)
  }))

  cat(sprintf("LSH Statistics:\n"))
  cat(sprintf("  Total buckets: %d\n", length(bucket_sizes)))
  cat(sprintf("  Avg bucket size: %.1f docs\n", mean(bucket_sizes)))
  cat(sprintf("  Max bucket size: %d docs\n", max(bucket_sizes)))
  cat(sprintf("  Buckets with 1 doc: %d\n", sum(bucket_sizes == 1)))
  cat(sprintf("  Buckets with 2+ docs: %d\n", sum(bucket_sizes >= 2)))

  # Simulate queries
  cat(sprintf("\nSimulating %d similarity queries...\n", n_queries))
  query_times <- numeric(n_queries)

  for (i in 1:n_queries) {
    query_doc <- sample(1:n_docs, 1)
    start_time <- Sys.time()

    # Get candidates from buckets
    candidates <- unique(unlist(lapply(1:bands, function(band) {
      start_idx <- (band - 1) * rows_per_band + 1
      end_idx <- band * rows_per_band
      band_sig <- signatures[[query_doc]][start_idx:end_idx]
      bucket_hash <- digest::digest(paste(band_sig, collapse = "_"))
      buckets[[band]][[bucket_hash]]
    })))

    # Compute actual similarities for candidates
    similarities <- sapply(candidates, function(cand) {
      if (cand == query_doc) return(1.0)
      estimate_jaccard(signatures[[query_doc]], signatures[[cand]])
    })

    # Filter by threshold
    similar_docs <- candidates[similarities >= 0.7]

    query_times[i] <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000  # ms
  }

  cat(sprintf("\nQuery Performance:\n"))
  cat(sprintf("  Mean: %.1f ms\n", mean(query_times)))
  cat(sprintf("  Median: %.1f ms\n", median(query_times)))
  cat(sprintf("  95th percentile: %.1f ms\n", quantile(query_times, 0.95)))
  cat(sprintf("  Max: %.1f ms\n", max(query_times)))

  if (median(query_times) < 500) {
    cat("\n✓ Performance target met (<500ms median query time)\n")
  } else {
    cat("\n⚠ Performance target missed (>500ms median query time)\n")
  }

  return(list(
    indexing_time = indexing_time,
    docs_per_second = n_docs / indexing_time,
    query_times = query_times,
    bucket_stats = list(
      total = length(bucket_sizes),
      avg_size = mean(bucket_sizes),
      max_size = max(bucket_sizes)
    )
  ))
}

# Run stress test
stress_results <- stress_test(n_docs = 1000, n_queries = 100)

cat("\n\n=== All Tests Complete ===\n")
cat("Run this script to verify the text reuse detection system.\n")
cat("For database integration tests, ensure PostgreSQL is running\n")
cat("and test database is configured.\n")
