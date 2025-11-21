# ==============================================================================
# READABILITY CALCULATION BATCH PROCESSOR
# ==============================================================================
# Calculates readability metrics for legislative documents in batches
# Designed to work with Migration 011 schema
#
# Dependencies: quanteda, DBI, RPostgres, stringi, logger
# Usage: Rscript calculate_readability_batch.R [--batch-size 100] [--limit 1000]
# ==============================================================================

library(quanteda)
library(DBI)
library(RPostgres)
library(stringi)
library(logger)
library(optparse)

# ==============================================================================
# CONFIGURATION
# ==============================================================================

# Parse command line arguments
option_list <- list(
  make_option(c("-b", "--batch-size"), type = "integer", default = 100,
              help = "Number of documents to process per batch [default %default]"),
  make_option(c("-l", "--limit"), type = "integer", default = NULL,
              help = "Maximum total documents to process [default: no limit]"),
  make_option(c("-p", "--priority-only"), action = "store_true", default = FALSE,
              help = "Only process high-priority documents (recent, long texts)"),
  make_option(c("-v", "--verbose"), action = "store_true", default = FALSE,
              help = "Enable verbose logging")
)

opt <- parse_args(OptionParser(option_list = option_list))

# Configure logging
if (opt$verbose) {
  log_threshold(DEBUG)
} else {
  log_threshold(INFO)
}

log_info("Starting readability batch processor")
log_info("Batch size: {opt$batch_size}")
if (!is.null(opt$limit)) log_info("Processing limit: {opt$limit} documents")

# ==============================================================================
# DATABASE CONNECTION
# ==============================================================================

connect_db <- function() {
  log_debug("Establishing database connection...")

  # Get credentials from environment or use defaults
  password <- Sys.getenv("DB_PASSWORD", "")
  if (password == "") {
    stop("DB_PASSWORD environment variable required. Set in .Renviron or system env.")
  }

  con <- dbConnect(
    RPostgres::Postgres(),
    host = Sys.getenv("DB_HOST", "localhost"),
    port = as.integer(Sys.getenv("DB_PORT", "5432")),
    dbname = Sys.getenv("DB_NAME", "monitor_legislativo"),
    user = Sys.getenv("DB_USER", "monitor_user"),
    password = password
  )

  log_info("Database connection established")
  return(con)
}

# ==============================================================================
# READABILITY CALCULATION FUNCTIONS
# ==============================================================================

#' Calculate readability metrics for Brazilian Portuguese text
#'
#' @param text Character string containing document text
#' @return Named list with readability metrics
calculate_readability <- function(text) {
  if (is.null(text) || nchar(text) == 0) {
    log_warn("Empty text provided")
    return(NULL)
  }

  tryCatch({
    # Clean text: remove excess whitespace
    text_clean <- stri_trim_both(text)
    text_clean <- stri_replace_all_regex(text_clean, "\\s+", " ")

    # Create corpus and tokens
    corp <- corpus(text_clean)
    toks <- tokens(corp, remove_punct = FALSE, remove_symbols = FALSE)

    # Calculate basic statistics
    sentences <- tokens(corp, what = "sentence", remove_punct = FALSE)
    n_sentences <- length(unlist(sentences))

    words <- tokens(corp, what = "word", remove_punct = TRUE, remove_symbols = TRUE)
    n_words <- length(unlist(words))

    # Calculate syllables (approximation for Portuguese)
    # Portuguese vowels: a, e, i, o, u, á, é, í, ó, ú, â, ê, ô, ã, õ
    syllable_count <- function(word) {
      word_lower <- tolower(word)
      # Count vowels and vowel groups
      vowels <- stri_count_regex(word_lower, "[aeiouáéíóúâêôãõ]+")
      max(1, vowels)  # At least 1 syllable per word
    }

    word_list <- unlist(words)
    n_syllables <- sum(sapply(word_list, syllable_count))
    n_complex_words <- sum(sapply(word_list, syllable_count) >= 3)

    # Calculate averages
    avg_sentence_length <- ifelse(n_sentences > 0, n_words / n_sentences, 0)
    avg_word_length <- ifelse(n_words > 0,
                              mean(nchar(word_list), na.rm = TRUE), 0)
    avg_syllables_per_word <- ifelse(n_words > 0, n_syllables / n_words, 0)

    # Calculate Flesch Reading Ease (adapted for Portuguese)
    # Portuguese formula: 248.835 - 1.015 * (words/sentences) - 84.6 * (syllables/words)
    flesch_score <- 248.835 -
                    (1.015 * avg_sentence_length) -
                    (84.6 * avg_syllables_per_word)
    flesch_score <- round(pmax(0, pmin(100, flesch_score)), 2)

    # Calculate Gunning Fog Index
    # Formula: 0.4 * ((words/sentences) + 100 * (complex_words/words))
    pct_complex <- ifelse(n_words > 0, n_complex_words / n_words, 0)
    fog_index <- 0.4 * (avg_sentence_length + 100 * pct_complex)
    fog_index <- round(pmax(6, pmin(20, fog_index)), 2)

    # Calculate SMOG Index
    # Formula: 1.0430 * sqrt(complex_words * (30 / sentences)) + 3.1291
    if (n_sentences >= 30) {
      smog_index <- 1.0430 * sqrt(n_complex_words * (30 / n_sentences)) + 3.1291
    } else {
      # Approximation for shorter texts
      smog_index <- 1.0430 * sqrt(n_complex_words + 1) + 3.1291
    }
    smog_index <- round(pmax(6, pmin(20, smog_index)), 2)

    log_debug("Calculated metrics: Flesch={flesch_score}, Fog={fog_index}, SMOG={smog_index}")

    return(list(
      flesch_kincaid_score = flesch_score,
      fog_index = fog_index,
      smog_index = smog_index,
      avg_sentence_length = round(avg_sentence_length, 2),
      avg_word_length = round(avg_word_length, 2),
      n_words = n_words,
      n_sentences = n_sentences,
      n_syllables = n_syllables
    ))

  }, error = function(e) {
    log_error("Error calculating readability: {e$message}")
    return(NULL)
  })
}

# ==============================================================================
# BATCH PROCESSING FUNCTIONS
# ==============================================================================

#' Fetch next batch of documents to analyze
#'
#' @param con Database connection
#' @param batch_size Number of documents to fetch
#' @param priority_only Only fetch high-priority documents
#' @return Data frame with document IDs and texts
fetch_batch <- function(con, batch_size, priority_only = FALSE) {
  priority_filter <- if (priority_only) {
    "AND priority_score >= 50"
  } else {
    ""
  }

  query <- sprintf("
    SELECT id, texto_completo, urn, tipo_documento, nivel
    FROM readability_analysis_queue
    WHERE analysis_status = 'never_analyzed'
    %s
    ORDER BY priority_score DESC, ano DESC, id
    LIMIT %d
  ", priority_filter, batch_size)

  log_debug("Fetching batch with query: {query}")
  docs <- dbGetQuery(con, query)

  log_info("Fetched {nrow(docs)} documents for processing")
  return(docs)
}

#' Update readability scores in database
#'
#' @param con Database connection
#' @param doc_id Document ID
#' @param metrics List of readability metrics
#' @return Boolean success status
update_scores <- function(con, doc_id, metrics) {
  if (is.null(metrics)) {
    log_warn("Skipping update for document {doc_id} due to NULL metrics")
    return(FALSE)
  }

  tryCatch({
    query <- "
      UPDATE documents
      SET flesch_kincaid_score = $1,
          fog_index = $2,
          smog_index = $3,
          avg_sentence_length = $4,
          avg_word_length = $5
      WHERE id = $6
    "

    dbExecute(con, query, params = list(
      metrics$flesch_kincaid_score,
      metrics$fog_index,
      metrics$smog_index,
      metrics$avg_sentence_length,
      metrics$avg_word_length,
      doc_id
    ))

    log_debug("Updated document {doc_id} successfully")
    return(TRUE)

  }, error = function(e) {
    log_error("Error updating document {doc_id}: {e$message}")
    return(FALSE)
  })
}

#' Process a batch of documents
#'
#' @param con Database connection
#' @param docs Data frame of documents to process
#' @return Named list with success/failure counts
process_batch <- function(con, docs) {
  if (nrow(docs) == 0) {
    log_info("No documents to process")
    return(list(success = 0, failed = 0, skipped = 0))
  }

  success_count <- 0
  failed_count <- 0
  skipped_count <- 0

  log_info("Processing batch of {nrow(docs)} documents...")

  pb <- txtProgressBar(min = 0, max = nrow(docs), style = 3)

  for (i in 1:nrow(docs)) {
    doc <- docs[i, ]

    # Skip if no text
    if (is.na(doc$texto_completo) || nchar(doc$texto_completo) < 50) {
      log_debug("Skipping document {doc$id} (insufficient text)")
      skipped_count <- skipped_count + 1
      setTxtProgressBar(pb, i)
      next
    }

    # Calculate readability
    metrics <- calculate_readability(doc$texto_completo)

    # Update database
    if (!is.null(metrics) && update_scores(con, doc$id, metrics)) {
      success_count <- success_count + 1
    } else {
      failed_count <- failed_count + 1
    }

    setTxtProgressBar(pb, i)

    # Small delay to avoid overwhelming database
    if (i %% 50 == 0) {
      Sys.sleep(0.1)
    }
  }

  close(pb)

  log_info("Batch complete: {success_count} success, {failed_count} failed, {skipped_count} skipped")

  return(list(
    success = success_count,
    failed = failed_count,
    skipped = skipped_count
  ))
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

main <- function() {
  log_info("===========================================")
  log_info("READABILITY BATCH PROCESSOR")
  log_info("===========================================")

  # Connect to database
  con <- connect_db()
  on.exit(dbDisconnect(con), add = TRUE)

  # Get total documents to process
  total_query <- "
    SELECT COUNT(*) as total
    FROM readability_analysis_queue
    WHERE analysis_status = 'never_analyzed'
  "
  total_docs <- dbGetQuery(con, total_query)$total
  log_info("Total documents in queue: {total_docs}")

  # Determine actual processing limit
  docs_to_process <- if (!is.null(opt$limit)) {
    min(opt$limit, total_docs)
  } else {
    total_docs
  }

  if (docs_to_process == 0) {
    log_info("No documents to process. Exiting.")
    return(invisible(NULL))
  }

  log_info("Will process up to {docs_to_process} documents")

  # Process in batches
  total_success <- 0
  total_failed <- 0
  total_skipped <- 0
  processed <- 0
  batch_num <- 1

  start_time <- Sys.time()

  while (processed < docs_to_process) {
    log_info("")
    log_info("--- BATCH {batch_num} ---")

    # Fetch next batch
    remaining <- docs_to_process - processed
    current_batch_size <- min(opt$batch_size, remaining)

    docs <- fetch_batch(con, current_batch_size, opt$priority_only)

    if (nrow(docs) == 0) {
      log_info("No more documents available. Stopping.")
      break
    }

    # Process batch
    results <- process_batch(con, docs)

    # Update totals
    total_success <- total_success + results$success
    total_failed <- total_failed + results$failed
    total_skipped <- total_skipped + results$skipped
    processed <- processed + nrow(docs)
    batch_num <- batch_num + 1

    # Log progress
    pct_complete <- round(100 * processed / docs_to_process, 1)
    log_info("Overall progress: {processed}/{docs_to_process} ({pct_complete}%)")
  }

  end_time <- Sys.time()
  duration <- as.numeric(difftime(end_time, start_time, units = "secs"))

  # Final summary
  log_info("")
  log_info("===========================================")
  log_info("PROCESSING COMPLETE")
  log_info("===========================================")
  log_info("Total processed: {processed} documents")
  log_info("  Success: {total_success}")
  log_info("  Failed: {total_failed}")
  log_info("  Skipped: {total_skipped}")
  log_info("Duration: {round(duration, 1)} seconds")
  log_info("Rate: {round(processed / duration, 2)} docs/second")

  # Query final statistics
  stats_query <- "
    SELECT
      COUNT(*) as total_with_scores,
      ROUND(AVG(flesch_kincaid_score)::numeric, 2) as avg_flesch,
      ROUND(AVG(fog_index)::numeric, 2) as avg_fog,
      ROUND(AVG(smog_index)::numeric, 2) as avg_smog
    FROM documents
    WHERE flesch_kincaid_score IS NOT NULL
  "
  stats <- dbGetQuery(con, stats_query)

  log_info("")
  log_info("DATABASE STATISTICS:")
  log_info("  Documents with scores: {stats$total_with_scores}")
  log_info("  Average Flesch score: {stats$avg_flesch}")
  log_info("  Average Fog Index: {stats$avg_fog}")
  log_info("  Average SMOG Index: {stats$avg_smog}")
  log_info("===========================================")

  return(invisible(list(
    processed = processed,
    success = total_success,
    failed = total_failed,
    skipped = total_skipped,
    duration = duration
  )))
}

# Execute main function
if (!interactive()) {
  tryCatch({
    main()
  }, error = function(e) {
    log_error("Fatal error: {e$message}")
    quit(status = 1)
  })
}
