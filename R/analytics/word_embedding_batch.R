#!/usr/bin/env Rscript
# =============================================================================
# Sprint 3: Word Embedding Batch Job
# =============================================================================
# Description: Batch job to train Word2Vec/GloVe models and generate document
#              embeddings for all 134k documents in the legislative corpus
# Usage: Rscript R/analytics/word_embedding_batch.R --mode=train --type=word2vec
# =============================================================================

suppressPackageStartupMessages({
  library(optparse)
  library(RPostgreSQL)
  library(pool)
  library(logger)
  library(dplyr)
})

# Source word embedding functions
source("R/analytics/word_embeddings.R")

# =============================================================================
# Command Line Arguments
# =============================================================================

option_list <- list(
  make_option(c("-m", "--mode"), type = "character", default = "train",
              help = "Mode: 'train' to train models, 'generate' to create embeddings, 'all' for both [default %default]"),

  make_option(c("-t", "--type"), type = "character", default = "word2vec",
              help = "Embedding type: 'word2vec', 'glove', or 'both' [default %default]"),

  make_option(c("-d", "--dim"), type = "integer", default = 300,
              help = "Embedding dimensionality [default %default]"),

  make_option(c("-i", "--iter"), type = "integer", default = 20,
              help = "Training iterations [default %default]"),

  make_option(c("-s", "--sample"), type = "integer", default = NULL,
              help = "Sample size for testing (NULL = full corpus) [default %default]"),

  make_option(c("-b", "--batch-size"), type = "integer", default = 1000,
              help = "Batch size for embedding generation [default %default]"),

  make_option(c("--save-db"), type = "logical", default = TRUE,
              help = "Save embeddings to database [default %default]"),

  make_option(c("--save-disk"), type = "logical", default = TRUE,
              help = "Save models to disk [default %default]"),

  make_option(c("--model-dir"), type = "character", default = "models",
              help = "Directory to save models [default %default]")
)

opt_parser <- OptionParser(option_list = option_list)
opt <- parse_args(opt_parser)

# =============================================================================
# Setup Logging
# =============================================================================

log_threshold(INFO)
log_appender(appender_tee(tempfile()))
log_info("=== Sprint 3: Word Embedding Batch Job ===")
log_info("Mode: {opt$mode}")
log_info("Type: {opt$type}")
log_info("Dimensions: {opt$dim}")
log_info("Iterations: {opt$iter}")
if (!is.null(opt$sample)) {
  log_info("Sample size: {opt$sample}")
}

# =============================================================================
# Database Connection
# =============================================================================

log_info("Connecting to database...")

# Try Cloud SQL first (production), fall back to local if not available
db_host <- Sys.getenv("DB_HOST", "34.151.237.30")
db_name <- Sys.getenv("DB_NAME", "lexml_db")
db_user <- Sys.getenv("DB_USER", "mackmonitor")
db_pass <- Sys.getenv("DB_PASSWORD", "")
if (db_pass == "") {
  stop("DB_PASSWORD environment variable required. Set in .Renviron or system env.")
}
db_port <- as.integer(Sys.getenv("DB_PORT", "5432"))

log_info("Database: {db_host}:{db_port}/{db_name}")

tryCatch({
  db_pool <- dbPool(
    PostgreSQL(),
    host = db_host,
    dbname = db_name,
    user = db_user,
    password = db_pass,
    port = db_port,
    maxSize = 10
  )

  # Test connection
  test_query <- dbGetQuery(db_pool, "SELECT COUNT(*) AS count FROM documents")
  log_info("Database connection successful. Total documents: {test_query$count}")

}, error = function(e) {
  log_error("Database connection failed: {e$message}")
  quit(status = 1)
})

# =============================================================================
# Create Model Directory
# =============================================================================

if (opt$save_disk) {
  if (!dir.exists(opt$model_dir)) {
    log_info("Creating model directory: {opt$model_dir}")
    dir.create(opt$model_dir, recursive = TRUE)
  }
}

# =============================================================================
# PART 1: Train Models
# =============================================================================

word2vec_model <- NULL
glove_model <- NULL

if (opt$mode %in% c("train", "all")) {

  log_info("=== TRAINING PHASE ===")

  # Train Word2Vec
  if (opt$type %in% c("word2vec", "both")) {
    log_info("Starting Word2Vec training...")

    tryCatch({
      word2vec_model <- train_word2vec_model(
        db_connection = db_pool,
        dim = opt$dim,
        iter = opt$iter,
        sample_size = opt$sample
      )

      if (opt$save_disk) {
        model_path <- file.path(opt$model_dir, "lexml_word2vec.bin")
        save_word2vec_model(word2vec_model, model_path)
        log_info("Word2Vec model saved to {model_path}")
      }

      log_info("Word2Vec training complete!")

    }, error = function(e) {
      log_error("Word2Vec training failed: {e$message}")
      traceback()
    })
  }

  # Train GloVe
  if (opt$type %in% c("glove", "both")) {
    log_info("Starting GloVe training...")

    tryCatch({
      glove_model <- train_glove_model(
        db_connection = db_pool,
        rank = opt$dim,
        n_iter = opt$iter,
        sample_size = opt$sample
      )

      if (opt$save_disk) {
        model_path <- file.path(opt$model_dir, "lexml_glove.rds")
        save_glove_model(glove_model, model_path)
        log_info("GloVe model saved to {model_path}")
      }

      log_info("GloVe training complete!")

    }, error = function(e) {
      log_error("GloVe training failed: {e$message}")
      traceback()
    })
  }
}

# =============================================================================
# PART 2: Generate Document Embeddings
# =============================================================================

if (opt$mode %in% c("generate", "all")) {

  log_info("=== EMBEDDING GENERATION PHASE ===")

  # Load models if not already in memory
  if (is.null(word2vec_model) && opt$type %in% c("word2vec", "both")) {
    model_path <- file.path(opt$model_dir, "lexml_word2vec.bin")
    if (file.exists(model_path)) {
      log_info("Loading Word2Vec model from {model_path}...")
      word2vec_model <- load_word2vec_model(model_path)
    } else {
      log_warn("Word2Vec model not found at {model_path}")
    }
  }

  if (is.null(glove_model) && opt$type %in% c("glove", "both")) {
    model_path <- file.path(opt$model_dir, "lexml_glove.rds")
    if (file.exists(model_path)) {
      log_info("Loading GloVe model from {model_path}...")
      glove_model <- load_glove_model(model_path)
    } else {
      log_warn("GloVe model not found at {model_path}")
    }
  }

  # Load all documents
  log_info("Loading documents from database...")
  query <- "
    SELECT id, texto
    FROM documents
    WHERE texto IS NOT NULL
      AND LENGTH(texto) > 100
    ORDER BY id
  "

  if (!is.null(opt$sample)) {
    query <- paste0(query, sprintf(" LIMIT %d", opt$sample))
  }

  docs <- dbGetQuery(db_pool, query)
  log_info("Loaded {nrow(docs)} documents")

  # Generate Word2Vec embeddings
  if (!is.null(word2vec_model)) {
    log_info("Generating Word2Vec document embeddings...")

    tryCatch({
      # Get word vectors from model
      word_vectors_w2v <- as.matrix(word2vec_model)

      # Compute document embeddings
      doc_embeddings_w2v <- compute_document_embeddings(
        texts = docs$texto,
        word_vectors = word_vectors_w2v,
        method = "mean"
      )

      log_info("Word2Vec embeddings generated: {nrow(doc_embeddings_w2v)} x {ncol(doc_embeddings_w2v)}")

      # Save to database
      if (opt$save_db) {
        log_info("Saving Word2Vec embeddings to database...")
        save_document_embeddings_to_db(
          document_ids = docs$id,
          embeddings = doc_embeddings_w2v,
          db_connection = db_pool,
          embedding_type = "word2vec",
          model_version = "1.0"
        )
        log_info("Word2Vec embeddings saved to database")
      }

      # Save to disk
      if (opt$save_disk) {
        embeddings_path <- file.path(opt$model_dir, "document_embeddings_word2vec.rds")
        saveRDS(list(ids = docs$id, embeddings = doc_embeddings_w2v), embeddings_path)
        log_info("Word2Vec embeddings saved to {embeddings_path}")
      }

    }, error = function(e) {
      log_error("Word2Vec embedding generation failed: {e$message}")
      traceback()
    })
  }

  # Generate GloVe embeddings
  if (!is.null(glove_model)) {
    log_info("Generating GloVe document embeddings...")

    tryCatch({
      # Compute document embeddings
      doc_embeddings_glove <- compute_document_embeddings(
        texts = docs$texto,
        word_vectors = glove_model,
        method = "mean"
      )

      log_info("GloVe embeddings generated: {nrow(doc_embeddings_glove)} x {ncol(doc_embeddings_glove)}")

      # Save to database
      if (opt$save_db) {
        log_info("Saving GloVe embeddings to database...")
        save_document_embeddings_to_db(
          document_ids = docs$id,
          embeddings = doc_embeddings_glove,
          db_connection = db_pool,
          embedding_type = "glove",
          model_version = "1.0"
        )
        log_info("GloVe embeddings saved to database")
      }

      # Save to disk
      if (opt$save_disk) {
        embeddings_path <- file.path(opt$model_dir, "document_embeddings_glove.rds")
        saveRDS(list(ids = docs$id, embeddings = doc_embeddings_glove), embeddings_path)
        log_info("GloVe embeddings saved to {embeddings_path}")
      }

    }, error = function(e) {
      log_error("GloVe embedding generation failed: {e$message}")
      traceback()
    })
  }
}

# =============================================================================
# PART 3: Compute Top-10 Similarity Cache
# =============================================================================

if (opt$mode %in% c("generate", "all") && opt$save_db) {

  log_info("=== SIMILARITY CACHE GENERATION ===")

  # Determine which embedding type to use for similarity cache
  cache_type <- NULL
  cache_embeddings <- NULL
  cache_ids <- NULL

  if (!is.null(word2vec_model) && opt$type %in% c("word2vec", "both")) {
    cache_type <- "word2vec"
    cache_embeddings <- doc_embeddings_w2v
    cache_ids <- docs$id
  } else if (!is.null(glove_model) && opt$type %in% c("glove", "both")) {
    cache_type <- "glove"
    cache_embeddings <- doc_embeddings_glove
    cache_ids <- docs$id
  }

  if (!is.null(cache_type)) {
    log_info("Computing top-10 similar documents for each document ({cache_type})...")

    # This could be very expensive for 134k docs (134k x 134k comparisons)
    # Only do this for smaller datasets or use Annoy for approximate search

    if (nrow(cache_embeddings) <= 10000) {
      # Exact search for small datasets
      log_info("Using exact search (small dataset)")

      for (i in seq_len(nrow(cache_embeddings))) {
        if (i %% 100 == 0) {
          log_info("Processing document {i}/{nrow(cache_embeddings)}...")
        }

        query_embedding <- cache_embeddings[i, ]
        query_id <- cache_ids[i]

        # Find top 11 (including self)
        similar_indices <- semantic_document_search(
          query_embedding = query_embedding,
          document_embeddings = cache_embeddings,
          top_n = 11
        )

        # Remove self from results
        similar_indices <- similar_indices[similar_indices != i]
        similar_indices <- similar_indices[1:10]  # Top 10

        # Save to database
        for (rank in seq_along(similar_indices)) {
          similar_id <- cache_ids[similar_indices[rank]]

          # Compute similarity score
          similarity_score <- cosine_similarity(
            query_embedding,
            cache_embeddings[similar_indices[rank], ]
          )

          query_insert <- sprintf("
            INSERT INTO semantic_similarity_cache
              (doc1_id, doc2_id, similarity_score, embedding_type, rank_position)
            VALUES (%d, %d, %f, '%s', %d)
            ON CONFLICT (doc1_id, doc2_id, embedding_type)
            DO UPDATE SET
              similarity_score = EXCLUDED.similarity_score,
              rank_position = EXCLUDED.rank_position
          ", query_id, similar_id, similarity_score, cache_type, rank)

          dbExecute(db_pool, query_insert)
        }
      }

      log_info("Similarity cache generation complete!")

    } else {
      log_warn("Dataset too large for exact similarity search ({nrow(cache_embeddings)} docs)")
      log_warn("Consider using Annoy for approximate nearest neighbors")
      log_warn("Skipping similarity cache generation")
    }
  }
}

# =============================================================================
# Cleanup and Summary
# =============================================================================

# Close database connection
poolClose(db_pool)
log_info("Database connection closed")

# Summary
log_info("=== BATCH JOB COMPLETE ===")
if (opt$mode %in% c("train", "all")) {
  if (!is.null(word2vec_model)) {
    log_info("Word2Vec model trained successfully")
  }
  if (!is.null(glove_model)) {
    log_info("GloVe model trained successfully")
  }
}

if (opt$mode %in% c("generate", "all")) {
  log_info("Document embeddings generated and saved")
  if (opt$save_db) {
    log_info("Embeddings saved to database")
  }
  if (opt$save_disk) {
    log_info("Models and embeddings saved to {opt$model_dir}/")
  }
}

log_info("All tasks completed successfully!")

# =============================================================================
# End of word_embedding_batch.R
# =============================================================================
