# Generate Document Embeddings from Word2Vec Model
# Sprint 3 - Advanced NLP
# Purpose: Generate 300-dimensional embeddings for all documents and populate similarity cache

library(DBI)
library(RPostgres)
library(word2vec)
library(quanteda)
library(dplyr)
library(stringr)
library(Matrix)

#' Load Word2Vec model from database
#'
#' @param con Database connection
#' @return Word2Vec model object and metadata
load_word2vec_model <- function(con) {
  cat("Loading Word2Vec model from database...\n")

  # Get model metadata
  model_info <- dbGetQuery(con, "
    SELECT
      model_type,
      model_version,
      vocabulary_size,
      vector_dimensions,
      training_docs,
      trained_at,
      model_path
    FROM nlp_models
    WHERE model_type = 'word2vec'
    ORDER BY trained_at DESC
    LIMIT 1
  ")

  if (nrow(model_info) == 0) {
    stop("No Word2Vec model found in database. Please run Word2Vec training first.")
  }

  cat(sprintf("Found Word2Vec model:\n"))
  cat(sprintf("  Version: %s\n", model_info$model_version))
  cat(sprintf("  Vocabulary: %d words\n", model_info$vocabulary_size))
  cat(sprintf("  Dimensions: %d\n", model_info$vector_dimensions))
  cat(sprintf("  Training docs: %d\n", model_info$training_docs))
  cat(sprintf("  Trained: %s\n", model_info$trained_at))

  # Load model from file
  if (!file.exists(model_info$model_path)) {
    stop(sprintf("Model file not found: %s", model_info$model_path))
  }

  model <- read.word2vec(model_info$model_path, normalize = TRUE)

  list(
    model = model,
    info = model_info
  )
}

#' Generate document embedding from Word2Vec model
#'
#' @param text Document text
#' @param model Word2Vec model
#' @return 300-dimensional embedding vector
generate_document_embedding <- function(text, model) {
  # Clean and tokenize
  tokens <- text %>%
    str_to_lower() %>%
    str_replace_all("[^a-záàâãéèêíïóôõöúçñ\\s]", " ") %>%
    str_squish() %>%
    strsplit("\\s+") %>%
    unlist()

  # Get word vectors for tokens that exist in vocabulary
  vocab <- rownames(as.matrix(model))
  valid_tokens <- tokens[tokens %in% vocab]

  if (length(valid_tokens) == 0) {
    # Return zero vector if no valid tokens
    return(rep(0, 300))
  }

  # Average pooling of word vectors
  word_vectors <- predict(model, valid_tokens, type = "embedding")

  if (is.matrix(word_vectors)) {
    embedding <- colMeans(word_vectors)
  } else {
    embedding <- word_vectors
  }

  # Normalize to unit length
  embedding / sqrt(sum(embedding^2))
}

#' Calculate cosine similarity between two vectors
#'
#' @param v1 First vector
#' @param v2 Second vector
#' @return Cosine similarity score (0-1)
cosine_similarity <- function(v1, v2) {
  sum(v1 * v2) / (sqrt(sum(v1^2)) * sqrt(sum(v2^2)))
}

#' Generate embeddings for all documents
#'
#' @param con Database connection
#' @param model_obj Word2Vec model object
#' @param batch_size Number of documents per batch
#' @param progress_interval Progress reporting interval
generate_all_embeddings <- function(con, model_obj, batch_size = 1000, progress_interval = 100) {
  model <- model_obj$model

  cat("\n=== Generating Document Embeddings ===\n")

  # Get total count
  total_docs <- dbGetQuery(con, "
    SELECT COUNT(*) as n
    FROM documentos
    WHERE texto_completo IS NOT NULL
      AND LENGTH(TRIM(texto_completo)) > 0
  ")$n

  cat(sprintf("Total documents to process: %d\n", total_docs))

  # Clear existing embeddings
  cat("Clearing existing embeddings...\n")
  dbExecute(con, "DELETE FROM word_embeddings WHERE model_id = (
    SELECT id FROM nlp_models WHERE model_type = 'word2vec' ORDER BY trained_at DESC LIMIT 1
  )")

  # Get model ID
  model_id <- dbGetQuery(con, "
    SELECT id FROM nlp_models
    WHERE model_type = 'word2vec'
    ORDER BY trained_at DESC
    LIMIT 1
  ")$id

  # Process in batches
  processed <- 0
  start_time <- Sys.time()

  for (offset in seq(0, total_docs - 1, by = batch_size)) {
    # Fetch batch
    docs <- dbGetQuery(con, sprintf("
      SELECT
        id,
        titulo,
        ementa,
        texto_completo
      FROM documentos
      WHERE texto_completo IS NOT NULL
        AND LENGTH(TRIM(texto_completo)) > 0
      ORDER BY id
      LIMIT %d OFFSET %d
    ", batch_size, offset))

    if (nrow(docs) == 0) break

    # Generate embeddings
    embeddings_list <- list()

    for (i in 1:nrow(docs)) {
      # Combine text fields
      combined_text <- paste(
        coalesce(docs$titulo[i], ""),
        coalesce(docs$ementa[i], ""),
        coalesce(docs$texto_completo[i], ""),
        sep = " "
      )

      # Generate embedding
      embedding <- generate_document_embedding(combined_text, model)

      # Store in list
      embeddings_list[[i]] <- data.frame(
        document_id = docs$id[i],
        model_id = model_id,
        embedding_vector = I(list(embedding)),
        generated_at = Sys.time()
      )

      processed <- processed + 1

      # Progress reporting
      if (processed %% progress_interval == 0) {
        elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
        rate <- processed / elapsed
        remaining <- (total_docs - processed) / rate

        cat(sprintf(
          "Progress: %d/%d (%.1f%%) | Rate: %.1f docs/sec | ETA: %.1f min\n",
          processed,
          total_docs,
          (processed / total_docs) * 100,
          rate,
          remaining / 60
        ))
      }
    }

    # Batch insert to database
    embeddings_df <- bind_rows(embeddings_list)

    # Convert embedding vectors to PostgreSQL array format
    embeddings_df <- embeddings_df %>%
      mutate(
        embedding_text = sapply(embedding_vector, function(vec) {
          paste0("{", paste(vec, collapse = ","), "}")
        })
      ) %>%
      select(-embedding_vector)

    # Insert batch
    dbExecute(con, sprintf("
      INSERT INTO word_embeddings (document_id, model_id, embedding_vector, generated_at)
      SELECT
        document_id,
        model_id,
        embedding_text::real[],
        generated_at
      FROM (VALUES %s) AS t(document_id, model_id, embedding_text, generated_at)
    ", paste(
      sprintf(
        "(%d, %d, '%s', '%s')",
        embeddings_df$document_id,
        embeddings_df$model_id,
        embeddings_df$embedding_text,
        embeddings_df$generated_at
      ),
      collapse = ","
    )))

    cat(sprintf("Batch inserted: %d embeddings\n", nrow(embeddings_df)))
  }

  elapsed_total <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))

  cat(sprintf("\n=== Embeddings Generation Complete ===\n"))
  cat(sprintf("Total documents: %d\n", processed))
  cat(sprintf("Total time: %.1f minutes\n", elapsed_total))
  cat(sprintf("Average rate: %.1f docs/min\n", processed / elapsed_total))
}

#' Calculate semantic similarity cache
#'
#' @param con Database connection
#' @param similarity_threshold Minimum similarity to store
#' @param batch_size Number of documents per batch
calculate_similarity_cache <- function(con, similarity_threshold = 0.5, batch_size = 500) {
  cat("\n=== Calculating Semantic Similarity Cache ===\n")
  cat(sprintf("Similarity threshold: %.2f\n", similarity_threshold))

  # Get model ID
  model_id <- dbGetQuery(con, "
    SELECT id FROM nlp_models
    WHERE model_type = 'word2vec'
    ORDER BY trained_at DESC
    LIMIT 1
  ")$id

  # Clear existing cache
  cat("Clearing existing similarity cache...\n")
  dbExecute(con, sprintf("DELETE FROM semantic_similarity_cache WHERE model_id = %d", model_id))

  # Get all embeddings
  cat("Loading embeddings from database...\n")
  embeddings <- dbGetQuery(con, sprintf("
    SELECT
      document_id,
      embedding_vector
    FROM word_embeddings
    WHERE model_id = %d
    ORDER BY document_id
  ", model_id))

  cat(sprintf("Loaded %d embeddings\n", nrow(embeddings)))

  # Convert to matrix
  embedding_matrix <- matrix(
    unlist(embeddings$embedding_vector),
    nrow = nrow(embeddings),
    byrow = TRUE
  )

  rownames(embedding_matrix) <- embeddings$document_id

  # Calculate pairwise similarities in batches
  total_pairs <- 0
  start_time <- Sys.time()

  for (i in 1:nrow(embeddings)) {
    doc_id_1 <- embeddings$document_id[i]
    vec_1 <- embedding_matrix[i, ]

    # Calculate similarities with all subsequent documents
    if (i < nrow(embeddings)) {
      similarities <- sapply((i + 1):nrow(embeddings), function(j) {
        cosine_similarity(vec_1, embedding_matrix[j, ])
      })

      # Filter by threshold
      high_sim_idx <- which(similarities >= similarity_threshold)

      if (length(high_sim_idx) > 0) {
        doc_ids_2 <- embeddings$document_id[(i + 1):nrow(embeddings)][high_sim_idx]
        sim_scores <- similarities[high_sim_idx]

        # Prepare batch insert
        cache_entries <- data.frame(
          document_id_1 = doc_id_1,
          document_id_2 = doc_ids_2,
          similarity_score = sim_scores,
          model_id = model_id,
          calculated_at = Sys.time()
        )

        # Insert batch
        dbWriteTable(con, "semantic_similarity_cache", cache_entries, append = TRUE)

        total_pairs <- total_pairs + length(high_sim_idx)
      }
    }

    # Progress reporting
    if (i %% 50 == 0) {
      elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
      rate <- i / elapsed
      remaining <- (nrow(embeddings) - i) / rate

      cat(sprintf(
        "Progress: %d/%d (%.1f%%) | Similar pairs: %d | ETA: %.1f min\n",
        i,
        nrow(embeddings),
        (i / nrow(embeddings)) * 100,
        total_pairs,
        remaining / 60
      ))
    }
  }

  elapsed_total <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))

  cat(sprintf("\n=== Similarity Cache Complete ===\n"))
  cat(sprintf("Total similar pairs: %d\n", total_pairs))
  cat(sprintf("Total time: %.1f minutes\n", elapsed_total))
}

#' Main function
#'
#' @param mode Mode: "embeddings", "similarity", "full"
#' @param batch_size Batch size for processing
#' @param similarity_threshold Minimum similarity for cache
main <- function(mode = "full", batch_size = 1000, similarity_threshold = 0.5) {
  cat("=== Document Embeddings Generation ===\n")
  cat(sprintf("Mode: %s\n", mode))
  cat(sprintf("Batch size: %d\n", batch_size))

  # Connect to database
  con <- dbConnect(
    RPostgres::Postgres(),
    host = Sys.getenv("DB_HOST", "localhost"),
    port = as.integer(Sys.getenv("DB_PORT", "5432")),
    dbname = Sys.getenv("DB_NAME", "monitor_legislativo"),
    user = Sys.getenv("DB_USER", "monitor_user"),
    password = Sys.getenv("DB_PASSWORD", "Sdonario1")
  )

  on.exit(dbDisconnect(con))

  tryCatch({
    # Load Word2Vec model
    model_obj <- load_word2vec_model(con)

    # Generate embeddings
    if (mode %in% c("embeddings", "full")) {
      generate_all_embeddings(con, model_obj, batch_size)
    }

    # Calculate similarity cache
    if (mode %in% c("similarity", "full")) {
      calculate_similarity_cache(con, similarity_threshold)
    }

    cat("\n=== SUCCESS ===\n")
    cat("Document embeddings generation complete!\n")

  }, error = function(e) {
    cat(sprintf("\n❌ ERROR: %s\n", e$message))
    quit(status = 1)
  })
}

# Helper function for coalesce
coalesce <- function(...) {
  Reduce(function(x, y) {
    i <- which(is.na(x))
    x[i] <- y[i]
    x
  }, list(...))
}
