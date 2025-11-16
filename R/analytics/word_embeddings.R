# =============================================================================
# Sprint 3: Word Embeddings (Word2Vec & GloVe)
# =============================================================================
# Description: Train domain-specific word embeddings on Brazilian legislative
#              corpus to enable semantic similarity search
# Version: 1.0
# Date: January 2025
# =============================================================================

library(word2vec)
library(text2vec)
library(quanteda)
library(RPostgreSQL)
library(dplyr)
library(logger)
library(RcppAnnoy)

# =============================================================================
# PART 1: Word2Vec Training
# =============================================================================

#' Train Word2Vec Model on Legislative Corpus
#'
#' Trains skip-gram Word2Vec model on all documents in the database.
#' Uses 300-dimensional vectors with standard hyperparameters.
#'
#' @param db_connection Database connection object (pool or RPostgreSQL)
#' @param dim Integer, dimensionality of embeddings (default: 300)
#' @param iter Integer, number of training iterations (default: 20)
#' @param min_count Integer, minimum word frequency (default: 5)
#' @param window Integer, context window size (default: 5)
#' @param threads Integer, number of CPU threads (default: 4)
#' @param sample_size Integer, optional sample size for testing (default: NULL = all docs)
#'
#' @return word2vec model object
#'
#' @examples
#' model <- train_word2vec_model(db_pool, sample_size = 1000)  # Test with 1k docs
#' model <- train_word2vec_model(db_pool)  # Full corpus training
train_word2vec_model <- function(db_connection,
                                  dim = 300,
                                  iter = 20,
                                  min_count = 5,
                                  window = 5,
                                  threads = 4,
                                  sample_size = NULL) {

  log_info("Starting Word2Vec training...")
  log_info("Parameters: dim={dim}, iter={iter}, min_count={min_count}, window={window}")

  # Load corpus
  log_info("Loading documents from database...")
  query <- "
    SELECT texto
    FROM documents
    WHERE texto IS NOT NULL
      AND LENGTH(texto) > 100
  "

  if (!is.null(sample_size)) {
    query <- paste0(query, sprintf(" LIMIT %d", sample_size))
    log_info("Using sample of {sample_size} documents for testing")
  }

  docs <- dbGetQuery(db_connection, query)
  log_info("Loaded {nrow(docs)} documents")

  if (nrow(docs) == 0) {
    stop("No documents loaded from database")
  }

  # Preprocess text
  log_info("Preprocessing text...")
  corpus_text <- preprocess_for_embeddings(docs$texto)
  log_info("Preprocessing complete. Sample: {substr(corpus_text[1], 1, 100)}...")

  # Train Word2Vec
  log_info("Training Word2Vec model (this may take several hours)...")
  start_time <- Sys.time()

  model <- word2vec(
    x = corpus_text,
    type = "skip-gram",      # Skip-gram better for semantic similarity
    dim = dim,
    iter = iter,
    min_count = min_count,
    window = window,
    threads = threads,
    negative = 5,            # Negative sampling rate
    hs = 0,                  # Don't use hierarchical softmax
    sample = 1e-3            # Subsampling threshold
  )

  elapsed <- difftime(Sys.time(), start_time, units = "mins")
  log_info("Word2Vec training complete in {round(elapsed, 2)} minutes")

  # Log model statistics
  vocab <- summary(model, type = "vocabulary")
  log_info("Vocabulary size: {nrow(vocab)}")
  log_info("Top 10 most frequent words:")
  print(head(vocab, 10))

  return(model)
}

#' Preprocess Text for Embedding Training
#'
#' Clean and normalize text for Word2Vec/GloVe training
#'
#' @param texts Character vector of documents
#' @return Character vector of preprocessed texts
preprocess_for_embeddings <- function(texts) {
  # Convert to lowercase
  texts <- tolower(texts)

  # Remove URLs
  texts <- gsub("https?://\\S+", " ", texts)

  # Remove email addresses
  texts <- gsub("\\S+@\\S+", " ", texts)

  # Remove numbers (keep words with numbers like "lei12345")
  # texts <- gsub("\\b\\d+\\b", " ", texts)

  # Remove punctuation but keep hyphens in compound words
  texts <- gsub("[^[:alnum:][:space:]-]", " ", texts)

  # Remove extra whitespace
  texts <- gsub("\\s+", " ", texts)
  texts <- trimws(texts)

  return(texts)
}

# =============================================================================
# PART 2: GloVe Training
# =============================================================================

#' Train GloVe Model on Legislative Corpus
#'
#' Trains GloVe (Global Vectors) model using co-occurrence matrix.
#' Alternative to Word2Vec with different training algorithm.
#'
#' @param db_connection Database connection object
#' @param rank Integer, dimensionality of embeddings (default: 300)
#' @param n_iter Integer, number of training iterations (default: 20)
#' @param min_count Integer, minimum word frequency (default: 5)
#' @param window Integer, skip-grams window size (default: 5)
#' @param sample_size Integer, optional sample size for testing
#'
#' @return Matrix of word vectors (words x dimensions)
train_glove_model <- function(db_connection,
                               rank = 300,
                               n_iter = 20,
                               min_count = 5,
                               window = 5,
                               sample_size = NULL) {

  log_info("Starting GloVe training...")

  # Load corpus
  log_info("Loading documents from database...")
  query <- "
    SELECT texto
    FROM documents
    WHERE texto IS NOT NULL
      AND LENGTH(texto) > 100
  "

  if (!is.null(sample_size)) {
    query <- paste0(query, sprintf(" LIMIT %d", sample_size))
  }

  docs <- dbGetQuery(db_connection, query)
  log_info("Loaded {nrow(docs)} documents")

  # Preprocess
  log_info("Preprocessing text...")
  texts_clean <- preprocess_for_embeddings(docs$texto)

  # Tokenization
  log_info("Tokenizing...")
  tokens <- word_tokenizer(texts_clean)
  it <- itoken(tokens, progressbar = TRUE)

  # Create vocabulary
  log_info("Creating vocabulary...")
  vocab <- create_vocabulary(it) %>%
    prune_vocabulary(term_count_min = min_count)

  log_info("Vocabulary size after pruning: {nrow(vocab)}")

  vectorizer <- vocab_vectorizer(vocab)

  # Create term co-occurrence matrix
  log_info("Creating term co-occurrence matrix...")
  tcm <- create_tcm(it, vectorizer, skip_grams_window = window)

  log_info("TCM dimensions: {nrow(tcm)} x {ncol(tcm)}")

  # Train GloVe
  log_info("Training GloVe model (this may take several hours)...")
  start_time <- Sys.time()

  glove <- GlobalVectors$new(rank = rank, x_max = 10, learning_rate = 0.15)
  wv_main <- glove$fit_transform(
    tcm,
    n_iter = n_iter,
    convergence_tol = 0.01,
    n_threads = 4
  )

  wv_context <- glove$components

  # Combine main and context vectors (standard GloVe approach)
  word_vectors <- wv_main + t(wv_context)

  elapsed <- difftime(Sys.time(), start_time, units = "mins")
  log_info("GloVe training complete in {round(elapsed, 2)} minutes")

  log_info("Final embedding dimensions: {nrow(word_vectors)} words x {ncol(word_vectors)} dims")

  return(word_vectors)
}

# =============================================================================
# PART 3: Document Embeddings
# =============================================================================

#' Compute Document Embeddings from Word Vectors
#'
#' Creates document-level embeddings by averaging word vectors.
#' Simple but effective approach for document similarity.
#'
#' @param texts Character vector of documents
#' @param word_vectors Matrix of word vectors (from Word2Vec or GloVe)
#' @param method Character, aggregation method ("mean" or "sum")
#'
#' @return Matrix of document embeddings (documents x dimensions)
compute_document_embeddings <- function(texts, word_vectors, method = "mean") {

  log_info("Computing document embeddings for {length(texts)} documents...")

  # Preprocess
  texts_clean <- preprocess_for_embeddings(texts)

  # Compute embeddings
  doc_embeddings <- lapply(seq_along(texts_clean), function(i) {
    if (i %% 1000 == 0) {
      log_info("Processing document {i}/{length(texts)}...")
    }

    doc <- texts_clean[i]
    tokens <- unlist(strsplit(doc, "\\s+"))

    # Get vectors for tokens that exist in vocabulary
    valid_tokens <- tokens[tokens %in% rownames(word_vectors)]

    if (length(valid_tokens) == 0) {
      # Return zero vector if no valid tokens
      return(rep(0, ncol(word_vectors)))
    }

    token_vectors <- word_vectors[valid_tokens, , drop = FALSE]

    # Aggregate
    if (method == "mean") {
      colMeans(token_vectors)
    } else if (method == "sum") {
      colSums(token_vectors)
    } else {
      stop("Invalid method. Use 'mean' or 'sum'")
    }
  })

  # Convert to matrix
  embeddings_matrix <- do.call(rbind, doc_embeddings)
  rownames(embeddings_matrix) <- NULL

  log_info("Document embeddings computed: {nrow(embeddings_matrix)} x {ncol(embeddings_matrix)}")

  return(embeddings_matrix)
}

# =============================================================================
# PART 4: Semantic Similarity Search
# =============================================================================

#' Find Most Similar Words
#'
#' Find top-N most similar words to a query word using cosine similarity
#'
#' @param query Character, query word
#' @param word_vectors Matrix of word vectors
#' @param top_n Integer, number of similar words to return
#'
#' @return Named vector of similarity scores
semantic_word_search <- function(query, word_vectors, top_n = 10) {

  query <- tolower(query)

  if (!query %in% rownames(word_vectors)) {
    stop("Query word '{query}' not in vocabulary")
  }

  query_vec <- word_vectors[query, ]

  # Compute cosine similarity with all words
  similarities <- sim2(
    x = matrix(query_vec, nrow = 1),
    y = word_vectors,
    method = "cosine",
    norm = "l2"
  )

  # Sort and get top N (excluding query itself)
  top_similar <- sort(similarities[1, ], decreasing = TRUE)
  top_similar <- top_similar[names(top_similar) != query]
  top_similar <- head(top_similar, top_n)

  return(top_similar)
}

#' Find Most Similar Documents
#'
#' Find top-N most similar documents to a query document
#'
#' @param query_embedding Numeric vector, query document embedding
#' @param document_embeddings Matrix of all document embeddings
#' @param top_n Integer, number of similar documents to return
#'
#' @return Integer vector of document indices (sorted by similarity)
semantic_document_search <- function(query_embedding, document_embeddings, top_n = 10) {

  # Compute cosine similarity
  similarities <- sim2(
    x = matrix(query_embedding, nrow = 1),
    y = document_embeddings,
    method = "cosine",
    norm = "l2"
  )

  # Sort and get top N
  top_indices <- order(similarities[1, ], decreasing = TRUE)[1:top_n]

  return(top_indices)
}

# =============================================================================
# PART 5: Approximate Nearest Neighbors (Fast Search)
# =============================================================================

#' Build Annoy Index for Fast Similarity Search
#'
#' Creates Annoy (Approximate Nearest Neighbors) index for fast retrieval.
#' Recommended for large document collections (>10k documents).
#'
#' @param embeddings Matrix of embeddings
#' @param n_trees Integer, number of trees (more = better accuracy, slower build)
#' @param metric Character, distance metric ("angular" for cosine similarity)
#'
#' @return Annoy index object
build_annoy_index <- function(embeddings, n_trees = 50, metric = "angular") {

  log_info("Building Annoy index with {n_trees} trees...")

  n_dims <- ncol(embeddings)
  n_items <- nrow(embeddings)

  # Create index
  annoy_index <- new(AnnoyAngular, n_dims)

  # Add items
  for (i in seq_len(n_items)) {
    if (i %% 10000 == 0) {
      log_info("Adding item {i}/{n_items} to index...")
    }
    annoy_index$addItem(i - 1, embeddings[i, ])  # Annoy uses 0-indexing
  }

  # Build index
  log_info("Building trees...")
  annoy_index$build(n_trees)

  log_info("Annoy index built successfully")

  return(annoy_index)
}

#' Fast Similarity Search with Annoy
#'
#' Query Annoy index for nearest neighbors
#'
#' @param query_embedding Numeric vector, query embedding
#' @param annoy_index Annoy index object
#' @param top_n Integer, number of neighbors to return
#'
#' @return List with indices and distances
fast_similarity_search <- function(query_embedding, annoy_index, top_n = 10) {

  # Get nearest neighbors
  result <- annoy_index$getNNsByVector(query_embedding, top_n, include_distances = TRUE)

  # Annoy uses 0-indexing, convert to 1-indexing
  indices <- result$item + 1
  distances <- result$distance

  # Convert angular distance to cosine similarity
  # angular_distance = sqrt(2 * (1 - cosine_similarity))
  similarities <- 1 - (distances^2 / 2)

  return(list(
    indices = indices,
    similarities = similarities
  ))
}

# =============================================================================
# PART 6: Database Storage Functions
# =============================================================================

#' Save Word Embeddings to Database
#'
#' Store word-level embeddings in word_embeddings table
#'
#' @param word_vectors Matrix of word vectors
#' @param db_connection Database connection
#' @param embedding_type Character, "word2vec" or "glove"
#' @param model_version Character, version identifier
save_word_embeddings_to_db <- function(word_vectors,
                                        db_connection,
                                        embedding_type = "word2vec",
                                        model_version = "1.0") {

  log_info("Saving {nrow(word_vectors)} word embeddings to database...")

  # Convert to data frame
  words <- rownames(word_vectors)

  # Process in batches
  batch_size <- 1000
  n_batches <- ceiling(length(words) / batch_size)

  for (batch in seq_len(n_batches)) {
    start_idx <- (batch - 1) * batch_size + 1
    end_idx <- min(batch * batch_size, length(words))

    batch_words <- words[start_idx:end_idx]

    log_info("Processing batch {batch}/{n_batches} ({start_idx}-{end_idx})...")

    for (i in seq_along(batch_words)) {
      word <- batch_words[i]
      embedding <- word_vectors[word, ]

      # Convert embedding to PostgreSQL array format
      embedding_str <- paste0("{", paste(embedding, collapse = ","), "}")

      query <- sprintf("
        INSERT INTO word_embeddings (word, embedding_type, embedding, model_version)
        VALUES ('%s', '%s', '%s'::float8[], '%s')
        ON CONFLICT (word, embedding_type)
        DO UPDATE SET
          embedding = EXCLUDED.embedding,
          model_version = EXCLUDED.model_version,
          created_at = NOW()
      ", word, embedding_type, embedding_str, model_version)

      dbExecute(db_connection, query)
    }

    log_info("Batch {batch}/{n_batches} complete")
  }

  log_info("Word embeddings saved successfully")
}

#' Save Document Embeddings to Database
#'
#' Store document-level embeddings in document_embeddings table
#'
#' @param document_ids Integer vector of document IDs
#' @param embeddings Matrix of document embeddings
#' @param db_connection Database connection
#' @param embedding_type Character, "word2vec", "glove", or "bert"
#' @param model_version Character, version identifier
save_document_embeddings_to_db <- function(document_ids,
                                            embeddings,
                                            db_connection,
                                            embedding_type = "word2vec",
                                            model_version = "1.0") {

  log_info("Saving {length(document_ids)} document embeddings to database...")

  if (length(document_ids) != nrow(embeddings)) {
    stop("Number of document IDs must match number of embeddings")
  }

  # Process in batches
  batch_size <- 1000
  n_batches <- ceiling(length(document_ids) / batch_size)

  for (batch in seq_len(n_batches)) {
    start_idx <- (batch - 1) * batch_size + 1
    end_idx <- min(batch * batch_size, length(document_ids))

    log_info("Processing batch {batch}/{n_batches} ({start_idx}-{end_idx})...")

    for (i in start_idx:end_idx) {
      doc_id <- document_ids[i]
      embedding <- embeddings[i, ]

      # Convert to PostgreSQL array format
      embedding_str <- paste0("{", paste(embedding, collapse = ","), "}")

      query <- sprintf("
        INSERT INTO document_embeddings (document_id, embedding_type, embedding, embedding_version)
        VALUES (%d, '%s', '%s'::float8[], '%s')
        ON CONFLICT (document_id, embedding_type)
        DO UPDATE SET
          embedding = EXCLUDED.embedding,
          embedding_version = EXCLUDED.embedding_version,
          updated_at = NOW()
      ", doc_id, embedding_type, embedding_str, model_version)

      dbExecute(db_connection, query)
    }

    log_info("Batch {batch}/{n_batches} complete")
  }

  log_info("Document embeddings saved successfully")
}

# =============================================================================
# PART 7: Model Persistence
# =============================================================================

#' Save Word2Vec Model to Disk
#'
#' Save trained Word2Vec model for later use
#'
#' @param model word2vec model object
#' @param file_path Character, path to save model
save_word2vec_model <- function(model, file_path) {
  log_info("Saving Word2Vec model to {file_path}...")
  write.word2vec(model, file_path, type = "bin")
  log_info("Model saved successfully")
}

#' Load Word2Vec Model from Disk
#'
#' Load previously trained Word2Vec model
#'
#' @param file_path Character, path to model file
#' @return word2vec model object
load_word2vec_model <- function(file_path) {
  log_info("Loading Word2Vec model from {file_path}...")
  model <- read.word2vec(file_path, normalize = TRUE)
  log_info("Model loaded successfully")
  return(model)
}

#' Save GloVe Model to Disk
#'
#' Save trained GloVe word vectors
#'
#' @param word_vectors Matrix of word vectors
#' @param file_path Character, path to save model
save_glove_model <- function(word_vectors, file_path) {
  log_info("Saving GloVe model to {file_path}...")
  saveRDS(word_vectors, file_path)
  log_info("Model saved successfully")
}

#' Load GloVe Model from Disk
#'
#' Load previously trained GloVe model
#'
#' @param file_path Character, path to model file
#' @return Matrix of word vectors
load_glove_model <- function(file_path) {
  log_info("Loading GloVe model from {file_path}...")
  word_vectors <- readRDS(file_path)
  log_info("Model loaded successfully")
  return(word_vectors)
}

# =============================================================================
# PART 8: Helper Functions
# =============================================================================

#' Get Embedding Vector from Model
#'
#' Extract embedding for a specific word (handles both Word2Vec and GloVe)
#'
#' @param word Character, query word
#' @param model word2vec model object OR matrix of word vectors (GloVe)
#'
#' @return Numeric vector, word embedding
get_word_embedding <- function(word, model) {
  word <- tolower(word)

  if (inherits(model, "word2vec")) {
    # Word2Vec model
    if (!word %in% summary(model, type = "vocabulary")$word) {
      stop("Word '{word}' not in vocabulary")
    }
    as.vector(predict(model, word, type = "embedding"))
  } else if (is.matrix(model)) {
    # GloVe word vectors
    if (!word %in% rownames(model)) {
      stop("Word '{word}' not in vocabulary")
    }
    model[word, ]
  } else {
    stop("Invalid model type")
  }
}

#' Calculate Cosine Similarity
#'
#' Compute cosine similarity between two vectors
#'
#' @param vec1 Numeric vector
#' @param vec2 Numeric vector
#'
#' @return Numeric, cosine similarity score (0-1)
cosine_similarity <- function(vec1, vec2) {
  sum(vec1 * vec2) / (sqrt(sum(vec1^2)) * sqrt(sum(vec2^2)))
}

# =============================================================================
# End of word_embeddings.R
# =============================================================================

log_info("word_embeddings.R loaded successfully")
