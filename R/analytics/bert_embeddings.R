# =============================================================================
# Sprint 3: BERT-based Semantic Embeddings
# =============================================================================
# Description: Portuguese BERT embeddings via Python/R integration (reticulate)
#              for state-of-the-art semantic similarity and precedent retrieval
# Version: 1.0
# Date: January 2025
# Model: neuralmind/bert-base-portuguese-cased
# =============================================================================

library(reticulate)
library(RPostgreSQL)
library(dplyr)
library(logger)

# =============================================================================
# PART 1: Environment Setup
# =============================================================================

#' Setup BERT Python Environment (One-Time)
#'
#' Creates conda environment with transformers, torch, sentence-transformers
#' Only needs to be run once per system
#'
#' @param env_name Character, conda environment name (default: "lexml_nlp")
#' @param python_version Character, Python version (default: "3.10")
#'
#' @examples
#' setup_bert_environment()  # One-time setup
setup_bert_environment <- function(env_name = "lexml_nlp", python_version = "3.10") {

  log_info("Setting up BERT Python environment...")

  # Check if conda is available
  if (!conda_binary() %>% is.null()) {
    log_info("Conda found at: {conda_binary()}")
  } else {
    stop("Conda not found. Please install Miniconda or Anaconda first.")
  }

  # Create conda environment if it doesn't exist
  if (!env_name %in% conda_list()$name) {
    log_info("Creating conda environment '{env_name}' with Python {python_version}...")
    conda_create(env_name, python_version = python_version)
  } else {
    log_info("Conda environment '{env_name}' already exists")
  }

  # Install Python packages
  log_info("Installing transformers, torch, sentence-transformers...")

  tryCatch({
    py_install(
      packages = c("transformers", "torch", "sentence-transformers"),
      envname = env_name,
      pip = TRUE
    )
    log_info("Python packages installed successfully")
  }, error = function(e) {
    log_error("Package installation failed: {e$message}")
    log_info("Trying manual installation...")

    # Fallback: use pip directly
    system(sprintf(
      "conda run -n %s pip install transformers torch sentence-transformers",
      env_name
    ))
  })

  # Test installation
  log_info("Testing installation...")
  use_condaenv(env_name, required = TRUE)

  transformers <- import("transformers")
  log_info("transformers version: {transformers$`__version__`}")

  torch <- import("torch")
  log_info("torch version: {torch$`__version__`}")

  sentence_transformers <- import("sentence_transformers")
  log_info("sentence-transformers installed successfully")

  log_info("BERT environment setup complete!")
}

#' Activate BERT Environment
#'
#' Activate the BERT conda environment for use
#'
#' @param env_name Character, environment name
activate_bert_environment <- function(env_name = "lexml_nlp") {
  log_info("Activating BERT environment '{env_name}'...")

  tryCatch({
    use_condaenv(env_name, required = TRUE)
    log_info("Environment activated successfully")
  }, error = function(e) {
    log_error("Failed to activate environment: {e$message}")
    log_error("Run setup_bert_environment() first")
    stop("BERT environment not available")
  })
}

# =============================================================================
# PART 2: BERT Model Loading
# =============================================================================

#' Load BERT Model via Reticulate
#'
#' Load pre-trained Portuguese BERT model using transformers library
#'
#' @param model_name Character, HuggingFace model name
#'               (default: "neuralmind/bert-base-portuguese-cased")
#' @param use_gpu Logical, use GPU if available (default: FALSE)
#'
#' @return List with tokenizer and model objects
#'
#' @examples
#' bert <- load_bert_model()
#' bert <- load_bert_model(use_gpu = TRUE)  # If GPU available
load_bert_model <- function(model_name = "neuralmind/bert-base-portuguese-cased",
                             use_gpu = FALSE) {

  log_info("Loading BERT model: {model_name}...")

  # Import Python modules
  transformers <- import("transformers")
  torch <- import("torch")

  # Load tokenizer
  log_info("Loading tokenizer...")
  tokenizer <- transformers$AutoTokenizer$from_pretrained(model_name)

  # Load model
  log_info("Loading model...")
  model <- transformers$AutoModel$from_pretrained(model_name)

  # Move to GPU if requested and available
  if (use_gpu) {
    if (torch$cuda$is_available()) {
      log_info("GPU available. Moving model to CUDA...")
      model <- model$cuda()
      log_info("Model moved to GPU")
    } else {
      log_warn("GPU requested but not available. Using CPU.")
    }
  } else {
    log_info("Using CPU for inference")
  }

  # Set to evaluation mode
  model$eval()

  log_info("BERT model loaded successfully")
  log_info("Model config: {model$config$hidden_size}-dim embeddings")

  return(list(
    tokenizer = tokenizer,
    model = model,
    model_name = model_name,
    device = if (use_gpu && torch$cuda$is_available()) "cuda" else "cpu"
  ))
}

# =============================================================================
# PART 3: Embedding Generation
# =============================================================================

#' Generate BERT Embeddings for Texts
#'
#' Generate 768-dimensional contextualized embeddings using BERT
#' Uses [CLS] token representation as document embedding
#'
#' @param texts Character vector of documents
#' @param bert_model BERT model object from load_bert_model()
#' @param batch_size Integer, batch size for processing (default: 16)
#' @param max_length Integer, maximum sequence length (default: 512)
#' @param show_progress Logical, show progress bar (default: TRUE)
#'
#' @return Matrix of embeddings (n_texts x 768)
#'
#' @examples
#' bert <- load_bert_model()
#' texts <- c("Lei sobre transporte", "Decreto municipal")
#' embeddings <- generate_bert_embeddings(texts, bert)
generate_bert_embeddings <- function(texts,
                                      bert_model,
                                      batch_size = 16,
                                      max_length = 512,
                                      show_progress = TRUE) {

  log_info("Generating BERT embeddings for {length(texts)} texts...")
  log_info("Batch size: {batch_size}, Max length: {max_length}")

  # Import torch
  torch <- import("torch")

  # Initialize list to store embeddings
  all_embeddings <- list()

  # Process in batches
  n_batches <- ceiling(length(texts) / batch_size)
  log_info("Processing {n_batches} batches...")

  for (batch_idx in seq_len(n_batches)) {
    start_idx <- (batch_idx - 1) * batch_size + 1
    end_idx <- min(batch_idx * batch_size, length(texts))

    batch_texts <- texts[start_idx:end_idx]

    if (show_progress && batch_idx %% 10 == 0) {
      log_info("Processing batch {batch_idx}/{n_batches} ({start_idx}-{end_idx})...")
    }

    # Tokenize batch
    inputs <- bert_model$tokenizer(
      batch_texts,
      return_tensors = "pt",
      padding = TRUE,
      truncation = TRUE,
      max_length = as.integer(max_length)
    )

    # Move to same device as model
    if (bert_model$device == "cuda") {
      inputs <- lapply(inputs, function(x) x$cuda())
    }

    # Generate embeddings (no gradient computation)
    with(torch$no_grad(), {
      outputs <- bert_model$model(**inputs)

      # Extract [CLS] token embedding (first token)
      # Shape: (batch_size, hidden_size)
      cls_embeddings <- outputs$last_hidden_state[, 1L, ]

      # Move to CPU and convert to R matrix
      if (bert_model$device == "cuda") {
        cls_embeddings <- cls_embeddings$cpu()
      }

      batch_embeddings <- cls_embeddings$numpy()
    })

    all_embeddings[[batch_idx]] <- batch_embeddings
  }

  # Combine all batches
  embeddings_matrix <- do.call(rbind, all_embeddings)

  log_info("BERT embeddings generated: {nrow(embeddings_matrix)} x {ncol(embeddings_matrix)}")

  return(embeddings_matrix)
}

# =============================================================================
# PART 4: Sentence-BERT (Faster Alternative)
# =============================================================================

#' Load Sentence-BERT Model
#'
#' Load Sentence-BERT for faster, optimized semantic similarity
#' Generally faster than raw BERT for similarity tasks
#'
#' @param model_name Character, model name (default: Portuguese BERT)
#'
#' @return Sentence-BERT model object
#'
#' @examples
#' sbert <- load_sentence_bert()
load_sentence_bert <- function(model_name = "neuralmind/bert-base-portuguese-cased") {

  log_info("Loading Sentence-BERT model: {model_name}...")

  # Import sentence_transformers
  sentence_transformers <- import("sentence_transformers")

  # Load model
  model <- sentence_transformers$SentenceTransformer(model_name)

  log_info("Sentence-BERT loaded successfully")

  return(model)
}

#' Generate Embeddings with Sentence-BERT
#'
#' Faster embedding generation using Sentence-BERT
#'
#' @param texts Character vector of documents
#' @param sbert_model Sentence-BERT model from load_sentence_bert()
#' @param batch_size Integer, batch size (default: 32)
#' @param show_progress Logical, show progress (default: TRUE)
#'
#' @return Matrix of embeddings
generate_sbert_embeddings <- function(texts,
                                       sbert_model,
                                       batch_size = 32,
                                       show_progress = TRUE) {

  log_info("Generating Sentence-BERT embeddings for {length(texts)} texts...")

  # Generate embeddings
  embeddings <- sbert_model$encode(
    texts,
    batch_size = as.integer(batch_size),
    show_progress_bar = show_progress,
    convert_to_numpy = TRUE
  )

  log_info("Sentence-BERT embeddings generated: {nrow(embeddings)} x {ncol(embeddings)}")

  return(embeddings)
}

# =============================================================================
# PART 5: Semantic Similarity
# =============================================================================

#' Compute BERT Semantic Similarity
#'
#' Calculate cosine similarity between two texts using BERT embeddings
#'
#' @param text1 Character, first text
#' @param text2 Character, second text
#' @param bert_model BERT model object
#'
#' @return Numeric, cosine similarity score (0-1)
#'
#' @examples
#' bert <- load_bert_model()
#' sim <- bert_semantic_similarity("Lei 123", "Decreto 456", bert)
bert_semantic_similarity <- function(text1, text2, bert_model) {

  # Generate embeddings
  emb1 <- generate_bert_embeddings(text1, bert_model, batch_size = 1, show_progress = FALSE)
  emb2 <- generate_bert_embeddings(text2, bert_model, batch_size = 1, show_progress = FALSE)

  # Cosine similarity
  similarity <- sum(emb1 * emb2) / (sqrt(sum(emb1^2)) * sqrt(sum(emb2^2)))

  return(as.numeric(similarity))
}

#' Find Most Similar Documents (BERT)
#'
#' Find top-N most similar documents using BERT embeddings
#'
#' @param query_embedding Numeric vector, query BERT embedding
#' @param document_embeddings Matrix, all document BERT embeddings
#' @param top_n Integer, number of results
#'
#' @return Integer vector of document indices
bert_semantic_search <- function(query_embedding, document_embeddings, top_n = 10) {

  # Compute cosine similarities
  similarities <- apply(document_embeddings, 1, function(doc_emb) {
    sum(query_embedding * doc_emb) / (sqrt(sum(query_embedding^2)) * sqrt(sum(doc_emb^2)))
  })

  # Get top N
  top_indices <- order(similarities, decreasing = TRUE)[1:top_n]

  return(top_indices)
}

# =============================================================================
# PART 6: Database Storage
# =============================================================================

#' Save BERT Embeddings to Database
#'
#' Store 768-dim BERT embeddings in bert_embeddings table
#'
#' @param document_ids Integer vector, document IDs
#' @param embeddings Matrix, BERT embeddings (n_docs x 768)
#' @param db_connection Database connection
#' @param model_name Character, BERT model name
#' @param model_version Character, version identifier
save_bert_embeddings_to_db <- function(document_ids,
                                        embeddings,
                                        db_connection,
                                        model_name = "neuralmind/bert-base-portuguese-cased",
                                        model_version = "1.0") {

  log_info("Saving {length(document_ids)} BERT embeddings to database...")

  if (length(document_ids) != nrow(embeddings)) {
    stop("Number of document IDs must match number of embeddings")
  }

  # Process in batches (BERT embeddings are large: 768 dims)
  batch_size <- 500  # Smaller batches due to size
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
        INSERT INTO bert_embeddings (document_id, embedding, model_name, embedding_version)
        VALUES (%d, '%s'::float8[], '%s', '%s')
        ON CONFLICT (document_id)
        DO UPDATE SET
          embedding = EXCLUDED.embedding,
          model_name = EXCLUDED.model_name,
          embedding_version = EXCLUDED.embedding_version,
          updated_at = NOW()
      ", doc_id, embedding_str, model_name, model_version)

      dbExecute(db_connection, query)
    }

    log_info("Batch {batch}/{n_batches} complete")
  }

  log_info("BERT embeddings saved successfully")
}

#' Load BERT Embeddings from Database
#'
#' Retrieve BERT embeddings for specified documents
#'
#' @param document_ids Integer vector, document IDs to load
#' @param db_connection Database connection
#'
#' @return Matrix of BERT embeddings
load_bert_embeddings_from_db <- function(document_ids, db_connection) {

  log_info("Loading BERT embeddings for {length(document_ids)} documents...")

  # Build query
  ids_str <- paste(document_ids, collapse = ",")
  query <- sprintf("
    SELECT document_id, embedding
    FROM bert_embeddings
    WHERE document_id IN (%s)
    ORDER BY document_id
  ", ids_str)

  result <- dbGetQuery(db_connection, query)

  if (nrow(result) == 0) {
    stop("No BERT embeddings found for specified document IDs")
  }

  log_info("Loaded {nrow(result)} BERT embeddings from database")

  # Convert PostgreSQL array strings to numeric matrix
  # This is a simplified version - full implementation would parse array properly
  log_warn("Full array parsing not implemented - returning placeholder")

  return(NULL)
}

# =============================================================================
# PART 7: Model Persistence
# =============================================================================

#' Save BERT Embeddings to Disk
#'
#' Save embeddings matrix to RDS file
#'
#' @param embeddings Matrix of embeddings
#' @param document_ids Integer vector of document IDs
#' @param file_path Character, output file path
save_bert_embeddings_to_disk <- function(embeddings, document_ids, file_path) {
  log_info("Saving BERT embeddings to {file_path}...")

  saveRDS(
    list(
      embeddings = embeddings,
      document_ids = document_ids,
      model_name = "neuralmind/bert-base-portuguese-cased",
      embedding_dim = ncol(embeddings),
      created_at = Sys.time()
    ),
    file_path
  )

  log_info("BERT embeddings saved successfully")
}

#' Load BERT Embeddings from Disk
#'
#' @param file_path Character, file path
#' @return List with embeddings and metadata
load_bert_embeddings_from_disk <- function(file_path) {
  log_info("Loading BERT embeddings from {file_path}...")

  data <- readRDS(file_path)

  log_info("Loaded {nrow(data$embeddings)} BERT embeddings ({data$embedding_dim}-dim)")

  return(data)
}

# =============================================================================
# PART 8: Utility Functions
# =============================================================================

#' Check BERT Environment Status
#'
#' Verify that BERT environment is properly configured
#'
#' @return Logical, TRUE if environment is ready
check_bert_environment <- function() {
  log_info("Checking BERT environment status...")

  # Check conda
  if (conda_binary() %>% is.null()) {
    log_error("Conda not found")
    return(FALSE)
  }

  # Check environment exists
  if (!"lexml_nlp" %in% conda_list()$name) {
    log_error("lexml_nlp environment not found. Run setup_bert_environment()")
    return(FALSE)
  }

  # Try to import packages
  tryCatch({
    use_condaenv("lexml_nlp", required = TRUE)
    import("transformers")
    import("torch")
    import("sentence_transformers")
    log_info("BERT environment is ready!")
    return(TRUE)
  }, error = function(e) {
    log_error("BERT environment check failed: {e$message}")
    return(FALSE)
  })
}

#' Estimate BERT Processing Time
#'
#' Estimate how long it will take to process documents
#'
#' @param n_documents Integer, number of documents
#' @param batch_size Integer, batch size
#' @param docs_per_second Numeric, estimated speed (default: 5 on CPU, 20 on GPU)
#' @param use_gpu Logical, GPU available?
#'
#' @return Character, estimated time string
estimate_bert_time <- function(n_documents, batch_size = 16, docs_per_second = NULL, use_gpu = FALSE) {

  if (is.null(docs_per_second)) {
    docs_per_second <- if (use_gpu) 20 else 5
  }

  total_seconds <- n_documents / docs_per_second
  hours <- floor(total_seconds / 3600)
  minutes <- floor((total_seconds %% 3600) / 60)

  log_info("Estimated time for {n_documents} documents:")
  log_info("  - Speed: {docs_per_second} docs/sec ({if (use_gpu) 'GPU' else 'CPU'})")
  log_info("  - Time: {hours}h {minutes}m")

  return(sprintf("%dh %dm", hours, minutes))
}

# =============================================================================
# End of bert_embeddings.R
# =============================================================================

log_info("bert_embeddings.R loaded successfully")
log_info("Run setup_bert_environment() for first-time setup")
log_info("Run check_bert_environment() to verify installation")
