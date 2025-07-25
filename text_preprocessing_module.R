# Text Preprocessing Module for Brazilian Legislative Documents
# MackMonitor v4 - Modular Text Analysis Pipeline
# Author: Analytics Module
# Date: 2025-01-25

library(tm)
library(quanteda)
library(tidytext)
library(stringr)
library(dplyr)
library(purrr)
library(future)
library(furrr)

# Configure parallel processing
plan(multisession, workers = availableCores() - 1)

# ============================================================================
# 1. CONFIGURATION AND SETUP
# ============================================================================

# Default preprocessing configuration
PREPROCESSING_CONFIG <- list(
  # Language settings
  language = "pt",
  
  # Tokenization settings
  remove_punct = TRUE,
  remove_numbers = TRUE,
  remove_symbols = TRUE,
  remove_separators = TRUE,
  remove_url = TRUE,
  
  # Case and whitespace
  tolower = TRUE,
  remove_whitespace = TRUE,
  
  # Stopwords
  use_stopwords = TRUE,
  custom_stopwords_file = "config/legal_stopwords_pt.txt",
  
  # Stemming
  use_stemming = TRUE,
  stemmer = "portuguese",
  
  # N-grams
  ngram_range = c(1, 2),
  
  # Document length filters
  min_doc_length = 10,
  max_doc_length = 10000,
  
  # Frequency filters
  min_term_freq = 5,
  max_term_freq = 0.95,  # Remove terms in >95% of docs
  
  # Legal boilerplate patterns
  remove_boilerplate = TRUE,
  boilerplate_patterns = c(
    "o presidente da república",
    "faço saber que o congresso nacional decreta",
    "esta lei entra em vigor",
    "revogam-se as disposições em contrário",
    "publicada no diário oficial"
  )
)

# ============================================================================
# 2. STOPWORD MANAGEMENT
# ============================================================================

#' Load and combine stopwords from multiple sources
#' @param config Preprocessing configuration list
#' @return Character vector of stopwords
load_stopwords <- function(config = PREPROCESSING_CONFIG) {
  # Base Portuguese stopwords
  base_stopwords <- stopwords("portuguese", source = "stopwords-iso")
  
  # Legal domain stopwords
  legal_stopwords <- c(
    "lei", "decreto", "artigo", "parágrafo", "inciso", "alínea",
    "caput", "federal", "estadual", "municipal", "união", "estado",
    "município", "competência", "atribuição", "disposição", "vigor"
  )
  
  # Custom stopwords from file if exists
  custom_stopwords <- c()
  if (!is.null(config$custom_stopwords_file) && 
      file.exists(config$custom_stopwords_file)) {
    custom_stopwords <- readLines(config$custom_stopwords_file, 
                                 encoding = "UTF-8", warn = FALSE)
  }
  
  # Combine all stopwords
  all_stopwords <- unique(c(base_stopwords, legal_stopwords, custom_stopwords))
  
  return(all_stopwords)
}

# ============================================================================
# 3. TEXT CLEANING FUNCTIONS
# ============================================================================

#' Clean individual document text
#' @param text Character string to clean
#' @param config Preprocessing configuration
#' @return Cleaned text
clean_text <- function(text, config = PREPROCESSING_CONFIG) {
  if (is.na(text) || text == "") return("")
  
  # Convert to lowercase
  if (config$tolower) {
    text <- tolower(text)
  }
  
  # Remove URLs
  if (config$remove_url) {
    text <- str_replace_all(text, "https?://[\\w\\.-]+[\\w/]*", " ")
    text <- str_replace_all(text, "www\\.[\\w\\.-]+[\\w/]*", " ")
  }
  
  # Remove email addresses
  text <- str_replace_all(text, "[\\w\\.-]+@[\\w\\.-]+", " ")
  
  # Remove legal boilerplate
  if (config$remove_boilerplate && !is.null(config$boilerplate_patterns)) {
    for (pattern in config$boilerplate_patterns) {
      text <- str_replace_all(text, pattern, " ")
    }
  }
  
  # Remove special characters but keep Portuguese diacritics
  text <- str_replace_all(text, "[^a-záàâãéèêíïóôõöúçñ\\s-]", " ")
  
  # Normalize whitespace
  if (config$remove_whitespace) {
    text <- str_replace_all(text, "\\s+", " ")
    text <- str_trim(text)
  }
  
  return(text)
}

#' Remove legal citations and references
#' @param text Character string
#' @return Text with citations removed
remove_legal_citations <- function(text) {
  # Remove law citations (e.g., "Lei nº 12.345/2020")
  text <- str_replace_all(text, 
    "lei\\s+n[º°]?\\s*\\d+\\.?\\d*/?\\d*", " ")
  
  # Remove decree citations
  text <- str_replace_all(text, 
    "decreto\\s+n[º°]?\\s*\\d+\\.?\\d*/?\\d*", " ")
  
  # Remove article references
  text <- str_replace_all(text, 
    "art(igo)?\\s*\\.?\\s*\\d+[º°]?", " ")
  
  # Remove date patterns
  text <- str_replace_all(text, 
    "\\d{1,2}\\s+de\\s+\\w+\\s+de\\s+\\d{4}", " ")
  
  return(text)
}

# ============================================================================
# 4. TOKENIZATION AND PROCESSING
# ============================================================================

#' Tokenize documents using quanteda
#' @param texts Character vector of texts
#' @param config Preprocessing configuration
#' @return Document-feature matrix
tokenize_documents <- function(texts, config = PREPROCESSING_CONFIG) {
  # Create corpus
  corp <- corpus(texts)
  
  # Tokenize
  toks <- tokens(corp,
    remove_punct = config$remove_punct,
    remove_symbols = config$remove_symbols,
    remove_numbers = config$remove_numbers,
    remove_url = config$remove_url,
    remove_separators = config$remove_separators
  )
  
  # Remove stopwords
  if (config$use_stopwords) {
    stopwords_list <- load_stopwords(config)
    toks <- tokens_remove(toks, stopwords_list)
  }
  
  # Apply stemming
  if (config$use_stemming) {
    toks <- tokens_wordstem(toks, language = config$stemmer)
  }
  
  # Create n-grams if specified
  if (!is.null(config$ngram_range) && length(config$ngram_range) == 2) {
    if (config$ngram_range[2] > 1) {
      toks <- tokens_ngrams(toks, n = config$ngram_range[1]:config$ngram_range[2])
    }
  }
  
  # Create document-feature matrix
  dfm_result <- dfm(toks)
  
  # Apply frequency trimming
  if (!is.null(config$min_term_freq) || !is.null(config$max_term_freq)) {
    min_freq <- config$min_term_freq %||% 1
    max_prop <- config$max_term_freq %||% 1.0
    
    dfm_result <- dfm_trim(dfm_result, 
                          min_termfreq = min_freq,
                          max_docfreq = max_prop,
                          docfreq_type = "prop")
  }
  
  return(dfm_result)
}

# ============================================================================
# 5. BATCH PROCESSING FUNCTIONS
# ============================================================================

#' Process documents in batches
#' @param documents Data frame with document texts
#' @param text_column Name of text column
#' @param batch_size Number of documents per batch
#' @param config Preprocessing configuration
#' @return Processed document-feature matrix
process_documents_batch <- function(documents, 
                                   text_column = "conteudo",
                                   batch_size = 1000,
                                   config = PREPROCESSING_CONFIG) {
  
  total_docs <- nrow(documents)
  n_batches <- ceiling(total_docs / batch_size)
  
  cat(sprintf("Processing %d documents in %d batches...\n", total_docs, n_batches))
  
  # Split into batches
  batches <- split(documents, 
                   rep(1:n_batches, each = batch_size, length.out = total_docs))
  
  # Process each batch in parallel
  dfm_list <- future_map(batches, function(batch) {
    # Clean texts
    cleaned_texts <- map_chr(batch[[text_column]], clean_text, config = config)
    
    # Additional cleaning for legal texts
    if (config$remove_boilerplate) {
      cleaned_texts <- map_chr(cleaned_texts, remove_legal_citations)
    }
    
    # Filter by document length
    doc_lengths <- str_count(cleaned_texts, "\\w+")
    valid_docs <- doc_lengths >= config$min_doc_length & 
                  doc_lengths <= config$max_doc_length
    
    if (sum(valid_docs) == 0) {
      return(NULL)
    }
    
    # Tokenize valid documents
    dfm_batch <- tokenize_documents(cleaned_texts[valid_docs], config)
    
    # Add document metadata
    docvars(dfm_batch, "doc_id") <- batch$id[valid_docs]
    docvars(dfm_batch, "tipo") <- batch$tipo[valid_docs]
    docvars(dfm_batch, "authority_level") <- batch$authority_level[valid_docs]
    docvars(dfm_batch, "date") <- batch$data_publicacao[valid_docs]
    
    return(dfm_batch)
  }, .progress = TRUE)
  
  # Remove NULL results
  dfm_list <- dfm_list[!sapply(dfm_list, is.null)]
  
  # Combine all batches
  if (length(dfm_list) > 0) {
    combined_dfm <- do.call(rbind, dfm_list)
    return(combined_dfm)
  } else {
    return(NULL)
  }
}

# ============================================================================
# 6. PREPROCESSING PIPELINE
# ============================================================================

#' Main preprocessing pipeline
#' @param conn Database connection
#' @param limit Number of documents to process (NULL for all)
#' @param config Preprocessing configuration
#' @return List with processed data and metadata
preprocess_legislative_texts <- function(conn, 
                                       limit = NULL,
                                       config = PREPROCESSING_CONFIG) {
  
  cat("Starting legislative text preprocessing pipeline...\n")
  
  # Load documents from database
  query <- "
    SELECT 
      id,
      titulo,
      tipo,
      conteudo,
      authority_level,
      data_publicacao,
      urn,
      estado,
      municipality
    FROM documents
    WHERE conteudo IS NOT NULL 
    AND conteudo != ''
    AND LENGTH(conteudo) > 50
  "
  
  if (!is.null(limit)) {
    query <- paste(query, "LIMIT", limit)
  }
  
  documents <- dbGetQuery(conn, query)
  
  cat(sprintf("Loaded %d documents for preprocessing\n", nrow(documents)))
  
  # Process documents
  processed_dfm <- process_documents_batch(documents, 
                                         text_column = "conteudo",
                                         config = config)
  
  if (is.null(processed_dfm)) {
    stop("No valid documents after preprocessing")
  }
  
  # Create summary statistics
  summary_stats <- list(
    n_documents = ndoc(processed_dfm),
    n_features = nfeat(processed_dfm),
    sparsity = sparsity(processed_dfm),
    avg_doc_length = mean(rowSums(processed_dfm)),
    feature_stats = textstat_frequency(processed_dfm)
  )
  
  # Save preprocessing configuration for reproducibility
  preprocessing_log <- list(
    timestamp = Sys.time(),
    config = config,
    input_docs = nrow(documents),
    output_docs = ndoc(processed_dfm),
    features = nfeat(processed_dfm)
  )
  
  result <- list(
    dfm = processed_dfm,
    documents = documents[docvars(processed_dfm, "doc_id"), ],
    summary = summary_stats,
    log = preprocessing_log
  )
  
  cat("\nPreprocessing complete!\n")
  cat(sprintf("- Documents processed: %d\n", result$summary$n_documents))
  cat(sprintf("- Features extracted: %d\n", result$summary$n_features))
  cat(sprintf("- Sparsity: %.2f%%\n", result$summary$sparsity * 100))
  
  return(result)
}

# ============================================================================
# 7. EXPORT FUNCTIONS
# ============================================================================

#' Save preprocessing results
#' @param results Preprocessing results from pipeline
#' @param output_dir Directory to save results
save_preprocessing_results <- function(results, output_dir = "preprocessing_output") {
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Save DFM as sparse matrix
  saveRDS(results$dfm, file.path(output_dir, "document_feature_matrix.rds"))
  
  # Save document metadata
  write.csv(results$documents, 
            file.path(output_dir, "processed_documents.csv"), 
            row.names = FALSE)
  
  # Save summary statistics
  write.csv(results$summary$feature_stats, 
            file.path(output_dir, "feature_statistics.csv"), 
            row.names = FALSE)
  
  # Save preprocessing log
  saveRDS(results$log, file.path(output_dir, "preprocessing_log.rds"))
  
  cat(sprintf("\nResults saved to %s/\n", output_dir))
}

# ============================================================================
# 8. VALIDATION FUNCTIONS
# ============================================================================

#' Validate preprocessing results
#' @param results Preprocessing results
#' @return Validation report
validate_preprocessing <- function(results) {
  validation <- list()
  
  # Check for empty documents
  empty_docs <- which(rowSums(results$dfm) == 0)
  validation$empty_documents <- length(empty_docs)
  
  # Check feature distribution
  feature_counts <- colSums(results$dfm)
  validation$single_occurrence_features <- sum(feature_counts == 1)
  validation$rare_features <- sum(feature_counts < 5)
  
  # Check document lengths
  doc_lengths <- rowSums(results$dfm)
  validation$short_documents <- sum(doc_lengths < 10)
  validation$long_documents <- sum(doc_lengths > 1000)
  
  # Generate validation report
  cat("\n=== PREPROCESSING VALIDATION ===\n")
  cat(sprintf("Empty documents: %d\n", validation$empty_documents))
  cat(sprintf("Single occurrence features: %d\n", validation$single_occurrence_features))
  cat(sprintf("Rare features (<5 occurrences): %d\n", validation$rare_features))
  cat(sprintf("Very short documents (<10 terms): %d\n", validation$short_documents))
  cat(sprintf("Very long documents (>1000 terms): %d\n", validation$long_documents))
  
  return(validation)
}