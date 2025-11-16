# =============================================================================
# Sprint 3: Structural Topic Modeling (STM)
# =============================================================================
# Description: Discover latent topics in legislative corpus and model how
#              topic prevalence and content vary by jurisdiction, power, and time
# Version: 1.0
# Date: January 2025
# =============================================================================

library(stm)
library(quanteda)
library(tidytext)
library(dplyr)
library(ggplot2)
library(RPostgreSQL)
library(logger)

# =============================================================================
# PART 1: Data Preparation
# =============================================================================

#' Prepare Data for STM Training
#'
#' Load documents from database with metadata and prepare for STM
#'
#' @param db_connection Database connection object
#' @param sample_size Integer, optional sample size for testing (default: NULL = all docs)
#' @param min_length Integer, minimum document length in characters (default: 100)
#'
#' @return List with documents, vocab, and metadata ready for STM
#'
#' @examples
#' stm_data <- prepare_stm_data(db_pool, sample_size = 5000)  # Test with 5k docs
#' stm_data <- prepare_stm_data(db_pool)  # Full corpus
prepare_stm_data <- function(db_connection, sample_size = NULL, min_length = 100) {

  log_info("Preparing data for STM...")

  # Load documents with metadata
  log_info("Loading documents from database...")
  query <- "
    SELECT
      id,
      texto,
      tipo_documento,
      nivel,
      estado_mapeado,
      poder,
      EXTRACT(YEAR FROM data_publicacao)::integer AS ano,
      data_publicacao
    FROM documents
    WHERE texto IS NOT NULL
      AND nivel IS NOT NULL
      AND LENGTH(texto) > $1
      AND data_publicacao IS NOT NULL
    ORDER BY RANDOM()
  "

  if (!is.null(sample_size)) {
    query <- paste0(query, sprintf(" LIMIT %d", sample_size))
    log_info("Using sample of {sample_size} documents")
  }

  docs <- dbGetQuery(db_connection, query, params = list(min_length))
  log_info("Loaded {nrow(docs)} documents")

  if (nrow(docs) < 100) {
    stop("Insufficient documents for topic modeling. Need at least 100 documents.")
  }

  # Handle missing values in metadata
  docs$nivel[is.na(docs$nivel)] <- "Unknown"
  docs$poder[is.na(docs$poder)] <- "Unknown"
  docs$estado_mapeado[is.na(docs$estado_mapeado)] <- "BR"
  docs$ano[is.na(docs$ano)] <- median(docs$ano, na.rm = TRUE)

  # Log metadata summary
  log_info("Metadata summary:")
  log_info("  - Jurisdiction levels: {paste(unique(docs$nivel), collapse = ', ')}")
  log_info("  - Powers: {paste(unique(docs$poder), collapse = ', ')}")
  log_info("  - Year range: {min(docs$ano)} - {max(docs$ano)}")
  log_info("  - States: {length(unique(docs$estado_mapeado))} unique")

  # Process text using textProcessor
  log_info("Processing text with textProcessor()...")
  processed <- textProcessor(
    documents = docs$texto,
    metadata = docs %>% select(id, tipo_documento, nivel, estado_mapeado, poder, ano),
    lowercase = TRUE,
    removestopwords = TRUE,
    removenumbers = FALSE,  # Keep numbers (e.g., "lei123")
    removepunctuation = TRUE,
    stem = FALSE,  # Portuguese stemming can be problematic
    language = "pt",
    verbose = TRUE
  )

  log_info("Text processing complete")

  # Prepare documents
  log_info("Preparing documents with prepDocuments()...")
  out <- prepDocuments(
    documents = processed$documents,
    vocab = processed$vocab,
    meta = processed$meta,
    lower.thresh = 10,  # Remove words appearing in <10 docs
    upper.thresh = nrow(docs) * 0.95,  # Remove words in >95% of docs
    verbose = TRUE
  )

  log_info("Document preparation complete")
  log_info("Final corpus statistics:")
  log_info("  - Documents: {length(out$documents)}")
  log_info("  - Vocabulary size: {length(out$vocab)}")
  log_info("  - Removed documents: {nrow(docs) - length(out$documents)}")

  return(out)
}

# =============================================================================
# PART 2: Model Selection (Optimal K)
# =============================================================================

#' Select Optimal Number of Topics
#'
#' Run searchK to compare models with different numbers of topics
#'
#' @param stm_data Output from prepare_stm_data()
#' @param k_range Integer vector, range of K values to try (default: seq(10, 50, by = 5))
#' @param prevalence Formula, prevalence covariate formula
#' @param max_em_its Integer, maximum EM iterations per model
#'
#' @return searchK object with diagnostic plots and metrics
#'
#' @examples
#' search_results <- select_k_topics(stm_data, k_range = c(20, 25, 30))
select_k_topics <- function(stm_data,
                             k_range = seq(10, 50, by = 5),
                             prevalence = ~ nivel + s(ano),
                             max_em_its = 75) {

  log_info("Running searchK to find optimal number of topics...")
  log_info("Testing K values: {paste(k_range, collapse = ', ')}")

  # Run searchK
  search_results <- searchK(
    documents = stm_data$documents,
    vocab = stm_data$vocab,
    K = k_range,
    prevalence = prevalence,
    data = stm_data$meta,
    max.em.its = max_em_its,
    init.type = "Spectral",
    verbose = TRUE
  )

  log_info("searchK complete!")

  # Plot diagnostics
  log_info("Plotting diagnostic metrics...")
  plot(search_results)

  # Print summary
  log_info("Summary of metrics:")
  print(search_results$results)

  # Recommendation
  log_info("\nInterpretation Guide:")
  log_info("  - Semantic Coherence: Higher is better (words in topics co-occur)")
  log_info("  - Exclusivity: Higher is better (topics are distinct)")
  log_info("  - Residuals: Lower is better (model fit)")
  log_info("  - Trade-off: Balance coherence and exclusivity")

  return(search_results)
}

# =============================================================================
# PART 3: Model Training
# =============================================================================

#' Fit STM with Prevalence and Content Covariates
#'
#' Train Structural Topic Model with specified covariates
#'
#' @param stm_data Output from prepare_stm_data()
#' @param K Integer, number of topics
#' @param prevalence Formula, how topic prevalence varies (default: ~ nivel + poder + s(ano))
#' @param content Formula, how topic content varies (default: ~ nivel)
#' @param max_em_its Integer, maximum EM iterations
#' @param init_type Character, initialization method ("Spectral" or "LDA")
#'
#' @return STM model object
#'
#' @examples
#' model <- fit_stm_model(stm_data, K = 30)
fit_stm_model <- function(stm_data,
                           K = 30,
                           prevalence = ~ nivel + poder + s(ano),
                           content = ~ nivel,
                           max_em_its = 75,
                           init_type = "Spectral") {

  log_info("Fitting STM model with K = {K} topics...")
  log_info("Prevalence formula: {deparse(prevalence)}")
  log_info("Content formula: {deparse(content)}")

  start_time <- Sys.time()

  # Fit model
  model <- stm(
    documents = stm_data$documents,
    vocab = stm_data$vocab,
    K = K,
    prevalence = prevalence,
    content = content,
    data = stm_data$meta,
    max.em.its = max_em_its,
    init.type = init_type,
    seed = 42,  # For reproducibility
    verbose = TRUE
  )

  elapsed <- difftime(Sys.time(), start_time, units = "mins")
  log_info("STM training complete in {round(elapsed, 2)} minutes")

  # Log model summary
  log_info("\nModel Summary:")
  log_info("  - Number of topics: {model$settings$dim$K}")
  log_info("  - Number of documents: {model$settings$dim$N}")
  log_info("  - Vocabulary size: {model$settings$dim$V}")
  log_info("  - Convergence: {model$convergence$converged}")

  return(model)
}

# =============================================================================
# PART 4: Covariate Effects Estimation
# =============================================================================

#' Estimate Effects of Covariates on Topic Prevalence
#'
#' Compute how jurisdiction, power, and time affect topic prevalence
#'
#' @param model STM model object
#' @param stm_data STM data object
#' @param formula Formula for effects (default: all topics ~ all covariates)
#'
#' @return estimateEffect object
estimate_covariate_effects <- function(model,
                                        stm_data,
                                        formula = 1:model$settings$dim$K ~ nivel + poder + s(ano)) {

  log_info("Estimating covariate effects on topic prevalence...")

  start_time <- Sys.time()

  effects <- estimateEffect(
    formula = formula,
    stmobj = model,
    metadata = stm_data$meta,
    uncertainty = "Global"
  )

  elapsed <- difftime(Sys.time(), start_time, units = "mins")
  log_info("Effect estimation complete in {round(elapsed, 2)} minutes")

  return(effects)
}

# =============================================================================
# PART 5: Visualization
# =============================================================================

#' Visualize STM Results
#'
#' Create standard STM visualizations
#'
#' @param model STM model object
#' @param effects estimateEffect object (optional)
#' @param stm_data STM data object
#' @param output_dir Character, directory to save plots (default: "plots")
visualize_stm <- function(model, effects = NULL, stm_data = NULL, output_dir = "plots") {

  log_info("Creating STM visualizations...")

  if (!dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE)
  }

  # 1. Topic Labels (Top Words)
  log_info("1. Generating topic labels...")
  labels <- labelTopics(model, n = 10)
  print(labels)

  # 2. Topic Prevalence
  log_info("2. Plotting topic prevalence...")
  png(file.path(output_dir, "topic_prevalence.png"), width = 800, height = 600)
  plot(model, type = "summary", xlim = c(0, 0.3), main = "Topic Prevalence")
  dev.off()

  # 3. Topic Correlations
  log_info("3. Computing topic correlations...")
  topic_corr <- topicCorr(model)

  png(file.path(output_dir, "topic_correlations.png"), width = 1000, height = 1000)
  plot(topic_corr, vertex.label.cex = 0.8, main = "Topic Correlation Network")
  dev.off()

  # 4. Word Clouds for Top Topics
  log_info("4. Creating word clouds for top 5 topics...")
  for (topic_num in 1:min(5, model$settings$dim$K)) {
    png(file.path(output_dir, sprintf("wordcloud_topic%02d.png", topic_num)),
        width = 800, height = 600)
    cloud(model, topic = topic_num, scale = c(4, 0.5))
    dev.off()
  }

  # 5. Covariate Effects (if provided)
  if (!is.null(effects)) {
    log_info("5. Plotting covariate effects...")

    # Effect of jurisdiction level
    png(file.path(output_dir, "effect_jurisdiction.png"), width = 1200, height = 800)
    plot(effects,
         covariate = "nivel",
         topics = c(1:min(9, model$settings$dim$K)),
         model = model,
         method = "difference",
         cov.value1 = "Federal",
         cov.value2 = "Estadual",
         xlim = c(-0.15, 0.15),
         main = "Effect of Jurisdiction Level (Federal vs. State)",
         xlab = "Change in Topic Prevalence",
         labeltype = "frex")
    dev.off()

    # Effect of time
    if ("ano" %in% colnames(stm_data$meta)) {
      png(file.path(output_dir, "effect_time.png"), width = 1200, height = 800)
      plot(effects,
           covariate = "ano",
           topics = c(1:min(9, model$settings$dim$K)),
           model = model,
           method = "continuous",
           main = "Topic Prevalence Over Time",
           xlab = "Year",
           labeltype = "frex")
      dev.off()
    }
  }

  log_info("Visualizations saved to {output_dir}/")
}

# =============================================================================
# PART 6: Topic Interpretation
# =============================================================================

#' Find Representative Documents for a Topic
#'
#' Get documents with highest proportion of a given topic
#'
#' @param model STM model object
#' @param stm_data STM data object
#' @param topic_num Integer, topic number
#' @param n Integer, number of representative documents
#'
#' @return Data frame with document metadata and topic proportion
find_representative_docs <- function(model, stm_data, topic_num, n = 5) {

  log_info("Finding representative documents for Topic {topic_num}...")

  # Get document-topic proportions (theta)
  theta <- model$theta

  # Find documents with highest proportion for this topic
  top_doc_indices <- order(theta[, topic_num], decreasing = TRUE)[1:n]

  # Get metadata
  representative_docs <- stm_data$meta[top_doc_indices, ]
  representative_docs$topic_proportion <- theta[top_doc_indices, topic_num]
  representative_docs$topic_number <- topic_num

  # Get original texts
  texts <- sapply(stm_data$documents[top_doc_indices], function(doc) {
    paste(stm_data$vocab[doc[1, ]], collapse = " ")
  })
  representative_docs$text_preview <- substr(texts, 1, 200)

  return(representative_docs)
}

#' Generate Topic Labels
#'
#' Create human-readable labels for topics based on top words
#'
#' @param model STM model object
#' @param method Character, labeling method ("prob", "frex", "lift", "score")
#' @param n_words Integer, number of words per label
#'
#' @return Character vector of topic labels
generate_topic_labels <- function(model, method = "frex", n_words = 3) {

  labels <- labelTopics(model, n = n_words)

  if (method == "prob") {
    words <- labels$prob
  } else if (method == "frex") {
    words <- labels$frex
  } else if (method == "lift") {
    words <- labels$lift
  } else if (method == "score") {
    words <- labels$score
  } else {
    stop("Invalid method. Use 'prob', 'frex', 'lift', or 'score'")
  }

  # Create labels from top words
  topic_labels <- apply(words, 1, function(w) {
    paste(w[1:n_words], collapse = " + ")
  })

  names(topic_labels) <- paste0("Topic ", 1:length(topic_labels))

  return(topic_labels)
}

# =============================================================================
# PART 7: Database Storage
# =============================================================================

#' Save STM Model to Database
#'
#' Store model metadata, topics, and document-topic proportions in database
#'
#' @param model STM model object
#' @param stm_data STM data object
#' @param effects estimateEffect object (optional)
#' @param db_connection Database connection
#' @param model_name Character, model name for identification
#' @param model_path Character, GCS path where model .rds is saved
save_stm_to_db <- function(model,
                            stm_data,
                            effects = NULL,
                            db_connection,
                            model_name = "default",
                            model_path = NULL) {

  log_info("Saving STM model to database...")

  # 1. Save model metadata
  log_info("Saving model metadata...")

  # Calculate quality metrics
  model_quality <- semanticCoherence(model, stm_data$documents)
  exclusivity_scores <- exclusivity(model)

  prevalence_formula <- deparse(model$settings$covariates$formula)
  content_formula <- if (!is.null(model$settings$gamma$mode)) {
    deparse(model$settings$gamma$formula)
  } else {
    NA
  }

  query_model <- sprintf("
    INSERT INTO stm_models
      (model_name, num_topics, model_version, prevalence_formula, content_formula,
       model_path, semantic_coherence, exclusivity, num_documents, vocabulary_size)
    VALUES ('%s', %d, '1.0', '%s', '%s', '%s', %f, %f, %d, %d)
    RETURNING id
  ",
    model_name,
    model$settings$dim$K,
    prevalence_formula,
    ifelse(is.na(content_formula), "NULL", paste0("'", content_formula, "'")),
    ifelse(is.null(model_path), "NULL", paste0("'", model_path, "'")),
    mean(model_quality),
    mean(exclusivity_scores),
    model$settings$dim$N,
    model$settings$dim$V
  )

  model_id <- dbGetQuery(db_connection, query_model)$id
  log_info("Model saved with ID: {model_id}")

  # 2. Save topics
  log_info("Saving topics...")

  topic_labels <- generate_topic_labels(model, method = "frex", n_words = 3)
  label_data <- labelTopics(model, n = 20)

  # Get expected topic proportions
  expected_props <- colMeans(model$theta)

  for (topic_num in 1:model$settings$dim$K) {
    top_words <- label_data$prob[topic_num, ]
    frex_words <- label_data$frex[topic_num, ]

    query_topic <- sprintf("
      INSERT INTO stm_topics
        (model_id, topic_number, topic_label_auto, top_words, top_words_frex, expected_proportion)
      VALUES (%d, %d, '%s', '{%s}', '{%s}', %f)
    ",
      model_id,
      topic_num,
      topic_labels[topic_num],
      paste(top_words, collapse = ","),
      paste(frex_words, collapse = ","),
      expected_props[topic_num]
    )

    dbExecute(db_connection, query_topic)
  }

  log_info("Topics saved")

  # 3. Save document-topic proportions
  log_info("Saving document-topic proportions...")

  theta <- model$theta

  for (i in seq_len(nrow(theta))) {
    doc_id <- stm_data$meta$id[i]

    # Get top 5 topics for this document
    top_topics <- order(theta[i, ], decreasing = TRUE)[1:5]

    for (rank in seq_along(top_topics)) {
      topic_num <- top_topics[rank]
      proportion <- theta[i, topic_num]

      query_doc_topic <- sprintf("
        INSERT INTO document_topics
          (document_id, model_id, topic_number, proportion, rank_position)
        VALUES (%d, %d, %d, %f, %d)
        ON CONFLICT (document_id, model_id, topic_number)
        DO UPDATE SET proportion = EXCLUDED.proportion, rank_position = EXCLUDED.rank_position
      ", doc_id, model_id, topic_num, proportion, rank)

      dbExecute(db_connection, query_doc_topic)
    }

    if (i %% 1000 == 0) {
      log_info("Processed {i}/{nrow(theta)} documents...")
    }
  }

  log_info("Document-topic proportions saved")

  # 4. Save covariate effects (if provided)
  if (!is.null(effects)) {
    log_info("Saving covariate effects...")

    # This is simplified - full implementation would extract all effect estimates
    # from the estimateEffect object and save them systematically

    log_info("Covariate effects extraction not fully implemented yet")
  }

  log_info("STM model saved to database successfully!")
  return(model_id)
}

# =============================================================================
# PART 8: Model Persistence
# =============================================================================

#' Save STM Model to Disk
#'
#' @param model STM model object
#' @param file_path Character, path to save model
save_stm_model <- function(model, file_path) {
  log_info("Saving STM model to {file_path}...")
  saveRDS(model, file_path)
  log_info("Model saved successfully")
}

#' Load STM Model from Disk
#'
#' @param file_path Character, path to model file
#' @return STM model object
load_stm_model <- function(file_path) {
  log_info("Loading STM model from {file_path}...")
  model <- readRDS(file_path)
  log_info("Model loaded successfully")
  return(model)
}

# =============================================================================
# End of structural_topic_modeling.R
# =============================================================================

log_info("structural_topic_modeling.R loaded successfully")
