# ============================================================================
# ADVANCED TOPIC MODELING AND SENTIMENT ANALYSIS
# Brazilian Legislative Monitoring System - Enhanced Text Analytics (Part 2)
# Author: Legislative Data Science Framework  
# Date: 2025-09-01
# Description: Advanced topic modeling with BERTopic/LDA and specialized
#              sentiment analysis for Portuguese legal/policy language
# ============================================================================

# Source the main NLP system
source("src/enhanced_brazilian_legal_nlp_system.R")

# Additional specialized libraries
suppressPackageStartupMessages({
  library(reticulate)     # Python integration for BERTopic
  library(ldatuning)      # LDA model tuning
  library(topicdoc)       # Topic model diagnostics
  library(keyATM)         # Keyword-assisted topic modeling
  library(seededlda)      # Seeded LDA for guided topic modeling
  library(textmineR)      # Topic model coherence calculation
  library(corrplot)       # Correlation visualization
  library(pheatmap)       # Heatmap visualization
  library(ggraph)         # Network graph visualization
  library(tidygraph)      # Tidy graph data manipulation
  library(ggalluvial)     # Alluvial plots for topic flows
  library(gganimate)      # Animated visualizations
  library(patchwork)      # Plot composition
  library(scales)         # Scale functions for ggplot2
})

# Advanced Topic Modeling System ============================================

#' Advanced Multi-Method Topic Modeling for Legal Documents
#' 
#' Implements multiple topic modeling approaches (LDA, STM, BERTopic, KeyATM)
#' with comprehensive model selection, validation, and coherence evaluation
#' optimized for large-scale Portuguese legal corpus analysis
#' 
#' @param texts Vector of preprocessed texts
#' @param metadata Document metadata (optional)
#' @param methods Vector of methods to use c("lda", "stm", "bertopic", "keyatm")
#' @param topic_range Range of topic numbers to test
#' @param validation_method Model validation approach
#' @param seed_topics Optional seed topics for guided modeling
#' @return Comprehensive topic modeling results with model comparison
advanced_legal_topic_modeling <- function(texts, 
                                         metadata = NULL,
                                         methods = c("lda", "stm", "keyatm"),
                                         topic_range = c(5, 50),
                                         validation_method = "coherence",
                                         seed_topics = NULL) {
  
  start_time <- Sys.time()
  cat("📚 Advanced Multi-Method Topic Modeling for Legal Documents\n")
  cat("📊 Processing", length(texts), "documents with", length(methods), "methods\n")
  cat("🎯 Testing topic range:", topic_range[1], "to", topic_range[2], "\n")
  
  # Initialize results structure
  modeling_results <- list(
    methods_used = methods,
    models = list(),
    model_comparisons = NULL,
    best_model = NULL,
    topic_evolution = NULL,
    semantic_validation = NULL,
    processing_metadata = list()
  )
  
  # Prepare text corpus for different modeling approaches
  cat("📋 Preparing corpus for multiple modeling methods...\n")
  
  # Create document-term matrix using quanteda
  corpus_quanteda <- corpus(texts)
  tokens_quanteda <- corpus_quanteda %>%
    tokens(what = "word", remove_punct = TRUE, remove_symbols = TRUE) %>%
    tokens_tolower() %>%
    tokens_remove(ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_legal_stopwords) %>%
    tokens_wordstem(language = "pt") %>%
    tokens_ngrams(n = 1:2, concatenator = "_")  # Include bigrams
  
  dfm_quanteda <- tokens_quanteda %>%
    dfm() %>%
    dfm_trim(min_docfreq = 5, max_docfreq = 0.95, docfreq_type = "prop") %>%
    dfm_trim(min_termfreq = 3)
  
  # Convert to various formats needed by different packages
  dtm_tm <- convert(dfm_quanteda, to = "tm")
  dtm_textminer <- convert(dfm_quanteda, to = "Matrix")
  
  cat("✅ Corpus prepared - Vocabulary:", ncol(dfm_quanteda), "terms\n")
  
  # Method 1: Enhanced Latent Dirichlet Allocation (LDA)
  if ("lda" %in% methods) {
    cat("🔍 Method 1: Enhanced LDA with comprehensive tuning...\n")
    modeling_results$models$lda <- enhanced_lda_modeling(
      dtm = dtm_tm,
      topic_range = topic_range,
      validation_method = validation_method
    )
  }
  
  # Method 2: Structural Topic Modeling (STM)
  if ("stm" %in% methods && !is.null(metadata)) {
    cat("🔍 Method 2: Structural Topic Modeling with metadata...\n")
    modeling_results$models$stm <- enhanced_stm_modeling(
      dfm = dfm_quanteda,
      metadata = metadata,
      topic_range = topic_range
    )
  }
  
  # Method 3: Keyword-Assisted Topic Modeling (keyATM)
  if ("keyatm" %in% methods) {
    cat("🔍 Method 3: Keyword-Assisted Topic Modeling...\n")
    modeling_results$models$keyatm <- enhanced_keyatm_modeling(
      texts = texts,
      topic_range = topic_range,
      seed_topics = seed_topics
    )
  }
  
  # Method 4: BERTopic (if Python environment available)
  if ("bertopic" %in% methods) {
    cat("🔍 Method 4: BERTopic with transformer models...\n")
    modeling_results$models$bertopic <- tryCatch({
      enhanced_bertopic_modeling(texts = texts, topic_range = topic_range)
    }, error = function(e) {
      cat("⚠️ BERTopic modeling failed:", e$message, "\n")
      NULL
    })
  }
  
  # Model comparison and selection
  cat("📊 Comparing models and selecting best approach...\n")
  modeling_results$model_comparisons <- compare_topic_models(modeling_results$models)
  modeling_results$best_model <- select_best_topic_model(modeling_results$models, modeling_results$model_comparisons)
  
  # Topic evolution analysis (if temporal metadata available)
  if (!isTRUE(is.null(metadata)) && "ano" %in% names(metadata)) {
    cat("📈 Analyzing topic evolution over time...\n")
    modeling_results$topic_evolution <- analyze_topic_evolution(
      best_model = modeling_results$best_model,
      metadata = metadata
    )
  }
  
  # Semantic validation and interpretation
  cat("🧠 Performing semantic validation and topic interpretation...\n")
  modeling_results$semantic_validation <- validate_topic_semantics(
    best_model = modeling_results$best_model,
    original_texts = texts
  )
  
  # Generate comprehensive processing metadata
  processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  modeling_results$processing_metadata <- list(
    documents_processed = length(texts),
    methods_applied = methods,
    vocabulary_size = ncol(dfm_quanteda),
    topic_range_tested = topic_range,
    best_model_method = modeling_results$best_model$method,
    best_model_topics = modeling_results$best_model$optimal_k,
    processing_time_minutes = processing_time,
    modeling_timestamp = Sys.time()
  )
  
  cat("🎉 Advanced topic modeling completed successfully!\n")
  cat("🏆 Best model:", modeling_results$best_model$method, "with", modeling_results$best_model$optimal_k, "topics\n")
  cat("⏱️ Total processing time:", round(processing_time, 2), "minutes\n")
  
  return(modeling_results)
}

#' Enhanced LDA Topic Modeling with Comprehensive Tuning
#' 
#' @param dtm Document-term matrix
#' @param topic_range Range of topics to test
#' @param validation_method Validation approach
#' @return Enhanced LDA results with model diagnostics
enhanced_lda_modeling <- function(dtm, topic_range, validation_method = "coherence") {
  
  # Generate sequence of topic numbers to test
  k_values <- seq(topic_range[1], topic_range[2], by = 5)
  
  # Comprehensive LDA tuning with multiple metrics
  cat("   🔬 Running comprehensive LDA tuning...\n")
  
  lda_tuning_results <- ldatuning::FindTopicsNumber(
    dtm = dtm,
    topics = k_values,
    metrics = c("Griffiths2004", "CaoJuan2009", "Arun2010", "Deveaud2014"),
    method = "Gibbs",
    control = list(
      seed = 1234,
      burnin = 1000,
      iter = 2000,
      keep = 100,
      verbose = FALSE
    ),
    verbose = TRUE
  )
  
  # Select optimal number of topics based on multiple criteria
  optimal_k <- select_optimal_k_lda(lda_tuning_results)
  
  cat("   🎯 Optimal number of topics:", optimal_k, "\n")
  
  # Fit final LDA model with optimal parameters
  final_lda_model <- topicmodels::LDA(
    dtm,
    k = optimal_k,
    method = "Gibbs",
    control = list(
      seed = 1234,
      burnin = 1000,
      iter = 3000,
      keep = 100,
      verbose = FALSE
    )
  )
  
  # Extract topic-term and document-topic distributions
  topic_terms <- tidytext::tidy(final_lda_model, matrix = "beta") %>%
    group_by(topic) %>%
    top_n(20, beta) %>%
    ungroup() %>%
    arrange(topic, -beta)
  
  document_topics <- tidytext::tidy(final_lda_model, matrix = "gamma") %>%
    group_by(document) %>%
    slice_max(gamma, n = 1) %>%
    ungroup()
  
  # Calculate topic coherence
  topic_coherence <- calculate_topic_coherence(final_lda_model, dtm)
  
  # Generate topic labels
  topic_labels <- generate_topic_labels(topic_terms, method = "top_terms")
  
  return(list(
    model = final_lda_model,
    optimal_k = optimal_k,
    tuning_results = lda_tuning_results,
    topic_terms = topic_terms,
    document_topics = document_topics,
    topic_coherence = topic_coherence,
    topic_labels = topic_labels,
    method = "lda"
  ))
}

#' Enhanced Structural Topic Modeling
#' 
#' @param dfm Document-feature matrix
#' @param metadata Document metadata
#' @param topic_range Range of topics to test
#' @return STM results with prevalence and content effects
enhanced_stm_modeling <- function(dfm, metadata, topic_range) {
  
  # Convert dfm to STM format
  stm_corpus <- quanteda::convert(dfm, to = "stm")
  
  # Prepare metadata for STM
  stm_metadata <- metadata %>%
    mutate(
      year_group = case_when(
        ano < 2000 ~ "pre_2000",
        ano < 2010 ~ "2000s",
        ano < 2020 ~ "2010s", 
        TRUE ~ "2020s"
      ),
      category_clean = str_to_lower(str_trim(categoria))
    )
  
  # Search for optimal number of topics
  cat("   🔍 STM topic number selection...\n")
  k_values <- seq(topic_range[1], topic_range[2], by = 10)
  
  stm_search <- stm::searchK(
    stm_corpus$documents,
    stm_corpus$vocab,
    K = k_values,
    prevalence = ~ category_clean + year_group,
    data = stm_metadata,
    init.type = "Spectral",
    verbose = FALSE
  )
  
  # Select optimal K based on exclusivity and semantic coherence
  optimal_k_stm <- k_values[which.max(stm_search$results$exclus + stm_search$results$semcoh)]
  
  # Fit final STM model
  cat("   📊 Fitting final STM model with K =", optimal_k_stm, "\n")
  
  final_stm_model <- stm::stm(
    stm_corpus$documents,
    stm_corpus$vocab,
    K = optimal_k_stm,
    prevalence = ~ category_clean + year_group,
    data = stm_metadata,
    init.type = "Spectral",
    verbose = FALSE
  )
  
  # Calculate topic effects and correlations
  prevalence_effects <- stm::estimateEffect(
    1:optimal_k_stm ~ category_clean + year_group,
    final_stm_model,
    meta = stm_metadata
  )
  
  topic_correlations <- stm::topicCorr(final_stm_model)
  
  return(list(
    model = final_stm_model,
    optimal_k = optimal_k_stm,
    search_results = stm_search,
    prevalence_effects = prevalence_effects,
    topic_correlations = topic_correlations,
    method = "stm"
  ))
}

# Advanced Regulatory Sentiment Analysis System ============================

#' Advanced Regulatory Sentiment Analysis for Portuguese Legal Texts
#' 
#' Comprehensive sentiment analysis specialized for Portuguese legal and policy
#' language with regulatory strictness assessment, temporal analysis, and
#' legal domain-specific sentiment classification
#' 
#' @param texts Vector of preprocessed texts
#' @param metadata Document metadata with temporal and categorical information
#' @param method Sentiment analysis method c("lexicon", "transformer", "hybrid")
#' @return Comprehensive sentiment analysis results
advanced_regulatory_sentiment_analysis <- function(texts, 
                                                  metadata = NULL,
                                                  method = "hybrid") {
  
  start_time <- Sys.time()
  cat("😊 Advanced Regulatory Sentiment Analysis\n")
  cat("📊 Processing", length(texts), "legal documents\n")
  cat("🎯 Using", method, "approach for sentiment classification\n")
  
  # Initialize results structure
  sentiment_results <- list(
    sentiment_scores = NULL,
    regulatory_strictness = NULL,
    legal_sentiment_distribution = NULL,
    temporal_sentiment_trends = NULL,
    domain_specific_analysis = NULL,
    sentiment_drivers = NULL,
    processing_metadata = list()
  )
  
  # Core sentiment analysis using multiple approaches
  cat("📊 Computing multi-dimensional sentiment scores...\n")
  
  sentiment_results$sentiment_scores <- compute_multidimensional_sentiment(texts, method)
  
  # Regulatory strictness assessment
  cat("⚖️ Assessing regulatory strictness and policy tone...\n")
  
  sentiment_results$regulatory_strictness <- assess_regulatory_strictness(
    texts = texts,
    base_sentiment = sentiment_results$sentiment_scores
  )
  
  # Legal domain-specific sentiment classification
  cat("🏛️ Performing legal domain-specific sentiment analysis...\n")
  
  sentiment_results$domain_specific_analysis <- analyze_legal_domain_sentiment(
    texts = texts,
    metadata = metadata,
    base_sentiment = sentiment_results$sentiment_scores
  )
  
  # Temporal sentiment trends (if metadata available)
  if (!isTRUE(is.null(metadata)) && "ano" %in% names(metadata)) {
    cat("📈 Analyzing temporal sentiment trends...\n")
    
    sentiment_results$temporal_sentiment_trends <- analyze_temporal_sentiment_trends(
      sentiment_scores = sentiment_results$sentiment_scores,
      metadata = metadata
    )
  }
  
  # Sentiment distribution analysis
  cat("📊 Computing sentiment distribution statistics...\n")
  
  sentiment_results$legal_sentiment_distribution <- compute_sentiment_distribution(
    sentiment_results$sentiment_scores,
    metadata
  )
  
  # Identify key sentiment drivers
  cat("🔍 Identifying key sentiment drivers and lexical patterns...\n")
  
  sentiment_results$sentiment_drivers <- identify_sentiment_drivers(
    texts = texts,
    sentiment_scores = sentiment_results$sentiment_scores
  )
  
  # Generate processing metadata
  processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  
  sentiment_results$processing_metadata <- list(
    documents_processed = length(texts),
    method_used = method,
    average_sentiment = mean(sentiment_results$sentiment_scores$compound_sentiment, na.rm = TRUE),
    sentiment_variance = var(sentiment_results$sentiment_scores$compound_sentiment, na.rm = TRUE),
    regulatory_strictness_mean = mean(sentiment_results$regulatory_strictness$strictness_index, na.rm = TRUE),
    processing_time_minutes = processing_time,
    analysis_timestamp = Sys.time()
  )
  
  cat("🎉 Advanced sentiment analysis completed successfully!\n")
  cat("📊 Average sentiment:", round(sentiment_results$processing_metadata$average_sentiment, 3), "\n")
  cat("⚖️ Average regulatory strictness:", round(sentiment_results$processing_metadata$regulatory_strictness_mean, 3), "\n")
  cat("⏱️ Processing time:", round(processing_time, 2), "minutes\n")
  
  return(sentiment_results)
}

#' Compute Multi-dimensional Sentiment Scores
#' 
#' @param texts Vector of texts
#' @param method Analysis method
#' @return Multi-dimensional sentiment scores
compute_multidimensional_sentiment <- function(texts, method = "hybrid") {
  
  sentiment_data <- tibble(
    doc_id = seq_along(texts),
    text = texts
  ) %>%
    filter(!is.na(text), nchar(text) > 0)
  
  # Basic sentiment using Portuguese lexicons
  sentiment_data <- sentiment_data %>%
    mutate(
      # Portuguese sentiment using sentimentr
      sentiment_basic = map_dbl(text, function(t) {
        tryCatch({
          sentimentr::sentiment(t, language = "portuguese")$sentiment
        }, error = function(e) 0)
      }),
      
      # Legal regulatory sentiment (enhanced)
      regulatory_sentiment = map_dbl(text, function(t) {
        compute_regulatory_sentiment_score(t)
      }),
      
      # Emotional valence analysis
      emotional_valence = map_dbl(text, function(t) {
        compute_emotional_valence(t)
      }),
      
      # Policy tone assessment
      policy_tone = map_dbl(text, function(t) {
        assess_policy_tone(t)
      }),
      
      # Legal certainty/uncertainty measurement
      legal_certainty = map_dbl(text, function(t) {
        measure_legal_certainty(t)
      })
    )
  
  # Compute compound sentiment score
  sentiment_data <- sentiment_data %>%
    mutate(
      compound_sentiment = (sentiment_basic + regulatory_sentiment + emotional_valence) / 3,
      sentiment_category = case_when(
        compound_sentiment > 0.1 ~ "Positive",
        compound_sentiment < -0.1 ~ "Negative", 
        TRUE ~ "Neutral"
      ),
      sentiment_intensity = abs(compound_sentiment),
      sentiment_confidence = pmin(1, sentiment_intensity * 2)  # Simple confidence measure
    )
  
  return(sentiment_data)
}

#' Assess Regulatory Strictness
#' 
#' @param texts Vector of texts  
#' @param base_sentiment Base sentiment scores
#' @return Regulatory strictness assessment
assess_regulatory_strictness <- function(texts, base_sentiment) {
  
  strictness_data <- tibble(
    doc_id = seq_along(texts),
    text = texts
  ) %>%
    mutate(
      # Regulatory strictness indicators
      mandatory_language = map_dbl(text, function(t) {
        mandatory_terms <- c("deve", "devem", "obrigatório", "obrigatória", "obrigação", "dever", "imperativo")
        sum(str_count(str_to_lower(t), paste0("\\b(", paste(mandatory_terms, collapse = "|"), ")\\b")))
      }),
      
      prohibitive_language = map_dbl(text, function(t) {
        prohibitive_terms <- c("proíbe", "proibido", "vedado", "não pode", "não poderá", "é vedado")
        sum(str_count(str_to_lower(t), paste0("\\b(", paste(prohibitive_terms, collapse = "|"), ")\\b")))
      }),
      
      permissive_language = map_dbl(text, function(t) {
        permissive_terms <- c("pode", "poderá", "permitido", "autorizado", "facultativo", "opcional")
        sum(str_count(str_to_lower(t), paste0("\\b(", paste(permissive_terms, collapse = "|"), ")\\b")))
      }),
      
      penalty_language = map_dbl(text, function(t) {
        penalty_terms <- c("multa", "penalidade", "sanção", "punição", "infração", "violação")
        sum(str_count(str_to_lower(t), paste0("\\b(", paste(penalty_terms, collapse = "|"), ")\\b")))
      }),
      
      # Calculate strictness index
      total_regulatory_language = mandatory_language + prohibitive_language + permissive_language + penalty_language,
      strictness_index = case_when(
        total_regulatory_language == 0 ~ 0.5,  # Neutral if no regulatory language
        TRUE ~ (mandatory_language + prohibitive_language + penalty_language) / total_regulatory_language
      ),
      
      # Regulatory style classification
      regulatory_style = case_when(
        strictness_index > 0.7 ~ "Prescriptive",
        strictness_index < 0.3 ~ "Flexible",
        TRUE ~ "Balanced"
      ),
      
      # Regulatory complexity assessment
      complexity_score = map_dbl(text, function(t) {
        assess_regulatory_complexity(t)
      })
    )
  
  return(strictness_data)
}

# Helper Functions ==========================================================

#' Compute Regulatory Sentiment Score
compute_regulatory_sentiment_score <- function(text) {
  text_lower <- str_to_lower(text)
  
  # Count positive regulatory terms
  positive_matches <- sum(map_int(ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_regulatory_sentiment$highly_positive, 
                                  ~ str_count(text_lower, paste0("\\b", .x, "\\b"))))
  positive_matches <- positive_matches + 0.5 * sum(map_int(ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_regulatory_sentiment$moderately_positive,
                                                           ~ str_count(text_lower, paste0("\\b", .x, "\\b"))))
  
  # Count negative regulatory terms
  negative_matches <- sum(map_int(ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_regulatory_sentiment$highly_negative,
                                  ~ str_count(text_lower, paste0("\\b", .x, "\\b"))))
  negative_matches <- negative_matches + 0.5 * sum(map_int(ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_regulatory_sentiment$moderately_negative,
                                                           ~ str_count(text_lower, paste0("\\b", .x, "\\b"))))
  
  # Calculate sentiment score
  total_matches <- positive_matches + negative_matches
  if (total_matches > 0) {
    return((positive_matches - negative_matches) / total_matches)
  } else {
    return(0)
  }
}

#' Compute Emotional Valence
compute_emotional_valence <- function(text) {
  # Simplified emotional valence based on Portuguese emotional terms
  emotional_positive <- c("benefício", "melhoria", "progresso", "sucesso", "crescimento", "desenvolvimento")
  emotional_negative <- c("problema", "crise", "dificuldade", "risco", "ameaça", "prejuízo")
  
  pos_count <- sum(str_count(str_to_lower(text), paste0("\\b(", paste(emotional_positive, collapse = "|"), ")\\b")))
  neg_count <- sum(str_count(str_to_lower(text), paste0("\\b(", paste(emotional_negative, collapse = "|"), ")\\b")))
  
  total_count <- pos_count + neg_count
  if (total_count > 0) {
    return((pos_count - neg_count) / total_count)
  } else {
    return(0)
  }
}

#' Assess Policy Tone
assess_policy_tone <- function(text) {
  # Policy tone indicators
  collaborative_terms <- c("cooperação", "parceria", "colaboração", "consenso", "diálogo")
  authoritative_terms <- c("determina", "estabelece", "ordena", "impõe", "exige")
  
  collab_count <- sum(str_count(str_to_lower(text), paste0("\\b(", paste(collaborative_terms, collapse = "|"), ")\\b")))
  auth_count <- sum(str_count(str_to_lower(text), paste0("\\b(", paste(authoritative_terms, collapse = "|"), ")\\b")))
  
  total_count <- collab_count + auth_count
  if (total_count > 0) {
    return((collab_count - auth_count) / total_count)
  } else {
    return(0)
  }
}

#' Measure Legal Certainty
measure_legal_certainty <- function(text) {
  # Legal certainty indicators
  certain_terms <- c("deve", "será", "é", "fica", "estabelece")
  uncertain_terms <- c("pode", "poderá", "eventualmente", "possivelmente", "caso")
  
  certain_count <- sum(str_count(str_to_lower(text), paste0("\\b(", paste(certain_terms, collapse = "|"), ")\\b")))
  uncertain_count <- sum(str_count(str_to_lower(text), paste0("\\b(", paste(uncertain_terms, collapse = "|"), ")\\b")))
  
  total_count <- certain_count + uncertain_count
  if (total_count > 0) {
    return(certain_count / total_count)
  } else {
    return(0.5)  # Neutral certainty
  }
}

#' Assess Regulatory Complexity
assess_regulatory_complexity <- function(text) {
  # Complexity indicators
  complex_structures <- str_count(text, "\\bse\\b.*\\bentão\\b|\\bcaso\\b.*\\bendorsim\\b")
  conditional_language <- str_count(str_to_lower(text), "\\b(desde que|contanto que|a menos que|exceto se)\\b")
  cross_references <- str_count(text, "\\b(artigo|art\\.|parágrafo|§|inciso|alínea)\\b")
  
  # Normalize by document length
  doc_length_words <- length(str_split(text, "\\s+")[[1]])
  if (doc_length_words > 0) {
    return((complex_structures + conditional_language + cross_references) / doc_length_words * 100)
  } else {
    return(0)
  }
}

# Export message
cat("✅ Advanced Topic Modeling and Sentiment Analysis components loaded!\n")
cat("🔧 Available advanced functions:\n")
cat("   - advanced_legal_topic_modeling(): Multi-method topic modeling\n")
cat("   - advanced_regulatory_sentiment_analysis(): Comprehensive sentiment analysis\n")
cat("📚 Ready for large-scale Portuguese legal text analysis!\n")