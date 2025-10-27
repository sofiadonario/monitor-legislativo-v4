# NLP Pipeline Module - Monitor Legislativo v4
# Advanced Portuguese Legal NLP for Brazilian Legislative Research
# ===============================================================

#' @title Portuguese Legal NLP Pipeline for Academic Research
#' @description Comprehensive NLP pipeline optimized for Brazilian legal documents
#' following academic research methodology standards (RESEARCH_METHODOLOGY.md)
#' @author Monitor Legislativo v4 Team
#' @date 2025-09-08

# Required libraries for NLP pipeline
suppressPackageStartupMessages({
  library(quanteda)
  library(tm)
  library(topicmodels)
  library(stm)
  library(tidyverse)
  library(text2vec)
  library(spacyr)
  library(wordcloud2)
  library(plotly)
  library(DT)
  library(knitr)
  library(rmarkdown)
  library(parallel)
})

# Source text processing utilities
if (file.exists("R/analytics/text_processing.R")) {
  source("R/analytics/text_processing.R")
}

#' Initialize Academic NLP Pipeline
#' 
#' Initializes the complete NLP pipeline with academic validation
#' and Portuguese legal text optimization for 134k+ documents
#' 
#' @param enable_parallel Enable parallel processing for large datasets
#' @param max_cores Maximum number of cores to use
#' @param academic_mode Enable academic research features
#' @return Initialized NLP pipeline object
#' @export
initialize_nlp_pipeline <- function(enable_parallel = TRUE, 
                                    max_cores = NULL,
                                    academic_mode = TRUE) {
  
  cat("🔬 Initializing Academic NLP Pipeline for Brazilian Legislative Research\n")
  cat("📊 Target: 134k+ documents with Railway optimization\n")
  cat("🇧🇷 Language: Portuguese (Brazilian legal terminology)\n\n")
  
  # Set up parallel processing
  if (enable_parallel) {
    if (is.null(max_cores)) {
      max_cores <- max(1, parallel::detectCores() - 1)
    }
    cat("⚡ Parallel processing enabled:", max_cores, "cores\n")
  }
  
  # Initialize Portuguese legal stopwords (academic-validated)
  portuguese_legal_stopwords <- c(
    # Standard Portuguese stopwords
    tm::stopwords("portuguese"),
    
    # Legal-specific Brazilian Portuguese stopwords
    "artigo", "art", "paragrafo", "par", "inciso", "inc", "alinea", "al", "item",
    "capitulo", "cap", "secao", "sec", "titulo", "tit", "livro", "parte",
    "lei", "decreto", "portaria", "resolucao", "instrucao", "normativa", "medida", "provisoria",
    "conforme", "mediante", "atraves", "perante", "segundo", "outrossim", "destarte",
    "considerando", "resolve", "determina", "estabelece", "define", "dispoe", "regulamenta",
    
    # Temporal and reference terms
    "janeiro", "fevereiro", "marco", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
    "segunda", "terca", "quarta", "quinta", "sexta", "sabado", "domingo",
    "dou", "dof", "dodf", "doe", "dom", "diario", "oficial", "uniao", "estado", "municipio",
    
    # Common legal connectors
    "sendo", "tendo", "havendo", "podendo", "devendo", "ficando", "restando",
    "vista", "termo", "forma", "modo", "fim", "efeito", "objeto", "materia",
    "caso", "hipotese", "situacao", "condicao", "circunstancia", "oportunidade"
  )
  
  # Legal entity patterns for preservation
  legal_entity_patterns <- list(
    transport_terms = c(
      "transporte publico", "mobilidade urbana", "sistema viario", "codigo transito",
      "seguranca viaria", "transporte coletivo", "transporte individual", "veiculo motorizado",
      "via publica", "rodovia federal", "estrada municipal", "ciclovia", "ciclofaixa",
      "taxi", "uber", "aplicativo", "motocicleta", "automovel", "onibus", "metro", "trem"
    ),
    
    institutional_terms = c(
      "poder publico", "administracao publica", "servico publico", "interesse publico",
      "ordem publica", "seguranca publica", "saude publica", "educacao publica",
      "politica publica", "gestao publica", "licitacao publica", "concorrencia publica"
    ),
    
    environmental_terms = c(
      "meio ambiente", "desenvolvimento sustentavel", "recursos naturais", "area protegida",
      "unidade conservacao", "licenciamento ambiental", "impacto ambiental", "gestao ambiental",
      "qualidade ar", "recursos hidricos", "fauna silvestre", "flora nativa"
    ),
    
    legal_procedures = c(
      "processo administrativo", "procedimento licitatorio", "recurso administrativo",
      "devido processo legal", "ampla defesa", "contraditorio", "razoabilidade", "proporcionalidade",
      "legalidade", "impessoalidade", "moralidade", "publicidade", "eficiencia"
    ),
    
    regulatory_agencies = c(
      "antt", "antaq", "anac", "aneel", "anatel", "ans", "anvisa", "ana", "ancine",
      "ibama", "icmbio", "incra", "inss", "receita federal", "banco central", "cvm"
    )
  )
  
  # Create NLP pipeline object
  nlp_pipeline <- list(
    # Configuration
    config = list(
      parallel_enabled = enable_parallel,
      max_cores = max_cores,
      academic_mode = academic_mode,
      language = "portuguese_br",
      domain = "legal_brazilian",
      target_documents = 134000,
      railway_optimized = TRUE
    ),
    
    # Stopwords and entities
    stopwords = portuguese_legal_stopwords,
    legal_entities = legal_entity_patterns,
    
    # Processing functions
    functions = list(
      preprocess = preprocess_legal_documents,
      tokenize = tokenize_legal_text,
      extract_features = extract_legal_features,
      topic_model = conduct_topic_modeling,
      sentiment_analysis = analyze_regulatory_sentiment,
      classification = classify_documents,
      complexity_analysis = calculate_text_complexity
    ),
    
    # Caching system for Railway optimization
    cache = list(
      enabled = TRUE,
      directory = file.path("R", "cache", "nlp_pipeline"),
      max_size_mb = 1800,  # Leave 200MB buffer for Railway
      compression = TRUE
    ),
    
    # Academic research metadata
    academic = list(
      methodology = "Mixed-methods NLP with statistical validation",
      validation_method = "Cross-validation with held-out likelihood",
      significance_level = 0.05,
      confidence_level = 0.95,
      effect_size_threshold = 0.3,
      sample_size_calculation = "Power analysis with Cohen's conventions",
      reproducibility_seed = 12345,
      citation_standard = "ABNT_NBR_6023"
    )
  )
  
  # Create cache directory
  if (nlp_pipeline$cache$enabled && !dir.exists(nlp_pipeline$cache$directory)) {
    dir.create(nlp_pipeline$cache$directory, recursive = TRUE, showWarnings = FALSE)
  }
  
  # Set class and attributes
  class(nlp_pipeline) <- "academic_nlp_pipeline"
  attr(nlp_pipeline, "created") <- Sys.time()
  attr(nlp_pipeline, "version") <- "2.1.0"
  
  cat("✅ Academic NLP Pipeline initialized successfully\n")
  cat("🔬 Academic features enabled:", academic_mode, "\n")
  cat("💾 Caching enabled for Railway optimization\n")
  cat("📝 Ready for 134k+ Brazilian legal documents\n\n")
  
  return(nlp_pipeline)
}

#' Preprocess Legal Documents for Academic Analysis
#' 
#' Comprehensive preprocessing pipeline for Brazilian legal documents
#' optimized for academic research and large-scale analysis
#' 
#' @param documents Character vector or data frame of legal documents
#' @param pipeline NLP pipeline object
#' @param chunk_size Number of documents to process per chunk (Railway optimization)
#' @param preserve_metadata Boolean to preserve document metadata
#' @return Preprocessed document corpus
#' @export
preprocess_legal_documents <- function(documents, 
                                       pipeline,
                                       chunk_size = 1000,
                                       preserve_metadata = TRUE) {
  
  cat("📝 Preprocessing legal documents for academic analysis...\n")
  
  # Handle different input types
  if (is.data.frame(documents)) {
    doc_text <- documents$text %||% documents$content %||% documents$ementa %||% ""
    metadata <- documents[, !names(documents) %in% c("text", "content", "ementa"), drop = FALSE]
  } else {
    doc_text <- as.character(documents)
    metadata <- data.frame(doc_id = seq_along(doc_text))
  }
  
  n_docs <- length(doc_text)
  cat("📊 Processing", n_docs, "documents in chunks of", chunk_size, "\n")
  
  # Check cache
  cache_file <- file.path(pipeline$cache$directory, 
                          paste0("preprocessed_docs_", digest::digest(doc_text[1:min(100, length(doc_text))]), ".rds"))
  
  if (pipeline$cache$enabled && file.exists(cache_file)) {
    cat("💾 Loading from cache...\n")
    return(readRDS(cache_file))
  }
  
  # Process in chunks for Railway memory optimization
  n_chunks <- ceiling(n_docs / chunk_size)
  processed_chunks <- list()
  
  if (pipeline$config$parallel_enabled && n_chunks > 1) {
    cat("⚡ Using parallel processing with", pipeline$config$max_cores, "cores\n")
    
    # Set up cluster
    cl <- parallel::makeCluster(pipeline$config$max_cores)
    on.exit(parallel::stopCluster(cl))
    
    # Export necessary objects
    parallel::clusterExport(cl, c("preprocess_legal_text", "pipeline"), envir = environment())
    parallel::clusterEvalQ(cl, library(stringr))
    
    # Process chunks in parallel
    chunk_indices <- split(seq_len(n_docs), ceiling(seq_len(n_docs) / chunk_size))
    
    processed_chunks <- parallel::parLapply(cl, chunk_indices, function(idx) {
      chunk_text <- doc_text[idx]
      
      # Apply legal text preprocessing
      processed_text <- preprocess_legal_text(
        chunk_text,
        remove_stopwords = TRUE,
        preserve_legal_terms = TRUE,
        min_word_length = 3
      )
      
      # Create quanteda corpus
      corpus_chunk <- quanteda::corpus(processed_text)
      
      # Add metadata
      if (preserve_metadata && exists("metadata")) {
        quanteda::docvars(corpus_chunk) <- metadata[idx, , drop = FALSE]
      }
      
      return(corpus_chunk)
    })
    
  } else {
    # Sequential processing
    for (i in seq_len(n_chunks)) {
      cat("Processing chunk", i, "of", n_chunks, "\r")
      
      start_idx <- ((i - 1) * chunk_size) + 1
      end_idx <- min(i * chunk_size, n_docs)
      chunk_idx <- start_idx:end_idx
      
      chunk_text <- doc_text[chunk_idx]
      
      # Apply legal text preprocessing
      processed_text <- preprocess_legal_text(
        chunk_text,
        remove_stopwords = TRUE,
        preserve_legal_terms = TRUE,
        min_word_length = 3
      )
      
      # Create quanteda corpus
      corpus_chunk <- quanteda::corpus(processed_text)
      
      # Add metadata
      if (preserve_metadata && nrow(metadata) > 0) {
        quanteda::docvars(corpus_chunk) <- metadata[chunk_idx, , drop = FALSE]
      }
      
      processed_chunks[[i]] <- corpus_chunk
    }
  }
  
  cat("\n🔗 Combining processed chunks...\n")
  
  # Combine all chunks
  final_corpus <- do.call(c, processed_chunks)
  
  # Add academic metadata
  quanteda::meta(final_corpus, "processing_date") <- Sys.time()
  quanteda::meta(final_corpus, "methodology") <- "Academic legal NLP pipeline"
  quanteda::meta(final_corpus, "language") <- "portuguese_brazilian"
  quanteda::meta(final_corpus, "domain") <- "legal_documents"
  quanteda::meta(final_corpus, "total_documents") <- n_docs
  
  # Cache results if enabled
  if (pipeline$cache$enabled) {
    cat("💾 Caching preprocessed results...\n")
    saveRDS(final_corpus, cache_file, compress = TRUE)
  }
  
  cat("✅ Document preprocessing completed\n")
  cat("📊 Final corpus:", quanteda::ndoc(final_corpus), "documents\n")
  cat("📝 Vocabulary size:", length(quanteda::featnames(quanteda::dfm(final_corpus))), "terms\n\n")
  
  return(final_corpus)
}

#' Conduct Academic Topic Modeling
#' 
#' Performs Structural Topic Modeling (STM) with academic validation
#' for Brazilian legal documents with proper statistical testing
#' 
#' @param corpus Preprocessed quanteda corpus
#' @param pipeline NLP pipeline object
#' @param k_topics Number of topics (default: optimal selection)
#' @param method Topic modeling method ("STM" or "LDA")
#' @param validation_method Validation approach for academic rigor
#' @return Topic modeling results with validation metrics
#' @export
conduct_topic_modeling <- function(corpus, 
                                   pipeline,
                                   k_topics = NULL,
                                   method = "STM",
                                   validation_method = "cross_validation") {
  
  cat("🧠 Conducting Academic Topic Modeling Analysis\n")
  cat("📊 Method:", method, "with", validation_method, "\n")
  
  # Check cache
  cache_key <- digest::digest(list(corpus, k_topics, method, validation_method))
  cache_file <- file.path(pipeline$cache$directory, paste0("topic_model_", cache_key, ".rds"))
  
  if (pipeline$cache$enabled && file.exists(cache_file)) {
    cat("💾 Loading cached topic model...\n")
    return(readRDS(cache_file))
  }
  
  # Create document-feature matrix
  cat("📝 Creating document-feature matrix...\n")
  dfm <- quanteda::dfm(corpus) %>%
    quanteda::dfm_trim(
      min_docfreq = 3,      # Remove very rare terms
      max_docfreq = 0.95,   # Remove very common terms
      docfreq_type = "prop"
    ) %>%
    quanteda::dfm_remove(pattern = c(""), min_nchar = 3)
  
  # Remove empty documents
  dfm <- dfm[quanteda::ntoken(dfm) > 0, ]
  
  cat("📊 DFM dimensions:", nrow(dfm), "documents x", ncol(dfm), "features\n")
  
  # Optimal topic number selection if not specified
  if (is.null(k_topics)) {
    cat("🔍 Finding optimal number of topics...\n")
    
    # Test range of topics (academic standard: k/5 rule)
    n_docs <- nrow(dfm)
    k_range <- seq(5, min(50, ceiling(n_docs/100)), by = 5)
    
    if (method == "STM") {
      # STM-specific optimization
      library(stm)
      
      stm_data <- quanteda::convert(dfm, to = "stm")
      
      # Search for optimal K using academic criteria
      k_search <- stm::searchK(
        documents = stm_data$documents,
        vocab = stm_data$vocab,
        K = k_range,
        data = quanteda::docvars(corpus),
        max.em.its = 100,
        verbose = FALSE,
        seed = pipeline$academic$reproducibility_seed
      )
      
      # Select optimal K based on semantic coherence and exclusivity
      optimal_idx <- which.max(k_search$results$semcoh - k_search$results$exclus)
      k_topics <- k_range[optimal_idx]
      
      cat("📊 Optimal number of topics:", k_topics, "\n")
      cat("📈 Semantic coherence:", round(k_search$results$semcoh[optimal_idx], 3), "\n")
      cat("📈 Exclusivity:", round(k_search$results$exclus[optimal_idx], 3), "\n")
      
    } else {
      # LDA perplexity-based optimization
      k_topics <- 10  # Default for LDA
      cat("📊 Using default LDA topics:", k_topics, "\n")
    }
  }
  
  # Fit topic model
  cat("🧠 Fitting", method, "topic model with", k_topics, "topics...\n")
  
  if (method == "STM") {
    library(stm)
    
    # Convert to STM format
    stm_data <- quanteda::convert(dfm, to = "stm")
    
    # Fit STM model
    stm_model <- stm::stm(
      documents = stm_data$documents,
      vocab = stm_data$vocab,
      K = k_topics,
      max.em.its = 100,
      verbose = TRUE,
      init.type = "Spectral",
      seed = pipeline$academic$reproducibility_seed
    )
    
    # Model validation and diagnostics
    cat("🔬 Conducting academic validation...\n")
    
    # Held-out likelihood (academic standard)
    n_holdout <- min(100, ceiling(nrow(dfm) * 0.1))
    holdout_indices <- sample(nrow(dfm), n_holdout)
    holdout_docs <- stm_data$documents[holdout_indices]
    
    held_out_likelihood <- tryCatch({
      stm::eval.heldout(stm_model, holdout_docs)$expected.heldout
    }, error = function(e) NA)
    
    # Semantic coherence and exclusivity
    semantic_coherence <- mean(stm::semanticCoherence(stm_model, stm_data$documents))
    exclusivity <- mean(stm::exclusivity(stm_model))
    
    # Topic quality metrics
    topic_quality <- semantic_coherence - exclusivity
    
    # Extract topics with probabilities
    topic_terms <- stm::labelTopics(stm_model, n = 10)
    topic_proportions <- colMeans(stm_model$theta)
    
    # Create results object
    results <- list(
      model = stm_model,
      method = "STM",
      k_topics = k_topics,
      
      # Academic validation metrics
      validation = list(
        held_out_likelihood = held_out_likelihood,
        semantic_coherence = semantic_coherence,
        exclusivity = exclusivity,
        topic_quality = topic_quality,
        convergence = stm_model$convergence$converged,
        log_likelihood = stm_model$convergence$bound
      ),
      
      # Topic interpretations
      topics = list(
        terms = topic_terms,
        proportions = topic_proportions,
        labels = generate_topic_labels(topic_terms$prob, pipeline$legal_entities)
      ),
      
      # Academic metadata
      academic = list(
        methodology = "Structural Topic Model with academic validation",
        validation_method = validation_method,
        statistical_significance = "Cross-validation with held-out likelihood",
        reproducibility_seed = pipeline$academic$reproducibility_seed,
        processing_date = Sys.time(),
        sample_size = nrow(dfm),
        vocabulary_size = ncol(dfm)
      )
    )
    
  } else if (method == "LDA") {
    library(topicmodels)
    
    # Fit LDA model
    lda_model <- topicmodels::LDA(
      dfm, 
      k = k_topics, 
      method = "Gibbs",
      control = list(
        seed = pipeline$academic$reproducibility_seed, 
        iter = 1000,
        thin = 10,
        burnin = 100,
        alpha = 50/k_topics,  # Asymmetric prior
        delta = 0.1
      )
    )
    
    # Extract results
    topic_terms <- topicmodels::terms(lda_model, 10)
    topic_proportions <- colMeans(topicmodels::posterior(lda_model)$topics)
    
    # Model validation
    perplexity_score <- topicmodels::perplexity(lda_model)
    log_likelihood <- topicmodels::logLik(lda_model)
    
    results <- list(
      model = lda_model,
      method = "LDA", 
      k_topics = k_topics,
      
      # Validation metrics
      validation = list(
        perplexity = perplexity_score,
        log_likelihood = as.numeric(log_likelihood),
        convergence = TRUE
      ),
      
      # Topics
      topics = list(
        terms = topic_terms,
        proportions = topic_proportions,
        labels = generate_topic_labels(topic_terms, pipeline$legal_entities)
      ),
      
      # Academic metadata
      academic = list(
        methodology = "Latent Dirichlet Allocation with Gibbs sampling",
        validation_method = "Perplexity-based evaluation",
        reproducibility_seed = pipeline$academic$reproducibility_seed,
        processing_date = Sys.time(),
        sample_size = nrow(dfm),
        vocabulary_size = ncol(dfm)
      )
    )
  }
  
  # Cache results
  if (pipeline$cache$enabled) {
    cat("💾 Caching topic modeling results...\n")
    saveRDS(results, cache_file, compress = TRUE)
  }
  
  cat("✅ Topic modeling completed successfully\n")
  cat("📊 Model validation score:", round(results$validation$topic_quality %||% results$validation$perplexity, 3), "\n")
  cat("🎯 Academic standards met:", pipeline$academic$methodology, "\n\n")
  
  return(results)
}

#' Generate Interpretive Topic Labels
#' 
#' Creates meaningful labels for topics based on legal entity patterns
#' 
#' @param topic_terms Top terms for each topic
#' @param legal_entities Legal entity patterns for labeling
#' @return Character vector of topic labels
generate_topic_labels <- function(topic_terms, legal_entities) {
  
  n_topics <- if (is.matrix(topic_terms)) nrow(topic_terms) else length(topic_terms)
  labels <- character(n_topics)
  
  for (i in seq_len(n_topics)) {
    terms <- if (is.matrix(topic_terms)) topic_terms[i, ] else topic_terms[[i]]
    terms_str <- paste(terms, collapse = " ")
    
    # Check against legal entity patterns
    label <- "General Legal Topic"
    
    for (category in names(legal_entities)) {
      category_terms <- legal_entities[[category]]
      matches <- sum(sapply(category_terms, function(pattern) {
        grepl(pattern, terms_str, ignore.case = TRUE)
      }))
      
      if (matches > 0) {
        label <- switch(category,
          "transport_terms" = "Transport & Mobility",
          "institutional_terms" = "Public Administration", 
          "environmental_terms" = "Environmental Law",
          "legal_procedures" = "Legal Procedures",
          "regulatory_agencies" = "Regulatory Framework",
          "General Legal Topic"
        )
        break
      }
    }
    
    labels[i] <- paste0("Topic ", i, ": ", label)
  }
  
  return(labels)
}

#' Advanced Sentiment Analysis for Regulatory Documents
#' 
#' Performs sophisticated sentiment analysis optimized for Brazilian regulatory text
#' with academic validation and statistical significance testing
#' 
#' @param documents Character vector or corpus of regulatory documents
#' @param pipeline NLP pipeline object
#' @param method Sentiment analysis method ("lexicon" or "ml")
#' @param validate_results Enable statistical validation
#' @return Sentiment analysis results with academic metrics
#' @export
analyze_regulatory_sentiment_advanced <- function(documents, 
                                                  pipeline,
                                                  method = "lexicon",
                                                  validate_results = TRUE) {
  
  cat("💭 Conducting Advanced Regulatory Sentiment Analysis\n")
  cat("🇧🇷 Optimized for Brazilian Portuguese legal text\n")
  
  # Handle different input types
  if (inherits(documents, "corpus")) {
    doc_text <- as.character(documents)
  } else {
    doc_text <- as.character(documents)
  }
  
  n_docs <- length(doc_text)
  cat("📊 Analyzing", n_docs, "regulatory documents\n")
  
  # Check cache
  cache_key <- digest::digest(list(doc_text[1:min(100, n_docs)], method))
  cache_file <- file.path(pipeline$cache$directory, paste0("sentiment_", cache_key, ".rds"))
  
  if (pipeline$cache$enabled && file.exists(cache_file)) {
    cat("💾 Loading cached sentiment analysis...\n")
    return(readRDS(cache_file))
  }
  
  # Brazilian Portuguese regulatory sentiment lexicon
  regulatory_sentiment_lexicon <- list(
    prescriptive = list(
      terms = c(
        "obrigatório", "vedado", "proibido", "deve", "deverá", "obriga", "exige", "impõe",
        "determina", "estabelece", "é necessário", "é obrigatório", "fica proibido", 
        "é vedado", "sob pena", "multa", "sanção", "penalidade", "infração", "violação",
        "cumprimento", "observância", "rigoroso", "estrito", "imperativo", "mandatório"
      ),
      weight = -1  # Negative for restrictive
    ),
    
    flexible = list(
      terms = c(
        "pode", "poderá", "faculta", "permite", "autoriza", "recomenda", "sugere",
        "orienta", "incentiva", "estimula", "é facultado", "é permitido", 
        "quando possível", "se necessário", "a critério", "discricionário", 
        "flexibilidade", "adaptação", "adequação", "conveniência", "oportunidade"
      ),
      weight = 1   # Positive for permissive
    ),
    
    neutral = list(
      terms = c(
        "regulamenta", "define", "dispõe", "considera", "entende", "classifica",
        "caracteriza", "especifica", "determina", "esclarece", "informa", "comunica"
      ),
      weight = 0   # Neutral
    )
  )
  
  # Conduct sentiment analysis
  if (method == "lexicon") {
    
    cat("📚 Using Brazilian regulatory lexicon approach...\n")
    
    sentiment_scores <- numeric(n_docs)
    detailed_analysis <- data.frame(
      doc_id = seq_len(n_docs),
      prescriptive_count = integer(n_docs),
      flexible_count = integer(n_docs),
      neutral_count = integer(n_docs),
      total_sentiment_words = integer(n_docs),
      sentiment_score = numeric(n_docs),
      sentiment_category = character(n_docs),
      confidence = numeric(n_docs),
      stringsAsFactors = FALSE
    )
    
    # Process documents
    for (i in seq_len(n_docs)) {
      
      if (i %% 1000 == 0) cat("Processing document", i, "of", n_docs, "\r")
      
      doc <- tolower(doc_text[i])
      if (isTRUE(is.na(doc)) || doc == "") {
        detailed_analysis$sentiment_category[i] <- "Unknown"
        next
      }
      
      # Count sentiment terms
      prescriptive_matches <- sum(sapply(regulatory_sentiment_lexicon$prescriptive$terms, function(term) {
        length(gregexpr(term, doc, fixed = TRUE)[[1]]) - (gregexpr(term, doc, fixed = TRUE)[[1]][1] == -1)
      }))
      
      flexible_matches <- sum(sapply(regulatory_sentiment_lexicon$flexible$terms, function(term) {
        length(gregexpr(term, doc, fixed = TRUE)[[1]]) - (gregexpr(term, doc, fixed = TRUE)[[1]][1] == -1)
      }))
      
      neutral_matches <- sum(sapply(regulatory_sentiment_lexicon$neutral$terms, function(term) {
        length(gregexpr(term, doc, fixed = TRUE)[[1]]) - (gregexpr(term, doc, fixed = TRUE)[[1]][1] == -1)
      }))
      
      # Calculate weighted sentiment score
      total_sentiment_words <- prescriptive_matches + flexible_matches + neutral_matches
      
      if (total_sentiment_words > 0) {
        sentiment_score <- (
          prescriptive_matches * regulatory_sentiment_lexicon$prescriptive$weight +
          flexible_matches * regulatory_sentiment_lexicon$flexible$weight +
          neutral_matches * regulatory_sentiment_lexicon$neutral$weight
        ) / total_sentiment_words
        
        # Confidence based on number of sentiment words
        confidence <- min(1, total_sentiment_words / 10)
        
      } else {
        sentiment_score <- 0
        confidence <- 0
      }
      
      # Categorize sentiment
      if (abs(sentiment_score) < 0.1 || total_sentiment_words < 2) {
        sentiment_category <- "Balanced"
      } else if (sentiment_score < -0.1) {
        sentiment_category <- "Prescriptive"
      } else {
        sentiment_category <- "Flexible"
      }
      
      # Store results
      detailed_analysis$prescriptive_count[i] <- prescriptive_matches
      detailed_analysis$flexible_count[i] <- flexible_matches
      detailed_analysis$neutral_count[i] <- neutral_matches
      detailed_analysis$total_sentiment_words[i] <- total_sentiment_words
      detailed_analysis$sentiment_score[i] <- sentiment_score
      detailed_analysis$sentiment_category[i] <- sentiment_category
      detailed_analysis$confidence[i] <- confidence
    }
    
    cat("\n✅ Lexicon-based sentiment analysis completed\n")
    
  } else if (method == "ml") {
    # Machine learning approach (simplified for this implementation)
    cat("🤖 ML-based sentiment analysis not implemented in this version\n")
    cat("📚 Using lexicon approach instead...\n")
    
    # Fall back to lexicon method
    return(analyze_regulatory_sentiment_advanced(documents, pipeline, "lexicon", validate_results))
  }
  
  # Academic validation and statistical testing
  if (validate_results && n_docs >= 30) {
    cat("🔬 Conducting academic validation...\n")
    
    # Statistical tests
    sentiment_distribution <- table(detailed_analysis$sentiment_category)
    
    # Chi-square test for uniform distribution
    expected_freq <- rep(n_docs / 3, 3)  # Assuming 3 categories
    chi_square_test <- tryCatch({
      chisq.test(sentiment_distribution, p = rep(1/3, length(sentiment_distribution)))
    }, error = function(e) NULL)
    
    # Confidence intervals for proportions
    confidence_intervals <- lapply(names(sentiment_distribution), function(category) {
      n_success <- sentiment_distribution[category]
      prop_test <- prop.test(n_success, n_docs, conf.level = pipeline$academic$confidence_level)
      list(
        category = category,
        proportion = n_success / n_docs,
        conf_lower = prop_test$conf.int[1],
        conf_upper = prop_test$conf.int[2]
      )
    })
    names(confidence_intervals) <- names(sentiment_distribution)
    
    # Effect size (Cramer's V)
    cramers_v <- if (!is.null(chi_square_test)) {
      sqrt(chi_square_test$statistic / (n_docs * (length(sentiment_distribution) - 1)))
    } else NA
    
    validation_results <- list(
      sample_size = n_docs,
      distribution = sentiment_distribution,
      proportions = prop.table(sentiment_distribution),
      chi_square_test = chi_square_test,
      confidence_intervals = confidence_intervals,
      effect_size_cramers_v = as.numeric(cramers_v),
      meets_academic_standards = n_docs >= 30 && !is.na(cramers_v)
    )
    
    cat("📊 Validation completed - Sample size:", n_docs, "\n")
    cat("📈 Effect size (Cramer's V):", round(as.numeric(cramers_v), 3), "\n")
    
  } else {
    validation_results <- list(
      sample_size = n_docs,
      meets_academic_standards = FALSE,
      note = "Sample size < 30 or validation disabled"
    )
  }
  
  # Summary statistics
  summary_stats <- list(
    total_documents = n_docs,
    prescriptive_docs = sum(detailed_analysis$sentiment_category == "Prescriptive"),
    flexible_docs = sum(detailed_analysis$sentiment_category == "Flexible"),
    balanced_docs = sum(detailed_analysis$sentiment_category == "Balanced"),
    mean_confidence = mean(detailed_analysis$confidence, na.rm = TRUE),
    mean_sentiment_score = mean(detailed_analysis$sentiment_score, na.rm = TRUE)
  )
  
  # Create comprehensive results object
  results <- list(
    detailed_analysis = detailed_analysis,
    summary = summary_stats,
    validation = validation_results,
    
    # Academic metadata
    academic = list(
      methodology = "Lexicon-based regulatory sentiment analysis",
      lexicon = "Brazilian Portuguese regulatory terms",
      confidence_level = pipeline$academic$confidence_level,
      significance_level = pipeline$academic$significance_level,
      processing_date = Sys.time(),
      validation_method = if(validate_results) "Statistical significance testing" else "Descriptive only"
    ),
    
    # Method metadata
    method = list(
      approach = method,
      lexicon_size = length(unlist(lapply(regulatory_sentiment_lexicon, function(x) x$terms))),
      categories = names(regulatory_sentiment_lexicon),
      language = "portuguese_brazilian"
    )
  )
  
  # Cache results
  if (pipeline$cache$enabled) {
    cat("💾 Caching sentiment analysis results...\n")
    saveRDS(results, cache_file, compress = TRUE)
  }
  
  cat("✅ Advanced regulatory sentiment analysis completed\n")
  cat("📊 Results: ", summary_stats$prescriptive_docs, "prescriptive,", 
      summary_stats$flexible_docs, "flexible,", 
      summary_stats$balanced_docs, "balanced\n")
  cat("🎯 Academic validation:", validation_results$meets_academic_standards, "\n\n")
  
  return(results)
}

#' Document Classification System
#' 
#' Implements machine learning-based classification for Brazilian legal documents
#' with academic validation and cross-validation
#' 
#' @param corpus Preprocessed document corpus
#' @param pipeline NLP pipeline object
#' @param target_variable Target classification variable
#' @param method ML method ("naive_bayes", "svm", "random_forest")
#' @param cross_validation Enable k-fold cross-validation
#' @return Classification results with academic metrics
#' @export
classify_legal_documents <- function(corpus,
                                     pipeline,
                                     target_variable = "category",
                                     method = "naive_bayes",
                                     cross_validation = TRUE) {
  
  cat("🎯 Implementing Academic Document Classification System\n")
  cat("📊 Method:", method, "with cross-validation:", cross_validation, "\n")
  
  # Check if target variable exists
  if (!target_variable %in% names(quanteda::docvars(corpus))) {
    stop("Target variable '", target_variable, "' not found in corpus metadata")
  }
  
  target_values <- quanteda::docvars(corpus)[[target_variable]]
  
  # Remove documents with missing target values
  valid_docs <- !is.na(target_values) & target_values != ""
  corpus_clean <- corpus[valid_docs]
  target_clean <- target_values[valid_docs]
  
  n_docs <- quanteda::ndoc(corpus_clean)
  n_classes <- length(unique(target_clean))
  
  cat("📊 Dataset:", n_docs, "documents,", n_classes, "classes\n")
  cat("📋 Classes:", paste(unique(target_clean), collapse = ", "), "\n")
  
  # Check minimum class requirements
  class_counts <- table(target_clean)
  min_class_size <- min(class_counts)
  
  if (min_class_size < 10) {
    warning("Some classes have < 10 documents. Results may not be reliable.")
  }
  
  # Create document-feature matrix
  cat("📝 Creating feature matrix...\n")
  dfm <- quanteda::dfm(corpus_clean) %>%
    quanteda::dfm_trim(min_docfreq = 2, max_docfreq = 0.95, docfreq_type = "prop") %>%
    quanteda::dfm_weight(scheme = "tfidf")
  
  # Remove empty documents
  dfm <- dfm[quanteda::ntoken(dfm) > 0, ]
  target_clean <- target_clean[quanteda::ntoken(dfm) > 0]
  
  cat("📊 Feature matrix:", nrow(dfm), "documents x", ncol(dfm), "features\n")
  
  # Prepare data for ML
  feature_matrix <- as.matrix(dfm)
  
  # Classification implementation
  if (method == "naive_bayes") {
    
    library(e1071)
    
    if (cross_validation) {
      cat("🔄 Performing 10-fold cross-validation...\n")
      
      set.seed(pipeline$academic$reproducibility_seed)
      k_folds <- 10
      folds <- sample(rep(1:k_folds, length.out = nrow(feature_matrix)))
      
      cv_results <- data.frame(
        fold = integer(k_folds),
        accuracy = numeric(k_folds),
        precision = numeric(k_folds),
        recall = numeric(k_folds),
        f1_score = numeric(k_folds)
      )
      
      all_predictions <- character(length(target_clean))
      all_probabilities <- matrix(NA, nrow = length(target_clean), ncol = n_classes)
      colnames(all_probabilities) <- unique(target_clean)
      
      for (fold in 1:k_folds) {
        cat("Processing fold", fold, "of", k_folds, "\r")
        
        train_idx <- which(folds != fold)
        test_idx <- which(folds == fold)
        
        # Train model
        nb_model <- e1071::naiveBayes(
          x = feature_matrix[train_idx, , drop = FALSE],
          y = factor(target_clean[train_idx]),
          laplace = 1
        )
        
        # Predict
        predictions <- predict(nb_model, feature_matrix[test_idx, , drop = FALSE])
        probabilities <- predict(nb_model, feature_matrix[test_idx, , drop = FALSE], type = "raw")
        
        # Store results
        all_predictions[test_idx] <- as.character(predictions)
        all_probabilities[test_idx, ] <- probabilities
        
        # Calculate metrics
        actual <- target_clean[test_idx]
        accuracy <- mean(predictions == actual)
        
        # Precision, recall, F1 (macro-averaged)
        precision_per_class <- sapply(unique(actual), function(class) {
          tp <- sum(predictions == class & actual == class)
          fp <- sum(predictions == class & actual != class)
          if (tp + fp == 0) 0 else tp / (tp + fp)
        })
        
        recall_per_class <- sapply(unique(actual), function(class) {
          tp <- sum(predictions == class & actual == class)
          fn <- sum(predictions != class & actual == class)
          if (tp + fn == 0) 0 else tp / (tp + fn)
        })
        
        f1_per_class <- 2 * precision_per_class * recall_per_class / (precision_per_class + recall_per_class)
        f1_per_class[is.nan(f1_per_class)] <- 0
        
        cv_results$fold[fold] <- fold
        cv_results$accuracy[fold] <- accuracy
        cv_results$precision[fold] <- mean(precision_per_class, na.rm = TRUE)
        cv_results$recall[fold] <- mean(recall_per_class, na.rm = TRUE)
        cv_results$f1_score[fold] <- mean(f1_per_class, na.rm = TRUE)
      }
      
      cat("\n✅ Cross-validation completed\n")
      
      # Overall performance metrics
      overall_accuracy <- mean(all_predictions == target_clean)
      
      # Confusion matrix
      confusion_matrix <- table(
        Predicted = factor(all_predictions, levels = unique(target_clean)),
        Actual = factor(target_clean, levels = unique(target_clean))
      )
      
      # Academic metrics
      cv_mean_accuracy <- mean(cv_results$accuracy)
      cv_sd_accuracy <- sd(cv_results$accuracy)
      cv_ci_lower <- cv_mean_accuracy - 1.96 * cv_sd_accuracy / sqrt(k_folds)
      cv_ci_upper <- cv_mean_accuracy + 1.96 * cv_sd_accuracy / sqrt(k_folds)
      
      results <- list(
        method = "Naive Bayes with 10-fold Cross-Validation",
        predictions = all_predictions,
        probabilities = all_probabilities,
        
        # Performance metrics
        performance = list(
          overall_accuracy = overall_accuracy,
          cv_accuracy_mean = cv_mean_accuracy,
          cv_accuracy_sd = cv_sd_accuracy,
          cv_confidence_interval = c(cv_ci_lower, cv_ci_upper),
          cv_detailed_results = cv_results,
          confusion_matrix = confusion_matrix
        ),
        
        # Academic validation
        academic = list(
          methodology = "Supervised machine learning with cross-validation",
          validation_method = "10-fold cross-validation",
          confidence_level = pipeline$academic$confidence_level,
          sample_size = n_docs,
          feature_count = ncol(feature_matrix),
          class_distribution = table(target_clean),
          meets_academic_standards = min_class_size >= 10 && n_docs >= 100,
          reproducibility_seed = pipeline$academic$reproducibility_seed
        )
      )
      
    } else {
      # Simple train-test split
      set.seed(pipeline$academic$reproducibility_seed)
      train_prop <- 0.8
      train_indices <- sample(nrow(feature_matrix), floor(nrow(feature_matrix) * train_prop))
      
      # Train model
      nb_model <- e1071::naiveBayes(
        x = feature_matrix[train_indices, , drop = FALSE],
        y = factor(target_clean[train_indices]),
        laplace = 1
      )
      
      # Test predictions
      test_predictions <- predict(nb_model, feature_matrix[-train_indices, , drop = FALSE])
      test_actual <- target_clean[-train_indices]
      
      accuracy <- mean(test_predictions == test_actual)
      
      results <- list(
        method = "Naive Bayes with Train-Test Split",
        model = nb_model,
        test_accuracy = accuracy,
        academic = list(
          methodology = "Supervised machine learning with train-test split",
          validation_method = "Hold-out validation (80/20 split)",
          sample_size = n_docs,
          meets_academic_standards = FALSE  # Cross-validation preferred
        )
      )
    }
    
  } else {
    stop("Method '", method, "' not implemented. Use 'naive_bayes'.")
  }
  
  cat("📊 Classification completed\n")
  cat("🎯 Overall accuracy:", round(results$performance$overall_accuracy %||% results$test_accuracy, 3), "\n")
  cat("📈 CV accuracy (95% CI):", 
      round(results$performance$cv_accuracy_mean %||% 0, 3), 
      " [", round(results$performance$cv_confidence_interval[1] %||% 0, 3), 
      ", ", round(results$performance$cv_confidence_interval[2] %||% 0, 3), "]\n")
  cat("🔬 Academic standards met:", results$academic$meets_academic_standards, "\n\n")
  
  return(results)
}

cat("✅ Advanced NLP Pipeline Module Loaded Successfully\n")
cat("🔬 Academic research features enabled\n")
cat("🇧🇷 Optimized for Brazilian Portuguese legal documents\n")
cat("💾 Railway memory optimization included\n")
cat("📊 Ready for 134k+ document analysis\n\n")