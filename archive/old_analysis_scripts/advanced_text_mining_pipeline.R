# ADVANCED TEXT MINING PIPELINE FOR BRAZILIAN LEGISLATIVE MONITORING
# =================================================================
# Comprehensive NLP system with Portuguese legal text processing
# Integrates with Railway PostgreSQL deployment
# Handles 134k+ documents with scalable processing
# Author: Brazilian Legislative Analytics Framework
# Version: 2.0.0 - Production Ready

cat("🚀 Advanced Text Mining Pipeline - Loading...\n")

# Suppress warnings for cleaner output
options(warn = -1)

# Load required libraries with error handling
required_packages <- c(
  # Core data processing
  "dplyr", "stringr", "purrr", "tidyr", "lubridate",
  # Text mining
  "tm", "quanteda", "tidytext", "textclean", "hunspell",
  # Topic modeling
  "topicmodels", "stm", "ldatuning", 
  # Sentiment analysis
  "sentimentr", "lexiconPT", "syuzhet",
  # Named Entity Recognition
  "udpipe", "spacyr",
  # Database
  "DBI", "RPostgres",
  # Visualization
  "ggplot2", "plotly", "wordcloud", "RColorBrewer", "viridis",
  # Performance
  "arrow", "parallel", "foreach", "doParallel",
  # Utilities
  "logger", "progress"
)

# Install and load packages
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("📦 Installing missing package:", pkg, "\n")
    install.packages(pkg, repos = "https://cran.rstudio.com/", quiet = TRUE)
  }
  suppressPackageStartupMessages(library(pkg, character.only = TRUE))
}

# Set up logging
log_threshold(INFO)

# Global variables for caching and performance
.text_mining_cache <- list()
.udpipe_model <- NULL
.stopwords_pt <- NULL

# =================================================================
# CORE TEXT PREPROCESSING FUNCTIONS
# =================================================================

#' Initialize Portuguese language resources
#' @return logical indicating success
initialize_portuguese_resources <- function() {
  tryCatch({
    # Load Portuguese stopwords with legal extensions
    .stopwords_pt <<- c(
      # Standard Portuguese stopwords
      stopwords::stopwords("pt"),
      # Legal/Administrative terms
      "lei", "decreto", "resolução", "portaria", "instrução", "normativa",
      "artigo", "parágrafo", "inciso", "alínea", "item", "capítulo",
      "estabelece", "dispõe", "institui", "cria", "altera", "revoga", "regulamenta",
      "brasil", "brasileiro", "brasileira", "nacional", "federal", "estadual", "municipal",
      "outras", "providências", "dá", "sobre", "para", "com", "por", "em", "de", "da", "do", "das", "dos",
      # Transportation specific
      "transporte", "rodoviário", "ferroviário", "aquaviário", "aéreo", "marítimo",
      "veículo", "tráfego", "trânsito", "infraestrutura", "logística",
      # Common legal phrases
      "tendo", "vista", "considerando", "resolve", "determina", "ficam", "fica"
    )
    
    # Download UDPipe model if not exists
    model_dir <- "udpipe_models"
    if (!dir.exists(model_dir)) {
      dir.create(model_dir, recursive = TRUE)
    }
    
    model_file <- file.path(model_dir, "portuguese-gsd-ud-2.5-191206.udpipe")
    if (!file.exists(model_file)) {
      cat("📥 Downloading Portuguese UDPipe model...\n")
      udpipe_download_model(language = "portuguese", model_dir = model_dir)
    }
    
    .udpipe_model <<- udpipe_load_model(model_file)
    cat("✅ Portuguese language resources initialized\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("⚠️ Error initializing Portuguese resources:", e$message, "\n")
    return(FALSE)
  })
}

#' Advanced Portuguese text preprocessing
#' @param texts Vector of texts to preprocess
#' @param remove_stopwords Logical, remove Portuguese stopwords
#' @param stem_words Logical, apply Portuguese stemming
#' @param min_char_length Minimum character length for documents
#' @return Vector of preprocessed texts
preprocess_legal_text <- function(texts, remove_stopwords = TRUE, 
                                 stem_words = FALSE, min_char_length = 50) {
  
  if (length(texts) == 0) return(character(0))
  
  cat("🔤 Preprocessing", length(texts), "legal texts...\n")
  
  # Step 1: Basic cleaning
  cleaned <- texts %>%
    # Convert to lowercase
    str_to_lower() %>%
    # Remove URLs and emails
    str_remove_all("http\\S+|www\\.\\S+|\\S+@\\S+") %>%
    # Remove legal document references (but keep important ones)
    str_remove_all("\\b(art|artigo)\\s*\\.?\\s*\\d+[°º]?\\s*[,.]?") %>%
    str_remove_all("\\b(par|parágrafo|§)\\s*\\.?\\s*\\d+[°º]?\\s*[,.]?") %>%
    str_remove_all("\\binciso\\s+[ivxlcdm]+\\b") %>%
    str_remove_all("\\balínea\\s+[a-zA-Z]\\b") %>%
    # Remove excessive numbers but keep years
    str_remove_all("\\b\\d{1,3}\\b(?!\\d)|\\b\\d{5,}\\b") %>%
    # Remove special characters but preserve Portuguese accents
    str_remove_all("[^a-zA-ZÀ-ÿ0-9\\s\\-]") %>%
    # Normalize whitespace
    str_replace_all("\\s+", " ") %>%
    str_trim()
  
  # Step 2: Legal document specific cleaning
  cleaned <- cleaned %>%
    # Remove common legal formulaic expressions
    str_remove_all("\\bdá\\s+outras\\s+providências\\b") %>%
    str_remove_all("\\be\\s+dá\\s+outras\\s+providências\\b") %>%
    str_remove_all("\\bno\\s+uso\\s+de\\s+suas\\s+atribuições\\b") %>%
    str_remove_all("\\btendo\\s+em\\s+vista\\b") %>%
    str_remove_all("\\bconsiderando\\s+que\\b") %>%
    # Remove classification metadata
    str_remove_all("classificação\\s*:\\s*[^\\n]*") %>%
    str_remove_all("autor\\s*:\\s*[^\\n]*") %>%
    str_remove_all("fonte\\s*:\\s*[^\\n]*")
  
  # Step 3: Stopword removal
  if (remove_stopwords && !is.null(.stopwords_pt)) {
    # Create regex pattern for word boundaries
    stopword_pattern <- paste0("\\b(", paste(.stopwords_pt, collapse = "|"), ")\\b")
    cleaned <- str_remove_all(cleaned, stopword_pattern)
  }
  
  # Step 4: Stemming (optional - can be computationally expensive)
  if (stem_words) {
    cleaned <- map_chr(cleaned, function(text) {
      words <- str_split(text, "\\s+")[[1]]
      if (length(words) > 0) {
        stemmed <- wordStem(words, language = "portuguese")
        return(paste(stemmed[stemmed != ""], collapse = " "))
      } else {
        return("")
      }
    })
  }
  
  # Final cleanup
  cleaned <- cleaned %>%
    str_replace_all("\\s+", " ") %>%
    str_trim() %>%
    # Filter by minimum length
    ifelse(nchar(.) < min_char_length, NA_character_, .)
  
  cat("✅ Text preprocessing completed\n")
  return(cleaned)
}

# =================================================================
# SENTIMENT ANALYSIS WITH REGULATORY CLASSIFICATION
# =================================================================

#' Create regulatory sentiment lexicon for Brazilian legal texts
#' @return data frame with regulatory terms and sentiment scores
create_regulatory_lexicon <- function() {
  
  # Positive regulatory terms (enabling, beneficial)
  positive_terms <- c(
    # Enabling terms
    "permite", "autoriza", "facilita", "promove", "incentiva", "estimula",
    "fortalece", "aprimora", "melhora", "desenvolve", "moderniza",
    "simplifica", "agiliza", "otimiza", "flexibiliza",
    # Rights and benefits
    "direito", "direitos", "benefício", "benefícios", "garantia", "garantias",
    "proteção", "segurança", "qualidade", "eficiência", "transparência",
    "participação", "democrático", "inclusivo", "sustentável",
    # Progressive terms
    "inovação", "modernização", "desenvolvimento", "progresso", "avanço",
    "melhoria", "aperfeiçoamento", "evolução", "crescimento"
  )
  
  # Negative regulatory terms (restrictive, prohibitive)
  negative_terms <- c(
    # Prohibitive terms
    "proíbe", "proibido", "proibição", "veda", "vedado", "impede", "impedir",
    "restringe", "restrição", "limita", "limitação", "condiciona",
    # Penalties and sanctions
    "multa", "penalidade", "sanção", "infração", "violação", "irregular",
    "ilegal", "ilícito", "crime", "delito", "contravenção",
    # Problems and issues
    "problema", "deficiência", "falha", "erro", "irregularidade",
    "inadequado", "insuficiente", "precário", "deficiente",
    # Risk and threat terms
    "risco", "perigo", "ameaça", "dano", "prejuízo", "lesão",
    "comprometimento", "deterioração", "degradação"
  )
  
  # Neutral regulatory terms (procedural)
  neutral_terms <- c(
    "estabelece", "dispõe", "regulamenta", "normatiza", "disciplina",
    "organiza", "estrutura", "define", "determina", "especifica",
    "classifica", "categoriza", "enumera", "relaciona", "identifica"
  )
  
  # Create lexicon data frame
  lexicon <- bind_rows(
    tibble(word = positive_terms, sentiment = 1, category = "positive"),
    tibble(word = negative_terms, sentiment = -1, category = "negative"),
    tibble(word = neutral_terms, sentiment = 0, category = "neutral")
  )
  
  return(lexicon)
}

#' Perform comprehensive sentiment analysis on legal texts
#' @param texts Vector of preprocessed texts
#' @param doc_metadata Data frame with document metadata
#' @return Data frame with sentiment analysis results
analyze_regulatory_sentiment <- function(texts, doc_metadata = NULL) {
  
  cat("💭 Performing regulatory sentiment analysis...\n")
  
  # Get regulatory lexicon
  reg_lexicon <- create_regulatory_lexicon()
  
  # Initialize results data frame
  results <- tibble(
    doc_id = seq_along(texts),
    text = texts,
    text_length_chars = nchar(texts),
    text_length_words = str_count(texts, "\\S+")
  )
  
  # Add metadata if provided
  if (!is.null(doc_metadata)) {
    results <- bind_cols(results, doc_metadata[seq_along(texts), ])
  }
  
  # Calculate sentiment scores
  results <- results %>%
    mutate(
      # Basic sentiment using sentimentr
      sentiment_basic = map_dbl(text, ~ {
        if (is.na(.x) || nchar(.x) == 0) return(0)
        tryCatch({
          sent_result <- sentiment(.x)
          return(mean(sent_result$sentiment, na.rm = TRUE))
        }, error = function(e) 0)
      }),
      
      # Regulatory lexicon sentiment
      sentiment_regulatory = map_dbl(text, ~ {
        if (is.na(.x) || nchar(.x) == 0) return(0)
        words <- str_split(str_to_lower(.x), "\\s+")[[1]]
        matches <- words[words %in% reg_lexicon$word]
        if (length(matches) == 0) return(0)
        
        sentiment_scores <- reg_lexicon$sentiment[match(matches, reg_lexicon$word)]
        return(mean(sentiment_scores, na.rm = TRUE))
      }),
      
      # Regulatory strictness index
      strictness_index = map_dbl(text, ~ {
        if (is.na(.x) || nchar(.x) == 0) return(0)
        text_lower <- str_to_lower(.x)
        
        # Count restrictive terms
        restrictive_patterns <- c(
          "\\bproib", "\\bved", "\\bimpede", "\\brestring", "\\blimit",
          "\\bmulta", "\\bpenal", "\\bsanção", "\\binfração",
          "\\bobrigatório", "\\bexigido", "\\bnecessário", "\\bindispensável"
        )
        
        restrictive_count <- sum(map_int(restrictive_patterns, ~ str_count(text_lower, .x)))
        
        # Count enabling terms
        enabling_patterns <- c(
          "\\bpermit", "\\bautori", "\\bfacil", "\\bpromov", "\\bincentiv",
          "\\bflexibil", "\\bsimplific", "\\bagiliz", "\\botimiz"
        )
        
        enabling_count <- sum(map_int(enabling_patterns, ~ str_count(text_lower, .x)))
        
        total_regulatory <- restrictive_count + enabling_count
        if (total_regulatory == 0) return(0.5)  # Neutral
        
        return(restrictive_count / total_regulatory)
      }),
      
      # Regulatory style classification
      regulatory_style = case_when(
        strictness_index >= 0.7 ~ "Prescriptive",
        strictness_index <= 0.3 ~ "Flexible",
        TRUE ~ "Balanced"
      ),
      
      # Overall sentiment category
      sentiment_category = case_when(
        sentiment_regulatory > 0.1 ~ "Positive",
        sentiment_regulatory < -0.1 ~ "Negative",
        TRUE ~ "Neutral"
      ),
      
      # Legal domain indicators
      has_penalties = str_detect(str_to_lower(text), "\\bmulta|\\bpenal|\\bsanção|\\binfração"),
      has_obligations = str_detect(str_to_lower(text), "\\bobrigatório|\\bdeve|\\bexigido"),
      has_permissions = str_detect(str_to_lower(text), "\\bpermit|\\bautori|\\bpode"),
      has_definitions = str_detect(str_to_lower(text), "\\bdefine|\\bentende|\\bconsider")
    )
  
  cat("✅ Regulatory sentiment analysis completed\n")
  return(results)
}

# =================================================================
# TOPIC MODELING SYSTEM
# =================================================================

#' Prepare document-term matrix for topic modeling
#' @param texts Vector of preprocessed texts
#' @param min_doc_freq Minimum document frequency for terms
#' @param max_doc_freq Maximum document frequency for terms (as proportion)
#' @return quanteda dfm object
prepare_dtm_for_topics <- function(texts, min_doc_freq = 3, max_doc_freq = 0.9) {
  
  cat("📊 Preparing document-term matrix for topic modeling...\n")
  
  # Remove empty texts
  valid_texts <- texts[!is.na(texts) & nchar(texts) > 0]
  
  if (length(valid_texts) == 0) {
    stop("No valid texts available for topic modeling")
  }
  
  # Create corpus
  corpus <- corpus(valid_texts)
  
  # Tokenize and create DTM
  tokens <- corpus %>%
    tokens(
      what = "word",
      remove_punct = TRUE,
      remove_symbols = TRUE,
      remove_numbers = TRUE,
      remove_url = TRUE
    ) %>%
    tokens_tolower() %>%
    tokens_remove(pattern = .stopwords_pt) %>%
    tokens_wordstem(language = "pt")
  
  # Create document-feature matrix
  dfm <- tokens %>%
    dfm() %>%
    dfm_trim(
      min_docfreq = min_doc_freq,
      max_docfreq = max_doc_freq,
      docfreq_type = "prop"
    ) %>%
    dfm_remove("")  # Remove empty features
  
  cat("✅ DTM created:", nrow(dfm), "documents,", ncol(dfm), "features\n")
  return(dfm)
}

#' Perform topic modeling with optimal topic selection
#' @param dfm Document-feature matrix
#' @param k_range Vector of topic numbers to test
#' @param method Method for topic modeling ("LDA" or "STM")
#' @param sample_size Maximum documents to use (for performance)
#' @return List with topic models and optimal selection
perform_topic_modeling <- function(dfm, k_range = c(5, 10, 15, 20), 
                                  method = "LDA", sample_size = 2000) {
  
  cat("🎯 Performing topic modeling with", method, "...\n")
  
  # Sample documents if dataset is too large
  if (nrow(dfm) > sample_size) {
    cat("📝 Sampling", sample_size, "documents for topic modeling\n")
    sample_indices <- sample(nrow(dfm), sample_size)
    dfm <- dfm[sample_indices, ]
  }
  
  # Convert to appropriate format
  if (method == "LDA") {
    dtm <- convert(dfm, to = "tm")
    
    # Find optimal number of topics
    cat("🔍 Finding optimal number of topics...\n")
    topic_models <- map(k_range, function(k) {
      cat("  Testing k =", k, "\n")
      LDA(dtm, k = k, control = list(seed = 1234, verbose = 0))
    })
    names(topic_models) <- paste0("k", k_range)
    
    # Calculate model metrics
    model_metrics <- tibble(
      k = k_range,
      perplexity = map_dbl(topic_models, perplexity),
      log_likelihood = map_dbl(topic_models, logLik)
    )
    
    # Select optimal model (lowest perplexity)
    optimal_k <- k_range[which.min(model_metrics$perplexity)]
    optimal_model <- topic_models[[paste0("k", optimal_k)]]
    
    cat("✅ Optimal number of topics:", optimal_k, "\n")
    
    return(list(
      models = topic_models,
      optimal_model = optimal_model,
      optimal_k = optimal_k,
      metrics = model_metrics,
      method = method
    ))
    
  } else if (method == "STM") {
    # STM implementation would go here
    # For now, fallback to LDA
    return(perform_topic_modeling(dfm, k_range, "LDA", sample_size))
  }
}

#' Extract and format topic results
#' @param topic_results Results from perform_topic_modeling
#' @param n_terms Number of top terms per topic
#' @return List with formatted topic information
extract_topic_insights <- function(topic_results, n_terms = 10) {
  
  cat("📋 Extracting topic insights...\n")
  
  optimal_model <- topic_results$optimal_model
  
  # Get top terms per topic
  topic_terms <- tidy(optimal_model, matrix = "beta") %>%
    group_by(topic) %>%
    slice_max(beta, n = n_terms) %>%
    arrange(topic, desc(beta)) %>%
    mutate(rank = row_number()) %>%
    ungroup()
  
  # Get document-topic probabilities
  doc_topics <- tidy(optimal_model, matrix = "gamma") %>%
    group_by(document) %>%
    slice_max(gamma, n = 1) %>%
    ungroup()
  
  # Create topic labels based on top terms
  topic_labels <- topic_terms %>%
    filter(rank <= 3) %>%
    group_by(topic) %>%
    summarise(
      label = paste(term, collapse = " + "),
      top_term = first(term),
      .groups = "drop"
    )
  
  # Topic statistics
  topic_stats <- doc_topics %>%
    count(topic, name = "n_documents") %>%
    left_join(topic_labels, by = "topic") %>%
    mutate(
      percentage = round(n_documents / sum(n_documents) * 100, 1)
    ) %>%
    arrange(desc(n_documents))
  
  cat("✅ Topic insights extracted for", nrow(topic_stats), "topics\n")
  
  return(list(
    topic_terms = topic_terms,
    doc_topics = doc_topics,
    topic_labels = topic_labels,
    topic_stats = topic_stats,
    optimal_k = topic_results$optimal_k
  ))
}

# =================================================================
# NAMED ENTITY RECOGNITION
# =================================================================

#' Perform Named Entity Recognition for Brazilian legal entities
#' @param texts Vector of texts (sample for performance)
#' @param sample_size Maximum number of documents to process
#' @return List with extracted entities
perform_legal_ner <- function(texts, sample_size = 500) {
  
  cat("🏛️ Performing Named Entity Recognition...\n")
  
  if (is.null(.udpipe_model)) {
    cat("⚠️ UDPipe model not loaded, skipping NER\n")
    return(list(entities = data.frame(), legal_entities = data.frame()))
  }
  
  # Sample texts for performance
  valid_texts <- texts[!is.na(texts) & nchar(texts) > 0]
  
  if (length(valid_texts) > sample_size) {
    cat("📝 Sampling", sample_size, "texts for NER\n")
    sample_indices <- sample(length(valid_texts), sample_size)
    valid_texts <- valid_texts[sample_indices]
  }
  
  # Process texts in batches
  batch_size <- 50
  all_annotations <- data.frame()
  
  for (i in seq(1, length(valid_texts), by = batch_size)) {
    end_idx <- min(i + batch_size - 1, length(valid_texts))
    batch_texts <- valid_texts[i:end_idx]
    
    cat("  Processing batch", ceiling(i/batch_size), "of", ceiling(length(valid_texts)/batch_size), "\n")
    
    batch_annotations <- map_dfr(seq_along(batch_texts), function(j) {
      doc_id <- i + j - 1
      text <- batch_texts[j]
      
      if (nchar(text) > 0) {
        tryCatch({
          annotated <- udpipe_annotate(.udpipe_model, x = text, doc_id = as.character(doc_id))
          as.data.frame(annotated)
        }, error = function(e) {
          data.frame()
        })
      } else {
        data.frame()
      }
    })
    
    all_annotations <- bind_rows(all_annotations, batch_annotations)
  }
  
  if (nrow(all_annotations) == 0) {
    cat("⚠️ No annotations extracted\n")
    return(list(entities = data.frame(), legal_entities = data.frame()))
  }
  
  # Extract general entities (nouns, proper nouns, adjectives)
  entities <- all_annotations %>%
    filter(upos %in% c("NOUN", "PROPN", "ADJ")) %>%
    group_by(lemma) %>%
    summarise(
      frequency = n(),
      pos_tags = paste(unique(upos), collapse = ","),
      .groups = "drop"
    ) %>%
    filter(
      nchar(lemma) > 2,
      frequency >= 2,
      !lemma %in% .stopwords_pt
    ) %>%
    arrange(desc(frequency))
  
  # Extract legal-specific entities
  legal_patterns <- c(
    # Laws and regulations
    "lei", "decreto", "resolução", "portaria", "instrução", "normativa",
    "código", "estatuto", "regimento", "regulamento",
    # Agencies and organizations
    "antt", "antaq", "anac", "dnit", "ministério", "secretaria",
    "agência", "autarquia", "fundação", "empresa",
    # Legal concepts
    "direito", "obrigação", "responsabilidade", "competência",
    "autorização", "licença", "permissão", "concessão"
  )
  
  legal_entities <- all_annotations %>%
    filter(
      upos %in% c("NOUN", "PROPN") &
      (str_detect(str_to_lower(lemma), paste(legal_patterns, collapse = "|")) |
       str_detect(str_to_lower(token), paste(legal_patterns, collapse = "|")))
    ) %>%
    group_by(lemma) %>%
    summarise(
      frequency = n(),
      contexts = paste(unique(token), collapse = ", "),
      .groups = "drop"
    ) %>%
    arrange(desc(frequency))
  
  cat("✅ NER completed:", nrow(entities), "general entities,", nrow(legal_entities), "legal entities\n")
  
  return(list(
    entities = entities,
    legal_entities = legal_entities
  ))
}

# =================================================================
# DATABASE INTEGRATION FUNCTIONS
# =================================================================

#' Save text mining results to Railway database
#' @param sentiment_results Sentiment analysis results
#' @param topic_results Topic modeling results
#' @param ner_results NER results
#' @param connection Database connection
#' @return logical indicating success
save_text_mining_to_db <- function(sentiment_results, topic_results, ner_results, connection) {
  
  cat("💾 Saving text mining results to database...\n")
  
  tryCatch({
    # Create tables if they don't exist
    dbExecute(connection, "
      CREATE TABLE IF NOT EXISTS text_mining_sentiment (
        id SERIAL PRIMARY KEY,
        doc_id INTEGER,
        sentiment_basic REAL,
        sentiment_regulatory REAL,
        strictness_index REAL,
        regulatory_style VARCHAR(50),
        sentiment_category VARCHAR(20),
        has_penalties BOOLEAN,
        has_obligations BOOLEAN,
        has_permissions BOOLEAN,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    ")
    
    dbExecute(connection, "
      CREATE TABLE IF NOT EXISTS text_mining_topics (
        id SERIAL PRIMARY KEY,
        topic_number INTEGER,
        term VARCHAR(100),
        beta REAL,
        rank_in_topic INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    ")
    
    dbExecute(connection, "
      CREATE TABLE IF NOT EXISTS text_mining_entities (
        id SERIAL PRIMARY KEY,
        entity VARCHAR(200),
        entity_type VARCHAR(50),
        frequency INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    ")
    
    # Clear existing data
    dbExecute(connection, "DELETE FROM text_mining_sentiment")
    dbExecute(connection, "DELETE FROM text_mining_topics")
    dbExecute(connection, "DELETE FROM text_mining_entities")
    
    # Save sentiment results
    if (!is.null(sentiment_results) && nrow(sentiment_results) > 0) {
      sentiment_to_save <- sentiment_results %>%
        select(doc_id, sentiment_basic, sentiment_regulatory, strictness_index,
               regulatory_style, sentiment_category, has_penalties, 
               has_obligations, has_permissions) %>%
        slice_head(n = 10000)  # Limit for performance
      
      dbWriteTable(connection, "text_mining_sentiment", sentiment_to_save, 
                   append = TRUE, row.names = FALSE)
    }
    
    # Save topic results
    if (!is.null(topic_results) && !is.null(topic_results$topic_terms)) {
      topic_terms_to_save <- topic_results$topic_terms %>%
        select(topic, term, beta) %>%
        mutate(rank_in_topic = row_number()) %>%
        rename(topic_number = topic)
      
      dbWriteTable(connection, "text_mining_topics", topic_terms_to_save,
                   append = TRUE, row.names = FALSE)
    }
    
    # Save entity results
    if (!is.null(ner_results$entities) && nrow(ner_results$entities) > 0) {
      entities_to_save <- ner_results$entities %>%
        slice_head(n = 1000) %>%
        mutate(entity_type = "general") %>%
        select(entity = lemma, entity_type, frequency)
      
      dbWriteTable(connection, "text_mining_entities", entities_to_save,
                   append = TRUE, row.names = FALSE)
    }
    
    if (!is.null(ner_results$legal_entities) && nrow(ner_results$legal_entities) > 0) {
      legal_entities_to_save <- ner_results$legal_entities %>%
        slice_head(n = 500) %>%
        mutate(entity_type = "legal") %>%
        select(entity = lemma, entity_type, frequency)
      
      dbWriteTable(connection, "text_mining_entities", legal_entities_to_save,
                   append = TRUE, row.names = FALSE)
    }
    
    cat("✅ Text mining results saved to database\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error saving to database:", e$message, "\n")
    return(FALSE)
  })
}

#' Load text mining results from Railway database
#' @param connection Database connection
#' @return List with cached results
load_text_mining_from_db <- function(connection) {
  
  tryCatch({
    sentiment_data <- dbReadTable(connection, "text_mining_sentiment")
    topic_data <- dbReadTable(connection, "text_mining_topics")
    entity_data <- dbReadTable(connection, "text_mining_entities")
    
    return(list(
      sentiment = sentiment_data,
      topics = topic_data,
      entities = entity_data,
      last_updated = Sys.time()
    ))
    
  }, error = function(e) {
    cat("⚠️ Could not load from database:", e$message, "\n")
    return(NULL)
  })
}

# =================================================================
# DASHBOARD INTEGRATION FUNCTIONS
# =================================================================

#' Get sentiment analysis summary for dashboard
#' @param connection Database connection
#' @return List with sentiment metrics
get_sentiment_dashboard_data <- function(connection = NULL) {
  
  # Try to load from database first
  if (!is.null(connection)) {
    cached_data <- load_text_mining_from_db(connection)
    if (!is.null(cached_data) && nrow(cached_data$sentiment) > 0) {
      sentiment_data <- cached_data$sentiment
      
      return(list(
        total_analyzed = nrow(sentiment_data),
        sentiment_distribution = table(sentiment_data$sentiment_category),
        regulatory_style_distribution = table(sentiment_data$regulatory_style),
        avg_strictness = round(mean(sentiment_data$strictness_index, na.rm = TRUE), 3),
        documents_with_penalties = sum(sentiment_data$has_penalties, na.rm = TRUE),
        documents_with_obligations = sum(sentiment_data$has_obligations, na.rm = TRUE),
        last_updated = Sys.time()
      ))
    }
  }
  
  # Return fallback data if database not available
  return(list(
    total_analyzed = 0,
    sentiment_distribution = c(Negative = 0, Neutral = 0, Positive = 0),
    regulatory_style_distribution = c(Balanced = 0, Flexible = 0, Prescriptive = 0),
    avg_strictness = 0,
    documents_with_penalties = 0,
    documents_with_obligations = 0,
    last_updated = Sys.time()
  ))
}

#' Get topic modeling summary for dashboard
#' @param connection Database connection
#' @return List with topic information
get_topics_dashboard_data <- function(connection = NULL) {
  
  if (!is.null(connection)) {
    cached_data <- load_text_mining_from_db(connection)
    if (!is.null(cached_data) && nrow(cached_data$topics) > 0) {
      topic_data <- cached_data$topics
      
      # Get top topics
      top_topics <- topic_data %>%
        filter(rank_in_topic <= 5) %>%
        group_by(topic_number) %>%
        summarise(
          top_terms = paste(term, collapse = ", "),
          avg_beta = round(mean(beta, na.rm = TRUE), 3),
          .groups = "drop"
        ) %>%
        arrange(desc(avg_beta)) %>%
        slice_head(n = 10)
      
      return(list(
        total_topics = length(unique(topic_data$topic_number)),
        top_topics = top_topics,
        last_updated = Sys.time()
      ))
    }
  }
  
  return(list(
    total_topics = 0,
    top_topics = data.frame(),
    last_updated = Sys.time()
  ))
}

#' Get entity recognition summary for dashboard
#' @param connection Database connection
#' @return List with entity information
get_entities_dashboard_data <- function(connection = NULL) {
  
  if (!is.null(connection)) {
    cached_data <- load_text_mining_from_db(connection)
    if (!is.null(cached_data) && nrow(cached_data$entities) > 0) {
      entity_data <- cached_data$entities
      
      top_general <- entity_data %>%
        filter(entity_type == "general") %>%
        arrange(desc(frequency)) %>%
        slice_head(n = 20)
      
      top_legal <- entity_data %>%
        filter(entity_type == "legal") %>%
        arrange(desc(frequency)) %>%
        slice_head(n = 20)
      
      return(list(
        total_entities = nrow(entity_data),
        top_general_entities = top_general,
        top_legal_entities = top_legal,
        last_updated = Sys.time()
      ))
    }
  }
  
  return(list(
    total_entities = 0,
    top_general_entities = data.frame(),
    top_legal_entities = data.frame(),
    last_updated = Sys.time()
  ))
}

# =================================================================
# MAIN PIPELINE EXECUTION FUNCTION
# =================================================================

#' Execute complete text mining pipeline
#' @param sample_size Number of documents to process (for performance)
#' @param connection Database connection
#' @param force_recompute Force recomputation even if cached results exist
#' @return List with all analysis results
run_advanced_text_mining_pipeline <- function(sample_size = 2000, connection = NULL, force_recompute = FALSE) {
  
  cat("🚀 STARTING ADVANCED TEXT MINING PIPELINE\n")
  cat("=" * 50, "\n")
  
  # Initialize Portuguese resources
  if (!initialize_portuguese_resources()) {
    cat("⚠️ Warning: Portuguese resources not fully initialized\n")
  }
  
  # Check for cached results first
  if (!force_recompute && !is.null(connection)) {
    cached_results <- load_text_mining_from_db(connection)
    if (!is.null(cached_results)) {
      cat("📋 Using cached text mining results\n")
      return(cached_results)
    }
  }
  
  # Load text data from database
  if (is.null(connection)) {
    cat("❌ No database connection provided\n")
    return(NULL)
  }
  
  # Get sample of documents for processing
  tryCatch({
    cat("📊 Loading sample of", sample_size, "documents from database...\n")
    
    sample_query <- sprintf("
      SELECT titulo, assuntos, ementa, categoria, autoridade, estado, ano
      FROM documents 
      WHERE titulo IS NOT NULL 
        AND LENGTH(titulo) > 20
      ORDER BY RANDOM()
      LIMIT %d
    ", sample_size)
    
    raw_data <- dbGetQuery(connection, sample_query)
    
    if (nrow(raw_data) == 0) {
      cat("❌ No documents found in database\n")
      return(NULL)
    }
    
    cat("✅ Loaded", nrow(raw_data), "documents\n")
    
    # Prepare combined text
    combined_texts <- paste(
      coalesce(raw_data$titulo, ""),
      coalesce(raw_data$assuntos, ""),
      coalesce(raw_data$ementa, ""),
      sep = " "
    )
    
    # Step 1: Preprocess texts
    cat("\n🔤 STEP 1: TEXT PREPROCESSING\n")
    preprocessed_texts <- preprocess_legal_text(combined_texts, remove_stopwords = TRUE)
    
    # Step 2: Sentiment Analysis
    cat("\n💭 STEP 2: SENTIMENT ANALYSIS\n")
    sentiment_results <- analyze_regulatory_sentiment(preprocessed_texts, raw_data)
    
    # Step 3: Topic Modeling
    cat("\n🎯 STEP 3: TOPIC MODELING\n")
    valid_texts <- preprocessed_texts[!is.na(preprocessed_texts) & nchar(preprocessed_texts) > 0]
    
    if (length(valid_texts) >= 10) {
      dtm <- prepare_dtm_for_topics(valid_texts, min_doc_freq = 2, max_doc_freq = 0.95)
      
      if (ncol(dtm) > 0 && nrow(dtm) > 0) {
        topic_modeling_results <- perform_topic_modeling(dtm, k_range = c(5, 8, 10, 12))
        topic_insights <- extract_topic_insights(topic_modeling_results)
      } else {
        cat("⚠️ DTM is empty, skipping topic modeling\n")
        topic_insights <- NULL
      }
    } else {
      cat("⚠️ Insufficient valid texts for topic modeling\n")
      topic_insights <- NULL
    }
    
    # Step 4: Named Entity Recognition
    cat("\n🏛️ STEP 4: NAMED ENTITY RECOGNITION\n")
    ner_results <- perform_legal_ner(preprocessed_texts, sample_size = min(500, length(preprocessed_texts)))
    
    # Step 5: Save to database
    cat("\n💾 STEP 5: SAVING RESULTS TO DATABASE\n")
    save_success <- save_text_mining_to_db(sentiment_results, topic_insights, ner_results, connection)
    
    # Compile final results
    final_results <- list(
      sentiment_analysis = sentiment_results,
      topic_modeling = topic_insights,
      named_entities = ner_results,
      processing_info = list(
        documents_processed = nrow(raw_data),
        valid_texts = sum(!is.na(preprocessed_texts)),
        processing_date = Sys.time(),
        sample_size = sample_size
      ),
      database_saved = save_success
    )
    
    cat("\n✅ ADVANCED TEXT MINING PIPELINE COMPLETED SUCCESSFULLY!\n")
    cat("📊 Processed", nrow(raw_data), "documents\n")
    cat("💭 Sentiment analysis:", nrow(sentiment_results), "documents\n")
    cat("🎯 Topics discovered:", ifelse(is.null(topic_insights), 0, topic_insights$optimal_k), "\n")
    cat("🏛️ Entities extracted:", ifelse(is.null(ner_results$entities), 0, nrow(ner_results$entities)), "\n")
    
    return(final_results)
    
  }, error = function(e) {
    cat("❌ Error in text mining pipeline:", e$message, "\n")
    return(NULL)
  })
}

# =================================================================
# INITIALIZATION
# =================================================================

# Initialize when script is loaded
cat("🔧 Initializing Advanced Text Mining Pipeline...\n")

# Check if we can connect to Railway database
tryCatch({
  source("RAILWAY_DATABASE_FIX.R")
  cat("✅ Railway database connection loaded\n")
}, error = function(e) {
  cat("⚠️ Railway database connection not available:", e$message, "\n")
})

cat("🎯 Advanced Text Mining Pipeline loaded and ready!\n")
cat("📋 Use run_advanced_text_mining_pipeline() to execute full analysis\n")
cat("📊 Use get_*_dashboard_data() functions for dashboard integration\n")