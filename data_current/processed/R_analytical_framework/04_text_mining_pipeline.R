#!/usr/bin/env Rscript
#' Brazilian Legislative Dataset - Phase 2: Text Mining Pipeline
#' 
#' This script implements a comprehensive text mining pipeline for the Brazilian
#' legislative dataset, including preprocessing, topic modeling, sentiment analysis,
#' and named entity recognition using tm, quanteda, tidytext, and other packages.
#' 
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-07-26
#' @version 1.0.0

# Load required libraries
suppressPackageStartupMessages({
  library(dplyr)
  library(stringr)
  library(tm)
  library(quanteda)
  library(tidytext)
  library(topicmodels)
  library(stm)
  library(ldatuning)
  library(sentimentr)
  library(lexiconPT)
  library(udpipe)
  library(spacyr)
  library(SnowballC)
  library(hunspell)
  library(textclean)
  library(textstat)
  library(ggplot2)
  library(wordcloud)
  library(RColorBrewer)
  library(viridis)
  library(purrr)
  library(lubridate)
  library(arrow)
  library(logger)
})

# Set up logging
log_threshold(INFO)

#' Text Mining Pipeline Functions
#' ==============================

#' Load and prepare text data
#' @param data_source Path to Parquet file or data frame
#' @return Prepared text data frame
load_text_data <- function(data_source) {
  
  log_info("Loading text data for mining...")
  
  if (is.character(data_source)) {
    # Load from Parquet file
    data <- read_parquet(data_source)
  } else {
    # Use provided data frame
    data <- data_source
  }
  
  # Combine text fields for analysis
  text_data <- data %>%
    mutate(
      # Combine title, subjects and summary into full text
      combined_text = paste(
        coalesce(titulo, ""),
        coalesce(assuntos, ""),
        coalesce(ementa, ""),
        sep = " "
      ),
      
      # Clean and prepare text fields
      titulo_clean = str_trim(titulo),
      assuntos_clean = str_trim(assuntos),
      ementa_clean = str_trim(ementa),
      
      # Create document ID
      doc_id = paste0("doc_", row_number()),
      
      # Extract year for temporal analysis
      year = year(data),
      decade = floor(year / 10) * 10
    ) %>%
    filter(
      # Keep only documents with meaningful text
      nchar(combined_text) > 50,
      !is.na(year),
      year >= 1900  # Remove obviously invalid dates
    )
  
  log_info("Loaded {nrow(text_data)} documents for text mining")
  return(text_data)
}

#' Advanced text preprocessing pipeline
#' @param text_vector Vector of text documents
#' @param language Language for processing (default: "portuguese")
#' @param remove_stopwords Whether to remove stopwords
#' @param stem_words Whether to perform stemming
#' @return Preprocessed text vector
preprocess_text <- function(text_vector, language = "portuguese", 
                          remove_stopwords = TRUE, stem_words = TRUE) {
  
  log_info("Preprocessing {length(text_vector)} text documents...")
  
  # Step 1: Basic cleaning
  cleaned_text <- text_vector %>%
    # Convert to lowercase
    str_to_lower() %>%
    # Remove extra whitespace
    str_squish() %>%
    # Remove URLs
    str_remove_all("http\\S+|www\\.\\S+") %>%
    # Remove email addresses
    str_remove_all("\\S+@\\S+") %>%
    # Remove numbers (but keep years that might be important)
    str_remove_all("\\b\\d{1,3}\\b|\\b\\d{5,}\\b") %>%
    # Remove special characters but keep Portuguese accents
    str_remove_all("[^a-zA-ZÀ-ÿ0-9\\s\\-]") %>%
    # Normalize multiple spaces
    str_replace_all("\\s+", " ") %>%
    str_trim()
  
  # Step 2: Portuguese-specific cleaning
  cleaned_text <- cleaned_text %>%
    # Remove common legal document artifacts
    str_remove_all("\\bartigo\\s+\\d+|\\bparágrafo\\s+\\d+|\\binciso\\s+[ivx]+") %>%
    str_remove_all("\\blei\\s+n[°º]?\\s*\\d+|\\bdecreto\\s+n[°º]?\\s*\\d+") %>%
    # Remove classification prefixes
    str_remove_all("autor:|classificação:|direito\\s+público") %>%
    # Remove common administrative terms that might not add value
    str_remove_all("\\bdá\\s+outras\\s+providências\\b|\\be\\s+dá\\s+outras\\s+providências\\b")
  
  # Step 3: Stopword removal (if requested)
  if (remove_stopwords) {
    # Load Portuguese stopwords
    portuguese_stopwords <- c(
      stopwords::stopwords("pt"),
      # Add custom legislative/legal stopwords
      "brasil", "brasileiro", "brasileira", "nacional", "federal", "estadual", "municipal",
      "lei", "decreto", "resolução", "portaria", "instrução", "normativa",
      "artigo", "parágrafo", "inciso", "alínea", "item",
      "estabelece", "dispõe", "institui", "cria", "altera", "revoga", "regulamenta",
      "outras", "providências", "dá", "sobre", "para", "com", "por", "em", "de", "da", "do", "das", "dos"
    )
    
    # Remove stopwords using word boundaries
    stopword_pattern <- paste0("\\b(", paste(portuguese_stopwords, collapse = "|"), ")\\b")
    cleaned_text <- str_remove_all(cleaned_text, stopword_pattern)
  }
  
  # Step 4: Stemming (if requested)
  if (stem_words) {
    # Use Portuguese stemming
    cleaned_text <- map_chr(cleaned_text, function(text) {
      words <- str_split(text, "\\s+")[[1]]
      stemmed_words <- wordStem(words, language = "portuguese")
      paste(stemmed_words, collapse = " ")
    })
  }
  
  # Final cleanup
  cleaned_text <- cleaned_text %>%
    str_replace_all("\\s+", " ") %>%
    str_trim() %>%
    # Remove very short or empty documents
    ifelse(nchar(.) < 10, NA_character_, .)
  
  log_info("Text preprocessing completed")
  return(cleaned_text)
}

#' Create document-term matrix using quanteda
#' @param text_data Data frame with text and metadata
#' @param text_column Name of the text column
#' @param min_docfreq Minimum document frequency for terms
#' @param max_docfreq Maximum document frequency for terms
#' @return quanteda dfm object
create_dtm_quanteda <- function(text_data, text_column = "combined_text", 
                               min_docfreq = 5, max_docfreq = 0.95) {
  
  log_info("Creating document-term matrix with quanteda...")
  
  # Create corpus
  corpus <- corpus(text_data, text_field = text_column)
  
  # Add document variables
  docvars(corpus, "year") <- text_data$year
  docvars(corpus, "categoria") <- text_data$categoria
  docvars(corpus, "modal") <- text_data$modal
  docvars(corpus, "autoridade") <- text_data$autoridade
  docvars(corpus, "jurisdicao") <- text_data$jurisdicao
  
  # Create tokens
  tokens <- corpus %>%
    tokens(
      what = "word",
      remove_punct = TRUE,
      remove_symbols = TRUE,
      remove_numbers = FALSE,
      remove_url = TRUE
    ) %>%
    tokens_tolower() %>%
    tokens_remove(stopwords("pt")) %>%
    tokens_wordstem(language = "pt")
  
  # Create document-feature matrix
  dfm <- tokens %>%
    dfm() %>%
    dfm_trim(
      min_docfreq = min_docfreq,
      max_docfreq = max_docfreq,
      docfreq_type = "prop"
    ) %>%
    dfm_remove("") # Remove empty tokens
  
  log_info("Created DTM with {nrow(dfm)} documents and {ncol(dfm)} features")
  return(dfm)
}

#' Perform topic modeling using multiple algorithms
#' @param dfm Document-feature matrix
#' @param k_range Range of topic numbers to test
#' @param algorithms Vector of algorithms to use
#' @return List of topic models
perform_topic_modeling <- function(dfm, k_range = c(5, 10, 15, 20, 25), 
                                 algorithms = c("LDA", "STM")) {
  
  log_info("Performing topic modeling...")
  
  # Convert to different formats as needed
  dtm_tm <- convert(dfm, to = "tm")
  stm_data <- convert(dfm, to = "stm")
  
  topic_models <- list()
  
  # LDA topic modeling
  if ("LDA" %in% algorithms) {
    log_info("Running LDA topic models...")
    
    lda_models <- map(k_range, function(k) {
      log_info("LDA with k={k}")
      LDA(dtm_tm, k = k, control = list(seed = 1234))
    })
    names(lda_models) <- paste0("LDA_k", k_range)
    topic_models$LDA <- lda_models
    
    # Find optimal number of topics for LDA
    log_info("Finding optimal number of topics for LDA...")
    lda_tuning <- FindTopicsNumber(
      dtm_tm,
      topics = k_range,
      metrics = c("Griffiths2004", "CaoJuan2009", "Arun2010", "Deveaud2014"),
      control = list(seed = 1234)
    )
    topic_models$LDA_tuning <- lda_tuning
  }
  
  # STM topic modeling
  if ("STM" %in% algorithms) {
    log_info("Running STM topic models...")
    
    stm_models <- map(k_range, function(k) {
      log_info("STM with k={k}")
      stm(documents = stm_data$documents,
          vocab = stm_data$vocab,
          K = k,
          prevalence = ~ year + categoria,
          data = stm_data$meta,
          init.type = "Spectral")
    })
    names(stm_models) <- paste0("STM_k", k_range)
    topic_models$STM <- stm_models
    
    # STM model selection
    log_info("STM model selection...")
    stm_select <- selectModel(stm_data$documents, stm_data$vocab, K = 20,
                             prevalence = ~ year + categoria, 
                             data = stm_data$meta,
                             runs = 5)
    topic_models$STM_selection <- stm_select
  }
  
  return(topic_models)
}

#' Perform sentiment analysis with custom legal dictionary
#' @param text_data Data frame with text
#' @param text_column Column containing text
#' @return Data frame with sentiment scores
perform_sentiment_analysis <- function(text_data, text_column = "combined_text") {
  
  log_info("Performing sentiment analysis...")
  
  # Create custom legal sentiment lexicon (Brazilian Portuguese)
  legal_positive <- c(
    "aprovação", "aprovado", "benefício", "melhoria", "desenvolvimento",
    "progresso", "eficiência", "transparência", "democrático", "participação",
    "modernização", "inovação", "sustentável", "segurança", "proteção",
    "direitos", "garantias", "qualidade", "excelência", "competência"
  )
  
  legal_negative <- c(
    "proibição", "proibido", "penalidade", "multa", "infração", "violação",
    "irregular", "ilegal", "problema", "deficiência", "falha", "risco",
    "ameaça", "dano", "prejuízo", "corrupção", "fraude", "negligência",
    "inadequado", "insuficiente", "crítico", "grave", "urgente"
  )
  
  # Combine with existing Portuguese lexicons
  custom_lexicon <- bind_rows(
    tibble(word = legal_positive, sentiment = 1, lexicon = "legal_custom"),
    tibble(word = legal_negative, sentiment = -1, lexicon = "legal_custom")
  )
  
  # Perform sentiment analysis using sentimentr
  sentiment_results <- text_data %>%
    mutate(
      # Basic sentiment using sentimentr
      sentiment_score = sentiment(get(text_column))$sentiment,
      
      # Custom lexicon-based sentiment
      custom_sentiment = map_dbl(get(text_column), function(text) {
        words <- str_split(str_to_lower(text), "\\s+")[[1]]
        positive_matches <- sum(words %in% legal_positive)
        negative_matches <- sum(words %in% legal_negative)
        total_matches <- positive_matches + negative_matches
        
        if (total_matches > 0) {
          (positive_matches - negative_matches) / total_matches
        } else {
          0
        }
      }),
      
      # Sentiment categories
      sentiment_category = case_when(
        sentiment_score > 0.1 ~ "Positive",
        sentiment_score < -0.1 ~ "Negative", 
        TRUE ~ "Neutral"
      ),
      
      custom_sentiment_category = case_when(
        custom_sentiment > 0.1 ~ "Positive",
        custom_sentiment < -0.1 ~ "Negative",
        TRUE ~ "Neutral"
      )
    )
  
  log_info("Sentiment analysis completed")
  return(sentiment_results)
}

#' Named Entity Recognition for legal documents
#' @param text_data Data frame with text
#' @param text_column Column containing text
#' @param model_name UDPipe model name
#' @return Data frame with extracted entities
perform_ner <- function(text_data, text_column = "combined_text", 
                       model_name = "portuguese-gsd-ud-2.5-191206.udpipe") {
  
  log_info("Performing Named Entity Recognition...")
  
  # Check if model exists, download if not
  model_file <- file.path("udpipe_models", model_name)
  if (!file.exists(model_file)) {
    dir.create("udpipe_models", showWarnings = FALSE)
    udpipe_download_model(language = "portuguese", model_dir = "udpipe_models")
  }
  
  # Load model
  model <- udpipe_load_model(model_file)
  
  # Sample data for NER (can be computationally expensive)
  sample_data <- text_data %>%
    slice_sample(n = min(1000, nrow(.))) %>%
    select(doc_id, all_of(text_column), categoria, modal, year)
  
  # Perform annotation
  annotations <- map_dfr(1:nrow(sample_data), function(i) {
    doc <- sample_data[i, ]
    text <- doc[[text_column]]
    
    if (!is.na(text) && nchar(text) > 0) {
      annotated <- udpipe_annotate(model, x = text, doc_id = doc$doc_id)
      as.data.frame(annotated)
    } else {
      data.frame()
    }
  })
  
  # Extract entities and key terms
  entities <- annotations %>%
    filter(upos %in% c("NOUN", "PROPN", "ADJ")) %>%
    group_by(doc_id, lemma) %>%
    summarise(
      frequency = n(),
      pos_tags = paste(unique(upos), collapse = ","),
      .groups = "drop"
    ) %>%
    filter(
      nchar(lemma) > 2,
      frequency >= 2
    )
  
  # Extract potential legal entities (organizations, laws, etc.)
  legal_entities <- annotations %>%
    filter(
      upos == "PROPN" | 
      str_detect(lemma, "lei|decreto|resolução|portaria|agência|ministério")
    ) %>%
    group_by(doc_id, lemma) %>%
    summarise(frequency = n(), .groups = "drop") %>%
    arrange(desc(frequency))
  
  log_info("NER completed. Extracted {nrow(entities)} general entities and {nrow(legal_entities)} legal entities")
  
  return(list(
    entities = entities,
    legal_entities = legal_entities,
    annotations = annotations
  ))
}

#' Generate comprehensive text mining report
#' @param text_data Original text data
#' @param topic_models Topic modeling results
#' @param sentiment_results Sentiment analysis results
#' @param ner_results NER results
#' @param output_dir Output directory
generate_text_mining_report <- function(text_data, topic_models, sentiment_results, 
                                       ner_results, output_dir) {
  
  log_info("Generating text mining report...")
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # 1. Basic text statistics
  text_stats <- text_data %>%
    summarise(
      total_documents = n(),
      avg_text_length = mean(nchar(combined_text), na.rm = TRUE),
      median_text_length = median(nchar(combined_text), na.rm = TRUE),
      date_range_start = min(year, na.rm = TRUE),
      date_range_end = max(year, na.rm = TRUE)
    )
  
  # 2. Topic modeling visualizations
  if (!is.null(topic_models$LDA)) {
    # Get best LDA model (using perplexity or other metrics)
    best_lda <- topic_models$LDA[[which.min(map_dbl(topic_models$LDA, perplexity))]]
    
    # Topic terms plot
    lda_terms <- tidy(best_lda, matrix = "beta") %>%
      group_by(topic) %>%
      top_n(10, beta) %>%
      ungroup() %>%
      arrange(topic, -beta)
    
    topic_plot <- lda_terms %>%
      mutate(term = reorder_within(term, beta, topic)) %>%
      ggplot(aes(beta, term, fill = factor(topic))) +
      geom_col(show.legend = FALSE) +
      facet_wrap(~ topic, scales = "free") +
      scale_y_reordered() +
      labs(title = "Top Terms by Topic (LDA)",
           x = "Beta (term probability within topic)",
           y = "Terms") +
      theme_minimal()
    
    ggsave(file.path(output_dir, "lda_topics.png"), topic_plot, 
           width = 12, height = 10, dpi = 300)
  }
  
  # 3. Sentiment analysis plots
  if (!is.null(sentiment_results)) {
    # Sentiment over time
    sentiment_time_plot <- sentiment_results %>%
      filter(!is.na(year)) %>%
      group_by(year, sentiment_category) %>%
      summarise(count = n(), .groups = "drop") %>%
      ggplot(aes(x = year, y = count, fill = sentiment_category)) +
      geom_col(position = "fill") +
      scale_fill_viridis_d() +
      labs(title = "Sentiment Distribution Over Time",
           x = "Year", y = "Proportion", fill = "Sentiment") +
      theme_minimal()
    
    # Sentiment by category
    sentiment_category_plot <- sentiment_results %>%
      group_by(categoria, sentiment_category) %>%
      summarise(count = n(), .groups = "drop") %>%
      ggplot(aes(x = categoria, y = count, fill = sentiment_category)) +
      geom_col(position = "fill") +
      coord_flip() +
      scale_fill_viridis_d() +
      labs(title = "Sentiment Distribution by Document Category",
           x = "Category", y = "Proportion", fill = "Sentiment") +
      theme_minimal()
    
    ggsave(file.path(output_dir, "sentiment_over_time.png"), sentiment_time_plot,
           width = 12, height = 6, dpi = 300)
    ggsave(file.path(output_dir, "sentiment_by_category.png"), sentiment_category_plot,
           width = 10, height = 8, dpi = 300)
  }
  
  # 4. Word clouds
  if (!is.null(ner_results$entities)) {
    # Most frequent terms
    top_terms <- ner_results$entities %>%
      group_by(lemma) %>%
      summarise(total_freq = sum(frequency), .groups = "drop") %>%
      top_n(100, total_freq)
    
    # Create word cloud
    png(file.path(output_dir, "wordcloud_top_terms.png"), width = 800, height = 600)
    wordcloud(words = top_terms$lemma, freq = top_terms$total_freq,
              min.freq = 2, max.words = 100, random.order = FALSE,
              rot.per = 0.35, colors = brewer.pal(8, "Dark2"))
    dev.off()
  }
  
  # 5. Save processed data
  write_parquet(sentiment_results, file.path(output_dir, "sentiment_analysis_results.parquet"))
  saveRDS(topic_models, file.path(output_dir, "topic_models.rds"))
  saveRDS(ner_results, file.path(output_dir, "ner_results.rds"))
  saveRDS(text_stats, file.path(output_dir, "text_statistics.rds"))
  
  log_info("Text mining report generated and saved to {output_dir}")
  
  return(list(
    text_stats = text_stats,
    output_dir = output_dir
  ))
}

#' Main text mining pipeline execution
#' @param data_source Path to data file or data frame
#' @param output_dir Output directory for results
run_text_mining_pipeline <- function(data_source, output_dir) {
  
  log_info("=== STARTING TEXT MINING PIPELINE ===")
  
  # 1. Load and prepare text data
  text_data <- load_text_data(data_source)
  
  # 2. Preprocess text
  text_data$preprocessed_text <- preprocess_text(text_data$combined_text)
  
  # 3. Create document-term matrix
  dfm <- create_dtm_quanteda(text_data, "preprocessed_text")
  
  # 4. Topic modeling
  topic_models <- perform_topic_modeling(dfm)
  
  # 5. Sentiment analysis
  sentiment_results <- perform_sentiment_analysis(text_data)
  
  # 6. Named Entity Recognition
  ner_results <- perform_ner(text_data)
  
  # 7. Generate comprehensive report
  report_results <- generate_text_mining_report(
    text_data, topic_models, sentiment_results, ner_results, output_dir
  )
  
  log_info("=== TEXT MINING PIPELINE COMPLETED ===")
  
  return(list(
    text_data = text_data,
    topic_models = topic_models,
    sentiment_results = sentiment_results,
    ner_results = ner_results,
    report_results = report_results
  ))
}

# Execute if run as script
if (!interactive()) {
  # Set paths
  parquet_file <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/parquet_dataset/combined_legislative_dataset.parquet"
  output_dir <- file.path(dirname(dirname(parquet_file)), "text_mining_results")
  
  # Check if Parquet file exists
  if (!file.exists(parquet_file)) {
    cat("Parquet file not found. Please run CSV to Parquet conversion first.\n")
    cat("Run: Rscript 02_csv_to_parquet_conversion.R\n")
    quit(status = 1)
  }
  
  # Run text mining pipeline
  results <- run_text_mining_pipeline(parquet_file, output_dir)
  
  cat("Text mining pipeline completed. Results saved to:", output_dir, "\n")
}