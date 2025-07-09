# AI Integration for Monitor Legislativo v4
# Document analysis, summarization, and intelligent query expansion

library(httr)
library(jsonlite)
library(digest)
library(dplyr)
library(lubridate)
library(future)
library(promises)

# AI Integration configuration
AI_CONFIG <- list(
  providers = list(
    openai = list(
      enabled = TRUE,
      api_key = Sys.getenv("OPENAI_API_KEY", ""),
      base_url = "https://api.openai.com/v1",
      models = list(
        text = "gpt-4o-mini",
        embedding = "text-embedding-3-small",
        summarization = "gpt-4o-mini",
        classification = "gpt-4o-mini"
      ),
      rate_limit = 60,  # requests per minute
      timeout = 30
    ),
    
    claude = list(
      enabled = TRUE,
      api_key = Sys.getenv("ANTHROPIC_API_KEY", ""),
      base_url = "https://api.anthropic.com/v1",
      models = list(
        text = "claude-3-haiku-20240307",
        summarization = "claude-3-haiku-20240307",
        analysis = "claude-3-sonnet-20240229"
      ),
      rate_limit = 50,
      timeout = 45
    ),
    
    huggingface = list(
      enabled = FALSE,
      api_key = Sys.getenv("HUGGINGFACE_API_KEY", ""),
      base_url = "https://api-inference.huggingface.co",
      models = list(
        summarization = "facebook/bart-large-cnn",
        classification = "nlptown/bert-base-multilingual-uncased-sentiment",
        embedding = "sentence-transformers/all-MiniLM-L6-v2"
      ),
      rate_limit = 100,
      timeout = 20
    )
  ),
  
  features = list(
    document_summarization = list(
      enabled = TRUE,
      max_length = 500,
      preferred_provider = "openai",
      fallback_provider = "claude",
      cache_results = TRUE
    ),
    
    semantic_search = list(
      enabled = TRUE,
      embedding_model = "text-embedding-3-small",
      similarity_threshold = 0.7,
      max_results = 20,
      enable_reranking = TRUE
    ),
    
    query_expansion = list(
      enabled = TRUE,
      expansion_limit = 5,
      use_synonyms = TRUE,
      use_legal_terms = TRUE,
      confidence_threshold = 0.6
    ),
    
    document_classification = list(
      enabled = TRUE,
      categories = c(
        "Lei", "Decreto", "Resolução", "Portaria", 
        "Instrução Normativa", "Medida Provisória", "Emenda Constitucional"
      ),
      confidence_threshold = 0.8,
      multi_label = TRUE
    ),
    
    text_analysis = list(
      enabled = TRUE,
      sentiment_analysis = TRUE,
      entity_extraction = TRUE,
      topic_modeling = FALSE,
      readability_scoring = TRUE
    )
  ),
  
  caching = list(
    enabled = TRUE,
    ttl_hours = 24,
    max_cache_size = 1000,
    cache_embeddings = TRUE,
    cache_summaries = TRUE
  ),
  
  performance = list(
    enable_async = TRUE,
    batch_size = 10,
    max_concurrent_requests = 5,
    retry_attempts = 3,
    circuit_breaker = TRUE
  )
)

# Global AI state
ai_state <- list(
  request_counts = list(),
  cached_results = list(),
  performance_metrics = list(),
  circuit_breakers = list()
)

#' Initialize AI integration system
#' @param config Optional configuration override
#' @return Initialization status
initialize_ai_integration <- function(config = NULL) {
  if (!is.null(config)) {
    AI_CONFIG <<- modifyList(AI_CONFIG, config)
  }
  
  log_event("Initializing AI integration system...", "INFO")
  
  # Initialize state
  ai_state$request_counts <<- list()
  ai_state$cached_results <<- list()
  ai_state$performance_metrics <<- list()
  ai_state$circuit_breakers <<- list()
  
  # Validate API keys and providers
  enabled_providers <- validate_ai_providers()
  
  # Initialize circuit breakers
  for (provider in names(AI_CONFIG$providers)) {
    if (AI_CONFIG$providers[[provider]]$enabled) {
      ai_state$circuit_breakers[[provider]] <<- list(
        failures = 0,
        last_failure = NULL,
        state = "closed"  # closed, open, half-open
      )
    }
  }
  
  log_event(paste("AI integration initialized with providers:", paste(enabled_providers, collapse = ", ")), "INFO")
  
  return(list(
    status = "success",
    enabled_providers = enabled_providers,
    features_enabled = sum(sapply(AI_CONFIG$features, function(x) x$enabled))
  ))
}

#' Summarize document using AI
#' @param document_text Document text content
#' @param summary_type Type of summary (executive, technical, legal)
#' @param max_length Maximum summary length
#' @param provider Preferred AI provider
#' @return Document summary
summarize_document <- function(document_text, summary_type = "executive", max_length = NULL, provider = NULL) {
  if (!AI_CONFIG$features$document_summarization$enabled) {
    return(list(error = "Document summarization is disabled"))
  }
  
  max_length <- max_length %||% AI_CONFIG$features$document_summarization$max_length
  provider <- provider %||% AI_CONFIG$features$document_summarization$preferred_provider
  
  # Check cache first
  cache_key <- generate_ai_cache_key("summarization", list(
    text = digest(document_text, algo = "md5"),
    type = summary_type,
    length = max_length
  ))
  
  if (AI_CONFIG$caching$enabled && AI_CONFIG$caching$cache_summaries) {
    cached_summary <- get_cached_ai_result(cache_key)
    if (!is.null(cached_summary)) {
      log_event("Cache HIT for document summarization", "INFO")
      return(cached_summary)
    }
  }
  
  # Prepare summarization prompt
  prompt <- create_summarization_prompt(document_text, summary_type, max_length)
  
  # Try primary provider
  summary_result <- call_ai_provider(provider, "summarization", prompt)
  
  # Fallback to secondary provider if primary fails
  if (!summary_result$success) {
    fallback_provider <- AI_CONFIG$features$document_summarization$fallback_provider
    if (fallback_provider != provider && !is.null(fallback_provider)) {
      log_event(paste("Falling back to", fallback_provider, "for summarization"), "WARN")
      summary_result <- call_ai_provider(fallback_provider, "summarization", prompt)
    }
  }
  
  if (summary_result$success) {
    # Cache successful result
    if (AI_CONFIG$caching$enabled) {
      cache_ai_result(cache_key, summary_result$data)
    }
    
    return(list(
      summary = summary_result$data$summary,
      summary_type = summary_type,
      original_length = nchar(document_text),
      summary_length = nchar(summary_result$data$summary),
      compression_ratio = round(nchar(summary_result$data$summary) / nchar(document_text), 3),
      provider = provider,
      generated_at = Sys.time()
    ))
  } else {
    return(list(
      error = "Summarization failed",
      message = summary_result$error
    ))
  }
}

#' Perform semantic search using AI embeddings
#' @param query Search query
#' @param documents Document collection to search
#' @param top_k Number of top results
#' @param provider AI provider for embeddings
#' @return Semantic search results
semantic_search <- function(query, documents, top_k = 10, provider = "openai") {
  if (!AI_CONFIG$features$semantic_search$enabled) {
    return(list(error = "Semantic search is disabled"))
  }
  
  # Generate query embedding
  query_embedding <- generate_text_embedding(query, provider)
  if (!query_embedding$success) {
    return(list(error = "Failed to generate query embedding"))
  }
  
  # Generate document embeddings (or retrieve from cache)
  document_embeddings <- list()
  for (i in seq_along(documents)) {
    doc <- documents[[i]]
    
    # Check cache for document embedding
    doc_cache_key <- generate_ai_cache_key("embedding", list(
      text = digest(doc$content, algo = "md5"),
      provider = provider
    ))
    
    cached_embedding <- get_cached_ai_result(doc_cache_key)
    if (!is.null(cached_embedding)) {
      document_embeddings[[i]] <- cached_embedding$embedding
    } else {
      doc_embedding <- generate_text_embedding(doc$content, provider)
      if (doc_embedding$success) {
        document_embeddings[[i]] <- doc_embedding$data$embedding
        
        # Cache embedding
        if (AI_CONFIG$caching$enabled && AI_CONFIG$caching$cache_embeddings) {
          cache_ai_result(doc_cache_key, list(embedding = doc_embedding$data$embedding))
        }
      } else {
        document_embeddings[[i]] <- NULL
      }
    }
  }
  
  # Calculate similarities
  similarities <- calculate_cosine_similarities(query_embedding$data$embedding, document_embeddings)
  
  # Filter and rank results
  valid_similarities <- similarities[!is.na(similarities)]
  threshold <- AI_CONFIG$features$semantic_search$similarity_threshold
  
  # Get top results above threshold
  result_indices <- which(valid_similarities >= threshold)
  if (length(result_indices) == 0) {
    return(list(
      results = list(),
      query = query,
      total_results = 0,
      message = "No documents found above similarity threshold"
    ))
  }
  
  # Sort by similarity score
  sorted_indices <- result_indices[order(valid_similarities[result_indices], decreasing = TRUE)]
  top_results <- head(sorted_indices, min(top_k, length(sorted_indices)))
  
  # Format results
  search_results <- lapply(top_results, function(idx) {
    list(
      document = documents[[idx]],
      similarity_score = valid_similarities[[idx]],
      rank = which(top_results == idx)
    )
  })
  
  return(list(
    results = search_results,
    query = query,
    total_results = length(search_results),
    embedding_provider = provider,
    search_time = Sys.time()
  ))
}

#' Expand search query using AI
#' @param query Original search query
#' @param domain Domain context (legal, regulatory, etc.)
#' @param provider AI provider
#' @return Expanded query terms
expand_search_query <- function(query, domain = "legal", provider = NULL) {
  if (!AI_CONFIG$features$query_expansion$enabled) {
    return(list(original_query = query, expanded_terms = c()))
  }
  
  provider <- provider %||% AI_CONFIG$features$document_summarization$preferred_provider
  
  # Check cache
  cache_key <- generate_ai_cache_key("query_expansion", list(
    query = query,
    domain = domain
  ))
  
  cached_expansion <- get_cached_ai_result(cache_key)
  if (!is.null(cached_expansion)) {
    return(cached_expansion)
  }
  
  # Create expansion prompt
  prompt <- create_query_expansion_prompt(query, domain)
  
  # Call AI provider
  expansion_result <- call_ai_provider(provider, "text", prompt)
  
  if (expansion_result$success) {
    # Parse expanded terms from response
    expanded_terms <- parse_expanded_terms(expansion_result$data$text)
    
    result <- list(
      original_query = query,
      expanded_terms = expanded_terms,
      domain = domain,
      provider = provider,
      generated_at = Sys.time()
    )
    
    # Cache result
    if (AI_CONFIG$caching$enabled) {
      cache_ai_result(cache_key, result)
    }
    
    return(result)
  } else {
    return(list(
      original_query = query,
      expanded_terms = c(),
      error = expansion_result$error
    ))
  }
}

#' Classify document using AI
#' @param document_text Document text
#' @param categories Optional custom categories
#' @param provider AI provider
#' @return Document classification
classify_document <- function(document_text, categories = NULL, provider = NULL) {
  if (!AI_CONFIG$features$document_classification$enabled) {
    return(list(error = "Document classification is disabled"))
  }
  
  categories <- categories %||% AI_CONFIG$features$document_classification$categories
  provider <- provider %||% AI_CONFIG$features$document_summarization$preferred_provider
  
  # Check cache
  cache_key <- generate_ai_cache_key("classification", list(
    text = digest(document_text, algo = "md5"),
    categories = digest(paste(categories, collapse = "|"), algo = "md5")
  ))
  
  cached_classification <- get_cached_ai_result(cache_key)
  if (!is.null(cached_classification)) {
    return(cached_classification)
  }
  
  # Create classification prompt
  prompt <- create_classification_prompt(document_text, categories)
  
  # Call AI provider
  classification_result <- call_ai_provider(provider, "classification", prompt)
  
  if (classification_result$success) {
    # Parse classification from response
    classifications <- parse_classification_result(classification_result$data$text, categories)
    
    result <- list(
      classifications = classifications,
      confidence_scores = calculate_classification_confidence(classifications),
      categories_used = categories,
      provider = provider,
      classified_at = Sys.time()
    )
    
    # Cache result
    if (AI_CONFIG$caching$enabled) {
      cache_ai_result(cache_key, result)
    }
    
    return(result)
  } else {
    return(list(
      error = "Classification failed",
      message = classification_result$error
    ))
  }
}

#' Analyze document text using AI
#' @param document_text Document text
#' @param analysis_types Types of analysis to perform
#' @param provider AI provider
#' @return Text analysis results
analyze_document_text <- function(document_text, analysis_types = c("sentiment", "entities", "readability"), provider = NULL) {
  if (!AI_CONFIG$features$text_analysis$enabled) {
    return(list(error = "Text analysis is disabled"))
  }
  
  provider <- provider %||% AI_CONFIG$features$document_summarization$preferred_provider
  
  # Check cache
  cache_key <- generate_ai_cache_key("text_analysis", list(
    text = digest(document_text, algo = "md5"),
    types = paste(analysis_types, collapse = "|")
  ))
  
  cached_analysis <- get_cached_ai_result(cache_key)
  if (!is.null(cached_analysis)) {
    return(cached_analysis)
  }
  
  analysis_results <- list()
  
  # Sentiment analysis
  if ("sentiment" %in% analysis_types && AI_CONFIG$features$text_analysis$sentiment_analysis) {
    sentiment_prompt <- create_sentiment_analysis_prompt(document_text)
    sentiment_result <- call_ai_provider(provider, "text", sentiment_prompt)
    
    if (sentiment_result$success) {
      analysis_results$sentiment <- parse_sentiment_result(sentiment_result$data$text)
    }
  }
  
  # Entity extraction
  if ("entities" %in% analysis_types && AI_CONFIG$features$text_analysis$entity_extraction) {
    entity_prompt <- create_entity_extraction_prompt(document_text)
    entity_result <- call_ai_provider(provider, "text", entity_prompt)
    
    if (entity_result$success) {
      analysis_results$entities <- parse_entity_result(entity_result$data$text)
    }
  }
  
  # Readability scoring
  if ("readability" %in% analysis_types && AI_CONFIG$features$text_analysis$readability_scoring) {
    analysis_results$readability <- calculate_readability_score(document_text)
  }
  
  result <- list(
    analysis = analysis_results,
    analysis_types = analysis_types,
    provider = provider,
    analyzed_at = Sys.time()
  )
  
  # Cache result
  if (AI_CONFIG$caching$enabled) {
    cache_ai_result(cache_key, result)
  }
  
  return(result)
}

#' Generate text embedding using AI
#' @param text Text to embed
#' @param provider AI provider
#' @return Text embedding
generate_text_embedding <- function(text, provider = "openai") {
  if (!check_circuit_breaker(provider)) {
    return(list(success = FALSE, error = "Circuit breaker open for provider"))
  }
  
  # Rate limiting check
  if (!check_ai_rate_limit(provider)) {
    return(list(success = FALSE, error = "Rate limit exceeded"))
  }
  
  provider_config <- AI_CONFIG$providers[[provider]]
  if (is.null(provider_config) || !provider_config$enabled) {
    return(list(success = FALSE, error = "Provider not available"))
  }
  
  tryCatch({
    if (provider == "openai") {
      response <- POST(
        url = paste0(provider_config$base_url, "/embeddings"),
        add_headers(
          "Authorization" = paste("Bearer", provider_config$api_key),
          "Content-Type" = "application/json"
        ),
        body = toJSON(list(
          input = text,
          model = provider_config$models$embedding
        ), auto_unbox = TRUE),
        timeout(provider_config$timeout)
      )
      
      if (status_code(response) == 200) {
        response_data <- fromJSON(content(response, "text", encoding = "UTF-8"))
        
        return(list(
          success = TRUE,
          data = list(
            embedding = response_data$data[[1]]$embedding,
            model = provider_config$models$embedding,
            usage = response_data$usage
          )
        ))
      } else {
        record_circuit_breaker_failure(provider)
        return(list(success = FALSE, error = paste("HTTP", status_code(response))))
      }
    }
    
    # Add other providers as needed
    return(list(success = FALSE, error = "Provider implementation not found"))
    
  }, error = function(e) {
    record_circuit_breaker_failure(provider)
    return(list(success = FALSE, error = e$message))
  })
}

# Helper functions

#' Call AI provider for text generation
#' @param provider Provider name
#' @param task Task type
#' @param prompt Text prompt
#' @return API response
call_ai_provider <- function(provider, task, prompt) {
  if (!check_circuit_breaker(provider)) {
    return(list(success = FALSE, error = "Circuit breaker open"))
  }
  
  if (!check_ai_rate_limit(provider)) {
    return(list(success = FALSE, error = "Rate limit exceeded"))
  }
  
  provider_config <- AI_CONFIG$providers[[provider]]
  
  tryCatch({
    if (provider == "openai") {
      model <- switch(task,
        "summarization" = provider_config$models$summarization,
        "classification" = provider_config$models$classification,
        provider_config$models$text
      )
      
      response <- POST(
        url = paste0(provider_config$base_url, "/chat/completions"),
        add_headers(
          "Authorization" = paste("Bearer", provider_config$api_key),
          "Content-Type" = "application/json"
        ),
        body = toJSON(list(
          model = model,
          messages = list(list(role = "user", content = prompt)),
          max_tokens = 1000,
          temperature = 0.3
        ), auto_unbox = TRUE),
        timeout(provider_config$timeout)
      )
      
      if (status_code(response) == 200) {
        response_data <- fromJSON(content(response, "text", encoding = "UTF-8"))
        
        return(list(
          success = TRUE,
          data = list(
            text = response_data$choices[[1]]$message$content,
            summary = response_data$choices[[1]]$message$content,
            model = model,
            usage = response_data$usage
          )
        ))
      } else {
        record_circuit_breaker_failure(provider)
        return(list(success = FALSE, error = paste("HTTP", status_code(response))))
      }
    } else if (provider == "claude") {
      model <- switch(task,
        "summarization" = provider_config$models$summarization,
        "analysis" = provider_config$models$analysis,
        provider_config$models$text
      )
      
      response <- POST(
        url = paste0(provider_config$base_url, "/messages"),
        add_headers(
          "x-api-key" = provider_config$api_key,
          "Content-Type" = "application/json",
          "anthropic-version" = "2023-06-01"
        ),
        body = toJSON(list(
          model = model,
          max_tokens = 1000,
          messages = list(list(role = "user", content = prompt))
        ), auto_unbox = TRUE),
        timeout(provider_config$timeout)
      )
      
      if (status_code(response) == 200) {
        response_data <- fromJSON(content(response, "text", encoding = "UTF-8"))
        
        return(list(
          success = TRUE,
          data = list(
            text = response_data$content[[1]]$text,
            summary = response_data$content[[1]]$text,
            model = model,
            usage = response_data$usage
          )
        ))
      } else {
        record_circuit_breaker_failure(provider)
        return(list(success = FALSE, error = paste("HTTP", status_code(response))))
      }
    }
    
    return(list(success = FALSE, error = "Provider not implemented"))
    
  }, error = function(e) {
    record_circuit_breaker_failure(provider)
    return(list(success = FALSE, error = e$message))
  })
}

#' Create summarization prompt
#' @param text Document text
#' @param summary_type Type of summary
#' @param max_length Maximum length
#' @return Formatted prompt
create_summarization_prompt <- function(text, summary_type, max_length) {
  paste0(
    "Analise o seguinte documento legislativo brasileiro e crie um resumo ", summary_type, " com no máximo ", max_length, " caracteres.\n\n",
    "Documento:\n", text, "\n\n",
    "Resumo ", summary_type, " (máximo ", max_length, " caracteres):"
  )
}

#' Create query expansion prompt
#' @param query Original query
#' @param domain Domain context
#' @return Formatted prompt
create_query_expansion_prompt <- function(query, domain) {
  paste0(
    "Expanda a seguinte consulta de busca no domínio ", domain, " brasileiro. ",
    "Forneça termos relacionados, sinônimos e variações que possam melhorar os resultados de busca.\n\n",
    "Consulta original: ", query, "\n\n",
    "Termos expandidos (separados por vírgula):"
  )
}

#' Create classification prompt
#' @param text Document text
#' @param categories Available categories
#' @return Formatted prompt
create_classification_prompt <- function(text, categories) {
  paste0(
    "Classifique o seguinte documento legislativo brasileiro nas categorias apropriadas.\n\n",
    "Categorias disponíveis: ", paste(categories, collapse = ", "), "\n\n",
    "Documento:\n", text, "\n\n",
    "Classificação (indique todas as categorias aplicáveis):"
  )
}

#' Validate AI providers
#' @return List of enabled providers
validate_ai_providers <- function() {
  enabled_providers <- c()
  
  for (provider_name in names(AI_CONFIG$providers)) {
    provider_config <- AI_CONFIG$providers[[provider_name]]
    
    if (provider_config$enabled && provider_config$api_key != "") {
      enabled_providers <- c(enabled_providers, provider_name)
    }
  }
  
  return(enabled_providers)
}

#' Check AI rate limit
#' @param provider Provider name
#' @return Whether request is allowed
check_ai_rate_limit <- function(provider) {
  current_minute <- format(Sys.time(), "%Y-%m-%d %H:%M")
  rate_key <- paste(provider, current_minute, sep = "_")
  
  if (is.null(ai_state$request_counts[[rate_key]])) {
    ai_state$request_counts[[rate_key]] <<- 0
  }
  
  rate_limit <- AI_CONFIG$providers[[provider]]$rate_limit
  
  if (ai_state$request_counts[[rate_key]] >= rate_limit) {
    return(FALSE)
  }
  
  ai_state$request_counts[[rate_key]] <<- ai_state$request_counts[[rate_key]] + 1
  return(TRUE)
}

#' Generate AI cache key
#' @param operation Operation type
#' @param params Parameters
#' @return Cache key
generate_ai_cache_key <- function(operation, params) {
  key_data <- list(operation = operation, params = params)
  digest(toJSON(key_data, auto_unbox = TRUE), algo = "md5")
}

#' Cache AI result
#' @param cache_key Cache key
#' @param result Result data
cache_ai_result <- function(cache_key, result) {
  if (!AI_CONFIG$caching$enabled) {
    return()
  }
  
  cache_entry <- list(
    data = result,
    cached_at = Sys.time(),
    ttl_hours = AI_CONFIG$caching$ttl_hours
  )
  
  ai_state$cached_results[[cache_key]] <<- cache_entry
  
  # Limit cache size
  if (length(ai_state$cached_results) > AI_CONFIG$caching$max_cache_size) {
    # Remove oldest entries
    timestamps <- sapply(ai_state$cached_results, function(x) x$cached_at)
    oldest_keys <- names(sort(timestamps))[1:100]
    
    for (key in oldest_keys) {
      ai_state$cached_results[[key]] <<- NULL
    }
  }
}

#' Get cached AI result
#' @param cache_key Cache key
#' @return Cached result or NULL
get_cached_ai_result <- function(cache_key) {
  cache_entry <- ai_state$cached_results[[cache_key]]
  
  if (is.null(cache_entry)) {
    return(NULL)
  }
  
  # Check if cache has expired
  age_hours <- as.numeric(Sys.time() - cache_entry$cached_at, units = "hours")
  if (age_hours > cache_entry$ttl_hours) {
    ai_state$cached_results[[cache_key]] <<- NULL
    return(NULL)
  }
  
  return(cache_entry$data)
}

#' Check circuit breaker status
#' @param provider Provider name
#' @return Whether provider is available
check_circuit_breaker <- function(provider) {
  if (!AI_CONFIG$performance$circuit_breaker) {
    return(TRUE)
  }
  
  cb <- ai_state$circuit_breakers[[provider]]
  if (is.null(cb)) {
    return(TRUE)
  }
  
  if (cb$state == "open") {
    # Check if enough time has passed to try again
    if (!is.null(cb$last_failure)) {
      time_since_failure <- as.numeric(Sys.time() - cb$last_failure, units = "mins")
      if (time_since_failure > 5) {  # 5 minute timeout
        ai_state$circuit_breakers[[provider]]$state <<- "half-open"
        return(TRUE)
      }
    }
    return(FALSE)
  }
  
  return(TRUE)
}

#' Record circuit breaker failure
#' @param provider Provider name
record_circuit_breaker_failure <- function(provider) {
  if (!AI_CONFIG$performance$circuit_breaker) {
    return()
  }
  
  cb <- ai_state$circuit_breakers[[provider]]
  if (is.null(cb)) {
    return()
  }
  
  cb$failures <- cb$failures + 1
  cb$last_failure <- Sys.time()
  
  # Open circuit breaker after 3 failures
  if (cb$failures >= 3) {
    cb$state <- "open"
    log_event(paste("Circuit breaker opened for provider:", provider), "WARN")
  }
  
  ai_state$circuit_breakers[[provider]] <<- cb
}

#' Calculate cosine similarities
#' @param query_embedding Query embedding vector
#' @param document_embeddings List of document embedding vectors
#' @return Vector of similarity scores
calculate_cosine_similarities <- function(query_embedding, document_embeddings) {
  sapply(document_embeddings, function(doc_embedding) {
    if (is.null(doc_embedding)) {
      return(NA)
    }
    
    # Calculate cosine similarity
    dot_product <- sum(query_embedding * doc_embedding)
    query_norm <- sqrt(sum(query_embedding^2))
    doc_norm <- sqrt(sum(doc_embedding^2))
    
    if (query_norm == 0 || doc_norm == 0) {
      return(0)
    }
    
    return(dot_product / (query_norm * doc_norm))
  })
}

#' Parse expanded terms from AI response
#' @param response_text AI response text
#' @return Vector of expanded terms
parse_expanded_terms <- function(response_text) {
  # Simple parsing - split by comma and clean
  terms <- strsplit(response_text, ",")[[1]]
  terms <- trimws(terms)
  terms <- terms[terms != ""]
  
  # Limit number of terms
  max_terms <- AI_CONFIG$features$query_expansion$expansion_limit
  return(head(terms, max_terms))
}

#' Calculate readability score
#' @param text Document text
#' @return Readability metrics
calculate_readability_score <- function(text) {
  # Simple readability metrics
  words <- strsplit(text, "\\s+")[[1]]
  sentences <- strsplit(text, "[.!?]+")[[1]]
  
  avg_words_per_sentence <- length(words) / length(sentences)
  avg_chars_per_word <- mean(nchar(words))
  
  # Simple complexity score (0-100)
  complexity <- min(100, (avg_words_per_sentence * 2) + (avg_chars_per_word * 5))
  
  return(list(
    total_words = length(words),
    total_sentences = length(sentences),
    avg_words_per_sentence = round(avg_words_per_sentence, 1),
    avg_chars_per_word = round(avg_chars_per_word, 1),
    complexity_score = round(complexity, 1),
    readability_level = if (complexity < 30) "Fácil" else if (complexity < 60) "Médio" else "Difícil"
  ))
}

#' Get AI integration statistics
#' @return Integration statistics
get_ai_statistics <- function() {
  # Calculate request statistics
  total_requests <- sum(sapply(ai_state$request_counts, function(x) x))
  
  # Provider breakdown
  provider_stats <- list()
  for (provider in names(AI_CONFIG$providers)) {
    provider_requests <- sum(sapply(names(ai_state$request_counts), function(key) {
      if (startsWith(key, provider)) {
        ai_state$request_counts[[key]]
      } else {
        0
      }
    }))
    provider_stats[[provider]] <- provider_requests
  }
  
  # Cache statistics
  cache_size <- length(ai_state$cached_results)
  cache_hit_ratio <- if (total_requests > 0) {
    # Simplified calculation
    0.3  # Placeholder
  } else {
    0
  }
  
  return(list(
    total_requests = total_requests,
    provider_breakdown = provider_stats,
    cache_size = cache_size,
    cache_hit_ratio = cache_hit_ratio,
    enabled_features = sum(sapply(AI_CONFIG$features, function(x) x$enabled)),
    circuit_breaker_status = sapply(ai_state$circuit_breakers, function(x) x$state)
  ))
}