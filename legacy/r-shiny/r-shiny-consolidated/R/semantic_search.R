# Semantic Search Engine for Monitor Legislativo v4
# AI-powered semantic search with embeddings and intelligent ranking

library(dplyr)
library(jsonlite)
library(digest)
library(stringr)
library(lubridate)
library(Matrix)

# Semantic search configuration
SEMANTIC_CONFIG <- list(
  embeddings = list(
    provider = "openai",
    model = "text-embedding-3-small",
    dimension = 1536,
    batch_size = 100,
    cache_embeddings = TRUE,
    embedding_ttl_days = 30
  ),
  
  search = list(
    similarity_threshold = 0.7,
    max_results = 50,
    boost_recent_documents = TRUE,
    recency_weight = 0.1,
    enable_query_expansion = TRUE,
    enable_reranking = TRUE
  ),
  
  indexing = list(
    chunk_size = 1000,
    overlap_size = 200,
    min_chunk_length = 100,
    index_metadata = TRUE,
    index_refresh_hours = 24
  ),
  
  ranking = list(
    factors = list(
      semantic_similarity = 0.6,
      keyword_match = 0.2,
      document_importance = 0.1,
      recency = 0.1
    ),
    importance_metrics = c("citation_count", "view_count", "download_count"),
    boost_official_sources = TRUE
  ),
  
  query_processing = list(
    enable_spell_check = TRUE,
    enable_synonym_expansion = TRUE,
    enable_legal_term_expansion = TRUE,
    max_expanded_terms = 10,
    stopwords_removal = TRUE
  )
)

# Global semantic search state
semantic_state <- list(
  embeddings_index = list(),
  document_chunks = list(),
  embedding_cache = list(),
  query_cache = list(),
  index_metadata = list()
)

#' Initialize semantic search system
#' @param config Optional configuration override
#' @return Initialization status
initialize_semantic_search <- function(config = NULL) {
  if (!is.null(config)) {
    SEMANTIC_CONFIG <<- modifyList(SEMANTIC_CONFIG, config)
  }
  
  log_event("Initializing semantic search system...", "INFO")
  
  # Initialize state
  semantic_state$embeddings_index <<- list()
  semantic_state$document_chunks <<- list()
  semantic_state$embedding_cache <<- list()
  semantic_state$query_cache <<- list()
  semantic_state$index_metadata <<- list()
  
  # Load existing embeddings index if available
  load_embeddings_index()
  
  # Validate AI integration
  ai_available <- check_ai_integration()
  
  log_event(paste("Semantic search initialized. AI available:", ai_available), "INFO")
  
  return(list(
    status = "success",
    ai_available = ai_available,
    indexed_documents = length(semantic_state$document_chunks),
    embedding_cache_size = length(semantic_state$embedding_cache)
  ))
}

#' Index documents for semantic search
#' @param documents List of documents to index
#' @param force_reindex Whether to force reindexing
#' @return Indexing result
index_documents_for_search <- function(documents, force_reindex = FALSE) {
  log_event(paste("Indexing", length(documents), "documents for semantic search"), "INFO")
  
  indexed_count <- 0
  error_count <- 0
  
  for (document in documents) {
    # Check if document is already indexed
    doc_id <- document$id %||% digest(document$content, algo = "md5")
    
    if (!force_reindex && doc_id %in% names(semantic_state$document_chunks)) {
      next
    }
    
    tryCatch({
      # Split document into chunks
      chunks <- split_document_into_chunks(document)
      
      # Generate embeddings for chunks
      chunk_embeddings <- list()
      for (i in seq_along(chunks)) {
        chunk <- chunks[[i]]
        
        # Check embedding cache
        chunk_cache_key <- generate_embedding_cache_key(chunk$content)
        cached_embedding <- get_cached_embedding(chunk_cache_key)
        
        if (!is.null(cached_embedding)) {
          chunk_embeddings[[i]] <- cached_embedding
        } else {
          # Generate new embedding
          embedding_result <- generate_text_embedding(chunk$content, SEMANTIC_CONFIG$embeddings$provider)
          
          if (embedding_result$success) {
            chunk_embeddings[[i]] <- embedding_result$data$embedding
            
            # Cache embedding
            cache_embedding(chunk_cache_key, embedding_result$data$embedding)
          } else {
            log_event(paste("Failed to generate embedding for chunk", i, "of document", doc_id), "WARN")
            chunk_embeddings[[i]] <- NULL
          }
        }
      }
      
      # Store document chunks and embeddings
      semantic_state$document_chunks[[doc_id]] <<- list(
        document = document,
        chunks = chunks,
        embeddings = chunk_embeddings,
        indexed_at = Sys.time()
      )
      
      # Update embeddings index
      for (i in seq_along(chunks)) {
        if (!is.null(chunk_embeddings[[i]])) {
          chunk_id <- paste0(doc_id, "_chunk_", i)
          semantic_state$embeddings_index[[chunk_id]] <<- list(
            document_id = doc_id,
            chunk_index = i,
            embedding = chunk_embeddings[[i]],
            metadata = list(
              content = chunks[[i]]$content,
              start_pos = chunks[[i]]$start_pos,
              end_pos = chunks[[i]]$end_pos,
              length = nchar(chunks[[i]]$content)
            )
          )
        }
      }
      
      indexed_count <- indexed_count + 1
      
    }, error = function(e) {
      log_event(paste("Error indexing document", doc_id, ":", e$message), "ERROR")
      error_count <- error_count + 1
    })
  }
  
  # Update index metadata
  semantic_state$index_metadata$last_update <<- Sys.time()
  semantic_state$index_metadata$total_documents <<- length(semantic_state$document_chunks)
  semantic_state$index_metadata$total_chunks <<- length(semantic_state$embeddings_index)
  
  log_event(paste("Indexing completed:", indexed_count, "documents indexed,", error_count, "errors"), "INFO")
  
  return(list(
    status = "completed",
    indexed_count = indexed_count,
    error_count = error_count,
    total_chunks = length(semantic_state$embeddings_index)
  ))
}

#' Perform semantic search
#' @param query Search query
#' @param filters Additional filters
#' @param options Search options
#' @return Search results
semantic_search_query <- function(query, filters = list(), options = list()) {
  log_event(paste("Performing semantic search for query:", query), "INFO")
  
  # Check query cache
  cache_key <- generate_query_cache_key(query, filters, options)
  cached_results <- get_cached_query_results(cache_key)
  
  if (!is.null(cached_results)) {
    log_event("Cache HIT for semantic search query", "INFO")
    return(cached_results)
  }
  
  # Process query
  processed_query <- process_search_query(query)
  
  # Generate query embedding
  query_embedding_result <- generate_text_embedding(processed_query$main_query, SEMANTIC_CONFIG$embeddings$provider)
  
  if (!query_embedding_result$success) {
    return(list(
      error = "Failed to generate query embedding",
      results = list(),
      total_results = 0
    ))
  }
  
  query_embedding <- query_embedding_result$data$embedding
  
  # Calculate similarities with all chunks
  similarities <- calculate_chunk_similarities(query_embedding)
  
  # Filter by similarity threshold
  threshold <- options$similarity_threshold %||% SEMANTIC_CONFIG$search$similarity_threshold
  relevant_chunks <- similarities[similarities$similarity >= threshold, ]
  
  if (nrow(relevant_chunks) == 0) {
    return(list(
      query = query,
      processed_query = processed_query,
      results = list(),
      total_results = 0,
      message = "No relevant documents found"
    ))
  }
  
  # Apply additional filters
  if (length(filters) > 0) {
    relevant_chunks <- apply_search_filters(relevant_chunks, filters)
  }
  
  # Rank results
  ranked_results <- rank_search_results(relevant_chunks, processed_query, options)
  
  # Limit results
  max_results <- options$max_results %||% SEMANTIC_CONFIG$search$max_results
  final_results <- head(ranked_results, max_results)
  
  # Format results
  formatted_results <- format_search_results(final_results, query)
  
  search_result <- list(
    query = query,
    processed_query = processed_query,
    results = formatted_results,
    total_results = nrow(relevant_chunks),
    returned_results = length(formatted_results),
    search_time = Sys.time(),
    embedding_provider = SEMANTIC_CONFIG$embeddings$provider
  )
  
  # Cache results
  cache_query_results(cache_key, search_result)
  
  return(search_result)
}

#' Process search query
#' @param query Raw search query
#' @return Processed query object
process_search_query <- function(query) {
  log_event("Processing search query", "INFO")
  
  # Clean query
  cleaned_query <- str_trim(query)
  cleaned_query <- str_squish(cleaned_query)
  
  # Remove stopwords if enabled
  if (SEMANTIC_CONFIG$query_processing$stopwords_removal) {
    cleaned_query <- remove_stopwords(cleaned_query)
  }
  
  # Expand query if enabled
  expanded_terms <- c()
  if (SEMANTIC_CONFIG$query_processing$enable_synonym_expansion) {
    expanded_terms <- c(expanded_terms, expand_with_synonyms(cleaned_query))
  }
  
  if (SEMANTIC_CONFIG$query_processing$enable_legal_term_expansion) {
    expanded_terms <- c(expanded_terms, expand_with_legal_terms(cleaned_query))
  }
  
  # Use AI query expansion if available
  if (SEMANTIC_CONFIG$search$enable_query_expansion && exists("expand_search_query")) {
    ai_expansion <- expand_search_query(cleaned_query, "legal")
    if (!is.null(ai_expansion$expanded_terms)) {
      expanded_terms <- c(expanded_terms, ai_expansion$expanded_terms)
    }
  }
  
  # Limit expanded terms
  max_terms <- SEMANTIC_CONFIG$query_processing$max_expanded_terms
  expanded_terms <- head(unique(expanded_terms), max_terms)
  
  return(list(
    original_query = query,
    main_query = cleaned_query,
    expanded_terms = expanded_terms,
    combined_query = paste(c(cleaned_query, expanded_terms), collapse = " ")
  ))
}

#' Split document into chunks
#' @param document Document object
#' @return List of document chunks
split_document_into_chunks <- function(document) {
  content <- document$content %||% document$text %||% ""
  chunk_size <- SEMANTIC_CONFIG$indexing$chunk_size
  overlap_size <- SEMANTIC_CONFIG$indexing$overlap_size
  min_length <- SEMANTIC_CONFIG$indexing$min_chunk_length
  
  if (nchar(content) <= chunk_size) {
    return(list(list(
      content = content,
      start_pos = 1,
      end_pos = nchar(content),
      chunk_index = 1
    )))
  }
  
  chunks <- list()
  start_pos <- 1
  chunk_index <- 1
  
  while (start_pos <= nchar(content)) {
    end_pos <- min(start_pos + chunk_size - 1, nchar(content))
    
    # Try to break at sentence boundaries
    if (end_pos < nchar(content)) {
      sentence_break <- find_sentence_break(content, start_pos, end_pos)
      if (sentence_break > start_pos + min_length) {
        end_pos <- sentence_break
      }
    }
    
    chunk_content <- substr(content, start_pos, end_pos)
    
    if (nchar(chunk_content) >= min_length) {
      chunks[[chunk_index]] <- list(
        content = chunk_content,
        start_pos = start_pos,
        end_pos = end_pos,
        chunk_index = chunk_index
      )
      chunk_index <- chunk_index + 1
    }
    
    # Move start position with overlap
    start_pos <- end_pos - overlap_size + 1
    
    if (start_pos > nchar(content)) {
      break
    }
  }
  
  return(chunks)
}

#' Calculate similarities between query and chunks
#' @param query_embedding Query embedding vector
#' @return Data frame with similarities
calculate_chunk_similarities <- function(query_embedding) {
  if (length(semantic_state$embeddings_index) == 0) {
    return(data.frame())
  }
  
  similarities <- data.frame(
    chunk_id = character(),
    document_id = character(),
    chunk_index = integer(),
    similarity = numeric(),
    stringsAsFactors = FALSE
  )
  
  for (chunk_id in names(semantic_state$embeddings_index)) {
    chunk_data <- semantic_state$embeddings_index[[chunk_id]]
    chunk_embedding <- chunk_data$embedding
    
    # Calculate cosine similarity
    similarity <- calculate_cosine_similarity(query_embedding, chunk_embedding)
    
    similarities <- rbind(similarities, data.frame(
      chunk_id = chunk_id,
      document_id = chunk_data$document_id,
      chunk_index = chunk_data$chunk_index,
      similarity = similarity,
      stringsAsFactors = FALSE
    ))
  }
  
  # Sort by similarity
  similarities <- similarities[order(similarities$similarity, decreasing = TRUE), ]
  
  return(similarities)
}

#' Apply search filters
#' @param results Search results
#' @param filters Filter criteria
#' @return Filtered results
apply_search_filters <- function(results, filters) {
  filtered_results <- results
  
  # Document type filter
  if (!is.null(filters$types) && length(filters$types) > 0) {
    doc_types <- sapply(filtered_results$document_id, function(doc_id) {
      doc_data <- semantic_state$document_chunks[[doc_id]]
      doc_data$document$tipo %||% ""
    })
    
    type_filter <- doc_types %in% filters$types
    filtered_results <- filtered_results[type_filter, ]
  }
  
  # State filter
  if (!is.null(filters$states) && length(filters$states) > 0) {
    doc_states <- sapply(filtered_results$document_id, function(doc_id) {
      doc_data <- semantic_state$document_chunks[[doc_id]]
      doc_data$document$estado %||% ""
    })
    
    state_filter <- doc_states %in% filters$states
    filtered_results <- filtered_results[state_filter, ]
  }
  
  # Date range filter
  if (!is.null(filters$date_from) || !is.null(filters$date_to)) {
    doc_dates <- sapply(filtered_results$document_id, function(doc_id) {
      doc_data <- semantic_state$document_chunks[[doc_id]]
      doc_date <- doc_data$document$data %||% doc_data$document$date
      
      if (is.null(doc_date)) {
        return(as.Date("1900-01-01"))
      }
      
      if (is.character(doc_date)) {
        return(as.Date(doc_date))
      }
      
      return(as.Date(doc_date))
    })
    
    if (!is.null(filters$date_from)) {
      date_from_filter <- doc_dates >= as.Date(filters$date_from)
      filtered_results <- filtered_results[date_from_filter, ]
    }
    
    if (!is.null(filters$date_to)) {
      date_to_filter <- doc_dates <= as.Date(filters$date_to)
      filtered_results <- filtered_results[date_to_filter, ]
    }
  }
  
  return(filtered_results)
}

#' Rank search results
#' @param results Search results
#' @param processed_query Processed query
#' @param options Search options
#' @return Ranked results
rank_search_results <- function(results, processed_query, options) {
  if (nrow(results) == 0) {
    return(results)
  }
  
  # Add ranking factors
  ranking_factors <- SEMANTIC_CONFIG$ranking$factors
  
  # Calculate composite score
  results$final_score <- 0
  
  # Semantic similarity score
  results$final_score <- results$final_score + 
    (results$similarity * ranking_factors$semantic_similarity)
  
  # Keyword match score
  keyword_scores <- sapply(results$chunk_id, function(chunk_id) {
    chunk_data <- semantic_state$embeddings_index[[chunk_id]]
    calculate_keyword_match_score(chunk_data$metadata$content, processed_query)
  })
  
  results$keyword_score <- keyword_scores
  results$final_score <- results$final_score + 
    (normalize_scores(keyword_scores) * ranking_factors$keyword_match)
  
  # Document importance score
  if (ranking_factors$document_importance > 0) {
    importance_scores <- sapply(results$document_id, function(doc_id) {
      calculate_document_importance(doc_id)
    })
    
    results$importance_score <- importance_scores
    results$final_score <- results$final_score + 
      (normalize_scores(importance_scores) * ranking_factors$document_importance)
  }
  
  # Recency score
  if (SEMANTIC_CONFIG$search$boost_recent_documents && ranking_factors$recency > 0) {
    recency_scores <- sapply(results$document_id, function(doc_id) {
      calculate_recency_score(doc_id)
    })
    
    results$recency_score <- recency_scores
    results$final_score <- results$final_score + 
      (normalize_scores(recency_scores) * ranking_factors$recency)
  }
  
  # Sort by final score
  results <- results[order(results$final_score, decreasing = TRUE), ]
  
  return(results)
}

#' Format search results
#' @param ranked_results Ranked search results
#' @param original_query Original query
#' @return Formatted results
format_search_results <- function(ranked_results, original_query) {
  if (nrow(ranked_results) == 0) {
    return(list())
  }
  
  formatted_results <- list()
  
  # Group by document to avoid duplicates
  doc_groups <- split(ranked_results, ranked_results$document_id)
  
  for (doc_id in names(doc_groups)) {
    doc_chunks <- doc_groups[[doc_id]]
    best_chunk <- doc_chunks[1, ]  # Highest scored chunk
    
    doc_data <- semantic_state$document_chunks[[doc_id]]
    document <- doc_data$document
    
    # Get relevant chunk content
    chunk_data <- semantic_state$embeddings_index[[best_chunk$chunk_id]]
    relevant_content <- chunk_data$metadata$content
    
    # Generate snippet with highlighting
    snippet <- generate_highlighted_snippet(relevant_content, original_query)
    
    formatted_result <- list(
      document_id = doc_id,
      title = document$titulo %||% document$title %||% "Documento sem título",
      type = document$tipo %||% document$type %||% "Tipo não especificado",
      estado = document$estado %||% document$state,
      data = document$data %||% document$date,
      url = document$url,
      snippet = snippet,
      similarity_score = round(best_chunk$similarity, 3),
      keyword_score = round(best_chunk$keyword_score %||% 0, 3),
      final_score = round(best_chunk$final_score, 3),
      chunk_info = list(
        chunk_index = best_chunk$chunk_index,
        start_pos = chunk_data$metadata$start_pos,
        end_pos = chunk_data$metadata$end_pos
      ),
      matched_chunks = nrow(doc_chunks)
    )
    
    formatted_results <- append(formatted_results, list(formatted_result))
  }
  
  return(formatted_results)
}

# Helper functions

#' Calculate cosine similarity
#' @param vec1 First vector
#' @param vec2 Second vector
#' @return Cosine similarity
calculate_cosine_similarity <- function(vec1, vec2) {
  if (length(vec1) != length(vec2)) {
    return(0)
  }
  
  dot_product <- sum(vec1 * vec2)
  norm1 <- sqrt(sum(vec1^2))
  norm2 <- sqrt(sum(vec2^2))
  
  if (norm1 == 0 || norm2 == 0) {
    return(0)
  }
  
  return(dot_product / (norm1 * norm2))
}

#' Calculate keyword match score
#' @param content Content text
#' @param processed_query Processed query
#' @return Keyword match score
calculate_keyword_match_score <- function(content, processed_query) {
  content_lower <- tolower(content)
  
  # Count matches for main query terms
  main_terms <- strsplit(tolower(processed_query$main_query), "\\s+")[[1]]
  main_matches <- sum(sapply(main_terms, function(term) {
    length(gregexpr(term, content_lower, fixed = TRUE)[[1]])
  }))
  
  # Count matches for expanded terms (lower weight)
  expanded_matches <- 0
  if (length(processed_query$expanded_terms) > 0) {
    expanded_matches <- sum(sapply(processed_query$expanded_terms, function(term) {
      length(gregexpr(tolower(term), content_lower, fixed = TRUE)[[1]])
    }))
  }
  
  # Calculate weighted score
  total_score <- (main_matches * 1.0) + (expanded_matches * 0.5)
  
  return(total_score)
}

#' Calculate document importance
#' @param doc_id Document ID
#' @return Importance score
calculate_document_importance <- function(doc_id) {
  doc_data <- semantic_state$document_chunks[[doc_id]]
  document <- doc_data$document
  
  importance <- 0
  
  # Official sources get higher importance
  if (SEMANTIC_CONFIG$ranking$boost_official_sources) {
    if (!is.null(document$fonte) && grepl("gov\\.br|oficial|planalto", document$fonte)) {
      importance <- importance + 0.5
    }
  }
  
  # Document type importance
  type_importance <- switch(document$tipo %||% "",
    "Lei" = 1.0,
    "Decreto" = 0.8,
    "Resolução" = 0.6,
    "Portaria" = 0.4,
    "Instrução Normativa" = 0.4,
    0.2
  )
  importance <- importance + type_importance
  
  return(importance)
}

#' Calculate recency score
#' @param doc_id Document ID
#' @return Recency score
calculate_recency_score <- function(doc_id) {
  doc_data <- semantic_state$document_chunks[[doc_id]]
  document <- doc_data$document
  
  doc_date <- document$data %||% document$date
  if (is.null(doc_date)) {
    return(0)
  }
  
  # Convert to date if string
  if (is.character(doc_date)) {
    doc_date <- as.Date(doc_date)
  }
  
  # Calculate days ago
  days_ago <- as.numeric(Sys.Date() - as.Date(doc_date))
  
  # Exponential decay: newer documents get higher scores
  recency_score <- exp(-days_ago / 365)  # Half-life of 1 year
  
  return(recency_score)
}

#' Normalize scores to 0-1 range
#' @param scores Vector of scores
#' @return Normalized scores
normalize_scores <- function(scores) {
  if (length(scores) == 0 || all(is.na(scores))) {
    return(scores)
  }
  
  min_score <- min(scores, na.rm = TRUE)
  max_score <- max(scores, na.rm = TRUE)
  
  if (min_score == max_score) {
    return(rep(1, length(scores)))
  }
  
  return((scores - min_score) / (max_score - min_score))
}

#' Find sentence break near position
#' @param text Full text
#' @param start_pos Start position
#' @param end_pos End position
#' @return Best break position
find_sentence_break <- function(text, start_pos, end_pos) {
  # Look for sentence endings near the end position
  search_start <- max(start_pos, end_pos - 100)
  search_text <- substr(text, search_start, end_pos)
  
  # Find last sentence ending
  sentence_endings <- gregexpr("[.!?]\\s+", search_text)[[1]]
  
  if (length(sentence_endings) > 0 && sentence_endings[1] != -1) {
    last_ending <- max(sentence_endings)
    return(search_start + last_ending)
  }
  
  return(end_pos)
}

#' Remove stopwords from text
#' @param text Input text
#' @return Text without stopwords
remove_stopwords <- function(text) {
  # Portuguese stopwords (simplified list)
  stopwords <- c("a", "o", "e", "de", "do", "da", "em", "um", "uma", "para", "com", "por", "que", "se", "na", "no")
  
  words <- strsplit(tolower(text), "\\s+")[[1]]
  filtered_words <- words[!words %in% stopwords]
  
  return(paste(filtered_words, collapse = " "))
}

#' Expand query with synonyms
#' @param query Query text
#' @return Expanded terms
expand_with_synonyms <- function(query) {
  # Simple synonym expansion (in production, use proper thesaurus)
  synonym_map <- list(
    "lei" = c("legislação", "norma", "regulamento"),
    "decreto" = c("regulamentação", "normatização"),
    "público" = c("estatal", "governamental", "oficial"),
    "administração" = c("gestão", "gerenciamento")
  )
  
  query_lower <- tolower(query)
  expanded_terms <- c()
  
  for (term in names(synonym_map)) {
    if (grepl(term, query_lower)) {
      expanded_terms <- c(expanded_terms, synonym_map[[term]])
    }
  }
  
  return(expanded_terms)
}

#' Expand query with legal terms
#' @param query Query text
#' @return Legal term expansions
expand_with_legal_terms <- function(query) {
  # Legal term associations
  legal_expansions <- list(
    "licitação" = c("pregão", "concorrência", "tomada de preços"),
    "servidor" = c("funcionário público", "agente público"),
    "transparência" = c("acesso à informação", "dados abertos"),
    "controle" = c("fiscalização", "auditoria", "monitoramento")
  )
  
  query_lower <- tolower(query)
  expanded_terms <- c()
  
  for (term in names(legal_expansions)) {
    if (grepl(term, query_lower)) {
      expanded_terms <- c(expanded_terms, legal_expansions[[term]])
    }
  }
  
  return(expanded_terms)
}

#' Generate highlighted snippet
#' @param content Content text
#' @param query Search query
#' @return Highlighted snippet
generate_highlighted_snippet <- function(content, query, max_length = 300) {
  if (nchar(content) <= max_length) {
    return(content)
  }
  
  # Find best snippet position (contains query terms)
  query_terms <- strsplit(tolower(query), "\\s+")[[1]]
  content_lower <- tolower(content)
  
  best_pos <- 1
  max_matches <- 0
  
  # Sliding window to find best position
  for (pos in seq(1, nchar(content) - max_length, by = 50)) {
    window_text <- substr(content_lower, pos, pos + max_length)
    matches <- sum(sapply(query_terms, function(term) {
      length(gregexpr(term, window_text, fixed = TRUE)[[1]])
    }))
    
    if (matches > max_matches) {
      max_matches <- matches
      best_pos <- pos
    }
  }
  
  snippet <- substr(content, best_pos, best_pos + max_length - 1)
  
  # Add ellipsis if needed
  if (best_pos > 1) {
    snippet <- paste0("...", snippet)
  }
  
  if (best_pos + max_length < nchar(content)) {
    snippet <- paste0(snippet, "...")
  }
  
  return(snippet)
}

#' Cache management functions
generate_embedding_cache_key <- function(content) {
  digest(content, algo = "md5")
}

cache_embedding <- function(cache_key, embedding) {
  if (!SEMANTIC_CONFIG$embeddings$cache_embeddings) {
    return()
  }
  
  semantic_state$embedding_cache[[cache_key]] <<- list(
    embedding = embedding,
    cached_at = Sys.time()
  )
}

get_cached_embedding <- function(cache_key) {
  if (!SEMANTIC_CONFIG$embeddings$cache_embeddings) {
    return(NULL)
  }
  
  cache_entry <- semantic_state$embedding_cache[[cache_key]]
  if (is.null(cache_entry)) {
    return(NULL)
  }
  
  # Check TTL
  age_days <- as.numeric(Sys.time() - cache_entry$cached_at, units = "days")
  if (age_days > SEMANTIC_CONFIG$embeddings$embedding_ttl_days) {
    semantic_state$embedding_cache[[cache_key]] <<- NULL
    return(NULL)
  }
  
  return(cache_entry$embedding)
}

generate_query_cache_key <- function(query, filters, options) {
  key_data <- list(query = query, filters = filters, options = options)
  digest(toJSON(key_data, auto_unbox = TRUE), algo = "md5")
}

cache_query_results <- function(cache_key, results) {
  semantic_state$query_cache[[cache_key]] <<- list(
    results = results,
    cached_at = Sys.time()
  )
}

get_cached_query_results <- function(cache_key) {
  cache_entry <- semantic_state$query_cache[[cache_key]]
  if (is.null(cache_entry)) {
    return(NULL)
  }
  
  # Simple TTL of 1 hour for query cache
  age_hours <- as.numeric(Sys.time() - cache_entry$cached_at, units = "hours")
  if (age_hours > 1) {
    semantic_state$query_cache[[cache_key]] <<- NULL
    return(NULL)
  }
  
  return(cache_entry$results)
}

check_ai_integration <- function() {
  return(exists("generate_text_embedding") && exists("AI_CONFIG"))
}

load_embeddings_index <- function() {
  index_file <- "semantic_search_index.rds"
  
  if (file.exists(index_file)) {
    tryCatch({
      index_data <- readRDS(index_file)
      semantic_state$embeddings_index <<- index_data$embeddings_index
      semantic_state$document_chunks <<- index_data$document_chunks
      semantic_state$index_metadata <<- index_data$index_metadata
      
      log_event("Loaded semantic search index from disk", "INFO")
    }, error = function(e) {
      log_event(paste("Failed to load semantic search index:", e$message), "WARN")
    })
  }
}

save_embeddings_index <- function() {
  index_file <- "semantic_search_index.rds"
  
  tryCatch({
    index_data <- list(
      embeddings_index = semantic_state$embeddings_index,
      document_chunks = semantic_state$document_chunks,
      index_metadata = semantic_state$index_metadata
    )
    
    saveRDS(index_data, index_file)
    log_event("Saved semantic search index to disk", "INFO")
  }, error = function(e) {
    log_event(paste("Failed to save semantic search index:", e$message), "ERROR")
  })
}

get_semantic_search_statistics <- function() {
  return(list(
    indexed_documents = length(semantic_state$document_chunks),
    indexed_chunks = length(semantic_state$embeddings_index),
    embedding_cache_size = length(semantic_state$embedding_cache),
    query_cache_size = length(semantic_state$query_cache),
    last_index_update = semantic_state$index_metadata$last_update,
    embedding_dimension = SEMANTIC_CONFIG$embeddings$dimension,
    similarity_threshold = SEMANTIC_CONFIG$search$similarity_threshold
  ))
}