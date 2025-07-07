# Enhanced Search Engine Core for Monitor Legislativo v4
# Advanced search functionality with vocabulary expansion and multi-source integration

library(dplyr)
library(stringr)
library(jsonlite)
library(future)
library(promises)

# Search engine configuration
SEARCH_CONFIG <- list(
  max_results_per_source = 500,
  timeout_seconds = 30,
  min_query_length = 2,
  enable_fuzzy_matching = TRUE,
  enable_vocabulary_expansion = TRUE,
  enable_result_ranking = TRUE,
  cache_duration_minutes = 30
)

#' Main search function with multi-source integration
#' @param query Search query string
#' @param filters List of search filters
#' @param sources Vector of sources to search ("lexml", "api", "csv")
#' @param options Search options
#' @return Promise with aggregated search results
enhanced_search <- function(query = NULL, filters = list(), 
                           sources = c("lexml", "api"), options = list()) {
  
  # Validate input
  if (is.null(query) || nchar(trimws(query)) < SEARCH_CONFIG$min_query_length) {
    log_event("Invalid search query", "WARN")
    return(future::resolved(create_empty_search_result()))
  }
  
  log_event(paste("Starting enhanced search for:", query))
  
  # Merge options with defaults
  search_options <- modifyList(SEARCH_CONFIG, options)
  
  # Check cache first
  cache_key <- create_search_cache_key(query, filters, sources)
  cached_result <- get_cache(cache_key)
  
  if (!is.null(cached_result)) {
    log_event("Returning cached search results")
    return(future::resolved(cached_result))
  }
  
  # Prepare search parameters
  search_params <- prepare_search_parameters(query, filters, search_options)
  
  # Execute multi-source search asynchronously
  future_promise({
    
    all_results <- list()
    search_stats <- list(
      total_sources = length(sources),
      successful_sources = 0,
      total_results = 0,
      search_time = Sys.time()
    )
    
    # Search each source
    for (source in sources) {
      
      tryCatch({
        log_event(paste("Searching source:", source))
        
        source_results <- execute_source_search(source, search_params, search_options)
        
        if (!is.null(source_results) && nrow(source_results) > 0) {
          all_results[[source]] <- source_results
          search_stats$successful_sources <- search_stats$successful_sources + 1
          search_stats$total_results <- search_stats$total_results + nrow(source_results)
          
          log_event(paste("Source", source, "returned", nrow(source_results), "results"))
        }
        
      }, error = function(e) {
        log_event(paste("Error searching source", source, ":", e$message), "ERROR")
      })
    }
    
    # Aggregate and process results
    if (length(all_results) > 0) {
      
      # Combine results from all sources
      combined_results <- aggregate_search_results(all_results)
      
      # Remove duplicates
      deduplicated_results <- remove_duplicate_documents(combined_results)
      
      # Rank and score results
      if (search_options$enable_result_ranking) {
        ranked_results <- rank_search_results(deduplicated_results, search_params)
      } else {
        ranked_results <- deduplicated_results
      }
      
      # Apply final filters and limits
      final_results <- apply_final_filters(ranked_results, filters, search_options)
      
      # Add search metadata
      final_results$search_metadata <- create_search_metadata(search_stats, search_params)
      
      # Cache results
      set_cache(cache_key, final_results, search_options$cache_duration_minutes * 60)
      
      log_event(paste("Enhanced search completed:", nrow(final_results), "final results"))
      
      return(final_results)
      
    } else {
      log_event("No results from any source", "WARN")
      return(create_empty_search_result())
    }
    
  }) %...!% {
    log_event(paste("Enhanced search failed:", .$message), "ERROR")
    return(create_fallback_search_results(query))
  }
}

#' Prepare search parameters from query and filters
#' @param query Original query
#' @param filters Search filters
#' @param options Search options
#' @return Processed search parameters
prepare_search_parameters <- function(query, filters, options) {
  
  # Clean and normalize query
  normalized_query <- str_trim(str_squish(query))
  
  # Expand vocabulary if enabled
  if (options$enable_vocabulary_expansion) {
    expanded_query <- expand_search_vocabulary(normalized_query, max_terms = 15)
    vocabulary_analysis <- analyze_vocabulary_coverage(normalized_query)
  } else {
    expanded_query <- normalized_query
    vocabulary_analysis <- NULL
  }
  
  # Parse query for special operators
  query_parts <- parse_query_operators(expanded_query)
  
  # Prepare date filters
  date_filters <- prepare_date_filters(filters)
  
  # Prepare type filters
  type_filters <- prepare_type_filters(filters)
  
  # Prepare geographic filters
  geo_filters <- prepare_geographic_filters(filters)
  
  search_params <- list(
    original_query = normalized_query,
    expanded_query = expanded_query,
    query_parts = query_parts,
    vocabulary_analysis = vocabulary_analysis,
    date_filters = date_filters,
    type_filters = type_filters,
    geo_filters = geo_filters,
    options = options
  )
  
  return(search_params)
}

#' Execute search for a specific source
#' @param source Source identifier
#' @param params Search parameters
#' @param options Search options
#' @return Data frame with results
execute_source_search <- function(source, params, options) {
  
  max_results <- min(options$max_results_per_source, 1000)
  
  tryCatch({
    
    switch(source,
      
      "lexml" = {
        # Use LexML integration
        search_lexml_enhanced(
          query = params$expanded_query,
          filters = list(
            date_from = params$date_filters$from,
            date_to = params$date_filters$to,
            types = params$type_filters,
            states = params$geo_filters$states
          ),
          expand_vocabulary = FALSE,  # Already expanded
          limit = max_results
        )
      },
      
      "api" = {
        # Use existing API client
        search_legislative_data(
          query = params$expanded_query,
          date_from = params$date_filters$from,
          date_to = params$date_filters$to,
          types = params$type_filters,
          states = params$geo_filters$states,
          limit = max_results
        )
      },
      
      "csv" = {
        # Use CSV fallback
        search_csv_data(
          query = params$original_query,
          filters = list(
            date_from = params$date_filters$from,
            date_to = params$date_filters$to,
            types = params$type_filters,
            states = params$geo_filters$states
          ),
          limit = max_results
        )
      },
      
      {
        log_event(paste("Unknown search source:", source), "WARN")
        return(NULL)
      }
    )
    
  }, error = function(e) {
    log_event(paste("Error in source search", source, ":", e$message), "ERROR")
    return(NULL)
  })
}

#' Parse query for special operators
#' @param query Search query
#' @return List with parsed query components
parse_query_operators <- function(query) {
  
  # Initialize components
  components <- list(
    terms = character(0),
    exact_phrases = character(0),
    excluded_terms = character(0),
    required_terms = character(0),
    field_searches = list()
  )
  
  # Extract exact phrases (quoted text)
  phrase_pattern <- '"([^"]+)"'
  phrases <- str_extract_all(query, phrase_pattern)[[1]]
  if (length(phrases) > 0) {
    components$exact_phrases <- str_remove_all(phrases, '"')
    query <- str_remove_all(query, phrase_pattern)
  }
  
  # Extract excluded terms (preceded by -)
  excluded_pattern <- '-\\w+'
  excluded <- str_extract_all(query, excluded_pattern)[[1]]
  if (length(excluded) > 0) {
    components$excluded_terms <- str_remove(excluded, '^-')
    query <- str_remove_all(query, excluded_pattern)
  }
  
  # Extract required terms (preceded by +)
  required_pattern <- '\\+\\w+'
  required <- str_extract_all(query, required_pattern)[[1]]
  if (length(required) > 0) {
    components$required_terms <- str_remove(required, '^\\+')
    query <- str_remove_all(query, required_pattern)
  }
  
  # Extract field searches (field:value)
  field_pattern <- '(\\w+):(\\w+)'
  field_matches <- str_match_all(query, field_pattern)[[1]]
  if (nrow(field_matches) > 0) {
    for (i in 1:nrow(field_matches)) {
      field_name <- field_matches[i, 2]
      field_value <- field_matches[i, 3]
      components$field_searches[[field_name]] <- field_value
    }
    query <- str_remove_all(query, field_pattern)
  }
  
  # Remaining terms
  remaining_terms <- str_split(str_trim(query), "\\s+")[[1]]
  remaining_terms <- remaining_terms[nchar(remaining_terms) > 0]
  components$terms <- remaining_terms
  
  return(components)
}

#' Prepare date filters from user input
#' @param filters User filters
#' @return Standardized date filters
prepare_date_filters <- function(filters) {
  
  date_from <- NULL
  date_to <- NULL
  
  # Parse date_from
  if (!is.null(filters$date_from)) {
    tryCatch({
      date_from <- as.Date(filters$date_from)
    }, error = function(e) {
      log_event("Invalid date_from format", "WARN")
    })
  }
  
  # Parse date_to
  if (!is.null(filters$date_to)) {
    tryCatch({
      date_to <- as.Date(filters$date_to)
    }, error = function(e) {
      log_event("Invalid date_to format", "WARN")
    })
  }
  
  # Default date range if not specified
  if (is.null(date_from) && is.null(date_to)) {
    date_from <- Sys.Date() - 365  # Last year
    date_to <- Sys.Date()
  }
  
  # Validate date range
  if (!is.null(date_from) && !is.null(date_to) && date_from > date_to) {
    log_event("Invalid date range: from > to", "WARN")
    # Swap dates
    temp <- date_from
    date_from <- date_to
    date_to <- temp
  }
  
  return(list(
    from = date_from,
    to = date_to,
    range_days = if (!is.null(date_from) && !is.null(date_to)) {
      as.numeric(date_to - date_from)
    } else NULL
  ))
}

#' Prepare type filters
#' @param filters User filters
#' @return Standardized type filters
prepare_type_filters <- function(filters) {
  
  if (is.null(filters$types) || "all" %in% filters$types) {
    return(NULL)  # No type filtering
  }
  
  # Standardize type names
  valid_types <- c("lei", "decreto", "portaria", "resolucao", "medida_provisoria",
                  "instrucao_normativa", "ordem_de_servico", "circular", "parecer")
  
  standardized_types <- intersect(tolower(filters$types), valid_types)
  
  if (length(standardized_types) == 0) {
    log_event("No valid document types specified", "WARN")
    return(NULL)
  }
  
  return(standardized_types)
}

#' Prepare geographic filters
#' @param filters User filters
#' @return Standardized geographic filters
prepare_geographic_filters <- function(filters) {
  
  geo_filters <- list(
    states = NULL,
    municipalities = NULL,
    regions = NULL
  )
  
  # Validate state codes
  if (!is.null(filters$states)) {
    valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
                     "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
                     "RS", "RO", "RR", "SC", "SP", "SE", "TO")
    
    geo_filters$states <- intersect(toupper(filters$states), valid_states)
  }
  
  # Add municipalities if specified
  if (!is.null(filters$municipalities)) {
    geo_filters$municipalities <- filters$municipalities
  }
  
  return(geo_filters)
}

#' Aggregate search results from multiple sources
#' @param results_list List of results from different sources
#' @return Combined data frame
aggregate_search_results <- function(results_list) {
  
  if (length(results_list) == 0) {
    return(create_empty_search_result())
  }
  
  # Standardize column names across sources
  standardized_results <- lapply(results_list, function(results) {
    standardize_result_columns(results)
  })
  
  # Combine all results
  combined <- do.call(rbind, standardized_results)
  
  # Add source ranking
  combined$fonte_ranking <- sapply(combined$fonte, function(fonte) {
    switch(tolower(fonte),
      "lexml brasil" = 1,
      "camara dos deputados" = 2,
      "senado federal" = 2,
      "assembleia legislativa" = 3,
      "camara municipal" = 4,
      5  # Default for unknown sources
    )
  })
  
  return(combined)
}

#' Standardize result columns across sources
#' @param results Results data frame
#' @return Standardized data frame
standardize_result_columns <- function(results) {
  
  if (is.null(results) || nrow(results) == 0) {
    return(create_empty_search_result())
  }
  
  # Ensure all required columns exist
  required_columns <- c("titulo", "tipo", "numero", "data", "ementa", "autor", 
                       "estado", "fonte", "url")
  
  for (col in required_columns) {
    if (!col %in% names(results)) {
      results[[col]] <- NA
    }
  }
  
  # Standardize data types
  results <- results %>%
    mutate(
      titulo = as.character(titulo),
      tipo = as.character(tipo),
      numero = as.character(numero),
      data = as.Date(data),
      ementa = as.character(ementa),
      autor = as.character(autor),
      estado = as.character(estado),
      fonte = as.character(fonte),
      url = as.character(url)
    )
  
  return(results)
}

#' Remove duplicate documents from results
#' @param results Combined results
#' @return Deduplicated results
remove_duplicate_documents <- function(results) {
  
  if (is.null(results) || nrow(results) == 0) {
    return(results)
  }
  
  log_event(paste("Removing duplicates from", nrow(results), "results"))
  
  # Create deduplication key
  results$dedup_key <- paste(
    str_to_lower(str_trim(results$titulo)),
    str_to_lower(str_trim(results$numero)),
    results$data,
    sep = "|"
  )
  
  # Remove exact duplicates
  exact_duplicates <- duplicated(results$dedup_key)
  results_no_exact <- results[!exact_duplicates, ]
  
  # Find similar documents (fuzzy matching)
  if (nrow(results_no_exact) > 1) {
    
    # Simple similarity check on titles
    similarity_threshold <- 0.8
    to_remove <- c()
    
    for (i in 1:(nrow(results_no_exact) - 1)) {
      if (i %in% to_remove) next
      
      for (j in (i + 1):nrow(results_no_exact)) {
        if (j %in% to_remove) next
        
        # Calculate title similarity
        title1 <- str_to_lower(str_trim(results_no_exact$titulo[i]))
        title2 <- str_to_lower(str_trim(results_no_exact$titulo[j]))
        
        if (nchar(title1) > 10 && nchar(title2) > 10) {
          similarity <- calculate_text_similarity(title1, title2)
          
          if (similarity >= similarity_threshold) {
            # Keep the one from better source
            if (results_no_exact$fonte_ranking[i] <= results_no_exact$fonte_ranking[j]) {
              to_remove <- c(to_remove, j)
            } else {
              to_remove <- c(to_remove, i)
              break
            }
          }
        }
      }
    }
    
    if (length(to_remove) > 0) {
      results_no_exact <- results_no_exact[-to_remove, ]
    }
  }
  
  # Remove deduplication columns
  results_no_exact$dedup_key <- NULL
  results_no_exact$fonte_ranking <- NULL
  
  log_event(paste("Deduplication completed:", nrow(results_no_exact), "unique results"))
  
  return(results_no_exact)
}

#' Calculate text similarity between two strings
#' @param text1 First text
#' @param text2 Second text
#' @return Similarity score (0-1)
calculate_text_similarity <- function(text1, text2) {
  
  if (is.na(text1) || is.na(text2) || nchar(text1) == 0 || nchar(text2) == 0) {
    return(0)
  }
  
  # Split into words
  words1 <- unique(str_split(text1, "\\s+")[[1]])
  words2 <- unique(str_split(text2, "\\s+")[[1]])
  
  # Calculate Jaccard similarity
  intersection <- length(intersect(words1, words2))
  union <- length(union(words1, words2))
  
  if (union == 0) return(0)
  
  return(intersection / union)
}

#' Rank search results by relevance
#' @param results Search results
#' @param params Search parameters
#' @return Ranked results
rank_search_results <- function(results, params) {
  
  if (is.null(results) || nrow(results) == 0) {
    return(results)
  }
  
  log_event("Ranking search results by relevance")
  
  # Calculate relevance scores
  results$relevance_score <- calculate_relevance_scores(results, params)
  
  # Sort by relevance score (descending)
  ranked_results <- results %>%
    arrange(desc(relevance_score), desc(data)) %>%
    select(-relevance_score)  # Remove score column for final output
  
  return(ranked_results)
}

#' Calculate relevance scores for search results
#' @param results Results data frame
#' @param params Search parameters
#' @return Vector of relevance scores
calculate_relevance_scores <- function(results, params) {
  
  original_terms <- str_to_lower(str_split(params$original_query, "\\s+")[[1]])
  
  scores <- sapply(1:nrow(results), function(i) {
    
    score <- 0
    row <- results[i, ]
    
    # Text content for searching
    text_content <- str_to_lower(paste(
      coalesce(row$titulo, ""),
      coalesce(row$ementa, ""),
      coalesce(row$tipo, "")
    ))
    
    # Exact phrase matches in title (high weight)
    for (term in original_terms) {
      if (str_detect(str_to_lower(row$titulo), fixed(term))) {
        score <- score + 10
      }
    }
    
    # Term frequency in title
    title_lower <- str_to_lower(coalesce(row$titulo, ""))
    for (term in original_terms) {
      term_count <- str_count(title_lower, fixed(term))
      score <- score + (term_count * 5)
    }
    
    # Term frequency in ementa
    ementa_lower <- str_to_lower(coalesce(row$ementa, ""))
    for (term in original_terms) {
      term_count <- str_count(ementa_lower, fixed(term))
      score <- score + (term_count * 2)
    }
    
    # Document type bonus (laws and decrees higher priority)
    if (!is.na(row$tipo)) {
      type_lower <- str_to_lower(row$tipo)
      if (str_detect(type_lower, "lei")) score <- score + 3
      if (str_detect(type_lower, "decreto")) score <- score + 2
    }
    
    # Recency bonus (newer documents get slight boost)
    if (!is.na(row$data)) {
      days_old <- as.numeric(Sys.Date() - row$data)
      if (days_old <= 365) score <- score + 2      # Last year
      else if (days_old <= 1825) score <- score + 1  # Last 5 years
    }
    
    # Source quality bonus
    if (!is.na(row$fonte)) {
      fonte_lower <- str_to_lower(row$fonte)
      if (str_detect(fonte_lower, "lexml")) score <- score + 2
      if (str_detect(fonte_lower, "federal|senado|camara")) score <- score + 1
    }
    
    return(max(score, 0))
  })
  
  return(scores)
}

#' Apply final filters and limits to results
#' @param results Ranked results
#' @param filters Original filters
#' @param options Search options
#' @return Final filtered results
apply_final_filters <- function(results, filters, options) {
  
  if (is.null(results) || nrow(results) == 0) {
    return(results)
  }
  
  # Apply result limit
  max_results <- min(options$max_results_per_source * 2, 2000)  # Overall limit
  
  if (nrow(results) > max_results) {
    results <- results[1:max_results, ]
    log_event(paste("Applied result limit:", max_results))
  }
  
  # Final data quality filter
  quality_filtered <- results %>%
    filter(
      !is.na(titulo),
      nchar(str_trim(titulo)) >= 5,
      !is.na(data),
      data >= as.Date("1988-10-05")  # Brazilian Constitution
    )
  
  log_event(paste("Final results after quality filter:", nrow(quality_filtered)))
  
  return(quality_filtered)
}

#' Create search metadata
#' @param stats Search statistics
#' @param params Search parameters
#' @return Metadata list
create_search_metadata <- function(stats, params) {
  
  list(
    search_query = params$original_query,
    expanded_query = params$expanded_query,
    vocabulary_coverage = params$vocabulary_analysis$coverage_percentage,
    sources_searched = stats$total_sources,
    successful_sources = stats$successful_sources,
    total_found = stats$total_results,
    search_duration = as.numeric(Sys.time() - stats$search_time, units = "secs"),
    timestamp = Sys.time()
  )
}

#' Create search cache key
#' @param query Search query
#' @param filters Filters
#' @param sources Sources
#' @return Cache key string
create_search_cache_key <- function(query, filters, sources) {
  
  # Create deterministic key from parameters
  key_components <- list(
    query = str_to_lower(str_trim(query)),
    filters = filters[order(names(filters))],
    sources = sort(sources)
  )
  
  key_string <- jsonlite::toJSON(key_components, auto_unbox = TRUE)
  cache_key <- paste0("enhanced_search:", digest::digest(key_string, algo = "md5"))
  
  return(cache_key)
}

#' Create fallback search results
#' @param query Original query
#' @return Fallback results
create_fallback_search_results <- function(query) {
  
  log_event("Creating fallback search results", "WARN")
  
  # Use existing CSV fallback
  fallback_results <- create_fallback_data()
  
  # Add search metadata
  fallback_results$search_metadata <- list(
    search_query = query,
    fallback_mode = TRUE,
    timestamp = Sys.time()
  )
  
  return(fallback_results)
}

#' Search CSV data (fallback method)
#' @param query Search query
#' @param filters Search filters
#' @param limit Result limit
#' @return Search results from CSV
search_csv_data <- function(query, filters, limit = 1000) {
  
  # This would integrate with existing CSV data functionality
  # For now, return existing fallback data
  csv_results <- create_fallback_data()
  
  # Apply basic filtering if query provided
  if (!is.null(query) && nchar(str_trim(query)) > 0) {
    query_terms <- str_to_lower(str_split(query, "\\s+")[[1]])
    
    # Filter by title and ementa
    csv_results <- csv_results %>%
      filter(
        rowwise() %>%
        any(sapply(query_terms, function(term) {
          str_detect(str_to_lower(paste(titulo, ementa)), term)
        }))
      )
  }
  
  return(head(csv_results, limit))
}