# ============================================================================
# INTELLIGENT AUTOCOMPLETE SYSTEM FOR BRAZILIAN LEGISLATIVE SEARCH
# ============================================================================
#
# This module implements an advanced autocomplete system specifically designed
# for Brazilian legal terminology and legislative document search with:
# - Context-aware legal term suggestions
# - Real-time query completion with fuzzy matching
# - Legal hierarchy-aware recommendations (Federal > State > Municipal)
# - Transport-specific term suggestions
# - Performance-optimized for sub-second response times
# - Railway deployment compatibility
#
# Author: Senior Data Scientist - Brazilian Legislative Analytics Team
# Date: January 2025
# Version: 1.0 - Production Ready for 134k+ documents
# ============================================================================

# Load required packages
required_autocomplete_packages <- c("stringr", "stringdist", "dplyr", "jsonlite", "digest")

available_autocomplete_packages <- character(0)
for (pkg in required_autocomplete_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    available_autocomplete_packages <- c(available_autocomplete_packages, pkg)
  }
}

suppressPackageStartupMessages({
  library(stringr)
  library(dplyr)
  library(jsonlite)
  library(digest)
  if ("stringdist" %in% available_autocomplete_packages) library(stringdist)
})

cat("💡 Intelligent Autocomplete loaded with", length(available_autocomplete_packages), "packages\n")

# ============================================================================
# AUTOCOMPLETE SYSTEM CONFIGURATION
# ============================================================================

.autocomplete_config <- list(
  # Response performance settings
  min_query_length = 2,
  max_suggestions = 10,
  fuzzy_threshold = 0.8,
  response_time_target_ms = 100,
  
  # Legal term categories with priorities
  legal_categories = list(
    "lei" = list(priority = 10, examples = c("Lei nº", "Lei Federal", "Lei Complementar")),
    "decreto" = list(priority = 9, examples = c("Decreto nº", "Decreto Federal", "Decreto Estadual")),
    "portaria" = list(priority = 8, examples = c("Portaria", "Portaria Ministerial")),
    "resolucao" = list(priority = 8, examples = c("Resolução", "Resolução CONTRAN", "Resolução ANTT")),
    "instrucao_normativa" = list(priority = 7, examples = c("Instrução Normativa", "IN")),
    "medida_provisoria" = list(priority = 9, examples = c("Medida Provisória", "MP")),
    "emenda_constitucional" = list(priority = 10, examples = c("Emenda Constitucional", "EC")),
    "orgao_regulador" = list(priority = 8, examples = c("ANTT", "ANAC", "ANTAQ", "ANP", "IBAMA")),
    "conceito_juridico" = list(priority = 6, examples = c("licitação", "contrato", "concessão")),
    "modalidade_transporte" = list(priority = 7, examples = c("rodoviário", "ferroviário", "aéreo", "marítimo"))
  ),
  
  # Brazilian legal authorities by level
  authorities = list(
    federal = c("Presidência da República", "Ministério dos Transportes", "ANTT", "ANAC", "ANTAQ", 
               "ANP", "IBAMA", "CONTRAN", "Casa Civil", "AGU"),
    state = c("Governo do Estado", "Secretaria de Transportes", "DETRAN", "Assembleia Legislativa",
             "Tribunal de Contas", "Ministério Público Estadual"),
    municipal = c("Prefeitura", "Câmara Municipal", "Secretaria Municipal", "Guarda Municipal")
  ),
  
  # Transport modal terms with context
  transport_modals = list(
    aereo = c("aviação", "aeroporto", "ANAC", "companhia aérea", "voo", "aeronáutica"),
    rodoviario = c("rodovia", "estrada", "ANTT", "caminhão", "pedágio", "BR-", "transporte rodoviário"),
    ferroviario = c("ferrovia", "trem", "estação ferroviária", "ANTT", "transporte ferroviário", "trilho"),
    maritimo = c("porto", "ANTAQ", "navegação", "navio", "transporte marítimo", "cabotagem"),
    hidroviario = c("hidrovia", "navegação interior", "transporte fluvial", "ANTAQ"),
    urbano = c("transporte público", "ônibus", "metrô", "mobilidade urbana", "trânsito", "BRT")
  ),
  
  # Common legal phrases and expressions
  legal_phrases = c(
    "dispõe sobre", "altera a lei", "regulamenta o decreto", "estabelece normas",
    "código de trânsito", "plano diretor", "política nacional", "sistema nacional",
    "agência reguladora", "concessão de serviço", "permissão de uso", "autorização para",
    "fiscalização e controle", "diretrizes gerais", "programa nacional"
  ),
  
  # Caching settings
  cache_enabled = TRUE,
  cache_ttl_seconds = 300,  # 5 minutes
  prefix_cache_enabled = TRUE,
  popular_terms_cache_ttl = 1800  # 30 minutes
)

# In-memory autocomplete caches
.autocomplete_cache <- list()
.prefix_cache <- list()
.popular_terms_cache <- list()

# Performance metrics
.autocomplete_metrics <- list(
  total_requests = 0,
  cache_hits = 0,
  cache_misses = 0,
  avg_response_time_ms = 0,
  slow_queries = 0
)

# ============================================================================
# CORE AUTOCOMPLETE FUNCTIONS
# ============================================================================

#' Generate intelligent autocomplete suggestions
#' @param partial_query Partial search query
#' @param context_filters Current search context (estado, species, etc.)
#' @param max_suggestions Maximum number of suggestions to return
#' @param include_fuzzy Whether to include fuzzy matches
#' @return List with suggestions and metadata
generate_autocomplete_suggestions <- function(partial_query, 
                                            context_filters = list(),
                                            max_suggestions = .autocomplete_config$max_suggestions,
                                            include_fuzzy = TRUE) {
  
  start_time <- Sys.time()
  
  tryCatch({
    # Input validation
    if (is.null(partial_query) || nchar(trimws(partial_query)) < .autocomplete_config$min_query_length) {
      return(create_empty_suggestions_response(partial_query))
    }
    
    partial_query <- str_trim(partial_query)
    .autocomplete_metrics$total_requests <<- .autocomplete_metrics$total_requests + 1
    
    # Check cache first
    if (.autocomplete_config$cache_enabled) {
      cache_key <- generate_autocomplete_cache_key(partial_query, context_filters, max_suggestions)
      cached_result <- get_cached_autocomplete(cache_key)
      
      if (!is.null(cached_result)) {
        .autocomplete_metrics$cache_hits <<- .autocomplete_metrics$cache_hits + 1
        return(cached_result)
      }
    }
    
    .autocomplete_metrics$cache_misses <<- .autocomplete_metrics$cache_misses + 1
    
    # Generate suggestions from multiple sources
    suggestions <- list()
    
    # 1. Legal document patterns
    legal_suggestions <- get_legal_document_suggestions(partial_query, context_filters)
    if (length(legal_suggestions) > 0) {
      suggestions$legal_documents <- legal_suggestions
    }
    
    # 2. Authority and organization suggestions
    authority_suggestions <- get_authority_suggestions(partial_query, context_filters)
    if (length(authority_suggestions) > 0) {
      suggestions$authorities <- authority_suggestions
    }
    
    # 3. Transport modal suggestions
    transport_suggestions <- get_transport_suggestions(partial_query, context_filters)
    if (length(transport_suggestions) > 0) {
      suggestions$transport <- transport_suggestions
    }
    
    # 4. Legal concept suggestions
    concept_suggestions <- get_legal_concept_suggestions(partial_query, context_filters)
    if (length(concept_suggestions) > 0) {
      suggestions$concepts <- concept_suggestions
    }
    
    # 5. Popular search terms
    popular_suggestions <- get_popular_terms_suggestions(partial_query, context_filters)
    if (length(popular_suggestions) > 0) {
      suggestions$popular <- popular_suggestions
    }
    
    # 6. Geographic suggestions (states, cities)
    geographic_suggestions <- get_geographic_suggestions(partial_query, context_filters)
    if (length(geographic_suggestions) > 0) {
      suggestions$geographic <- geographic_suggestions
    }
    
    # 7. Fuzzy matching for typos (if enabled)
    if (include_fuzzy && "stringdist" %in% available_autocomplete_packages) {
      fuzzy_suggestions <- get_fuzzy_suggestions(partial_query, suggestions)
      if (length(fuzzy_suggestions) > 0) {
        suggestions$fuzzy <- fuzzy_suggestions
      }
    }
    
    # Combine, rank, and limit suggestions
    final_suggestions <- combine_and_rank_suggestions(suggestions, partial_query, max_suggestions, context_filters)
    
    # Calculate response time
    end_time <- Sys.time()
    response_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    
    # Update performance metrics
    update_autocomplete_metrics(response_time_ms)
    
    # Create response
    response <- create_suggestions_response(final_suggestions, partial_query, context_filters, response_time_ms)
    
    # Cache the response
    if (.autocomplete_config$cache_enabled) {
      cache_autocomplete_response(cache_key, response)
    }
    
    return(response)
    
  }, error = function(e) {
    cat("❌ Autocomplete error for query '", partial_query, "':", e$message, "\n")
    return(create_empty_suggestions_response(partial_query, error_message = e$message))
  })
}

# ============================================================================
# SUGGESTION SOURCE FUNCTIONS
# ============================================================================

#' Get legal document pattern suggestions
#' @param query Partial query
#' @param context Current search context
#' @return Named vector of suggestions
get_legal_document_suggestions <- function(query, context) {
  
  suggestions <- character(0)
  query_lower <- tolower(query)
  
  # Check for legal document patterns
  for (category in names(.autocomplete_config$legal_categories)) {
    cat_info <- .autocomplete_config$legal_categories[[category]]
    
    for (example in cat_info$examples) {
      example_lower <- tolower(example)
      
      # Prefix matching
      if (startsWith(example_lower, query_lower)) {
        suggestions[example] <- paste0("Legal (", category, ") - Priority: ", cat_info$priority)
      }
      # Fuzzy matching for longer queries
      else if (nchar(query) >= 3 && grepl(query_lower, example_lower, fixed = TRUE)) {
        suggestions[example] <- paste0("Legal (", category, ") - Contains match")
      }
    }
  }
  
  return(suggestions)
}

#' Get government authority suggestions
#' @param query Partial query
#' @param context Current search context
#' @return Named vector of suggestions
get_authority_suggestions <- function(query, context) {
  
  suggestions <- character(0)
  query_lower <- tolower(query)
  
  # Prioritize authorities based on context
  authority_priority <- c("federal", "state", "municipal")
  
  # Adjust priority based on context
  if (!is.null(context$estado)) {
    if (context$estado == "BR" || context$estado == "DF") {
      authority_priority <- c("federal", "state", "municipal")
    } else {
      authority_priority <- c("state", "municipal", "federal")
    }
  }
  
  for (level in authority_priority) {
    authorities <- .autocomplete_config$authorities[[level]]
    
    for (authority in authorities) {
      authority_lower <- tolower(authority)
      
      if (startsWith(authority_lower, query_lower) || 
          grepl(query_lower, authority_lower, fixed = TRUE)) {
        
        level_label <- switch(level,
                             "federal" = "Federal",
                             "state" = "Estadual", 
                             "municipal" = "Municipal")
        
        suggestions[authority] <- paste0("Autoridade ", level_label)
      }
    }
  }
  
  return(suggestions)
}

#' Get transport modal suggestions
#' @param query Partial query
#' @param context Current search context
#' @return Named vector of suggestions
get_transport_suggestions <- function(query, context) {
  
  suggestions <- character(0)
  query_lower <- tolower(query)
  
  # Prioritize based on current transport context
  modal_priority <- names(.autocomplete_config$transport_modals)
  
  if (!is.null(context$transport_category) && context$transport_category != "Geral") {
    # Move current modal to front
    current_modal <- switch(tolower(context$transport_category),
                           "aéreo" = "aereo",
                           "rodoviário" = "rodoviario", 
                           "ferroviário" = "ferroviario",
                           "marítimo" = "maritimo",
                           "hidroviário" = "hidroviario",
                           "urbano" = "urbano",
                           NULL)
    
    if (!is.null(current_modal) && current_modal %in% modal_priority) {
      modal_priority <- c(current_modal, setdiff(modal_priority, current_modal))
    }
  }
  
  for (modal in modal_priority) {
    terms <- .autocomplete_config$transport_modals[[modal]]
    
    for (term in terms) {
      term_lower <- tolower(term)
      
      if (startsWith(term_lower, query_lower) || 
          grepl(query_lower, term_lower, fixed = TRUE)) {
        
        modal_label <- switch(modal,
                             "aereo" = "Aéreo",
                             "rodoviario" = "Rodoviário",
                             "ferroviario" = "Ferroviário", 
                             "maritimo" = "Marítimo",
                             "hidroviario" = "Hidroviário",
                             "urbano" = "Urbano")
        
        suggestions[term] <- paste0("Transporte ", modal_label)
      }
    }
  }
  
  return(suggestions)
}

#' Get legal concept suggestions
#' @param query Partial query
#' @param context Current search context
#' @return Named vector of suggestions
get_legal_concept_suggestions <- function(query, context) {
  
  suggestions <- character(0)
  query_lower <- tolower(query)
  
  for (phrase in .autocomplete_config$legal_phrases) {
    phrase_lower <- tolower(phrase)
    
    if (startsWith(phrase_lower, query_lower) || 
        grepl(query_lower, phrase_lower, fixed = TRUE)) {
      suggestions[phrase] <- "Expressão Jurídica"
    }
  }
  
  return(suggestions)
}

#' Get popular search terms suggestions
#' @param query Partial query
#' @param context Current search context
#' @return Named vector of suggestions
get_popular_terms_suggestions <- function(query, context) {
  
  # This would typically query the database for popular search terms
  # For now, return common Brazilian legal search terms
  
  popular_terms <- c(
    "código de trânsito brasileiro", "lei de licitações", "plano diretor",
    "transporte público", "mobilidade urbana", "agência reguladora",
    "política nacional de transportes", "concessão de rodovia",
    "programa nacional", "sistema viário", "infraestrutura de transportes"
  )
  
  suggestions <- character(0)
  query_lower <- tolower(query)
  
  for (term in popular_terms) {
    term_lower <- tolower(term)
    
    if (startsWith(term_lower, query_lower) || 
        grepl(query_lower, term_lower, fixed = TRUE)) {
      suggestions[term] <- "Termo Popular"
    }
  }
  
  return(suggestions)
}

#' Get geographic suggestions (states, cities)
#' @param query Partial query
#' @param context Current search context
#' @return Named vector of suggestions
get_geographic_suggestions <- function(query, context) {
  
  suggestions <- character(0)
  query_lower <- tolower(query)
  
  # Brazilian states
  states <- c(
    "Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará",
    "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
    "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará",
    "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro",
    "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", "Roraima",
    "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"
  )
  
  # Major Brazilian cities
  cities <- c(
    "São Paulo", "Rio de Janeiro", "Brasília", "Salvador", "Fortaleza",
    "Belo Horizonte", "Manaus", "Curitiba", "Recife", "Porto Alegre",
    "Belém", "Goiânia", "Guarulhos", "Campinas", "São Luís",
    "Maceió", "Nova Iguaçu", "Duque de Caxias", "Natal", "Teresina"
  )
  
  # Check states
  for (state in states) {
    state_lower <- tolower(state)
    if (startsWith(state_lower, query_lower)) {
      suggestions[state] <- "Estado"
    }
  }
  
  # Check cities
  for (city in cities) {
    city_lower <- tolower(city)
    if (startsWith(city_lower, query_lower)) {
      suggestions[city] <- "Município"
    }
  }
  
  return(suggestions)
}

#' Get fuzzy matching suggestions for typos
#' @param query Partial query
#' @param existing_suggestions Already found suggestions
#' @return Named vector of fuzzy suggestions
get_fuzzy_suggestions <- function(query, existing_suggestions) {
  
  if (!requireNamespace("stringdist", quietly = TRUE) || nchar(query) < 3) {
    return(character(0))
  }
  
  # Combine all existing suggestion keys for fuzzy matching
  all_terms <- character(0)
  for (category in names(existing_suggestions)) {
    all_terms <- c(all_terms, names(existing_suggestions[[category]]))
  }
  
  if (length(all_terms) == 0) {
    return(character(0))
  }
  
  # Calculate string distances
  distances <- stringdist::stringdist(tolower(query), tolower(all_terms), method = "jw")
  
  # Find terms with distance below threshold
  fuzzy_matches <- all_terms[distances < (1 - .autocomplete_config$fuzzy_threshold)]
  
  if (length(fuzzy_matches) == 0) {
    return(character(0))
  }
  
  # Create suggestions with distance information
  suggestions <- character(0)
  for (match in head(fuzzy_matches, 3)) {  # Limit fuzzy suggestions
    match_distance <- distances[all_terms == match][1]
    suggestions[match] <- paste0("Sugestão (similarity: ", round((1 - match_distance) * 100), "%)")
  }
  
  return(suggestions)
}

# ============================================================================
# SUGGESTION RANKING AND COMBINATION
# ============================================================================

#' Combine and rank suggestions from all sources
#' @param suggestions List of suggestion categories
#' @param query Original query
#' @param max_suggestions Maximum suggestions to return
#' @param context Search context
#' @return Ranked vector of final suggestions
combine_and_rank_suggestions <- function(suggestions, query, max_suggestions, context) {
  
  if (length(suggestions) == 0) {
    return(character(0))
  }
  
  # Scoring weights by category
  category_weights <- list(
    legal_documents = 10,
    authorities = 8,
    transport = 7,
    concepts = 6,
    popular = 5,
    geographic = 4,
    fuzzy = 2
  )
  
  # Collect all suggestions with scores
  scored_suggestions <- data.frame(
    term = character(0),
    category = character(0),
    description = character(0),
    score = numeric(0),
    stringsAsFactors = FALSE
  )
  
  for (category in names(suggestions)) {
    category_suggestions <- suggestions[[category]]
    
    if (length(category_suggestions) > 0) {
      base_weight <- category_weights[[category]] %||% 1
      
      for (i in seq_along(category_suggestions)) {
        term <- names(category_suggestions)[i]
        description <- category_suggestions[i]
        
        # Calculate suggestion score
        score <- calculate_suggestion_score(term, query, base_weight, context)
        
        scored_suggestions <- rbind(scored_suggestions, data.frame(
          term = term,
          category = category,
          description = description,
          score = score,
          stringsAsFactors = FALSE
        ))
      }
    }
  }
  
  # Remove duplicates, keeping the highest scored version
  if (nrow(scored_suggestions) > 0) {
    scored_suggestions <- scored_suggestions %>%
      arrange(desc(score)) %>%
      distinct(term, .keep_all = TRUE)
    
    # Limit to max suggestions
    if (nrow(scored_suggestions) > max_suggestions) {
      scored_suggestions <- scored_suggestions[1:max_suggestions, ]
    }
    
    # Return as named vector
    final_suggestions <- setNames(scored_suggestions$description, scored_suggestions$term)
    return(final_suggestions)
  }
  
  return(character(0))
}

#' Calculate individual suggestion score
#' @param term Suggestion term
#' @param query Original query
#' @param base_weight Base category weight
#' @param context Search context
#' @return Numeric score
calculate_suggestion_score <- function(term, query, base_weight, context) {
  
  score <- base_weight
  
  term_lower <- tolower(term)
  query_lower <- tolower(query)
  
  # Exact prefix match bonus
  if (startsWith(term_lower, query_lower)) {
    score <- score + 5
  }
  
  # Length preference (shorter terms often more relevant)
  if (nchar(term) <= nchar(query) + 10) {
    score <- score + 2
  }
  
  # Context relevance bonus
  if (!is.null(context$transport_category) && context$transport_category != "Geral") {
    transport_terms <- unlist(.autocomplete_config$transport_modals)
    if (any(sapply(transport_terms, function(t) grepl(tolower(t), term_lower)))) {
      score <- score + 3
    }
  }
  
  # Geographic context bonus
  if (!is.null(context$estado) && context$estado != "all") {
    if (grepl(context$estado, term, ignore.case = TRUE)) {
      score <- score + 3
    }
  }
  
  return(score)
}

# ============================================================================
# CACHING SYSTEM
# ============================================================================

#' Generate cache key for autocomplete request
#' @param query Query string
#' @param context Search context
#' @param max_suggestions Maximum suggestions
#' @return MD5 hash cache key
generate_autocomplete_cache_key <- function(query, context, max_suggestions) {
  cache_data <- list(
    query = tolower(trimws(query)),
    context = context,
    max_suggestions = max_suggestions,
    version = "1.0"
  )
  
  return(paste0("autocomplete_", digest(cache_data, algo = "md5")))
}

#' Get cached autocomplete response
#' @param cache_key Cache key
#' @return Cached response or NULL
get_cached_autocomplete <- function(cache_key) {
  
  if (cache_key %in% names(.autocomplete_cache)) {
    cache_entry <- .autocomplete_cache[[cache_key]]
    
    # Check if cache entry is still valid
    if (Sys.time() < cache_entry$expires_at) {
      return(cache_entry$data)
    } else {
      # Remove expired entry
      .autocomplete_cache[[cache_key]] <<- NULL
    }
  }
  
  return(NULL)
}

#' Cache autocomplete response
#' @param cache_key Cache key
#' @param response Response data
cache_autocomplete_response <- function(cache_key, response) {
  
  .autocomplete_cache[[cache_key]] <<- list(
    data = response,
    cached_at = Sys.time(),
    expires_at = Sys.time() + .autocomplete_config$cache_ttl_seconds
  )
  
  # Clean up old entries periodically
  if (length(.autocomplete_cache) > 1000) {
    cleanup_autocomplete_cache()
  }
}

#' Clean up expired autocomplete cache entries
cleanup_autocomplete_cache <- function() {
  
  current_time <- Sys.time()
  expired_keys <- character(0)
  
  for (key in names(.autocomplete_cache)) {
    if (current_time >= .autocomplete_cache[[key]]$expires_at) {
      expired_keys <- c(expired_keys, key)
    }
  }
  
  if (length(expired_keys) > 0) {
    for (key in expired_keys) {
      .autocomplete_cache[[key]] <<- NULL
    }
    cat("🧹 Cleaned", length(expired_keys), "expired autocomplete cache entries\n")
  }
}

# ============================================================================
# RESPONSE FORMATTING
# ============================================================================

#' Create formatted suggestions response
#' @param suggestions Final suggestions vector
#' @param query Original query
#' @param context Search context
#' @param response_time_ms Response time in milliseconds
#' @return Structured response list
create_suggestions_response <- function(suggestions, query, context, response_time_ms) {
  
  return(list(
    query = query,
    suggestions = if(length(suggestions) > 0) {
      mapply(function(term, desc) {
        list(
          text = term,
          description = desc,
          category = extract_category_from_description(desc)
        )
      }, names(suggestions), suggestions, SIMPLIFY = FALSE, USE.NAMES = FALSE)
    } else {
      list()
    },
    metadata = list(
      total_found = length(suggestions),
      response_time_ms = round(response_time_ms, 2),
      context = context,
      cached = FALSE,
      timestamp = Sys.time()
    )
  ))
}

#' Create empty suggestions response for errors or no matches
#' @param query Original query
#' @param error_message Optional error message
#' @return Empty response structure
create_empty_suggestions_response <- function(query, error_message = NULL) {
  
  return(list(
    query = query,
    suggestions = list(),
    metadata = list(
      total_found = 0,
      response_time_ms = 0,
      error = error_message,
      timestamp = Sys.time()
    )
  ))
}

#' Extract category from suggestion description
#' @param description Suggestion description
#' @return Category string
extract_category_from_description <- function(description) {
  
  if (grepl("Legal", description, ignore.case = TRUE)) return("legal")
  if (grepl("Autoridade", description, ignore.case = TRUE)) return("authority")
  if (grepl("Transporte", description, ignore.case = TRUE)) return("transport")
  if (grepl("Expressão", description, ignore.case = TRUE)) return("concept")
  if (grepl("Popular", description, ignore.case = TRUE)) return("popular")
  if (grepl("Estado|Município", description, ignore.case = TRUE)) return("geographic")
  if (grepl("Sugestão", description, ignore.case = TRUE)) return("fuzzy")
  
  return("other")
}

# ============================================================================
# PERFORMANCE MONITORING
# ============================================================================

#' Update autocomplete performance metrics
#' @param response_time_ms Response time in milliseconds
update_autocomplete_metrics <- function(response_time_ms) {
  
  .autocomplete_metrics$avg_response_time_ms <<- 
    (.autocomplete_metrics$avg_response_time_ms + response_time_ms) / 2
  
  if (response_time_ms > .autocomplete_config$response_time_target_ms) {
    .autocomplete_metrics$slow_queries <<- .autocomplete_metrics$slow_queries + 1
  }
}

#' Get autocomplete performance statistics
#' @return List with performance metrics
get_autocomplete_performance_stats <- function() {
  
  cache_hit_rate <- 0
  if ((.autocomplete_metrics$cache_hits + .autocomplete_metrics$cache_misses) > 0) {
    cache_hit_rate <- .autocomplete_metrics$cache_hits / 
                     (.autocomplete_metrics$cache_hits + .autocomplete_metrics$cache_misses) * 100
  }
  
  return(list(
    total_requests = .autocomplete_metrics$total_requests,
    cache_hits = .autocomplete_metrics$cache_hits,
    cache_misses = .autocomplete_metrics$cache_misses,
    cache_hit_rate_percent = round(cache_hit_rate, 2),
    avg_response_time_ms = round(.autocomplete_metrics$avg_response_time_ms, 2),
    slow_queries = .autocomplete_metrics$slow_queries,
    target_response_time_ms = .autocomplete_config$response_time_target_ms,
    cache_size = length(.autocomplete_cache),
    available_packages = available_autocomplete_packages,
    legal_categories = length(.autocomplete_config$legal_categories),
    transport_modals = length(.autocomplete_config$transport_modals)
  ))
}

# ============================================================================
# INITIALIZATION
# ============================================================================

cat("✅ Intelligent Autocomplete System loaded successfully\n")
cat("   💡 Legal categories:", length(.autocomplete_config$legal_categories), "\n")
cat("   🚛 Transport modals:", length(.autocomplete_config$transport_modals), "\n")
cat("   ⚖️ Legal phrases:", length(.autocomplete_config$legal_phrases), "\n")
cat("   💾 Caching:", if(.autocomplete_config$cache_enabled) "ENABLED" else "DISABLED", "\n")
cat("   🎯 Target response time:", .autocomplete_config$response_time_target_ms, "ms\n")

# Export main functions
.GlobalEnv$generate_autocomplete_suggestions <- generate_autocomplete_suggestions
.GlobalEnv$get_autocomplete_performance_stats <- get_autocomplete_performance_stats
.GlobalEnv$cleanup_autocomplete_cache <- cleanup_autocomplete_cache