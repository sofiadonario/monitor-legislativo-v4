# ============================================================================
# ENHANCED SEARCH API - SPRINT 7A (API-005)
# ============================================================================
# 
# Advanced search endpoints with Portuguese legal term optimization for Brazilian Legislative Monitoring System
# Features sophisticated full-text search with NLP, legal term boosting, and semantic analysis
#
# Enhanced Features:
# - Portuguese language NLP with legal terminology
# - Semantic search with legal concept understanding
# - Advanced query parsing with Boolean operators
# - Search result ranking with Brazilian legal term boosting
# - Auto-suggestion with legal term completion
# - Search analytics and query optimization
# - Faceted search with legal document categorization
# ============================================================================

cat("🔍 Loading Enhanced Search API - Sprint 7A (API-005)\n")

# Load required libraries for advanced search functionality
required_packages <- c("dplyr", "stringr", "tm", "SnowballC", "jsonlite", "lubridate")
for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE, quietly = TRUE))
  }
}

# Portuguese legal terminology dictionary with semantic relationships
PORTUGUESE_LEGAL_DICTIONARY <- list(
  "direito" = list(
    synonyms = c("norma", "regra", "ordenamento", "direito legal", "preceito"),
    related = c("lei", "jurisprudência", "doutrina", "justiça"),
    weight = 2.5,
    category = "fundamental_concept",
    semantic_field = "law_theory"
  ),
  "lei" = list(
    synonyms = c("norma", "dispositivo", "regramento", "statute", "legislação"),
    related = c("decreto", "portaria", "resolução", "medida provisória"),
    weight = 3.0,
    category = "legal_instrument",
    semantic_field = "legislation"
  ),
  "constituição" = list(
    synonyms = c("carta magna", "lei maior", "norma fundamental", "text constitucional"),
    related = c("direito constitucional", "soberania", "federação"),
    weight = 3.5,
    category = "constitutional",
    semantic_field = "constitutional_law"
  ),
  "jurisprudência" = list(
    synonyms = c("precedente", "decisão judicial", "orientação jurisprudencial", "entendimento"),
    related = c("súmula", "acórdão", "sentença", "tribunal"),
    weight = 2.8,
    category = "judicial_precedent",
    semantic_field = "case_law"
  ),
  "tribunal" = list(
    synonyms = c("corte", "juízo", "vara", "instância"),
    related = c("magistrado", "juiz", "desembargador", "ministro"),
    weight = 2.3,
    category = "judicial_institution",
    semantic_field = "judiciary"
  ),
  "processo" = list(
    synonyms = c("procedimento", "ação", "demanda", "lide"),
    related = c("petição", "recurso", "sentença", "execução"),
    weight = 2.0,
    category = "procedural",
    semantic_field = "procedure"
  ),
  "administração pública" = list(
    synonyms = c("poder público", "estado", "governo", "órgão público"),
    related = c("servidor público", "licitação", "concurso", "transparência"),
    weight = 2.4,
    category = "administrative",
    semantic_field = "public_administration"
  ),
  "tributário" = list(
    synonyms = c("fiscal", "imposto", "tributo", "taxa"),
    related = c("receita", "arrecadação", "sonegação", "elisão"),
    weight = 2.2,
    category = "tax_law",
    semantic_field = "taxation"
  ),
  "civil" = list(
    synonyms = c("privado", "particular", "pessoa física", "contrato"),
    related = c("família", "sucessão", "propriedade", "obrigação"),
    weight = 2.1,
    category = "civil_law",
    semantic_field = "private_law"
  ),
  "penal" = list(
    synonyms = c("criminal", "crime", "delito", "infração"),
    related = c("pena", "prisão", "multa", "liberdade"),
    weight = 2.6,
    category = "criminal_law",
    semantic_field = "criminal_justice"
  )
)

# Portuguese stopwords for legal documents
PORTUGUESE_LEGAL_STOPWORDS <- c(
  "o", "a", "os", "as", "um", "uma", "uns", "umas", "de", "do", "da", "dos", "das",
  "em", "no", "na", "nos", "nas", "por", "para", "com", "sem", "sob", "sobre",
  "entre", "durante", "através", "mediante", "segundo", "conforme", "perante",
  "que", "se", "não", "sim", "mas", "porém", "contudo", "todavia", "entretanto",
  "artigo", "art", "parágrafo", "inciso", "alínea", "item", "caput", "§"
)

# Advanced query processing and optimization
process_search_query <- function(query, enable_nlp = TRUE, include_synonyms = TRUE) {
  if (is.null(query) || nchar(trimws(query)) == 0) {
    return(list(
      original = "",
      processed = "",
      terms = c(),
      legal_terms = c(),
      boosted_terms = c(),
      query_type = "empty"
    ))
  }
  
  # Clean and normalize query
  cleaned_query <- tolower(trimws(query))
  cleaned_query <- gsub("[[:punct:]]+", " ", cleaned_query)
  cleaned_query <- gsub("\\s+", " ", cleaned_query)
  
  # Extract individual terms
  query_terms <- strsplit(cleaned_query, "\\s+")[[1]]
  query_terms <- query_terms[!query_terms %in% PORTUGUESE_LEGAL_STOPWORDS]
  query_terms <- query_terms[nchar(query_terms) > 2]
  
  # Identify legal terms and create boosted query
  legal_terms_found <- c()
  boosted_terms <- c()
  expanded_terms <- c()
  
  if (enable_nlp && include_synonyms) {
    for (term in query_terms) {
      # Check for exact matches in legal dictionary
      for (legal_term in names(PORTUGUESE_LEGAL_DICTIONARY)) {
        term_data <- PORTUGUESE_LEGAL_DICTIONARY[[legal_term]]
        
        # Check if term matches legal term or synonyms
        if (term == legal_term || term %in% term_data$synonyms) {
          legal_terms_found <- c(legal_terms_found, legal_term)
          boosted_terms <- c(boosted_terms, legal_term)
          
          # Add related terms for semantic expansion
          if (length(term_data$related) > 0) {
            expanded_terms <- c(expanded_terms, term_data$related[1:min(3, length(term_data$related))])
          }
          
          break
        }
        
        # Check for partial matches (stemming-like)
        if (grepl(substr(term, 1, max(4, nchar(term)-2)), legal_term) ||
            grepl(substr(legal_term, 1, max(4, nchar(legal_term)-2)), term)) {
          legal_terms_found <- c(legal_terms_found, legal_term)
          boosted_terms <- c(boosted_terms, legal_term)
          break
        }
      }
    }
  }
  
  # Create enhanced search terms
  all_search_terms <- unique(c(query_terms, boosted_terms, expanded_terms))
  
  # Determine query type
  query_type <- "simple"
  if (length(legal_terms_found) > 0) {
    query_type <- "legal_optimized"
  }
  if (grepl("AND|OR|NOT|\\+|\\-", query, ignore.case = TRUE)) {
    query_type <- "boolean"
  }
  if (grepl('".+"', query)) {
    query_type <- "phrase"
  }
  
  return(list(
    original = query,
    processed = paste(all_search_terms, collapse = " "),
    terms = query_terms,
    legal_terms = unique(legal_terms_found),
    boosted_terms = unique(boosted_terms),
    expanded_terms = unique(expanded_terms),
    query_type = query_type,
    search_complexity = length(all_search_terms)
  ))
}

# Advanced relevance scoring with legal term boosting
calculate_relevance_score <- function(document, query_analysis, base_score = 1.0) {
  score <- base_score
  
  # Get document text for analysis
  doc_text <- paste(
    document$title %||% document$titulo %||% "",
    document$summary %||% document$ementa %||% "",
    document$subjects %||% document$assuntos %||% ""
  )
  doc_text_lower <- tolower(doc_text)
  
  # Base text matching score
  term_matches <- 0
  for (term in query_analysis$terms) {
    if (grepl(term, doc_text_lower)) {
      term_matches <- term_matches + 1
    }
  }
  
  if (length(query_analysis$terms) > 0) {
    score <- score * (1 + term_matches / length(query_analysis$terms))
  }
  
  # Legal term boosting
  legal_boost <- 1.0
  for (legal_term in query_analysis$legal_terms) {
    if (legal_term %in% names(PORTUGUESE_LEGAL_DICTIONARY)) {
      term_data <- PORTUGUESE_LEGAL_DICTIONARY[[legal_term]]
      
      # Check for legal term presence
      if (grepl(legal_term, doc_text_lower)) {
        legal_boost <- legal_boost + term_data$weight
      }
      
      # Check for synonyms
      for (synonym in term_data$synonyms) {
        if (grepl(synonym, doc_text_lower)) {
          legal_boost <- legal_boost + (term_data$weight * 0.8)
          break
        }
      }
    }
  }
  
  score <- score * legal_boost
  
  # Document type relevance
  if (!is.null(document$document_type) || !is.null(document$tipo)) {
    doc_type <- tolower(document$document_type %||% document$tipo %||% "")
    
    # Boost score based on document type relevance to legal terms
    for (legal_term in query_analysis$legal_terms) {
      if (legal_term == "lei" && grepl("lei", doc_type)) {
        score <- score * 1.5
      } else if (legal_term == "decreto" && grepl("decreto", doc_type)) {
        score <- score * 1.5
      } else if (legal_term == "constituição" && grepl("constitui", doc_type)) {
        score <- score * 2.0
      }
    }
  }
  
  # Recency boost
  if (!is.null(document$publication_date) || !is.null(document$data_publicacao)) {
    pub_date <- as.Date(document$publication_date %||% document$data_publicacao)
    if (!is.na(pub_date)) {
      days_old <- as.numeric(Sys.Date() - pub_date)
      if (days_old < 365) {
        recency_boost <- 1 + (1 - (days_old / 365)) * 0.2
        score <- score * recency_boost
      }
    }
  }
  
  return(round(score, 4))
}

# POST /api/v1/search/advanced - Advanced search with Portuguese legal term optimization
#* @post /api/v1/search/advanced
#* @param req Request object containing advanced search parameters
#* @tag search
#* @serializer unboxedJSON
function(req) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  start_time <- Sys.time()
  
  # Parse request body
  body <- tryCatch({
    jsonlite::fromJSON(req$postBody)
  }, error = function(e) {
    return(list())
  })
  
  # Extract search parameters
  query <- body$query %||% ""
  enable_nlp <- body$enable_nlp %||% TRUE
  include_synonyms <- body$include_synonyms %||% TRUE
  legal_term_boost <- body$legal_term_boost %||% TRUE
  semantic_expansion <- body$semantic_expansion %||% TRUE
  filters <- body$filters %||% list()
  sort_by <- body$sort_by %||% "relevance"
  include_highlights <- body$include_highlights %||% TRUE
  include_facets <- body$include_facets %||% TRUE
  limit <- min(max(as.numeric(body$limit %||% 50), 1), 1000)
  offset <- max(as.numeric(body$offset %||% 0), 0)
  
  if (nchar(trimws(query)) == 0) {
    return(error_response("Search query is required", 400))
  }
  
  tryCatch({
    # Process query with NLP optimization
    query_analysis <- process_search_query(query, enable_nlp, include_synonyms)
    
    # Build search query for database
    search_results <- list()
    
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      main_table <- if (exists("get_main_table")) get_main_table() else "documents"
      
      # Base search query with Portuguese full-text search
      base_query <- sprintf("
        SELECT 
          d.id,
          d.titulo as title,
          d.ementa as summary,
          d.autor as author,
          d.data_publicacao as publication_date,
          d.url,
          d.urn,
          d.tipo as document_type,
          d.estado as state,
          d.municipio as municipality,
          d.assuntos as subjects,
          d.species,
          ts_rank_cd(
            to_tsvector('portuguese', d.titulo || ' ' || COALESCE(d.ementa, '') || ' ' || COALESCE(d.assuntos, '')),
            plainto_tsquery('portuguese', $1)
          ) as base_relevance
        FROM %s d
        WHERE to_tsvector('portuguese', d.titulo || ' ' || COALESCE(d.ementa, '') || ' ' || COALESCE(d.assuntos, ''))
              @@ plainto_tsquery('portuguese', $1)
      ", main_table)
      
      # Add filters
      filter_conditions <- c()
      params <- list(query_analysis$processed)
      param_count <- 1
      
      if (!is.null(filters$states) && length(filters$states) > 0) {
        param_count <- param_count + 1
        params[[param_count]] <- filters$states
        filter_conditions <- c(filter_conditions, sprintf("d.estado = ANY($%d)", param_count))
      }
      
      if (!is.null(filters$document_types) && length(filters$document_types) > 0) {
        param_count <- param_count + 1
        params[[param_count]] <- filters$document_types
        filter_conditions <- c(filter_conditions, sprintf("d.tipo = ANY($%d)", param_count))
      }
      
      if (!is.null(filters$date_range)) {
        if (!is.null(filters$date_range$start)) {
          param_count <- param_count + 1
          params[[param_count]] <- as.Date(filters$date_range$start)
          filter_conditions <- c(filter_conditions, sprintf("d.data_publicacao >= $%d", param_count))
        }
        if (!is.null(filters$date_range$end)) {
          param_count <- param_count + 1
          params[[param_count]] <- as.Date(filters$date_range$end)
          filter_conditions <- c(filter_conditions, sprintf("d.data_publicacao <= $%d", param_count))
        }
      }
      
      # Apply filters
      if (length(filter_conditions) > 0) {
        base_query <- paste(base_query, "AND", paste(filter_conditions, collapse = " AND "))
      }
      
      # Add sorting
      if (sort_by == "relevance") {
        base_query <- paste(base_query, "ORDER BY base_relevance DESC, d.data_publicacao DESC")
      } else if (sort_by == "date_desc") {
        base_query <- paste(base_query, "ORDER BY d.data_publicacao DESC")
      } else if (sort_by == "date_asc") {
        base_query <- paste(base_query, "ORDER BY d.data_publicacao ASC")
      } else if (sort_by == "title") {
        base_query <- paste(base_query, "ORDER BY d.titulo ASC")
      }
      
      # Add pagination
      base_query <- paste(base_query, sprintf("LIMIT %d OFFSET %d", limit, offset))
      
      # Execute search
      result <- dbGetQuery(secure_db_pool, base_query, params)
      
      # Get total count
      count_query <- gsub("SELECT.*?FROM", "SELECT COUNT(*) as total FROM", base_query)
      count_query <- gsub("ORDER BY.*", "", count_query)
      count_query <- gsub("LIMIT.*", "", count_query)
      total_result <- dbGetQuery(secure_db_pool, count_query, params)
      total_count <- scalar_num(total_result$total, 0)
      
    } else {
      # Fallback search using simple text matching
      fallback_data <- get_library_documents(
        search_term = query,
        limit = limit,
        offset = offset
      )
      
      result <- fallback_data
      total_count <- nrow(fallback_data)
    }
    
    # Process search results with advanced relevance scoring
    processed_results <- list()
    
    if (nrow(result) > 0) {
      for (i in 1:nrow(result)) {
        doc <- result[i, ]
        
        # Calculate enhanced relevance score
        enhanced_relevance <- if (legal_term_boost) {
          calculate_relevance_score(doc, query_analysis, doc$base_relevance %||% 1.0)
        } else {
          as.numeric(doc$base_relevance %||% 1.0)
        }
        
        # Build result document
        result_doc <- list(
          id = as.character(doc$id),
          title = as.character(doc$title %||% ""),
          summary = as.character(doc$summary %||% ""),
          author = as.character(doc$author %||% ""),
          publication_date = as.character(doc$publication_date %||% ""),
          document_type = as.character(doc$document_type %||% ""),
          state = as.character(doc$state %||% ""),
          municipality = as.character(doc$municipality %||% ""),
          subjects = as.character(doc$subjects %||% ""),
          url = as.character(doc$url %||% ""),
          urn = as.character(doc$urn %||% ""),
          relevance_score = enhanced_relevance,
          match_info = list(
            matched_terms = query_analysis$terms,
            matched_legal_terms = query_analysis$legal_terms,
            query_type = query_analysis$query_type
          )
        )
        
        # Add highlighting if requested
        if (include_highlights) {
          highlighted_title <- doc$title %||% ""
          highlighted_summary <- doc$summary %||% ""
          
          for (term in c(query_analysis$terms, query_analysis$boosted_terms)) {
            if (nchar(term) > 2) {
              highlighted_title <- gsub(paste0("(", term, ")"), 
                                      "<mark>\\1</mark>", 
                                      highlighted_title, ignore.case = TRUE)
              highlighted_summary <- gsub(paste0("(", term, ")"), 
                                        "<mark>\\1</mark>", 
                                        highlighted_summary, ignore.case = TRUE)
            }
          }
          
          result_doc$highlights <- list(
            title = highlighted_title,
            summary = substr(highlighted_summary, 1, 300)
          )
        }
        
        processed_results[[i]] <- result_doc
      }
      
      # Re-sort by enhanced relevance if using relevance sorting
      if (sort_by == "relevance" && legal_term_boost) {
        processed_results <- processed_results[order(sapply(processed_results, function(x) x$relevance_score), decreasing = TRUE)]
      }
    }
    
    # Generate search facets if requested
    search_facets <- NULL
    if (include_facets && length(processed_results) > 0) {
      # Document type facets
      doc_types <- table(sapply(processed_results, function(x) x$document_type))
      state_facets <- table(sapply(processed_results, function(x) x$state))
      year_facets <- table(sapply(processed_results, function(x) {
        if (nchar(x$publication_date) > 0) {
          format(as.Date(x$publication_date), "%Y")
        } else "Unknown"
      }))
      
      search_facets <- list(
        document_types = lapply(names(doc_types), function(dt) {
          list(value = dt, count = as.numeric(doc_types[dt]))
        }),
        states = lapply(names(state_facets), function(st) {
          list(value = st, count = as.numeric(state_facets[st]))
        }),
        years = lapply(names(year_facets), function(yr) {
          list(value = yr, count = as.numeric(year_facets[yr]))
        }),
        legal_concepts = if (length(query_analysis$legal_terms) > 0) {
          lapply(query_analysis$legal_terms, function(term) {
            term_data <- PORTUGUESE_LEGAL_DICTIONARY[[term]]
            list(
              concept = term,
              category = term_data$category,
              semantic_field = term_data$semantic_field,
              related_terms = term_data$related[1:min(3, length(term_data$related))]
            )
          })
        } else NULL
      )
    }
    
    search_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    return(success_response(
      data = list(
        results = processed_results,
        query_analysis = query_analysis,
        facets = search_facets,
        search_metadata = list(
          total_results = total_count %||% 0,
          returned_results = length(processed_results),
          query_processed = query_analysis$processed,
          legal_terms_detected = length(query_analysis$legal_terms),
          semantic_expansion_applied = semantic_expansion && length(query_analysis$expanded_terms) > 0,
          search_optimizations = list(
            nlp_enabled = enable_nlp,
            legal_term_boost = legal_term_boost,
            synonym_expansion = include_synonyms,
            portuguese_stemming = TRUE
          )
        )
      ),
      meta = list(
        search_time = round(search_time, 3),
        query_complexity = query_analysis$search_complexity,
        optimization_level = if (length(query_analysis$legal_terms) > 0) "legal_optimized" else "standard",
        limit = limit,
        offset = offset
      ),
      message = paste("Advanced search completed:", length(processed_results), "results found")
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Advanced search error:", e$message),
      code = 500
    ))
  })
}

# GET /api/v1/search/suggest - Auto-suggestion with legal term completion
#* @get /api/v1/search/suggest
#* @param q:str Query prefix for suggestions
#* @param limit:int Maximum suggestions (default: 10)
#* @param include_legal_terms:bool Include legal term suggestions
#* @param context:str Search context (legal, academic, general)
#* @tag search
#* @serializer unboxedJSON
function(q = "", limit = 10, include_legal_terms = TRUE, context = "legal") {
  API_STATE$request_count <<- API_STATE$request_count + 1
  
  if (nchar(trimws(q)) < 2) {
    return(success_response(
      data = list(suggestions = list()),
      message = "Query too short for suggestions (minimum 2 characters)"
    ))
  }
  
  query_prefix <- tolower(trimws(q))
  limit <- min(max(as.numeric(limit), 1), 50)
  
  tryCatch({
    suggestions <- list()
    
    # Legal term suggestions
    if (include_legal_terms) {
      legal_suggestions <- list()
      
      for (legal_term in names(PORTUGUESE_LEGAL_DICTIONARY)) {
        term_data <- PORTUGUESE_LEGAL_DICTIONARY[[legal_term]]
        
        # Check if legal term starts with query
        if (startsWith(legal_term, query_prefix)) {
          legal_suggestions[[length(legal_suggestions) + 1]] <- list(
            text = legal_term,
            type = "legal_term",
            category = term_data$category,
            description = paste("Termo jurídico:", term_data$semantic_field),
            weight = term_data$weight,
            boost = TRUE
          )
        }
        
        # Check synonyms
        for (synonym in term_data$synonyms) {
          if (startsWith(synonym, query_prefix)) {
            legal_suggestions[[length(legal_suggestions) + 1]] <- list(
              text = synonym,
              type = "legal_synonym",
              primary_term = legal_term,
              category = term_data$category,
              description = paste("Sinônimo de", legal_term),
              weight = term_data$weight * 0.8,
              boost = TRUE
            )
          }
        }
      }
      
      # Sort legal suggestions by weight
      if (length(legal_suggestions) > 0) {
        legal_suggestions <- legal_suggestions[order(sapply(legal_suggestions, function(x) x$weight), decreasing = TRUE)]
        suggestions <- c(suggestions, legal_suggestions[1:min(limit/2, length(legal_suggestions))])
      }
    }
    
    # Historical search suggestions (mock implementation)
    historical_suggestions <- list()
    
    # Common legal search patterns
    common_patterns <- c(
      "direito constitucional",
      "direito administrativo", 
      "direito penal",
      "direito civil",
      "processo civil",
      "processo penal",
      "lei orgânica",
      "código civil",
      "código penal",
      "constituição federal",
      "supremo tribunal federal",
      "superior tribunal justiça"
    )
    
    for (pattern in common_patterns) {
      if (grepl(query_prefix, pattern, ignore.case = TRUE)) {
        historical_suggestions[[length(historical_suggestions) + 1]] <- list(
          text = pattern,
          type = "common_search",
          description = "Busca comum no sistema",
          frequency = runif(1, 0.5, 1.0), # Mock frequency
          boost = FALSE
        )
      }
    }
    
    # Add historical suggestions
    remaining_slots <- limit - length(suggestions)
    if (remaining_slots > 0 && length(historical_suggestions) > 0) {
      historical_suggestions <- historical_suggestions[order(sapply(historical_suggestions, function(x) x$frequency), decreasing = TRUE)]
      suggestions <- c(suggestions, historical_suggestions[1:min(remaining_slots, length(historical_suggestions))])
    }
    
    # Document-based suggestions from database
    if (exists("secure_db_pool") && !is.null(secure_db_pool) && length(suggestions) < limit) {
      main_table <- if (exists("get_main_table")) get_main_table() else "documents"
      
      # Find document titles that match query prefix
      title_query <- sprintf("
        SELECT DISTINCT d.titulo as title
        FROM %s d
        WHERE d.titulo ILIKE $1
        ORDER BY d.data_publicacao DESC
        LIMIT $2
      ", main_table)
      
      title_result <- dbGetQuery(secure_db_pool, title_query, 
                                list(paste0(query_prefix, "%"), limit - length(suggestions)))
      
      if (nrow(title_result) > 0) {
        for (i in 1:nrow(title_result)) {
          title_row <- title_result[i, ]
          suggestions[[length(suggestions) + 1]] <- list(
            text = as.character(title_row$title),
            type = "document_title",
            description = "Título de documento no sistema",
            boost = FALSE
          )
        }
      }
    }
    
    # Context-specific suggestions
    if (context == "academic") {
      academic_terms <- c("tese", "dissertação", "artigo científico", "revisão bibliográfica")
      for (term in academic_terms) {
        if (startsWith(term, query_prefix) && length(suggestions) < limit) {
          suggestions[[length(suggestions) + 1]] <- list(
            text = term,
            type = "academic_context",
            description = "Termo acadêmico",
            boost = FALSE
          )
        }
      }
    }
    
    # Remove duplicates and limit results
    unique_suggestions <- list()
    seen_texts <- c()
    
    for (suggestion in suggestions) {
      if (!suggestion$text %in% seen_texts && length(unique_suggestions) < limit) {
        unique_suggestions[[length(unique_suggestions) + 1]] <- suggestion
        seen_texts <- c(seen_texts, suggestion$text)
      }
    }
    
    return(success_response(
      data = list(
        query = q,
        suggestions = unique_suggestions,
        suggestion_metadata = list(
          total_suggestions = length(unique_suggestions),
          legal_terms_count = sum(sapply(unique_suggestions, function(x) x$type == "legal_term")),
          context_applied = context,
          boost_enabled = include_legal_terms
        )
      ),
      meta = list(
        query_length = nchar(q),
        suggestion_limit = limit,
        context = context
      ),
      message = paste("Generated", length(unique_suggestions), "search suggestions")
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Search suggestion error:", e$message),
      code = 500
    ))
  })
}

# POST /api/v1/search/semantic - Semantic search with legal concept understanding
#* @post /api/v1/search/semantic
#* @param req Request object containing semantic search parameters
#* @tag search  
#* @serializer unboxedJSON
function(req) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  start_time <- Sys.time()
  
  # Parse request body
  body <- tryCatch({
    jsonlite::fromJSON(req$postBody)
  }, error = function(e) {
    return(list())
  })
  
  # Extract semantic search parameters
  concept <- body$concept %||% ""
  semantic_fields <- body$semantic_fields %||% c()
  similarity_threshold <- as.numeric(body$similarity_threshold %||% 0.6)
  expand_concepts <- body$expand_concepts %||% TRUE
  include_related_concepts <- body$include_related_concepts %||% TRUE
  limit <- min(max(as.numeric(body$limit %||% 50), 1), 500)
  
  if (nchar(trimws(concept)) == 0) {
    return(error_response("Legal concept is required for semantic search", 400))
  }
  
  tryCatch({
    # Find legal concepts related to search term
    related_concepts <- list()
    semantic_expansion_terms <- c()
    
    concept_lower <- tolower(trimws(concept))
    
    # Find matching legal concepts
    for (legal_term in names(PORTUGUESE_LEGAL_DICTIONARY)) {
      term_data <- PORTUGUESE_LEGAL_DICTIONARY[[legal_term]]
      
      # Calculate concept similarity (simplified)
      similarity_score <- 0
      
      # Direct match
      if (concept_lower == legal_term) {
        similarity_score <- 1.0
      }
      # Synonym match
      else if (concept_lower %in% tolower(term_data$synonyms)) {
        similarity_score <- 0.9
      }
      # Partial match
      else if (grepl(concept_lower, legal_term) || grepl(legal_term, concept_lower)) {
        similarity_score <- 0.7
      }
      # Related term match
      else if (any(grepl(concept_lower, tolower(term_data$related)))) {
        similarity_score <- 0.6
      }
      # Semantic field match
      else if (any(sapply(semantic_fields, function(sf) grepl(sf, term_data$semantic_field, ignore.case = TRUE)))) {
        similarity_score <- 0.5
      }
      
      if (similarity_score >= similarity_threshold) {
        related_concepts[[legal_term]] <- list(
          term = legal_term,
          similarity = similarity_score,
          category = term_data$category,
          semantic_field = term_data$semantic_field,
          synonyms = term_data$synonyms,
          related_terms = term_data$related,
          weight = term_data$weight
        )
        
        # Add terms for search expansion
        semantic_expansion_terms <- c(semantic_expansion_terms, legal_term)
        if (expand_concepts) {
          semantic_expansion_terms <- c(semantic_expansion_terms, term_data$synonyms[1:min(2, length(term_data$synonyms))])
          semantic_expansion_terms <- c(semantic_expansion_terms, term_data$related[1:min(2, length(term_data$related))])
        }
      }
    }
    
    # Create semantic search query
    semantic_query <- paste(unique(semantic_expansion_terms), collapse = " OR ")
    
    # Execute semantic search on documents
    search_results <- list()
    
    if (exists("secure_db_pool") && !is.null(secure_db_pool) && nchar(semantic_query) > 0) {
      main_table <- if (exists("get_main_table")) get_main_table() else "documents"
      
      # Semantic search query with concept boosting
      search_query <- sprintf("
        SELECT 
          d.id,
          d.titulo as title,
          d.ementa as summary,
          d.autor as author,
          d.data_publicacao as publication_date,
          d.tipo as document_type,
          d.estado as state,
          d.assuntos as subjects,
          d.url,
          ts_rank_cd(
            to_tsvector('portuguese', d.titulo || ' ' || COALESCE(d.ementa, '') || ' ' || COALESCE(d.assuntos, '')),
            to_tsquery('portuguese', $1)
          ) as semantic_relevance
        FROM %s d
        WHERE to_tsvector('portuguese', d.titulo || ' ' || COALESCE(d.ementa, '') || ' ' || COALESCE(d.assuntos, ''))
              @@ to_tsquery('portuguese', $1)
        ORDER BY semantic_relevance DESC
        LIMIT $2
      ", main_table)
      
      # Prepare query for PostgreSQL (replace OR with |)
      pg_query <- gsub(" OR ", " | ", semantic_query)
      
      result <- dbGetQuery(secure_db_pool, search_query, list(pg_query, limit))
      
      # Process results with concept matching
      if (nrow(result) > 0) {
        for (i in 1:nrow(result)) {
          doc <- result[i, ]
          
          # Identify matched concepts in document
          doc_text <- paste(doc$title, doc$summary, doc$subjects)
          matched_concepts <- c()
          concept_scores <- c()
          
          for (concept_name in names(related_concepts)) {
            concept_info <- related_concepts[[concept_name]]
            
            # Check for concept presence
            if (grepl(concept_name, doc_text, ignore.case = TRUE)) {
              matched_concepts <- c(matched_concepts, concept_name)
              concept_scores <- c(concept_scores, concept_info$similarity * concept_info$weight)
            }
          }
          
          # Calculate final semantic score
          final_score <- as.numeric(doc$semantic_relevance)
          if (length(concept_scores) > 0) {
            final_score <- final_score * (1 + sum(concept_scores))
          }
          
          search_results[[i]] <- list(
            id = as.character(doc$id),
            title = as.character(doc$title),
            summary = as.character(doc$summary),
            author = as.character(doc$author %||% ""),
            publication_date = as.character(doc$publication_date %||% ""),
            document_type = as.character(doc$document_type %||% ""),
            state = as.character(doc$state %||% ""),
            subjects = as.character(doc$subjects %||% ""),
            url = as.character(doc$url %||% ""),
            semantic_score = round(final_score, 4),
            matched_concepts = matched_concepts,
            concept_relevance = if (length(concept_scores) > 0) round(mean(concept_scores), 3) else 0
          )
        }
        
        # Sort by semantic score
        search_results <- search_results[order(sapply(search_results, function(x) x$semantic_score), decreasing = TRUE)]
      }
    } else {
      # Fallback semantic search
      search_results <- list(
        list(
          id = "semantic_sample",
          title = paste("Conceito semântico:", concept),
          summary = "Resultado de exemplo para busca semântica",
          semantic_score = 0.8,
          matched_concepts = names(related_concepts)[1:min(3, length(related_concepts))]
        )
      )
    }
    
    search_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    return(success_response(
      data = list(
        search_results = search_results,
        semantic_analysis = list(
          original_concept = concept,
          related_concepts = related_concepts,
          semantic_expansion = unique(semantic_expansion_terms),
          concept_relationships = if (include_related_concepts) {
            lapply(related_concepts, function(rc) {
              list(
                concept = rc$term,
                relationship_type = rc$category,
                semantic_distance = 1 - rc$similarity
              )
            })
          } else NULL
        ),
        search_metadata = list(
          total_results = length(search_results),
          concepts_found = length(related_concepts),
          similarity_threshold = similarity_threshold,
          semantic_fields = semantic_fields
        )
      ),
      meta = list(
        search_time = round(search_time, 3),
        search_type = "semantic",
        expansion_enabled = expand_concepts,
        concept_count = length(related_concepts)
      ),
      message = paste("Semantic search completed for concept:", concept)
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Semantic search error:", e$message),
      code = 500
    ))
  })
}

# GET /api/v1/search/legal-terms - Legal terminology dictionary and search optimization info
#* @get /api/v1/search/legal-terms
#* @param category:str Filter by legal category
#* @param semantic_field:str Filter by semantic field
#* @param include_examples:bool Include search examples
#* @tag search
#* @serializer unboxedJSON
function(category = "all", semantic_field = "all", include_examples = TRUE) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  
  # Filter legal terms based on parameters
  filtered_terms <- PORTUGUESE_LEGAL_DICTIONARY
  
  if (category != "all") {
    filtered_terms <- filtered_terms[sapply(filtered_terms, function(term) term$category == category)]
  }
  
  if (semantic_field != "all") {
    filtered_terms <- filtered_terms[sapply(filtered_terms, function(term) term$semantic_field == semantic_field)]
  }
  
  # Format terms for API response
  formatted_terms <- lapply(names(filtered_terms), function(term_name) {
    term_data <- filtered_terms[[term_name]]
    
    term_info <- list(
      term = term_name,
      category = term_data$category,
      semantic_field = term_data$semantic_field,
      weight = term_data$weight,
      synonyms = term_data$synonyms,
      related_terms = term_data$related,
      search_boost = term_data$weight > 2.0
    )
    
    if (include_examples) {
      term_info$search_examples <- c(
        paste("busca por:", term_name),
        paste("sinônimo:", term_data$synonyms[1]),
        if (length(term_data$related) > 0) paste("termo relacionado:", term_data$related[1])
      )
    }
    
    return(term_info)
  })
  
  names(formatted_terms) <- names(filtered_terms)
  
  # Generate category and semantic field summaries
  categories <- unique(sapply(PORTUGUESE_LEGAL_DICTIONARY, function(x) x$category))
  semantic_fields <- unique(sapply(PORTUGUESE_LEGAL_DICTIONARY, function(x) x$semantic_field))
  
  category_stats <- lapply(categories, function(cat) {
    cat_terms <- PORTUGUESE_LEGAL_DICTIONARY[sapply(PORTUGUESE_LEGAL_DICTIONARY, function(x) x$category == cat)]
    list(
      category = cat,
      term_count = length(cat_terms),
      avg_weight = round(mean(sapply(cat_terms, function(x) x$weight)), 2),
      high_boost_terms = sum(sapply(cat_terms, function(x) x$weight > 2.0))
    )
  })
  
  return(success_response(
    data = list(
      legal_terms = formatted_terms,
      dictionary_stats = list(
        total_terms = length(PORTUGUESE_LEGAL_DICTIONARY),
        filtered_terms = length(filtered_terms),
        categories = category_stats,
        semantic_fields = semantic_fields
      ),
      optimization_info = list(
        portuguese_nlp = "Enabled",
        legal_term_boosting = "Active",
        synonym_expansion = "Supported",
        semantic_search = "Available"
      )
    ),
    meta = list(
      filter_category = category,
      filter_semantic_field = semantic_field,
      examples_included = include_examples
    ),
    message = paste("Legal terminology dictionary with", length(filtered_terms), "terms")
  ))
}

cat("✅ Enhanced Search API Loaded - Sprint 7A (API-005)\n")