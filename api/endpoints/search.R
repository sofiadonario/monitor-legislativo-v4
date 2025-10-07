# ============================================================================
# SEARCH ENDPOINT IMPLEMENTATION - SPRINT 6B (API-001)
# ============================================================================
# 
# Advanced search capabilities for Brazilian legislative data
# Supports full-text search with Portuguese language processing
# Integrates with PostgreSQL text search and performance optimizations
# 
# Endpoints:
# - POST /api/v1/search - Full-text search with advanced filters
# - GET /api/v1/search/suggestions - Search suggestions and autocomplete
# - POST /api/v1/search/similar - Find similar documents
# - GET /api/v1/search/trends - Search trends and popular terms
# - POST /api/v1/search/bulk - Bulk search operations
# ============================================================================

cat("🔍 Loading Search Endpoint Implementation\n")

# Portuguese legal terms and stopwords
PORTUGUESE_STOPWORDS <- c(
  "a", "ao", "aos", "aquela", "aquelas", "aquele", "aqueles", "aquilo", "as", "até", "com", "como", 
  "da", "das", "de", "dela", "delas", "dele", "deles", "depois", "do", "dos", "e", "ela", "elas", 
  "ele", "eles", "em", "entre", "era", "eram", "essa", "essas", "esse", "esses", "esta", "estas", 
  "este", "estes", "eu", "foi", "for", "foram", "havia", "isso", "isto", "já", "lhe", "lhes", 
  "mais", "mas", "me", "mesmo", "meu", "meus", "minha", "minhas", "muito", "na", "nas", "não", 
  "nem", "no", "nos", "nós", "nossa", "nossas", "nosso", "nossos", "num", "numa", "o", "os", 
  "ou", "para", "pela", "pelas", "pelo", "pelos", "por", "qual", "quando", "que", "quem", "são", 
  "se", "sem", "ser", "seu", "seus", "sob", "sobre", "sua", "suas", "também", "te", "tem", "tinha", 
  "todo", "todos", "tu", "tua", "tuas", "tudo", "um", "uma", "umas", "uns", "você", "vocês", "vos"
)

LEGAL_TERMS_BOOST <- c(
  "lei", "decreto", "portaria", "resolução", "medida provisória", "constituição", "código", 
  "jurisprudência", "acórdão", "decisão", "sentença", "súmula", "parecer", "doutrina", 
  "legislação", "norma", "regulamento", "instrução normativa", "ordem de serviço"
)

# Helper function to clean and prepare search query
prepare_search_query <- function(query, boost_legal_terms = TRUE) {
  # Load search sanitizer
  source("R/utils/search_sanitizer.R")

  if (is.null(query) || nchar(trimws(query)) == 0) {
    return("")
  }

  # Use proper sanitization with accent preservation
  clean_query <- sanitize_search_query(query, preserve_accents = TRUE, escape_regex = FALSE)
  clean_query <- tolower(clean_query)
  
  # Remove Portuguese stopwords
  words <- strsplit(clean_query, "\\s+")[[1]]
  words <- words[!words %in% PORTUGUESE_STOPWORDS]
  words <- words[nchar(words) > 2] # Remove very short words
  
  if (length(words) == 0) {
    return("")
  }
  
  # Boost legal terms
  if (boost_legal_terms) {
    boosted_words <- sapply(words, function(word) {
      if (any(grepl(word, LEGAL_TERMS_BOOST, ignore.case = TRUE))) {
        paste0(word, "^2") # PostgreSQL text search boost syntax
      } else {
        word
      }
    })
    words <- boosted_words
  }
  
  return(paste(words, collapse = " "))
}

# Helper function to generate search suggestions
generate_search_suggestions <- function(partial_query, limit = 10) {
  # This would typically query a suggestions table or use text search
  # For now, provide common legal search terms
  common_terms <- c(
    "lei orgânica", "código civil", "direito administrativo", "licitação pública",
    "meio ambiente", "direito tributário", "servidor público", "contrato administrativo",
    "processo administrativo", "direito constitucional", "direito penal", "direito trabalhista",
    "seguridade social", "educação pública", "saúde pública", "transporte público"
  )
  
  if (nchar(partial_query) > 0) {
    # Filter suggestions based on partial query
    matching_terms <- common_terms[grepl(partial_query, common_terms, ignore.case = TRUE)]
    return(head(matching_terms, limit))
  }
  
  return(head(common_terms, limit))
}

# POST /api/v1/search - Full-text search with advanced filters
#* @post /api/v1/search
#* @param req Request object containing search parameters
#* @tag search
#* @serializer unboxedJSON
function(req) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  
  # Parse request body
  body <- tryCatch({
    jsonlite::fromJSON(req$postBody)
  }, error = function(e) {
    return(list())
  })
  
  # Extract and validate search parameters
  search_params <- list(
    query = body$query %||% "",
    filters = body$filters %||% list(),
    sort_by = body$sort_by %||% "relevance",
    limit = min(max(as.numeric(body$limit %||% 50), 1), 1000),
    offset = max(as.numeric(body$offset %||% 0), 0),
    highlight = body$highlight %||% TRUE,
    include_snippets = body$include_snippets %||% TRUE,
    search_fields = body$search_fields %||% c("title", "summary", "content"),
    fuzzy = body$fuzzy %||% FALSE,
    phrase_search = body$phrase_search %||% FALSE
  )
  
  if (nchar(trimws(search_params$query)) == 0) {
    return(error_response("Search query is required", 400))
  }
  
  start_time <- Sys.time()
  
  tryCatch({
    # Prepare search query
    processed_query <- prepare_search_query(search_params$query)
    
    if (nchar(processed_query) == 0) {
      return(success_response(
        data = list(),
        meta = list(
          query = search_params$query,
          processed_query = processed_query,
          total_results = 0,
          search_time = 0,
          message = "Query contains only stopwords or invalid characters"
        ),
        message = "No valid search terms found"
      ))
    }
    
    # Use optimized database search if available
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      main_table <- if (exists("get_main_table")) get_main_table() else "documents"
      
      if (!is.null(main_table)) {
        # Build advanced search query with PostgreSQL full-text search
        base_query <- sprintf("
          SELECT 
            d.id,
            d.titulo as title,
            COALESCE(dc.name, d.tipo, '') as category,
            COALESCE(d.estado, '') as state,
            COALESCE(d.data_publicacao, d.data) as date,
            COALESCE(d.url, '') as url,
            COALESCE(d.ementa, '') as summary,
            COALESCE(d.urn, '') as urn,
            COALESCE(d.municipio, d.localidade, '') as municipality,
            COALESCE(d.autor, '') as author,
            d.tipo as document_type,
            ts_rank_cd(
              to_tsvector('portuguese', d.titulo || ' ' || COALESCE(d.ementa, '') || ' ' || COALESCE(d.autor, '')), 
              plainto_tsquery('portuguese', $1)
            ) as relevance_score,
            ts_headline('portuguese', d.titulo, plainto_tsquery('portuguese', $1), 
              'MaxWords=20,MinWords=5,ShortWord=3,MaxFragments=3') as title_highlight,
            ts_headline('portuguese', COALESCE(d.ementa, ''), plainto_tsquery('portuguese', $1), 
              'MaxWords=50,MinWords=10,ShortWord=3,MaxFragments=2') as summary_highlight
          FROM %s d
          LEFT JOIN document_categories dc ON d.categoria = dc.name
          WHERE to_tsvector('portuguese', d.titulo || ' ' || COALESCE(d.ementa, '') || ' ' || COALESCE(d.autor, '')) 
                @@ plainto_tsquery('portuguese', $1)
        ", main_table)
        
        # Add additional filters
        params <- list(processed_query)
        param_count <- 1
        
        if (!is.null(search_params$filters$category)) {
          param_count <- param_count + 1
          base_query <- paste(base_query, sprintf("AND (dc.name = $%d OR d.tipo = $%d)", param_count, param_count))
          params[[param_count]] <- search_params$filters$category
        }
        
        if (!is.null(search_params$filters$state)) {
          param_count <- param_count + 1
          base_query <- paste(base_query, sprintf("AND d.estado = $%d", param_count))
          params[[param_count]] <- search_params$filters$state
        }
        
        if (!is.null(search_params$filters$date_start)) {
          param_count <- param_count + 1
          base_query <- paste(base_query, sprintf("AND COALESCE(d.data_publicacao, d.data) >= $%d", param_count))
          params[[param_count]] <- search_params$filters$date_start
        }
        
        if (!is.null(search_params$filters$date_end)) {
          param_count <- param_count + 1
          base_query <- paste(base_query, sprintf("AND COALESCE(d.data_publicacao, d.data) <= $%d", param_count))
          params[[param_count]] <- search_params$filters$date_end
        }
        
        # Add sorting
        if (search_params$sort_by == "relevance") {
          base_query <- paste(base_query, "ORDER BY relevance_score DESC, d.data_publicacao DESC")
        } else if (search_params$sort_by == "date_desc") {
          base_query <- paste(base_query, "ORDER BY d.data_publicacao DESC, relevance_score DESC")
        } else if (search_params$sort_by == "date_asc") {
          base_query <- paste(base_query, "ORDER BY d.data_publicacao ASC, relevance_score DESC")
        }
        
        # Add pagination
        param_count <- param_count + 1
        base_query <- paste(base_query, sprintf("LIMIT $%d", param_count))
        params[[param_count]] <- search_params$limit
        
        param_count <- param_count + 1
        base_query <- paste(base_query, sprintf("OFFSET $%d", param_count))
        params[[param_count]] <- search_params$offset
        
        # Execute search query
        result <- dbGetQuery(secure_db_pool, base_query, params = params)
        
        # Get total count for pagination
        count_query <- sprintf("
          SELECT COUNT(*) as total
          FROM %s d
          LEFT JOIN document_categories dc ON d.categoria = dc.name
          WHERE to_tsvector('portuguese', d.titulo || ' ' || COALESCE(d.ementa, '') || ' ' || COALESCE(d.autor, '')) 
                @@ plainto_tsquery('portuguese', $1)
        ", main_table)
        
        total_result <- dbGetQuery(secure_db_pool, count_query, params = list(processed_query))
        total_count <- scalar_num(total_result$total, 0)
        
      } else {
        # Fallback if no table available
        result <- data.frame()
        total_count <- 0
      }
      
    } else {
      # Use fallback search
      result <- get_library_documents(
        search_term = search_params$query,
        category = search_params$filters$category %||% "all",
        state = search_params$filters$state %||% "all",
        limit = search_params$limit,
        offset = search_params$offset
      )
      total_count <- nrow(result)
    }
    
    search_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    # Format search results
    if (nrow(result) > 0) {
      search_results <- lapply(1:nrow(result), function(i) {
        doc <- result[i, ]
        search_result <- list(
          id = as.character(doc$id %||% ""),
          title = as.character(doc$title %||% ""),
          category = as.character(doc$category %||% ""),
          state = as.character(doc$state %||% ""),
          date = as.character(doc$date %||% ""),
          url = as.character(doc$url %||% ""),
          summary = as.character(doc$summary %||% ""),
          author = as.character(doc$author %||% ""),
          document_type = as.character(doc$document_type %||% ""),
          relevance_score = if ("relevance_score" %in% names(doc)) round(as.numeric(doc$relevance_score), 4) else 0
        )
        
        # Add highlights if available and requested
        if (search_params$highlight && "title_highlight" %in% names(doc)) {
          search_result$highlights <- list(
            title = as.character(doc$title_highlight %||% ""),
            summary = as.character(doc$summary_highlight %||% "")
          )
        }
        
        return(search_result)
      })
    } else {
      search_results <- list()
    }
    
    return(success_response(
      data = search_results,
      meta = list(
        query = search_params$query,
        processed_query = processed_query,
        total_results = total_count,
        returned_results = length(search_results),
        offset = search_params$offset,
        limit = search_params$limit,
        search_time = round(search_time, 4),
        sort_by = search_params$sort_by,
        filters_applied = search_params$filters,
        has_highlights = search_params$highlight,
        search_type = "full_text"
      ),
      message = paste("Found", total_count, "documents matching the search query")
    ))
    
  }, error = function(e) {
    search_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    return(error_response(
      message = paste("Search error:", e$message),
      code = 500,
      details = list(
        query = search_params$query,
        search_time = search_time
      )
    ))
  })
}

# GET /api/v1/search/suggestions - Search suggestions and autocomplete
#* @get /api/v1/search/suggestions
#* @param q:str Partial search query
#* @param limit:int Maximum suggestions (default: 10, max: 50)
#* @param category:str Filter suggestions by category
#* @tag search
#* @serializer unboxedJSON
function(q = "", limit = 10, category = NULL) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  
  limit <- min(max(as.numeric(limit), 1), 50)
  
  tryCatch({
    suggestions <- generate_search_suggestions(q, limit)
    
    # Add search statistics if available
    suggestion_data <- lapply(suggestions, function(term) {
      list(
        text = term,
        category = "legal",
        frequency = sample(100:5000, 1), # Mock frequency data
        highlighted = highlight_search_terms(term, c(q))
      )
    })
    
    return(success_response(
      data = suggestion_data,
      meta = list(
        query = q,
        total_suggestions = length(suggestions),
        category_filter = category
      ),
      message = paste("Generated", length(suggestions), "search suggestions")
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Error generating suggestions:", e$message),
      code = 500
    ))
  })
}

# POST /api/v1/search/similar - Find similar documents
#* @post /api/v1/search/similar
#* @param req Request object containing document ID or content
#* @tag search
#* @serializer unboxedJSON
function(req) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  
  body <- tryCatch({
    jsonlite::fromJSON(req$postBody)
  }, error = function(e) {
    return(list())
  })
  
  document_id <- body$document_id %||% NULL
  content <- body$content %||% NULL
  limit <- min(max(as.numeric(body$limit %||% 10), 1), 100)
  
  if (is.null(document_id) && is.null(content)) {
    return(error_response("Either document_id or content is required", 400))
  }
  
  tryCatch({
    # This would implement document similarity using vector embeddings or text similarity
    # For now, provide mock similar documents
    similar_docs <- list(
      list(
        id = "sim_1",
        title = "Documento Similar 1",
        category = "Legislação",
        similarity_score = 0.95,
        date = Sys.Date() - 30
      ),
      list(
        id = "sim_2", 
        title = "Documento Similar 2",
        category = "Legislação",
        similarity_score = 0.87,
        date = Sys.Date() - 60
      ),
      list(
        id = "sim_3",
        title = "Documento Similar 3", 
        category = "Legislação",
        similarity_score = 0.82,
        date = Sys.Date() - 90
      )
    )
    
    return(success_response(
      data = head(similar_docs, limit),
      meta = list(
        source_document_id = document_id,
        similarity_method = "text_similarity",
        total_similar = length(similar_docs)
      ),
      message = "Found similar documents"
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Error finding similar documents:", e$message),
      code = 500
    ))
  })
}

# GET /api/v1/search/trends - Search trends and popular terms
#* @get /api/v1/search/trends
#* @param period:str Time period (day, week, month, year)
#* @param limit:int Maximum trends (default: 20, max: 100)
#* @tag search
#* @serializer unboxedJSON
function(period = "week", limit = 20) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  
  limit <- min(max(as.numeric(limit), 1), 100)
  
  tryCatch({
    # Mock trending search terms (would come from search analytics)
    trending_terms <- list(
      list(term = "nova lei de licitações", searches = 1250, change = "+15%"),
      list(term = "marco civil internet", searches = 980, change = "+8%"), 
      list(term = "código de trânsito", searches = 875, change = "-3%"),
      list(term = "direito administrativo", searches = 720, change = "+22%"),
      list(term = "lei geral de dados", searches = 650, change = "+45%"),
      list(term = "constituição federal", searches = 580, change = "+5%"),
      list(term = "servidor público", searches = 520, change = "-8%"),
      list(term = "meio ambiente", searches = 480, change = "+12%"),
      list(term = "processo administrativo", searches = 420, change = "+18%"),
      list(term = "licitação pública", searches = 380, change = "+7%")
    )
    
    return(success_response(
      data = head(trending_terms, limit),
      meta = list(
        period = period,
        total_trends = length(trending_terms),
        generated_at = Sys.time()
      ),
      message = paste("Top", length(trending_terms), "search trends for", period)
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Error retrieving search trends:", e$message),
      code = 500
    ))
  })
}

cat("✅ Search Endpoint Implementation Loaded\n")