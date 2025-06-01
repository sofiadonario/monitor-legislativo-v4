#' @title Funções de Busca no Monitor Legislativo
#' @description Funções para realizar buscas avançadas na base de documentos legislativos
#' @author Monitor Legislativo Research Team
#' @importFrom dplyr tibble bind_rows filter arrange select mutate
#' @importFrom purrr map_dfr map_chr safely
#' @importFrom stringr str_trim str_to_lower
#' @importFrom cli cli_alert_info cli_progress_bar cli_progress_update cli_progress_done
#' @importFrom glue glue

#' Busca geral de documentos legislativos
#'
#' @description
#' Realiza busca de texto completo na base de dados do Monitor Legislativo com
#' suporte a filtros avançados e processamento de linguagem natural em português.
#'
#' @param query String. Termo de busca (obrigatório).
#' @param filters List. Filtros adicionais (categoria, estado, data, etc.).
#' @param sort_by String. Critério de ordenação: "relevance", "date_desc", "date_asc".
#' @param limit Integer. Número máximo de resultados (padrão: 50, máximo: 1000).
#' @param offset Integer. Número de resultados para pular (paginação).
#' @param highlight Logical. Incluir destaques nos resultados.
#' @param fuzzy Logical. Habilitar busca difusa (tolerância a erros de digitação).
#' @param as_tibble Logical. Retornar como tibble (padrão: TRUE).
#' @param verbose Logical. Exibir informações de progresso.
#' 
#' @return tibble ou list com resultados da busca e metadados.
#' 
#' @examples
#' \dontrun{
#' # Busca simples
#' results <- ml_search("lei de licitações")
#' 
#' # Busca com filtros
#' results <- ml_search(
#'   query = "transporte público",
#'   filters = list(
#'     category = "Lei",
#'     state = "SP",
#'     date_start = "2020-01-01",
#'     date_end = "2023-12-31"
#'   ),
#'   sort_by = "date_desc",
#'   limit = 100
#' )
#' 
#' # Busca fuzzy para termos com possíveis erros
#' results <- ml_search("codigo sivil", fuzzy = TRUE)
#' }
#' 
#' @export
ml_search <- function(query,
                      filters = list(),
                      sort_by = "relevance",
                      limit = 50,
                      offset = 0,
                      highlight = TRUE,
                      fuzzy = FALSE,
                      as_tibble = TRUE,
                      verbose = FALSE) {
  
  # Validar parâmetros
  if (is.null(query) || nchar(trimws(query)) == 0) {
    stop("Parâmetro 'query' é obrigatório e não pode estar vazio")
  }
  
  if (!sort_by %in% c("relevance", "date_desc", "date_asc")) {
    stop("sort_by deve ser um de: 'relevance', 'date_desc', 'date_asc'")
  }
  
  limit <- max(1, min(as.integer(limit), 1000))
  offset <- max(0, as.integer(offset))
  
  if (verbose) {
    cli_alert_info(glue("Buscando por: '{query}'"))
    if (length(filters) > 0) {
      cli_alert_info(glue("Aplicando {length(filters)} filtro(s)"))
    }
  }
  
  # Preparar body da requisição
  request_body <- list(
    query = trimws(query),
    filters = filters,
    sort_by = sort_by,
    limit = limit,
    offset = offset,
    highlight = highlight,
    include_snippets = TRUE,
    search_fields = c("title", "summary", "content"),
    fuzzy = fuzzy,
    phrase_search = FALSE
  )
  
  # Fazer chamada à API
  tryCatch({
    result <- .ml_api_call("POST", "/search", body = request_body)
    
    if (is.null(result) || !result$success) {
      stop("Falha na busca: ", result$message %||% "Erro desconhecido")
    }
    
    # Processar resultados
    documents <- result$data %||% list()
    meta <- result$meta %||% list()
    
    if (verbose) {
      cli_alert_info(glue("Encontrados {meta$total_results %||% 0} documentos"))
      cli_alert_info(glue("Tempo de busca: {meta$search_time %||% 0} segundos"))
    }
    
    if (length(documents) == 0) {
      if (as_tibble) {
        return(tibble(
          id = character(0),
          title = character(0),
          category = character(0),
          state = character(0),
          date = character(0),
          summary = character(0)
        ))
      } else {
        return(list(data = list(), meta = meta))
      }
    }
    
    # Converter para tibble se solicitado
    if (as_tibble) {
      documents_df <- map_dfr(documents, function(doc) {
        tibble(
          id = as.character(doc$id %||% ""),
          title = as.character(doc$title %||% ""),
          category = as.character(doc$category %||% ""),
          state = as.character(doc$state %||% ""),
          municipality = as.character(doc$municipality %||% ""),
          date = as.character(doc$date %||% ""),
          summary = as.character(doc$summary %||% ""),
          author = as.character(doc$author %||% ""),
          document_type = as.character(doc$document_type %||% ""),
          url = as.character(doc$url %||% ""),
          relevance_score = as.numeric(doc$relevance_score %||% 0),
          title_highlight = if (highlight && !is.null(doc$highlights$title)) {
            as.character(doc$highlights$title)
          } else {
            as.character(doc$title %||% "")
          },
          summary_highlight = if (highlight && !is.null(doc$highlights$summary)) {
            as.character(doc$highlights$summary)
          } else {
            as.character(doc$summary %||% "")
          }
        )
      })
      
      # Adicionar metadados como atributos
      attr(documents_df, "search_meta") <- meta
      attr(documents_df, "search_query") <- query
      
      return(documents_df)
    } else {
      return(list(data = documents, meta = meta))
    }
    
  }, error = function(e) {
    stop("Erro na busca: ", e$message)
  })
}

#' Busca de documentos com filtros específicos
#'
#' @description
#' Versão simplificada da busca focada especificamente em documentos legislativos
#' com filtros pré-definidos para uso acadêmico.
#'
#' @param query String. Termo de busca.
#' @param category String. Categoria do documento ("Lei", "Decreto", "Portaria", etc.).
#' @param state String. Estado (sigla de 2 letras, ex: "SP", "RJ").
#' @param municipality String. Município.
#' @param date_start String. Data inicial (formato: "YYYY-MM-DD").
#' @param date_end String. Data final (formato: "YYYY-MM-DD").
#' @param limit Integer. Número máximo de resultados.
#' @param sort_by String. Critério de ordenação.
#' 
#' @return tibble com documentos encontrados.
#' 
#' @examples
#' \dontrun{
#' # Buscar leis de São Paulo sobre transporte
#' docs <- ml_search_documents(
#'   query = "transporte público",
#'   category = "Lei",
#'   state = "SP",
#'   date_start = "2020-01-01"
#' )
#' 
#' # Buscar decretos municipais
#' docs <- ml_search_documents(
#'   query = "meio ambiente",
#'   category = "Decreto",
#'   municipality = "São Paulo"
#' )
#' }
#' 
#' @export
ml_search_documents <- function(query,
                               category = NULL,
                               state = NULL,
                               municipality = NULL,
                               date_start = NULL,
                               date_end = NULL,
                               limit = 50,
                               sort_by = "relevance") {
  
  # Construir filtros
  filters <- list()
  
  if (!is.null(category)) {
    filters$category <- category
  }
  
  if (!is.null(state)) {
    filters$state <- toupper(state)
  }
  
  if (!is.null(municipality)) {
    filters$municipality <- municipality
  }
  
  if (!is.null(date_start)) {
    filters$date_start <- date_start
  }
  
  if (!is.null(date_end)) {
    filters$date_end <- date_end
  }
  
  # Usar função principal de busca
  return(ml_search(
    query = query,
    filters = filters,
    sort_by = sort_by,
    limit = limit,
    as_tibble = TRUE
  ))
}

#' Busca avançada com múltiplos termos e operadores
#'
#' @description
#' Busca avançada que suporta operadores booleanos, frases exatas e busca
#' em campos específicos para pesquisadores que precisam de maior controle.
#'
#' @param query String. Consulta avançada com operadores.
#' @param search_fields Vector. Campos específicos para busca ("title", "summary", "content").
#' @param phrase_search Logical. Buscar frase exata.
#' @param boost_legal_terms Logical. Dar maior peso a termos jurídicos.
#' @param filters List. Filtros adicionais.
#' @param limit Integer. Número máximo de resultados.
#' @param include_snippets Logical. Incluir trechos relevantes.
#' 
#' @return tibble com resultados da busca avançada.
#' 
#' @examples
#' \dontrun{
#' # Busca com operadores booleanos
#' docs <- ml_search_advanced(
#'   query = "transporte AND (público OR coletivo)",
#'   search_fields = c("title", "summary"),
#'   phrase_search = FALSE
#' )
#' 
#' # Busca por frase exata
#' docs <- ml_search_advanced(
#'   query = "código de trânsito brasileiro",
#'   phrase_search = TRUE,
#'   boost_legal_terms = TRUE
#' )
#' 
#' # Busca apenas em títulos
#' docs <- ml_search_advanced(
#'   query = "lei complementar",
#'   search_fields = "title"
#' )
#' }
#' 
#' @export
ml_search_advanced <- function(query,
                              search_fields = c("title", "summary", "content"),
                              phrase_search = FALSE,
                              boost_legal_terms = TRUE,
                              filters = list(),
                              limit = 50,
                              include_snippets = TRUE) {
  
  # Validar campos de busca
  valid_fields <- c("title", "summary", "content", "author")
  search_fields <- intersect(search_fields, valid_fields)
  
  if (length(search_fields) == 0) {
    search_fields <- c("title", "summary", "content")
  }
  
  # Preparar body da requisição
  request_body <- list(
    query = trimws(query),
    filters = filters,
    sort_by = "relevance",
    limit = limit,
    offset = 0,
    highlight = TRUE,
    include_snippets = include_snippets,
    search_fields = search_fields,
    fuzzy = FALSE,
    phrase_search = phrase_search,
    boost_legal_terms = boost_legal_terms
  )
  
  # Fazer chamada à API
  tryCatch({
    result <- .ml_api_call("POST", "/search", body = request_body)
    
    if (is.null(result) || !result$success) {
      stop("Falha na busca avançada: ", result$message %||% "Erro desconhecido")
    }
    
    documents <- result$data %||% list()
    
    if (length(documents) == 0) {
      return(tibble(
        id = character(0),
        title = character(0),
        category = character(0),
        summary = character(0),
        snippets = character(0)
      ))
    }
    
    # Converter para tibble com snippets
    documents_df <- map_dfr(documents, function(doc) {
      snippets <- if (include_snippets && !is.null(doc$snippets)) {
        paste(doc$snippets, collapse = " ... ")
      } else {
        ""
      }
      
      tibble(
        id = as.character(doc$id %||% ""),
        title = as.character(doc$title %||% ""),
        category = as.character(doc$category %||% ""),
        state = as.character(doc$state %||% ""),
        date = as.character(doc$date %||% ""),
        summary = as.character(doc$summary %||% ""),
        relevance_score = as.numeric(doc$relevance_score %||% 0),
        snippets = snippets,
        search_fields_used = paste(search_fields, collapse = ", ")
      )
    })
    
    # Adicionar metadados
    attr(documents_df, "search_meta") <- result$meta
    attr(documents_df, "advanced_query") <- query
    attr(documents_df, "search_fields") <- search_fields
    
    return(documents_df)
    
  }, error = function(e) {
    stop("Erro na busca avançada: ", e$message)
  })
}

#' Obter sugestões de busca
#'
#' @description
#' Obtém sugestões de termos de busca baseadas em entrada parcial,
#' útil para implementar autocompletar em interfaces.
#'
#' @param partial_query String. Termo parcial para sugestões.
#' @param limit Integer. Número máximo de sugestões (padrão: 10, máximo: 50).
#' @param category String. Filtrar sugestões por categoria.
#' 
#' @return Vector com sugestões de busca.
#' 
#' @examples
#' \dontrun{
#' # Obter sugestões para termo parcial
#' suggestions <- ml_search_suggestions("lei org")
#' print(suggestions)
#' 
#' # Sugestões filtradas por categoria
#' suggestions <- ml_search_suggestions("meio", category = "Ambiental")
#' }
#' 
#' @export
ml_search_suggestions <- function(partial_query,
                                 limit = 10,
                                 category = NULL) {
  
  if (is.null(partial_query) || nchar(trimws(partial_query)) == 0) {
    return(character(0))
  }
  
  limit <- max(1, min(as.integer(limit), 50))
  
  # Construir parâmetros da query
  params <- list(
    q = trimws(partial_query),
    limit = limit
  )
  
  if (!is.null(category)) {
    params$category <- category
  }
  
  # Construir URL com parâmetros
  query_string <- paste(
    names(params),
    vapply(params, function(x) URLencode(as.character(x)), character(1)),
    sep = "=",
    collapse = "&"
  )
  
  endpoint <- paste0("/search/suggestions?", query_string)
  
  tryCatch({
    result <- .ml_api_call("GET", endpoint)
    
    if (is.null(result) || !result$success) {
      return(character(0))
    }
    
    suggestions <- result$data %||% list()
    
    if (length(suggestions) == 0) {
      return(character(0))
    }
    
    # Extrair texto das sugestões
    suggestion_texts <- map_chr(suggestions, function(s) {
      as.character(s$text %||% "")
    })
    
    return(suggestion_texts[nchar(suggestion_texts) > 0])
    
  }, error = function(e) {
    warning("Erro ao obter sugestões: ", e$message)
    return(character(0))
  })
}

#' Buscar documentos similares
#'
#' @description
#' Encontra documentos similares a um documento específico ou a um texto fornecido,
#' usando análise de similaridade semântica.
#'
#' @param document_id String. ID do documento de referência.
#' @param content String. Texto de referência (alternativo ao document_id).
#' @param limit Integer. Número máximo de documentos similares.
#' @param similarity_threshold Numeric. Limiar mínimo de similaridade (0-1).
#' 
#' @return tibble com documentos similares ordenados por similaridade.
#' 
#' @examples
#' \dontrun{
#' # Encontrar documentos similares por ID
#' similar <- ml_search_similar(document_id = "doc_123", limit = 10)
#' 
#' # Encontrar documentos similares por conteúdo
#' similar <- ml_search_similar(
#'   content = "Esta lei dispõe sobre transporte público urbano",
#'   limit = 5,
#'   similarity_threshold = 0.7
#' )
#' }
#' 
#' @export
ml_search_similar <- function(document_id = NULL,
                             content = NULL,
                             limit = 10,
                             similarity_threshold = 0.5) {
  
  if (is.null(document_id) && is.null(content)) {
    stop("Deve fornecer 'document_id' ou 'content'")
  }
  
  limit <- max(1, min(as.integer(limit), 100))
  similarity_threshold <- max(0, min(as.numeric(similarity_threshold), 1))
  
  # Preparar body da requisição
  request_body <- list(
    limit = limit,
    similarity_threshold = similarity_threshold
  )
  
  if (!is.null(document_id)) {
    request_body$document_id <- document_id
  }
  
  if (!is.null(content)) {
    request_body$content <- content
  }
  
  tryCatch({
    result <- .ml_api_call("POST", "/search/similar", body = request_body)
    
    if (is.null(result) || !result$success) {
      stop("Falha na busca de similares: ", result$message %||% "Erro desconhecido")
    }
    
    documents <- result$data %||% list()
    
    if (length(documents) == 0) {
      return(tibble(
        id = character(0),
        title = character(0),
        similarity_score = numeric(0),
        category = character(0),
        date = character(0)
      ))
    }
    
    # Converter para tibble
    similar_df <- map_dfr(documents, function(doc) {
      tibble(
        id = as.character(doc$id %||% ""),
        title = as.character(doc$title %||% ""),
        category = as.character(doc$category %||% ""),
        date = as.character(doc$date %||% ""),
        similarity_score = as.numeric(doc$similarity_score %||% 0),
        summary = as.character(doc$summary %||% "")
      )
    }) %>%
      arrange(desc(similarity_score))
    
    # Adicionar metadados
    attr(similar_df, "similarity_meta") <- result$meta
    attr(similar_df, "reference_document") <- document_id
    attr(similar_df, "reference_content") <- if (!is.null(content)) substr(content, 1, 100) else NULL
    
    return(similar_df)
    
  }, error = function(e) {
    stop("Erro na busca de similares: ", e$message)
  })
}

#' Obter tendências de busca
#'
#' @description
#' Recupera as tendências de busca mais populares em diferentes períodos,
#' útil para análise de interesse público em temas legislativos.
#'
#' @param period String. Período de análise ("day", "week", "month", "year").
#' @param limit Integer. Número máximo de tendências.
#' @param category String. Filtrar por categoria específica.
#' 
#' @return tibble com termos de busca mais populares e estatísticas.
#' 
#' @examples
#' \dontrun{
#' # Tendências da semana
#' trends <- ml_search_trends(period = "week")
#' 
#' # Tendências mensais limitadas
#' trends <- ml_search_trends(period = "month", limit = 20)
#' 
#' # Tendências por categoria
#' trends <- ml_search_trends(period = "month", category = "Lei")
#' }
#' 
#' @export
ml_search_trends <- function(period = "week",
                            limit = 20,
                            category = NULL) {
  
  if (!period %in% c("day", "week", "month", "year")) {
    stop("period deve ser um de: 'day', 'week', 'month', 'year'")
  }
  
  limit <- max(1, min(as.integer(limit), 100))
  
  # Construir parâmetros
  params <- list(
    period = period,
    limit = limit
  )
  
  if (!is.null(category)) {
    params$category <- category
  }
  
  # Construir URL
  query_string <- paste(
    names(params),
    vapply(params, function(x) URLencode(as.character(x)), character(1)),
    sep = "=",
    collapse = "&"
  )
  
  endpoint <- paste0("/search/trends?", query_string)
  
  tryCatch({
    result <- .ml_api_call("GET", endpoint)
    
    if (is.null(result) || !result$success) {
      return(tibble(
        term = character(0),
        searches = integer(0),
        change_percent = character(0)
      ))
    }
    
    trends <- result$data %||% list()
    
    if (length(trends) == 0) {
      return(tibble(
        term = character(0),
        searches = integer(0),
        change_percent = character(0)
      ))
    }
    
    # Converter para tibble
    trends_df <- map_dfr(trends, function(trend) {
      tibble(
        term = as.character(trend$term %||% ""),
        searches = as.integer(trend$searches %||% 0),
        change_percent = as.character(trend$change %||% ""),
        rank = as.integer(trend$rank %||% 0)
      )
    })
    
    # Adicionar metadados
    attr(trends_df, "trends_meta") <- result$meta
    attr(trends_df, "period") <- period
    
    return(trends_df)
    
  }, error = function(e) {
    warning("Erro ao obter tendências: ", e$message)
    return(tibble(
      term = character(0),
      searches = integer(0),
      change_percent = character(0)
    ))
  })
}