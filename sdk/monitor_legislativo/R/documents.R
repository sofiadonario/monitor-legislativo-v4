#' @title Funções de Documentos do Monitor Legislativo
#' @description Funções para acessar, filtrar e manipular documentos legislativos
#' @author Monitor Legislativo Research Team
#' @importFrom dplyr tibble bind_rows filter arrange select mutate case_when
#' @importFrom purrr map_dfr map_chr map_lgl safely
#' @importFrom stringr str_trim str_detect str_extract str_replace_all
#' @importFrom lubridate ymd parse_date_time
#' @importFrom cli cli_alert_info cli_progress_bar cli_progress_update cli_progress_done
#' @importFrom glue glue

#' Obter documento específico por ID
#'
#' @description
#' Recupera um documento legislativo específico pelo seu ID único,
#' incluindo metadados completos e conteúdo quando disponível.
#'
#' @param document_id String. ID único do documento.
#' @param include_content Logical. Incluir conteúdo completo do documento.
#' @param include_metadata Logical. Incluir metadados estendidos.
#' @param format String. Formato de retorno ("tibble", "list", "text").
#' 
#' @return tibble, list ou string dependendo do formato especificado.
#' 
#' @examples
#' \dontrun{
#' # Obter documento básico
#' doc <- ml_get_document("doc_123")
#' 
#' # Obter documento com conteúdo completo
#' doc <- ml_get_document("doc_123", include_content = TRUE)
#' 
#' # Obter como lista para processamento
#' doc <- ml_get_document("doc_123", format = "list")
#' 
#' # Obter apenas o texto
#' text <- ml_get_document("doc_123", format = "text")
#' }
#' 
#' @export
ml_get_document <- function(document_id,
                           include_content = FALSE,
                           include_metadata = TRUE,
                           format = "tibble") {
  
  if (is.null(document_id) || nchar(trimws(document_id)) == 0) {
    stop("document_id é obrigatório")
  }
  
  if (!format %in% c("tibble", "list", "text")) {
    stop("format deve ser um de: 'tibble', 'list', 'text'")
  }
  
  # Construir parâmetros
  params <- list(
    include_content = include_content,
    include_metadata = include_metadata
  )
  
  # Construir URL
  query_string <- paste(
    names(params),
    vapply(params, function(x) URLencode(as.character(x)), character(1)),
    sep = "=",
    collapse = "&"
  )
  
  endpoint <- glue("/documents/{document_id}?{query_string}")
  
  tryCatch({
    result <- .ml_api_call("GET", endpoint)
    
    if (is.null(result) || !result$success) {
      stop("Documento não encontrado ou erro na API: ", result$message %||% "Erro desconhecido")
    }
    
    doc_data <- result$data
    
    if (is.null(doc_data)) {
      stop("Documento não encontrado")
    }
    
    # Retornar formato específico
    if (format == "text") {
      return(as.character(doc_data$content %||% doc_data$summary %||% ""))
    }
    
    if (format == "list") {
      return(doc_data)
    }
    
    # Formato tibble (padrão)
    doc_tibble <- tibble(
      id = as.character(doc_data$id %||% document_id),
      title = as.character(doc_data$title %||% ""),
      category = as.character(doc_data$category %||% ""),
      document_type = as.character(doc_data$document_type %||% ""),
      state = as.character(doc_data$state %||% ""),
      municipality = as.character(doc_data$municipality %||% ""),
      date = as.character(doc_data$date %||% ""),
      publication_date = as.character(doc_data$publication_date %||% ""),
      author = as.character(doc_data$author %||% ""),
      summary = as.character(doc_data$summary %||% ""),
      url = as.character(doc_data$url %||% ""),
      urn = as.character(doc_data$urn %||% ""),
      source = as.character(doc_data$source %||% ""),
      language = as.character(doc_data$language %||% "pt"),
      content = if (include_content) as.character(doc_data$content %||% "") else NA_character_,
      word_count = as.integer(doc_data$word_count %||% 0),
      page_count = as.integer(doc_data$page_count %||% 0),
      file_size = as.integer(doc_data$file_size %||% 0),
      last_updated = as.character(doc_data$last_updated %||% ""),
      access_count = as.integer(doc_data$access_count %||% 0)
    )
    
    # Adicionar metadados como atributos
    if (include_metadata && !is.null(doc_data$metadata)) {
      attr(doc_tibble, "metadata") <- doc_data$metadata
    }
    
    attr(doc_tibble, "retrieved_at") <- Sys.time()
    attr(doc_tibble, "includes_content") <- include_content
    
    return(doc_tibble)
    
  }, error = function(e) {
    stop("Erro ao obter documento: ", e$message)
  })
}

#' Obter múltiplos documentos por IDs
#'
#' @description
#' Recupera múltiplos documentos legislativos de uma vez,
#' otimizado para operações em lote.
#'
#' @param document_ids Vector. IDs dos documentos a serem recuperados.
#' @param include_content Logical. Incluir conteúdo completo dos documentos.
#' @param batch_size Integer. Tamanho do lote para requisições (padrão: 50).
#' @param progress Logical. Exibir barra de progresso.
#' @param on_error String. Ação em caso de erro: "skip", "stop", "warn".
#' 
#' @return tibble com todos os documentos encontrados.
#' 
#' @examples
#' \dontrun{
#' # Obter múltiplos documentos
#' docs <- ml_get_documents(c("doc_1", "doc_2", "doc_3"))
#' 
#' # Obter com conteúdo e progresso
#' docs <- ml_get_documents(
#'   document_ids = my_doc_ids,
#'   include_content = TRUE,
#'   progress = TRUE
#' )
#' 
#' # Obter com tratamento de erro personalizado
#' docs <- ml_get_documents(
#'   document_ids = my_doc_ids,
#'   on_error = "warn",
#'   batch_size = 25
#' )
#' }
#' 
#' @export
ml_get_documents <- function(document_ids,
                            include_content = FALSE,
                            batch_size = 50,
                            progress = TRUE,
                            on_error = "skip") {
  
  if (length(document_ids) == 0) {
    return(tibble(
      id = character(0),
      title = character(0),
      category = character(0),
      date = character(0)
    ))
  }
  
  if (!on_error %in% c("skip", "stop", "warn")) {
    stop("on_error deve ser um de: 'skip', 'stop', 'warn'")
  }
  
  # Remover IDs duplicados e vazios
  document_ids <- unique(document_ids[nchar(trimws(document_ids)) > 0])
  
  if (length(document_ids) == 0) {
    stop("Nenhum ID de documento válido fornecido")
  }
  
  batch_size <- max(1, min(as.integer(batch_size), 100))
  
  # Criar lotes
  batches <- split(document_ids, ceiling(seq_along(document_ids) / batch_size))
  
  if (progress && length(batches) > 1) {
    cli_alert_info(glue("Recuperando {length(document_ids)} documentos em {length(batches)} lotes"))
    pb <- cli_progress_bar(
      total = length(document_ids),
      format = "Processando documentos {cli::pb_current}/{cli::pb_total} [{cli::pb_percent}] ETA: {cli::pb_eta}"
    )
  }
  
  # Função segura para obter documento
  safe_get_doc <- safely(function(id) {
    ml_get_document(id, include_content = include_content, format = "tibble")
  })
  
  all_documents <- list()
  
  for (i in seq_along(batches)) {
    batch_ids <- batches[[i]]
    
    # Preparar requisição em lote
    request_body <- list(
      document_ids = batch_ids,
      include_content = include_content,
      include_metadata = TRUE
    )
    
    tryCatch({
      # Tentar requisição em lote primeiro
      result <- .ml_api_call("POST", "/documents/batch", body = request_body)
      
      if (!is.null(result) && result$success && !is.null(result$data)) {
        # Processar resposta em lote
        batch_docs <- map_dfr(result$data, function(doc_data) {
          tibble(
            id = as.character(doc_data$id %||% ""),
            title = as.character(doc_data$title %||% ""),
            category = as.character(doc_data$category %||% ""),
            document_type = as.character(doc_data$document_type %||% ""),
            state = as.character(doc_data$state %||% ""),
            municipality = as.character(doc_data$municipality %||% ""),
            date = as.character(doc_data$date %||% ""),
            author = as.character(doc_data$author %||% ""),
            summary = as.character(doc_data$summary %||% ""),
            url = as.character(doc_data$url %||% ""),
            content = if (include_content) as.character(doc_data$content %||% "") else NA_character_
          )
        })
        
        all_documents[[i]] <- batch_docs
        
      } else {
        # Fallback para requisições individuais
        batch_results <- map(batch_ids, safe_get_doc)
        
        # Processar resultados individuais
        batch_docs <- map_dfr(batch_results, function(res) {
          if (is.null(res$error)) {
            return(res$result)
          } else {
            if (on_error == "stop") {
              stop("Erro ao obter documento: ", res$error$message)
            } else if (on_error == "warn") {
              warning("Erro ao obter documento: ", res$error$message)
            }
            return(NULL)
          }
        })
        
        all_documents[[i]] <- batch_docs
      }
      
    }, error = function(e) {
      if (on_error == "stop") {
        stop("Erro no lote ", i, ": ", e$message)
      } else if (on_error == "warn") {
        warning("Erro no lote ", i, ": ", e$message)
      }
      all_documents[[i]] <- tibble()
    })
    
    # Atualizar progresso
    if (progress && length(batches) > 1) {
      cli_progress_update(set = min(i * batch_size, length(document_ids)))
    }
  }
  
  if (progress && length(batches) > 1) {
    cli_progress_done()
  }
  
  # Combinar todos os documentos
  if (length(all_documents) > 0) {
    final_docs <- bind_rows(all_documents)
    
    # Adicionar metadados
    attr(final_docs, "batch_info") <- list(
      total_requested = length(document_ids),
      total_retrieved = nrow(final_docs),
      batch_size = batch_size,
      include_content = include_content,
      retrieved_at = Sys.time()
    )
    
    return(final_docs)
  } else {
    return(tibble(
      id = character(0),
      title = character(0),
      category = character(0),
      date = character(0)
    ))
  }
}

#' Filtrar documentos por critérios avançados
#'
#' @description
#' Aplica filtros avançados a um conjunto de documentos,
#' útil para refinar resultados de busca ou análise exploratória.
#'
#' @param documents tibble. Documentos para filtrar (resultado de ml_search ou ml_get_documents).
#' @param category Vector. Categorias a incluir.
#' @param state Vector. Estados a incluir (siglas).
#' @param date_range Vector. Intervalo de datas (c(início, fim)).
#' @param min_relevance Numeric. Score mínimo de relevância.
#' @param text_filter String. Filtro adicional de texto (regex).
#' @param author_filter String. Filtro por autor.
#' @param has_content Logical. Filtrar apenas documentos com conteúdo.
#' @param sort_by String. Critério de ordenação.
#' 
#' @return tibble com documentos filtrados.
#' 
#' @examples
#' \dontrun{
#' # Buscar documentos e filtrar
#' docs <- ml_search("transporte público")
#' 
#' # Filtrar por estado e data
#' filtered <- ml_filter_documents(
#'   documents = docs,
#'   state = c("SP", "RJ"),
#'   date_range = c("2020-01-01", "2023-12-31")
#' )
#' 
#' # Filtrar por relevância e categoria
#' filtered <- ml_filter_documents(
#'   documents = docs,
#'   category = c("Lei", "Decreto"),
#'   min_relevance = 0.7,
#'   sort_by = "date_desc"
#' )
#' 
#' # Filtro de texto avançado
#' filtered <- ml_filter_documents(
#'   documents = docs,
#'   text_filter = "sustentável|sustentabilidade",
#'   has_content = TRUE
#' )
#' }
#' 
#' @export
ml_filter_documents <- function(documents,
                               category = NULL,
                               state = NULL,
                               date_range = NULL,
                               min_relevance = NULL,
                               text_filter = NULL,
                               author_filter = NULL,
                               has_content = NULL,
                               sort_by = NULL) {
  
  if (!is.data.frame(documents) || nrow(documents) == 0) {
    return(documents)
  }
  
  filtered <- documents
  
  # Filtro por categoria
  if (!is.null(category)) {
    if ("category" %in% names(filtered)) {
      filtered <- filtered %>%
        filter(category %in% !!category)
    } else {
      warning("Coluna 'category' não encontrada")
    }
  }
  
  # Filtro por estado
  if (!is.null(state)) {
    if ("state" %in% names(filtered)) {
      # Normalizar siglas para maiúsculo
      state <- toupper(state)
      filtered <- filtered %>%
        filter(toupper(state) %in% !!state)
    } else {
      warning("Coluna 'state' não encontrada")
    }
  }
  
  # Filtro por intervalo de datas
  if (!is.null(date_range) && length(date_range) == 2) {
    if ("date" %in% names(filtered)) {
      tryCatch({
        # Tentar converter datas
        start_date <- ymd(date_range[1])
        end_date <- ymd(date_range[2])
        
        filtered <- filtered %>%
          mutate(
            date_parsed = ymd(date)
          ) %>%
          filter(
            !is.na(date_parsed),
            date_parsed >= !!start_date,
            date_parsed <= !!end_date
          ) %>%
          select(-date_parsed)
        
      }, error = function(e) {
        warning("Erro ao filtrar por data: ", e$message)
      })
    } else {
      warning("Coluna 'date' não encontrada")
    }
  }
  
  # Filtro por relevância mínima
  if (!is.null(min_relevance)) {
    if ("relevance_score" %in% names(filtered)) {
      filtered <- filtered %>%
        filter(relevance_score >= !!min_relevance)
    } else {
      warning("Coluna 'relevance_score' não encontrada")
    }
  }
  
  # Filtro de texto (regex)
  if (!is.null(text_filter)) {
    text_columns <- intersect(names(filtered), c("title", "summary", "content"))
    
    if (length(text_columns) > 0) {
      # Criar condição de filtro para qualquer coluna de texto
      filter_condition <- FALSE
      
      for (col in text_columns) {
        filter_condition <- filter_condition | str_detect(!!sym(col), regex(text_filter, ignore_case = TRUE))
      }
      
      filtered <- filtered %>%
        filter(!!filter_condition)
    } else {
      warning("Nenhuma coluna de texto encontrada para filtrar")
    }
  }
  
  # Filtro por autor
  if (!is.null(author_filter)) {
    if ("author" %in% names(filtered)) {
      filtered <- filtered %>%
        filter(str_detect(author, regex(author_filter, ignore_case = TRUE)))
    } else {
      warning("Coluna 'author' não encontrada")
    }
  }
  
  # Filtro por presença de conteúdo
  if (!is.null(has_content)) {
    if ("content" %in% names(filtered)) {
      if (has_content) {
        filtered <- filtered %>%
          filter(!is.na(content), nchar(content) > 0)
      } else {
        filtered <- filtered %>%
          filter(is.na(content) | nchar(content) == 0)
      }
    } else {
      warning("Coluna 'content' não encontrada")
    }
  }
  
  # Ordenação
  if (!is.null(sort_by)) {
    if (sort_by == "relevance" && "relevance_score" %in% names(filtered)) {
      filtered <- filtered %>% arrange(desc(relevance_score))
    } else if (sort_by == "date_desc" && "date" %in% names(filtered)) {
      filtered <- filtered %>% arrange(desc(date))
    } else if (sort_by == "date_asc" && "date" %in% names(filtered)) {
      filtered <- filtered %>% arrange(date)
    } else if (sort_by == "title" && "title" %in% names(filtered)) {
      filtered <- filtered %>% arrange(title)
    } else if (sort_by == "category" && "category" %in% names(filtered)) {
      filtered <- filtered %>% arrange(category, title)
    } else {
      warning("Critério de ordenação '", sort_by, "' não disponível ou coluna não encontrada")
    }
  }
  
  # Adicionar informações de filtro aos atributos
  filter_info <- list(
    original_count = nrow(documents),
    filtered_count = nrow(filtered),
    filters_applied = list(
      category = category,
      state = state,
      date_range = date_range,
      min_relevance = min_relevance,
      text_filter = text_filter,
      author_filter = author_filter,
      has_content = has_content,
      sort_by = sort_by
    ),
    filtered_at = Sys.time()
  )
  
  attr(filtered, "filter_info") <- filter_info
  
  return(filtered)
}

#' Obter metadados de documentos
#'
#' @description
#' Recupera metadados estendidos de documentos sem carregar o conteúdo completo,
#' útil para análises estatísticas e catalogação.
#'
#' @param document_ids Vector. IDs dos documentos.
#' @param fields Vector. Campos específicos a recuperar.
#' @param include_stats Logical. Incluir estatísticas de acesso e uso.
#' 
#' @return tibble com metadados dos documentos.
#' 
#' @examples
#' \dontrun{
#' # Obter metadados básicos
#' metadata <- ml_get_document_metadata(c("doc_1", "doc_2"))
#' 
#' # Obter campos específicos
#' metadata <- ml_get_document_metadata(
#'   document_ids = my_ids,
#'   fields = c("title", "date", "category", "word_count")
#' )
#' 
#' # Incluir estatísticas de uso
#' metadata <- ml_get_document_metadata(
#'   document_ids = my_ids,
#'   include_stats = TRUE
#' )
#' }
#' 
#' @export
ml_get_document_metadata <- function(document_ids,
                                    fields = NULL,
                                    include_stats = FALSE) {
  
  if (length(document_ids) == 0) {
    return(tibble())
  }
  
  # Campos padrão
  default_fields <- c("id", "title", "category", "date", "state", "municipality", 
                     "author", "document_type", "word_count", "page_count")
  
  if (is.null(fields)) {
    fields <- default_fields
  }
  
  # Preparar requisição
  request_body <- list(
    document_ids = document_ids,
    fields = fields,
    include_stats = include_stats,
    metadata_only = TRUE
  )
  
  tryCatch({
    result <- .ml_api_call("POST", "/documents/metadata", body = request_body)
    
    if (is.null(result) || !result$success) {
      stop("Erro ao obter metadados: ", result$message %||% "Erro desconhecido")
    }
    
    metadata_list <- result$data %||% list()
    
    if (length(metadata_list) == 0) {
      return(tibble())
    }
    
    # Converter para tibble
    metadata_df <- map_dfr(metadata_list, function(meta) {
      # Criar linha com campos solicitados
      row_data <- list()
      
      for (field in fields) {
        row_data[[field]] <- meta[[field]] %||% NA
      }
      
      # Adicionar estatísticas se solicitadas
      if (include_stats && !is.null(meta$stats)) {
        row_data$access_count <- meta$stats$access_count %||% 0
        row_data$download_count <- meta$stats$download_count %||% 0
        row_data$citation_count <- meta$stats$citation_count %||% 0
        row_data$last_accessed <- meta$stats$last_accessed %||% ""
      }
      
      return(as_tibble(row_data))
    })
    
    # Adicionar metadados
    attr(metadata_df, "fields_requested") <- fields
    attr(metadata_df, "include_stats") <- include_stats
    attr(metadata_df, "retrieved_at") <- Sys.time()
    
    return(metadata_df)
    
  }, error = function(e) {
    stop("Erro ao obter metadados: ", e$message)
  })
}

#' Validar existência de documentos
#'
#' @description
#' Verifica rapidamente quais documentos existem na base de dados
#' sem carregar dados desnecessários.
#'
#' @param document_ids Vector. IDs dos documentos a verificar.
#' @param return_missing Logical. Retornar também IDs não encontrados.
#' 
#' @return list com IDs existentes e opcionalmente IDs faltantes.
#' 
#' @examples
#' \dontrun{
#' # Verificar existência
#' validation <- ml_validate_documents(c("doc_1", "doc_2", "doc_3"))
#' print(validation$existing)
#' 
#' # Incluir IDs faltantes
#' validation <- ml_validate_documents(my_ids, return_missing = TRUE)
#' print(validation$missing)
#' }
#' 
#' @export
ml_validate_documents <- function(document_ids, return_missing = FALSE) {
  
  if (length(document_ids) == 0) {
    return(list(existing = character(0), missing = character(0)))
  }
  
  # Remover duplicados
  document_ids <- unique(document_ids)
  
  request_body <- list(
    document_ids = document_ids,
    validate_only = TRUE
  )
  
  tryCatch({
    result <- .ml_api_call("POST", "/documents/validate", body = request_body)
    
    if (is.null(result) || !result$success) {
      stop("Erro na validação: ", result$message %||% "Erro desconhecido")
    }
    
    existing_ids <- result$data$existing %||% character(0)
    
    validation_result <- list(
      existing = existing_ids,
      total_checked = length(document_ids),
      found_count = length(existing_ids)
    )
    
    if (return_missing) {
      missing_ids <- setdiff(document_ids, existing_ids)
      validation_result$missing <- missing_ids
      validation_result$missing_count <- length(missing_ids)
    }
    
    return(validation_result)
    
  }, error = function(e) {
    # Fallback: tentar obter metadados mínimos
    safe_metadata <- safely(function(ids) {
      ml_get_document_metadata(ids, fields = "id")
    })
    
    meta_result <- safe_metadata(document_ids)
    
    if (is.null(meta_result$error)) {
      existing_ids <- meta_result$result$id
      validation_result <- list(
        existing = existing_ids,
        total_checked = length(document_ids),
        found_count = length(existing_ids)
      )
      
      if (return_missing) {
        missing_ids <- setdiff(document_ids, existing_ids)
        validation_result$missing <- missing_ids
        validation_result$missing_count <- length(missing_ids)
      }
      
      return(validation_result)
    } else {
      stop("Erro na validação: ", e$message)
    }
  })
}