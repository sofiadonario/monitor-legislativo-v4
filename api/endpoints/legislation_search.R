# ============================================================================
# LEGISLATION SEARCH ENDPOINT - WEEK 6 REST API IMPLEMENTATION
# ============================================================================
# 
# Comprehensive REST API endpoint for Brazilian legislative document search
# Implements performance optimizations, Brazilian context validation, and
# academic research features for 134k+ document dataset
# 
# Endpoints:
# - GET /api/v1/legislation/search - Main search with filters
# - GET /api/v1/legislation/{id} - Specific document details
# - GET /api/v1/legislation/types - Available document types
# - GET /api/v1/legislation/states - Available states and statistics
# ============================================================================

cat("📋 Loading Enhanced Legislation Search Endpoints - Week 6\n")

# Brazilian legal document types with Portuguese names
DOCUMENT_TYPES <- list(
  "lei" = "Lei",
  "decreto" = "Decreto", 
  "portaria" = "Portaria",
  "resolucao" = "Resolução",
  "medida_provisoria" = "Medida Provisória",
  "instrucao_normativa" = "Instrução Normativa",
  "ordem_servico" = "Ordem de Serviço",
  "circular" = "Circular",
  "ato" = "Ato",
  "deliberacao" = "Deliberação"
)

# Brazilian states with full names
BRAZILIAN_STATES <- list(
  "AC" = "Acre", "AL" = "Alagoas", "AP" = "Amapá", "AM" = "Amazonas",
  "BA" = "Bahia", "CE" = "Ceará", "DF" = "Distrito Federal", "ES" = "Espírito Santo",
  "GO" = "Goiás", "MA" = "Maranhão", "MT" = "Mato Grosso", "MS" = "Mato Grosso do Sul",
  "MG" = "Minas Gerais", "PA" = "Pará", "PB" = "Paraíba", "PR" = "Paraná",
  "PE" = "Pernambuco", "PI" = "Piauí", "RJ" = "Rio de Janeiro", "RN" = "Rio Grande do Norte",
  "RS" = "Rio Grande do Sul", "RO" = "Rondônia", "RR" = "Roraima", "SC" = "Santa Catarina",
  "SP" = "São Paulo", "SE" = "Sergipe", "TO" = "Tocantins"
)

# Validation helper functions
validate_brazilian_parameters <- function(estado = NULL, ano = NULL, tipo = NULL) {
  errors <- character(0)
  
  # Validate state
  if (!is.null(estado)) {
    if (!(toupper(estado) %in% names(BRAZILIAN_STATES))) {
      errors <- c(errors, "Estado inválido. Use códigos UF válidos (ex: SP, RJ, MG)")
    }
  }
  
  # Validate year
  if (!is.null(ano)) {
    ano_num <- suppressWarnings(as.numeric(ano))
    if (is.na(ano_num) || ano_num < 1988 || ano_num > as.numeric(format(Sys.Date(), "%Y"))) {
      errors <- c(errors, paste("Ano deve estar entre 1988 e", format(Sys.Date(), "%Y")))
    }
  }
  
  # Validate document type
  if (!is.null(tipo)) {
    if (!(tolower(tipo) %in% names(DOCUMENT_TYPES))) {
      valid_types <- paste(names(DOCUMENT_TYPES), collapse = ", ")
      errors <- c(errors, paste("Tipo de documento inválido. Tipos válidos:", valid_types))
    }
  }
  
  return(errors)
}

# Performance-optimized search query builder
build_search_query <- function(q = NULL, estado = NULL, ano = NULL, tipo = NULL, municipio = NULL, limit = 50, offset = 0) {
  # Base query with text search optimization
  base_query <- "
    SELECT 
      id, titulo, ementa, estado, municipio, 
      species as tipo_documento, data_publicacao,
      numero, ano, orgao_expedidor,
      CASE 
        WHEN titulo ILIKE $1 THEN 3
        WHEN ementa ILIKE $1 THEN 2
        ELSE 1
      END as relevance_score
    FROM documents 
    WHERE 1=1
  "
  
  params <- list()
  param_count <- 1
  
  # Add text search if provided
  if (!is.null(q) && nchar(trimws(q)) > 0) {
    search_term <- paste0("%", trimws(q), "%")
    base_query <- paste(base_query, "AND (titulo ILIKE $", param_count, " OR ementa ILIKE $", param_count, ")", sep="")
    params[[param_count]] <- search_term
    param_count <- param_count + 1
  }
  
  # Add state filter
  if (!is.null(estado)) {
    base_query <- paste(base_query, "AND estado = $", param_count, sep="")
    params[[param_count]] <- toupper(estado)
    param_count <- param_count + 1
  }
  
  # Add year filter
  if (!is.null(ano)) {
    base_query <- paste(base_query, "AND ano = $", param_count, sep="")
    params[[param_count]] <- as.numeric(ano)
    param_count <- param_count + 1
  }
  
  # Add document type filter
  if (!is.null(tipo)) {
    base_query <- paste(base_query, "AND LOWER(species) LIKE $", param_count, sep="")
    params[[param_count]] <- paste0("%", tolower(tipo), "%")
    param_count <- param_count + 1
  }
  
  # Add municipality filter
  if (!is.null(municipio)) {
    base_query <- paste(base_query, "AND municipio ILIKE $", param_count, sep="")
    params[[param_count]] <- paste0("%", municipio, "%")
    param_count <- param_count + 1
  }
  
  # Add ordering and pagination
  if (!is.null(q) && nchar(trimws(q)) > 0) {
    base_query <- paste(base_query, "ORDER BY relevance_score DESC, data_publicacao DESC")
  } else {
    base_query <- paste(base_query, "ORDER BY data_publicacao DESC")
  }
  
  base_query <- paste(base_query, "LIMIT $", param_count, "OFFSET $", param_count + 1, sep="")
  params[[param_count]] <- limit
  params[[param_count + 1]] <- offset
  
  return(list(query = base_query, params = params))
}

# Format response for different content types
format_response <- function(data, format = "json", fields = NULL) {
  # Apply field selection if specified
  if (!is.null(fields) && nchar(trimws(fields)) > 0) {
    selected_fields <- trimws(strsplit(fields, ",")[[1]])
    available_fields <- names(data)
    valid_fields <- selected_fields[selected_fields %in% available_fields]
    
    if (length(valid_fields) > 0) {
      data <- data[, valid_fields, drop = FALSE]
    }
  }
  
  if (format == "xml") {
    # Convert to XML format (simplified implementation)
    xml_data <- paste0(
      '<?xml version="1.0" encoding="UTF-8"?>\n',
      '<documents>\n'
    )
    
    for (i in seq_len(nrow(data))) {
      xml_data <- paste0(xml_data, '  <document>\n')
      for (col in names(data)) {
        value <- if (is.na(data[i, col])) "" else as.character(data[i, col])
        xml_data <- paste0(xml_data, '    <', col, '>', value, '</', col, '>\n')
      }
      xml_data <- paste0(xml_data, '  </document>\n')
    }
    
    xml_data <- paste0(xml_data, '</documents>')
    return(xml_data)
  }
  
  return(data)  # Default JSON format
}

# Main legislation search endpoint
#' @get /api/v1/legislation/search
#' @param q:str Search query text for titles and summaries
#' @param estado:str Brazilian state code (SP, RJ, MG, etc.)
#' @param ano:int Publication year (1988-2024)
#' @param tipo:str Document type (lei, decreto, portaria, etc.)
#' @param municipio:str Municipality name
#' @param limit:int Maximum results (default: 50, max: 200)
#' @param offset:int Results offset for pagination (default: 0)
#' @param format:str Response format (json, xml) default: json
#' @param fields:str Comma-separated field selection
#' @tag legislation
#' @serializer unboxedJSON
function(req, res, q = NULL, estado = NULL, ano = NULL, tipo = NULL, municipio = NULL, limit = 50, offset = 0, format = "json", fields = NULL) {
  
  # Track API request
  start_time <- Sys.time()
  
  # Validate parameters
  validation_errors <- validate_brazilian_parameters(estado, ano, tipo)
  if (length(validation_errors) > 0) {
    return(list(
      error = TRUE,
      message = "Parâmetros inválidos",
      details = validation_errors,
      code = 400,
      timestamp = Sys.time()
    ))
  }
  
  # Validate limits
  limit <- min(max(as.numeric(limit), 1), 200)
  offset <- max(as.numeric(offset), 0)
  
  # Set response headers
  res$setHeader("Content-Language", "pt-BR")
  if (format == "xml") {
    res$setHeader("Content-Type", "application/xml; charset=utf-8")
  } else {
    res$setHeader("Content-Type", "application/json; charset=utf-8")
  }
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      # Build optimized query
      query_info <- build_search_query(q, estado, ano, tipo, municipio, limit, offset)
      
      # Execute query with parameters
      result <- dbGetQuery(secure_db_pool, query_info$query, query_info$params)
      
      # Get total count for pagination
      count_query <- gsub("SELECT.*?FROM", "SELECT COUNT(*) as total FROM", query_info$query)
      count_query <- gsub("ORDER BY.*", "", count_query)
      count_query <- gsub("LIMIT.*", "", count_query)
      
      total_result <- dbGetQuery(secure_db_pool, count_query, query_info$params[1:(length(query_info$params)-2)])
      total_count <- total_result$total[1]
      
      # Format response data
      formatted_data <- format_response(result, format, fields)
      
      # Calculate performance metrics
      processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
      
      if (format == "xml") {
        return(formatted_data)
      } else {
        return(list(
          error = FALSE,
          message = paste("Encontrados", nrow(result), "documentos"),
          data = formatted_data,
          meta = list(
            total = total_count,
            returned = nrow(result),
            limit = limit,
            offset = offset,
            has_more = (offset + limit) < total_count,
            next_offset = if ((offset + limit) < total_count) offset + limit else NULL,
            filters = list(
              query = q,
              estado = estado,
              ano = ano,
              tipo = tipo,
              municipio = municipio
            ),
            performance = list(
              processing_time_seconds = round(processing_time, 3),
              source = "database"
            )
          ),
          timestamp = Sys.time()
        ))
      }
      
    } else {
      # Fallback to sample data
      sample_data <- data.frame(
        id = paste0("doc_", 1:min(10, limit)),
        titulo = paste("Lei Municipal sobre Transporte", 1:min(10, limit)),
        ementa = paste("Regulamenta o transporte público municipal", 1:min(10, limit)),
        estado = rep(c("SP", "RJ", "MG", "RS", "PR"), length.out = min(10, limit)),
        municipio = rep(c("São Paulo", "Rio de Janeiro", "Belo Horizonte", "Porto Alegre", "Curitiba"), length.out = min(10, limit)),
        tipo_documento = rep("Lei", min(10, limit)),
        data_publicacao = seq(as.Date("2020-01-01"), as.Date("2024-01-01"), length.out = min(10, limit)),
        numero = paste0("LEI-", 1000 + 1:min(10, limit)),
        ano = 2024,
        orgao_expedidor = "Prefeitura Municipal",
        stringsAsFactors = FALSE
      )
      
      formatted_data <- format_response(sample_data, format, fields)
      
      if (format == "xml") {
        return(formatted_data)
      } else {
        return(list(
          error = FALSE,
          message = "Dados de exemplo - banco não disponível",
          data = formatted_data,
          meta = list(
            total = 10,
            returned = nrow(sample_data),
            limit = limit,
            offset = offset,
            source = "fallback",
            warning = "Usando dados de exemplo"
          ),
          timestamp = Sys.time()
        ))
      }
    }
    
  }, error = function(e) {
    return(list(
      error = TRUE,
      message = "Erro interno do servidor",
      details = "Erro ao processar consulta de legislação",
      code = 500,
      timestamp = Sys.time(),
      debug = if (Sys.getenv("DEBUG") == "true") e$message else NULL
    ))
  })
}

# Get specific document by ID
#' @get /api/v1/legislation/<id>
#' @param id Document ID
#' @tag legislation
#' @serializer unboxedJSON
function(req, res, id) {
  
  if (is.null(id) || nchar(trimws(id)) == 0) {
    res$status <- 400
    return(list(
      error = TRUE,
      message = "ID do documento é obrigatório",
      code = 400,
      timestamp = Sys.time()
    ))
  }
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      query <- "
        SELECT 
          id, titulo, ementa, conteudo, estado, municipio, 
          species as tipo_documento, data_publicacao, numero, ano, 
          orgao_expedidor, url_original, observacoes,
          created_at, updated_at
        FROM documents 
        WHERE id = $1
      "
      
      result <- dbGetQuery(secure_db_pool, query, list(id))
      
      if (nrow(result) > 0) {
        return(list(
          error = FALSE,
          message = "Documento encontrado",
          data = result[1, ],
          meta = list(
            document_id = id,
            source = "database"
          ),
          timestamp = Sys.time()
        ))
      } else {
        res$status <- 404
        return(list(
          error = TRUE,
          message = "Documento não encontrado",
          code = 404,
          timestamp = Sys.time()
        ))
      }
      
    } else {
      # Fallback sample document
      sample_doc <- data.frame(
        id = id,
        titulo = paste("Lei Municipal sobre Transporte -", id),
        ementa = "Regulamenta o sistema de transporte público municipal e estabelece diretrizes para sua operação",
        estado = "SP",
        municipio = "São Paulo",
        tipo_documento = "Lei",
        data_publicacao = Sys.Date(),
        numero = paste0("LEI-", id),
        ano = 2024,
        orgao_expedidor = "Prefeitura Municipal de São Paulo",
        url_original = paste0("https://exemplo.com/documento/", id),
        stringsAsFactors = FALSE
      )
      
      return(list(
        error = FALSE,
        message = "Documento de exemplo - banco não disponível",
        data = sample_doc,
        meta = list(
          document_id = id,
          source = "fallback",
          warning = "Dados de exemplo"
        ),
        timestamp = Sys.time()
      ))
    }
    
  }, error = function(e) {
    res$status <- 500
    return(list(
      error = TRUE,
      message = "Erro interno do servidor",
      details = "Erro ao buscar documento",
      code = 500,
      timestamp = Sys.time()
    ))
  })
}

# Get available document types
#' @get /api/v1/legislation/types
#' @tag legislation
#' @serializer unboxedJSON
function(req, res) {
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      query <- "
        SELECT 
          species as tipo,
          COUNT(*) as quantidade,
          MIN(data_publicacao) as data_mais_antiga,
          MAX(data_publicacao) as data_mais_recente
        FROM documents 
        WHERE species IS NOT NULL AND species != ''
        GROUP BY species
        ORDER BY quantidade DESC
      "
      
      result <- dbGetQuery(secure_db_pool, query)
      
      return(list(
        error = FALSE,
        message = "Tipos de documentos disponíveis",
        data = result,
        meta = list(
          total_types = nrow(result),
          source = "database"
        ),
        timestamp = Sys.time()
      ))
      
    } else {
      # Fallback types list
      types_data <- data.frame(
        tipo = names(DOCUMENT_TYPES),
        nome_completo = unlist(DOCUMENT_TYPES),
        quantidade = c(45000, 32000, 28000, 15000, 8000, 4000, 1500, 800, 600, 300),
        stringsAsFactors = FALSE
      )
      
      return(list(
        error = FALSE,
        message = "Tipos de documentos (dados de exemplo)",
        data = types_data,
        meta = list(
          total_types = nrow(types_data),
          source = "fallback"
        ),
        timestamp = Sys.time()
      ))
    }
    
  }, error = function(e) {
    return(list(
      error = TRUE,
      message = "Erro ao buscar tipos de documentos",
      code = 500,
      timestamp = Sys.time()
    ))
  })
}

# Get states statistics
#' @get /api/v1/legislation/states
#' @tag legislation
#' @serializer unboxedJSON  
function(req, res) {
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      query <- "
        SELECT 
          estado,
          COUNT(*) as total_documentos,
          COUNT(DISTINCT municipio) as municipios_com_legislacao,
          MIN(data_publicacao) as legislacao_mais_antiga,
          MAX(data_publicacao) as legislacao_mais_recente,
          ROUND(COUNT(*)::numeric * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentual_total
        FROM documents 
        WHERE estado IS NOT NULL AND estado != ''
        GROUP BY estado
        ORDER BY total_documentos DESC
      "
      
      result <- dbGetQuery(secure_db_pool, query)
      
      # Add full state names
      result$nome_estado <- sapply(result$estado, function(x) BRAZILIAN_STATES[[x]] %||% x)
      
      return(list(
        error = FALSE,
        message = "Estatísticas por estado",
        data = result,
        meta = list(
          total_states = nrow(result),
          source = "database"
        ),
        timestamp = Sys.time()
      ))
      
    } else {
      # Fallback state statistics
      states_data <- data.frame(
        estado = c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE"),
        nome_estado = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Rio Grande do Sul", "Paraná", "Santa Catarina", "Bahia", "Goiás", "Pernambuco", "Ceará"),
        total_documentos = c(25000, 18000, 15000, 12000, 10000, 8000, 7000, 6000, 5000, 4000),
        municipios_com_legislacao = c(450, 92, 320, 250, 200, 180, 280, 150, 120, 100),
        percentual_total = c(18.5, 13.4, 11.2, 8.9, 7.4, 5.9, 5.2, 4.5, 3.7, 3.0),
        stringsAsFactors = FALSE
      )
      
      return(list(
        error = FALSE,
        message = "Estatísticas por estado (dados de exemplo)",
        data = states_data,
        meta = list(
          total_states = nrow(states_data),
          source = "fallback"
        ),
        timestamp = Sys.time()
      ))
    }
    
  }, error = function(e) {
    return(list(
      error = TRUE,
      message = "Erro ao buscar estatísticas dos estados",
      code = 500,
      timestamp = Sys.time()
    ))
  })
}

cat("✅ Enhanced Legislation Search Endpoints loaded successfully\n")