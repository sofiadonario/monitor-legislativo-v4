# ============================================================================
# CITATIONS GENERATION ENDPOINT - WEEK 6 REST API IMPLEMENTATION
# ============================================================================
# 
# Academic citation generation for Brazilian legislative documents
# Supports multiple citation formats (ABNT, APA, Chicago, Vancouver)
# Optimized for Brazilian legal documents and academic standards
# 
# Endpoints:
# - GET /api/v1/citations/generate - Generate citations in multiple formats
# - POST /api/v1/citations/batch - Batch citation generation
# - GET /api/v1/citations/formats - Available citation formats
# - GET /api/v1/citations/validate - Validate citation format
# ============================================================================

cat("📚 Loading Citations Generation Endpoints - Week 6\n")

# Citation format templates
CITATION_FORMATS <- list(
  abnt = list(
    name = "ABNT (NBR 6023)",
    description = "Associação Brasileira de Normas Técnicas - Padrão brasileiro para citações",
    template = "{autor_institucional}. {titulo}. {local_publicacao}: {orgao_expedidor}, {data_publicacao}. {numero_documento}. Disponível em: {url}. Acesso em: {data_acesso}."
  ),
  apa = list(
    name = "APA (7ª Edição)",
    description = "American Psychological Association Style",
    template = "{orgao_expedidor}. ({ano}). {titulo}. {local_publicacao}: {orgao_expedidor}. Recuperado de {url}"
  ),
  chicago = list(
    name = "Chicago Manual of Style",
    description = "Chicago style for academic citations", 
    template = "{orgao_expedidor}. \"{titulo}.\" {local_publicacao}: {orgao_expedidor}, {ano}. {url}."
  ),
  vancouver = list(
    name = "Vancouver Style",
    description = "International Committee of Medical Journal Editors",
    template = "{orgao_expedidor}. {titulo}. {local_publicacao}: {orgao_expedidor}; {ano}. [citado {data_acesso}]. Disponível em: {url}"
  ),
  bibtex = list(
    name = "BibTeX",
    description = "LaTeX bibliography format",
    template = "@misc{{key,\n  author = {{{orgao_expedidor}}},\n  title = {{{titulo}}},\n  year = {{{ano}}},\n  publisher = {{{orgao_expedidor}}},\n  address = {{{local_publicacao}}},\n  url = {{{url}}},\n  note = {{Acessado em {data_acesso}}}\n}}"
  ),
  ris = list(
    name = "RIS (Research Information Systems)",
    description = "Reference manager format",
    template = "TY  - LEGAL\nAU  - {orgao_expedidor}\nTI  - {titulo}\nPY  - {ano}\nPB  - {orgao_expedidor}\nCY  - {local_publicacao}\nUR  - {url}\nER  -"
  )
)

# Brazilian legal document type mappings
DOCUMENT_TYPE_MAPPING <- list(
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

# Helper function to clean and format text for citations
clean_citation_text <- function(text) {
  if (is.null(text) || is.na(text) || text == "") {
    return("")
  }
  
  # Remove extra whitespace and normalize
  text <- trimws(gsub("\\s+", " ", text))
  
  # Capitalize first letter if needed
  if (nchar(text) > 0) {
    substr(text, 1, 1) <- toupper(substr(text, 1, 1))
  }
  
  return(text)
}

# Format date for Brazilian standards
format_brazilian_date <- function(date_input) {
  if (is.null(date_input) || is.na(date_input)) {
    return(format(Sys.Date(), "%d %b. %Y"))
  }
  
  tryCatch({
    date_obj <- as.Date(date_input)
    return(format(date_obj, "%d %b. %Y"))
  }, error = function(e) {
    return(format(Sys.Date(), "%d %b. %Y"))
  })
}

# Generate citation key for BibTeX
generate_citation_key <- function(orgao, titulo, ano) {
  # Create a unique key from organization, title, and year
  orgao_clean <- gsub("[^A-Za-z0-9]", "", orgao)
  titulo_words <- strsplit(titulo, "\\s+")[[1]][1:3]  # First 3 words
  titulo_clean <- paste(gsub("[^A-Za-z0-9]", "", titulo_words), collapse = "")
  
  return(paste0(tolower(orgao_clean), ano, tolower(titulo_clean)))
}

# Main citation generation function
generate_citation <- function(document_data, format = "abnt", access_date = Sys.Date()) {
  
  if (!(format %in% names(CITATION_FORMATS))) {
    stop(paste("Formato de citação inválido:", format))
  }
  
  # Extract and clean document information
  titulo <- clean_citation_text(document_data$titulo)
  orgao_expedidor <- clean_citation_text(document_data$orgao_expedidor %||% "Órgão não identificado")
  local_publicacao <- clean_citation_text(document_data$municipio %||% document_data$estado %||% "Local não identificado")
  data_publicacao <- format_brazilian_date(document_data$data_publicacao)
  ano <- as.numeric(format(as.Date(document_data$data_publicacao %||% Sys.Date()), "%Y"))
  numero_documento <- clean_citation_text(document_data$numero %||% "")
  tipo_documento <- DOCUMENT_TYPE_MAPPING[[tolower(document_data$species %||% "")]] %||% "Documento"
  url <- document_data$url_original %||% paste0("https://monitor-legislativo.br/documento/", document_data$id)
  data_acesso <- format_brazilian_date(access_date)
  
  # Create author institutional based on organ and location
  if (local_publicacao != "" && orgao_expedidor != local_publicacao) {
    autor_institucional <- paste(local_publicacao, orgao_expedidor, sep = ". ")
  } else {
    autor_institucional <- orgao_expedidor
  }
  
  # Build complete title with document type and number
  if (numero_documento != "") {
    titulo_completo <- paste(tipo_documento, numero_documento, "-", titulo)
  } else {
    titulo_completo <- paste(tipo_documento, titulo)
  }
  
  # Get format template
  template <- CITATION_FORMATS[[format]]$template
  
  # Replace placeholders with actual data
  citation <- template
  citation <- gsub("\\{autor_institucional\\}", autor_institucional, citation)
  citation <- gsub("\\{titulo\\}", titulo_completo, citation)
  citation <- gsub("\\{local_publicacao\\}", local_publicacao, citation)
  citation <- gsub("\\{orgao_expedidor\\}", orgao_expedidor, citation)
  citation <- gsub("\\{data_publicacao\\}", data_publicacao, citation)
  citation <- gsub("\\{ano\\}", ano, citation)
  citation <- gsub("\\{numero_documento\\}", numero_documento, citation)
  citation <- gsub("\\{url\\}", url, citation)
  citation <- gsub("\\{data_acesso\\}", data_acesso, citation)
  
  # Special handling for BibTeX key
  if (format == "bibtex") {
    citation_key <- generate_citation_key(orgao_expedidor, titulo, ano)
    citation <- gsub("\\{key\\}", citation_key, citation)
  }
  
  return(list(
    citation = citation,
    format = format,
    format_name = CITATION_FORMATS[[format]]$name,
    document_id = document_data$id,
    generated_at = Sys.time()
  ))
}

# Generate citations endpoint
#' @get /api/v1/citations/generate
#' @param document_id:str Document ID (required)
#' @param format:str Citation format (abnt, apa, chicago, vancouver, bibtex, ris)
#' @param access_date:str Access date (YYYY-MM-DD format, default: today)
#' @param all_formats:bool Generate all available formats (default: false)
#' @tag citations
#' @serializer unboxedJSON
function(req, res, document_id, format = "abnt", access_date = NULL, all_formats = FALSE) {
  
  if (is.null(document_id) || nchar(trimws(document_id)) == 0) {
    return(list(
      error = TRUE,
      message = "ID do documento é obrigatório",
      code = 400,
      timestamp = Sys.time()
    ))
  }
  
  # Parse access date
  if (is.null(access_date)) {
    access_date <- Sys.Date()
  } else {
    tryCatch({
      access_date <- as.Date(access_date)
    }, error = function(e) {
      return(list(
        error = TRUE,
        message = "Formato de data de acesso inválido. Use YYYY-MM-DD",
        code = 400,
        timestamp = Sys.time()
      ))
    })
  }
  
  tryCatch({
    # Get document data
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      query <- "
        SELECT 
          id, titulo, ementa, estado, municipio, species,
          data_publicacao, numero, ano, orgao_expedidor, url_original
        FROM documents 
        WHERE id = $1
      "
      
      document_data <- dbGetQuery(secure_db_pool, query, list(document_id))
      
      if (nrow(document_data) == 0) {
        return(list(
          error = TRUE,
          message = "Documento não encontrado",
          code = 404,
          timestamp = Sys.time()
        ))
      }
      
      doc <- document_data[1, ]
      
    } else {
      # Fallback document data
      doc <- list(
        id = document_id,
        titulo = "Lei Municipal sobre Transporte Público",
        ementa = "Regulamenta o sistema de transporte público municipal",
        estado = "SP",
        municipio = "São Paulo",
        species = "lei",
        data_publicacao = "2024-01-15",
        numero = "LEI-2024-001",
        ano = 2024,
        orgao_expedidor = "Prefeitura Municipal de São Paulo",
        url_original = paste0("https://monitor-legislativo.br/documento/", document_id)
      )
    }
    
    # Generate citations
    if (all_formats == TRUE || all_formats == "true") {
      citations <- list()
      for (fmt in names(CITATION_FORMATS)) {
        citations[[fmt]] <- generate_citation(doc, fmt, access_date)
      }
      
      return(list(
        error = FALSE,
        message = "Citações geradas em todos os formatos",
        data = citations,
        meta = list(
          document_id = document_id,
          total_formats = length(citations),
          access_date = as.character(access_date)
        ),
        timestamp = Sys.time()
      ))
      
    } else {
      # Single format citation
      if (!(format %in% names(CITATION_FORMATS))) {
        return(list(
          error = TRUE,
          message = paste("Formato inválido. Formatos disponíveis:", paste(names(CITATION_FORMATS), collapse = ", ")),
          code = 400,
          timestamp = Sys.time()
        ))
      }
      
      citation_result <- generate_citation(doc, format, access_date)
      
      return(list(
        error = FALSE,
        message = "Citação gerada com sucesso",
        data = citation_result,
        meta = list(
          document_id = document_id,
          format_requested = format,
          access_date = as.character(access_date)
        ),
        timestamp = Sys.time()
      ))
    }
    
  }, error = function(e) {
    return(list(
      error = TRUE,
      message = "Erro ao gerar citação",
      details = "Erro interno no processamento",
      code = 500,
      timestamp = Sys.time(),
      debug = if (Sys.getenv("DEBUG") == "true") e$message else NULL
    ))
  })
}

# Batch citation generation
#' @post /api/v1/citations/batch
#' @param req Request object with document IDs and citation parameters
#' @tag citations
#' @serializer unboxedJSON
function(req, res) {
  
  # Parse request body
  body <- tryCatch({
    jsonlite::fromJSON(req$postBody)
  }, error = function(e) {
    return(NULL)
  })
  
  if (is.null(body) || is.null(body$document_ids)) {
    return(list(
      error = TRUE,
      message = "Lista de IDs de documentos é obrigatória",
      code = 400,
      timestamp = Sys.time()
    ))
  }
  
  document_ids <- body$document_ids
  format <- body$format %||% "abnt"
  access_date <- tryCatch({
    as.Date(body$access_date %||% Sys.Date())
  }, error = function(e) {
    Sys.Date()
  })
  
  # Limit batch size for performance
  if (length(document_ids) > 100) {
    return(list(
      error = TRUE,
      message = "Limite máximo de 100 documentos por lote",
      code = 400,
      timestamp = Sys.time()
    ))
  }
  
  tryCatch({
    citations <- list()
    errors <- list()
    
    for (doc_id in document_ids) {
      tryCatch({
        # Get document (simplified for batch processing)
        if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
          query <- "
            SELECT 
              id, titulo, ementa, estado, municipio, species,
              data_publicacao, numero, ano, orgao_expedidor, url_original
            FROM documents 
            WHERE id = $1
          "
          doc_data <- dbGetQuery(secure_db_pool, query, list(doc_id))
          
          if (nrow(doc_data) > 0) {
            citation <- generate_citation(doc_data[1, ], format, access_date)
            citations[[doc_id]] <- citation
          } else {
            errors[[doc_id]] <- "Documento não encontrado"
          }
          
        } else {
          # Fallback for batch
          fallback_doc <- list(
            id = doc_id,
            titulo = paste("Documento", doc_id),
            estado = "SP",
            municipio = "São Paulo",
            species = "lei",
            data_publicacao = "2024-01-01",
            numero = paste0("DOC-", doc_id),
            ano = 2024,
            orgao_expedidor = "Órgão Municipal"
          )
          citation <- generate_citation(fallback_doc, format, access_date)
          citations[[doc_id]] <- citation
        }
        
      }, error = function(e) {
        errors[[doc_id]] <- e$message
      })
    }
    
    return(list(
      error = FALSE,
      message = paste("Processados", length(document_ids), "documentos"),
      data = list(
        citations = citations,
        errors = errors
      ),
      meta = list(
        total_requested = length(document_ids),
        successful_citations = length(citations),
        failed_citations = length(errors),
        format = format,
        access_date = as.character(access_date)
      ),
      timestamp = Sys.time()
    ))
    
  }, error = function(e) {
    return(list(
      error = TRUE,
      message = "Erro no processamento em lote",
      code = 500,
      timestamp = Sys.time()
    ))
  })
}

# Available citation formats
#' @get /api/v1/citations/formats
#' @tag citations
#' @serializer unboxedJSON
function(req, res) {
  
  formats_info <- list()
  for (format_key in names(CITATION_FORMATS)) {
    formats_info[[format_key]] <- CITATION_FORMATS[[format_key]][c("name", "description")]
  }
  
  return(list(
    error = FALSE,
    message = "Formatos de citação disponíveis",
    data = formats_info,
    meta = list(
      total_formats = length(formats_info),
      default_format = "abnt"
    ),
    timestamp = Sys.time()
  ))
}

# Validate citation format
#' @get /api/v1/citations/validate
#' @param citation:str Citation text to validate
#' @param format:str Expected citation format
#' @tag citations
#' @serializer unboxedJSON
function(req, res, citation, format = "abnt") {
  
  if (is.null(citation) || nchar(trimws(citation)) == 0) {
    return(list(
      error = TRUE,
      message = "Texto da citação é obrigatório",
      code = 400,
      timestamp = Sys.time()
    ))
  }
  
  # Basic validation based on format patterns
  validation_result <- list(
    is_valid = FALSE,
    format = format,
    errors = character(0),
    suggestions = character(0)
  )
  
  if (format == "abnt") {
    # Check for basic ABNT elements
    has_author <- grepl("^[A-Z]", citation)
    has_title <- grepl("[A-Za-z]", citation)
    has_date <- grepl("\\d{4}", citation)
    has_period <- grepl("\\.$", citation)
    
    if (!has_author) validation_result$errors <- c(validation_result$errors, "Autor institucional não identificado")
    if (!has_title) validation_result$errors <- c(validation_result$errors, "Título não identificado")
    if (!has_date) validation_result$errors <- c(validation_result$errors, "Data de publicação não encontrada")
    if (!has_period) validation_result$errors <- c(validation_result$errors, "Citação deve terminar com ponto final")
    
    validation_result$is_valid <- length(validation_result$errors) == 0
    
    if (!validation_result$is_valid) {
      validation_result$suggestions <- c("Verifique se todos os elementos obrigatórios estão presentes: autor, título, data e pontuação")
    }
  } else {
    validation_result$errors <- c("Validação disponível apenas para formato ABNT")
    validation_result$suggestions <- c("Use o formato ABNT para validação automática")
  }
  
  return(list(
    error = FALSE,
    message = if (validation_result$is_valid) "Citação válida" else "Citação com problemas",
    data = validation_result,
    timestamp = Sys.time()
  ))
}

cat("✅ Citations Generation Endpoints loaded successfully\n")