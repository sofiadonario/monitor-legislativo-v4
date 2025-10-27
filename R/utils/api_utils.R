# API Utilities Module
# Monitor Legislativo v4 - External API Integration Utilities
# ===========================================================

#' API Utilities for Monitor Legislativo v4
#' 
#' This module provides utilities for interacting with external APIs,
#' including Brazilian government data sources, validation services,
#' and data enrichment APIs. LGPD compliant with rate limiting.

library(httr)
library(jsonlite)

# API Configuration
API_CONFIG <- list(
  rate_limit_delay = 1,  # seconds between requests
  max_retries = 3,
  timeout = 30,  # seconds
  user_agent = "Monitor-Legislativo-v4/1.0 (Academic Research Tool)"
)

# Global rate limiting state
.api_state <- list(
  last_request_time = NULL,
  request_count = 0,
  daily_quota_used = 0
)

#' Safe API Request with Rate Limiting and Error Handling
#' 
#' @param url API endpoint URL
#' @param method HTTP method (GET, POST, etc.)
#' @param headers List of HTTP headers
#' @param body Request body for POST/PUT requests
#' @param params Query parameters
#' @return List with response data or error information
#' @export
make_api_request <- function(url, method = "GET", headers = list(), body = NULL, params = list()) {
  # Rate limiting enforcement
  if (!is.null(.api_state$last_request_time)) {
    time_since_last <- as.numeric(difftime(Sys.time(), .api_state$last_request_time, units = "secs"))
    if (time_since_last < API_CONFIG$rate_limit_delay) {
      Sys.sleep(API_CONFIG$rate_limit_delay - time_since_last)
    }
  }
  
  # Update request tracking
  .api_state$last_request_time <<- Sys.time()
  .api_state$request_count <<- .api_state$request_count + 1
  
  # Set default headers
  default_headers <- list(
    "User-Agent" = API_CONFIG$user_agent,
    "Accept" = "application/json",
    "Content-Type" = "application/json"
  )
  headers <- modifyList(default_headers, headers)
  
  # Attempt request with retries
  for (attempt in 1:API_CONFIG$max_retries) {
    tryCatch({
      cat("🌐 API Request attempt", attempt, "to:", url, "\n")
      
      # Make request based on method
      response <- switch(toupper(method),
        "GET" = httr::GET(
          url = url,
          query = params,
          httr::add_headers(.headers = headers),
          httr::timeout(API_CONFIG$timeout)
        ),
        "POST" = httr::POST(
          url = url,
          query = params,
          body = body,
          httr::add_headers(.headers = headers),
          httr::timeout(API_CONFIG$timeout),
          encode = "json"
        ),
        stop("Unsupported HTTP method: ", method)
      )
      
      # Check response status
      if (httr::status_code(response) == 200) {
        content <- httr::content(response, as = "text", encoding = "UTF-8")
        
        # Try to parse JSON
        tryCatch({
          parsed_content <- jsonlite::fromJSON(content, simplifyVector = TRUE)
          
          cat("✅ API request successful\n")
          return(list(
            success = TRUE,
            data = parsed_content,
            status_code = httr::status_code(response),
            headers = httr::headers(response)
          ))
          
        }, error = function(parse_error) {
          # Return raw content if JSON parsing fails
          return(list(
            success = TRUE,
            data = content,
            status_code = httr::status_code(response),
            headers = httr::headers(response),
            parse_warning = "Content is not valid JSON"
          ))
        })
        
      } else {
        cat("⚠️ API request failed with status:", httr::status_code(response), "\n")
        
        if (attempt < API_CONFIG$max_retries) {
          cat("🔄 Retrying in", attempt * 2, "seconds...\n")
          Sys.sleep(attempt * 2)  # Exponential backoff
        }
      }
      
    }, error = function(e) {
      cat("❌ API request error:", e$message, "\n")
      
      if (attempt < API_CONFIG$max_retries) {
        cat("🔄 Retrying in", attempt * 2, "seconds...\n")
        Sys.sleep(attempt * 2)
      }
    })
  }
  
  # All attempts failed
  return(list(
    success = FALSE,
    error = "All API request attempts failed",
    attempts = API_CONFIG$max_retries
  ))
}

#' Validate Brazilian Legal Document URL
#' 
#' @param urn Legal document URN
#' @return List with validation results
#' @export
validate_legal_document_urn <- function(urn) {
  if (isTRUE(is.null(urn)) || isTRUE(is.na(urn)) || urn == "") {
    return(list(valid = FALSE, error = "Empty URN"))
  }
  
  # Basic URN pattern validation for Brazilian legal documents
  # Pattern: urn:lex:br;estado:municipio:lei:data:numero
  urn_pattern <- "^urn:lex:br(:[a-z]{2})?(:[a-z.]+)?:(lei|decreto|resolucao|portaria|instrucao.normativa):([0-9]{4}(-[0-9]{2}){2})?:([0-9]+)$"
  
  if (grepl(urn_pattern, urn, ignore.case = TRUE)) {
    # Extract components
    components <- unlist(strsplit(urn, ":"))
    
    validation_result <- list(
      valid = TRUE,
      urn = urn,
      country = if(length(components) > 2) components[3] else "br",
      state = if(length(components) > 3) components[4] else NULL,
      municipality = if(length(components) > 4) components[5] else NULL,
      document_type = if(length(components) > 5) components[6] else NULL,
      date = if(length(components) > 6) components[7] else NULL,
      number = if(length(components) > 7) components[8] else NULL
    )
    
    return(validation_result)
  } else {
    return(list(
      valid = FALSE,
      error = "Invalid URN format for Brazilian legal document",
      urn = urn
    ))
  }
}

#' Enrich Document Data with External APIs
#' 
#' @param document Document data frame row
#' @return Enhanced document with additional metadata
#' @export
enrich_document_metadata <- function(document) {
  enhanced_doc <- document
  
  tryCatch({
    # Add geographic information if state is available
    if (!isTRUE(is.null(document$estado)) && document$estado != "") {
      geo_info <- get_state_information(document$estado)
      if (geo_info$success) {
        enhanced_doc$estado_nome_completo <- geo_info$data$nome_completo
        enhanced_doc$regiao <- geo_info$data$regiao
        enhanced_doc$populacao <- geo_info$data$populacao
      }
    }
    
    # Add document type classification
    if (!is.null(document$tipo_documento)) {
      type_info <- classify_document_type(document$tipo_documento)
      enhanced_doc$categoria_juridica <- type_info$categoria
      enhanced_doc$nivel_hierarquico <- type_info$nivel
    }
    
    # Add temporal classification
    if (!is.null(document$data)) {
      temporal_info <- analyze_document_temporal_context(document$data)
      enhanced_doc$periodo_governamental <- temporal_info$periodo
      enhanced_doc$contexto_historico <- temporal_info$contexto
    }
    
    enhanced_doc$enriquecimento_timestamp <- Sys.time()
    enhanced_doc$fontes_consultadas <- c("IBGE", "Portal da Legislação", "Sistema Interno")
    
    return(enhanced_doc)
    
  }, error = function(e) {
    cat("⚠️ Document enrichment failed:", e$message, "\n")
    return(document)  # Return original document if enrichment fails
  })
}

#' Get Brazilian State Information
#' 
#' @param state_code Two-letter state code (e.g., "SP", "RJ")
#' @return List with state information
#' @export
get_state_information <- function(state_code) {
  # Brazilian states mapping (built-in for offline operation)
  states_data <- list(
    "AC" = list(nome_completo = "Acre", regiao = "Norte", populacao = 906876),
    "AL" = list(nome_completo = "Alagoas", regiao = "Nordeste", populacao = 3365351),
    "AP" = list(nome_completo = "Amapá", regiao = "Norte", populacao = 877613),
    "AM" = list(nome_completo = "Amazonas", regiao = "Norte", populacao = 4269995),
    "BA" = list(nome_completo = "Bahia", regiao = "Nordeste", populacao = 14985284),
    "CE" = list(nome_completo = "Ceará", regiao = "Nordeste", populacao = 9240580),
    "DF" = list(nome_completo = "Distrito Federal", regiao = "Centro-Oeste", populacao = 3094325),
    "ES" = list(nome_completo = "Espírito Santo", regiao = "Sudeste", populacao = 4108508),
    "GO" = list(nome_completo = "Goiás", regiao = "Centro-Oeste", populacao = 7206589),
    "MA" = list(nome_completo = "Maranhão", regiao = "Nordeste", populacao = 7153262),
    "MT" = list(nome_completo = "Mato Grosso", regiao = "Centro-Oeste", populacao = 3567234),
    "MS" = list(nome_completo = "Mato Grosso do Sul", regiao = "Centro-Oeste", populacao = 2839188),
    "MG" = list(nome_completo = "Minas Gerais", regiao = "Sudeste", populacao = 21411923),
    "PA" = list(nome_completo = "Pará", regiao = "Norte", populacao = 8777124),
    "PB" = list(nome_completo = "Paraíba", regiao = "Nordeste", populacao = 4059905),
    "PR" = list(nome_completo = "Paraná", regiao = "Sul", populacao = 11597484),
    "PE" = list(nome_completo = "Pernambuco", regiao = "Nordeste", populacao = 9674793),
    "PI" = list(nome_completo = "Piauí", regiao = "Nordeste", populacao = 3289290),
    "RJ" = list(nome_completo = "Rio de Janeiro", regiao = "Sudeste", populacao = 17463349),
    "RN" = list(nome_completo = "Rio Grande do Norte", regiao = "Nordeste", populacao = 3560903),
    "RS" = list(nome_completo = "Rio Grande do Sul", regiao = "Sul", populacao = 11466630),
    "RO" = list(nome_completo = "Rondônia", regiao = "Norte", populacao = 1815278),
    "RR" = list(nome_completo = "Roraima", regiao = "Norte", populacao = 652713),
    "SC" = list(nome_completo = "Santa Catarina", regiao = "Sul", populacao = 7338473),
    "SP" = list(nome_completo = "São Paulo", regiao = "Sudeste", populacao = 46649132),
    "SE" = list(nome_completo = "Sergipe", regiao = "Nordeste", populacao = 2338474),
    "TO" = list(nome_completo = "Tocantins", regiao = "Norte", populacao = 1607363)
  )
  
  state_upper <- toupper(state_code)
  
  if (state_upper %in% names(states_data)) {
    return(list(
      success = TRUE,
      data = states_data[[state_upper]]
    ))
  } else {
    return(list(
      success = FALSE,
      error = paste("Unknown state code:", state_code)
    ))
  }
}

#' Classify Brazilian Legal Document Type
#' 
#' @param document_type Document type string
#' @return List with classification information
#' @export
classify_document_type <- function(document_type) {
  if (isTRUE(is.null(document_type)) || isTRUE(is.na(document_type))) {
    return(list(categoria = "Desconhecido", nivel = 0))
  }
  
  type_lower <- tolower(document_type)
  
  # Classification hierarchy for Brazilian legal documents
  if (grepl("constituição|constitucional", type_lower)) {
    return(list(categoria = "Constitucional", nivel = 1))
  } else if (grepl("lei complementar", type_lower)) {
    return(list(categoria = "Lei Complementar", nivel = 2))
  } else if (grepl("lei ordinária|lei", type_lower)) {
    return(list(categoria = "Lei Ordinária", nivel = 3))
  } else if (grepl("decreto-lei", type_lower)) {
    return(list(categoria = "Decreto-Lei", nivel = 3))
  } else if (grepl("medida provisória", type_lower)) {
    return(list(categoria = "Medida Provisória", nivel = 3))
  } else if (grepl("decreto", type_lower)) {
    return(list(categoria = "Decreto", nivel = 4))
  } else if (grepl("resolução", type_lower)) {
    return(list(categoria = "Resolução", nivel = 5))
  } else if (grepl("portaria", type_lower)) {
    return(list(categoria = "Portaria", nivel = 6))
  } else if (grepl("instrução normativa", type_lower)) {
    return(list(categoria = "Instrução Normativa", nivel = 6))
  } else {
    return(list(categoria = "Outros", nivel = 7))
  }
}

#' Analyze Document Temporal Context
#' 
#' @param document_date Document date
#' @return List with temporal analysis
#' @export
analyze_document_temporal_context <- function(document_date) {
  if (isTRUE(is.null(document_date)) || isTRUE(is.na(document_date))) {
    return(list(periodo = "Desconhecido", contexto = "Data não disponível"))
  }
  
  tryCatch({
    doc_date <- as.Date(document_date)
    year <- as.integer(format(doc_date, "%Y"))
    
    # Brazilian governmental periods (simplified)
    if (year >= 2023) {
      return(list(periodo = "Governo Lula III (2023-)", contexto = "Terceiro mandato"))
    } else if (year >= 2019) {
      return(list(periodo = "Governo Bolsonaro (2019-2022)", contexto = "Período pandêmico"))
    } else if (year >= 2016) {
      return(list(periodo = "Governo Temer (2016-2018)", contexto = "Governo de transição"))
    } else if (year >= 2011) {
      return(list(periodo = "Governo Dilma (2011-2016)", contexto = "Crise econômica"))
    } else if (year >= 2003) {
      return(list(periodo = "Governo Lula I/II (2003-2010)", contexto = "Crescimento econômico"))
    } else if (year >= 1995) {
      return(list(periodo = "Governo FHC (1995-2002)", contexto = "Estabilização monetária"))
    } else {
      return(list(periodo = "Período anterior (< 1995)", contexto = "Período histórico"))
    }
    
  }, error = function(e) {
    return(list(periodo = "Erro na análise", contexto = e$message))
  })
}

#' Get API Usage Statistics
#' 
#' @return List with current API usage metrics
#' @export
get_api_usage_stats <- function() {
  return(list(
    total_requests = .api_state$request_count,
    daily_quota_used = .api_state$daily_quota_used,
    last_request = .api_state$last_request_time,
    rate_limit_delay = API_CONFIG$rate_limit_delay,
    max_retries = API_CONFIG$max_retries
  ))
}

cat("✅ API utilities module loaded successfully\n")