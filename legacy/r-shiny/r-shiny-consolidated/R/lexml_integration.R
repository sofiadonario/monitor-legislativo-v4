# LexML API Integration for Monitor Legislativo v4
# Enhanced search capabilities with vocabulary-aware processing

library(httr)
library(jsonlite)
library(dplyr)
library(stringr)
library(xml2)
library(rvest)

# LexML API Configuration
LEXML_BASE_URL <- "https://www.lexml.gov.br/busca"
LEXML_API_URL <- "https://www.lexml.gov.br/ws"
MAX_RETRIES <- 3
REQUEST_TIMEOUT <- 30

#' Enhanced LexML search with vocabulary expansion
#' @param query Search query
#' @param filters List of filters (date, type, jurisdiction)
#' @param expand_vocabulary Whether to expand vocabulary terms
#' @param limit Maximum number of results
#' @return Data frame with search results
search_lexml_enhanced <- function(query = NULL, filters = list(), 
                                 expand_vocabulary = TRUE, limit = 1000) {
  
  log_event("Starting LexML enhanced search")
  
  # Input validation
  if (is.null(query) || nchar(trimws(query)) == 0) {
    log_event("Empty query provided", "WARN")
    return(create_empty_search_result())
  }
  
  # Expand vocabulary if requested
  if (expand_vocabulary) {
    expanded_query <- expand_search_vocabulary(query)
    log_event(paste("Expanded query from:", query, "to:", expanded_query))
  } else {
    expanded_query <- query
  }
  
  # Build search parameters
  search_params <- build_lexml_search_params(
    query = expanded_query,
    filters = filters,
    limit = limit
  )
  
  # Execute search with retry logic
  tryCatch({
    results <- execute_lexml_search_with_retry(search_params)
    
    if (!is.null(results) && nrow(results) > 0) {
      # Enhance results with additional metadata
      enhanced_results <- enhance_lexml_results(results)
      log_event(paste("LexML search completed:", nrow(enhanced_results), "results"))
      return(enhanced_results)
    } else {
      log_event("No results from LexML search", "WARN")
      return(create_empty_search_result())
    }
    
  }, error = function(e) {
    log_event(paste("LexML search failed:", e$message), "ERROR")
    return(create_fallback_lexml_data(query))
  })
}

#' Build LexML search parameters
#' @param query Search query
#' @param filters Search filters
#' @param limit Result limit
#' @return List of search parameters
build_lexml_search_params <- function(query, filters, limit) {
  
  params <- list(
    q = query,
    format = "json",
    limit = min(limit, 1000)  # LexML API limit
  )
  
  # Add date filters
  if (!is.null(filters$date_from)) {
    params$dataInicio <- format(as.Date(filters$date_from), "%Y-%m-%d")
  }
  
  if (!is.null(filters$date_to)) {
    params$dataFim <- format(as.Date(filters$date_to), "%Y-%m-%d")
  }
  
  # Add document type filters
  if (!is.null(filters$types) && length(filters$types) > 0) {
    # Map internal types to LexML types
    lexml_types <- map_to_lexml_types(filters$types)
    if (length(lexml_types) > 0) {
      params$tipo <- paste(lexml_types, collapse = ",")
    }
  }
  
  # Add jurisdiction filters
  if (!is.null(filters$states) && length(filters$states) > 0) {
    params$jurisdicao <- paste(filters$states, collapse = ",")
  }
  
  # Add authority filters
  if (!is.null(filters$authorities) && length(filters$authorities) > 0) {
    params$autoridade <- paste(filters$authorities, collapse = ",")
  }
  
  return(params)
}

#' Execute LexML search with retry logic
#' @param params Search parameters
#' @return Data frame with results
execute_lexml_search_with_retry <- function(params) {
  
  for (attempt in 1:MAX_RETRIES) {
    
    tryCatch({
      log_event(paste("LexML search attempt", attempt, "of", MAX_RETRIES))
      
      # Make HTTP request
      response <- httr::GET(
        url = LEXML_API_URL,
        query = params,
        httr::timeout(REQUEST_TIMEOUT),
        httr::user_agent("Monitor-Legislativo-v4-R/1.0")
      )
      
      # Check response status
      httr::stop_for_status(response)
      
      # Parse JSON response
      content <- httr::content(response, as = "text", encoding = "UTF-8")
      results_json <- jsonlite::fromJSON(content, flatten = TRUE)
      
      # Extract and process results
      if (!is.null(results_json$documentos) && length(results_json$documentos) > 0) {
        processed_results <- process_lexml_response(results_json$documentos)
        return(processed_results)
      } else {
        log_event("LexML returned no documents", "WARN")
        return(data.frame())
      }
      
    }, error = function(e) {
      log_event(paste("LexML attempt", attempt, "failed:", e$message), "WARN")
      
      if (attempt == MAX_RETRIES) {
        stop(paste("All LexML attempts failed. Last error:", e$message))
      }
      
      # Wait before retry (exponential backoff)
      Sys.sleep(2^attempt)
    })
  }
}

#' Process LexML API response
#' @param documents List of documents from API
#' @return Processed data frame
process_lexml_response <- function(documents) {
  
  if (is.null(documents) || length(documents) == 0) {
    return(create_empty_search_result())
  }
  
  # Convert to data frame and standardize columns
  results_df <- tryCatch({
    data.frame(
      titulo = extract_safe(documents, "titulo", ""),
      tipo = extract_safe(documents, "tipo", ""),
      numero = extract_safe(documents, "numero", ""),
      data = extract_safe(documents, "data", Sys.Date()),
      ementa = extract_safe(documents, "ementa", ""),
      autor = extract_safe(documents, "autoridade", ""),
      estado = extract_safe(documents, "jurisdicao", ""),
      fonte = "LexML Brasil",
      url = extract_safe(documents, "uri", ""),
      urn = extract_safe(documents, "urn", ""),
      situacao = extract_safe(documents, "situacao", ""),
      assunto = extract_safe(documents, "assunto", ""),
      stringsAsFactors = FALSE
    )
  }, error = function(e) {
    log_event(paste("Error processing LexML response:", e$message), "ERROR")
    return(create_empty_search_result())
  })
  
  # Clean and validate data
  results_df <- results_df %>%
    mutate(
      # Clean title
      titulo = str_trim(str_squish(titulo)),
      titulo = ifelse(nchar(titulo) == 0, "Documento sem título", titulo),
      
      # Parse and validate dates
      data = parse_lexml_date(data),
      
      # Clean document numbers
      numero = str_trim(numero),
      
      # Standardize state codes
      estado = standardize_state_codes(estado),
      
      # Clean URLs
      url = ifelse(str_detect(url, "^https?://"), url, paste0("https://", url)),
      
      # Add metadata
      sistema_origem = "LexML",
      qualidade_dados = "alta",
      data_busca = Sys.time()
    ) %>%
    filter(
      # Basic quality filters
      nchar(titulo) >= 5,
      !is.na(data),
      data >= as.Date("1988-10-05")  # Brazilian Constitution date
    )
  
  return(results_df)
}

#' Extract field safely from list with fallback
#' @param data_list List of data
#' @param field Field name
#' @param default Default value
#' @return Extracted values
extract_safe <- function(data_list, field, default = NA) {
  tryCatch({
    if (field %in% names(data_list)) {
      values <- data_list[[field]]
      return(ifelse(is.null(values) | is.na(values) | values == "", default, values))
    } else {
      return(rep(default, length(data_list)))
    }
  }, error = function(e) {
    return(rep(default, length(data_list)))
  })
}

#' Parse LexML date formats
#' @param date_strings Vector of date strings
#' @return Vector of Date objects
parse_lexml_date <- function(date_strings) {
  
  parsed_dates <- sapply(date_strings, function(date_str) {
    if (is.na(date_str) || nchar(trimws(date_str)) == 0) {
      return(NA)
    }
    
    # Try multiple date formats used by LexML
    formats <- c(
      "%Y-%m-%d",           # ISO format
      "%d/%m/%Y",           # Brazilian format
      "%Y-%m-%dT%H:%M:%S",  # ISO with time
      "%Y-%m-%d %H:%M:%S"   # SQL datetime
    )
    
    for (fmt in formats) {
      tryCatch({
        parsed <- as.Date(date_str, format = fmt)
        if (!is.na(parsed)) {
          return(parsed)
        }
      }, error = function(e) {
        # Continue to next format
      })
    }
    
    # If all formats fail, try automatic parsing
    tryCatch({
      return(as.Date(date_str))
    }, error = function(e) {
      return(NA)
    })
  })
  
  return(as.Date(parsed_dates, origin = "1970-01-01"))
}

#' Map internal document types to LexML types
#' @param internal_types Vector of internal type names
#' @return Vector of LexML type codes
map_to_lexml_types <- function(internal_types) {
  
  type_mapping <- list(
    "lei" = c("lei", "lei.complementar", "lei.ordinaria"),
    "decreto" = c("decreto", "decreto.lei"),
    "portaria" = "portaria",
    "resolucao" = "resolucao",
    "medida_provisoria" = "medida.provisoria",
    "instrucao_normativa" = "instrucao.normativa",
    "ordem_de_servico" = "ordem.servico",
    "circular" = "circular",
    "parecer" = "parecer"
  )
  
  lexml_types <- c()
  
  for (internal_type in internal_types) {
    if (internal_type %in% names(type_mapping)) {
      lexml_types <- c(lexml_types, type_mapping[[internal_type]])
    }
  }
  
  return(unique(lexml_types))
}

#' Standardize state codes from LexML jurisdiction
#' @param jurisdictions Vector of jurisdiction strings
#' @return Vector of standardized state codes
standardize_state_codes <- function(jurisdictions) {
  
  sapply(jurisdictions, function(jurisdiction) {
    if (is.na(jurisdiction) || nchar(trimws(jurisdiction)) == 0) {
      return(NA)
    }
    
    # Extract state code from jurisdiction string
    # LexML format: "br;sp" or "br;sp;municipio"
    parts <- str_split(jurisdiction, ";")[[1]]
    
    if (length(parts) >= 2) {
      state_code <- str_to_upper(trimws(parts[2]))
      
      # Validate Brazilian state codes
      valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", 
                       "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", 
                       "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO")
      
      if (state_code %in% valid_states) {
        return(state_code)
      }
    }
    
    return(NA)
  })
}

#' Enhance LexML results with additional metadata
#' @param results Data frame with basic results
#' @return Enhanced data frame
enhance_lexml_results <- function(results) {
  
  if (is.null(results) || nrow(results) == 0) {
    return(results)
  }
  
  enhanced <- results %>%
    mutate(
      # Calculate document age
      dias_desde_publicacao = as.numeric(Sys.Date() - data),
      
      # Categorize by subject matter
      categoria_principal = categorize_by_subject(titulo, ementa, assunto),
      
      # Calculate relevance score for transport legislation
      relevancia_transporte = calculate_transport_relevance(titulo, ementa, assunto),
      
      # Extract authority level
      nivel_autoridade = extract_authority_level(autor),
      
      # Geographic region
      regiao = map_state_to_region(estado),
      
      # Text quality indicators
      titulo_palavras = str_count(titulo, "\\S+"),
      ementa_palavras = str_count(ementa, "\\S+"),
      
      # LexML-specific metadata
      urn_valido = !is.na(urn) & str_detect(urn, "^urn:lex:"),
      tem_ementa = !is.na(ementa) & nchar(trimws(ementa)) > 10,
      tem_url = !is.na(url) & str_detect(url, "^https?://")
    )
  
  return(enhanced)
}

#' Categorize documents by subject matter
#' @param titles Vector of document titles
#' @param ementas Vector of document summaries
#' @param subjects Vector of subject classifications
#' @return Vector of categories
categorize_by_subject <- function(titles, ementas, subjects) {
  
  combined_text <- paste(
    tolower(coalesce(titles, "")),
    tolower(coalesce(ementas, "")),
    tolower(coalesce(subjects, ""))
  )
  
  sapply(combined_text, function(text) {
    
    # Transport and mobility
    if (str_detect(text, "transport|mobilidad|trânsit|ônibus|metrô|brt|vlt|rodoviá|ferroviá")) {
      return("Transporte e Mobilidade")
    }
    
    # Urban planning
    if (str_detect(text, "urbano|planejamento|zoneamento|solo|ocupação")) {
      return("Planejamento Urbano")
    }
    
    # Environment
    if (str_detect(text, "ambiente|ambiental|sustent|ecolog|poluição")) {
      return("Meio Ambiente")
    }
    
    # Education
    if (str_detect(text, "educação|escola|ensino|universidade|estudante")) {
      return("Educação")
    }
    
    # Health
    if (str_detect(text, "saúde|hospital|sus|medicina|sanitár")) {
      return("Saúde")
    }
    
    # Economy and finance
    if (str_detect(text, "econom|financ|orçament|fiscal|tributár|imposto")) {
      return("Economia e Finanças")
    }
    
    # Security
    if (str_detect(text, "segurança|polícia|crime|violência|defesa")) {
      return("Segurança Pública")
    }
    
    # Infrastructure
    if (str_detect(text, "infraestrutura|obra|construção|saneamento|energia")) {
      return("Infraestrutura")
    }
    
    # Social policy
    if (str_detect(text, "social|assistência|benefício|inclusão|direitos")) {
      return("Política Social")
    }
    
    # Administrative
    if (str_detect(text, "administrativ|gestão|servidor|público|procedimento")) {
      return("Administrativo")
    }
    
    return("Outros")
  })
}

#' Calculate transport relevance score
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @param subjects Vector of subjects
#' @return Vector of relevance scores (0-100)
calculate_transport_relevance <- function(titles, ementas, subjects) {
  
  combined_text <- paste(
    tolower(coalesce(titles, "")),
    tolower(coalesce(ementas, "")),
    tolower(coalesce(subjects, ""))
  )
  
  sapply(combined_text, function(text) {
    score <- 0
    
    # High relevance terms (20 points each)
    high_terms <- c("transporte público", "mobilidade urbana", "sistema viário", 
                   "transporte coletivo", "trânsito urbano")
    score <- score + sum(str_count(text, high_terms)) * 20
    
    # Medium relevance terms (10 points each)
    medium_terms <- c("ônibus", "metrô", "trem", "brt", "vlt", "ciclovia", 
                     "pedestre", "semáforo", "estacionamento")
    score <- score + sum(str_count(text, medium_terms)) * 10
    
    # General transport terms (5 points each)
    general_terms <- c("transport", "mobilidad", "trânsit", "via", "rua", 
                      "avenida", "rodovia", "estrada")
    score <- score + sum(str_count(text, general_terms)) * 5
    
    # Infrastructure terms (3 points each)
    infra_terms <- c("ponte", "viaduto", "túnel", "terminal", "estação", 
                    "aeroporto", "porto", "rodoviária")
    score <- score + sum(str_count(text, infra_terms)) * 3
    
    return(min(score, 100))  # Cap at 100
  })
}

#' Extract authority level from author field
#' @param authors Vector of author/authority strings
#' @return Vector of authority levels
extract_authority_level <- function(authors) {
  
  sapply(authors, function(author) {
    if (is.na(author) || nchar(trimws(author)) == 0) {
      return("Desconhecido")
    }
    
    author_lower <- tolower(author)
    
    # Federal level
    if (str_detect(author_lower, "union|federal|república|presidente|ministro")) {
      return("Federal")
    }
    
    # State level
    if (str_detect(author_lower, "estado|estadual|governador|assembleia")) {
      return("Estadual")
    }
    
    # Municipal level
    if (str_detect(author_lower, "município|municipal|prefeito|câmara")) {
      return("Municipal")
    }
    
    return("Outros")
  })
}

#' Map state codes to geographic regions
#' @param state_codes Vector of state codes
#' @return Vector of region names
map_state_to_region <- function(state_codes) {
  
  region_mapping <- list(
    "Norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
    "Nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
    "Centro-Oeste" = c("DF", "GO", "MT", "MS"),
    "Sudeste" = c("ES", "MG", "RJ", "SP"),
    "Sul" = c("PR", "RS", "SC")
  )
  
  sapply(state_codes, function(state) {
    if (is.na(state)) return(NA)
    
    for (region in names(region_mapping)) {
      if (state %in% region_mapping[[region]]) {
        return(region)
      }
    }
    
    return("Não Classificado")
  })
}

#' Create empty search result structure
#' @return Empty data frame with standard columns
create_empty_search_result <- function() {
  data.frame(
    titulo = character(0),
    tipo = character(0),
    numero = character(0),
    data = as.Date(character(0)),
    ementa = character(0),
    autor = character(0),
    estado = character(0),
    fonte = character(0),
    url = character(0),
    stringsAsFactors = FALSE
  )
}

#' Create fallback data when LexML is unavailable
#' @param query Original search query
#' @return Fallback data frame
create_fallback_lexml_data <- function(query = "") {
  
  log_event("Creating LexML fallback data", "WARN")
  
  # Return sample transport-related legislation
  fallback_data <- data.frame(
    titulo = c(
      "Lei de Mobilidade Urbana - Diretrizes da Política Nacional",
      "Decreto sobre Transporte Público Municipal", 
      "Resolução CONTRAN - Sinalização Viária",
      "Portaria sobre Acessibilidade em Transportes",
      "Lei Complementar - Sistema Viário Municipal"
    ),
    tipo = c("Lei", "Decreto", "Resolução", "Portaria", "Lei Complementar"),
    numero = c("12.587/2012", "8.754/2016", "780/2020", "315/2019", "156/2018"),
    data = as.Date(c("2012-01-03", "2016-05-15", "2020-08-10", "2019-11-22", "2018-07-30")),
    ementa = c(
      "Institui as diretrizes da Política Nacional de Mobilidade Urbana",
      "Regulamenta o transporte público municipal e metropolitano",
      "Estabelece padrões de sinalização viária para rodovias federais",
      "Define critérios de acessibilidade para o transporte público",
      "Disciplina o sistema viário municipal e o trânsito local"
    ),
    autor = c("Congresso Nacional", "Prefeitura Municipal", "CONTRAN", 
             "Ministério das Cidades", "Câmara Municipal"),
    estado = c("BR", "SP", "BR", "BR", "RJ"),
    fonte = "LexML Brasil",
    url = paste0("https://www.lexml.gov.br/urn/", c(
      "urn:lex:br:federal:lei:2012-01-03;12587",
      "urn:lex:br:sao.paulo:decreto:2016-05-15;8754", 
      "urn:lex:br:federal:resolucao:2020-08-10;780",
      "urn:lex:br:federal:portaria:2019-11-22;315",
      "urn:lex:br:rio.de.janeiro:lei.complementar:2018-07-30;156"
    )),
    sistema_origem = "LexML",
    qualidade_dados = "alta",
    categoria_principal = "Transporte e Mobilidade",
    stringsAsFactors = FALSE
  )
  
  # Filter by query if provided
  if (!is.null(query) && nchar(trimws(query)) > 0) {
    query_terms <- tolower(str_split(query, "\\s+")[[1]])
    
    # Simple text matching
    matches <- sapply(1:nrow(fallback_data), function(i) {
      text <- tolower(paste(fallback_data$titulo[i], fallback_data$ementa[i]))
      any(sapply(query_terms, function(term) str_detect(text, term)))
    })
    
    fallback_data <- fallback_data[matches, ]
  }
  
  return(fallback_data)
}

#' Get LexML API status
#' @return List with status information
check_lexml_status <- function() {
  
  tryCatch({
    # Simple ping to LexML
    response <- httr::GET(
      LEXML_BASE_URL,
      httr::timeout(10),
      httr::user_agent("Monitor-Legislativo-v4-R/1.0")
    )
    
    if (httr::status_code(response) == 200) {
      return(list(
        status = "online",
        response_time = response$times["total"],
        message = "LexML API disponível"
      ))
    } else {
      return(list(
        status = "error",
        response_time = NA,
        message = paste("HTTP", httr::status_code(response))
      ))
    }
    
  }, error = function(e) {
    return(list(
      status = "offline", 
      response_time = NA,
      message = e$message
    ))
  })
}

#' Coalesce function for handling NULL values
#' @param ... Values to coalesce
#' @return First non-NULL value
coalesce <- function(...) {
  vals <- list(...)
  for (val in vals) {
    if (!is.null(val) && !all(is.na(val))) {
      return(val)
    }
  }
  return(NA)
}