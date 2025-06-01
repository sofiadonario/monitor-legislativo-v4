# ============================================================================
# EXTERNAL API INTEGRATION WITH ERROR HANDLING - SPRINT 4B
# ============================================================================
#
# Robust API integration system for Brazilian government data sources
# Handles LexML, IBGE, and other transparency portal APIs
# Features comprehensive error handling, retry logic, and monitoring
#
# Features:
# - LexML API integration with Brazilian legislative standards
# - IBGE API integration for geographic and demographic data
# - Transparency portal API connections
# - Circuit breaker pattern for API failures
# - Exponential backoff retry mechanisms
# - Rate limiting and quota management
# - API health monitoring and status tracking
# - Graceful degradation when services are unavailable
# - Caching system for API responses
# - API response validation and sanitization
#
# Author: Legislative Data Science Team
# Version: 4B.1.0 (Sprint 4B)
# Updated: 2025-01-20
# ============================================================================

# Load required packages
required_packages <- c(
  "httr", "jsonlite", "xml2", "curl", "RCurl",
  "dplyr", "stringr", "lubridate", "digest", 
  "memoise", "cachem"
)

missing_packages <- c()
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("⚠️ WARNING: Missing API integration packages:", paste(missing_packages, collapse = ", "), "\n")
}

# Load available packages
suppressPackageStartupMessages({
  if (requireNamespace("httr", quietly = TRUE)) library(httr)
  if (requireNamespace("jsonlite", quietly = TRUE)) library(jsonlite)
  if (requireNamespace("xml2", quietly = TRUE)) library(xml2)
  if (requireNamespace("dplyr", quietly = TRUE)) library(dplyr)
  if (requireNamespace("stringr", quietly = TRUE)) library(stringr)
  if (requireNamespace("lubridate", quietly = TRUE)) library(lubridate)
  if (requireNamespace("digest", quietly = TRUE)) library(digest)
  if (requireNamespace("memoise", quietly = TRUE)) library(memoise)
  if (requireNamespace("cachem", quietly = TRUE)) library(cachem)
})

# ============================================================================
# API CONFIGURATION
# ============================================================================

API_CONFIG <- list(
  # LexML Configuration (Brazilian Legislative XML)
  lexml = list(
    base_url = "https://www.lexml.gov.br",
    endpoints = list(
      search = "/busca",
      document = "/documento",
      metadata = "/metadados"
    ),
    rate_limit = 60,          # requests per minute
    timeout = 30,             # seconds
    max_retries = 3,
    backoff_factor = 2,
    formats = c("xml", "json", "rdf"),
    user_agent = "Brazilian-Legislative-Monitor/4.0",
    headers = list(
      "Accept" = "application/json,application/xml",
      "Accept-Language" = "pt-BR,pt;q=0.9",
      "Accept-Charset" = "UTF-8"
    )
  ),
  
  # IBGE Configuration (Brazilian Institute of Geography and Statistics)
  ibge = list(
    base_url = "https://servicodados.ibge.gov.br",
    endpoints = list(
      municipalities = "/api/v1/localidades/municipios",
      states = "/api/v1/localidades/estados",
      regions = "/api/v1/localidades/regioes",
      districts = "/api/v1/localidades/distritos"
    ),
    rate_limit = 120,         # requests per minute
    timeout = 20,             # seconds
    max_retries = 3,
    backoff_factor = 1.5,
    user_agent = "Brazilian-Legislative-Monitor/4.0"
  ),
  
  # Transparency Portal Configuration
  transparency = list(
    base_url = "https://portaldatransparencia.gov.br",
    endpoints = list(
      contracts = "/api-de-dados/contratos",
      agreements = "/api-de-dados/convenios",
      transfers = "/api-de-dados/transferencias"
    ),
    rate_limit = 30,          # requests per minute
    timeout = 45,             # seconds
    max_retries = 5,
    backoff_factor = 2,
    user_agent = "Brazilian-Legislative-Monitor/4.0"
  ),
  
  # General Settings
  general = list(
    cache_duration = 3600,    # 1 hour in seconds
    circuit_breaker_threshold = 5,
    circuit_breaker_timeout = 300,  # 5 minutes
    health_check_interval = 60,     # 1 minute
    max_concurrent_requests = 3,
    connection_pool_size = 10
  )
)

# ============================================================================
# API ERROR HANDLING CLASSES
# ============================================================================

#' API Error Handling and Retry Logic
APIErrorHandler <- R6::R6Class("APIErrorHandler",
  public = list(
    max_retries = 3,
    backoff_factor = 2,
    retry_on_status = c(429, 500, 502, 503, 504),
    
    initialize = function(max_retries = 3, backoff_factor = 2) {
      self$max_retries <- max_retries
      self$backoff_factor <- backoff_factor
      log_etl("INFO", sprintf("API error handler initialized (retries: %d, backoff: %s)", 
                             max_retries, backoff_factor), "API_ERROR_HANDLER")
    },
    
    execute_with_retry = function(api_call_func, ..., context = "API") {
      last_error <- NULL
      
      for (attempt in 1:self$max_retries) {
        tryCatch({
          result <- api_call_func(...)
          
          if (self$is_successful_response(result)) {
            if (attempt > 1) {
              log_etl("INFO", sprintf("API call succeeded on attempt %d", attempt), context)
            }
            return(result)
          } else {
            # Handle HTTP errors
            status_code <- self$extract_status_code(result)
            if (status_code %in% self$retry_on_status) {
              if (attempt < self$max_retries) {
                wait_time <- self$calculate_backoff_delay(attempt)
                log_etl("WARN", sprintf("API error %d, retrying in %.1f seconds (attempt %d/%d)", 
                                       status_code, wait_time, attempt, self$max_retries), context)
                Sys.sleep(wait_time)
                next
              } else {
                last_error <- sprintf("API error %d after %d attempts", status_code, self$max_retries)
              }
            } else {
              last_error <- sprintf("Non-retryable API error: %d", status_code)
              break
            }
          }
          
        }, error = function(e) {
          last_error <<- e$message
          if (attempt < self$max_retries) {
            wait_time <- self$calculate_backoff_delay(attempt)
            log_etl("ERROR", sprintf("API call failed: %s, retrying in %.1f seconds (attempt %d/%d)", 
                                    e$message, wait_time, attempt, self$max_retries), context)
            Sys.sleep(wait_time)
          } else {
            log_etl("ERROR", sprintf("API call failed after %d attempts: %s", 
                                   self$max_retries, e$message), context)
          }
        })
      }
      
      # All retries exhausted
      stop(paste("API call failed after", self$max_retries, "attempts:", last_error))
    },
    
    is_successful_response = function(response) {
      if (is.null(response)) return(FALSE)
      
      if (inherits(response, "response")) {
        return(httr::status_code(response) >= 200 && httr::status_code(response) < 300)
      }
      
      return(TRUE)  # Assume success for non-httr responses
    },
    
    extract_status_code = function(response) {
      if (inherits(response, "response")) {
        return(httr::status_code(response))
      }
      return(200)  # Default to success
    },
    
    calculate_backoff_delay = function(attempt) {
      # Exponential backoff with jitter
      base_delay <- self$backoff_factor ^ (attempt - 1)
      jitter <- runif(1, 0.8, 1.2)  # Add ±20% jitter
      return(base_delay * jitter)
    }
  )
)

#' Circuit Breaker Pattern for API Protection
APICircuitBreaker <- R6::R6Class("APICircuitBreaker",
  public = list(
    failure_threshold = 5,
    timeout_duration = 300,   # 5 minutes
    failure_count = 0,
    last_failure_time = NULL,
    state = "CLOSED",         # CLOSED, OPEN, HALF_OPEN
    
    initialize = function(failure_threshold = 5, timeout_duration = 300) {
      self$failure_threshold <- failure_threshold
      self$timeout_duration <- timeout_duration
      log_etl("INFO", sprintf("Circuit breaker initialized (threshold: %d, timeout: %ds)", 
                             failure_threshold, timeout_duration), "CIRCUIT_BREAKER")
    },
    
    can_proceed = function() {
      current_time <- Sys.time()
      
      if (self$state == "CLOSED") {
        return(TRUE)
      }
      
      if (self$state == "OPEN") {
        if (is.null(self$last_failure_time) || 
            difftime(current_time, self$last_failure_time, units = "secs") >= self$timeout_duration) {
          self$state <- "HALF_OPEN"
          log_etl("INFO", "Circuit breaker transitioning to HALF_OPEN", "CIRCUIT_BREAKER")
          return(TRUE)
        }
        return(FALSE)
      }
      
      if (self$state == "HALF_OPEN") {
        return(TRUE)
      }
      
      return(FALSE)
    },
    
    record_success = function() {
      if (self$state == "HALF_OPEN") {
        self$state <- "CLOSED"
        self$failure_count <- 0
        log_etl("INFO", "Circuit breaker reset to CLOSED state", "CIRCUIT_BREAKER")
      } else if (self$state == "CLOSED") {
        self$failure_count <- max(0, self$failure_count - 1)  # Gradual recovery
      }
    },
    
    record_failure = function() {
      self$failure_count <- self$failure_count + 1
      self$last_failure_time <- Sys.time()
      
      if (self$failure_count >= self$failure_threshold) {
        self$state <- "OPEN"
        log_etl("ERROR", sprintf("Circuit breaker OPENED after %d failures", self$failure_count), "CIRCUIT_BREAKER")
      }
    },
    
    get_status = function() {
      list(
        state = self$state,
        failure_count = self$failure_count,
        last_failure_time = self$last_failure_time,
        can_proceed = self$can_proceed()
      )
    }
  )
)

#' Rate Limiter with Token Bucket Algorithm
APIRateLimiter <- R6::R6Class("APIRateLimiter",
  public = list(
    requests_per_minute = 60,
    tokens = 60,
    last_refill = NULL,
    
    initialize = function(requests_per_minute = 60) {
      self$requests_per_minute <- requests_per_minute
      self$tokens <- requests_per_minute
      self$last_refill <- Sys.time()
      log_etl("INFO", sprintf("Rate limiter initialized (%d requests/minute)", 
                             requests_per_minute), "RATE_LIMITER")
    },
    
    can_proceed = function(tokens_needed = 1) {
      self$refill_tokens()
      return(self$tokens >= tokens_needed)
    },
    
    consume_tokens = function(tokens_needed = 1) {
      if (self$can_proceed(tokens_needed)) {
        self$tokens <- self$tokens - tokens_needed
        return(TRUE)
      }
      return(FALSE)
    },
    
    refill_tokens = function() {
      current_time <- Sys.time()
      time_passed <- as.numeric(difftime(current_time, self$last_refill, units = "secs"))
      
      # Refill tokens based on time passed
      tokens_to_add <- (time_passed / 60) * self$requests_per_minute
      self$tokens <- min(self$requests_per_minute, self$tokens + tokens_to_add)
      self$last_refill <- current_time
    },
    
    wait_for_tokens = function(tokens_needed = 1) {
      while (!self$can_proceed(tokens_needed)) {
        wait_time <- (tokens_needed - self$tokens) * (60 / self$requests_per_minute)
        log_etl("DEBUG", sprintf("Rate limit reached, waiting %.1f seconds", wait_time), "RATE_LIMITER")
        Sys.sleep(min(wait_time, 5))  # Wait max 5 seconds at a time
        self$refill_tokens()
      }
      self$consume_tokens(tokens_needed)
    }
  )
)

# ============================================================================
# LEXML API INTEGRATION
# ============================================================================

#' LexML API Client for Brazilian Legislative Data
LexMLAPIClient <- R6::R6Class("LexMLAPIClient",
  public = list(
    base_url = NULL,
    error_handler = NULL,
    circuit_breaker = NULL,
    rate_limiter = NULL,
    cache = NULL,
    
    initialize = function() {
      self$base_url <- API_CONFIG$lexml$base_url
      self$error_handler <- APIErrorHandler$new(
        API_CONFIG$lexml$max_retries, 
        API_CONFIG$lexml$backoff_factor
      )
      self$circuit_breaker <- APICircuitBreaker$new(
        API_CONFIG$general$circuit_breaker_threshold,
        API_CONFIG$general$circuit_breaker_timeout
      )
      self$rate_limiter <- APIRateLimiter$new(API_CONFIG$lexml$rate_limit)
      
      # Initialize cache
      if (requireNamespace("cachem", quietly = TRUE)) {
        self$cache <- cachem::cache_mem(max_size = 100 * 1024^2)  # 100 MB
      }
      
      log_etl("INFO", "LexML API client initialized", "LEXML_API")
    },
    
    search_documents = function(query_params = list(), max_results = 1000) {
      if (!self$circuit_breaker$can_proceed()) {
        log_etl("ERROR", "LexML API circuit breaker is OPEN", "LEXML_API")
        return(NULL)
      }
      
      # Create cache key
      cache_key <- digest::digest(list(action = "search", params = query_params), algo = "md5")
      
      # Check cache first
      if (!is.null(self$cache)) {
        cached_result <- self$cache$get(cache_key)
        if (!is.null(cached_result)) {
          log_etl("DEBUG", "Returning cached LexML search results", "LEXML_API")
          return(cached_result)
        }
      }
      
      tryCatch({
        results <- self$error_handler$execute_with_retry(
          self$execute_search_request,
          query_params = query_params,
          max_results = max_results,
          context = "LEXML_API"
        )
        
        self$circuit_breaker$record_success()
        
        # Cache results
        if (!is.null(self$cache) && !is.null(results)) {
          self$cache$set(cache_key, results, ttl = API_CONFIG$general$cache_duration)
        }
        
        return(results)
        
      }, error = function(e) {
        self$circuit_breaker$record_failure()
        log_etl("ERROR", sprintf("LexML search failed: %s", e$message), "LEXML_API")
        return(NULL)
      })
    },
    
    execute_search_request = function(query_params, max_results) {
      self$rate_limiter$wait_for_tokens()
      
      # Build request URL
      search_url <- paste0(self$base_url, API_CONFIG$lexml$endpoints$search)
      
      # Default parameters
      default_params <- list(
        formato = "json",
        limite = min(100, max_results),
        inicio = 0
      )
      
      # Merge with user parameters
      final_params <- modifyList(default_params, query_params)
      
      log_etl("DEBUG", sprintf("LexML API request: %s", search_url), "LEXML_API")
      
      # Make API request
      response <- httr::GET(
        url = search_url,
        query = final_params,
        httr::timeout(API_CONFIG$lexml$timeout),
        httr::add_headers(
          "User-Agent" = API_CONFIG$lexml$user_agent,
          .headers = API_CONFIG$lexml$headers
        ),
        httr::config(followlocation = TRUE)
      )
      
      # Check response
      if (httr::status_code(response) != 200) {
        stop(sprintf("LexML API error: HTTP %d", httr::status_code(response)))
      }
      
      # Parse response
      content_text <- httr::content(response, "text", encoding = "UTF-8")
      
      if (nchar(content_text) == 0) {
        log_etl("WARN", "Empty response from LexML API", "LEXML_API")
        return(NULL)
      }
      
      # Parse JSON
      parsed_data <- jsonlite::fromJSON(content_text, flatten = TRUE)
      
      # Extract documents
      documents <- self$extract_documents_from_response(parsed_data)
      
      log_etl("INFO", sprintf("LexML API returned %d documents", nrow(documents)), "LEXML_API")
      
      return(documents)
    },
    
    extract_documents_from_response = function(parsed_data) {
      if (is.null(parsed_data)) return(data.frame())
      
      # Handle different response structures
      docs_data <- NULL
      
      if ("documentos" %in% names(parsed_data)) {
        docs_data <- parsed_data$documentos
      } else if ("items" %in% names(parsed_data)) {
        docs_data <- parsed_data$items
      } else if ("results" %in% names(parsed_data)) {
        docs_data <- parsed_data$results
      } else if (is.data.frame(parsed_data)) {
        docs_data <- parsed_data
      }
      
      if (is.null(docs_data) || nrow(docs_data) == 0) {
        return(data.frame())
      }
      
      # Standardize document structure
      standardized <- data.frame(
        titulo = self$safe_extract(docs_data, "titulo"),
        tipo = self$safe_extract(docs_data, "tipo"),
        data = self$parse_dates(self$safe_extract(docs_data, c("data", "dataPublicacao", "dataPromulgacao"))),
        autoridade = self$safe_extract(docs_data, c("autoridade", "orgao", "autor")),
        estado = self$extract_state_from_locality(self$safe_extract(docs_data, c("localidade", "jurisdicao"))),
        municipio = self$extract_municipality_from_locality(self$safe_extract(docs_data, c("localidade", "jurisdicao"))),
        ementa = self$safe_extract(docs_data, c("ementa", "resumo", "descricao")),
        url = self$safe_extract(docs_data, c("url", "link", "uri")),
        urn = self$safe_extract(docs_data, "urn"),
        assuntos = self$extract_subjects(docs_data),
        categoria = self$categorize_document(self$safe_extract(docs_data, "tipo")),
        fonte = "LexML",
        data_extracao = Sys.time(),
        stringsAsFactors = FALSE
      )
      
      return(standardized)
    },
    
    safe_extract = function(data, field_names) {
      if (is.character(field_names) && length(field_names) == 1) {
        field_names <- c(field_names)
      }
      
      for (field in field_names) {
        if (field %in% names(data)) {
          values <- data[[field]]
          if (!is.null(values) && length(values) > 0) {
            return(as.character(values))
          }
        }
      }
      
      return(rep("", nrow(data)))
    },
    
    parse_dates = function(date_strings) {
      if (is.null(date_strings) || length(date_strings) == 0) {
        return(rep(NA, 0))
      }
      
      parsed_dates <- rep(NA, length(date_strings))
      
      date_formats <- c(
        "%Y-%m-%d",     # ISO format
        "%d/%m/%Y",     # Brazilian format
        "%d-%m-%Y",     # Alternative Brazilian
        "%Y/%m/%d",     # Alternative ISO
        "%d.%m.%Y"      # Dotted format
      )
      
      for (i in seq_along(date_strings)) {
        if (is.na(date_strings[i]) || date_strings[i] == "") next
        
        for (fmt in date_formats) {
          tryCatch({
            parsed <- as.Date(date_strings[i], format = fmt)
            if (!is.na(parsed)) {
              parsed_dates[i] <- parsed
              break
            }
          }, error = function(e) NULL)
        }
      }
      
      return(parsed_dates)
    },
    
    extract_state_from_locality = function(localities) {
      if (is.null(localities)) return(rep("", 0))
      
      states <- character(length(localities))
      
      # Brazilian state patterns
      state_patterns <- c(
        "AC" = c("Acre", "AC"),
        "AL" = c("Alagoas", "AL"),
        "AP" = c("Amapá", "AP"),
        "AM" = c("Amazonas", "AM"),
        "BA" = c("Bahia", "BA"),
        "CE" = c("Ceará", "CE"),
        "DF" = c("Distrito Federal", "DF"),
        "ES" = c("Espírito Santo", "ES"),
        "GO" = c("Goiás", "GO"),
        "MA" = c("Maranhão", "MA"),
        "MT" = c("Mato Grosso", "MT"),
        "MS" = c("Mato Grosso do Sul", "MS"),
        "MG" = c("Minas Gerais", "MG"),
        "PA" = c("Pará", "PA"),
        "PB" = c("Paraíba", "PB"),
        "PR" = c("Paraná", "PR"),
        "PE" = c("Pernambuco", "PE"),
        "PI" = c("Piauí", "PI"),
        "RJ" = c("Rio de Janeiro", "RJ"),
        "RN" = c("Rio Grande do Norte", "RN"),
        "RS" = c("Rio Grande do Sul", "RS"),
        "RO" = c("Rondônia", "RO"),
        "RR" = c("Roraima", "RR"),
        "SC" = c("Santa Catarina", "SC"),
        "SP" = c("São Paulo", "SP"),
        "SE" = c("Sergipe", "SE"),
        "TO" = c("Tocantins", "TO")
      )
      
      for (i in seq_along(localities)) {
        if (is.na(localities[i]) || localities[i] == "") {
          states[i] <- ""
          next
        }
        
        locality_upper <- toupper(localities[i])
        
        for (state_abbr in names(state_patterns)) {
          patterns <- state_patterns[[state_abbr]]
          for (pattern in patterns) {
            if (grepl(toupper(pattern), locality_upper)) {
              states[i] <- state_abbr
              break
            }
          }
          if (states[i] != "") break
        }
      }
      
      return(states)
    },
    
    extract_municipality_from_locality = function(localities) {
      if (is.null(localities)) return(rep("", 0))
      
      municipalities <- character(length(localities))
      
      for (i in seq_along(localities)) {
        if (is.na(localities[i]) || localities[i] == "") {
          municipalities[i] <- ""
          next
        }
        
        # Extract municipality name (usually first part before state)
        parts <- strsplit(localities[i], "[,-/]")[[1]]
        if (length(parts) > 0) {
          municipalities[i] <- stringr::str_trim(parts[1])
        }
      }
      
      return(municipalities)
    },
    
    extract_subjects = function(data) {
      subject_fields <- c("assuntos", "descritores", "palavras_chave", "temas")
      
      subjects <- rep("", nrow(data))
      
      for (field in subject_fields) {
        if (field %in% names(data)) {
          field_data <- data[[field]]
          
          if (is.list(field_data)) {
            subjects <- sapply(field_data, function(x) {
              if (is.character(x) && length(x) > 0) {
                return(paste(x, collapse = "; "))
              }
              return("")
            })
          } else if (is.character(field_data)) {
            subjects <- field_data
          }
          
          if (any(subjects != "")) break
        }
      }
      
      return(subjects)
    },
    
    categorize_document = function(tipos) {
      if (is.null(tipos)) return(rep("Outros", 0))
      
      categories <- character(length(tipos))
      
      for (i in seq_along(tipos)) {
        if (is.na(tipos[i]) || tipos[i] == "") {
          categories[i] <- "Outros"
          next
        }
        
        tipo_lower <- tolower(tipos[i])
        
        if (grepl("lei|decreto|portaria|resolução|instrução|medida provisória", tipo_lower)) {
          categories[i] <- "Legislação"
        } else if (grepl("acórdão|decisão|sentença|súmula", tipo_lower)) {
          categories[i] <- "Jurisprudência"
        } else if (grepl("parecer|estudo|relatório|análise", tipo_lower)) {
          categories[i] <- "Doutrina"
        } else if (grepl("projeto|proposta|emenda", tipo_lower)) {
          categories[i] <- "Proposições"
        } else {
          categories[i] <- "Outros"
        }
      }
      
      return(categories)
    },
    
    get_document_by_urn = function(urn) {
      if (!self$circuit_breaker$can_proceed()) {
        log_etl("ERROR", "LexML API circuit breaker is OPEN", "LEXML_API")
        return(NULL)
      }
      
      cache_key <- digest::digest(list(action = "document", urn = urn), algo = "md5")
      
      if (!is.null(self$cache)) {
        cached_result <- self$cache$get(cache_key)
        if (!is.null(cached_result)) {
          return(cached_result)
        }
      }
      
      tryCatch({
        result <- self$error_handler$execute_with_retry(
          self$execute_document_request,
          urn = urn,
          context = "LEXML_API"
        )
        
        self$circuit_breaker$record_success()
        
        if (!is.null(self$cache) && !is.null(result)) {
          self$cache$set(cache_key, result, ttl = API_CONFIG$general$cache_duration)
        }
        
        return(result)
        
      }, error = function(e) {
        self$circuit_breaker$record_failure()
        log_etl("ERROR", sprintf("LexML document fetch failed: %s", e$message), "LEXML_API")
        return(NULL)
      })
    },
    
    execute_document_request = function(urn) {
      self$rate_limiter$wait_for_tokens()
      
      document_url <- paste0(self$base_url, API_CONFIG$lexml$endpoints$document, "/", urn)
      
      response <- httr::GET(
        url = document_url,
        httr::timeout(API_CONFIG$lexml$timeout),
        httr::add_headers(
          "User-Agent" = API_CONFIG$lexml$user_agent,
          .headers = API_CONFIG$lexml$headers
        )
      )
      
      if (httr::status_code(response) != 200) {
        stop(sprintf("LexML document API error: HTTP %d", httr::status_code(response)))
      }
      
      content_text <- httr::content(response, "text", encoding = "UTF-8")
      parsed_data <- jsonlite::fromJSON(content_text, flatten = TRUE)
      
      return(parsed_data)
    },
    
    health_check = function() {
      tryCatch({
        test_response <- httr::GET(
          url = self$base_url,
          httr::timeout(10),
          httr::add_headers("User-Agent" = API_CONFIG$lexml$user_agent)
        )
        
        is_healthy <- httr::status_code(test_response) < 500
        
        return(list(
          service = "LexML",
          healthy = is_healthy,
          status_code = httr::status_code(test_response),
          circuit_breaker_state = self$circuit_breaker$get_status()$state,
          last_check = Sys.time()
        ))
        
      }, error = function(e) {
        return(list(
          service = "LexML",
          healthy = FALSE,
          error = e$message,
          circuit_breaker_state = self$circuit_breaker$get_status()$state,
          last_check = Sys.time()
        ))
      })
    }
  )
)

# ============================================================================
# IBGE API INTEGRATION
# ============================================================================

#' IBGE API Client for Geographic Data
IBGEAPIClient <- R6::R6Class("IBGEAPIClient",
  public = list(
    base_url = NULL,
    error_handler = NULL,
    circuit_breaker = NULL,
    rate_limiter = NULL,
    cache = NULL,
    
    initialize = function() {
      self$base_url <- API_CONFIG$ibge$base_url
      self$error_handler <- APIErrorHandler$new(
        API_CONFIG$ibge$max_retries,
        API_CONFIG$ibge$backoff_factor
      )
      self$circuit_breaker <- APICircuitBreaker$new()
      self$rate_limiter <- APIRateLimiter$new(API_CONFIG$ibge$rate_limit)
      
      if (requireNamespace("cachem", quietly = TRUE)) {
        self$cache <- cachem::cache_mem(max_size = 50 * 1024^2)  # 50 MB
      }
      
      log_etl("INFO", "IBGE API client initialized", "IBGE_API")
    },
    
    get_states = function(region_id = NULL) {
      if (!self$circuit_breaker$can_proceed()) {
        log_etl("ERROR", "IBGE API circuit breaker is OPEN", "IBGE_API")
        return(NULL)
      }
      
      cache_key <- digest::digest(list(action = "states", region = region_id), algo = "md5")
      
      if (!is.null(self$cache)) {
        cached_result <- self$cache$get(cache_key)
        if (!is.null(cached_result)) {
          return(cached_result)
        }
      }
      
      tryCatch({
        result <- self$error_handler$execute_with_retry(
          self$execute_states_request,
          region_id = region_id,
          context = "IBGE_API"
        )
        
        self$circuit_breaker$record_success()
        
        if (!is.null(self$cache) && !is.null(result)) {
          self$cache$set(cache_key, result, ttl = API_CONFIG$general$cache_duration * 24)  # Cache states for 24 hours
        }
        
        return(result)
        
      }, error = function(e) {
        self$circuit_breaker$record_failure()
        log_etl("ERROR", sprintf("IBGE states request failed: %s", e$message), "IBGE_API")
        return(NULL)
      })
    },
    
    execute_states_request = function(region_id = NULL) {
      self$rate_limiter$wait_for_tokens()
      
      states_url <- paste0(self$base_url, API_CONFIG$ibge$endpoints$states)
      
      params <- list()
      if (!is.null(region_id)) {
        params$regiao <- region_id
      }
      
      response <- httr::GET(
        url = states_url,
        query = params,
        httr::timeout(API_CONFIG$ibge$timeout),
        httr::add_headers("User-Agent" = API_CONFIG$ibge$user_agent)
      )
      
      if (httr::status_code(response) != 200) {
        stop(sprintf("IBGE states API error: HTTP %d", httr::status_code(response)))
      }
      
      content_text <- httr::content(response, "text", encoding = "UTF-8")
      parsed_data <- jsonlite::fromJSON(content_text, flatten = TRUE)
      
      # Standardize state data
      if (is.data.frame(parsed_data) && nrow(parsed_data) > 0) {
        standardized <- data.frame(
          codigo_ibge = parsed_data$id,
          nome = parsed_data$nome,
          sigla = parsed_data$sigla,
          regiao_codigo = sapply(parsed_data$regiao, function(x) ifelse(is.null(x$id), NA, x$id)),
          regiao_nome = sapply(parsed_data$regiao, function(x) ifelse(is.null(x$nome), NA, x$nome)),
          regiao_sigla = sapply(parsed_data$regiao, function(x) ifelse(is.null(x$sigla), NA, x$sigla)),
          data_atualizacao = Sys.time(),
          stringsAsFactors = FALSE
        )
        
        return(standardized)
      }
      
      return(NULL)
    },
    
    get_municipalities = function(state_id = NULL) {
      if (!self$circuit_breaker$can_proceed()) {
        log_etl("ERROR", "IBGE API circuit breaker is OPEN", "IBGE_API")
        return(NULL)
      }
      
      cache_key <- digest::digest(list(action = "municipalities", state = state_id), algo = "md5")
      
      if (!is.null(self$cache)) {
        cached_result <- self$cache$get(cache_key)
        if (!is.null(cached_result)) {
          return(cached_result)
        }
      }
      
      tryCatch({
        result <- self$error_handler$execute_with_retry(
          self$execute_municipalities_request,
          state_id = state_id,
          context = "IBGE_API"
        )
        
        self$circuit_breaker$record_success()
        
        if (!is.null(self$cache) && !is.null(result)) {
          self$cache$set(cache_key, result, ttl = API_CONFIG$general$cache_duration * 12)  # Cache municipalities for 12 hours
        }
        
        return(result)
        
      }, error = function(e) {
        self$circuit_breaker$record_failure()
        log_etl("ERROR", sprintf("IBGE municipalities request failed: %s", e$message), "IBGE_API")
        return(NULL)
      })
    },
    
    execute_municipalities_request = function(state_id = NULL) {
      self$rate_limiter$wait_for_tokens()
      
      municipalities_url <- paste0(self$base_url, API_CONFIG$ibge$endpoints$municipalities)
      
      params <- list()
      if (!is.null(state_id)) {
        municipalities_url <- paste0(municipalities_url, "/", state_id)
      }
      
      response <- httr::GET(
        url = municipalities_url,
        query = params,
        httr::timeout(API_CONFIG$ibge$timeout),
        httr::add_headers("User-Agent" = API_CONFIG$ibge$user_agent)
      )
      
      if (httr::status_code(response) != 200) {
        stop(sprintf("IBGE municipalities API error: HTTP %d", httr::status_code(response)))
      }
      
      content_text <- httr::content(response, "text", encoding = "UTF-8")
      parsed_data <- jsonlite::fromJSON(content_text, flatten = TRUE)
      
      # Standardize municipality data
      if (is.data.frame(parsed_data) && nrow(parsed_data) > 0) {
        standardized <- data.frame(
          codigo_ibge = parsed_data$id,
          nome = parsed_data$nome,
          estado_codigo = sapply(parsed_data$microrregiao.mesorregiao.UF.id, function(x) x),
          estado_nome = sapply(parsed_data$microrregiao.mesorregiao.UF.nome, function(x) x),
          estado_sigla = sapply(parsed_data$microrregiao.mesorregiao.UF.sigla, function(x) x),
          microrregiao_codigo = sapply(parsed_data$microrregiao, function(x) x$id),
          microrregiao_nome = sapply(parsed_data$microrregiao, function(x) x$nome),
          mesorregiao_codigo = sapply(parsed_data$microrregiao.mesorregiao, function(x) x$id),
          mesorregiao_nome = sapply(parsed_data$microrregiao.mesorregiao, function(x) x$nome),
          data_atualizacao = Sys.time(),
          stringsAsFactors = FALSE
        )
        
        return(standardized)
      }
      
      return(NULL)
    },
    
    health_check = function() {
      tryCatch({
        test_response <- httr::GET(
          url = paste0(self$base_url, API_CONFIG$ibge$endpoints$states, "?limit=1"),
          httr::timeout(10),
          httr::add_headers("User-Agent" = API_CONFIG$ibge$user_agent)
        )
        
        is_healthy <- httr::status_code(test_response) < 500
        
        return(list(
          service = "IBGE",
          healthy = is_healthy,
          status_code = httr::status_code(test_response),
          circuit_breaker_state = self$circuit_breaker$get_status()$state,
          last_check = Sys.time()
        ))
        
      }, error = function(e) {
        return(list(
          service = "IBGE",
          healthy = FALSE,
          error = e$message,
          circuit_breaker_state = self$circuit_breaker$get_status()$state,
          last_check = Sys.time()
        ))
      })
    }
  )
)

# ============================================================================
# API INTEGRATION ORCHESTRATOR
# ============================================================================

#' Main API Integration Orchestrator
APIOrchestrator <- R6::R6Class("APIOrchestrator",
  public = list(
    lexml_client = NULL,
    ibge_client = NULL,
    health_status = list(),
    
    initialize = function() {
      self$lexml_client <- LexMLAPIClient$new()
      self$ibge_client <- IBGEAPIClient$new()
      
      log_etl("INFO", "API orchestrator initialized", "API_ORCHESTRATOR")
    },
    
    fetch_legislative_documents = function(query_params = list(), max_results = 1000, enrich_with_geo = TRUE) {
      log_etl("INFO", sprintf("Fetching legislative documents (max: %d)", max_results), "API_ORCHESTRATOR")
      
      # Fetch documents from LexML
      documents <- self$lexml_client$search_documents(query_params, max_results)
      
      if (is.null(documents) || nrow(documents) == 0) {
        log_etl("WARN", "No documents retrieved from LexML", "API_ORCHESTRATOR")
        return(NULL)
      }
      
      # Enrich with geographic data if requested
      if (enrich_with_geo) {
        documents <- self$enrich_documents_with_geography(documents)
      }
      
      log_etl("INFO", sprintf("Legislative document fetch complete: %d documents", nrow(documents)), "API_ORCHESTRATOR")
      return(documents)
    },
    
    enrich_documents_with_geography = function(documents) {
      if (is.null(documents) || nrow(documents) == 0) return(documents)
      
      log_etl("INFO", "Enriching documents with geographic data", "API_ORCHESTRATOR")
      
      # Get states reference data
      states_data <- self$ibge_client$get_states()
      
      if (!is.null(states_data)) {
        # Merge state information
        documents <- merge(documents, states_data, 
                          by.x = "estado", by.y = "sigla", 
                          all.x = TRUE, suffixes = c("", "_ibge"))
      }
      
      # Enrich municipalities for documents that have municipality information
      documents_with_municipalities <- documents[!is.na(documents$municipio) & documents$municipio != "", ]
      
      if (nrow(documents_with_municipalities) > 0) {
        unique_states <- unique(documents_with_municipalities$estado)
        
        for (state in unique_states) {
          if (is.na(state) || state == "") next
          
          state_municipalities <- self$ibge_client$get_municipalities(state)
          
          if (!is.null(state_municipalities)) {
            state_docs_indices <- which(documents$estado == state & 
                                       !is.na(documents$municipio) & 
                                       documents$municipio != "")
            
            for (idx in state_docs_indices) {
              municipality_name <- documents$municipio[idx]
              
              # Fuzzy match municipality name
              if (requireNamespace("stringdist", quietly = TRUE)) {
                distances <- stringdist::stringdist(
                  tolower(municipality_name),
                  tolower(state_municipalities$nome),
                  method = "jw"
                )
                
                best_match_idx <- which.min(distances)
                if (distances[best_match_idx] < 0.3) {
                  documents$municipio_ibge_codigo[idx] <- state_municipalities$codigo_ibge[best_match_idx]
                  documents$municipio_ibge_nome[idx] <- state_municipalities$nome[best_match_idx]
                }
              }
            }
          }
        }
      }
      
      return(documents)
    },
    
    run_health_checks = function() {
      log_etl("INFO", "Running API health checks", "API_ORCHESTRATOR")
      
      # Check LexML API health
      lexml_health <- self$lexml_client$health_check()
      
      # Check IBGE API health
      ibge_health <- self$ibge_client$health_check()
      
      # Store health status
      self$health_status <- list(
        lexml = lexml_health,
        ibge = ibge_health,
        last_check = Sys.time()
      )
      
      # Log health status
      overall_healthy <- lexml_health$healthy && ibge_health$healthy
      
      if (overall_healthy) {
        log_etl("INFO", "All APIs are healthy", "API_ORCHESTRATOR")
      } else {
        unhealthy_apis <- c()
        if (!lexml_health$healthy) unhealthy_apis <- c(unhealthy_apis, "LexML")
        if (!ibge_health$healthy) unhealthy_apis <- c(unhealthy_apis, "IBGE")
        
        log_etl("WARN", sprintf("Unhealthy APIs: %s", paste(unhealthy_apis, collapse = ", ")), "API_ORCHESTRATOR")
      }
      
      return(self$health_status)
    },
    
    get_api_status_summary = function() {
      if (length(self$health_status) == 0) {
        self$run_health_checks()
      }
      
      return(list(
        overall_healthy = self$health_status$lexml$healthy && self$health_status$ibge$healthy,
        services = list(
          lexml = list(
            healthy = self$health_status$lexml$healthy,
            circuit_breaker_state = self$health_status$lexml$circuit_breaker_state
          ),
          ibge = list(
            healthy = self$health_status$ibge$healthy,
            circuit_breaker_state = self$health_status$ibge$circuit_breaker_state
          )
        ),
        last_health_check = self$health_status$last_check
      ))
    }
  )
)

# ============================================================================
# EXPORTS AND INITIALIZATION
# ============================================================================

# Global API orchestrator
api_orchestrator <- NULL

initialize_api_integration <- function() {
  cat("🌐 Initializing External API Integration System...\n")
  
  tryCatch({
    api_orchestrator <<- APIOrchestrator$new()
    
    # Run initial health checks
    api_orchestrator$run_health_checks()
    
    cat("✅ API integration system initialized successfully\n")
    cat("🔧 Components loaded:\n")
    cat("   - LexML API Client (Brazilian Legislative XML)\n")
    cat("   - IBGE API Client (Geographic Data)\n")
    cat("   - Rate Limiters and Circuit Breakers\n")
    cat("   - Error Handling and Retry Logic\n")
    cat("   - Response Caching System\n")
    cat("📊 Ready for external API operations\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ API integration initialization failed:", e$message, "\n")
    return(FALSE)
  })
}

# Export main functions
fetch_legislative_data <- function(query_params = list(), max_results = 1000, enrich_geography = TRUE) {
  if (is.null(api_orchestrator)) {
    if (!initialize_api_integration()) {
      return(NULL)
    }
  }
  
  return(api_orchestrator$fetch_legislative_documents(query_params, max_results, enrich_geography))
}

get_api_health_status <- function() {
  if (is.null(api_orchestrator)) {
    return(list(status = "not_initialized"))
  }
  
  return(api_orchestrator$get_api_status_summary())
}

run_api_health_checks <- function() {
  if (is.null(api_orchestrator)) {
    if (!initialize_api_integration()) {
      return(NULL)
    }
  }
  
  return(api_orchestrator$run_health_checks())
}

cat("🌐 External API Integration with Error Handling loaded\n")
cat("📋 Brazilian Government APIs (LexML, IBGE) Ready\n")
cat("🔧 Use initialize_api_integration() to start\n")