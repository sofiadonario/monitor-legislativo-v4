# External Service Integrations for Monitor Legislativo v4
# Government APIs, regulatory agencies, and external data validation

library(httr)
library(jsonlite)
library(xml2)
library(rvest)
library(lubridate)
library(digest)
library(future)
library(promises)

# External services configuration
EXTERNAL_CONFIG <- list(
  government_apis = list(
    camara_deputados = list(
      base_url = "https://dadosabertos.camara.leg.br/api/v2",
      rate_limit = 300,  # requests per hour
      timeout = 30,
      retry_attempts = 3,
      api_key = Sys.getenv("CAMARA_API_KEY", ""),
      enabled = TRUE
    ),
    
    senado_federal = list(
      base_url = "https://legis.senado.leg.br/dadosabertos",
      rate_limit = 200,
      timeout = 30, 
      retry_attempts = 3,
      enabled = TRUE
    ),
    
    planalto = list(
      base_url = "http://www4.planalto.gov.br/legislacao",
      rate_limit = 100,
      timeout = 45,
      retry_attempts = 2,
      enabled = TRUE
    ),
    
    lexml = list(
      base_url = "https://www.lexml.gov.br",
      rate_limit = 500,
      timeout = 60,
      retry_attempts = 3,
      enabled = TRUE
    )
  ),
  
  regulatory_agencies = list(
    antt = list(
      name = "Agência Nacional de Transportes Terrestres",
      base_url = "https://portal.antt.gov.br",
      data_endpoints = list(
        resolutions = "/resolucoes",
        instructions = "/instrucoes-normativas"
      ),
      enabled = TRUE
    ),
    
    antaq = list(
      name = "Agência Nacional de Transportes Aquaviários", 
      base_url = "http://portal.antaq.gov.br",
      data_endpoints = list(
        resolutions = "/index.php/component/content/article/9-uncategorised/2654-resolucoes"
      ),
      enabled = TRUE
    ),
    
    anac = list(
      name = "Agência Nacional de Aviação Civil",
      base_url = "https://www.anac.gov.br",
      data_endpoints = list(
        resolutions = "/assuntos/legislacao/legislacao-1/resolucoes",
        instructions = "/assuntos/legislacao/legislacao-1/instrucoes-normativas"
      ),
      enabled = TRUE
    ),
    
    aneel = list(
      name = "Agência Nacional de Energia Elétrica",
      base_url = "https://www.aneel.gov.br",
      data_endpoints = list(
        resolutions = "/regulacao/resolucoes",
        procedures = "/regulacao/procedimentos"
      ),
      enabled = TRUE
    ),
    
    ans = list(
      name = "Agência Nacional de Saúde Suplementar",
      base_url = "https://www.ans.gov.br",
      data_endpoints = list(
        resolutions = "/aans/noticias-ans/regulamentacao/resolucoes"
      ),
      enabled = TRUE
    ),
    
    anatel = list(
      name = "Agência Nacional de Telecomunicações",
      base_url = "https://www.anatel.gov.br",
      data_endpoints = list(
        resolutions = "/regulamentado/resolucoes",
        acts = "/regulamentado/atos"
      ),
      enabled = TRUE
    ),
    
    anvisa = list(
      name = "Agência Nacional de Vigilância Sanitária",
      base_url = "https://www.anvisa.gov.br",
      data_endpoints = list(
        resolutions = "/regulamentacao/resolucoes",
        instructions = "/regulamentacao/instrucoes-normativas"
      ),
      enabled = TRUE
    ),
    
    ana = list(
      name = "Agência Nacional de Águas",
      base_url = "https://www.ana.gov.br",
      data_endpoints = list(
        resolutions = "/regulacao/resolucoes"
      ),
      enabled = TRUE
    ),
    
    anp = list(
      name = "Agência Nacional do Petróleo",
      base_url = "https://www.gov.br/anp",
      data_endpoints = list(
        resolutions = "/pt-br/assuntos/regulacao-e-outorgas/legislacao/resolucoes-anp"
      ),
      enabled = TRUE
    ),
    
    ancine = list(
      name = "Agência Nacional do Cinema",
      base_url = "https://www.gov.br/ancine",
      data_endpoints = list(
        instructions = "/pt-br/assuntos/regulacao/instrucoes-normativas"
      ),
      enabled = TRUE
    ),
    
    anm = list(
      name = "Agência Nacional de Mineração",
      base_url = "https://www.gov.br/anm",
      data_endpoints = list(
        resolutions = "/pt-br/assuntos/regulacao/resolucoes"
      ),
      enabled = TRUE
    )
  ),
  
  data_validation = list(
    enable_cross_validation = TRUE,
    validation_sources = c("camara", "senado", "lexml"),
    confidence_threshold = 0.8,
    max_validation_attempts = 3
  ),
  
  health_monitoring = list(
    check_interval_minutes = 15,
    failure_threshold = 3,
    recovery_threshold = 2,
    alert_on_failures = TRUE
  ),
  
  caching = list(
    cache_responses = TRUE,
    cache_ttl_hours = 6,
    max_cache_size_mb = 100
  )
)

# Global state for external integrations
external_state <- list(
  service_health = list(),
  request_counts = list(),
  last_health_check = NULL,
  cached_responses = list()
)

#' Initialize external service integrations
#' @param config Optional configuration override
#' @return Initialization status
initialize_external_integrations <- function(config = NULL) {
  if (!is.null(config)) {
    EXTERNAL_CONFIG <<- modifyList(EXTERNAL_CONFIG, config)
  }
  
  log_event("Initializing external service integrations...", "INFO")
  
  # Initialize service health tracking
  external_state$service_health <<- list()
  external_state$request_counts <<- list()
  external_state$cached_responses <<- list()
  
  # Perform initial health checks
  initial_health <- check_all_services_health()
  
  # Start health monitoring if enabled
  if (EXTERNAL_CONFIG$health_monitoring$alert_on_failures) {
    start_health_monitoring()
  }
  
  enabled_services <- sum(sapply(EXTERNAL_CONFIG$government_apis, function(x) x$enabled))
  enabled_agencies <- sum(sapply(EXTERNAL_CONFIG$regulatory_agencies, function(x) x$enabled))
  
  log_event(paste("External integrations initialized:", enabled_services, "government APIs,", enabled_agencies, "regulatory agencies"), "INFO")
  
  return(list(
    status = "success",
    government_apis = enabled_services,
    regulatory_agencies = enabled_agencies,
    health_status = initial_health
  ))
}

#' Integrate with Câmara dos Deputados API
#' @param endpoint API endpoint
#' @param params Query parameters
#' @param use_cache Whether to use caching
#' @return API response data
integrate_camara_api <- function(endpoint, params = NULL, use_cache = TRUE) {
  if (!EXTERNAL_CONFIG$government_apis$camara_deputados$enabled) {
    return(list(error = "Câmara API integration disabled"))
  }
  
  service_config <- EXTERNAL_CONFIG$government_apis$camara_deputados
  
  # Check rate limiting
  if (!check_rate_limit("camara", service_config$rate_limit)) {
    return(list(error = "Rate limit exceeded for Câmara API"))
  }
  
  # Generate cache key
  cache_key <- if (use_cache && EXTERNAL_CONFIG$caching$cache_responses) {
    generate_cache_key("camara", endpoint, params)
  } else {
    NULL
  }
  
  # Check cache first
  if (!is.null(cache_key)) {
    cached_response <- get_cached_response(cache_key)
    if (!is.null(cached_response)) {
      log_event("Cache HIT for Câmara API request", "INFO")
      return(cached_response)
    }
  }
  
  # Build request URL
  url <- paste0(service_config$base_url, endpoint)
  
  # Execute request with retry logic
  response <- execute_api_request(
    url = url,
    params = params,
    timeout = service_config$timeout,
    retry_attempts = service_config$retry_attempts,
    headers = if (service_config$api_key != "") {
      list("Authorization" = paste("Bearer", service_config$api_key))
    } else {
      list()
    }
  )
  
  # Cache successful response
  if (!is.null(cache_key) && response$success) {
    cache_response(cache_key, response$data)
  }
  
  # Track request
  track_service_request("camara", response$success)
  
  return(response$data)
}

#' Integrate with Senado Federal API
#' @param endpoint API endpoint
#' @param params Query parameters
#' @param use_cache Whether to use caching
#' @return API response data
integrate_senado_api <- function(endpoint, params = NULL, use_cache = TRUE) {
  if (!EXTERNAL_CONFIG$government_apis$senado_federal$enabled) {
    return(list(error = "Senado API integration disabled"))
  }
  
  service_config <- EXTERNAL_CONFIG$government_apis$senado_federal
  
  # Check rate limiting
  if (!check_rate_limit("senado", service_config$rate_limit)) {
    return(list(error = "Rate limit exceeded for Senado API"))
  }
  
  # Generate cache key
  cache_key <- if (use_cache && EXTERNAL_CONFIG$caching$cache_responses) {
    generate_cache_key("senado", endpoint, params)
  } else {
    NULL
  }
  
  # Check cache first
  if (!is.null(cache_key)) {
    cached_response <- get_cached_response(cache_key)
    if (!is.null(cached_response)) {
      log_event("Cache HIT for Senado API request", "INFO")
      return(cached_response)
    }
  }
  
  # Build request URL
  url <- paste0(service_config$base_url, endpoint)
  
  # Execute request
  response <- execute_api_request(
    url = url,
    params = params,
    timeout = service_config$timeout,
    retry_attempts = service_config$retry_attempts
  )
  
  # Cache successful response
  if (!is.null(cache_key) && response$success) {
    cache_response(cache_key, response$data)
  }
  
  # Track request
  track_service_request("senado", response$success)
  
  return(response$data)
}

#' Integrate with LexML service
#' @param urn Document URN
#' @param format Response format
#' @param use_cache Whether to use caching
#' @return LexML response data
integrate_lexml_service <- function(urn, format = "json", use_cache = TRUE) {
  if (!EXTERNAL_CONFIG$government_apis$lexml$enabled) {
    return(list(error = "LexML integration disabled"))
  }
  
  service_config <- EXTERNAL_CONFIG$government_apis$lexml
  
  # Check rate limiting
  if (!check_rate_limit("lexml", service_config$rate_limit)) {
    return(list(error = "Rate limit exceeded for LexML"))
  }
  
  # Generate cache key
  cache_key <- if (use_cache && EXTERNAL_CONFIG$caching$cache_responses) {
    generate_cache_key("lexml", urn, list(format = format))
  } else {
    NULL
  }
  
  # Check cache first
  if (!is.null(cache_key)) {
    cached_response <- get_cached_response(cache_key)
    if (!is.null(cached_response)) {
      log_event("Cache HIT for LexML request", "INFO")
      return(cached_response)
    }
  }
  
  # Build request URL
  url <- paste0(service_config$base_url, "/urn/", urn)
  
  # Execute request
  response <- execute_api_request(
    url = url,
    params = list(formato = format),
    timeout = service_config$timeout,
    retry_attempts = service_config$retry_attempts
  )
  
  # Cache successful response
  if (!is.null(cache_key) && response$success) {
    cache_response(cache_key, response$data)
  }
  
  # Track request
  track_service_request("lexml", response$success)
  
  return(response$data)
}

#' Integrate with regulatory agency data
#' @param agency_code Agency code (antt, antaq, etc.)
#' @param data_type Type of data to retrieve
#' @param use_cache Whether to use caching
#' @return Agency data
integrate_regulatory_agency <- function(agency_code, data_type = "resolutions", use_cache = TRUE) {
  agency_config <- EXTERNAL_CONFIG$regulatory_agencies[[agency_code]]
  
  if (is.null(agency_config) || !agency_config$enabled) {
    return(list(error = paste("Agency", agency_code, "integration disabled or not found")))
  }
  
  # Check if data type is supported
  if (!data_type %in% names(agency_config$data_endpoints)) {
    return(list(error = paste("Data type", data_type, "not supported for", agency_code)))
  }
  
  # Generate cache key
  cache_key <- if (use_cache && EXTERNAL_CONFIG$caching$cache_responses) {
    generate_cache_key(agency_code, data_type, NULL)
  } else {
    NULL
  }
  
  # Check cache first
  if (!is.null(cache_key)) {
    cached_response <- get_cached_response(cache_key)
    if (!is.null(cached_response)) {
      log_event(paste("Cache HIT for", agency_code, "request"), "INFO")
      return(cached_response)
    }
  }
  
  # Build request URL
  endpoint <- agency_config$data_endpoints[[data_type]]
  url <- paste0(agency_config$base_url, endpoint)
  
  # Execute scraping request (most agencies don't have APIs)
  response <- scrape_agency_data(url, agency_code, data_type)
  
  # Cache successful response
  if (!is.null(cache_key) && !is.null(response) && !("error" %in% names(response))) {
    cache_response(cache_key, response)
  }
  
  # Track request
  track_service_request(agency_code, !is.null(response) && !("error" %in% names(response)))
  
  return(response)
}

#' Execute API request with retry logic
#' @param url Request URL
#' @param params Query parameters
#' @param timeout Request timeout
#' @param retry_attempts Number of retry attempts
#' @param headers Additional headers
#' @return Response object
execute_api_request <- function(url, params = NULL, timeout = 30, retry_attempts = 3, headers = list()) {
  last_error <- NULL
  
  for (attempt in 1:retry_attempts) {
    tryCatch({
      # Add default headers
      default_headers <- list(
        "User-Agent" = "Monitor-Legislativo-v4/1.0 (Academic Research Platform)",
        "Accept" = "application/json, text/xml, text/html"
      )
      
      request_headers <- modifyList(default_headers, headers)
      
      # Execute request
      response <- if (is.null(params)) {
        GET(url, do.call(add_headers, request_headers), timeout(timeout))
      } else {
        GET(url, query = params, do.call(add_headers, request_headers), timeout(timeout))
      }
      
      # Check response status
      if (status_code(response) == 200) {
        # Parse response based on content type
        content_type <- headers(response)[["content-type"]] %||% ""
        
        response_data <- if (grepl("application/json", content_type)) {
          fromJSON(content(response, "text", encoding = "UTF-8"), simplifyVector = FALSE)
        } else if (grepl("text/xml|application/xml", content_type)) {
          parse_xml_response(content(response, "text", encoding = "UTF-8"))
        } else {
          content(response, "text", encoding = "UTF-8")
        }
        
        return(list(
          success = TRUE,
          data = response_data,
          status_code = status_code(response),
          attempt = attempt
        ))
      } else {
        last_error <- paste("HTTP", status_code(response), http_status(response)$message)
      }
      
    }, error = function(e) {
      last_error <<- e$message
      
      if (attempt < retry_attempts) {
        # Wait before retry (exponential backoff)
        Sys.sleep(2^(attempt - 1))
      }
    })
  }
  
  # All attempts failed
  log_event(paste("API request failed after", retry_attempts, "attempts:", last_error), "ERROR")
  
  return(list(
    success = FALSE,
    error = last_error,
    attempts = retry_attempts
  ))
}

#' Scrape data from regulatory agency websites
#' @param url Website URL
#' @param agency_code Agency code
#' @param data_type Data type
#' @return Scraped data
scrape_agency_data <- function(url, agency_code, data_type) {
  tryCatch({
    # Read webpage
    page <- read_html(url)
    
    # Extract data based on agency and data type
    scraped_data <- switch(agency_code,
      "antt" = scrape_antt_data(page, data_type),
      "antaq" = scrape_antaq_data(page, data_type),
      "anac" = scrape_anac_data(page, data_type),
      "aneel" = scrape_aneel_data(page, data_type),
      scrape_generic_agency_data(page, data_type)
    )
    
    return(list(
      agency = agency_code,
      data_type = data_type,
      url = url,
      scraped_at = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ"),
      data = scraped_data
    ))
    
  }, error = function(e) {
    log_event(paste("Scraping error for", agency_code, ":", e$message), "ERROR")
    return(list(
      error = paste("Failed to scrape data from", agency_code),
      message = e$message
    ))
  })
}

#' Scrape ANTT data
#' @param page HTML page object
#' @param data_type Data type
#' @return Scraped ANTT data
scrape_antt_data <- function(page, data_type) {
  if (data_type == "resolutions") {
    # Extract resolution links and titles
    resolution_links <- page %>%
      html_nodes("a[href*='resolucao'], a[href*='resolução']") %>%
      html_attr("href")
    
    resolution_titles <- page %>%
      html_nodes("a[href*='resolucao'], a[href*='resolução']") %>%
      html_text() %>%
      trimws()
    
    return(data.frame(
      type = "resolution",
      title = resolution_titles,
      url = resolution_links,
      stringsAsFactors = FALSE
    ))
  }
  
  return(list(message = "No specific scraping logic for this data type"))
}

#' Scrape generic agency data
#' @param page HTML page object
#' @param data_type Data type
#' @return Generic scraped data
scrape_generic_agency_data <- function(page, data_type) {
  # Extract all links that might be documents
  document_links <- page %>%
    html_nodes("a[href*='.pdf'], a[href*='resoluc'], a[href*='instruc'], a[href*='portaria']") %>%
    html_attr("href")
  
  document_titles <- page %>%
    html_nodes("a[href*='.pdf'], a[href*='resoluc'], a[href*='instruc'], a[href*='portaria']") %>%
    html_text() %>%
    trimws()
  
  if (length(document_links) > 0) {
    return(data.frame(
      type = "document",
      title = document_titles,
      url = document_links,
      stringsAsFactors = FALSE
    ))
  }
  
  return(list(message = "No documents found"))
}

#' Validate data across multiple sources
#' @param document_id Document identifier
#' @param validation_sources Sources to use for validation
#' @return Validation result
validate_data_across_sources <- function(document_id, validation_sources = NULL) {
  if (!EXTERNAL_CONFIG$data_validation$enable_cross_validation) {
    return(list(validated = FALSE, message = "Cross-validation disabled"))
  }
  
  validation_sources <- validation_sources %||% EXTERNAL_CONFIG$data_validation$validation_sources
  
  validation_results <- list()
  
  for (source in validation_sources) {
    validation_results[[source]] <- switch(source,
      "camara" = validate_with_camara(document_id),
      "senado" = validate_with_senado(document_id),
      "lexml" = validate_with_lexml(document_id),
      list(status = "unknown_source")
    )
  }
  
  # Calculate confidence score
  successful_validations <- sum(sapply(validation_results, function(x) x$status == "found"))
  total_validations <- length(validation_results)
  confidence_score <- successful_validations / total_validations
  
  return(list(
    validated = confidence_score >= EXTERNAL_CONFIG$data_validation$confidence_threshold,
    confidence_score = confidence_score,
    validation_results = validation_results,
    sources_checked = validation_sources
  ))
}

#' Check service health for all external integrations
#' @return Health check results
check_all_services_health <- function() {
  health_results <- list()
  
  # Check government APIs
  for (service_name in names(EXTERNAL_CONFIG$government_apis)) {
    service_config <- EXTERNAL_CONFIG$government_apis[[service_name]]
    
    if (service_config$enabled) {
      health_results[[service_name]] <- check_service_health(service_name, service_config)
    }
  }
  
  # Check regulatory agencies (simplified health check)
  for (agency_name in names(EXTERNAL_CONFIG$regulatory_agencies)) {
    agency_config <- EXTERNAL_CONFIG$regulatory_agencies[[agency_name]]
    
    if (agency_config$enabled) {
      health_results[[agency_name]] <- check_agency_health(agency_name, agency_config)
    }
  }
  
  # Update global health state
  external_state$service_health <<- health_results
  external_state$last_health_check <<- Sys.time()
  
  return(health_results)
}

#' Check individual service health
#' @param service_name Service name
#' @param service_config Service configuration
#' @return Health check result
check_service_health <- function(service_name, service_config) {
  tryCatch({
    # Simple health check - test base URL accessibility
    response <- GET(service_config$base_url, timeout(10))
    
    if (status_code(response) %in% c(200, 301, 302)) {
      return(list(
        status = "healthy",
        response_time_ms = response$times[["total"]] * 1000,
        last_check = Sys.time()
      ))
    } else {
      return(list(
        status = "unhealthy",
        status_code = status_code(response),
        last_check = Sys.time()
      ))
    }
    
  }, error = function(e) {
    return(list(
      status = "unhealthy",
      error = e$message,
      last_check = Sys.time()
    ))
  })
}

#' Start health monitoring for external services
start_health_monitoring <- function() {
  if (!EXTERNAL_CONFIG$health_monitoring$alert_on_failures) {
    return()
  }
  
  future({
    while (TRUE) {
      Sys.sleep(EXTERNAL_CONFIG$health_monitoring$check_interval_minutes * 60)
      
      tryCatch({
        health_results <- check_all_services_health()
        
        # Check for service failures
        for (service_name in names(health_results)) {
          result <- health_results[[service_name]]
          
          if (result$status == "unhealthy") {
            log_event(paste("External service unhealthy:", service_name), "WARN")
            
            # Trigger alert if monitoring system is available
            if (exists("trigger_alert")) {
              trigger_alert(
                type = "external_service",
                severity = "warning",
                message = paste("External service", service_name, "is unhealthy"),
                details = result
              )
            }
          }
        }
        
      }, error = function(e) {
        log_event(paste("Health monitoring error:", e$message), "ERROR")
      })
    }
  })
  
  log_event("External service health monitoring started", "INFO")
}

# Helper functions

#' Check rate limit for service
#' @param service_name Service name
#' @param rate_limit Rate limit (requests per hour)
#' @return Whether request is allowed
check_rate_limit <- function(service_name, rate_limit) {
  current_hour <- format(Sys.time(), "%Y-%m-%d %H")
  rate_key <- paste(service_name, current_hour, sep = "_")
  
  if (is.null(external_state$request_counts[[rate_key]])) {
    external_state$request_counts[[rate_key]] <<- 0
  }
  
  if (external_state$request_counts[[rate_key]] >= rate_limit) {
    return(FALSE)
  }
  
  external_state$request_counts[[rate_key]] <<- external_state$request_counts[[rate_key]] + 1
  return(TRUE)
}

#' Generate cache key
#' @param service Service name
#' @param endpoint Endpoint or identifier
#' @param params Parameters
#' @return Cache key
generate_cache_key <- function(service, endpoint, params) {
  key_data <- list(service = service, endpoint = endpoint, params = params)
  digest(toJSON(key_data, auto_unbox = TRUE), algo = "md5")
}

#' Cache API response
#' @param cache_key Cache key
#' @param response_data Response data
cache_response <- function(cache_key, response_data) {
  if (!EXTERNAL_CONFIG$caching$cache_responses) {
    return()
  }
  
  cache_entry <- list(
    data = response_data,
    cached_at = Sys.time(),
    ttl_hours = EXTERNAL_CONFIG$caching$cache_ttl_hours
  )
  
  external_state$cached_responses[[cache_key]] <<- cache_entry
  
  # Limit cache size
  if (length(external_state$cached_responses) > 1000) {
    # Remove oldest entries
    timestamps <- sapply(external_state$cached_responses, function(x) x$cached_at)
    oldest_keys <- names(sort(timestamps))[1:100]
    
    for (key in oldest_keys) {
      external_state$cached_responses[[key]] <<- NULL
    }
  }
}

#' Get cached response
#' @param cache_key Cache key
#' @return Cached response or NULL
get_cached_response <- function(cache_key) {
  cache_entry <- external_state$cached_responses[[cache_key]]
  
  if (is.null(cache_entry)) {
    return(NULL)
  }
  
  # Check if cache has expired
  age_hours <- as.numeric(Sys.time() - cache_entry$cached_at, units = "hours")
  if (age_hours > cache_entry$ttl_hours) {
    external_state$cached_responses[[cache_key]] <<- NULL
    return(NULL)
  }
  
  return(cache_entry$data)
}

#' Track service request
#' @param service_name Service name
#' @param success Whether request was successful
track_service_request <- function(service_name, success) {
  request_info <- list(
    timestamp = Sys.time(),
    service = service_name,
    success = success
  )
  
  # Store request info for monitoring
  if (is.null(external_state$request_history)) {
    external_state$request_history <<- list()
  }
  
  external_state$request_history <<- append(external_state$request_history, list(request_info), after = 0)
  
  # Limit history size
  if (length(external_state$request_history) > 1000) {
    external_state$request_history <<- head(external_state$request_history, 1000)
  }
}

#' Parse XML response to list
#' @param xml_text XML response text
#' @return Parsed list
parse_xml_response <- function(xml_text) {
  tryCatch({
    xml_doc <- read_xml(xml_text)
    # Simple XML to list conversion (can be enhanced)
    return(list(xml_content = xml_text))
  }, error = function(e) {
    return(list(error = "Failed to parse XML response"))
  })
}

#' Get external integration statistics
#' @return Integration statistics
get_integration_statistics <- function() {
  if (is.null(external_state$request_history)) {
    return(list(total_requests = 0))
  }
  
  # Calculate statistics from request history
  total_requests <- length(external_state$request_history)
  successful_requests <- sum(sapply(external_state$request_history, function(x) x$success))
  
  # Service breakdown
  service_stats <- table(sapply(external_state$request_history, function(x) x$service))
  
  # Recent activity (last 24 hours)
  recent_cutoff <- Sys.time() - hours(24)
  recent_requests <- Filter(function(x) x$timestamp > recent_cutoff, external_state$request_history)
  
  return(list(
    total_requests = total_requests,
    successful_requests = successful_requests,
    success_rate = if (total_requests > 0) successful_requests / total_requests else 0,
    service_breakdown = as.list(service_stats),
    recent_requests_24h = length(recent_requests),
    last_health_check = external_state$last_health_check,
    services_healthy = sum(sapply(external_state$service_health, function(x) x$status == "healthy")),
    total_services = length(external_state$service_health)
  ))
}