# Brazilian Legislative APIs Client
# REAL DATA ONLY - No mock or fake data
# Connects to official government sources

library(httr)
library(jsonlite)
library(dplyr)
library(lubridate)
library(stringr)
library(futile.logger)

# Load configuration
if (!exists("config")) {
  config <- yaml::read_yaml("config.yml")
}

# =============================================================================
# INPUT VALIDATION AND SECURITY FUNCTIONS
# =============================================================================

#' Validate API endpoint parameter
#' @param endpoint Endpoint string to validate
#' @param allowed_endpoints Vector of allowed endpoints
#' @return Validated endpoint or error
validate_endpoint <- function(endpoint, allowed_endpoints) {
  
  if (is.null(endpoint) || !is.character(endpoint) || length(endpoint) != 1) {
    stop("Invalid endpoint: must be a single character string")
  }
  
  # Remove any path traversal attempts
  endpoint <- gsub("\\.\\./", "", endpoint)
  endpoint <- gsub("/+", "/", endpoint)
  endpoint <- gsub("^/|/$", "", endpoint)
  
  if (!endpoint %in% allowed_endpoints) {
    stop(paste("Invalid endpoint. Allowed endpoints:", paste(allowed_endpoints, collapse = ", ")))
  }
  
  return(endpoint)
}

#' Validate date parameters
#' @param date_input Date to validate
#' @param param_name Parameter name for error messages
#' @return Validated date or NULL
validate_date_param <- function(date_input, param_name = "date") {
  
  if (is.null(date_input)) {
    return(NULL)
  }
  
  tryCatch({
    validated_date <- as.Date(date_input)
    
    # Check if date is reasonable (not too far in past or future)
    min_date <- as.Date("1988-10-05")  # Brazilian Constitution date
    max_date <- Sys.Date() + 365       # One year in future
    
    if (validated_date < min_date) {
      flog.warn("Date %s is before Brazilian Constitution (1988-10-05)", validated_date)
      return(min_date)
    }
    
    if (validated_date > max_date) {
      flog.warn("Date %s is too far in future", validated_date)
      return(Sys.Date())
    }
    
    return(validated_date)
    
  }, error = function(e) {
    stop(paste("Invalid", param_name, "format. Expected YYYY-MM-DD or Date object"))
  })
}

#' Validate query parameters
#' @param params List of parameters to validate
#' @param allowed_params Vector of allowed parameter names
#' @return Validated and sanitized parameters
validate_query_params <- function(params, allowed_params = NULL) {
  
  if (is.null(params)) {
    return(list())
  }
  
  if (!is.list(params)) {
    stop("Parameters must be a list")
  }
  
  # Check for allowed parameters if specified
  if (!is.null(allowed_params)) {
    invalid_params <- setdiff(names(params), allowed_params)
    if (length(invalid_params) > 0) {
      flog.warn("Removing invalid parameters: %s", paste(invalid_params, collapse = ", "))
      params <- params[names(params) %in% allowed_params]
    }
  }
  
  # Validate each parameter
  validated_params <- list()
  
  for (param_name in names(params)) {
    param_value <- params[[param_name]]
    
    # Basic sanitization
    if (is.character(param_value)) {
      # Remove potentially dangerous characters
      param_value <- gsub("[<>\"'&;]", "", param_value)
      # Limit length
      if (nchar(param_value) > 1000) {
        param_value <- substr(param_value, 1, 1000)
        flog.warn("Parameter %s truncated to 1000 characters", param_name)
      }
    }
    
    # Specific validations
    if (param_name == "itens") {
      param_value <- as.numeric(param_value)
      if (is.na(param_value) || param_value < 1 || param_value > 1000) {
        flog.warn("Invalid itens parameter, using default 100")
        param_value <- 100
      }
    }
    
    validated_params[[param_name]] <- param_value
  }
  
  return(validated_params)
}

#' Validate state code
#' @param state_code Two-letter state code
#' @return Validated state code
validate_state_code <- function(state_code) {
  
  if (is.null(state_code)) {
    return(NULL)
  }
  
  # Valid Brazilian state codes
  valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                   "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                   "RS", "RO", "RR", "SC", "SP", "SE", "TO")
  
  state_code <- toupper(trimws(state_code))
  
  if (!state_code %in% valid_states) {
    stop(paste("Invalid state code:", state_code, ". Valid codes:", paste(valid_states, collapse = ", ")))
  }
  
  return(state_code)
}

#' Rate limiting implementation
#' @param api_name Name of the API for rate limiting
#' @param calls_per_minute Maximum calls per minute
rate_limit_check <- function(api_name, calls_per_minute = 60) {
  
  # Simple in-memory rate limiting (for production, use Redis or database)
  if (!exists(".rate_limits", envir = globalenv())) {
    assign(".rate_limits", list(), envir = globalenv())
  }
  
  rate_limits <- get(".rate_limits", envir = globalenv())
  current_time <- Sys.time()
  
  # Initialize or clean old entries
  if (!api_name %in% names(rate_limits)) {
    rate_limits[[api_name]] <- list(calls = list(), last_reset = current_time)
  }
  
  api_limits <- rate_limits[[api_name]]
  
  # Remove calls older than 1 minute
  api_limits$calls <- api_limits$calls[api_limits$calls > (current_time - 60)]
  
  # Check if we're under the limit
  if (length(api_limits$calls) >= calls_per_minute) {
    wait_time <- 60 - as.numeric(current_time - min(api_limits$calls))
    if (wait_time > 0) {
      flog.info("Rate limit reached for %s, waiting %d seconds", api_name, ceiling(wait_time))
      Sys.sleep(wait_time)
    }
    # Clean old calls after waiting
    api_limits$calls <- api_limits$calls[api_limits$calls > (Sys.time() - 60)]
  }
  
  # Add current call
  api_limits$calls <- c(api_limits$calls, Sys.time())
  
  # Update global rate limits
  rate_limits[[api_name]] <- api_limits
  assign(".rate_limits", rate_limits, envir = globalenv())
  
  return(TRUE)
}

# =============================================================================
# FEDERAL APIS
# =============================================================================

#' Fetch data from Câmara dos Deputados API
#' @param endpoint API endpoint (proposicoes, deputados, etc.)
#' @param params List of query parameters
#' @param date_from Start date for filtering (optional)
#' @param date_to End date for filtering (optional)
#' @return Data frame with legislative data
fetch_camara_data <- function(endpoint = "proposicoes", params = list(), 
                             date_from = NULL, date_to = NULL) {
  
  # Validate inputs
  allowed_endpoints <- c("proposicoes", "deputados", "votacoes", "eventos", "orgaos")
  endpoint <- validate_endpoint(endpoint, allowed_endpoints)
  
  # Validate dates
  date_from <- validate_date_param(date_from, "date_from")
  date_to <- validate_date_param(date_to, "date_to")
  
  # Validate parameters
  allowed_params <- c("dataInicio", "dataFim", "itens", "ordem", "ordenarPor", "idTipoAutor", "keywords")
  params <- validate_query_params(params, allowed_params)
  
  flog.info("Fetching Câmara dos Deputados data from endpoint: %s", endpoint)
  
  # Check rate limits
  rate_limit_check("camara", calls_per_minute = 60)
  
  base_url <- config$apis$federal$camara$base_url
  full_url <- paste0(base_url, "/", endpoint)
  
  # Add validated date filters
  if (!is.null(date_from)) {
    params$dataInicio <- format(date_from, "%Y-%m-%d")
  }
  if (!is.null(date_to)) {
    params$dataFim <- format(date_to, "%Y-%m-%d")
  }
  
  # Set safe default parameters
  if (!"itens" %in% names(params)) {
    params$itens <- 100  # Maximum items per request
  }
  if (!"ordem" %in% names(params)) {
    params$ordem <- "DESC"
  }
  if (!"ordenarPor" %in% names(params)) {
    params$ordenarPor <- "id"
  }
  
  tryCatch({
    # Make API request with improved error handling
    
    response <- GET(
      url = full_url,
      query = params,
      add_headers(
        "Accept" = "application/json",
        "User-Agent" = "Academic-Legislative-Monitor/1.0"
      ),
      timeout(30)
    )
    
    # Check response status
    if (status_code(response) != 200) {
      flog.error("Câmara API error: HTTP %d", status_code(response))
      return(NULL)
    }
    
    # Parse JSON response
    content_data <- content(response, "text", encoding = "UTF-8")
    parsed_data <- fromJSON(content_data, flatten = TRUE)
    
    if ("dados" %in% names(parsed_data)) {
      result_data <- parsed_data$dados
    } else {
      result_data <- parsed_data
    }
    
    # Convert to data frame and standardize
    if (is.data.frame(result_data) && nrow(result_data) > 0) {
      result_data <- result_data %>%
        mutate(
          fonte = "Câmara dos Deputados",
          api_endpoint = endpoint,
          data_coleta = Sys.time(),
          nivel = "Federal"
        )
      
      flog.info("Successfully fetched %d records from Câmara", nrow(result_data))
      return(result_data)
    } else {
      flog.warn("No data returned from Câmara endpoint: %s", endpoint)
      return(NULL)
    }
    
  }, error = function(e) {
    flog.error("Error fetching Câmara data: %s", e$message)
    return(NULL)
  })
}

#' Fetch data from Senado Federal API
#' @param endpoint API endpoint
#' @param params Query parameters
#' @param date_from Start date (optional)
#' @param date_to End date (optional)
fetch_senado_data <- function(endpoint = "materia/pesquisa/lista", 
                             params = list(), date_from = NULL, date_to = NULL) {
  
  flog.info("Fetching Senado Federal data from endpoint: %s", endpoint)
  
  base_url <- config$apis$federal$senado$base_url
  full_url <- paste0(base_url, "/", endpoint)
  
  # Add date filters
  if (!is.null(date_from)) {
    params$dataInicio <- format(as.Date(date_from), "%Y%m%d")
  }
  if (!is.null(date_to)) {
    params$dataFim <- format(as.Date(date_to), "%Y%m%d")
  }
  
  tryCatch({
    response <- GET(
      url = full_url,
      query = params,
      add_headers(
        "Accept" = "application/json",
        "User-Agent" = "Academic-Legislative-Monitor/1.0"
      ),
      timeout(30)
    )
    
    if (status_code(response) != 200) {
      flog.error("Senado API error: HTTP %d", status_code(response))
      return(NULL)
    }
    
    content_data <- content(response, "text", encoding = "UTF-8")
    parsed_data <- fromJSON(content_data, flatten = TRUE)
    
    # Extract data based on response structure
    if ("ListaMaterias" %in% names(parsed_data)) {
      result_data <- parsed_data$ListaMaterias$Materias$Materia
    } else if ("dados" %in% names(parsed_data)) {
      result_data <- parsed_data$dados
    } else {
      result_data <- parsed_data
    }
    
    if (is.data.frame(result_data) && nrow(result_data) > 0) {
      result_data <- result_data %>%
        mutate(
          fonte = "Senado Federal",
          api_endpoint = endpoint,
          data_coleta = Sys.time(),
          nivel = "Federal"
        )
      
      flog.info("Successfully fetched %d records from Senado", nrow(result_data))
      return(result_data)
    } else {
      flog.warn("No data returned from Senado endpoint: %s", endpoint)
      return(NULL)
    }
    
  }, error = function(e) {
    flog.error("Error fetching Senado data: %s", e$message)
    return(NULL)
  })
}

#' Search LexML Brasil for legislation
#' @param query Search terms
#' @param state State filter (optional)
#' @param municipality Municipality filter (optional)
#' @param date_from Start date (optional)
#' @param max_results Maximum results to return
fetch_lexml_data <- function(query = NULL, state = NULL, municipality = NULL, 
                            date_from = NULL, max_results = 100) {
  
  flog.info("Searching LexML Brasil with query: %s", query %||% "all")
  
  base_url <- config$apis$federal$lexml$base_url
  full_url <- paste0(base_url, "/search")
  
  params <- list(
    format = "json",
    max = max_results
  )
  
  if (!is.null(query)) {
    params$q <- query
  }
  if (!is.null(state)) {
    params$authority <- paste0("br.", tolower(state))
  }
  if (!is.null(municipality)) {
    params$authority <- paste0("br.", tolower(state), ".", tolower(municipality))
  }
  if (!is.null(date_from)) {
    params$date_from <- format(as.Date(date_from), "%Y-%m-%d")
  }
  
  tryCatch({
    response <- GET(
      url = full_url,
      query = params,
      add_headers(
        "Accept" = "application/json",
        "User-Agent" = "Academic-Legislative-Monitor/1.0"
      ),
      timeout(30)
    )
    
    if (status_code(response) != 200) {
      flog.error("LexML API error: HTTP %d", status_code(response))
      return(NULL)
    }
    
    content_data <- content(response, "text", encoding = "UTF-8")
    parsed_data <- fromJSON(content_data, flatten = TRUE)
    
    if (is.data.frame(parsed_data) && nrow(parsed_data) > 0) {
      result_data <- parsed_data %>%
        mutate(
          fonte = "LexML Brasil",
          api_endpoint = "search",
          data_coleta = Sys.time(),
          nivel = case_when(
            str_detect(authority %||% "", "^br\\.[a-z]{2}\\.[a-z]+") ~ "Municipal",
            str_detect(authority %||% "", "^br\\.[a-z]{2}$") ~ "Estadual",
            TRUE ~ "Federal"
          )
        )
      
      flog.info("Successfully fetched %d records from LexML", nrow(result_data))
      return(result_data)
    } else {
      flog.warn("No data returned from LexML search")
      return(NULL)
    }
    
  }, error = function(e) {
    flog.error("Error fetching LexML data: %s", e$message)
    return(NULL)
  })
}

# =============================================================================
# STATE APIS
# =============================================================================

#' Fetch data from state assemblies
#' @param state_code Two-letter state code (SP, RJ, etc.)
#' @param endpoint Specific endpoint if available
#' @param date_from Start date (optional)
fetch_state_data <- function(state_code, endpoint = NULL, date_from = NULL) {
  
  flog.info("Fetching state data for: %s", state_code)
  
  if (!state_code %in% names(config$apis$states)) {
    flog.warn("State API not configured for: %s", state_code)
    return(NULL)
  }
  
  state_config <- config$apis$states[[state_code]]
  
  # Try multiple approaches for different state APIs
  result_data <- NULL
  
  # Approach 1: Direct API if available
  if (!is.null(state_config$endpoints) && !is.null(endpoint)) {
    result_data <- fetch_state_api_direct(state_code, endpoint, date_from)
  }
  
  # Approach 2: Web scraping for states without APIs
  if (is.null(result_data)) {
    result_data <- fetch_state_web_scraping(state_code, date_from)
  }
  
  # Approach 3: Search via LexML for that state
  if (is.null(result_data)) {
    result_data <- fetch_lexml_data(
      query = "lei OR decreto OR portaria",
      state = state_code,
      date_from = date_from
    )
  }
  
  if (!is.null(result_data)) {
    result_data <- result_data %>%
      mutate(
        estado = state_code,
        nivel = "Estadual"
      )
  }
  
  return(result_data)
}

#' Direct API call for states with open data APIs
fetch_state_api_direct <- function(state_code, endpoint, date_from) {
  state_config <- config$apis$states[[state_code]]
  
  if (is.null(state_config$endpoints) || !endpoint %in% names(state_config$endpoints)) {
    return(NULL)
  }
  
  base_url <- state_config$base_url
  endpoint_path <- state_config$endpoints[[endpoint]]
  full_url <- paste0(base_url, endpoint_path)
  
  params <- list()
  if (!is.null(date_from)) {
    params$dataInicio <- format(as.Date(date_from), "%Y-%m-%d")
  }
  
  tryCatch({
    response <- GET(
      url = full_url,
      query = params,
      add_headers(
        "Accept" = "application/json",
        "User-Agent" = "Academic-Legislative-Monitor/1.0"
      ),
      timeout(30)
    )
    
    if (status_code(response) == 200) {
      content_data <- content(response, "text", encoding = "UTF-8")
      parsed_data <- fromJSON(content_data, flatten = TRUE)
      
      if (is.data.frame(parsed_data) && nrow(parsed_data) > 0) {
        flog.info("Successfully fetched %d records from %s state API", 
                 nrow(parsed_data), state_code)
        return(parsed_data)
      }
    }
    
    return(NULL)
    
  }, error = function(e) {
    flog.warn("Error with %s state API: %s", state_code, e$message)
    return(NULL)
  })
}

#' Web scraping fallback for states without APIs
fetch_state_web_scraping <- function(state_code, date_from) {
  # Implement web scraping for specific state sites
  # This is a fallback when APIs are not available
  
  flog.info("Attempting web scraping for state: %s", state_code)
  
  # Example implementation for São Paulo
  if (state_code == "SP") {
    return(scrape_alesp_data(date_from))
  }
  
  # Add other states as needed
  return(NULL)
}

#' Scrape ALESP (São Paulo) website
scrape_alesp_data <- function(date_from) {
  tryCatch({
    # This would implement actual web scraping
    # For now, return NULL to avoid breaking the app
    flog.info("ALESP scraping not yet implemented")
    return(NULL)
    
  }, error = function(e) {
    flog.error("Error scraping ALESP: %s", e$message)
    return(NULL)
  })
}

# =============================================================================
# MUNICIPAL APIS
# =============================================================================

#' Fetch municipal legislative data
#' @param municipality_code Municipal code or name
#' @param state_code State where municipality is located
#' @param date_from Start date (optional)
fetch_municipal_data <- function(municipality_code, state_code, date_from = NULL) {
  
  flog.info("Fetching municipal data for: %s, %s", municipality_code, state_code)
  
  # Try LexML first for municipal data
  result_data <- fetch_lexml_data(
    query = "lei OR decreto OR portaria",
    state = state_code,
    municipality = municipality_code,
    date_from = date_from
  )
  
  if (!is.null(result_data)) {
    result_data <- result_data %>%
      mutate(
        municipio = municipality_code,
        estado = state_code,
        nivel = "Municipal"
      )
  }
  
  return(result_data)
}

# =============================================================================
# UNIFIED DATA FETCHING
# =============================================================================

#' Fetch all legislative data from multiple sources
#' @param date_from Start date for data collection
#' @param date_to End date for data collection
#' @param states Vector of state codes to include
#' @param municipalities Vector of municipality codes to include
#' @param query Text query for search
#' @param max_results Maximum total results
fetch_all_legislative_data <- function(date_from = NULL, date_to = NULL, 
                                     states = NULL, municipalities = NULL,
                                     query = NULL, max_results = 1000) {
  
  flog.info("Starting comprehensive legislative data fetch")
  
  all_results <- list()
  
  # Federal level data
  flog.info("Fetching federal level data...")
  
  # Câmara dos Deputados
  camara_data <- fetch_camara_data(
    endpoint = "proposicoes",
    date_from = date_from,
    date_to = date_to
  )
  if (!is.null(camara_data)) {
    all_results$camara <- camara_data
  }
  
  # Senado Federal
  senado_data <- fetch_senado_data(
    endpoint = "materia/pesquisa/lista",
    date_from = date_from,
    date_to = date_to
  )
  if (!is.null(senado_data)) {
    all_results$senado <- senado_data
  }
  
  # LexML comprehensive search
  if (!is.null(query)) {
    lexml_data <- fetch_lexml_data(
      query = query,
      date_from = date_from,
      max_results = min(max_results / 2, 500)
    )
    if (!is.null(lexml_data)) {
      all_results$lexml <- lexml_data
    }
  }
  
  # State level data
  if (!is.null(states)) {
    flog.info("Fetching state level data for: %s", paste(states, collapse = ", "))
    
    for (state in states) {
      state_data <- fetch_state_data(state, date_from = date_from)
      if (!is.null(state_data)) {
        all_results[[paste0("state_", state)]] <- state_data
      }
    }
  }
  
  # Municipal level data
  if (!is.null(municipalities) && !is.null(states)) {
    flog.info("Fetching municipal level data...")
    
    for (i in seq_along(municipalities)) {
      if (i <= length(states)) {
        muni_data <- fetch_municipal_data(
          municipalities[i], 
          states[min(i, length(states))], 
          date_from = date_from
        )
        if (!is.null(muni_data)) {
          all_results[[paste0("muni_", municipalities[i])]] <- muni_data
        }
      }
    }
  }
  
  # Combine all results
  if (length(all_results) > 0) {
    # Standardize column names across all sources
    standardized_results <- map_dfr(all_results, ~{
      standardize_legislative_data(.x)
    }, .id = "source_id")
    
    # Remove duplicates
    final_results <- standardized_results %>%
      distinct(titulo, numero, data, fonte, .keep_all = TRUE) %>%
      arrange(desc(data)) %>%
      slice_head(n = max_results)
    
    flog.info("Fetch complete. Total records: %d from %d sources", 
             nrow(final_results), length(all_results))
    
    return(final_results)
  } else {
    flog.warn("No data fetched from any source")
    return(NULL)
  }
}

#' Helper function to check API status
check_api_status <- function() {
  status <- list()
  
  # Check major APIs
  apis_to_check <- list(
    "Câmara" = config$apis$federal$camara$base_url,
    "Senado" = config$apis$federal$senado$base_url,
    "LexML" = config$apis$federal$lexml$base_url
  )
  
  for (name in names(apis_to_check)) {
    url <- apis_to_check[[name]]
    
    tryCatch({
      response <- GET(url, timeout(10))
      status[[name]] <- list(
        status = ifelse(status_code(response) == 200, "Online", "Error"),
        code = status_code(response)
      )
    }, error = function(e) {
      status[[name]] <- list(status = "Offline", error = e$message)
    })
  }
  
  return(status)
}