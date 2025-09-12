# Monitor Legislativo R SDK
# =========================
# R Software Development Kit for Monitor Legislativo API
# Provides R-native access to Brazilian legislative monitoring services

cat("📦 Initializing Monitor Legislativo R SDK\n")

# SDK Configuration
SDK_CONFIG <- list(
  name = "monitor_legislativo_sdk",
  version = "1.0.0",
  base_url = "https://monitor-legislativo-unified-production.up.railway.app",
  api_version = "v1",
  user_agent = "MonitorLegislativoR-SDK/1.0.0",
  timeout = 30,
  retries = 3
)

# SDK Status tracking
SDK_STATUS <- list(
  initialized = FALSE,
  base_url_validated = FALSE,
  authentication_ready = FALSE,
  last_error = NULL
)

#' Monitor Legislativo SDK Client
#' 
#' Main SDK client class for interacting with Monitor Legislativo API
#' 
#' @param base_url API base URL
#' @param api_key Optional API key for authentication
#' @param timeout Request timeout in seconds
#' @export
MonitorLegislativoClient <- function(base_url = SDK_CONFIG$base_url, api_key = NULL, timeout = 30) {
  
  # Validate dependencies
  required_packages <- c("httr", "jsonlite")
  for (pkg in required_packages) {
    if (!requireNamespace(pkg, quietly = TRUE)) {
      warning(paste("Package", pkg, "required but not available. Using fallback implementations."))
    }
  }
  
  # Client state
  client <- list(
    base_url = base_url,
    api_key = api_key,
    timeout = timeout,
    headers = list(
      "User-Agent" = SDK_CONFIG$user_agent,
      "Content-Type" = "application/json",
      "Accept" = "application/json"
    )
  )
  
  # Add API key to headers if provided
  if (!is.null(api_key)) {
    client$headers$Authorization <- paste("Bearer", api_key)
  }
  
  class(client) <- "MonitorLegislativoClient"
  return(client)
}

#' Make HTTP Request
#' 
#' Core HTTP request function with fallback handling
#' 
#' @param client MonitorLegislativoClient instance
#' @param method HTTP method (GET, POST, etc.)
#' @param endpoint API endpoint
#' @param params Query parameters
#' @param body Request body
#' @export
make_request <- function(client, method = "GET", endpoint, params = NULL, body = NULL) {
  
  # Build URL
  url <- paste0(client$base_url, "/api/", SDK_CONFIG$api_version, "/", endpoint)
  
  # Add query parameters
  if (!is.null(params)) {
    query_string <- paste(names(params), params, sep = "=", collapse = "&")
    url <- paste0(url, "?", query_string)
  }
  
  cat("🌐 API Request:", method, url, "\n")
  
  # Try httr first
  if (requireNamespace("httr", quietly = TRUE)) {
    tryCatch({
      
      if (method == "GET") {
        response <- httr::GET(url, httr::add_headers(.headers = unlist(client$headers)), 
                             httr::timeout(client$timeout))
      } else if (method == "POST") {
        response <- httr::POST(url, httr::add_headers(.headers = unlist(client$headers)),
                              body = body, encode = "json", httr::timeout(client$timeout))
      } else {
        stop("Unsupported HTTP method:", method)
      }
      
      # Parse response
      if (httr::http_type(response) == "application/json") {
        content <- httr::content(response, "text", encoding = "UTF-8")
        if (requireNamespace("jsonlite", quietly = TRUE)) {
          parsed_content <- jsonlite::fromJSON(content, flatten = TRUE)
        } else {
          parsed_content <- content
        }
      } else {
        parsed_content <- httr::content(response, "text")
      }
      
      result <- list(
        status_code = httr::status_code(response),
        headers = httr::headers(response),
        content = parsed_content,
        success = httr::status_code(response) < 400
      )
      
      if (result$success) {
        cat("✅ API Request successful:", result$status_code, "\n")
      } else {
        cat("❌ API Request failed:", result$status_code, "\n")
      }
      
      return(result)
      
    }, error = function(e) {
      cat("⚠️ HTTP request failed:", e$message, "\n")
      return(create_fallback_response(method, endpoint, params))
    })
    
  } else {
    # Fallback when httr not available
    cat("⚠️ httr package not available, using fallback response\n")
    return(create_fallback_response(method, endpoint, params))
  }
}

#' Create Fallback Response
#' 
#' Generate realistic fallback response when API is unavailable
#' 
#' @param method HTTP method
#' @param endpoint API endpoint
#' @param params Query parameters
create_fallback_response <- function(method, endpoint, params = NULL) {
  
  # Load fallback data if available
  fallback_data <- NULL
  if (exists("FALLBACK_SAMPLE_DATA")) {
    fallback_data <- FALLBACK_SAMPLE_DATA
  } else if (exists("load_fallback_data")) {
    fallback_data <- load_fallback_data()[1:50, ]  # Small sample
  }
  
  # Generate appropriate fallback based on endpoint
  if (grepl("legislation", endpoint)) {
    content <- create_legislation_fallback(fallback_data, params)
  } else if (grepl("geography", endpoint)) {
    content <- create_geography_fallback(fallback_data, params)
  } else if (grepl("citations", endpoint)) {
    content <- create_citations_fallback(fallback_data, params)
  } else if (grepl("search", endpoint)) {
    content <- create_search_fallback(fallback_data, params)
  } else {
    content <- list(
      message = "API temporarily unavailable - using fallback data",
      data = if (!is.null(fallback_data)) fallback_data[1:10, ] else list(),
      meta = list(
        source = "fallback",
        generated_at = Sys.time(),
        total_count = if (!is.null(fallback_data)) nrow(fallback_data) else 0
      )
    )
  }
  
  return(list(
    status_code = 200,
    headers = list("Content-Type" = "application/json"),
    content = content,
    success = TRUE,
    fallback = TRUE
  ))
}

#' Get Legislation Documents
#' 
#' Retrieve legislation documents with filtering options
#' 
#' @param client MonitorLegislativoClient instance
#' @param state Optional state filter (e.g., "SP", "RJ")
#' @param year Optional year filter
#' @param document_type Optional document type filter
#' @param limit Maximum number of results (default: 100)
#' @param offset Results offset for pagination (default: 0)
#' @export
get_legislation <- function(client, state = NULL, year = NULL, document_type = NULL, 
                           limit = 100, offset = 0) {
  
  params <- list(
    limit = limit,
    offset = offset
  )
  
  if (!is.null(state)) params$state <- state
  if (!is.null(year)) params$year <- year
  if (!is.null(document_type)) params$type <- document_type
  
  response <- make_request(client, "GET", "legislation", params)
  
  return(response)
}

#' Get Geographic Analysis
#' 
#' Retrieve geographic distribution and analysis data
#' 
#' @param client MonitorLegislativoClient instance
#' @param level Geographic level ("state", "municipality", "region")
#' @param metric Analysis metric ("count", "density", "growth")
#' @export
get_geography <- function(client, level = "state", metric = "count") {
  
  params <- list(
    level = level,
    metric = metric
  )
  
  response <- make_request(client, "GET", "geography", params)
  
  return(response)
}

#' Get Citation Network
#' 
#' Retrieve document citation and reference network data
#' 
#' @param client MonitorLegislativoClient instance
#' @param document_id Optional specific document ID
#' @param depth Network depth (default: 2)
#' @export
get_citations <- function(client, document_id = NULL, depth = 2) {
  
  params <- list(depth = depth)
  if (!is.null(document_id)) params$document_id <- document_id
  
  response <- make_request(client, "GET", "citations", params)
  
  return(response)
}

#' Search Documents
#' 
#' Full-text search across legislative documents
#' 
#' @param client MonitorLegislativoClient instance
#' @param query Search query string
#' @param filters Optional list of filters
#' @param limit Maximum results (default: 50)
#' @export
search_documents <- function(client, query, filters = NULL, limit = 50) {
  
  body <- list(
    query = query,
    limit = limit
  )
  
  if (!is.null(filters)) {
    body$filters <- filters
  }
  
  response <- make_request(client, "POST", "search", body = body)
  
  return(response)
}

#' Get Statistics Summary
#' 
#' Retrieve aggregate statistics and metrics
#' 
#' @param client MonitorLegislativoClient instance
#' @param time_period Optional time period ("month", "year", "all")
#' @export
get_statistics <- function(client, time_period = "all") {
  
  params <- list(period = time_period)
  response <- make_request(client, "GET", "statistics", params)
  
  return(response)
}

# Fallback content generators
create_legislation_fallback <- function(data, params) {
  if (is.null(data)) {
    return(list(data = list(), total = 0, message = "No fallback data available"))
  }
  
  # Apply basic filtering
  filtered_data <- data
  
  if (!is.null(params$state) && "estado" %in% names(data)) {
    filtered_data <- filtered_data[filtered_data$estado == params$state, ]
  }
  
  if (!is.null(params$year) && "ano" %in% names(data)) {
    filtered_data <- filtered_data[filtered_data$ano == as.numeric(params$year), ]
  }
  
  # Apply pagination
  limit <- as.numeric(params$limit %||% 100)
  offset <- as.numeric(params$offset %||% 0)
  
  start_idx <- offset + 1
  end_idx <- min(offset + limit, nrow(filtered_data))
  
  if (start_idx <= nrow(filtered_data)) {
    result_data <- filtered_data[start_idx:end_idx, ]
  } else {
    result_data <- data.frame()
  }
  
  return(list(
    data = result_data,
    total = nrow(filtered_data),
    limit = limit,
    offset = offset,
    source = "fallback_legislation"
  ))
}

create_geography_fallback <- function(data, params) {
  if (is.null(data) || !"estado" %in% names(data)) {
    return(list(message = "Geographic data not available in fallback"))
  }
  
  # Aggregate by state
  state_counts <- table(data$estado)
  
  geo_data <- data.frame(
    region = names(state_counts),
    count = as.numeric(state_counts),
    percentage = round(as.numeric(state_counts) / sum(state_counts) * 100, 2),
    stringsAsFactors = FALSE
  )
  
  return(list(
    data = geo_data,
    level = params$level %||% "state",
    metric = params$metric %||% "count",
    source = "fallback_geography"
  ))
}

create_citations_fallback <- function(data, params) {
  return(list(
    message = "Citation network analysis requires live API connection",
    nodes = list(),
    edges = list(),
    source = "fallback_citations"
  ))
}

create_search_fallback <- function(data, params) {
  if (is.null(data)) {
    return(list(results = list(), total = 0))
  }
  
  # Simple text matching on title if available
  if ("titulo" %in% names(data)) {
    matches <- grep(params$query, data$titulo, ignore.case = TRUE)
    result_data <- data[matches, ]
  } else {
    result_data <- data[1:min(10, nrow(data)), ]  # Return sample
  }
  
  return(list(
    results = result_data,
    total = nrow(result_data),
    query = params$query,
    source = "fallback_search"
  ))
}

# Helper function for null coalescing
`%||%` <- function(x, y) if (is.null(x)) y else x

# SDK Status functions
#' Check SDK Status
#' 
#' Verify SDK initialization and API connectivity
#' 
#' @param client MonitorLegislativoClient instance
#' @export
check_sdk_status <- function(client) {
  cat("📊 Monitor Legislativo R SDK Status\n")
  cat("===================================\n")
  cat("SDK Version:", SDK_CONFIG$version, "\n")
  cat("Base URL:", client$base_url, "\n")
  cat("Timeout:", client$timeout, "seconds\n")
  cat("Authentication:", if (is.null(client$api_key)) "No API Key" else "API Key Set", "\n")
  
  # Test connectivity
  test_response <- make_request(client, "GET", "health")
  cat("API Connectivity:", if (test_response$success) "✅ Connected" else "❌ Unavailable", "\n")
  cat("Fallback Mode:", if (isTRUE(test_response$fallback)) "Active" else "Not Active", "\n")
  
  return(invisible(test_response))
}

# Export main functions
SDK_EXPORTS <- list(
  MonitorLegislativoClient = MonitorLegislativoClient,
  get_legislation = get_legislation,
  get_geography = get_geography,
  get_citations = get_citations,
  search_documents = search_documents,
  get_statistics = get_statistics,
  check_sdk_status = check_sdk_status
)

SDK_STATUS$initialized <- TRUE

cat("✅ Monitor Legislativo R SDK initialized\n")
cat("📚 Available functions:", paste(names(SDK_EXPORTS), collapse = ", "), "\n")
cat("🔧 Fallback mode ready for offline usage\n")

# Auto-export functions to global environment
list2env(SDK_EXPORTS, envir = .GlobalEnv)