# RestRserve API Implementation for Monitor Legislativo v4
# High-performance RESTful API endpoints with authentication and rate limiting

library(RestRserve)
library(jsonlite)
library(httr)
library(digest)
library(lubridate)
library(DBI)
library(future)
library(promises)

# API configuration
API_CONFIG <- list(
  server = list(
    host = Sys.getenv("API_HOST", "0.0.0.0"),
    port = as.integer(Sys.getenv("API_PORT", "8080")),
    workers = as.integer(Sys.getenv("API_WORKERS", "4")),
    max_request_size = 50 * 1024 * 1024,  # 50MB
    request_timeout = 30,
    enable_cors = TRUE
  ),
  
  authentication = list(
    require_auth = FALSE,  # Set to TRUE for production
    api_key_header = "X-API-Key",
    jwt_secret = Sys.getenv("JWT_SECRET", "default-secret-change-in-production"),
    token_expiry_hours = 24
  ),
  
  rate_limiting = list(
    enabled = TRUE,
    requests_per_minute = 60,
    burst_limit = 100,
    whitelist_ips = c("127.0.0.1", "::1"),
    rate_limit_header = "X-RateLimit-Remaining"
  ),
  
  versioning = list(
    current_version = "v1",
    supported_versions = c("v1"),
    version_header = "API-Version",
    deprecation_warnings = TRUE
  ),
  
  caching = list(
    enabled = TRUE,
    default_ttl = 300,  # 5 minutes
    max_cache_size = 1000,
    cache_headers = TRUE
  ),
  
  monitoring = list(
    track_requests = TRUE,
    track_response_times = TRUE,
    track_errors = TRUE,
    health_check_endpoint = TRUE
  )
)

# Global API state
api_state <- list(
  app = NULL,
  request_counts = list(),
  performance_metrics = list(),
  active_connections = 0
)

#' Initialize RestRserve API application
#' @param config Optional configuration override
#' @return API application instance
initialize_api_server <- function(config = NULL) {
  if (!is.null(config)) {
    API_CONFIG <<- modifyList(API_CONFIG, config)
  }
  
  log_event("Initializing RestRserve API server...", "INFO")
  
  # Create RestRserve application
  app <- Application$new(
    content_type = "application/json",
    middleware = create_api_middleware()
  )
  
  # Configure CORS if enabled
  if (API_CONFIG$server$enable_cors) {
    app$add_middleware(cors_middleware())
  }
  
  # Add rate limiting middleware
  if (API_CONFIG$rate_limiting$enabled) {
    app$add_middleware(rate_limiting_middleware())
  }
  
  # Add authentication middleware
  if (API_CONFIG$authentication$require_auth) {
    app$add_middleware(authentication_middleware())
  }
  
  # Add monitoring middleware
  if (API_CONFIG$monitoring$track_requests) {
    app$add_middleware(monitoring_middleware())
  }
  
  # Register API endpoints
  register_api_endpoints(app)
  
  # Store app instance
  api_state$app <<- app
  
  log_event("RestRserve API server initialized successfully", "INFO")
  
  return(app)
}

#' Create API middleware stack
#' @return List of middleware functions
create_api_middleware <- function() {
  list(
    error_handling_middleware(),
    request_logging_middleware(),
    response_formatting_middleware()
  )
}

#' CORS middleware for cross-origin requests
#' @return CORS middleware function
cors_middleware <- function() {
  function(request, response) {
    response$set_header("Access-Control-Allow-Origin", "*")
    response$set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    response$set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, API-Version")
    response$set_header("Access-Control-Max-Age", "86400")
    
    if (request$method == "OPTIONS") {
      response$set_status_code(200L)
      return(TRUE)  # Stop processing
    }
    
    return(FALSE)  # Continue processing
  }
}

#' Rate limiting middleware
#' @return Rate limiting middleware function
rate_limiting_middleware <- function() {
  function(request, response) {
    client_ip <- request$headers[["X-Forwarded-For"]] %||% request$remote_addr
    
    # Skip rate limiting for whitelisted IPs
    if (client_ip %in% API_CONFIG$rate_limiting$whitelist_ips) {
      return(FALSE)
    }
    
    # Check rate limit
    rate_limit_result <- check_api_rate_limit(client_ip)
    
    if (!rate_limit_result$allowed) {
      response$set_status_code(429L)
      response$set_header("Retry-After", "60")
      response$set_body(list(
        error = "Rate limit exceeded",
        message = rate_limit_result$message,
        retry_after = 60
      ))
      return(TRUE)  # Stop processing
    }
    
    # Add rate limit headers
    response$set_header(API_CONFIG$rate_limiting$rate_limit_header, 
                       as.character(rate_limit_result$remaining))
    
    return(FALSE)  # Continue processing
  }
}

#' Authentication middleware
#' @return Authentication middleware function
authentication_middleware <- function() {
  function(request, response) {
    # Skip authentication for health check and public endpoints
    if (request$path %in% c("/health", "/v1/health", "/api/v1/health")) {
      return(FALSE)
    }
    
    # Check for API key or JWT token
    api_key <- request$headers[[API_CONFIG$authentication$api_key_header]]
    auth_header <- request$headers[["Authorization"]]
    
    auth_result <- if (!is.null(api_key)) {
      validate_api_key(api_key)
    } else if (!is.null(auth_header) && startsWith(auth_header, "Bearer ")) {
      token <- substring(auth_header, 8)
      validate_jwt_token(token)
    } else {
      list(valid = FALSE, message = "Missing authentication credentials")
    }
    
    if (!auth_result$valid) {
      response$set_status_code(401L)
      response$set_body(list(
        error = "Authentication failed",
        message = auth_result$message
      ))
      return(TRUE)  # Stop processing
    }
    
    # Add user context to request
    request$user <- auth_result$user
    
    return(FALSE)  # Continue processing
  }
}

#' Monitoring middleware
#' @return Monitoring middleware function
monitoring_middleware <- function() {
  function(request, response) {
    # Record request start time
    request$start_time <- Sys.time()
    
    # Track request
    track_api_request(request)
    
    return(FALSE)  # Continue processing
  }
}

#' Error handling middleware
#' @return Error handling middleware function
error_handling_middleware <- function() {
  function(request, response) {
    tryCatch({
      return(FALSE)  # Continue processing
    }, error = function(e) {
      log_event(paste("API Error:", e$message), "ERROR")
      
      response$set_status_code(500L)
      response$set_body(list(
        error = "Internal server error",
        message = "An unexpected error occurred",
        request_id = generate_request_id()
      ))
      
      return(TRUE)  # Stop processing
    })
  }
}

#' Request logging middleware
#' @return Request logging middleware function
request_logging_middleware <- function() {
  function(request, response) {
    log_event(paste("API Request:", request$method, request$path), "INFO")
    return(FALSE)  # Continue processing
  }
}

#' Response formatting middleware
#' @return Response formatting middleware function
response_formatting_middleware <- function() {
  function(request, response) {
    # Add API version header
    response$set_header(API_CONFIG$versioning$version_header, API_CONFIG$versioning$current_version)
    
    # Add request ID header
    response$set_header("X-Request-ID", generate_request_id())
    
    # Track response time if monitoring enabled
    if (API_CONFIG$monitoring$track_response_times && !is.null(request$start_time)) {
      response_time <- as.numeric(Sys.time() - request$start_time, units = "secs") * 1000
      response$set_header("X-Response-Time", paste0(round(response_time, 2), "ms"))
      
      track_api_response_time(request$path, response_time)
    }
    
    return(FALSE)  # Continue processing
  }
}

#' Register all API endpoints
#' @param app RestRserve application instance
register_api_endpoints <- function(app) {
  # Health check endpoint
  app$add_get("/health", health_check_handler)
  app$add_get("/api/v1/health", health_check_handler)
  
  # Legislative data endpoints
  app$add_get("/api/v1/search", search_documents_handler)
  app$add_get("/api/v1/documents/{id}", get_document_handler)
  app$add_get("/api/v1/documents", list_documents_handler)
  
  # Geographic endpoints
  app$add_get("/api/v1/geographic/states", list_states_handler)
  app$add_get("/api/v1/geographic/municipalities", list_municipalities_handler)
  app$add_get("/api/v1/geographic/search", geographic_search_handler)
  
  # Analytics endpoints
  app$add_get("/api/v1/analytics/summary", analytics_summary_handler)
  app$add_get("/api/v1/analytics/reports", list_reports_handler)
  app$add_post("/api/v1/analytics/reports", generate_report_handler)
  
  # Export endpoints
  app$add_post("/api/v1/export", export_data_handler)
  app$add_get("/api/v1/export/{id}", download_export_handler)
  
  # Cache management endpoints
  app$add_post("/api/v1/cache/clear", clear_cache_handler)
  app$add_get("/api/v1/cache/stats", cache_stats_handler)
  
  # System endpoints
  app$add_get("/api/v1/system/status", system_status_handler)
  app$add_get("/api/v1/system/metrics", system_metrics_handler)
  
  log_event("API endpoints registered successfully", "INFO")
}

#' Health check endpoint handler
#' @param request HTTP request object
#' @param response HTTP response object
health_check_handler <- function(request, response) {
  health_status <- list(
    status = "healthy",
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ"),
    version = API_CONFIG$versioning$current_version,
    uptime_seconds = as.numeric(Sys.time() - api_state$startup_time, units = "secs"),
    checks = list(
      database = check_database_connection(),
      redis = check_redis_connection(),
      memory = check_memory_usage()
    )
  )
  
  # Determine overall status
  check_results <- sapply(health_status$checks, function(x) x$status)
  overall_status <- if (all(check_results == "healthy")) {
    "healthy"
  } else if (any(check_results == "unhealthy")) {
    "unhealthy"
  } else {
    "degraded"
  }
  
  health_status$status <- overall_status
  
  # Set appropriate status code
  status_code <- switch(overall_status,
    "healthy" = 200L,
    "degraded" = 200L,
    "unhealthy" = 503L,
    200L
  )
  
  response$set_status_code(status_code)
  response$set_body(health_status)
}

#' Search documents endpoint handler
#' @param request HTTP request object
#' @param response HTTP response object
search_documents_handler <- function(request, response) {
  # Parse query parameters
  query_params <- request$query
  
  search_query <- query_params$q %||% ""
  limit <- as.integer(query_params$limit %||% 100)
  offset <- as.integer(query_params$offset %||% 0)
  types <- if (!is.null(query_params$types)) strsplit(query_params$types, ",")[[1]] else NULL
  states <- if (!is.null(query_params$states)) strsplit(query_params$states, ",")[[1]] else NULL
  
  # Validate parameters
  if (limit > 1000) {
    response$set_status_code(400L)
    response$set_body(list(
      error = "Invalid parameter",
      message = "Limit cannot exceed 1000"
    ))
    return()
  }
  
  # Check cache first
  cache_key <- generate_search_cache_key(list(
    query = search_query,
    limit = limit,
    offset = offset,
    types = types,
    states = states
  ))
  
  cached_result <- get_cached_search_results(search_query, list(
    types = types,
    states = states,
    limit = limit,
    offset = offset
  ))
  
  if (!is.null(cached_result)) {
    response$set_header("X-Cache", "HIT")
    response$set_body(format_search_response(cached_result, offset, limit))
    return()
  }
  
  # Perform search
  tryCatch({
    search_results <- enhanced_search(
      query = search_query,
      filters = list(
        types = types,
        states = states,
        limit = limit,
        offset = offset
      ),
      sources = c("lexml", "api"),
      options = list(
        enable_vocabulary_expansion = TRUE,
        enable_result_ranking = TRUE
      )
    )
    
    # Cache results
    cache_search_results(search_query, list(
      types = types,
      states = states,
      limit = limit,
      offset = offset
    ), search_results)
    
    response$set_header("X-Cache", "MISS")
    response$set_body(format_search_response(search_results, offset, limit))
    
  }, error = function(e) {
    log_event(paste("Search API error:", e$message), "ERROR")
    response$set_status_code(500L)
    response$set_body(list(
      error = "Search failed",
      message = "Unable to perform search operation"
    ))
  })
}

#' Get single document endpoint handler
#' @param request HTTP request object
#' @param response HTTP response object
get_document_handler <- function(request, response) {
  document_id <- request$path_params$id
  
  if (is.null(document_id) || document_id == "") {
    response$set_status_code(400L)
    response$set_body(list(
      error = "Invalid parameter",
      message = "Document ID is required"
    ))
    return()
  }
  
  tryCatch({
    # Get document from database or cache
    document <- get_document_by_id(document_id)
    
    if (is.null(document)) {
      response$set_status_code(404L)
      response$set_body(list(
        error = "Document not found",
        message = paste("Document with ID", document_id, "does not exist")
      ))
      return()
    }
    
    response$set_body(list(
      data = document,
      meta = list(
        id = document_id,
        retrieved_at = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ")
      )
    ))
    
  }, error = function(e) {
    log_event(paste("Get document API error:", e$message), "ERROR")
    response$set_status_code(500L)
    response$set_body(list(
      error = "Document retrieval failed",
      message = "Unable to retrieve document"
    ))
  })
}

#' Analytics summary endpoint handler
#' @param request HTTP request object
#' @param response HTTP response object
analytics_summary_handler <- function(request, response) {
  period <- request$query$period %||% "daily"
  
  if (!period %in% c("daily", "weekly", "monthly")) {
    response$set_status_code(400L)
    response$set_body(list(
      error = "Invalid parameter",
      message = "Period must be one of: daily, weekly, monthly"
    ))
    return()
  }
  
  tryCatch({
    analytics_data <- get_analytics_dashboard_data()
    
    summary <- list(
      period = period,
      generated_at = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ"),
      usage = analytics_data$usage_summary,
      cost = analytics_data$cost_summary,
      insights = analytics_data$insights
    )
    
    response$set_body(summary)
    
  }, error = function(e) {
    log_event(paste("Analytics API error:", e$message), "ERROR")
    response$set_status_code(500L)
    response$set_body(list(
      error = "Analytics retrieval failed",
      message = "Unable to retrieve analytics data"
    ))
  })
}

#' Export data endpoint handler
#' @param request HTTP request object
#' @param response HTTP response object
export_data_handler <- function(request, response) {
  if (request$content_type != "application/json") {
    response$set_status_code(400L)
    response$set_body(list(
      error = "Invalid content type",
      message = "Request must be JSON"
    ))
    return()
  }
  
  export_request <- fromJSON(request$body, simplifyVector = FALSE)
  
  # Validate export request
  validation_result <- validate_export_request(export_request)
  if (!validation_result$valid) {
    response$set_status_code(400L)
    response$set_body(list(
      error = "Invalid export request",
      message = validation_result$message
    ))
    return()
  }
  
  tryCatch({
    # Generate export asynchronously
    export_id <- generate_export_id()
    
    future({
      export_legislative_data(
        data = export_request$data,
        format = export_request$format %||% "csv",
        template = export_request$template %||% "research_dataset",
        options = export_request$options %||% list(),
        quality = export_request$quality %||% "standard"
      )
    }) %...>% {
      # Store export result
      store_export_result(export_id, .)
    } %...!% {
      # Store export error
      store_export_error(export_id, .)
    }
    
    response$set_status_code(202L)
    response$set_body(list(
      export_id = export_id,
      status = "processing",
      message = "Export request accepted",
      download_url = paste0("/api/v1/export/", export_id)
    ))
    
  }, error = function(e) {
    log_event(paste("Export API error:", e$message), "ERROR")
    response$set_status_code(500L)
    response$set_body(list(
      error = "Export failed",
      message = "Unable to process export request"
    ))
  })
}

#' System status endpoint handler
#' @param request HTTP request object
#' @param response HTTP response object
system_status_handler <- function(request, response) {
  tryCatch({
    status <- list(
      timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ"),
      version = API_CONFIG$versioning$current_version,
      environment = Sys.getenv("R_CONFIG_ACTIVE", "development"),
      system = list(
        r_version = R.version.string,
        platform = Sys.info()[["sysname"]],
        memory_mb = get_memory_usage()$used_mb,
        uptime_seconds = as.numeric(Sys.time() - api_state$startup_time, units = "secs")
      ),
      api = list(
        active_connections = api_state$active_connections,
        total_requests = length(api_state$request_counts),
        rate_limit_enabled = API_CONFIG$rate_limiting$enabled,
        authentication_required = API_CONFIG$authentication$require_auth
      )
    )
    
    response$set_body(status)
    
  }, error = function(e) {
    log_event(paste("System status API error:", e$message), "ERROR")
    response$set_status_code(500L)
    response$set_body(list(
      error = "System status unavailable",
      message = "Unable to retrieve system status"
    ))
  })
}

# Helper functions

#' Check API rate limit for client IP
#' @param client_ip Client IP address
#' @return Rate limit check result
check_api_rate_limit <- function(client_ip) {
  if (is.null(redis_connection)) {
    return(list(allowed = TRUE, remaining = API_CONFIG$rate_limiting$requests_per_minute))
  }
  
  current_minute <- format(Sys.time(), "%Y-%m-%d %H:%M")
  rate_key <- paste0("rate_limit:", client_ip, ":", current_minute)
  
  tryCatch({
    current_count <- as.integer(redis_connection$GET(rate_key) %||% 0)
    
    if (current_count >= API_CONFIG$rate_limiting$requests_per_minute) {
      return(list(
        allowed = FALSE,
        remaining = 0,
        message = "Rate limit exceeded for this minute"
      ))
    }
    
    # Increment counter
    redis_connection$INCR(rate_key)
    redis_connection$EXPIRE(rate_key, 60)  # Expire after 1 minute
    
    return(list(
      allowed = TRUE,
      remaining = API_CONFIG$rate_limiting$requests_per_minute - current_count - 1
    ))
    
  }, error = function(e) {
    log_event(paste("Rate limit check error:", e$message), "ERROR")
    return(list(allowed = TRUE, remaining = API_CONFIG$rate_limiting$requests_per_minute))
  })
}

#' Validate API key
#' @param api_key API key to validate
#' @return Validation result
validate_api_key <- function(api_key) {
  # Simple API key validation (in production, use proper key management)
  valid_keys <- c("dev-key-123", "test-key-456")
  
  if (api_key %in% valid_keys) {
    return(list(
      valid = TRUE,
      user = list(id = "api_user", role = "api_access")
    ))
  }
  
  return(list(
    valid = FALSE,
    message = "Invalid API key"
  ))
}

#' Validate JWT token
#' @param token JWT token to validate
#' @return Validation result
validate_jwt_token <- function(token) {
  tryCatch({
    # Decode JWT token (simplified validation)
    decoded <- jose::jwt_decode_sig(token, API_CONFIG$authentication$jwt_secret)
    
    # Check expiration
    if (decoded$exp < as.numeric(Sys.time())) {
      return(list(valid = FALSE, message = "Token expired"))
    }
    
    return(list(
      valid = TRUE,
      user = list(id = decoded$sub, role = decoded$role %||% "user")
    ))
    
  }, error = function(e) {
    return(list(valid = FALSE, message = "Invalid token"))
  })
}

#' Track API request
#' @param request HTTP request object
track_api_request <- function(request) {
  if (!API_CONFIG$monitoring$track_requests) {
    return()
  }
  
  request_info <- list(
    timestamp = Sys.time(),
    method = request$method,
    path = request$path,
    ip = request$headers[["X-Forwarded-For"]] %||% request$remote_addr,
    user_agent = request$headers[["User-Agent"]]
  )
  
  api_state$request_counts <<- append(api_state$request_counts, list(request_info), after = 0)
  
  # Limit request history
  if (length(api_state$request_counts) > 1000) {
    api_state$request_counts <<- head(api_state$request_counts, 1000)
  }
}

#' Track API response time
#' @param path Request path
#' @param response_time Response time in milliseconds
track_api_response_time <- function(path, response_time) {
  if (!API_CONFIG$monitoring$track_response_times) {
    return()
  }
  
  metric <- list(
    timestamp = Sys.time(),
    path = path,
    response_time_ms = response_time
  )
  
  api_state$performance_metrics <<- append(api_state$performance_metrics, list(metric), after = 0)
  
  # Limit performance metrics
  if (length(api_state$performance_metrics) > 500) {
    api_state$performance_metrics <<- head(api_state$performance_metrics, 500)
  }
}

#' Format search response
#' @param results Search results
#' @param offset Result offset
#' @param limit Result limit
#' @return Formatted response
format_search_response <- function(results, offset, limit) {
  total_count <- if (!is.null(results)) nrow(results) else 0
  
  response_data <- list(
    data = if (!is.null(results)) results else list(),
    meta = list(
      total = total_count,
      offset = offset,
      limit = limit,
      has_more = total_count > (offset + limit)
    ),
    links = list(
      self = paste0("/api/v1/search?offset=", offset, "&limit=", limit)
    )
  )
  
  # Add next/prev links
  if (total_count > (offset + limit)) {
    response_data$links$next <- paste0("/api/v1/search?offset=", offset + limit, "&limit=", limit)
  }
  
  if (offset > 0) {
    prev_offset <- max(0, offset - limit)
    response_data$links$prev <- paste0("/api/v1/search?offset=", prev_offset, "&limit=", limit)
  }
  
  return(response_data)
}

#' Generate unique request ID
#' @return Request ID string
generate_request_id <- function() {
  paste0("req_", format(Sys.time(), "%Y%m%d_%H%M%S"), "_", sample(1000:9999, 1))
}

#' Generate unique export ID
#' @return Export ID string
generate_export_id <- function() {
  paste0("exp_", format(Sys.time(), "%Y%m%d_%H%M%S"), "_", sample(1000:9999, 1))
}

#' Validate export request
#' @param export_request Export request object
#' @return Validation result
validate_export_request <- function(export_request) {
  required_fields <- c("format")
  
  for (field in required_fields) {
    if (is.null(export_request[[field]])) {
      return(list(
        valid = FALSE,
        message = paste("Missing required field:", field)
      ))
    }
  }
  
  valid_formats <- c("csv", "xlsx", "json", "html", "xml")
  if (!export_request$format %in% valid_formats) {
    return(list(
      valid = FALSE,
      message = paste("Invalid format. Must be one of:", paste(valid_formats, collapse = ", "))
    ))
  }
  
  return(list(valid = TRUE))
}

#' Start RestRserve API server
#' @param app RestRserve application instance
#' @param background Whether to run in background
#' @return Server instance
start_api_server <- function(app = NULL, background = TRUE) {
  if (is.null(app)) {
    app <- api_state$app
  }
  
  if (is.null(app)) {
    stop("API application not initialized. Call initialize_api_server() first.")
  }
  
  # Record startup time
  api_state$startup_time <<- Sys.time()
  
  log_event(paste("Starting RestRserve API server on", API_CONFIG$server$host, ":", API_CONFIG$server$port), "INFO")
  
  # Create backend
  backend <- BackendRserve$new()
  
  if (background) {
    # Start server in background
    future({
      backend$start(
        app = app,
        http_port = API_CONFIG$server$port,
        http_host = API_CONFIG$server$host,
        encoding = "utf8"
      )
    })
    
    log_event("RestRserve API server started in background", "INFO")
    return(backend)
  } else {
    # Start server in foreground (blocking)
    backend$start(
      app = app,
      http_port = API_CONFIG$server$port,
      http_host = API_CONFIG$server$host,
      encoding = "utf8"
    )
    
    return(backend)
  }
}

#' Initialize complete API system
#' @param start_server Whether to start the server immediately
#' @return Initialization result
initialize_api_system <- function(start_server = FALSE) {
  log_event("Initializing complete API system...", "INFO")
  
  # Initialize API application
  app <- initialize_api_server()
  
  # Start server if requested
  server <- if (start_server) {
    start_api_server(app, background = TRUE)
  } else {
    NULL
  }
  
  result <- list(
    status = "success",
    app = app,
    server = server,
    config = API_CONFIG
  )
  
  log_event("API system initialization completed", "INFO")
  
  return(result)
}