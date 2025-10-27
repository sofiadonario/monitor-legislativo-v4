# ============================================================================
# HEALTH & STATUS ENDPOINTS - WEEK 6 REST API IMPLEMENTATION
# ============================================================================
# 
# Comprehensive health monitoring and API status endpoints
# Provides detailed system information for monitoring and debugging
# Includes performance metrics, database status, and service availability
# 
# Endpoints:
# - GET /api/v1/health - Basic health check (public)
# - GET /api/v1/status - Detailed system status (authenticated)
# - GET /api/v1/metrics - Performance metrics (authenticated)
# - GET /api/v1/info - API information and configuration
# ============================================================================

cat("🏥 Loading Health & Status Endpoints - Week 6\n")

# System configuration and constants
SYSTEM_CONFIG <- list(
  version = "4.0.0-week6",
  build_date = "2024-01-15",
  environment = Sys.getenv("ENVIRONMENT", "development"),
  region = "South America (São Paulo)",
  deployment_platform = "Railway",
  start_time = Sys.time(),
  
  # Health check thresholds
  thresholds = list(
    response_time_ms = 500,
    memory_usage_mb = 512,
    cpu_usage_percent = 80,
    database_connection_timeout_seconds = 5
  ),
  
  # Service dependencies
  dependencies = list(
    database = list(
      name = "PostgreSQL",
      required = TRUE,
      timeout_seconds = 5
    ),
    cache = list(
      name = "Redis",
      required = FALSE,
      timeout_seconds = 3
    ),
    external_apis = list(
      ibge = list(
        name = "IBGE API",
        required = FALSE,
        timeout_seconds = 10
      )
    )
  )
)

# Global metrics tracking
API_METRICS <- list(
  requests = list(
    total = 0,
    current_hour = 0,
    errors = 0,
    last_reset = Sys.time()
  ),
  response_times = numeric(0),
  endpoints_usage = list(),
  error_log = list()
)

# Helper function to check database health
check_database_health <- function() {
  start_time <- Sys.time()
  
  db_status <- list(
    status = "unknown",
    response_time_ms = NA,
    error = NULL,
    details = list()
  )
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      # Test basic connectivity
      test_query <- "SELECT 1 as health_check, NOW() as server_time"
      result <- dbGetQuery(secure_db_pool, test_query)
      
      response_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
      
      if (nrow(result) > 0) {
        db_status$status <- "healthy"
        db_status$response_time_ms <- round(response_time, 2)
        db_status$details <- list(
          server_time = result$server_time[1],
          connection_pool_size = if (is(secure_db_pool, "Pool")) poolCheckout(secure_db_pool) else "single",
          last_connected = Sys.time()
        )
      } else {
        db_status$status <- "unhealthy"
        db_status$error <- "Query returned no results"
      }
      
      # Additional database health checks
      tryCatch({
        # Check table existence
        table_check <- dbGetQuery(secure_db_pool, "SELECT COUNT(*) as table_count FROM information_schema.tables WHERE table_schema = 'public'")
        db_status$details$table_count <- table_check$table_count[1]
        
        # Check document count
        doc_count <- dbGetQuery(secure_db_pool, "SELECT COUNT(*) as total_documents FROM documents")
        db_status$details$total_documents <- doc_count$total_documents[1]
        
      }, error = function(e) {
        db_status$details$metadata_error <- e$message
      })
      
    } else {
      db_status$status <- "unavailable"
      db_status$error <- "Database connection not initialized"
    }
    
  }, error = function(e) {
    response_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
    db_status$status <- "error"
    db_status$response_time_ms <- round(response_time, 2)
    db_status$error <- e$message
  })
  
  return(db_status)
}

# Helper function to get system resource usage
get_system_resources <- function() {
  resources <- list(
    memory_usage_mb = NA,
    cpu_usage_percent = NA,
    uptime_seconds = as.numeric(difftime(Sys.time(), SYSTEM_CONFIG$start_time, units = "secs")),
    load_average = NA,
    disk_usage = list()
  )
  
  tryCatch({
    # Memory usage (approximate)
    if (Sys.info()[["sysname"]] == "Linux") {
      # Try to get memory info on Linux
      if (file.exists("/proc/meminfo")) {
        meminfo <- readLines("/proc/meminfo", n = 10)
        total_line <- grep("MemTotal", meminfo, value = TRUE)
        available_line <- grep("MemAvailable", meminfo, value = TRUE)
        
        if (isTRUE(length(total_line) > 0) && length(available_line) > 0) {
          total_kb <- as.numeric(gsub(".*?([0-9]+).*", "\\1", total_line))
          available_kb <- as.numeric(gsub(".*?([0-9]+).*", "\\1", available_line))
          used_mb <- (total_kb - available_kb) / 1024
          resources$memory_usage_mb <- round(used_mb, 1)
        }
      }
      
      # Load average
      if (file.exists("/proc/loadavg")) {
        loadavg <- readLines("/proc/loadavg", n = 1)
        resources$load_average <- as.numeric(strsplit(loadavg, " ")[[1]][1])
      }
    } else {
      # Fallback memory estimation
      resources$memory_usage_mb <- round(as.numeric(object.size(ls(envir = .GlobalEnv))) / 1024^2, 1)
    }
    
    # R-specific memory info
    resources$r_memory_usage <- list(
      objects_mb = round(sum(sapply(ls(envir = .GlobalEnv), function(x) object.size(get(x)))) / 1024^2, 1),
      gc_info = gc()
    )
    
  }, error = function(e) {
    resources$resource_error <- e$message
  })
  
  return(resources)
}

# Helper function to check external service health
check_external_services <- function() {
  services <- list()
  
  # Check IBGE API (example external service)
  tryCatch({
    start_time <- Sys.time()
    
    # Simple HEAD request to IBGE API
    if (requireNamespace("httr", quietly = TRUE)) {
      response <- httr::HEAD("https://servicodados.ibge.gov.br/api/v1/localidades/estados",
                            httr::timeout(3))
      
      response_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
      
      services$ibge_api <- list(
        status = if (httr::status_code(response) == 200) "healthy" else "unhealthy",
        response_time_ms = round(response_time, 2),
        status_code = httr::status_code(response)
      )
    } else {
      services$ibge_api <- list(
        status = "unknown",
        error = "httr package not available"
      )
    }
    
  }, error = function(e) {
    services$ibge_api <- list(
      status = "error",
      error = e$message
    )
  })
  
  return(services)
}

# Update API metrics
update_metrics <- function(endpoint = NULL, response_time_ms = NULL, error = FALSE) {
  # Update global counters
  API_METRICS$requests$total <<- API_METRICS$requests$total + 1
  
  # Reset hourly counter if needed
  if (difftime(Sys.time(), API_METRICS$requests$last_reset, units = "hours") >= 1) {
    API_METRICS$requests$current_hour <<- 0
    API_METRICS$requests$last_reset <<- Sys.time()
  }
  
  API_METRICS$requests$current_hour <<- API_METRICS$requests$current_hour + 1
  
  if (error) {
    API_METRICS$requests$errors <<- API_METRICS$requests$errors + 1
  }
  
  # Track response times (keep last 100)
  if (!is.null(response_time_ms)) {
    API_METRICS$response_times <<- tail(c(API_METRICS$response_times, response_time_ms), 100)
  }
  
  # Track endpoint usage
  if (!is.null(endpoint)) {
    if (is.null(API_METRICS$endpoints_usage[[endpoint]])) {
      API_METRICS$endpoints_usage[[endpoint]] <<- 0
    }
    API_METRICS$endpoints_usage[[endpoint]] <<- API_METRICS$endpoints_usage[[endpoint]] + 1
  }
}

# Basic health check endpoint (public)
#' @get /api/v1/health
#' @tag system
#' @serializer unboxedJSON
function(req, res) {
  start_time <- Sys.time()
  
  # Basic health indicators
  health_status <- list(
    status = "healthy",
    timestamp = Sys.time(),
    version = SYSTEM_CONFIG$version,
    environment = SYSTEM_CONFIG$environment
  )
  
  # Check critical dependencies
  db_health <- check_database_health()
  
  # Determine overall health
  if (db_health$status %in% c("error", "unhealthy")) {
    health_status$status <- "unhealthy"
  } else if (db_health$status == "unavailable") {
    health_status$status <- "degraded"
  }
  
  # Calculate response time
  response_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
  health_status$response_time_ms <- round(response_time, 2)
  
  # Set appropriate HTTP status
  if (health_status$status == "healthy") {
    res$status <- 200
  } else if (health_status$status == "degraded") {
    res$status <- 200  # Still operational
  } else {
    res$status <- 503  # Service unavailable
  }
  
  # Update metrics
  update_metrics("health", response_time, health_status$status != "healthy")
  
  return(list(
    error = health_status$status != "healthy",
    message = paste("Monitor Legislativo API status:", health_status$status),
    data = health_status,
    timestamp = Sys.time()
  ))
}

# Detailed system status endpoint (authenticated)
#' @get /api/v1/status
#' @tag system
#' @serializer unboxedJSON
function(req, res) {
  start_time <- Sys.time()
  
  # Comprehensive status check
  status_report <- list(
    system = list(
      status = "operational",
      version = SYSTEM_CONFIG$version,
      build_date = SYSTEM_CONFIG$build_date,
      environment = SYSTEM_CONFIG$environment,
      region = SYSTEM_CONFIG$region,
      platform = SYSTEM_CONFIG$deployment_platform,
      uptime_seconds = as.numeric(difftime(Sys.time(), SYSTEM_CONFIG$start_time, units = "secs")),
      uptime_human = format(Sys.time() - SYSTEM_CONFIG$start_time)
    ),
    
    database = check_database_health(),
    
    resources = get_system_resources(),
    
    external_services = check_external_services(),
    
    api_info = list(
      total_endpoints = length(c("health", "status", "legislation/search", "geographic/analysis", "citations/generate", "export/data")),
      authentication_required = TRUE,
      rate_limiting_enabled = TRUE,
      current_requests_per_second = if (length(API_METRICS$response_times) > 0) {
        round(length(API_METRICS$response_times) / 60, 2)  # Approximate
      } else 0
    )
  )
  
  # Determine overall system status
  critical_services <- c("database")
  if (any(sapply(critical_services, function(service) {
    status_report[[service]]$status %in% c("error", "unhealthy")
  }))) {
    status_report$system$status <- "degraded"
  }
  
  # Add performance indicators
  response_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
  status_report$performance <- list(
    status_check_time_ms = round(response_time, 2),
    avg_response_time_ms = if (length(API_METRICS$response_times) > 0) {
      round(mean(API_METRICS$response_times), 2)
    } else NA,
    p95_response_time_ms = if (length(API_METRICS$response_times) > 10) {
      round(quantile(API_METRICS$response_times, 0.95), 2)
    } else NA
  )
  
  # Update metrics
  update_metrics("status", response_time)
  
  return(list(
    error = FALSE,
    message = "Detailed system status",
    data = status_report,
    timestamp = Sys.time()
  ))
}

# Performance metrics endpoint (authenticated)
#' @get /api/v1/metrics
#' @tag system
#' @serializer unboxedJSON
function(req, res) {
  
  # Calculate various metrics
  current_time <- Sys.time()
  uptime_seconds <- as.numeric(difftime(current_time, SYSTEM_CONFIG$start_time, units = "secs"))
  
  metrics <- list(
    request_metrics = list(
      total_requests = API_METRICS$requests$total,
      requests_current_hour = API_METRICS$requests$current_hour,
      total_errors = API_METRICS$requests$errors,
      error_rate_percent = if (API_METRICS$requests$total > 0) {
        round((API_METRICS$requests$errors / API_METRICS$requests$total) * 100, 2)
      } else 0,
      requests_per_second = if (uptime_seconds > 0) {
        round(API_METRICS$requests$total / uptime_seconds, 4)
      } else 0
    ),
    
    response_time_metrics = if (length(API_METRICS$response_times) > 0) {
      list(
        count = length(API_METRICS$response_times),
        avg_ms = round(mean(API_METRICS$response_times), 2),
        median_ms = round(median(API_METRICS$response_times), 2),
        p95_ms = round(quantile(API_METRICS$response_times, 0.95), 2),
        p99_ms = round(quantile(API_METRICS$response_times, 0.99), 2),
        min_ms = round(min(API_METRICS$response_times), 2),
        max_ms = round(max(API_METRICS$response_times), 2)
      )
    } else {
      list(
        count = 0,
        message = "No response time data available"
      )
    },
    
    endpoint_usage = API_METRICS$endpoints_usage,
    
    system_metrics = list(
      uptime_seconds = uptime_seconds,
      uptime_human = format(current_time - SYSTEM_CONFIG$start_time),
      memory_usage = get_system_resources()$memory_usage_mb,
      start_time = SYSTEM_CONFIG$start_time,
      environment = SYSTEM_CONFIG$environment
    ),
    
    health_summary = list(
      overall_status = "operational",
      last_health_check = current_time,
      critical_alerts = list()  # Would contain any alerts
    )
  )
  
  # Add database metrics if available
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    tryCatch({
      # Get database-specific metrics
      db_metrics_query <- "
        SELECT 
          (SELECT COUNT(*) FROM documents) as total_documents,
          (SELECT COUNT(DISTINCT estado) FROM documents WHERE estado IS NOT NULL) as states_covered,
          (SELECT COUNT(DISTINCT municipio) FROM documents WHERE municipio IS NOT NULL) as municipalities_covered,
          (SELECT MIN(data_publicacao) FROM documents WHERE data_publicacao IS NOT NULL) as oldest_document,
          (SELECT MAX(data_publicacao) FROM documents WHERE data_publicacao IS NOT NULL) as newest_document
      "
      
      db_metrics <- dbGetQuery(secure_db_pool, db_metrics_query)
      
      metrics$database_metrics <- list(
        total_documents = db_metrics$total_documents[1],
        states_covered = db_metrics$states_covered[1],
        municipalities_covered = db_metrics$municipalities_covered[1],
        date_range = list(
          oldest = db_metrics$oldest_document[1],
          newest = db_metrics$newest_document[1]
        )
      )
      
    }, error = function(e) {
      metrics$database_metrics <- list(
        error = "Could not retrieve database metrics",
        details = e$message
      )
    })
  }
  
  return(list(
    error = FALSE,
    message = "Performance metrics",
    data = metrics,
    timestamp = Sys.time()
  ))
}

# API information endpoint
#' @get /api/v1/info
#' @tag system
#' @serializer unboxedJSON
function(req, res) {
  
  api_info <- list(
    name = "Monitor Legislativo v4 API",
    description = "API REST para acesso a documentos legislativos brasileiros sobre transporte",
    version = SYSTEM_CONFIG$version,
    build_info = list(
      build_date = SYSTEM_CONFIG$build_date,
      environment = SYSTEM_CONFIG$environment,
      region = SYSTEM_CONFIG$region,
      platform = SYSTEM_CONFIG$deployment_platform
    ),
    
    endpoints = list(
      base_url = "https://monitor-legislativo-unified-production.up.railway.app/api/v1",
      documentation_url = "https://monitor-legislativo.br/docs",
      openapi_spec_url = "/api/v1/docs/openapi.yaml",
      available_endpoints = list(
        "GET /health" = "Health check (public)",
        "GET /status" = "Detailed system status",
        "GET /metrics" = "Performance metrics",
        "GET /info" = "API information",
        "GET /legislation/search" = "Search legislative documents",
        "GET /legislation/{id}" = "Get specific document",
        "GET /legislation/types" = "Available document types",
        "GET /legislation/states" = "State statistics",
        "GET /geographic/analysis" = "Geographic analysis",
        "GET /geographic/ibge" = "IBGE integration",
        "GET /citations/generate" = "Generate academic citations",
        "POST /citations/batch" = "Batch citation generation",
        "GET /citations/formats" = "Available citation formats",
        "GET /export/data" = "Data export",
        "GET /export/formats" = "Export formats",
        "GET /auth/validate" = "Validate API key"
      )
    ),
    
    authentication = list(
      method = "API Key",
      header = "X-API-Key",
      tiers = list(
        demo = list(
          name = "Demonstração",
          requests_per_hour = 100,
          max_results = 50
        ),
        academic = list(
          name = "Pesquisa Acadêmica", 
          requests_per_hour = 1000,
          max_results = 1000
        ),
        institutional = list(
          name = "Institucional",
          requests_per_hour = 2000,
          max_results = 5000
        )
      )
    ),
    
    data_info = list(
      total_documents = "134,000+",
      coverage = "Todos os estados brasileiros",
      period = "1988-2024",
      focus = "Legislação de transporte e mobilidade urbana",
      update_frequency = "Contínua",
      quality_assurance = "Validação acadêmica"
    ),
    
    compliance = list(
      lgpd_compliant = TRUE,
      academic_standards = "ABNT, APA, Chicago",
      data_protection = "Criptografia TLS 1.3",
      audit_logging = TRUE,
      geographical_compliance = "Brasil (Lei de Acesso à Informação)"
    ),
    
    support = list(
      documentation = "https://monitor-legislativo.br/docs",
      api_guide = "https://monitor-legislativo.br/docs/api-guide",
      tutorials = "https://monitor-legislativo.br/docs/tutorials",
      examples = "https://monitor-legislativo.br/docs/examples",
      contact_email = "api-suporte@monitor-legislativo.br",
      github = "https://github.com/monitor-legislativo/api-v4"
    )
  )
  
  return(list(
    error = FALSE,
    message = "API information",
    data = api_info,
    timestamp = Sys.time()
  ))
}

# Middleware to track metrics for all requests
api_metrics_middleware <- function(req, res) {
  # Record request start time
  req$start_time <- Sys.time()
  
  # Extract endpoint from path
  endpoint <- gsub("^/api/v1/", "", req$PATH_INFO)
  req$endpoint <- endpoint
  
  plumber::forward()
}

# Response middleware to calculate and store response times
api_response_middleware <- function(req, res, value) {
  if (!is.null(req$start_time)) {
    response_time <- as.numeric(difftime(Sys.time(), req$start_time, units = "secs")) * 1000
    
    # Update metrics
    update_metrics(
      endpoint = req$endpoint,
      response_time_ms = response_time,
      error = res$status >= 400
    )
  }
  
  # Add performance headers
  res$setHeader("X-Response-Time", paste0(round(response_time, 2), "ms"))
  res$setHeader("X-API-Version", SYSTEM_CONFIG$version)
  
  return(value)
}

cat("✅ Health & Status Endpoints loaded successfully\n")
cat("📊 Features: Health monitoring • Performance metrics • System status • Resource tracking\n")
cat("🔍 Endpoints: /health • /status • /metrics • /info\n")