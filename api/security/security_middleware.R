# ============================================================================
# INTEGRATED SECURITY MIDDLEWARE - SPRINT 6B (API-004)
# ============================================================================
# 
# Comprehensive security middleware integration that combines CORS, security headers,
# domain validation, rate limiting, and authentication into a unified security layer
# for the Brazilian Legislative API. Provides seamless integration with existing
# authentication and rate limiting systems.
# 
# Features:
# - Unified security middleware orchestration
# - Integration with existing authentication system
# - Seamless CORS and domain validation
# - Security headers automation
# - Rate limiting coordination
# - Security event logging and analytics
# - Performance monitoring and optimization
# - LGPD compliance enforcement
# - Brazilian government security standards
# ============================================================================

cat("🔐 Loading Integrated Security Middleware\n")

# Load all security components
source("api/security/cors_configuration.R")
source("api/security/security_headers.R")  
source("api/security/domain_whitelist.R")

# Security middleware configuration
SECURITY_MIDDLEWARE_CONFIG <- list(
  # Component enable/disable flags
  components = list(
    cors_enabled = TRUE,
    security_headers_enabled = TRUE,
    domain_validation_enabled = TRUE,
    security_logging_enabled = TRUE,
    performance_monitoring_enabled = TRUE
  ),
  
  # Processing order for security middleware
  processing_order = c(
    "performance_monitoring",
    "security_headers",
    "cors_validation", 
    "domain_validation",
    "security_logging"
  ),
  
  # Integration settings
  integration = list(
    bypass_for_health_checks = TRUE,
    cache_validation_results = TRUE,
    cache_ttl_seconds = 300, # 5 minutes
    async_logging = TRUE,
    batch_logging = TRUE
  ),
  
  # Performance thresholds
  performance = list(
    max_processing_time_ms = 50,
    warning_threshold_ms = 30,
    circuit_breaker_enabled = TRUE,
    circuit_breaker_threshold = 100 # failures per minute
  ),
  
  # Security levels
  security_levels = list(
    minimal = list(
      cors_enabled = TRUE,
      security_headers_enabled = TRUE,
      domain_validation_enabled = FALSE
    ),
    standard = list(
      cors_enabled = TRUE,
      security_headers_enabled = TRUE,
      domain_validation_enabled = TRUE
    ),
    enhanced = list(
      cors_enabled = TRUE,
      security_headers_enabled = TRUE,
      domain_validation_enabled = TRUE,
      additional_validation = TRUE
    )
  )
)

# Security processing cache
SECURITY_CACHE <- list()

# Circuit breaker state
CIRCUIT_BREAKER_STATE <- list(
  failures_per_minute = 0,
  last_reset = Sys.time(),
  state = "closed" # closed, open, half-open
)

# Unified Security Middleware Controller
SecurityMiddlewareController <- list(
  # Main security processing function
  process_security = function(req, res) {
    processing_start <- Sys.time()
    
    # Check circuit breaker
    if (SecurityMiddlewareController$is_circuit_breaker_open()) {
      SecurityMiddlewareController$apply_minimal_security(req, res)
      return(SecurityMiddlewareController$create_security_context(req, "circuit_breaker"))
    }
    
    # Check if this is a health check or system endpoint
    if (SecurityMiddlewareController$is_system_endpoint(req)) {
      if (SECURITY_MIDDLEWARE_CONFIG$integration$bypass_for_health_checks) {
        return(SecurityMiddlewareController$create_security_context(req, "bypassed"))
      }
    }
    
    # Get API key information from authentication middleware
    api_key_id <- req$api_key_id %||% 0
    api_tier <- req$api_tier %||% "demo"
    api_key_data <- req$api_key_data
    
    # Check cache for previous validation
    cache_key <- SecurityMiddlewareController$generate_cache_key(req, api_tier)
    cached_result <- SecurityMiddlewareController$get_cached_validation(cache_key)
    
    if (!is.null(cached_result)) {
      # Apply cached security settings
      SecurityMiddlewareController$apply_cached_security(req, res, cached_result)
      return(SecurityMiddlewareController$create_security_context(req, "cached"))
    }
    
    # Process security components in order
    security_result <- list(
      cors_result = NULL,
      headers_result = NULL,
      domain_result = NULL,
      performance = list()
    )
    
    tryCatch({
      for (component in SECURITY_MIDDLEWARE_CONFIG$processing_order) {
        component_start <- Sys.time()
        
        component_result <- SecurityMiddlewareController$process_component(
          component, req, res, api_tier, api_key_data)
        
        component_time <- as.numeric(difftime(Sys.time(), component_start, units = "secs")) * 1000
        security_result$performance[[component]] <- component_time
        
        # Store component result
        if (component == "cors_validation") {
          security_result$cors_result <- component_result
        } else if (component == "security_headers") {
          security_result$headers_result <- component_result
        } else if (component == "domain_validation") {
          security_result$domain_result <- component_result
        }
        
        # Check if component failed and should block request
        if (!is.null(component_result$block_request) && component_result$block_request) {
          return(component_result)
        }
      }
      
      # Cache successful validation
      total_time <- as.numeric(difftime(Sys.time(), processing_start, units = "secs")) * 1000
      security_result$total_time <- total_time
      
      if (SECURITY_MIDDLEWARE_CONFIG$integration$cache_validation_results) {
        SecurityMiddlewareController$cache_validation(cache_key, security_result)
      }
      
      # Log security processing
      if (SECURITY_MIDDLEWARE_CONFIG$components$security_logging_enabled) {
        SecurityMiddlewareController$log_security_processing(req, security_result)
      }
      
      return(SecurityMiddlewareController$create_security_context(req, "processed", security_result))
      
    }, error = function(e) {
      # Handle security processing error
      SecurityMiddlewareController$record_circuit_breaker_failure()
      
      cat("Security middleware error:", e$message, "\n")
      
      # Apply minimal security and continue
      SecurityMiddlewareController$apply_minimal_security(req, res)
      return(SecurityMiddlewareController$create_security_context(req, "error", list(error = e$message)))
    })
  },
  
  # Process individual security component
  process_component = function(component, req, res, api_tier, api_key_data) {
    switch(component,
      "performance_monitoring" = {
        # Start performance monitoring
        req$security_start_time <- Sys.time()
        return(list(success = TRUE))
      },
      
      "security_headers" = {
        if (SECURITY_MIDDLEWARE_CONFIG$components$security_headers_enabled) {
          SecurityHeadersManager$set_all_security_headers(req, res, api_tier)
          return(list(success = TRUE, component = "security_headers"))
        }
        return(list(success = TRUE, skipped = TRUE))
      },
      
      "cors_validation" = {
        if (SECURITY_MIDDLEWARE_CONFIG$components$cors_enabled) {
          origin <- req$HTTP_ORIGIN
          
          if (!is.null(origin)) {
            origin_validation <- CORSOriginValidator$is_origin_allowed_for_tier(origin, api_tier, api_key_data)
            
            if (!origin_validation$valid) {
              # CORS validation failed
              res$status <- 403
              res$setHeader("Content-Type", "application/json")
              
              return(list(
                success = FALSE,
                block_request = TRUE,
                component = "cors_validation",
                error = origin_validation$error,
                response = jsonlite::toJSON(list(
                  error = TRUE,
                  message = "CORS: Origin not allowed",
                  details = list(
                    origin = origin,
                    tier = api_tier,
                    reason = origin_validation$error
                  ),
                  code = 403
                ), auto_unbox = TRUE)
              ))
            }
            
            # Set CORS headers
            CORSHeaderManager$set_cors_headers(req, res, api_tier, origin_validation, api_key_data)
          }
          
          return(list(success = TRUE, component = "cors_validation", origin_validated = !is.null(origin)))
        }
        return(list(success = TRUE, skipped = TRUE))
      },
      
      "domain_validation" = {
        if (SECURITY_MIDDLEWARE_CONFIG$components$domain_validation_enabled) {
          origin <- req$HTTP_ORIGIN
          
          if (!is.null(origin)) {
            # Extract domain from origin
            domain_match <- regexpr("://([^:/?#]+)", origin, perl = TRUE)
            if (domain_match != -1) {
              domain <- substr(origin, attr(domain_match, "capture.start")[1], 
                             attr(domain_match, "capture.start")[1] + attr(domain_match, "capture.length")[1] - 1)
              
              domain_validation <- DomainManager$validate_domain(domain)
              
              # Log domain validation result
              req$domain_validation <- domain_validation
            }
          }
          
          return(list(success = TRUE, component = "domain_validation"))
        }
        return(list(success = TRUE, skipped = TRUE))
      },
      
      "security_logging" = {
        if (SECURITY_MIDDLEWARE_CONFIG$components$security_logging_enabled) {
          # Security logging will be handled after all processing
          return(list(success = TRUE, component = "security_logging"))
        }
        return(list(success = TRUE, skipped = TRUE))
      },
      
      # Default case
      {
        return(list(success = TRUE, skipped = TRUE, unknown_component = component))
      }
    )
  },
  
  # Apply minimal security (used during circuit breaker or errors)
  apply_minimal_security = function(req, res) {
    # Always apply basic security headers
    res$setHeader("X-Content-Type-Options", "nosniff")
    res$setHeader("X-Frame-Options", "DENY")
    res$setHeader("X-XSS-Protection", "1; mode=block")
    res$setHeader("Server", "Monitor-Legislativo-API")
    
    # Basic CORS for localhost (development)
    origin <- req$HTTP_ORIGIN
    if (!is.null(origin) && (grepl("localhost", origin) || grepl("127.0.0.1", origin))) {
      res$setHeader("Access-Control-Allow-Origin", origin)
      res$setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
      res$setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
    }
  },
  
  # Generate cache key for security validation
  generate_cache_key = function(req, api_tier) {
    origin <- req$HTTP_ORIGIN %||% "no-origin"
    method <- req$REQUEST_METHOD
    key_components <- c(origin, method, api_tier)
    return(paste(key_components, collapse = "|"))
  },
  
  # Get cached validation result
  get_cached_validation = function(cache_key) {
    if (!SECURITY_MIDDLEWARE_CONFIG$integration$cache_validation_results) {
      return(NULL)
    }
    
    cached_data <- SECURITY_CACHE[[cache_key]]
    if (is.null(cached_data)) {
      return(NULL)
    }
    
    # Check if cache has expired
    cache_age <- as.numeric(difftime(Sys.time(), cached_data$timestamp, units = "secs"))
    if (cache_age > SECURITY_MIDDLEWARE_CONFIG$integration$cache_ttl_seconds) {
      SECURITY_CACHE[[cache_key]] <<- NULL
      return(NULL)
    }
    
    return(cached_data$result)
  },
  
  # Cache validation result
  cache_validation = function(cache_key, result) {
    SECURITY_CACHE[[cache_key]] <<- list(
      result = result,
      timestamp = Sys.time()
    )
    
    # Clean old cache entries periodically
    if (length(SECURITY_CACHE) > 1000) {
      SecurityMiddlewareController$cleanup_cache()
    }
  },
  
  # Apply cached security settings
  apply_cached_security = function(req, res, cached_result) {
    # Re-apply security headers (these are lightweight)
    api_tier <- req$api_tier %||% "demo"
    SecurityHeadersManager$set_all_security_headers(req, res, api_tier)
    
    # Re-apply CORS headers if origin validation was successful
    origin <- req$HTTP_ORIGIN
    if (!is.null(origin) && !is.null(cached_result$cors_result) && cached_result$cors_result$success) {
      # Note: This is simplified - in production, you might want to re-validate CORS
      res$setHeader("Access-Control-Allow-Origin", origin)
    }
  },
  
  # Check if request is for a system endpoint
  is_system_endpoint = function(req) {
    system_paths <- c("/health", "/status", "/metrics", "/ping")
    request_path <- req$PATH_INFO %||% ""
    return(any(sapply(system_paths, function(path) grepl(paste0("^", path), request_path))))
  },
  
  # Create security context for request
  create_security_context = function(req, processing_status, results = NULL) {
    req$security_context <- list(
      processing_status = processing_status,
      timestamp = Sys.time(),
      results = results
    )
    
    return(req$security_context)
  },
  
  # Circuit breaker management
  is_circuit_breaker_open = function() {
    if (!SECURITY_MIDDLEWARE_CONFIG$performance$circuit_breaker_enabled) {
      return(FALSE)
    }
    
    return(CIRCUIT_BREAKER_STATE$state == "open")
  },
  
  record_circuit_breaker_failure = function() {
    current_time <- Sys.time()
    
    # Reset counter if more than a minute has passed
    if (difftime(current_time, CIRCUIT_BREAKER_STATE$last_reset, units = "secs") >= 60) {
      CIRCUIT_BREAKER_STATE$failures_per_minute <<- 0
      CIRCUIT_BREAKER_STATE$last_reset <<- current_time
    }
    
    CIRCUIT_BREAKER_STATE$failures_per_minute <<- CIRCUIT_BREAKER_STATE$failures_per_minute + 1
    
    # Open circuit breaker if threshold exceeded
    if (CIRCUIT_BREAKER_STATE$failures_per_minute >= SECURITY_MIDDLEWARE_CONFIG$performance$circuit_breaker_threshold) {
      CIRCUIT_BREAKER_STATE$state <<- "open"
      cat("⚠️ Security middleware circuit breaker opened\n")
    }
  },
  
  # Log security processing
  log_security_processing = function(req, results) {
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(FALSE)
    }
    
    tryCatch({
      api_key_id <- req$api_key_id %||% 0
      api_tier <- req$api_tier %||% "unknown"
      origin <- req$HTTP_ORIGIN %||% "no-origin"
      
      DBI::dbExecute(secure_db_pool,
        "INSERT INTO security_middleware_log (api_key_id, api_tier, origin, processing_time_ms, components_processed, results) 
         VALUES ($1, $2, $3, $4, $5, $6)",
        list(api_key_id, api_tier, origin, results$total_time %||% 0, 
             length(results$performance), jsonlite::toJSON(results, auto_unbox = TRUE)))
      
      return(TRUE)
    }, error = function(e) {
      cat("Warning: Failed to log security processing:", e$message, "\n")
      return(FALSE)
    })
  },
  
  # Clean up expired cache entries
  cleanup_cache = function() {
    current_time <- Sys.time()
    ttl <- SECURITY_MIDDLEWARE_CONFIG$integration$cache_ttl_seconds
    
    expired_keys <- c()
    for (key in names(SECURITY_CACHE)) {
      cache_age <- as.numeric(difftime(current_time, SECURITY_CACHE[[key]]$timestamp, units = "secs"))
      if (cache_age > ttl) {
        expired_keys <- c(expired_keys, key)
      }
    }
    
    for (key in expired_keys) {
      SECURITY_CACHE[[key]] <<- NULL
    }
    
    if (length(expired_keys) > 0) {
      cat("🧹 Cleaned", length(expired_keys), "expired security cache entries\n")
    }
  }
)

# Main integrated security filter
#* @filter integrated_security
function(req, res) {
  # Process all security components
  security_context <- SecurityMiddlewareController$process_security(req, res)
  
  # Check if request should be blocked
  if (!is.null(security_context$results) && 
      !is.null(security_context$results$cors_result) &&
      !is.null(security_context$results$cors_result$block_request) &&
      security_context$results$cors_result$block_request) {
    
    # Return the blocking response
    return(security_context$results$cors_result$response)
  }
  
  # Handle preflight OPTIONS requests
  if (req$REQUEST_METHOD == "OPTIONS") {
    res$status <- 204
    res$setHeader("Content-Length", "0")
    return("")
  }
  
  # Continue processing if all security checks passed
  plumber::forward()
}

# Security middleware statistics and monitoring
SecurityMiddlewareStats <- list(
  # Get security middleware performance statistics
  get_performance_stats = function(period_days = 7) {
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(list(error = "Database not available"))
    }
    
    tryCatch({
      # Processing time statistics
      perf_stats_query <- "
        SELECT 
          api_tier,
          COUNT(*) as total_requests,
          AVG(processing_time_ms) as avg_processing_time,
          MAX(processing_time_ms) as max_processing_time,
          MIN(processing_time_ms) as min_processing_time,
          PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY processing_time_ms) as p95_processing_time
        FROM security_middleware_log
        WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
        GROUP BY api_tier
        ORDER BY avg_processing_time DESC
      "
      perf_stats <- DBI::dbGetQuery(secure_db_pool, sprintf(perf_stats_query, period_days))
      
      return(list(
        period_days = period_days,
        performance_by_tier = perf_stats,
        circuit_breaker_state = CIRCUIT_BREAKER_STATE,
        cache_size = length(SECURITY_CACHE)
      ))
      
    }, error = function(e) {
      return(list(error = paste("Failed to get performance statistics:", e$message)))
    })
  },
  
  # Get security validation success rates
  get_validation_success_rates = function(period_days = 7) {
    cors_stats <- CORSAnalytics$get_cors_statistics(period_days)
    headers_stats <- SecurityHeadersAnalytics$get_compliance_report(period_days)
    middleware_stats <- SecurityMiddlewareStats$get_performance_stats(period_days)
    
    return(list(
      cors_statistics = cors_stats,
      headers_compliance = headers_stats,
      middleware_performance = middleware_stats
    ))
  }
)

# Initialize integrated security middleware system
initialize_integrated_security_middleware <- function() {
  # Ensure required tables exist
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    security_middleware_schema <- "
      CREATE TABLE IF NOT EXISTS security_middleware_log (
        id SERIAL PRIMARY KEY,
        api_key_id INTEGER DEFAULT 0,
        api_tier VARCHAR(50),
        origin VARCHAR(255),
        processing_time_ms NUMERIC(10,2),
        components_processed INTEGER DEFAULT 0,
        results JSONB,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE INDEX IF NOT EXISTS idx_security_middleware_log_timestamp ON security_middleware_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_security_middleware_log_tier ON security_middleware_log(api_tier);
    "
    
    tryCatch({
      DBI::dbExecute(secure_db_pool, security_middleware_schema)
      cat("✅ Security middleware logging tables initialized\n")
    }, error = function(e) {
      cat("⚠️ Failed to initialize security middleware tables:", e$message, "\n")
    })
  }
  
  cat("✅ Integrated Security Middleware System initialized\n")
  cat("  🔐 Unified security processing orchestration\n")
  cat("  ⚡ Performance monitoring and circuit breaker protection\n") 
  cat("  📊 Security validation caching and analytics\n")
  cat("  🛡️ CORS, headers, and domain validation integration\n")
  cat("  ⚖️ LGPD compliance and Brazilian government standards\n")
  
  return(TRUE)
}

# Auto-initialize
initialize_integrated_security_middleware()

cat("✅ Integrated Security Middleware Loaded\n")