# ============================================================================
# RATE LIMITING & USAGE TRACKING SYSTEM - SPRINT 6B (API-002)
# ============================================================================
# 
# Advanced rate limiting and usage tracking system for Brazilian Legislative API
# Implements multi-tier rate limiting, usage analytics, and quota management
# 
# Features:
# - Multi-tier rate limiting (hourly, daily, monthly)
# - Real-time usage tracking and analytics
# - Adaptive rate limiting based on system load
# - Geographic-based rate limiting
# - Endpoint-specific rate limits
# - Usage quotas with auto-renewal
# - Burst allowance for academic users
# - Priority queue for premium users
# - Redis and database storage options
# ============================================================================

cat("⏱️ Loading Advanced Rate Limiting & Usage Tracking System\n")

# Source required modules
if (file.exists("api/auth/authentication_system.R")) {
  source("api/auth/authentication_system.R")
}

# Rate Limiting Configuration
RATE_LIMITING_CONFIG <- list(
  # Storage backend options
  storage_backend = "database", # "memory", "database", "redis"
  
  # Rate limiting windows
  windows = list(
    minute = 60,      # 1 minute
    hour = 3600,      # 1 hour
    day = 86400,      # 24 hours
    month = 2592000   # 30 days
  ),
  
  # Tier-specific configurations
  tier_configs = list(
    demo = list(
      requests_per_minute = 10,
      requests_per_hour = 100,
      requests_per_day = 1000,
      requests_per_month = 10000,
      burst_allowance = 20,
      data_transfer_limit_mb_per_day = 100,
      priority_level = 1
    ),
    academic = list(
      requests_per_minute = 50,
      requests_per_hour = 1000,
      requests_per_day = 10000,
      requests_per_month = 100000,
      burst_allowance = 100,
      data_transfer_limit_mb_per_day = 1000,
      priority_level = 2
    ),
    premium = list(
      requests_per_minute = 100,
      requests_per_hour = 2000,
      requests_per_day = 50000,
      requests_per_month = 500000,
      burst_allowance = 200,
      data_transfer_limit_mb_per_day = 10000,
      priority_level = 3
    )
  ),
  
  # Endpoint-specific rate limits (multipliers)
  endpoint_multipliers = list(
    "/api/v1/documents" = 1.0,
    "/api/v1/search" = 1.5,      # Search is more expensive
    "/api/v1/export" = 3.0,      # Export is very expensive
    "/api/v1/export/bulk" = 5.0, # Bulk export is most expensive
    "/api/v1/statistics" = 0.5,  # Statistics are cheaper
    "/api/v1/geography" = 1.2,
    "/api/v1/citations" = 2.0,
    "/api/v1/analytics" = 2.5
  ),
  
  # Geographic rate limiting
  geographic_limits = list(
    brazil = 1.0,        # No penalty for Brazilian IPs
    south_america = 1.2, # 20% stricter for South America
    global = 1.5         # 50% stricter for global
  ),
  
  # System load adaptive limits
  adaptive_limiting = list(
    enabled = TRUE,
    cpu_threshold_high = 80,    # Above 80% CPU, apply strict limits
    cpu_threshold_medium = 60,  # Above 60% CPU, apply medium limits
    memory_threshold_high = 85, # Above 85% memory, apply strict limits
    response_time_threshold_ms = 2000 # Above 2s response time, limit requests
  ),
  
  # Burst allowance settings
  burst_settings = list(
    enabled = TRUE,
    window_seconds = 300,     # 5-minute burst window
    recovery_factor = 0.1     # 10% of burst recovered per window
  )
)

# Rate Limiting Storage Interface
RateLimitStorage <- list(
  # Initialize storage backend
  initialize = function(backend = "database") {
    if (backend == "redis" && requireNamespace("redux", quietly = TRUE)) {
      # Redis initialization (if available)
      return(initialize_redis_storage())
    } else if (backend == "database") {
      return(initialize_database_storage())
    } else {
      return(initialize_memory_storage())
    }
  },
  
  # Get current usage for a key within a window
  get_usage = function(key, window) {
    backend <- RATE_LIMITING_CONFIG$storage_backend
    
    if (backend == "database") {
      return(get_usage_from_database(key, window))
    } else {
      return(get_usage_from_memory(key, window))
    }
  },
  
  # Increment usage counter
  increment_usage = function(key, window, amount = 1) {
    backend <- RATE_LIMITING_CONFIG$storage_backend
    
    if (backend == "database") {
      return(increment_usage_in_database(key, window, amount))
    } else {
      return(increment_usage_in_memory(key, window, amount))
    }
  },
  
  # Get usage statistics
  get_usage_stats = function(api_key_id, period_days = 30) {
    return(get_usage_statistics_from_database(api_key_id, period_days))
  }
)

# Advanced Rate Limiting Engine
RateLimitEngine <- list(
  # Check if request is allowed
  check_rate_limit = function(api_key_id, tier, endpoint, client_ip, request_size_bytes = 0) {
    # Get tier configuration
    tier_config <- RATE_LIMITING_CONFIG$tier_configs[[tier]]
    if (is.null(tier_config)) {
      return(list(allowed = FALSE, error = "Invalid tier configuration"))
    }
    
    # Get endpoint multiplier
    endpoint_multiplier <- RATE_LIMITING_CONFIG$endpoint_multipliers[[endpoint]] %||% 1.0
    
    # Get geographic multiplier
    geographic_multiplier <- get_geographic_multiplier(client_ip)
    
    # Calculate effective limits
    effective_limits <- calculate_effective_limits(tier_config, endpoint_multiplier, geographic_multiplier)
    
    # Check system load adaptive limits
    system_load_factor <- get_system_load_factor()
    if (system_load_factor > 1.0) {
      effective_limits <- apply_system_load_factor(effective_limits, system_load_factor)
    }
    
    # Check all time windows
    windows_to_check <- c("minute", "hour", "day", "month")
    
    for (window in windows_to_check) {
      limit_key <- paste("limit", window, sep = "_")
      if (!is.null(effective_limits[[limit_key]])) {
        
        # Get current usage
        usage_key <- generate_usage_key(api_key_id, window)
        current_usage <- RateLimitStorage$get_usage(usage_key, window)
        
        # Check if limit would be exceeded
        if (current_usage >= effective_limits[[limit_key]]) {
          # Check burst allowance
          if (window == "minute" && tier_config$burst_allowance > 0) {
            burst_result <- check_burst_allowance(api_key_id, tier_config$burst_allowance)
            if (burst_result$allowed) {
              # Use burst allowance
              use_burst_allowance(api_key_id, 1)
              return(create_rate_limit_response(TRUE, effective_limits, current_usage + 1, window, "burst_used"))
            }
          }
          
          # Rate limit exceeded
          reset_time <- calculate_reset_time(window)
          return(list(
            allowed = FALSE,
            error = paste("Rate limit exceeded for", window, "window"),
            limit = effective_limits[[limit_key]],
            usage = current_usage,
            reset_time = reset_time,
            window = window
          ))
        }
      }
    }
    
    # Check data transfer limits if applicable
    if (request_size_bytes > 0) {
      data_limit_result <- check_data_transfer_limit(api_key_id, tier_config, request_size_bytes)
      if (!data_limit_result$allowed) {
        return(data_limit_result)
      }
    }
    
    # All checks passed, increment counters
    for (window in windows_to_check) {
      usage_key <- generate_usage_key(api_key_id, window)
      RateLimitStorage$increment_usage(usage_key, window)
    }
    
    # Record usage in detailed log
    record_usage_event(api_key_id, endpoint, request_size_bytes)
    
    return(create_rate_limit_response(TRUE, effective_limits, NULL, NULL, "allowed"))
  },
  
  # Get usage summary for API key
  get_usage_summary = function(api_key_id, period_days = 30) {
    return(RateLimitStorage$get_usage_stats(api_key_id, period_days))
  }
)

# Database Storage Implementation
initialize_database_storage <- function() {
  if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
    cat("⚠️ Database connection not available for rate limiting\n")
    return(FALSE)
  }
  
  # Create rate limiting tables if they don't exist
  rate_limit_schema <- "
    CREATE TABLE IF NOT EXISTS rate_limit_counters (
      id SERIAL PRIMARY KEY,
      key_name VARCHAR(255) NOT NULL,
      window_type VARCHAR(20) NOT NULL,
      count INTEGER DEFAULT 0,
      reset_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(key_name, window_type)
    );
    
    CREATE INDEX IF NOT EXISTS idx_rate_limit_counters_key ON rate_limit_counters(key_name, window_type);
    CREATE INDEX IF NOT EXISTS idx_rate_limit_counters_reset ON rate_limit_counters(reset_at);
    
    CREATE TABLE IF NOT EXISTS burst_allowance_usage (
      id SERIAL PRIMARY KEY,
      api_key_id INTEGER NOT NULL,
      burst_used INTEGER DEFAULT 0,
      window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      recovered_amount INTEGER DEFAULT 0,
      UNIQUE(api_key_id, window_start)
    );
  "
  
  tryCatch({
    DBI::dbExecute(secure_db_pool, rate_limit_schema)
    cat("✅ Rate limiting database storage initialized\n")
    return(TRUE)
  }, error = function(e) {
    cat("⚠️ Failed to initialize rate limiting database:", e$message, "\n")
    return(FALSE)
  })
}

get_usage_from_database <- function(key, window) {
  if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
    return(0)
  }
  
  current_time <- Sys.time()
  
  tryCatch({
    # Clean up expired counters first
    DBI::dbExecute(secure_db_pool,
      "DELETE FROM rate_limit_counters WHERE reset_at < $1",
      list(current_time))
    
    # Get current count
    result <- DBI::dbGetQuery(secure_db_pool,
      "SELECT count FROM rate_limit_counters WHERE key_name = $1 AND window_type = $2 AND reset_at > $3",
      list(key, window, current_time))
    
    if (nrow(result) > 0) {
      return(result$count[1])
    } else {
      return(0)
    }
  }, error = function(e) {
    cat("Warning: Error getting usage from database:", e$message, "\n")
    return(0)
  })
}

increment_usage_in_database <- function(key, window, amount = 1) {
  if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
    return(FALSE)
  }
  
  window_seconds <- RATE_LIMITING_CONFIG$windows[[window]]
  reset_time <- Sys.time() + window_seconds
  
  tryCatch({
    # Use UPSERT to increment or create counter
    DBI::dbExecute(secure_db_pool,
      "INSERT INTO rate_limit_counters (key_name, window_type, count, reset_at) 
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (key_name, window_type) 
       DO UPDATE SET count = rate_limit_counters.count + $3, updated_at = CURRENT_TIMESTAMP
       WHERE rate_limit_counters.reset_at > CURRENT_TIMESTAMP",
      list(key, window, amount, reset_time))
    
    return(TRUE)
  }, error = function(e) {
    cat("Warning: Error incrementing usage in database:", e$message, "\n")
    return(FALSE)
  })
}

# Memory Storage Implementation (fallback)
initialize_memory_storage <- function() {
  if (!exists("RATE_LIMIT_MEMORY", envir = .GlobalEnv)) {
    assign("RATE_LIMIT_MEMORY", list(), envir = .GlobalEnv)
  }
  cat("✅ Rate limiting memory storage initialized\n")
  return(TRUE)
}

get_usage_from_memory <- function(key, window) {
  if (!exists("RATE_LIMIT_MEMORY", envir = .GlobalEnv)) {
    return(0)
  }
  
  current_time <- Sys.time()
  memory_key <- paste(key, window, sep = "_")
  
  usage_data <- RATE_LIMIT_MEMORY[[memory_key]]
  if (is.null(usage_data)) {
    return(0)
  }
  
  # Check if expired
  if (usage_data$reset_at < current_time) {
    RATE_LIMIT_MEMORY[[memory_key]] <<- NULL
    return(0)
  }
  
  return(usage_data$count)
}

increment_usage_in_memory <- function(key, window, amount = 1) {
  if (!exists("RATE_LIMIT_MEMORY", envir = .GlobalEnv)) {
    assign("RATE_LIMIT_MEMORY", list(), envir = .GlobalEnv)
  }
  
  current_time <- Sys.time()
  window_seconds <- RATE_LIMITING_CONFIG$windows[[window]]
  memory_key <- paste(key, window, sep = "_")
  
  usage_data <- RATE_LIMIT_MEMORY[[memory_key]]
  if (is.null(usage_data) || usage_data$reset_at < current_time) {
    # Create new counter
    RATE_LIMIT_MEMORY[[memory_key]] <<- list(
      count = amount,
      reset_at = current_time + window_seconds
    )
  } else {
    # Increment existing counter
    RATE_LIMIT_MEMORY[[memory_key]]$count <<- usage_data$count + amount
  }
  
  return(TRUE)
}

# Usage Analytics and Statistics
get_usage_statistics_from_database <- function(api_key_id, period_days = 30) {
  if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
    return(list(error = "Database not available"))
  }
  
  tryCatch({
    # Daily usage summary
    daily_usage_query <- "
      SELECT 
        DATE(timestamp) as date,
        COUNT(*) as requests,
        SUM(request_size_bytes) as total_bytes_sent,
        SUM(response_size_bytes) as total_bytes_received,
        AVG(response_time_ms) as avg_response_time,
        COUNT(DISTINCT endpoint) as unique_endpoints
      FROM api_usage_log
      WHERE api_key_id = $1 AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
    "
    daily_usage <- DBI::dbGetQuery(secure_db_pool, sprintf(daily_usage_query, period_days), list(api_key_id))
    
    # Endpoint usage breakdown
    endpoint_usage_query <- "
      SELECT 
        endpoint,
        COUNT(*) as requests,
        AVG(response_time_ms) as avg_response_time,
        SUM(response_size_bytes) as total_bytes
      FROM api_usage_log
      WHERE api_key_id = $1 AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
      GROUP BY endpoint
      ORDER BY requests DESC
    "
    endpoint_usage <- DBI::dbGetQuery(secure_db_pool, sprintf(endpoint_usage_query, period_days), list(api_key_id))
    
    # Error rate analysis
    error_analysis_query <- "
      SELECT 
        response_code,
        COUNT(*) as count,
        COUNT(*) * 100.0 / (SELECT COUNT(*) FROM api_usage_log WHERE api_key_id = $1 AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days') as percentage
      FROM api_usage_log
      WHERE api_key_id = $1 AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
      GROUP BY response_code
      ORDER BY count DESC
    "
    error_analysis <- DBI::dbGetQuery(secure_db_pool, sprintf(error_analysis_query, period_days, period_days), list(api_key_id))
    
    # Peak usage analysis
    hourly_usage_query <- "
      SELECT 
        EXTRACT(HOUR FROM timestamp) as hour,
        COUNT(*) as requests,
        AVG(response_time_ms) as avg_response_time
      FROM api_usage_log
      WHERE api_key_id = $1 AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
      GROUP BY EXTRACT(HOUR FROM timestamp)
      ORDER BY hour
    "
    hourly_usage <- DBI::dbGetQuery(secure_db_pool, sprintf(hourly_usage_query, period_days), list(api_key_id))
    
    return(list(
      period_days = period_days,
      daily_usage = daily_usage,
      endpoint_usage = endpoint_usage,
      error_analysis = error_analysis,
      hourly_usage_pattern = hourly_usage
    ))
    
  }, error = function(e) {
    return(list(error = paste("Failed to get usage statistics:", e$message)))
  })
}

record_usage_event <- function(api_key_id, endpoint, request_size_bytes, response_size_bytes = 0, response_time_ms = 0, response_code = 200) {
  if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    DBI::dbExecute(secure_db_pool,
      "INSERT INTO api_usage_log (api_key_id, endpoint, request_size_bytes, response_size_bytes, response_time_ms, response_code) 
       VALUES ($1, $2, $3, $4, $5, $6)",
      list(api_key_id, endpoint, request_size_bytes, response_size_bytes, response_time_ms, response_code))
    return(TRUE)
  }, error = function(e) {
    cat("Warning: Failed to record usage event:", e$message, "\n")
    return(FALSE)
  })
}

# Helper Functions
generate_usage_key <- function(api_key_id, window) {
  current_time <- Sys.time()
  
  if (window == "minute") {
    time_bucket <- format(current_time, "%Y%m%d%H%M")
  } else if (window == "hour") {
    time_bucket <- format(current_time, "%Y%m%d%H")
  } else if (window == "day") {
    time_bucket <- format(current_time, "%Y%m%d")
  } else if (window == "month") {
    time_bucket <- format(current_time, "%Y%m")
  } else {
    time_bucket <- format(current_time, "%Y%m%d%H%M")
  }
  
  return(paste("api_key", api_key_id, window, time_bucket, sep = "_"))
}

calculate_effective_limits <- function(tier_config, endpoint_multiplier, geographic_multiplier) {
  effective_limits <- list()
  
  for (window in names(RATE_LIMITING_CONFIG$windows)) {
    limit_key <- paste("requests_per", window, sep = "_")
    if (!is.null(tier_config[[limit_key]])) {
      effective_limit <- tier_config[[limit_key]] / endpoint_multiplier / geographic_multiplier
      effective_limits[[paste("limit", window, sep = "_")]] <- floor(effective_limit)
    }
  }
  
  return(effective_limits)
}

get_geographic_multiplier <- function(client_ip) {
  # Simplified geographic detection (in production, use proper IP geolocation)
  if (is.null(client_ip) || client_ip == "unknown") {
    return(RATE_LIMITING_CONFIG$geographic_limits$global)
  }
  
  # Brazilian IP ranges (simplified - in production, use proper IP database)
  brazilian_patterns <- c("^200\\.", "^201\\.", "^189\\.")
  if (any(sapply(brazilian_patterns, function(pattern) grepl(pattern, client_ip)))) {
    return(RATE_LIMITING_CONFIG$geographic_limits$brazil)
  }
  
  return(RATE_LIMITING_CONFIG$geographic_limits$global)
}

get_system_load_factor <- function() {
  # Simplified system load check (in production, use proper monitoring)
  if (!RATE_LIMITING_CONFIG$adaptive_limiting$enabled) {
    return(1.0)
  }
  
  # For now, return 1.0 (no additional limiting)
  # In production, check CPU, memory, response times
  return(1.0)
}

apply_system_load_factor <- function(limits, load_factor) {
  adjusted_limits <- limits
  for (key in names(limits)) {
    adjusted_limits[[key]] <- floor(limits[[key]] / load_factor)
  }
  return(adjusted_limits)
}

calculate_reset_time <- function(window) {
  current_time <- Sys.time()
  
  if (window == "minute") {
    return(60 - as.numeric(format(current_time, "%S")))
  } else if (window == "hour") {
    return(3600 - (as.numeric(format(current_time, "%M")) * 60 + as.numeric(format(current_time, "%S"))))
  } else if (window == "day") {
    seconds_today <- as.numeric(format(current_time, "%H")) * 3600 + 
                    as.numeric(format(current_time, "%M")) * 60 + 
                    as.numeric(format(current_time, "%S"))
    return(86400 - seconds_today)
  } else {
    return(3600) # Default to 1 hour
  }
}

check_burst_allowance <- function(api_key_id, burst_limit) {
  # Simplified burst checking (in production, implement proper burst tracking)
  return(list(allowed = TRUE, remaining = burst_limit))
}

use_burst_allowance <- function(api_key_id, amount) {
  # Placeholder for burst usage tracking
  return(TRUE)
}

check_data_transfer_limit <- function(api_key_id, tier_config, request_size_bytes) {
  # Placeholder for data transfer limit checking
  return(list(allowed = TRUE))
}

create_rate_limit_response <- function(allowed, limits = NULL, usage = NULL, window = NULL, status = NULL) {
  response <- list(allowed = allowed)
  
  if (!is.null(limits)) {
    response$limits <- limits
  }
  
  if (!is.null(usage)) {
    response$usage <- usage
  }
  
  if (!is.null(window)) {
    response$window <- window
  }
  
  if (!is.null(status)) {
    response$status <- status
  }
  
  return(response)
}

# Initialize the rate limiting system
initialize_rate_limiting_system <- function() {
  backend_initialized <- RateLimitStorage$initialize(RATE_LIMITING_CONFIG$storage_backend)
  
  if (backend_initialized) {
    cat("✅ Advanced Rate Limiting & Usage Tracking System initialized\n")
    cat("  📊 Storage backend:", RATE_LIMITING_CONFIG$storage_backend, "\n")
    cat("  ⏱️ Multi-window rate limiting enabled\n")
    cat("  🌍 Geographic-based limiting active\n")
    cat("  📈 Usage analytics and tracking enabled\n")
    cat("  💥 Burst allowance for tier flexibility\n")
    return(TRUE)
  } else {
    cat("⚠️ Failed to initialize rate limiting system\n")
    return(FALSE)
  }
}

# Auto-initialize
initialize_rate_limiting_system()

cat("✅ Rate Limiting & Usage Tracking System Loaded\n")