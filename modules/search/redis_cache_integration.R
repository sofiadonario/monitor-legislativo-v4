# ============================================================================
# REDIS CACHE INTEGRATION FOR AUTOCOMPLETE SYSTEM
# ============================================================================
#
# This module provides Redis caching integration for the intelligent
# autocomplete system to achieve sub-100ms response times.
#
# Features:
# - Redis connection management with Railway deployment support
# - Intelligent cache key generation for consistent lookups
# - TTL-based cache expiration for fresh suggestions
# - Fallback to in-memory caching when Redis unavailable
# - Performance monitoring and cache hit statistics
# - Memory-efficient serialization for legal terms
#
# Author: Senior Data Engineer - Brazilian Legal Analytics Team
# Date: January 2025
# Version: 1.0 - Production Ready
# ============================================================================

cat("💾 Loading Redis Cache Integration for Autocomplete...\n")

# Load required packages with error handling
redis_packages <- c("jsonlite", "digest")

for (pkg in redis_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("⚠️ Package", pkg, "not available for Redis cache\n")
  }
}

suppressPackageStartupMessages({
  if (requireNamespace("jsonlite", quietly = TRUE)) library(jsonlite)
  if (requireNamespace("digest", quietly = TRUE)) library(digest)
})

# Try to load Redis client packages
redis_available <- FALSE
tryCatch({
  if (requireNamespace("redux", quietly = TRUE)) {
    library(redux)
    redis_available <- TRUE
    cat("✅ Redux Redis client available\n")
  } else if (requireNamespace("RcppRedis", quietly = TRUE)) {
    library(RcppRedis)
    redis_available <- TRUE
    cat("✅ RcppRedis client available\n")
  } else {
    cat("ℹ️ No Redis client packages found, using in-memory fallback\n")
  }
}, error = function(e) {
  cat("⚠️ Redis client loading failed:", e$message, "\n")
  redis_available <- FALSE
})

# ============================================================================
# REDIS CONFIGURATION AND CONNECTION
# ============================================================================

.redis_config <- list(
  # Connection settings
  host = Sys.getenv("REDIS_HOST", "localhost"),
  port = as.numeric(Sys.getenv("REDIS_PORT", "6379")),
  password = Sys.getenv("REDIS_PASSWORD", ""),
  database = as.numeric(Sys.getenv("REDIS_DB", "0")),
  
  # Cache settings
  default_ttl = as.numeric(Sys.getenv("AUTOCOMPLETE_CACHE_TTL", "300")), # 5 minutes
  key_prefix = "autocomplete:",
  max_key_length = 250,
  
  # Performance settings
  connection_timeout = 5, # seconds
  retry_attempts = 3,
  
  # Railway deployment settings
  railway_redis_url = Sys.getenv("REDIS_URL", ""),
  enable_ssl = Sys.getenv("REDIS_SSL", "false") == "true"
)

# Global Redis connection
.redis_connection <- NULL
.redis_connection_status <- list(
  connected = FALSE,
  last_attempt = NULL,
  error = NULL,
  connection_method = "none"
)

# In-memory cache fallback
.memory_cache <- list()
.cache_stats <- list(
  hits = 0,
  misses = 0,
  redis_hits = 0,
  memory_hits = 0,
  total_requests = 0
)

# ============================================================================
# REDIS CONNECTION MANAGEMENT
# ============================================================================

#' Initialize Redis connection with Railway support
#' @return Boolean indicating success
init_redis_connection <- function() {
  
  if (!redis_available) {
    cat("ℹ️ Redis not available, using in-memory cache only\n")
    .redis_connection_status$connected <<- FALSE
    .redis_connection_status$connection_method <<- "memory_only"
    return(FALSE)
  }
  
  cat("🔌 Initializing Redis connection...\n")
  
  tryCatch({
    # Try Railway Redis URL first
    if (.redis_config$railway_redis_url != "") {
      cat("🚀 Using Railway Redis URL\n")
      
      # Parse Redis URL for Railway
      redis_url <- .redis_config$railway_redis_url
      
      if (requireNamespace("redux", quietly = TRUE)) {
        .redis_connection <<- redux::hiredis(url = redis_url)
      } else if (requireNamespace("RcppRedis", quietly = TRUE)) {
        # RcppRedis doesn't support URLs directly, need to parse
        url_parts <- parse_redis_url(redis_url)
        .redis_connection <<- new(RcppRedis::Redis, 
                                 host = url_parts$host,
                                 port = url_parts$port)
        if (url_parts$password != "") {
          .redis_connection$auth(url_parts$password)
        }
      }
      
      .redis_connection_status$connection_method <<- "railway_url"
      
    } else {
      # Use individual connection parameters
      cat("🔧 Using individual Redis connection parameters\n")
      
      if (requireNamespace("redux", quietly = TRUE)) {
        .redis_connection <<- redux::hiredis(
          host = .redis_config$host,
          port = .redis_config$port,
          password = if(.redis_config$password != "") .redis_config$password else NULL,
          db = .redis_config$database
        )
      } else if (requireNamespace("RcppRedis", quietly = TRUE)) {
        .redis_connection <<- new(RcppRedis::Redis, 
                                 host = .redis_config$host,
                                 port = .redis_config$port)
        if (.redis_config$password != "") {
          .redis_connection$auth(.redis_config$password)
        }
        if (.redis_config$database != 0) {
          .redis_connection$select(.redis_config$database)
        }
      }
      
      .redis_connection_status$connection_method <<- "parameters"
    }
    
    # Test connection
    test_result <- test_redis_connection()
    
    if (test_result) {
      .redis_connection_status$connected <<- TRUE
      .redis_connection_status$last_attempt <<- Sys.time()
      .redis_connection_status$error <<- NULL
      cat("✅ Redis connection established successfully\n")
      return(TRUE)
    } else {
      cat("❌ Redis connection test failed\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    .redis_connection_status$connected <<- FALSE
    .redis_connection_status$error <<- e$message
    .redis_connection_status$last_attempt <<- Sys.time()
    
    cat("❌ Redis connection failed:", e$message, "\n")
    cat("🔄 Falling back to in-memory cache\n")
    
    return(FALSE)
  })
}

#' Test Redis connection
#' @return Boolean indicating connection success
test_redis_connection <- function() {
  if (is.null(.redis_connection)) return(FALSE)
  
  tryCatch({
    if (requireNamespace("redux", quietly = TRUE) && inherits(.redis_connection, "redis_api")) {
      # Test with redux
      result <- .redis_connection$PING()
      return(result == "PONG")
    } else if (requireNamespace("RcppRedis", quietly = TRUE)) {
      # Test with RcppRedis
      result <- .redis_connection$ping()
      return(result == "PONG")
    }
    return(FALSE)
  }, error = function(e) {
    return(FALSE)
  })
}

#' Parse Redis URL for connection parameters
#' @param redis_url Redis URL string
#' @return List with connection parameters
parse_redis_url <- function(redis_url) {
  # Basic URL parsing for redis://user:pass@host:port/db
  if (!grepl("^redis://", redis_url)) {
    stop("Invalid Redis URL format")
  }
  
  url_without_protocol <- sub("^redis://", "", redis_url)
  
  # Split auth and connection parts
  if (grepl("@", url_without_protocol)) {
    parts <- strsplit(url_without_protocol, "@")[[1]]
    auth_part <- parts[1]
    connection_part <- parts[2]
    
    # Parse auth (user:password)
    if (grepl(":", auth_part)) {
      auth_parts <- strsplit(auth_part, ":")[[1]]
      password <- auth_parts[2]
    } else {
      password <- auth_part
    }
  } else {
    connection_part <- url_without_protocol
    password <- ""
  }
  
  # Parse host:port/db
  if (grepl("/", connection_part)) {
    parts <- strsplit(connection_part, "/")[[1]]
    host_port <- parts[1]
    db <- as.numeric(parts[2])
  } else {
    host_port <- connection_part
    db <- 0
  }
  
  # Parse host:port
  if (grepl(":", host_port)) {
    parts <- strsplit(host_port, ":")[[1]]
    host <- parts[1]
    port <- as.numeric(parts[2])
  } else {
    host <- host_port
    port <- 6379
  }
  
  return(list(
    host = host,
    port = port,
    password = password,
    database = db
  ))
}

# ============================================================================
# CACHE OPERATIONS
# ============================================================================

#' Generate optimized cache key for autocomplete queries
#' @param query User query
#' @param context Search context
#' @return Cache key string
generate_autocomplete_cache_key <- function(query, context = list()) {
  # Normalize query
  normalized_query <- str_to_lower(str_trim(query))
  normalized_query <- str_replace_all(normalized_query, "[^a-z0-9\\s]", "")
  normalized_query <- str_replace_all(normalized_query, "\\s+", "_")
  
  # Create context hash for consistent caching
  context_hash <- ""
  if (length(context) > 0) {
    # Sort context for consistent keys
    context_sorted <- context[order(names(context))]
    context_string <- paste(names(context_sorted), context_sorted, collapse = "|")
    
    if (requireNamespace("digest", quietly = TRUE)) {
      context_hash <- substr(digest::digest(context_string, "md5"), 1, 8)
    } else {
      # Simple hash fallback
      context_hash <- substr(as.character(abs(sum(utf8ToInt(context_string)))), 1, 6)
    }
  }
  
  # Build final key
  cache_key <- paste0(.redis_config$key_prefix, normalized_query)
  if (context_hash != "") {
    cache_key <- paste0(cache_key, ":", context_hash)
  }
  
  # Ensure key length limit
  if (nchar(cache_key) > .redis_config$max_key_length) {
    if (requireNamespace("digest", quietly = TRUE)) {
      cache_key <- paste0(.redis_config$key_prefix, 
                         digest::digest(paste(normalized_query, context_hash), "md5"))
    } else {
      cache_key <- substr(cache_key, 1, .redis_config$max_key_length)
    }
  }
  
  return(cache_key)
}

#' Get autocomplete suggestions from cache
#' @param cache_key Cache key
#' @return Cached suggestions or NULL
get_cached_autocomplete <- function(cache_key) {
  .cache_stats$total_requests <<- .cache_stats$total_requests + 1
  
  # Try Redis first
  if (.redis_connection_status$connected && !is.null(.redis_connection)) {
    tryCatch({
      if (requireNamespace("redux", quietly = TRUE) && inherits(.redis_connection, "redis_api")) {
        cached_json <- .redis_connection$GET(cache_key)
      } else if (requireNamespace("RcppRedis", quietly = TRUE)) {
        cached_json <- .redis_connection$get(cache_key)
      } else {
        cached_json <- NULL
      }
      
      if (!is.null(cached_json) && cached_json != "") {
        cached_data <- jsonlite::fromJSON(cached_json, simplifyVector = FALSE)
        .cache_stats$hits <<- .cache_stats$hits + 1
        .cache_stats$redis_hits <<- .cache_stats$redis_hits + 1
        return(cached_data)
      }
    }, error = function(e) {
      cat("⚠️ Redis cache read error:", e$message, "\n")
    })
  }
  
  # Try in-memory cache
  if (cache_key %in% names(.memory_cache)) {
    cache_entry <- .memory_cache[[cache_key]]
    
    # Check TTL
    if (difftime(Sys.time(), cache_entry$timestamp, units = "secs") < .redis_config$default_ttl) {
      .cache_stats$hits <<- .cache_stats$hits + 1
      .cache_stats$memory_hits <<- .cache_stats$memory_hits + 1
      return(cache_entry$data)
    } else {
      # Remove expired entry
      .memory_cache[[cache_key]] <<- NULL
    }
  }
  
  # Cache miss
  .cache_stats$misses <<- .cache_stats$misses + 1
  return(NULL)
}

#' Store autocomplete suggestions in cache
#' @param cache_key Cache key
#' @param suggestions Suggestions to cache
#' @param ttl Time to live in seconds
store_autocomplete_cache <- function(cache_key, suggestions, ttl = NULL) {
  if (is.null(ttl)) ttl <- .redis_config$default_ttl
  
  tryCatch({
    # Serialize data
    json_data <- jsonlite::toJSON(suggestions, auto_unbox = TRUE)
    
    # Store in Redis
    if (.redis_connection_status$connected && !is.null(.redis_connection)) {
      tryCatch({
        if (requireNamespace("redux", quietly = TRUE) && inherits(.redis_connection, "redis_api")) {
          .redis_connection$SETEX(cache_key, ttl, json_data)
        } else if (requireNamespace("RcppRedis", quietly = TRUE)) {
          .redis_connection$setex(cache_key, ttl, json_data)
        }
      }, error = function(e) {
        cat("⚠️ Redis cache write error:", e$message, "\n")
      })
    }
    
    # Store in memory cache as backup
    .memory_cache[[cache_key]] <<- list(
      data = suggestions,
      timestamp = Sys.time()
    )
    
    # Limit memory cache size
    if (length(.memory_cache) > 100) {
      # Remove oldest 20 entries
      timestamps <- sapply(.memory_cache, function(x) x$timestamp)
      old_keys <- names(sort(timestamps))[1:20]
      .memory_cache[old_keys] <<- NULL
    }
    
  }, error = function(e) {
    cat("⚠️ Cache storage error:", e$message, "\n")
  })
}

#' Clear autocomplete cache
#' @param pattern Optional pattern to match keys for deletion
clear_autocomplete_cache <- function(pattern = NULL) {
  tryCatch({
    # Clear Redis cache
    if (.redis_connection_status$connected && !is.null(.redis_connection)) {
      if (is.null(pattern)) {
        pattern <- paste0(.redis_config$key_prefix, "*")
      }
      
      if (requireNamespace("redux", quietly = TRUE) && inherits(.redis_connection, "redis_api")) {
        keys <- .redis_connection$KEYS(pattern)
        if (length(keys) > 0) {
          .redis_connection$DEL(keys)
        }
      } else if (requireNamespace("RcppRedis", quietly = TRUE)) {
        keys <- .redis_connection$keys(pattern)
        if (length(keys) > 0) {
          for (key in keys) {
            .redis_connection$del(key)
          }
        }
      }
    }
    
    # Clear memory cache
    if (is.null(pattern)) {
      .memory_cache <<- list()
    } else {
      # Remove matching keys from memory cache
      matching_keys <- grep(pattern, names(.memory_cache), value = TRUE)
      .memory_cache[matching_keys] <<- NULL
    }
    
    cat("✅ Autocomplete cache cleared\n")
    
  }, error = function(e) {
    cat("⚠️ Cache clear error:", e$message, "\n")
  })
}

# ============================================================================
# CACHE STATISTICS AND MONITORING
# ============================================================================

#' Get cache performance statistics
#' @return List with cache statistics
get_cache_stats <- function() {
  hit_rate <- if (.cache_stats$total_requests > 0) {
    (.cache_stats$hits / .cache_stats$total_requests) * 100
  } else {
    0
  }
  
  return(list(
    connection_status = .redis_connection_status,
    performance = list(
      total_requests = .cache_stats$total_requests,
      cache_hits = .cache_stats$hits,
      cache_misses = .cache_stats$misses,
      hit_rate_percent = round(hit_rate, 2),
      redis_hits = .cache_stats$redis_hits,
      memory_hits = .cache_stats$memory_hits
    ),
    cache_sizes = list(
      memory_cache_entries = length(.memory_cache),
      redis_available = .redis_connection_status$connected
    ),
    configuration = list(
      default_ttl = .redis_config$default_ttl,
      key_prefix = .redis_config$key_prefix,
      redis_host = .redis_config$host,
      redis_port = .redis_config$port,
      connection_method = .redis_connection_status$connection_method
    )
  ))
}

#' Log cache performance metrics
log_cache_performance <- function() {
  stats <- get_cache_stats()
  
  cat("📊 AUTOCOMPLETE CACHE PERFORMANCE:\n")
  cat(sprintf("   Total requests: %d\n", stats$performance$total_requests))
  cat(sprintf("   Cache hit rate: %.1f%%\n", stats$performance$hit_rate_percent))
  cat(sprintf("   Redis hits: %d\n", stats$performance$redis_hits))
  cat(sprintf("   Memory hits: %d\n", stats$performance$memory_hits))
  cat(sprintf("   Memory cache size: %d entries\n", stats$cache_sizes$memory_cache_entries))
  cat(sprintf("   Redis status: %s\n", 
              if(stats$cache_sizes$redis_available) "Connected" else "Disconnected"))
}

# ============================================================================
# PUBLIC API FUNCTIONS
# ============================================================================

#' Main function to get cached autocomplete suggestions
#' @param query User query
#' @param context Search context
#' @param suggestions_function Function to generate suggestions if cache miss
#' @return Autocomplete suggestions (cached or fresh)
get_or_set_autocomplete_cache <- function(query, context = list(), suggestions_function = NULL) {
  cache_key <- generate_autocomplete_cache_key(query, context)
  
  # Try to get from cache
  cached_result <- get_cached_autocomplete(cache_key)
  
  if (!is.null(cached_result)) {
    # Cache hit
    cached_result$metadata$cache_hit <- TRUE
    return(cached_result)
  }
  
  # Cache miss - generate fresh suggestions
  if (is.null(suggestions_function)) {
    return(NULL)
  }
  
  fresh_result <- suggestions_function(query, context)
  fresh_result$metadata$cache_hit <- FALSE
  
  # Store in cache
  store_autocomplete_cache(cache_key, fresh_result)
  
  return(fresh_result)
}

# ============================================================================
# INITIALIZATION
# ============================================================================

# Initialize Redis connection on load
if (redis_available) {
  init_success <- init_redis_connection()
  
  if (init_success) {
    cat("✅ Redis Cache Integration initialized successfully\n")
    cat("   🚀 Sub-100ms autocomplete performance enabled\n")
    cat("   📊 Performance monitoring active\n")
  } else {
    cat("⚠️ Redis connection failed, using in-memory cache only\n")
    cat("   🔄 Fallback cache active\n")
  }
} else {
  cat("ℹ️ Redis Cache Integration using in-memory fallback only\n")
  cat("   📝 Install 'redux' or 'RcppRedis' package for Redis support\n")
}

# Export main functions
.GlobalEnv$get_cached_autocomplete <- get_cached_autocomplete
.GlobalEnv$store_autocomplete_cache <- store_autocomplete_cache
.GlobalEnv$get_or_set_autocomplete_cache <- get_or_set_autocomplete_cache
.GlobalEnv$get_cache_stats <- get_cache_stats
.GlobalEnv$clear_autocomplete_cache <- clear_autocomplete_cache
.GlobalEnv$log_cache_performance <- log_cache_performance

cat("🚀 REDIS CACHE INTEGRATION FOR AUTOCOMPLETE READY!\n")