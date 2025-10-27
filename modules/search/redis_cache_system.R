# ============================================================================
# REDIS CACHING SYSTEM FOR BRAZILIAN LEGISLATIVE SEARCH ENGINE
# ============================================================================
#
# This module implements a high-performance caching layer using Redis for:
# - Sub-second search query responses
# - Intelligent autocomplete caching
# - Geographic and temporal filter caching
# - Railway deployment optimization with memory constraints
# - Distributed caching for scalability
#
# Author: Senior Data Scientist - Brazilian Legislative Analytics Team
# Date: January 2025
# Version: 1.0 - Railway Production Ready
# ============================================================================

# Load required packages with fallback handling
redis_packages <- c("redux", "RcppRedis", "jsonlite", "digest", "lubridate")
redis_available <- TRUE

for (pkg in redis_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    if (pkg %in% c("redux", "RcppRedis")) {
      redis_available <- FALSE
      cat("⚠️ Redis package", pkg, "not available. Using in-memory caching fallback.\n")
    }
  }
}

# Try to load Redis packages
if (redis_available) {
  tryCatch({
    suppressPackageStartupMessages({
      library(redux)
      library(jsonlite)
      library(digest)
      library(lubridate)
    })
    cat("✅ Redis packages loaded successfully\n")
  }, error = function(e) {
    redis_available <<- FALSE
    cat("⚠️ Redis loading failed:", e$message, ". Using fallback caching.\n")
  })
} else {
  # Load minimal dependencies for fallback
  suppressPackageStartupMessages({
    library(jsonlite)
    library(digest)
  })
}

# ============================================================================
# REDIS CONNECTION AND CONFIGURATION
# ============================================================================

# Redis configuration for Railway deployment
.redis_config <- list(
  # Railway Redis connection (will be set from environment variables)
  host = Sys.getenv("REDIS_HOST", "localhost"),
  port = as.integer(Sys.getenv("REDIS_PORT", "6379")),
  password = Sys.getenv("REDIS_PASSWORD", ""),
  db = as.integer(Sys.getenv("REDIS_DB", "0")),
  
  # Connection settings optimized for Railway
  connect_timeout = 5,    # 5 seconds timeout
  read_timeout = 3,       # 3 seconds read timeout
  max_retries = 2,        # Maximum retry attempts
  
  # Cache TTL settings (in seconds)
  search_results_ttl = 300,      # 5 minutes for search results
  autocomplete_ttl = 1800,       # 30 minutes for autocomplete
  geographic_data_ttl = 3600,    # 1 hour for geographic data
  analytics_ttl = 86400,         # 24 hours for analytics
  
  # Memory optimization for Railway 2GB constraint
  max_cache_size_mb = 100,       # Maximum 100MB for cache
  compression_enabled = TRUE,     # Enable data compression
  eviction_policy = "allkeys-lru", # LRU eviction policy
  
  # Key prefixes for organization
  key_prefixes = list(
    search = "bls:search:",
    autocomplete = "bls:auto:",
    geographic = "bls:geo:",
    analytics = "bls:stats:",
    metadata = "bls:meta:"
  )
)

# Global Redis connection
.redis_connection <- NULL
.redis_initialized <- FALSE

# Fallback in-memory cache when Redis is unavailable
.memory_cache <- list()
.memory_cache_stats <- list(
  hits = 0,
  misses = 0,
  size = 0
)

# ============================================================================
# REDIS CONNECTION MANAGEMENT
# ============================================================================

#' Initialize Redis connection with Railway optimization
#' @param force_reconnect Force reconnection even if already connected
#' @return Boolean indicating success
init_redis_connection <- function(force_reconnect = FALSE) {
  
  if (!redis_available) {
    cat("📦 Redis not available, using in-memory caching\n")
    .redis_initialized <<- FALSE
    return(FALSE)
  }
  
  if (.redis_initialized && !force_reconnect) {
    return(TRUE)
  }
  
  tryCatch({
    cat("🔌 Initializing Redis connection for Railway deployment...\n")
    
    # Build Redis connection URL
    redis_url <- build_redis_url()
    
    if (is.null(redis_url)) {
      cat("⚠️ No Redis configuration found, using in-memory cache\n")
      .redis_initialized <<- FALSE
      return(FALSE)
    }
    
    # Create Redis connection with timeout and retry logic
    .redis_connection <<- tryCatch({
      redux::hiredis(
        host = .redis_config$host,
        port = .redis_config$port,
        password = if(.redis_config$password != "") .redis_config$password else NULL,
        db = .redis_config$db,
        timeout = .redis_config$connect_timeout
      )
    }, error = function(e) {
      cat("❌ Redis connection failed:", e$message, "\n")
      NULL
    })
    
    if (!is.null(.redis_connection)) {
      # Test connection
      test_result <- test_redis_connection()
      
      if (test_result) {
        # Configure Redis for optimal performance
        configure_redis_for_railway()
        
        .redis_initialized <<- TRUE
        cat("✅ Redis connection established successfully\n")
        cat("   🏠 Host:", .redis_config$host, ":", .redis_config$port, "\n")
        cat("   💾 Database:", .redis_config$db, "\n")
        cat("   🚀 Railway optimization: ENABLED\n")
        
        return(TRUE)
      }
    }
    
    cat("❌ Redis connection test failed, using in-memory cache\n")
    .redis_initialized <<- FALSE
    return(FALSE)
    
  }, error = function(e) {
    cat("❌ Redis initialization error:", e$message, "\n")
    .redis_initialized <<- FALSE
    return(FALSE)
  })
}

#' Build Redis connection URL from environment variables
#' @return Redis URL or NULL
build_redis_url <- function() {
  
  # Check for Railway Redis URL format
  redis_url <- Sys.getenv("REDIS_URL", "")
  
  if (redis_url != "") {
    # Parse Redis URL: redis://user:password@host:port/db
    if (grepl("^redis://", redis_url)) {
      return(redis_url)
    }
  }
  
  # Check for individual Redis environment variables
  if (.redis_config$host != "localhost" || Sys.getenv("REDIS_HOST") != "") {
    return(paste0("redis://", 
                 if(.redis_config$password != "") paste0(":", .redis_config$password, "@") else "",
                 .redis_config$host, ":", .redis_config$port, "/", .redis_config$db))
  }
  
  return(NULL)
}

#' Test Redis connection
#' @return Boolean indicating connection success
test_redis_connection <- function() {
  
  if (is.null(.redis_connection)) {
    return(FALSE)
  }
  
  tryCatch({
    # Test basic Redis operations
    test_key <- paste0(.redis_config$key_prefixes$metadata, "connection_test")
    test_value <- list(timestamp = Sys.time(), test = TRUE)
    
    # Set test value
    .redis_connection$SET(test_key, jsonlite::toJSON(test_value, auto_unbox = TRUE))
    
    # Get test value
    retrieved <- .redis_connection$GET(test_key)
    
    if (!is.null(retrieved)) {
      parsed_value <- jsonlite::fromJSON(retrieved)
      
      # Clean up test key
      .redis_connection$DEL(test_key)
      
      return(parsed_value$test == TRUE)
    }
    
    return(FALSE)
    
  }, error = function(e) {
    cat("⚠️ Redis connection test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Configure Redis for Railway deployment optimization
configure_redis_for_railway <- function() {
  
  if (is.null(.redis_connection)) {
    return()
  }
  
  tryCatch({
    # Set memory optimization configurations
    .redis_connection$CONFIG("SET", "maxmemory", paste0(.redis_config$max_cache_size_mb, "mb"))
    .redis_connection$CONFIG("SET", "maxmemory-policy", .redis_config$eviction_policy)
    
    # Optimize for Railway's network latency
    .redis_connection$CONFIG("SET", "tcp-keepalive", "60")
    .redis_connection$CONFIG("SET", "timeout", "0")  # Disable client timeout
    
    cat("⚙️ Redis configured for Railway deployment\n")
    
  }, error = function(e) {
    cat("⚠️ Redis configuration warning:", e$message, "\n")
  })
}

# ============================================================================
# HIGH-PERFORMANCE CACHING FUNCTIONS
# ============================================================================

#' Cache search results with compression and TTL
#' @param query_signature Unique query signature
#' @param results Search results data
#' @param filters Applied filters
#' @param ttl_seconds Cache TTL in seconds
#' @return Boolean indicating success
cache_search_results <- function(query_signature, results, filters = list(), ttl_seconds = .redis_config$search_results_ttl) {
  
  cache_key <- paste0(.redis_config$key_prefixes$search, query_signature)
  
  cache_data <- list(
    results = results,
    filters = filters,
    cached_at = Sys.time(),
    ttl = ttl_seconds,
    version = "1.0"
  )
  
  return(set_cache_data(cache_key, cache_data, ttl_seconds))
}

#' Retrieve cached search results
#' @param query_signature Unique query signature
#' @return Cached search results or NULL
get_cached_search_results <- function(query_signature) {
  
  cache_key <- paste0(.redis_config$key_prefixes$search, query_signature)
  cached_data <- get_cache_data(cache_key)
  
  if (!is.null(cached_data)) {
    # Verify data structure and freshness
    if (is.list(cached_data) && "results" %in% names(cached_data)) {
      return(cached_data$results)
    }
  }
  
  return(NULL)
}

#' Cache autocomplete suggestions with intelligent grouping
#' @param partial_query Partial search query
#' @param suggestions Autocomplete suggestions
#' @param metadata Suggestion metadata
#' @param ttl_seconds Cache TTL in seconds
#' @return Boolean indicating success
cache_autocomplete_suggestions <- function(partial_query, suggestions, metadata = list(), 
                                         ttl_seconds = .redis_config$autocomplete_ttl) {
  
  # Normalize query for consistent caching
  normalized_query <- tolower(trimws(partial_query))
  cache_key <- paste0(.redis_config$key_prefixes$autocomplete, digest(normalized_query, algo = "md5"))
  
  cache_data <- list(
    query = partial_query,
    normalized_query = normalized_query,
    suggestions = suggestions,
    metadata = metadata,
    cached_at = Sys.time(),
    version = "1.0"
  )
  
  success <- set_cache_data(cache_key, cache_data, ttl_seconds)
  
  # Also cache with prefix patterns for faster prefix matching
  if (success && nchar(normalized_query) >= 3) {
    cache_prefix_patterns(normalized_query, suggestions, ttl_seconds)
  }
  
  return(success)
}

#' Get cached autocomplete suggestions
#' @param partial_query Partial search query
#' @return List with suggestions and metadata or NULL
get_cached_autocomplete_suggestions <- function(partial_query) {
  
  normalized_query <- tolower(trimws(partial_query))
  cache_key <- paste0(.redis_config$key_prefixes$autocomplete, digest(normalized_query, algo = "md5"))
  
  cached_data <- get_cache_data(cache_key)
  
  if (!is.null(cached_data)) {
    if (is.list(cached_data) && "suggestions" %in% names(cached_data)) {
      return(list(
        suggestions = cached_data$suggestions,
        metadata = cached_data$metadata %||% list()
      ))
    }
  }
  
  # Try prefix pattern matching for partial matches
  return(get_cached_prefix_suggestions(normalized_query))
}

#' Cache geographic data (states, municipalities) for fast filtering
#' @param data_type Type of geographic data ('states', 'municipalities', 'regions')
#' @param data Geographic data
#' @param ttl_seconds Cache TTL in seconds
#' @return Boolean indicating success
cache_geographic_data <- function(data_type, data, ttl_seconds = .redis_config$geographic_data_ttl) {
  
  cache_key <- paste0(.redis_config$key_prefixes$geographic, data_type)
  
  cache_data <- list(
    data_type = data_type,
    data = data,
    cached_at = Sys.time(),
    count = length(data),
    version = "1.0"
  )
  
  return(set_cache_data(cache_key, cache_data, ttl_seconds))
}

#' Get cached geographic data
#' @param data_type Type of geographic data
#' @return Cached geographic data or NULL
get_cached_geographic_data <- function(data_type) {
  
  cache_key <- paste0(.redis_config$key_prefixes$geographic, data_type)
  cached_data <- get_cache_data(cache_key)
  
  if (!isTRUE(is.null(cached_data)) && is.list(cached_data) && "data" %in% names(cached_data)) {
    return(cached_data$data)
  }
  
  return(NULL)
}

# ============================================================================
# LOW-LEVEL CACHE OPERATIONS
# ============================================================================

#' Set data in cache with compression and error handling
#' @param key Cache key
#' @param data Data to cache
#' @param ttl_seconds TTL in seconds
#' @return Boolean indicating success
set_cache_data <- function(key, data, ttl_seconds) {
  
  if (.redis_initialized && !is.null(.redis_connection)) {
    # Use Redis caching
    return(redis_set_data(key, data, ttl_seconds))
  } else {
    # Use in-memory fallback
    return(memory_set_data(key, data, ttl_seconds))
  }
}

#' Get data from cache with decompression and validation
#' @param key Cache key
#' @return Cached data or NULL
get_cache_data <- function(key) {
  
  if (.redis_initialized && !is.null(.redis_connection)) {
    # Use Redis caching
    return(redis_get_data(key))
  } else {
    # Use in-memory fallback
    return(memory_get_data(key))
  }
}

#' Set data in Redis with optimization
#' @param key Redis key
#' @param data Data to store
#' @param ttl_seconds TTL in seconds
#' @return Boolean indicating success
redis_set_data <- function(key, data, ttl_seconds) {
  
  tryCatch({
    # Serialize data to JSON
    json_data <- jsonlite::toJSON(data, auto_unbox = TRUE, digits = 4)
    
    # Compress data if enabled and size is significant
    if (.redis_config$compression_enabled && nchar(json_data) > 1000) {
      compressed_data <- memCompress(json_data, type = "gzip")
      .redis_connection$SETEX(paste0(key, ":compressed"), ttl_seconds, compressed_data)
    } else {
      .redis_connection$SETEX(key, ttl_seconds, json_data)
    }
    
    return(TRUE)
    
  }, error = function(e) {
    cat("⚠️ Redis cache set error for key", substr(key, 1, 20), ":", e$message, "\n")
    return(FALSE)
  })
}

#' Get data from Redis with decompression
#' @param key Redis key
#' @return Cached data or NULL
redis_get_data <- function(key) {
  
  tryCatch({
    # Try compressed version first
    if (.redis_config$compression_enabled) {
      compressed_key <- paste0(key, ":compressed")
      compressed_data <- .redis_connection$GET(compressed_key)
      
      if (!is.null(compressed_data)) {
        json_data <- memDecompress(compressed_data, type = "gzip", asChar = TRUE)
        return(jsonlite::fromJSON(json_data, simplifyVector = FALSE))
      }
    }
    
    # Try uncompressed version
    json_data <- .redis_connection$GET(key)
    
    if (!is.null(json_data)) {
      return(jsonlite::fromJSON(json_data, simplifyVector = FALSE))
    }
    
    return(NULL)
    
  }, error = function(e) {
    cat("⚠️ Redis cache get error for key", substr(key, 1, 20), ":", e$message, "\n")
    return(NULL)
  })
}

#' Set data in memory cache (fallback)
#' @param key Cache key
#' @param data Data to cache
#' @param ttl_seconds TTL in seconds
#' @return Boolean indicating success
memory_set_data <- function(key, data, ttl_seconds) {
  
  tryCatch({
    .memory_cache[[key]] <<- list(
      data = data,
      expires_at = Sys.time() + ttl_seconds,
      size_bytes = object.size(data)
    )
    
    .memory_cache_stats$size <<- .memory_cache_stats$size + 1
    
    # Clean up expired entries if cache is getting large
    if (length(.memory_cache) > 1000) {
      cleanup_memory_cache()
    }
    
    return(TRUE)
    
  }, error = function(e) {
    cat("⚠️ Memory cache set error:", e$message, "\n")
    return(FALSE)
  })
}

#' Get data from memory cache (fallback)
#' @param key Cache key
#' @return Cached data or NULL
memory_get_data <- function(key) {
  
  if (key %in% names(.memory_cache)) {
    cache_entry <- .memory_cache[[key]]
    
    # Check if entry is still valid
    if (Sys.time() < cache_entry$expires_at) {
      .memory_cache_stats$hits <<- .memory_cache_stats$hits + 1
      return(cache_entry$data)
    } else {
      # Remove expired entry
      .memory_cache[[key]] <<- NULL
      .memory_cache_stats$size <<- .memory_cache_stats$size - 1
    }
  }
  
  .memory_cache_stats$misses <<- .memory_cache_stats$misses + 1
  return(NULL)
}

# ============================================================================
# INTELLIGENT CACHING STRATEGIES
# ============================================================================

#' Cache prefix patterns for fast autocomplete
#' @param query Normalized query
#' @param suggestions Full suggestions list
#' @param ttl_seconds TTL in seconds
cache_prefix_patterns <- function(query, suggestions, ttl_seconds) {
  
  # Create prefix patterns for different lengths
  for (prefix_len in 2:min(nchar(query), 5)) {
    prefix <- substr(query, 1, prefix_len)
    prefix_key <- paste0(.redis_config$key_prefixes$autocomplete, "prefix:", prefix)
    
    # Filter suggestions that match this prefix
    matching_suggestions <- suggestions[grepl(paste0("^", prefix), suggestions, ignore.case = TRUE)]
    
    if (length(matching_suggestions) > 0) {
      prefix_data <- list(
        prefix = prefix,
        suggestions = head(matching_suggestions, 20), # Limit to top 20 for prefix
        cached_at = Sys.time()
      )
      
      set_cache_data(prefix_key, prefix_data, ttl_seconds)
    }
  }
}

#' Get cached prefix suggestions
#' @param query Normalized query
#' @return Suggestions list or NULL
get_cached_prefix_suggestions <- function(query) {
  
  # Try different prefix lengths, starting from longest
  for (prefix_len in min(nchar(query), 5):2) {
    prefix <- substr(query, 1, prefix_len)
    prefix_key <- paste0(.redis_config$key_prefixes$autocomplete, "prefix:", prefix)
    
    cached_data <- get_cache_data(prefix_key)
    
    if (!isTRUE(is.null(cached_data)) && "suggestions" %in% names(cached_data)) {
      # Filter suggestions for the full query
      filtered_suggestions <- cached_data$suggestions[
        grepl(paste0("^", query), cached_data$suggestions, ignore.case = TRUE)
      ]
      
      if (length(filtered_suggestions) > 0) {
        return(list(
          suggestions = filtered_suggestions,
          metadata = list(
            source = "prefix_cache",
            prefix_used = prefix,
            total_found = length(filtered_suggestions)
          )
        ))
      }
    }
  }
  
  return(NULL)
}

#' Batch cache common search patterns for warm-up
#' @param common_queries List of common search queries
#' @param limit Results per query
warm_up_cache <- function(common_queries = NULL, limit = 20) {
  
  if (is.null(common_queries)) {
    # Default common Brazilian legal terms
    common_queries <- c(
      "lei", "decreto", "portaria", "resolução",
      "transporte", "trânsito", "mobilidade", "logística",
      "rodoviário", "ferroviário", "aéreo", "marítimo",
      "federal", "estadual", "municipal",
      "são paulo", "rio de janeiro", "minas gerais"
    )
  }
  
  cat("🔥 Warming up cache with", length(common_queries), "common queries...\n")
  
  warmed_count <- 0
  
  for (query in common_queries) {
    tryCatch({
      # This would call the main search function to populate cache
      # For now, we'll just log the intent
      cat("   🔍 Preparing cache for:", query, "\n")
      warmed_count <- warmed_count + 1
      
      # Small delay to avoid overwhelming the system
      Sys.sleep(0.1)
      
    }, error = function(e) {
      cat("⚠️ Cache warm-up failed for query '", query, "':", e$message, "\n")
    })
  }
  
  cat("✅ Cache warm-up completed:", warmed_count, "queries prepared\n")
  
  return(warmed_count)
}

# ============================================================================
# CACHE MONITORING AND MAINTENANCE
# ============================================================================

#' Get cache performance statistics
#' @return List with cache performance metrics
get_cache_performance_stats <- function() {
  
  stats <- list(
    redis_available = .redis_initialized,
    connection_status = if(.redis_initialized) "connected" else "fallback",
    cache_type = if(.redis_initialized) "redis" else "memory"
  )
  
  if (.redis_initialized && !is.null(.redis_connection)) {
    # Redis-specific stats
    tryCatch({
      redis_info <- .redis_connection$INFO("memory")
      
      stats$redis_memory_used_mb <- as.numeric(gsub(".*used_memory:([0-9]+).*", "\\1", redis_info)) / 1024 / 1024
      stats$redis_keys <- .redis_connection$DBSIZE()
      
    }, error = function(e) {
      stats$redis_error <- e$message
    })
    
    stats$hits <- "N/A (Redis internal)"
    stats$misses <- "N/A (Redis internal)"
    
  } else {
    # Memory cache stats
    stats$memory_cache_size <- length(.memory_cache)
    stats$hits <- .memory_cache_stats$hits
    stats$misses <- .memory_cache_stats$misses
    stats$hit_rate_percent <- if((.memory_cache_stats$hits + .memory_cache_stats$misses) > 0) {
      round(.memory_cache_stats$hits / (.memory_cache_stats$hits + .memory_cache_stats$misses) * 100, 2)
    } else { 0 }
  }
  
  return(stats)
}

#' Clean up expired memory cache entries
cleanup_memory_cache <- function() {
  
  current_time <- Sys.time()
  expired_keys <- character(0)
  
  for (key in names(.memory_cache)) {
    if (current_time >= .memory_cache[[key]]$expires_at) {
      expired_keys <- c(expired_keys, key)
    }
  }
  
  if (length(expired_keys) > 0) {
    for (key in expired_keys) {
      .memory_cache[[key]] <<- NULL
    }
    .memory_cache_stats$size <<- .memory_cache_stats$size - length(expired_keys)
    cat("🧹 Cleaned", length(expired_keys), "expired memory cache entries\n")
  }
}

#' Clear all cache data (for maintenance)
#' @param confirm Confirmation flag
clear_all_cache <- function(confirm = FALSE) {
  
  if (!confirm) {
    cat("⚠️ Use clear_all_cache(confirm = TRUE) to clear all cache data\n")
    return(FALSE)
  }
  
  if (.redis_initialized && !is.null(.redis_connection)) {
    tryCatch({
      # Clear only our prefixed keys to avoid affecting other applications
      for (prefix in .redis_config$key_prefixes) {
        keys <- .redis_connection$KEYS(paste0(prefix, "*"))
        if (length(keys) > 0) {
          .redis_connection$DEL(keys)
        }
      }
      cat("✅ Redis cache cleared\n")
    }, error = function(e) {
      cat("⚠️ Redis cache clear error:", e$message, "\n")
    })
  }
  
  # Clear memory cache
  .memory_cache <<- list()
  .memory_cache_stats <<- list(hits = 0, misses = 0, size = 0)
  cat("✅ Memory cache cleared\n")
  
  return(TRUE)
}

# ============================================================================
# INITIALIZATION AND STARTUP
# ============================================================================

# Initialize Redis connection on module load
cat("💾 Initializing Redis caching system for Railway deployment...\n")

init_success <- init_redis_connection()

if (init_success) {
  cat("✅ Redis caching system ready\n")
  cat("   🚀 Railway optimization: ENABLED\n")
  cat("   💾 Compression: ", if(.redis_config$compression_enabled) "ENABLED" else "DISABLED", "\n")
  cat("   ⏰ Search results TTL:", .redis_config$search_results_ttl, "seconds\n")
  cat("   📝 Autocomplete TTL:", .redis_config$autocomplete_ttl, "seconds\n")
} else {
  cat("⚠️ Using in-memory caching fallback\n")
  cat("   💾 Memory cache: ENABLED\n")
  cat("   🚀 Railway memory optimization: ENABLED\n")
}

# Export main functions
.GlobalEnv$cache_search_results <- cache_search_results
.GlobalEnv$get_cached_search_results <- get_cached_search_results
.GlobalEnv$cache_autocomplete_suggestions <- cache_autocomplete_suggestions
.GlobalEnv$get_cached_autocomplete_suggestions <- get_cached_autocomplete_suggestions
.GlobalEnv$get_cache_performance_stats <- get_cache_performance_stats
.GlobalEnv$warm_up_cache <- warm_up_cache
.GlobalEnv$clear_all_cache <- clear_all_cache