# Cache Utilities Module
# Monitor Legislativo v4 - Redis and Memory Caching Utilities
# ===========================================================

#' Cache Utilities for Monitor Legislativo v4
#' 
#' This module provides Redis integration and memory caching utilities
#' optimized for Railway deployment with 2GB memory constraints.
#' Implements intelligent caching strategies for legislative data.

library(digest)

# Cache configuration optimized for Railway
CACHE_CONFIG <- list(
  redis_enabled = FALSE,  # Will be set based on availability
  memory_cache_enabled = TRUE,
  max_memory_cache_mb = 256,  # 256MB limit for Railway
  default_ttl = 3600,  # 1 hour
  search_result_ttl = 1800,  # 30 minutes
  document_ttl = 7200,  # 2 hours
  analytics_ttl = 900,  # 15 minutes
  max_cache_entries = 1000
)

# Global cache storage
.memory_cache <- list()
.cache_stats <- list(
  hits = 0,
  misses = 0,
  evictions = 0,
  memory_usage_mb = 0
)

#' Initialize Cache System
#' 
#' @param redis_host Redis server host (optional)
#' @param redis_port Redis server port (optional)
#' @return Cache initialization status
#' @export
init_cache_system <- function(redis_host = NULL, redis_port = NULL) {
  cat("🚀 Initializing enhanced cache system for Railway deployment...\n")
  
  # Try to initialize Redis if available
  redis_available <- FALSE
  
  # Check for Redis from existing cache module
  if (file.exists("R/cache/redis.R")) {
    tryCatch({
      source("R/cache/redis.R", local = FALSE)
      if (exists("init_redis_connection")) {
        redis_result <- init_redis_connection()
        if (!isTRUE(is.null(redis_result)) && redis_result$success) {
          CACHE_CONFIG$redis_enabled <<- TRUE
          redis_available <- TRUE
          cat("✅ Redis cache initialized from existing module\n")
        }
      }
    }, error = function(e) {
      cat("⚠️ Redis module initialization failed:", e$message, "\n")
    })
  }
  
  # Fallback Redis initialization
  if (!redis_available && (!isTRUE(is.null(redis_host)) || Sys.getenv("REDIS_URL") != "")) {
    tryCatch({
      if (requireNamespace("redux", quietly = TRUE)) {
        redis_url <- if(!is.null(redis_host)) {
          paste0("redis://", redis_host, ":", ifelse(is.null(redis_port), 6379, redis_port))
        } else {
          Sys.getenv("REDIS_URL")
        }
        
        # Test Redis connection
        .redis_conn <<- redux::hiredis(redis::redis_config(url = redis_url))
        .redis_conn$ping()
        
        CACHE_CONFIG$redis_enabled <<- TRUE
        redis_available <- TRUE
        cat("✅ Redis cache initialized successfully\n")
        
      } else {
        cat("⚠️ Redux package not available, using memory cache only\n")
      }
    }, error = function(e) {
      cat("⚠️ Redis connection failed:", e$message, "\n")
      cat("   Falling back to memory cache only\n")
    })
  }
  
  # Initialize enhanced memory cache
  .memory_cache <<- list()
  .cache_stats <<- list(
    hits = 0, 
    misses = 0, 
    evictions = 0, 
    memory_usage_mb = 0,
    redis_hits = 0,
    redis_misses = 0,
    cache_layers = if(redis_available) c("redis", "memory") else c("memory")
  )
  
  cat("✅ Enhanced cache system initialized\n")
  cat("   - Redis:", if(redis_available) "ENABLED" else "DISABLED", "\n")
  cat("   - Memory cache: ENABLED (max", CACHE_CONFIG$max_memory_cache_mb, "MB)\n")
  cat("   - Cache layers:", paste(.cache_stats$cache_layers, collapse = " + "), "\n")
  
  return(list(
    redis_enabled = redis_available,
    memory_cache_enabled = TRUE,
    max_memory_mb = CACHE_CONFIG$max_memory_cache_mb,
    cache_layers = .cache_stats$cache_layers
  ))
}

#' Generate Cache Key
#' 
#' @param prefix Key prefix (e.g., "search", "document", "analytics")
#' @param ... Additional parameters to include in key
#' @return MD5 hash cache key
#' @export
generate_cache_key <- function(prefix, ...) {
  params <- list(...)
  key_string <- paste0(prefix, "_", paste(params, collapse = "_"))
  return(digest::digest(key_string, algo = "md5"))
}

#' Set Cache Value
#' 
#' @param key Cache key
#' @param value Value to cache
#' @param ttl Time to live in seconds (optional)
#' @param prefix Cache prefix for categorization
#' @return TRUE if cached successfully, FALSE otherwise
#' @export
cache_set <- function(key, value, ttl = NULL, prefix = "general") {
  if (is.null(ttl)) {
    ttl <- CACHE_CONFIG$default_ttl
  }
  
  # Try Redis first if available
  if (CACHE_CONFIG$redis_enabled && exists(".redis_conn")) {
    tryCatch({
      serialized_value <- serialize(value, NULL)
      .redis_conn$setex(key, ttl, serialized_value)
      return(TRUE)
    }, error = function(e) {
      cat("⚠️ Redis cache set failed:", e$message, "\n")
      # Fall through to memory cache
    })
  }
  
  # Memory cache fallback
  tryCatch({
    # Check memory usage and evict if necessary
    check_memory_limit()
    
    cache_entry <- list(
      value = value,
      created_at = Sys.time(),
      expires_at = Sys.time() + ttl,
      prefix = prefix,
      access_count = 0
    )
    
    .memory_cache[[key]] <<- cache_entry
    update_memory_usage()
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Memory cache set failed:", e$message, "\n")
    return(FALSE)
  })
}

#' Get Cache Value with Enhanced Layered Caching
#' 
#' @param key Cache key
#' @return Cached value or NULL if not found/expired
#' @export
cache_get <- function(key) {
  # Layer 1: Try Redis first if available
  if (CACHE_CONFIG$redis_enabled && exists(".redis_conn")) {
    tryCatch({
      serialized_value <- .redis_conn$get(key)
      if (!is.null(serialized_value)) {
        .cache_stats$hits <<- .cache_stats$hits + 1
        .cache_stats$redis_hits <<- .cache_stats$redis_hits + 1
        
        # Promote to memory cache for faster subsequent access
        value <- unserialize(serialized_value)
        tryCatch({
          cache_entry <- list(
            value = value,
            created_at = Sys.time(),
            expires_at = Sys.time() + CACHE_CONFIG$default_ttl,
            prefix = "redis_promoted",
            access_count = 1,
            last_accessed = Sys.time()
          )
          .memory_cache[[key]] <<- cache_entry
        }, error = function(e) {
          # Ignore memory cache promotion errors
        })
        
        return(value)
      } else {
        .cache_stats$redis_misses <<- .cache_stats$redis_misses + 1
      }
    }, error = function(e) {
      cat("⚠️ Redis cache get failed:", e$message, "\n")
      .cache_stats$redis_misses <<- .cache_stats$redis_misses + 1
      # Fall through to memory cache
    })
  }
  
  # Layer 2: Memory cache fallback
  if (key %in% names(.memory_cache)) {
    cache_entry <- .memory_cache[[key]]
    
    # Check if expired
    if (Sys.time() > cache_entry$expires_at) {
      .memory_cache[[key]] <<- NULL
      .cache_stats$misses <<- .cache_stats$misses + 1
      return(NULL)
    }
    
    # Update access statistics
    cache_entry$access_count <- cache_entry$access_count + 1
    cache_entry$last_accessed <- Sys.time()
    .memory_cache[[key]] <<- cache_entry
    
    .cache_stats$hits <<- .cache_stats$hits + 1
    return(cache_entry$value)
  }
  
  .cache_stats$misses <<- .cache_stats$misses + 1
  return(NULL)
}

#' Cache Search Results
#' 
#' @param search_params Search parameters list
#' @param results Search results to cache
#' @return TRUE if cached successfully
#' @export
cache_search_results <- function(search_params, results) {
  key <- generate_cache_key("search", 
                           search_params$search_term, 
                           search_params$category,
                           search_params$state,
                           search_params$limit,
                           search_params$offset)
  
  return(cache_set(key, results, CACHE_CONFIG$search_result_ttl, "search"))
}

#' Get Cached Search Results
#' 
#' @param search_params Search parameters list
#' @return Cached results or NULL
#' @export
cache_get_search_results <- function(search_params) {
  key <- generate_cache_key("search", 
                           search_params$search_term, 
                           search_params$category,
                           search_params$state,
                           search_params$limit,
                           search_params$offset)
  
  return(cache_get(key))
}

#' Cache Document Data
#' 
#' @param document_id Document identifier
#' @param document_data Document data to cache
#' @return TRUE if cached successfully
#' @export
cache_document <- function(document_id, document_data) {
  key <- generate_cache_key("document", document_id)
  return(cache_set(key, document_data, CACHE_CONFIG$document_ttl, "document"))
}

#' Get Cached Document
#' 
#' @param document_id Document identifier
#' @return Cached document or NULL
#' @export
cache_get_document <- function(document_id) {
  key <- generate_cache_key("document", document_id)
  return(cache_get(key))
}

#' Cache Analytics Results
#' 
#' @param analytics_type Type of analytics (e.g., "temporal", "sentiment")
#' @param params Analytics parameters
#' @param results Analytics results to cache
#' @return TRUE if cached successfully
#' @export
cache_analytics <- function(analytics_type, params, results) {
  key <- generate_cache_key("analytics", analytics_type, paste(params, collapse = "_"))
  return(cache_set(key, results, CACHE_CONFIG$analytics_ttl, "analytics"))
}

#' Get Cached Analytics
#' 
#' @param analytics_type Type of analytics
#' @param params Analytics parameters
#' @return Cached analytics or NULL
#' @export
cache_get_analytics <- function(analytics_type, params) {
  key <- generate_cache_key("analytics", analytics_type, paste(params, collapse = "_"))
  return(cache_get(key))
}

#' Check Memory Usage and Evict if Necessary
#' 
#' @return Number of entries evicted
#' @export
check_memory_limit <- function() {
  if (length(.memory_cache) <= CACHE_CONFIG$max_cache_entries) {
    return(0)
  }
  
  # Get cache entries with access information
  cache_info <- data.frame(
    key = names(.memory_cache),
    created_at = sapply(.memory_cache, function(x) as.numeric(x$created_at)),
    access_count = sapply(.memory_cache, function(x) x$access_count),
    stringsAsFactors = FALSE
  )
  
  # Sort by access count (ascending) and creation time (ascending)
  # Remove least recently used items
  cache_info <- cache_info[order(cache_info$access_count, cache_info$created_at), ]
  
  # Calculate how many to evict (remove 20% when limit exceeded)
  num_to_evict <- ceiling(nrow(cache_info) * 0.2)
  keys_to_evict <- cache_info$key[1:num_to_evict]
  
  # Remove selected entries
  for (key in keys_to_evict) {
    .memory_cache[[key]] <<- NULL
  }
  
  .cache_stats$evictions <<- .cache_stats$evictions + num_to_evict
  update_memory_usage()
  
  cat("🧹 Evicted", num_to_evict, "cache entries to free memory\n")
  return(num_to_evict)
}

#' Update Memory Usage Statistics
#' 
#' @export
update_memory_usage <- function() {
  # Estimate memory usage (rough calculation)
  total_size <- 0
  for (entry in .memory_cache) {
    total_size <- total_size + object.size(entry)
  }
  
  .cache_stats$memory_usage_mb <<- as.numeric(total_size) / (1024 * 1024)
}

#' Clear Cache by Prefix
#' 
#' @param prefix Cache prefix to clear (optional, clears all if NULL)
#' @return Number of entries cleared
#' @export
cache_clear <- function(prefix = NULL) {
  entries_cleared <- 0
  
  # Clear Redis cache if available
  if (CACHE_CONFIG$redis_enabled && exists(".redis_conn")) {
    tryCatch({
      if (is.null(prefix)) {
        .redis_conn$flushdb()
        cat("🧹 Redis cache cleared completely\n")
      } else {
        # Redis doesn't have prefix clearing, would need to implement key scanning
        cat("⚠️ Redis prefix clearing not implemented\n")
      }
    }, error = function(e) {
      cat("⚠️ Redis cache clear failed:", e$message, "\n")
    })
  }
  
  # Clear memory cache
  if (is.null(prefix)) {
    entries_cleared <- length(.memory_cache)
    .memory_cache <<- list()
  } else {
    keys_to_remove <- c()
    for (key in names(.memory_cache)) {
      if (.memory_cache[[key]]$prefix == prefix) {
        keys_to_remove <- c(keys_to_remove, key)
      }
    }
    
    for (key in keys_to_remove) {
      .memory_cache[[key]] <<- NULL
      entries_cleared <- entries_cleared + 1
    }
  }
  
  update_memory_usage()
  cat("🧹 Cleared", entries_cleared, "memory cache entries\n")
  return(entries_cleared)
}

#' Get Enhanced Cache Statistics
#' 
#' @return List with comprehensive cache performance statistics
#' @export
get_cache_stats <- function() {
  total_hits <- .cache_stats$hits
  total_misses <- .cache_stats$misses
  
  hit_rate <- if ((total_hits + total_misses) > 0) {
    total_hits / (total_hits + total_misses) * 100
  } else {
    0
  }
  
  redis_hit_rate <- if ((.cache_stats$redis_hits + .cache_stats$redis_misses) > 0) {
    .cache_stats$redis_hits / (.cache_stats$redis_hits + .cache_stats$redis_misses) * 100
  } else {
    0
  }
  
  stats <- list(
    # System configuration
    redis_enabled = CACHE_CONFIG$redis_enabled,
    memory_cache_enabled = CACHE_CONFIG$memory_cache_enabled,
    cache_layers = .cache_stats$cache_layers,
    
    # Memory cache metrics
    memory_total_entries = length(.memory_cache),
    memory_usage_mb = round(.cache_stats$memory_usage_mb, 2),
    max_memory_mb = CACHE_CONFIG$max_memory_cache_mb,
    memory_utilization_percent = round((.cache_stats$memory_usage_mb / CACHE_CONFIG$max_memory_cache_mb) * 100, 2),
    
    # Overall performance metrics
    total_hits = total_hits,
    total_misses = total_misses,
    overall_hit_rate_percent = round(hit_rate, 2),
    total_evictions = .cache_stats$evictions,
    
    # Redis-specific metrics
    redis_hits = .cache_stats$redis_hits,
    redis_misses = .cache_stats$redis_misses,
    redis_hit_rate_percent = round(redis_hit_rate, 2),
    
    # Performance insights
    cache_efficiency = if(hit_rate > 80) "Excellent" else if(hit_rate > 60) "Good" else if(hit_rate > 40) "Fair" else "Poor",
    
    # Recommendations
    recommendations = generate_cache_recommendations(hit_rate, .cache_stats$memory_usage_mb)
  )
  
  # Add Redis-specific info if available
  if (CACHE_CONFIG$redis_enabled && exists(".redis_conn")) {
    tryCatch({
      redis_info <- .redis_conn$info()
      stats$redis_memory_usage <- redis_info$used_memory_human
      stats$redis_connected_clients <- redis_info$connected_clients
      stats$redis_total_commands_processed <- redis_info$total_commands_processed
    }, error = function(e) {
      stats$redis_error <- e$message
    })
  }
  
  return(stats)
}

#' Generate Cache Performance Recommendations
#' 
#' @param hit_rate Current cache hit rate percentage
#' @param memory_usage Current memory usage in MB
#' @return Character vector of recommendations
generate_cache_recommendations <- function(hit_rate, memory_usage) {
  recommendations <- c()
  
  if (hit_rate < 50) {
    recommendations <- c(recommendations, "Consider increasing cache TTL values")
    recommendations <- c(recommendations, "Review cache key strategies for better reuse")
  }
  
  if (memory_usage > CACHE_CONFIG$max_memory_cache_mb * 0.9) {
    recommendations <- c(recommendations, "Memory cache near capacity - consider cleanup")
  }
  
  if (.cache_stats$evictions > 100) {
    recommendations <- c(recommendations, "High eviction rate - consider increasing memory limit")
  }
  
  if (CACHE_CONFIG$redis_enabled && .cache_stats$redis_misses > .cache_stats$redis_hits) {
    recommendations <- c(recommendations, "Redis cache underperforming - check TTL settings")
  }
  
  if (length(recommendations) == 0) {
    recommendations <- c("Cache performance is optimal")
  }
  
  return(recommendations)
}

#' Warm Up Cache with Common Queries
#' 
#' @export
cache_warmup <- function() {
  cat("🔥 Warming up cache with common queries...\n")
  
  # Common search terms for Brazilian legislation
  common_searches <- c(
    "transporte", "meio ambiente", "educação", "saúde", "segurança",
    "lei", "decreto", "resolução", "portaria"
  )
  
  # Pre-cache some common search results
  for (search_term in common_searches) {
    tryCatch({
      # This would typically call your search function
      # For now, we'll just create placeholder cache entries
      key <- generate_cache_key("search", search_term, "all", "all", 50, 0)
      cache_set(key, list(placeholder = TRUE, search_term = search_term), 
               CACHE_CONFIG$search_result_ttl, "search")
    }, error = function(e) {
      cat("⚠️ Cache warmup failed for:", search_term, "-", e$message, "\n")
    })
  }
  
  cat("✅ Cache warmup completed\n")
}

cat("✅ Cache utilities module loaded successfully\n")