# Search Result Caching System - Week 3 Implementation
# Monitor Legislativo v4 - Redis Integration for Performance Optimization
# ========================================================================

#' Search Result Caching System with Redis Integration
#' 
#' Implements high-performance search result caching using Redis for Monitor
#' Legislativo v4. Provides sub-second response times for repeated queries
#' and reduces database load for the 134k+ document collection.
#' 
#' Features:
#' - Redis-based caching with configurable TTL
#' - Intelligent cache key generation
#' - Cache warming for popular searches
#' - Performance metrics and monitoring
#' - Automatic cache invalidation
#' 
#' Target: <200ms response time for cached results
#' 
#' @family caching-utilities
#' @export

library(digest)

# Global cache configuration
.cache_config <- list(
  enabled = TRUE,
  default_ttl = 3600,  # 1 hour
  max_cache_size = 1000,  # Maximum number of cached queries
  key_prefix = "ml_search:",
  redis_host = Sys.getenv("REDIS_HOST", "localhost"),
  redis_port = as.numeric(Sys.getenv("REDIS_PORT", 6379)),
  redis_password = Sys.getenv("REDIS_PASSWORD", ""),
  fallback_memory = TRUE  # Use in-memory cache if Redis unavailable
)

# In-memory cache fallback
.memory_cache <- new.env(parent = emptyenv())
.cache_stats <- list(
  hits = 0,
  misses = 0,
  stores = 0,
  redis_available = FALSE
)

# Redis connection object
.redis_conn <- NULL

#' Initialize Redis connection for caching
#' 
#' @return List with connection status and details
#' @export
init_search_cache <- function() {
  cat("🚀 Initializing search result caching system...\n")
  
  # Check if Redis package is available
  if (!requireNamespace("redux", quietly = TRUE)) {
    warning("Redux package not available - using memory cache fallback")
    .cache_stats$redis_available <<- FALSE
    return(list(
      status = "fallback",
      backend = "memory",
      redis_available = FALSE
    ))
  }
  
  # Attempt Redis connection
  tryCatch({
    library(redux)
    
    .redis_conn <<- redux::hiredis(
      host = .cache_config$redis_host,
      port = .cache_config$redis_port,
      password = if (.cache_config$redis_password != "") .cache_config$redis_password else NULL
    )
    
    # Test connection
    test_key <- paste0(.cache_config$key_prefix, "connection_test")
    .redis_conn$SET(test_key, "ok")
    test_result <- .redis_conn$GET(test_key)
    .redis_conn$DEL(test_key)
    
    if (test_result == "ok") {
      .cache_stats$redis_available <<- TRUE
      cat("✅ Redis cache connection established\n")
      cat("   Host:", .cache_config$redis_host, "\n")
      cat("   Port:", .cache_config$redis_port, "\n")
      cat("   TTL:", .cache_config$default_ttl, "seconds\n")
      
      return(list(
        status = "connected",
        backend = "redis",
        redis_available = TRUE,
        host = .cache_config$redis_host,
        port = .cache_config$redis_port
      ))
    }
  }, error = function(e) {
    warning("Redis connection failed: ", e$message, " - using memory cache")
    .cache_stats$redis_available <<- FALSE
  })
  
  # Fallback to memory cache
  return(list(
    status = "fallback",
    backend = "memory",
    redis_available = FALSE,
    fallback_reason = "Redis connection failed"
  ))
}

#' Generate cache key for search parameters
#' 
#' @param query Search query string
#' @param filters List of search filters
#' @param sort_by Sort parameter
#' @param limit Result limit
#' @return Character string cache key
generate_cache_key <- function(query, filters = list(), sort_by = "relevance", limit = 100) {
  # Create deterministic cache key
  cache_data <- list(
    query = tolower(trimws(query)),
    filters = filters[order(names(filters))],  # Sort filters for consistency
    sort_by = sort_by,
    limit = limit,
    version = "v4"  # Cache version for invalidation
  )
  
  # Generate hash
  cache_hash <- digest(cache_data, algo = "md5", serialize = TRUE)
  cache_key <- paste0(.cache_config$key_prefix, cache_hash)
  
  return(cache_key)
}

#' Store search results in cache
#' 
#' @param cache_key Cache key string
#' @param search_results Search result object
#' @param ttl Time to live in seconds (optional)
#' @return TRUE if stored successfully, FALSE otherwise
store_search_results <- function(cache_key, search_results, ttl = NULL) {
  if (!.cache_config$enabled) {
    return(FALSE)
  }
  
  if (is.null(ttl)) {
    ttl <- .cache_config$default_ttl
  }
  
  tryCatch({
    # Prepare cache data with metadata
    cache_object <- list(
      results = search_results$results,
      total_count = search_results$total_count,
      search_time = search_results$search_time,
      query = search_results$query,
      filters = search_results$filters,
      sort_by = search_results$sort_by,
      cached_at = Sys.time(),
      ttl = ttl
    )
    
    # Serialize for storage
    serialized_data <- serialize(cache_object, connection = NULL, ascii = FALSE)
    
    # Store in Redis if available
    if (.cache_stats$redis_available && !is.null(.redis_conn)) {
      base64_data <- base64enc::base64encode(serialized_data)
      .redis_conn$SET(cache_key, base64_data)
      .redis_conn$EXPIRE(cache_key, ttl)
      
      .cache_stats$stores <<- .cache_stats$stores + 1
      return(TRUE)
    }
    
    # Fallback to memory cache
    if (.cache_config$fallback_memory) {
      # Implement simple LRU by removing oldest entries
      if (length(ls(.memory_cache)) >= .cache_config$max_cache_size) {
        oldest_key <- names(sort(sapply(ls(.memory_cache), function(k) {
          get(k, envir = .memory_cache)$cached_at
        })))[1]
        rm(list = oldest_key, envir = .memory_cache)
      }
      
      assign(cache_key, cache_object, envir = .memory_cache)
      .cache_stats$stores <<- .cache_stats$stores + 1
      return(TRUE)
    }
    
    return(FALSE)
    
  }, error = function(e) {
    warning("Failed to store search results in cache: ", e$message)
    return(FALSE)
  })
}

#' Retrieve search results from cache
#' 
#' @param cache_key Cache key string
#' @return Cached search results or NULL if not found/expired
retrieve_search_results <- function(cache_key) {
  if (!.cache_config$enabled) {
    return(NULL)
  }
  
  tryCatch({
    cache_object <- NULL
    
    # Try Redis first
    if (.cache_stats$redis_available && !is.null(.redis_conn)) {
      cached_data <- .redis_conn$GET(cache_key)
      if (!is.null(cached_data)) {
        serialized_data <- base64enc::base64decode(cached_data)
        cache_object <- unserialize(serialized_data)
      }
    }
    
    # Fallback to memory cache
    if (is.null(cache_object) && .cache_config$fallback_memory) {
      if (exists(cache_key, envir = .memory_cache)) {
        cache_object <- get(cache_key, envir = .memory_cache)
        
        # Check TTL for memory cache
        if (difftime(Sys.time(), cache_object$cached_at, units = "secs") > cache_object$ttl) {
          rm(list = cache_key, envir = .memory_cache)
          cache_object <- NULL
        }
      }
    }
    
    if (!is.null(cache_object)) {
      .cache_stats$hits <<- .cache_stats$hits + 1
      
      # Return search result format
      return(list(
        results = cache_object$results,
        total_count = cache_object$total_count,
        search_time = 0.05,  # Cached result time
        query = cache_object$query,
        filters = cache_object$filters,
        sort_by = cache_object$sort_by,
        from_cache = TRUE,
        cached_at = cache_object$cached_at
      ))
    } else {
      .cache_stats$misses <<- .cache_stats$misses + 1
      return(NULL)
    }
    
  }, error = function(e) {
    warning("Failed to retrieve from cache: ", e$message)
    .cache_stats$misses <<- .cache_stats$misses + 1
    return(NULL)
  })
}

#' Cache-aware search function
#' 
#' @param pool Database connection pool
#' @param query Search query
#' @param filters Search filters
#' @param sort_by Sort parameter
#' @param limit Result limit
#' @return Search results (from cache or database)
cached_search_documents <- function(pool, query, filters = list(), sort_by = "relevance", limit = 100) {
  # Generate cache key
  cache_key <- generate_cache_key(query, filters, sort_by, limit)
  
  # Try cache first
  cached_results <- retrieve_search_results(cache_key)
  if (!is.null(cached_results)) {
    return(cached_results)
  }
  
  # Execute database search
  search_start_time <- Sys.time()
  
  if (!is.null(pool)) {
    tryCatch({
      results <- execute_query(pool,
        "SELECT * FROM search_legislative_documents($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        params = list(
          query,
          filters$filter_estado,
          filters$filter_municipio,
          filters$filter_tipo,
          filters$filter_categoria,
          filters$filter_ano_min,
          filters$filter_ano_max,
          filters$filter_data_inicio,
          filters$filter_data_fim,
          limit,
          0,  # offset
          sort_by
        )
      )
    }, error = function(e) {
      warning("Database search failed: ", e$message)
      results <- data.frame()
    })
  } else {
    results <- data.frame()
  }
  
  search_time <- as.numeric(difftime(Sys.time(), search_start_time, units = "secs"))
  
  # Create search result object
  search_results <- list(
    results = if (!is.null(results)) results else data.frame(),
    total_count = if (!is.null(results)) nrow(results) else 0,
    search_time = search_time,
    query = query,
    filters = filters,
    sort_by = sort_by,
    from_cache = FALSE
  )
  
  # Store in cache for future use
  store_search_results(cache_key, search_results)
  
  return(search_results)
}

#' Warm cache with popular searches
#' 
#' @param pool Database connection pool
#' @param popular_queries List of popular search queries
#' @return Number of queries cached
warm_search_cache <- function(pool, popular_queries = NULL) {
  if (!.cache_config$enabled || is.null(pool)) {
    return(0)
  }
  
  # Default popular searches if not provided
  if (is.null(popular_queries)) {
    popular_queries <- c(
      "lei orgânica",
      "código civil", 
      "direito administrativo",
      "licitação pública",
      "meio ambiente",
      "transporte público",
      "servidor público",
      "processo administrativo",
      "constituição federal"
    )
  }
  
  cached_count <- 0
  
  for (query in popular_queries) {
    tryCatch({
      # Cache with basic filters
      cached_search_documents(pool, query, filters = list(), sort_by = "relevance", limit = 100)
      cached_count <- cached_count + 1
      
      # Add some popular filter combinations
      cached_search_documents(pool, query, filters = list(filter_estado = "SP"), sort_by = "relevance", limit = 100)
      cached_search_documents(pool, query, filters = list(filter_tipo = "lei"), sort_by = "relevance", limit = 100)
      
    }, error = function(e) {
      warning("Failed to warm cache for query: ", query, " - ", e$message)
    })
  }
  
  cat("🔥 Cache warmed with", cached_count, "popular searches\n")
  return(cached_count)
}

#' Get cache performance statistics
#' 
#' @return List of cache performance metrics
get_cache_stats <- function() {
  total_requests <- .cache_stats$hits + .cache_stats$misses
  hit_rate <- if (total_requests > 0) .cache_stats$hits / total_requests else 0
  
  stats <- list(
    enabled = .cache_config$enabled,
    redis_available = .cache_stats$redis_available,
    backend = if (.cache_stats$redis_available) "redis" else "memory",
    total_requests = total_requests,
    cache_hits = .cache_stats$hits,
    cache_misses = .cache_stats$misses,
    hit_rate = round(hit_rate * 100, 2),
    stores = .cache_stats$stores
  )
  
  # Add Redis-specific stats if available
  if (.cache_stats$redis_available && !is.null(.redis_conn)) {
    tryCatch({
      redis_info <- .redis_conn$INFO("memory")
      stats$redis_memory_used <- redis_info$used_memory_human
    }, error = function(e) {
      # Redis info not available
    })
  }
  
  # Add memory cache stats
  if (.cache_config$fallback_memory) {
    stats$memory_cache_size <- length(ls(.memory_cache))
  }
  
  return(stats)
}

#' Clear search cache
#' 
#' @param pattern Optional pattern to match keys for selective clearing
#' @return Number of keys cleared
clear_search_cache <- function(pattern = NULL) {
  cleared_count <- 0
  
  # Clear Redis cache
  if (.cache_stats$redis_available && !is.null(.redis_conn)) {
    tryCatch({
      if (is.null(pattern)) {
        # Clear all search cache keys
        keys <- .redis_conn$KEYS(paste0(.cache_config$key_prefix, "*"))
      } else {
        keys <- .redis_conn$KEYS(paste0(.cache_config$key_prefix, pattern, "*"))
      }
      
      if (length(keys) > 0) {
        .redis_conn$DEL(keys)
        cleared_count <- cleared_count + length(keys)
      }
    }, error = function(e) {
      warning("Failed to clear Redis cache: ", e$message)
    })
  }
  
  # Clear memory cache
  if (.cache_config$fallback_memory) {
    if (is.null(pattern)) {
      rm(list = ls(.memory_cache), envir = .memory_cache)
      cleared_count <- cleared_count + length(ls(.memory_cache))
    } else {
      matching_keys <- ls(.memory_cache)[grepl(pattern, ls(.memory_cache))]
      if (length(matching_keys) > 0) {
        rm(list = matching_keys, envir = .memory_cache)
        cleared_count <- cleared_count + length(matching_keys)
      }
    }
  }
  
  # Reset stats
  .cache_stats$hits <<- 0
  .cache_stats$misses <<- 0
  .cache_stats$stores <<- 0
  
  cat("🧹 Cleared", cleared_count, "cache entries\n")
  return(cleared_count)
}

#' Monitor cache performance and auto-optimize
#' 
#' @return List of optimization actions taken
optimize_search_cache <- function() {
  stats <- get_cache_stats()
  actions <- list()
  
  # Check hit rate and suggest optimizations
  if (stats$hit_rate < 30 && stats$total_requests > 100) {
    actions$low_hit_rate <- "Consider increasing cache TTL or warming cache with popular queries"
  }
  
  # Check memory usage
  if (stats$backend == "memory" && stats$memory_cache_size > 800) {
    cleared <- clear_search_cache("old_")  # Clear old entries
    actions$memory_cleanup <- paste("Cleared", cleared, "old entries to free memory")
  }
  
  # Suggest Redis if using memory fallback with high load
  if (!stats$redis_available && stats$total_requests > 1000) {
    actions$redis_suggestion <- "Consider enabling Redis for better caching performance"
  }
  
  return(actions)
}

# Initialize cache system on load
init_result <- init_search_cache()

cat("✅ Search Cache System loaded\n")
cat("   Backend:", init_result$backend, "\n")
cat("   Status:", init_result$status, "\n")
if (init_result$redis_available) {
  cat("   Redis: Connected\n")
} else {
  cat("   Fallback: In-memory cache\n")
}