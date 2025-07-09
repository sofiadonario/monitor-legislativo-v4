# Redis Cache Integration for Monitor Legislativo v4
# Multi-level caching strategy with cache warming and invalidation

library(redux)
library(jsonlite)
library(digest)
library(lubridate)
library(future)
library(promises)

# Redis cache configuration
REDIS_CONFIG <- list(
  connection = list(
    host = Sys.getenv("REDIS_HOST", "localhost"),
    port = as.integer(Sys.getenv("REDIS_PORT", "6379")),
    password = Sys.getenv("REDIS_PASSWORD", ""),
    db = as.integer(Sys.getenv("REDIS_DB", "0")),
    timeout = 30,
    max_retries = 3
  ),
  
  cache_strategies = list(
    search_results = list(
      ttl = 3600,  # 1 hour
      prefix = "search:",
      compression = TRUE,
      invalidation_tags = c("documents", "search")
    ),
    
    lexml_vocabulary = list(
      ttl = 86400,  # 24 hours
      prefix = "vocab:",
      compression = TRUE,
      invalidation_tags = c("vocabulary", "lexml")
    ),
    
    geographic_data = list(
      ttl = 604800,  # 7 days
      prefix = "geo:",
      compression = FALSE,
      invalidation_tags = c("geographic", "ibge")
    ),
    
    document_metadata = list(
      ttl = 7200,  # 2 hours
      prefix = "doc:",
      compression = TRUE,
      invalidation_tags = c("documents", "metadata")
    ),
    
    analytics_data = list(
      ttl = 1800,  # 30 minutes
      prefix = "analytics:",
      compression = TRUE,
      invalidation_tags = c("analytics", "dashboard")
    ),
    
    session_data = list(
      ttl = 28800,  # 8 hours
      prefix = "session:",
      compression = FALSE,
      invalidation_tags = c("session", "user")
    )
  ),
  
  warming_strategies = list(
    search_results = list(
      enabled = TRUE,
      warm_on_startup = TRUE,
      warm_queries = c("transporte", "mobilidade", "trânsito", "rodoviário", "ferroviário")
    ),
    
    geographic_data = list(
      enabled = TRUE,
      warm_on_startup = TRUE,
      preload_states = c("SP", "RJ", "MG", "RS", "PR")
    ),
    
    vocabulary = list(
      enabled = TRUE,
      warm_on_startup = TRUE,
      preload_concepts = c("transport", "infrastructure", "regulation")
    )
  ),
  
  monitoring = list(
    track_hit_rate = TRUE,
    track_performance = TRUE,
    alert_threshold_ms = 1000,
    log_slow_operations = TRUE
  )
)

# Global Redis connection
redis_connection <- NULL

#' Initialize Redis connection with retry logic
#' @return Redis connection object or NULL if failed
initialize_redis_connection <- function() {
  tryCatch({
    # Create Redis connection with configuration
    redis_connection <<- redux::hiredis(
      host = REDIS_CONFIG$connection$host,
      port = REDIS_CONFIG$connection$port,
      password = if (REDIS_CONFIG$connection$password != "") REDIS_CONFIG$connection$password else NULL,
      db = REDIS_CONFIG$connection$db,
      timeout = REDIS_CONFIG$connection$timeout
    )
    
    # Test connection
    redis_connection$PING()
    
    log_event("Redis connection established successfully", "INFO")
    return(redis_connection)
    
  }, error = function(e) {
    log_event(paste("Failed to connect to Redis:", e$message), "ERROR")
    redis_connection <<- NULL
    return(NULL)
  })
}

#' Generate cache key with consistent hashing
#' @param type Cache type
#' @param data Input data for hashing
#' @param params Additional parameters
#' @return Cache key string
generate_cache_key <- function(type, data, params = NULL) {
  # Get cache configuration for type
  cache_config <- REDIS_CONFIG$cache_strategies[[type]]
  if (is.null(cache_config)) {
    stop(paste("Unknown cache type:", type))
  }
  
  # Create hash input
  hash_input <- list(
    data = data,
    params = params,
    type = type
  )
  
  # Generate consistent hash
  hash_value <- digest(toJSON(hash_input, auto_unbox = TRUE), algo = "md5")
  
  # Return prefixed key
  paste0(cache_config$prefix, hash_value)
}

#' Store data in Redis cache with compression and TTL
#' @param key Cache key
#' @param data Data to cache
#' @param type Cache type for configuration
#' @param custom_ttl Custom TTL override
#' @return Boolean indicating success
redis_set <- function(key, data, type, custom_ttl = NULL) {
  if (is.null(redis_connection)) {
    log_event("Redis not available for SET operation", "WARN")
    return(FALSE)
  }
  
  start_time <- Sys.time()
  
  tryCatch({
    # Get cache configuration
    cache_config <- REDIS_CONFIG$cache_strategies[[type]]
    ttl <- custom_ttl %||% cache_config$ttl
    
    # Prepare data for storage
    cache_data <- list(
      data = data,
      timestamp = as.numeric(Sys.time()),
      type = type,
      tags = cache_config$invalidation_tags
    )
    
    # Serialize data
    serialized_data <- if (cache_config$compression) {
      # Compress JSON for large objects
      json_data <- toJSON(cache_data, auto_unbox = TRUE)
      memCompress(charToRaw(json_data), type = "gzip")
    } else {
      toJSON(cache_data, auto_unbox = TRUE)
    }
    
    # Store in Redis with TTL
    redis_connection$SETEX(key, ttl, serialized_data)
    
    # Track performance if enabled
    if (REDIS_CONFIG$monitoring$track_performance) {
      operation_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
      record_cache_metric("set_time", operation_time, type)
      
      if (operation_time > REDIS_CONFIG$monitoring$alert_threshold_ms) {
        log_event(paste("Slow Redis SET operation:", operation_time, "ms for key", key), "WARN")
      }
    }
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Redis SET error for key", key, ":", e$message), "ERROR")
    return(FALSE)
  })
}

#' Retrieve data from Redis cache with decompression
#' @param key Cache key
#' @param type Cache type for configuration
#' @return Cached data or NULL if not found
redis_get <- function(key, type) {
  if (is.null(redis_connection)) {
    log_event("Redis not available for GET operation", "WARN")
    return(NULL)
  }
  
  start_time <- Sys.time()
  
  tryCatch({
    # Get cache configuration
    cache_config <- REDIS_CONFIG$cache_strategies[[type]]
    
    # Retrieve from Redis
    raw_data <- redis_connection$GET(key)
    
    if (is.null(raw_data)) {
      record_cache_metric("miss", 1, type)
      return(NULL)
    }
    
    # Deserialize data
    cache_data <- if (cache_config$compression) {
      # Decompress if needed
      if (is.raw(raw_data)) {
        decompressed <- memDecompress(raw_data, type = "gzip")
        fromJSON(rawToChar(decompressed))
      } else {
        fromJSON(raw_data)
      }
    } else {
      fromJSON(raw_data)
    }
    
    # Validate cache data structure
    if (!all(c("data", "timestamp", "type") %in% names(cache_data))) {
      log_event(paste("Invalid cache data structure for key:", key), "WARN")
      redis_connection$DEL(key)  # Remove corrupted data
      return(NULL)
    }
    
    # Record cache hit
    record_cache_metric("hit", 1, type)
    
    # Track performance if enabled
    if (REDIS_CONFIG$monitoring$track_performance) {
      operation_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
      record_cache_metric("get_time", operation_time, type)
    }
    
    return(cache_data$data)
    
  }, error = function(e) {
    log_event(paste("Redis GET error for key", key, ":", e$message), "ERROR")
    record_cache_metric("error", 1, type)
    return(NULL)
  })
}

#' Cache search results with intelligent key generation
#' @param query Search query
#' @param filters Search filters
#' @param results Search results to cache
#' @param ttl Custom TTL
#' @return Cache key used
cache_search_results <- function(query, filters, results, ttl = NULL) {
  cache_key <- generate_cache_key("search_results", list(
    query = query,
    filters = filters
  ))
  
  success <- redis_set(cache_key, results, "search_results", ttl)
  
  if (success) {
    log_event(paste("Cached search results for query:", substr(query, 1, 50)), "INFO")
  }
  
  return(cache_key)
}

#' Retrieve cached search results
#' @param query Search query
#' @param filters Search filters
#' @return Cached results or NULL
get_cached_search_results <- function(query, filters) {
  cache_key <- generate_cache_key("search_results", list(
    query = query,
    filters = filters
  ))
  
  results <- redis_get(cache_key, "search_results")
  
  if (!is.null(results)) {
    log_event(paste("Cache HIT for search query:", substr(query, 1, 50)), "INFO")
  }
  
  return(results)
}

#' Cache vocabulary data with hierarchical structure
#' @param vocabulary_type Type of vocabulary (transport, legal, etc.)
#' @param vocabulary_data Vocabulary data to cache
#' @return Cache key used
cache_vocabulary_data <- function(vocabulary_type, vocabulary_data) {
  cache_key <- generate_cache_key("lexml_vocabulary", list(
    type = vocabulary_type
  ))
  
  success <- redis_set(cache_key, vocabulary_data, "lexml_vocabulary")
  
  if (success) {
    log_event(paste("Cached vocabulary data for type:", vocabulary_type), "INFO")
  }
  
  return(cache_key)
}

#' Retrieve cached vocabulary data
#' @param vocabulary_type Type of vocabulary
#' @return Cached vocabulary or NULL
get_cached_vocabulary <- function(vocabulary_type) {
  cache_key <- generate_cache_key("lexml_vocabulary", list(
    type = vocabulary_type
  ))
  
  return(redis_get(cache_key, "lexml_vocabulary"))
}

#' Cache geographic data with spatial indexing
#' @param geographic_level Level (state, municipality, etc.)
#' @param geo_data Geographic data to cache
#' @return Cache key used
cache_geographic_data <- function(geographic_level, geo_data) {
  cache_key <- generate_cache_key("geographic_data", list(
    level = geographic_level
  ))
  
  success <- redis_set(cache_key, geo_data, "geographic_data")
  
  if (success) {
    log_event(paste("Cached geographic data for level:", geographic_level), "INFO")
  }
  
  return(cache_key)
}

#' Retrieve cached geographic data
#' @param geographic_level Geographic level
#' @return Cached geographic data or NULL
get_cached_geographic_data <- function(geographic_level) {
  cache_key <- generate_cache_key("geographic_data", list(
    level = geographic_level
  ))
  
  return(redis_get(cache_key, "geographic_data"))
}

#' Invalidate cache by tags
#' @param tags Vector of invalidation tags
#' @return Number of keys invalidated
invalidate_cache_by_tags <- function(tags) {
  if (is.null(redis_connection)) {
    return(0)
  }
  
  invalidated_count <- 0
  
  tryCatch({
    # Get all cache types that match the tags
    for (cache_type in names(REDIS_CONFIG$cache_strategies)) {
      cache_config <- REDIS_CONFIG$cache_strategies[[cache_type]]
      
      if (any(tags %in% cache_config$invalidation_tags)) {
        # Get all keys for this cache type
        pattern <- paste0(cache_config$prefix, "*")
        keys <- redis_connection$KEYS(pattern)
        
        if (length(keys) > 0) {
          redis_connection$DEL(keys)
          invalidated_count <- invalidated_count + length(keys)
          
          log_event(paste("Invalidated", length(keys), "keys for cache type:", cache_type), "INFO")
        }
      }
    }
    
  }, error = function(e) {
    log_event(paste("Cache invalidation error:", e$message), "ERROR")
  })
  
  return(invalidated_count)
}

#' Warm cache with common queries and data
#' @param strategies Warming strategies to execute
#' @return List of warming results
warm_cache <- function(strategies = NULL) {
  if (is.null(redis_connection)) {
    log_event("Redis not available for cache warming", "WARN")
    return(list())
  }
  
  # Use all strategies if none specified
  if (is.null(strategies)) {
    strategies <- names(REDIS_CONFIG$warming_strategies)
  }
  
  warming_results <- list()
  
  for (strategy_name in strategies) {
    strategy <- REDIS_CONFIG$warming_strategies[[strategy_name]]
    
    if (!strategy$enabled || !strategy$warm_on_startup) {
      next
    }
    
    tryCatch({
      warming_results[[strategy_name]] <- switch(strategy_name,
        "search_results" = warm_search_cache(strategy),
        "geographic_data" = warm_geographic_cache(strategy),
        "vocabulary" = warm_vocabulary_cache(strategy),
        list(status = "not_implemented")
      )
      
    }, error = function(e) {
      log_event(paste("Cache warming error for", strategy_name, ":", e$message), "ERROR")
      warming_results[[strategy_name]] <- list(status = "error", message = e$message)
    })
  }
  
  log_event(paste("Cache warming completed for", length(warming_results), "strategies"), "INFO")
  return(warming_results)
}

#' Warm search cache with common queries
#' @param strategy Warming strategy configuration
#' @return Warming results
warm_search_cache <- function(strategy) {
  warmed_queries <- 0
  
  for (query in strategy$warm_queries) {
    # Simulate search for common queries to warm cache
    future({
      # This would normally call the actual search function
      # For now, we'll create placeholder data structure
      search_results <- data.frame(
        titulo = paste("Documento sobre", query),
        tipo = "Lei",
        numero = sample(1000:9999, 5),
        data = Sys.Date() - sample(1:365, 5),
        estado = sample(c("SP", "RJ", "MG"), 5, replace = TRUE),
        stringsAsFactors = FALSE
      )
      
      cache_search_results(query, list(), search_results)
      
    }) %...>% {
      warmed_queries <<- warmed_queries + 1
    }
  }
  
  return(list(
    status = "success", 
    queries_warmed = length(strategy$warm_queries),
    completed = warmed_queries
  ))
}

#' Warm geographic cache with state data
#' @param strategy Warming strategy configuration
#' @return Warming results
warm_geographic_cache <- function(strategy) {
  warmed_states <- 0
  
  for (state in strategy$preload_states) {
    # Cache geographic data for each state
    geo_data <- list(
      state_code = state,
      municipalities = paste("Municípios de", state),
      coordinates = list(lat = -15.7942, lng = -47.8825)  # Placeholder
    )
    
    cache_geographic_data(paste0("state_", state), geo_data)
    warmed_states <- warmed_states + 1
  }
  
  return(list(
    status = "success",
    states_warmed = warmed_states
  ))
}

#' Warm vocabulary cache with concepts
#' @param strategy Warming strategy configuration  
#' @return Warming results
warm_vocabulary_cache <- function(strategy) {
  warmed_concepts <- 0
  
  for (concept in strategy$preload_concepts) {
    # Cache vocabulary data for each concept
    vocab_data <- list(
      concept = concept,
      related_terms = paste("Termos relacionados a", concept),
      hierarchies = list(broader = "broader_concept", narrower = "narrower_concept")
    )
    
    cache_vocabulary_data(concept, vocab_data)
    warmed_concepts <- warmed_concepts + 1
  }
  
  return(list(
    status = "success",
    concepts_warmed = warmed_concepts
  ))
}

#' Record cache performance metrics
#' @param metric_name Name of the metric
#' @param value Metric value
#' @param cache_type Cache type
record_cache_metric <- function(metric_name, value, cache_type) {
  if (!REDIS_CONFIG$monitoring$track_performance) {
    return()
  }
  
  # Store metric in a time series format
  metric_key <- paste0("metrics:", cache_type, ":", metric_name)
  timestamp <- as.numeric(Sys.time())
  
  tryCatch({
    # Store metric with timestamp (keeping last 1000 entries)
    redis_connection$LPUSH(metric_key, paste(timestamp, value, sep = ":"))
    redis_connection$LTRIM(metric_key, 0, 999)
    redis_connection$EXPIRE(metric_key, 86400)  # 24 hours TTL
    
  }, error = function(e) {
    # Silently fail for metrics to avoid disrupting main flow
  })
}

#' Get cache performance statistics
#' @param cache_type Optional cache type filter
#' @return Cache statistics
get_cache_statistics <- function(cache_type = NULL) {
  if (is.null(redis_connection)) {
    return(list(status = "redis_unavailable"))
  }
  
  tryCatch({
    stats <- list()
    
    # Get basic Redis info
    redis_info <- redis_connection$INFO()
    
    # Parse Redis info for relevant metrics
    stats$redis_memory_used <- extract_redis_info(redis_info, "used_memory_human")
    stats$redis_connected_clients <- extract_redis_info(redis_info, "connected_clients")
    stats$redis_total_commands <- extract_redis_info(redis_info, "total_commands_processed")
    
    # Get cache-specific metrics
    cache_types <- if (is.null(cache_type)) {
      names(REDIS_CONFIG$cache_strategies)
    } else {
      cache_type
    }
    
    for (type in cache_types) {
      type_stats <- list()
      
      # Get hit/miss metrics
      hits_key <- paste0("metrics:", type, ":hit")
      misses_key <- paste0("metrics:", type, ":miss")
      
      hits <- redis_connection$LLEN(hits_key)
      misses <- redis_connection$LLEN(misses_key)
      
      total_requests <- hits + misses
      hit_rate <- if (total_requests > 0) hits / total_requests else 0
      
      type_stats$hit_rate <- round(hit_rate * 100, 2)
      type_stats$total_requests <- total_requests
      type_stats$hits <- hits
      type_stats$misses <- misses
      
      # Get performance metrics
      get_times_key <- paste0("metrics:", type, ":get_time")
      set_times_key <- paste0("metrics:", type, ":set_time")
      
      get_times <- redis_connection$LRANGE(get_times_key, 0, 99)
      set_times <- redis_connection$LRANGE(set_times_key, 0, 99)
      
      if (length(get_times) > 0) {
        get_values <- sapply(get_times, function(x) as.numeric(strsplit(x, ":")[[1]][2]))
        type_stats$avg_get_time_ms <- round(mean(get_values), 2)
      }
      
      if (length(set_times) > 0) {
        set_values <- sapply(set_times, function(x) as.numeric(strsplit(x, ":")[[1]][2]))
        type_stats$avg_set_time_ms <- round(mean(set_values), 2)
      }
      
      stats[[type]] <- type_stats
    }
    
    return(stats)
    
  }, error = function(e) {
    log_event(paste("Error getting cache statistics:", e$message), "ERROR")
    return(list(status = "error", message = e$message))
  })
}

#' Extract specific information from Redis INFO output
#' @param redis_info Redis INFO output
#' @param key Key to extract
#' @return Extracted value or NULL
extract_redis_info <- function(redis_info, key) {
  lines <- strsplit(redis_info, "\n")[[1]]
  for (line in lines) {
    if (grepl(paste0("^", key, ":"), line)) {
      return(gsub(paste0("^", key, ":"), "", line))
    }
  }
  return(NULL)
}

#' Clear all cache data
#' @param confirm Confirmation flag
#' @return Number of keys deleted
clear_all_cache <- function(confirm = FALSE) {
  if (!confirm) {
    stop("clear_all_cache requires confirm = TRUE to proceed")
  }
  
  if (is.null(redis_connection)) {
    return(0)
  }
  
  tryCatch({
    # Get all cache keys
    all_keys <- c()
    for (cache_type in names(REDIS_CONFIG$cache_strategies)) {
      cache_config <- REDIS_CONFIG$cache_strategies[[cache_type]]
      pattern <- paste0(cache_config$prefix, "*")
      keys <- redis_connection$KEYS(pattern)
      all_keys <- c(all_keys, keys)
    }
    
    if (length(all_keys) > 0) {
      redis_connection$DEL(all_keys)
      log_event(paste("Cleared", length(all_keys), "cache keys"), "INFO")
      return(length(all_keys))
    }
    
    return(0)
    
  }, error = function(e) {
    log_event(paste("Error clearing cache:", e$message), "ERROR")
    return(0)
  })
}

#' Initialize Redis cache system
#' @param warm_on_startup Whether to warm cache on startup
#' @return Initialization status
initialize_redis_cache <- function(warm_on_startup = TRUE) {
  log_event("Initializing Redis cache system...", "INFO")
  
  # Initialize connection
  connection <- initialize_redis_connection()
  
  if (is.null(connection)) {
    log_event("Redis cache initialization failed - running without cache", "WARN")
    return(list(status = "failed", message = "Redis connection failed"))
  }
  
  # Warm cache if requested
  warming_results <- list()
  if (warm_on_startup) {
    warming_results <- warm_cache()
  }
  
  log_event("Redis cache system initialized successfully", "INFO")
  
  return(list(
    status = "success",
    connection = connection,
    warming_results = warming_results
  ))
}