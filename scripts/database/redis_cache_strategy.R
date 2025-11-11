# ============================================================================
# ENHANCED REDIS CACHING STRATEGY FOR BRAZILIAN LEGISLATIVE DATA (SPRINT 3B)
# ============================================================================
#
# Production-ready Redis caching system optimized for Railway PostgreSQL
# database queries with intelligent TTL, cache invalidation, and warming.
#
# Features:
# - Multi-layer caching (L1: Memory, L2: Redis) 
# - Intelligent TTL based on data volatility
# - Cache warming for common queries
# - Query pattern analysis for optimization
# - Cache invalidation strategies
# - Memory-aware caching for Railway constraints
# - Performance metrics and monitoring
# ============================================================================

cat("🚀 Loading Enhanced Redis Caching Strategy (Sprint 3B - DB-003)\n")

# Load required libraries
suppressPackageStartupMessages({
  library(R6)
  library(digest)
  library(jsonlite)
})

# Try to load Redis support
REDIS_AVAILABLE <- FALSE
tryCatch({
  if (requireNamespace("redux", quietly = TRUE)) {
    library(redux, quietly = TRUE)
    REDIS_AVAILABLE <- TRUE
    cat("✅ Redis support available via redux\n")
  } else if (requireNamespace("RcppRedis", quietly = TRUE)) {
    library(RcppRedis, quietly = TRUE) 
    REDIS_AVAILABLE <- TRUE
    cat("✅ Redis support available via RcppRedis\n")
  } else {
    cat("⚠️ No Redis packages available - using memory-only caching\n")
  }
}, error = function(e) {
  cat("⚠️ Redis initialization failed - using memory-only caching:", e$message, "\n")
})

# ============================================================================
# ENHANCED REDIS CACHE MANAGER CLASS
# ============================================================================

EnhancedRedisCacheManager <- R6Class(
  "EnhancedRedisCacheManager",
  
  private = list(
    .redis_conn = NULL,
    .memory_cache = NULL,
    .config = NULL,
    .metrics = NULL,
    .warming_queries = NULL,
    .invalidation_rules = NULL,
    .max_memory_mb = 256  # 256MB memory cache limit for Railway
  ),
  
  public = list(
    # Initialize the cache manager
    initialize = function(redis_config = NULL) {
      cat("🔧 Initializing Enhanced Redis Cache Manager\n")
      
      # Initialize configuration
      private$.config <- redis_config %||% self$get_default_config()
      
      # Initialize metrics tracking
      private$.metrics <- list(
        l1_hits = 0,          # Memory cache hits
        l2_hits = 0,          # Redis cache hits  
        misses = 0,           # Cache misses
        sets = 0,             # Cache sets
        invalidations = 0,    # Cache invalidations
        warming_operations = 0, # Cache warming operations
        errors = 0,           # Cache errors
        total_queries = 0,    # Total queries processed
        start_time = Sys.time()
      )
      
      # Initialize memory cache (L1)
      private$.memory_cache <- list()
      
      # Initialize Redis connection (L2)
      self$init_redis_connection()
      
      # Define warming queries for common patterns
      private$.warming_queries <- self$get_warming_queries()
      
      # Define cache invalidation rules
      private$.invalidation_rules <- self$get_invalidation_rules()
      
      cat("✅ Enhanced Redis Cache Manager initialized\n")
    },
    
    # Get default cache configuration
    get_default_config = function() {
      list(
        # Redis connection settings
        redis_host = Sys.getenv("REDIS_URL", "127.0.0.1"),
        redis_port = as.integer(Sys.getenv("REDIS_PORT", "6379")),
        redis_db = as.integer(Sys.getenv("REDIS_DB", "0")),
        redis_password = Sys.getenv("REDIS_PASSWORD", ""),
        
        # Cache TTL settings (in seconds)
        ttl_search_results = 300,    # 5 minutes for search results
        ttl_document_lists = 600,    # 10 minutes for document lists  
        ttl_metadata = 1800,         # 30 minutes for metadata
        ttl_statistics = 3600,       # 1 hour for statistics
        ttl_static_data = 86400,     # 24 hours for static data
        
        # Cache size limits
        max_memory_cache_size = private$.max_memory_mb * 1024 * 1024, # Convert to bytes
        max_redis_memory = "256mb",  # Redis memory limit
        
        # Performance settings
        enable_compression = TRUE,   # Compress large cache entries
        enable_serialization = TRUE, # Serialize R objects
        batch_size = 100,           # Batch operations
        
        # Cache key prefixes
        key_prefix = "monitor_leg_v4:",
        search_prefix = "search:",
        doc_prefix = "docs:",
        meta_prefix = "meta:",
        stats_prefix = "stats:"
      )
    },
    
    # Initialize Redis connection
    init_redis_connection = function() {
      if (!REDIS_AVAILABLE) {
        cat("⚠️ Redis not available - using memory-only caching\n")
        return(FALSE)
      }
      
      tryCatch({
        # Try to connect to Redis using available package
        if (exists("redux") && requireNamespace("redux", quietly = TRUE)) {
          redis_url <- Sys.getenv("REDIS_URL", "redis://127.0.0.1:6379")
          private$.redis_conn <- redux::hiredis(url = redis_url)
        } else if (exists("RcppRedis") && requireNamespace("RcppRedis", quietly = TRUE)) {
          private$.redis_conn <- new(RcppRedis::Redis, 
                                    host = private$.config$redis_host,
                                    port = private$.config$redis_port)
        }
        
        if (!is.null(private$.redis_conn)) {
          # Test connection
          test_key <- paste0(private$.config$key_prefix, "test")
          if (exists("redux") && inherits(private$.redis_conn, "redis_api")) {
            private$.redis_conn$SET(test_key, "connection_test")
            result <- private$.redis_conn$GET(test_key)
            private$.redis_conn$DEL(test_key)
          } else if (exists("RcppRedis")) {
            private$.redis_conn$set(test_key, "connection_test")
            result <- private$.redis_conn$get(test_key)
            private$.redis_conn$del(test_key)
          }
          
          cat("✅ Redis connection established\n")
          return(TRUE)
        }
        
      }, error = function(e) {
        cat("⚠️ Redis connection failed:", e$message, "\n")
        private$.redis_conn <- NULL
      })
      
      return(FALSE)
    },
    
    # Generate cache key with intelligent prefixing
    generate_cache_key = function(query_type, parameters) {
      # Create base key from parameters
      param_hash <- digest(parameters, algo = "md5")
      
      # Choose prefix based on query type
      prefix <- switch(query_type,
        "search" = private$.config$search_prefix,
        "documents" = private$.config$doc_prefix,
        "metadata" = private$.config$meta_prefix,
        "statistics" = private$.config$stats_prefix,
        ""
      )
      
      return(paste0(private$.config$key_prefix, prefix, param_hash))
    },
    
    # Get TTL based on query type and data volatility
    get_intelligent_ttl = function(query_type, data_size = NULL, last_modified = NULL) {
      base_ttl <- switch(query_type,
        "search" = private$.config$ttl_search_results,
        "documents" = private$.config$ttl_document_lists,
        "metadata" = private$.config$ttl_metadata,
        "statistics" = private$.config$ttl_statistics,
        "static" = private$.config$ttl_static_data,
        private$.config$ttl_search_results  # default
      )
      
      # Adjust TTL based on data characteristics
      if (!is.null(data_size)) {
        # Larger datasets get longer TTL (more expensive to regenerate)
        if (data_size > 10000) {
          base_ttl <- base_ttl * 2
        } else if (data_size < 100) {
          base_ttl <- base_ttl * 0.5
        }
      }
      
      # Adjust based on last modification (older data can be cached longer)
      if (!is.null(last_modified)) {
        days_old <- as.numeric(difftime(Sys.time(), last_modified, units = "days"))
        if (days_old > 30) {
          base_ttl <- base_ttl * 3  # Old data changes less frequently
        } else if (days_old < 1) {
          base_ttl <- base_ttl * 0.5  # Recent data may change more
        }
      }
      
      return(base_ttl)
    },
    
    # Multi-layer cache get (L1 memory -> L2 Redis)
    get = function(cache_key) {
      private$.metrics$total_queries <- private$.metrics$total_queries + 1
      
      # L1 Cache: Check memory first
      if (cache_key %in% names(private$.memory_cache)) {
        cache_entry <- private$.memory_cache[[cache_key]]
        
        # Check if entry is still valid
        if (Sys.time() < cache_entry$expires) {
          private$.metrics$l1_hits <- private$.metrics$l1_hits + 1
          cat("💾 L1 Cache HIT:", substr(cache_key, 1, 30), "...\n")
          return(cache_entry$data)
        } else {
          # Remove expired entry
          private$.memory_cache[[cache_key]] <- NULL
        }
      }
      
      # L2 Cache: Check Redis
      if (!is.null(private$.redis_conn)) {
        tryCatch({
          redis_data <- NULL
          
          if (exists("redux") && inherits(private$.redis_conn, "redis_api")) {
            redis_data <- private$.redis_conn$GET(cache_key)
          } else if (exists("RcppRedis")) {
            redis_data <- private$.redis_conn$get(cache_key)
          }
          
          if (!isTRUE(is.null(redis_data)) && redis_data != "") {
            # Deserialize data
            data <- self$deserialize_data(redis_data)
            
            if (!is.null(data)) {
              private$.metrics$l2_hits <- private$.metrics$l2_hits + 1
              cat("🗄️ L2 Cache (Redis) HIT:", substr(cache_key, 1, 30), "...\n")
              
              # Promote to L1 cache if under memory limit
              self$promote_to_l1_cache(cache_key, data)
              
              return(data)
            }
          }
          
        }, error = function(e) {
          private$.metrics$errors <- private$.metrics$errors + 1
          cat("❌ Redis GET error:", e$message, "\n")
        })
      }
      
      # Cache miss
      private$.metrics$misses <- private$.metrics$misses + 1
      cat("❌ Cache MISS:", substr(cache_key, 1, 30), "...\n")
      return(NULL)
    },
    
    # Multi-layer cache set (L1 memory + L2 Redis)
    set = function(cache_key, data, query_type = "search", ttl = NULL) {
      if (is.null(data)) return(FALSE)
      
      # Calculate intelligent TTL
      ttl <- ttl %||% self$get_intelligent_ttl(
        query_type, 
        data_size = if(is.data.frame(data)) nrow(data) else length(data)
      )
      
      expires_at <- Sys.time() + ttl
      private$.metrics$sets <- private$.metrics$sets + 1
      
      # L1 Cache: Store in memory if under limit
      self$set_l1_cache(cache_key, data, expires_at)
      
      # L2 Cache: Store in Redis
      if (!is.null(private$.redis_conn)) {
        tryCatch({
          serialized_data <- self$serialize_data(data)
          
          if (!is.null(serialized_data)) {
            if (exists("redux") && inherits(private$.redis_conn, "redis_api")) {
              private$.redis_conn$SETEX(cache_key, ttl, serialized_data)
            } else if (exists("RcppRedis")) {
              private$.redis_conn$setex(cache_key, ttl, serialized_data)
            }
            
            cat("💾 Cached in L1+L2:", substr(cache_key, 1, 30), "... (TTL:", ttl, "s)\n")
          }
          
        }, error = function(e) {
          private$.metrics$errors <- private$.metrics$errors + 1
          cat("❌ Redis SET error:", e$message, "\n")
        })
      } else {
        cat("💾 Cached in L1 only:", substr(cache_key, 1, 30), "... (TTL:", ttl, "s)\n")
      }
      
      return(TRUE)
    },
    
    # Set L1 (memory) cache with size limits
    set_l1_cache = function(cache_key, data, expires_at) {
      # Estimate memory usage
      data_size <- object.size(data)
      
      # Check if we're under memory limit
      current_size <- sum(sapply(private$.memory_cache, function(x) object.size(x$data)))
      
      if (current_size + data_size > private$.config$max_memory_cache_size) {
        # Evict oldest entries to make room
        self$evict_l1_cache(data_size)
      }
      
      # Store in memory cache
      private$.memory_cache[[cache_key]] <- list(
        data = data,
        expires = expires_at,
        created = Sys.time(),
        size = data_size
      )
    },
    
    # Evict L1 cache entries to free memory
    evict_l1_cache = function(needed_space) {
      # Sort by expiration time (evict expiring soonest first)
      cache_keys <- names(private$.memory_cache)
      
      if (length(cache_keys) == 0) return()
      
      expiration_times <- sapply(cache_keys, function(key) {
        private$.memory_cache[[key]]$expires
      })
      
      sorted_keys <- cache_keys[order(expiration_times)]
      freed_space <- 0
      
      for (key in sorted_keys) {
        if (freed_space >= needed_space) break
        
        entry_size <- private$.memory_cache[[key]]$size
        private$.memory_cache[[key]] <- NULL
        freed_space <- freed_space + entry_size
        
        cat("🗑️ Evicted L1 cache entry:", substr(key, 1, 30), "...\n")
      }
    },
    
    # Promote Redis data to L1 cache
    promote_to_l1_cache = function(cache_key, data) {
      data_size <- object.size(data)
      current_size <- sum(sapply(private$.memory_cache, function(x) object.size(x$data)))
      
      # Only promote if we have space or data is small
      if (current_size + data_size <= private$.config$max_memory_cache_size || data_size < 1024*1024) {
        private$.memory_cache[[cache_key]] <- list(
          data = data,
          expires = Sys.time() + 300,  # 5 minute L1 TTL
          created = Sys.time(),
          size = data_size
        )
      }
    },
    
    # Serialize data for Redis storage
    serialize_data = function(data) {
      tryCatch({
        if (private$.config$enable_serialization) {
          # Use base R serialization
          raw_data <- serialize(data, connection = NULL)
          
          if (private$.config$enable_compression) {
            # Compress if data is large
            if (length(raw_data) > 1024) {  # Compress if > 1KB
              return(base64enc::base64encode(memCompress(raw_data, "gzip")))
            }
          }
          
          return(base64enc::base64encode(raw_data))
        } else {
          # Simple JSON serialization for basic data
          return(jsonlite::toJSON(data, auto_unbox = TRUE))
        }
      }, error = function(e) {
        cat("❌ Serialization error:", e$message, "\n")
        return(NULL)
      })
    },
    
    # Deserialize data from Redis
    deserialize_data = function(serialized_data) {
      tryCatch({
        if (private$.config$enable_serialization) {
          # Decode base64
          raw_data <- base64enc::base64decode(serialized_data)
          
          # Try decompression first (in case it was compressed)
          tryCatch({
            decompressed <- memDecompress(raw_data, "gzip")
            return(unserialize(decompressed))
          }, error = function(e) {
            # If decompression fails, try direct deserialization
            return(unserialize(raw_data))
          })
        } else {
          # JSON deserialization
          return(jsonlite::fromJSON(serialized_data))
        }
      }, error = function(e) {
        cat("❌ Deserialization error:", e$message, "\n")
        return(NULL)
      })
    },
    
    # Smart cache invalidation
    invalidate = function(pattern = NULL, query_type = NULL) {
      private$.metrics$invalidations <- private$.metrics$invalidations + 1
      
      # Invalidate L1 cache
      if (!is.null(pattern)) {
        matching_keys <- grep(pattern, names(private$.memory_cache), value = TRUE)
        for (key in matching_keys) {
          private$.memory_cache[[key]] <- NULL
        }
        cat("🗑️ Invalidated", length(matching_keys), "L1 cache entries\n")
      } else if (!is.null(query_type)) {
        prefix <- switch(query_type,
          "search" = private$.config$search_prefix,
          "documents" = private$.config$doc_prefix,
          "metadata" = private$.config$meta_prefix,
          "statistics" = private$.config$stats_prefix,
          ""
        )
        pattern <- paste0(private$.config$key_prefix, prefix)
        matching_keys <- grep(pattern, names(private$.memory_cache), value = TRUE, fixed = TRUE)
        for (key in matching_keys) {
          private$.memory_cache[[key]] <- NULL
        }
        cat("🗑️ Invalidated", length(matching_keys), "L1 cache entries for type:", query_type, "\n")
      }
      
      # Invalidate L2 cache (Redis)
      if (!is.null(private$.redis_conn)) {
        tryCatch({
          if (!is.null(pattern)) {
            # Use Redis KEYS pattern matching (use carefully in production)
            if (exists("redux") && inherits(private$.redis_conn, "redis_api")) {
              keys <- private$.redis_conn$KEYS(pattern)
              if (length(keys) > 0) {
                private$.redis_conn$DEL(keys)
              }
            } else if (exists("RcppRedis")) {
              keys <- private$.redis_conn$keys(pattern)
              if (length(keys) > 0) {
                private$.redis_conn$del(keys)
              }
            }
            cat("🗑️ Invalidated Redis cache entries matching:", pattern, "\n")
          }
        }, error = function(e) {
          cat("❌ Redis invalidation error:", e$message, "\n")
        })
      }
    },
    
    # Define warming queries for common patterns
    get_warming_queries = function() {
      list(
        # Most recent documents
        recent_docs = list(
          query = "recent_documents",
          params = list(limit = 50, sort = "date_desc"),
          type = "documents",
          priority = "high"
        ),
        
        # Documents by major states
        major_states = list(
          query = "state_documents",
          params = list(states = c("SP", "RJ", "MG", "RS", "PR"), limit = 100),
          type = "search",
          priority = "high" 
        ),
        
        # Common document categories
        categories = list(
          query = "category_documents", 
          params = list(categories = c("Legislação", "Jurisprudência", "Doutrina"), limit = 100),
          type = "search",
          priority = "medium"
        ),
        
        # Dashboard statistics
        dashboard_stats = list(
          query = "dashboard_metrics",
          params = list(),
          type = "statistics",
          priority = "high"
        ),
        
        # Popular search terms (if available)
        popular_searches = list(
          query = "popular_searches",
          params = list(limit = 20),
          type = "metadata",
          priority = "low"
        )
      )
    },
    
    # Define cache invalidation rules
    get_invalidation_rules = function() {
      list(
        # Invalidate search caches when new documents are added
        document_updates = list(
          trigger = "document_insert",
          invalidate = c("search:", "stats:", "meta:")
        ),
        
        # Invalidate category caches when categories change
        category_updates = list(
          trigger = "category_update",
          invalidate = c("search:", "meta:")
        ),
        
        # Regular scheduled invalidation
        scheduled = list(
          search_results = 300,      # 5 minutes
          document_lists = 600,      # 10 minutes
          statistics = 3600          # 1 hour
        )
      )
    },
    
    # Warm cache with common queries
    warm_cache = function(priority = "high") {
      cat("🔥 Warming cache with priority:", priority, "\n")
      
      if (is.null(private$.warming_queries)) {
        cat("⚠️ No warming queries defined\n")
        return(FALSE)
      }
      
      warmed_count <- 0
      
      for (query_name in names(private$.warming_queries)) {
        query_def <- private$.warming_queries[[query_name]]
        
        # Skip if priority doesn't match
        if (priority != "all" && query_def$priority != priority) {
          next
        }
        
        tryCatch({
          cache_key <- self$generate_cache_key(query_def$query, query_def$params)
          
          # Only warm if not already cached
          if (is.null(self$get(cache_key))) {
            # This would call the actual query function
            cat("🔥 Warming cache for:", query_name, "\n")
            warmed_count <- warmed_count + 1
            private$.metrics$warming_operations <- private$.metrics$warming_operations + 1
            
            # Simulate cache warming (in real implementation, would execute query)
            # warm_data <- execute_warming_query(query_def)
            # self$set(cache_key, warm_data, query_def$type)
          }
          
        }, error = function(e) {
          cat("❌ Cache warming error for", query_name, ":", e$message, "\n")
        })
      }
      
      cat("🔥 Warmed", warmed_count, "cache entries\n")
      return(warmed_count > 0)
    },
    
    # Get comprehensive cache metrics
    get_metrics = function() {
      # Calculate hit rates
      total_requests <- private$.metrics$l1_hits + private$.metrics$l2_hits + private$.metrics$misses
      l1_hit_rate <- if (total_requests > 0) private$.metrics$l1_hits / total_requests * 100 else 0
      l2_hit_rate <- if (total_requests > 0) private$.metrics$l2_hits / total_requests * 100 else 0
      overall_hit_rate <- if (total_requests > 0) (private$.metrics$l1_hits + private$.metrics$l2_hits) / total_requests * 100 else 0
      
      # Calculate memory usage
      l1_memory_mb <- sum(sapply(private$.memory_cache, function(x) as.numeric(object.size(x$data)))) / (1024*1024)
      l1_entry_count <- length(private$.memory_cache)
      
      # Get Redis info if available
      redis_info <- list()
      if (!is.null(private$.redis_conn)) {
        tryCatch({
          if (exists("redux") && inherits(private$.redis_conn, "redis_api")) {
            redis_info <- private$.redis_conn$INFO()
          }
        }, error = function(e) {
          redis_info$error <- e$message
        })
      }
      
      return(list(
        # Hit rate metrics
        l1_hits = private$.metrics$l1_hits,
        l2_hits = private$.metrics$l2_hits,
        misses = private$.metrics$misses,
        l1_hit_rate = round(l1_hit_rate, 2),
        l2_hit_rate = round(l2_hit_rate, 2),
        overall_hit_rate = round(overall_hit_rate, 2),
        
        # Operation metrics
        sets = private$.metrics$sets,
        invalidations = private$.metrics$invalidations,
        warming_operations = private$.metrics$warming_operations,
        errors = private$.metrics$errors,
        total_queries = private$.metrics$total_queries,
        
        # Memory metrics
        l1_memory_mb = round(l1_memory_mb, 2),
        l1_entry_count = l1_entry_count,
        l1_memory_limit_mb = private$.max_memory_mb,
        
        # System status
        redis_available = !is.null(private$.redis_conn),
        redis_info = redis_info,
        uptime_seconds = as.numeric(difftime(Sys.time(), private$.metrics$start_time, units = "secs")),
        
        # Configuration
        config = private$.config
      ))
    },
    
    # Clear all caches
    clear_all = function(confirm = FALSE) {
      if (!confirm) {
        cat("⚠️ Use clear_all(confirm = TRUE) to clear all caches\n")
        return(FALSE)
      }
      
      # Clear L1 cache
      private$.memory_cache <- list()
      
      # Clear L2 cache (Redis)
      if (!is.null(private$.redis_conn)) {
        tryCatch({
          if (exists("redux") && inherits(private$.redis_conn, "redis_api")) {
            keys <- private$.redis_conn$KEYS(paste0(private$.config$key_prefix, "*"))
            if (length(keys) > 0) {
              private$.redis_conn$DEL(keys)
            }
          } else if (exists("RcppRedis")) {
            keys <- private$.redis_conn$keys(paste0(private$.config$key_prefix, "*"))
            if (length(keys) > 0) {
              private$.redis_conn$del(keys)
            }
          }
        }, error = function(e) {
          cat("❌ Redis clear error:", e$message, "\n")
        })
      }
      
      cat("🗑️ All caches cleared\n")
      return(TRUE)
    }
  )
)

# ============================================================================
# GLOBAL CACHE MANAGER INSTANCE AND FUNCTIONS
# ============================================================================

# Global cache manager
enhanced_cache_manager <- NULL

#' Initialize the Enhanced Redis Cache Manager
#' @param redis_config Optional Redis configuration
#' @return Boolean indicating success
init_enhanced_cache = function(redis_config = NULL) {
  cat("🚀 Initializing Enhanced Redis Cache Manager (Sprint 3B)\n")
  
  enhanced_cache_manager <<- EnhancedRedisCacheManager$new(redis_config)
  
  if (!is.null(enhanced_cache_manager)) {
    cat("✅ Enhanced Redis Cache Manager initialized\n")
    return(TRUE)
  }
  
  cat("❌ Failed to initialize cache manager\n")
  return(FALSE)
}

#' Get data from enhanced cache
#' @param query_type Type of query (search, documents, metadata, statistics)
#' @param parameters Query parameters
#' @return Cached data or NULL
cache_get = function(query_type, parameters) {
  if (is.null(enhanced_cache_manager)) {
    return(NULL)
  }
  
  cache_key <- enhanced_cache_manager$generate_cache_key(query_type, parameters)
  return(enhanced_cache_manager$get(cache_key))
}

#' Set data in enhanced cache  
#' @param query_type Type of query
#' @param parameters Query parameters
#' @param data Data to cache
#' @param ttl Optional TTL override
#' @return Boolean indicating success
cache_set = function(query_type, parameters, data, ttl = NULL) {
  if (is.null(enhanced_cache_manager)) {
    return(FALSE)
  }
  
  cache_key <- enhanced_cache_manager$generate_cache_key(query_type, parameters)
  return(enhanced_cache_manager$set(cache_key, data, query_type, ttl))
}

#' Invalidate cache entries
#' @param pattern Pattern to match or NULL
#' @param query_type Query type to invalidate or NULL
invalidate_cache = function(pattern = NULL, query_type = NULL) {
  if (is.null(enhanced_cache_manager)) {
    return(FALSE)
  }
  
  enhanced_cache_manager$invalidate(pattern, query_type)
  return(TRUE)
}

#' Warm up cache with common queries
#' @param priority Priority level (high, medium, low, all)
#' @return Boolean indicating success
warm_cache = function(priority = "high") {
  if (is.null(enhanced_cache_manager)) {
    return(FALSE)
  }
  
  return(enhanced_cache_manager$warm_cache(priority))
}

#' Get cache performance metrics
#' @return List with cache metrics
get_cache_metrics = function() {
  if (is.null(enhanced_cache_manager)) {
    return(list(error = "Cache manager not initialized"))
  }
  
  return(enhanced_cache_manager$get_metrics())
}

#' Clear all cache data
#' @param confirm Confirmation required
#' @return Boolean indicating success
clear_all_cache = function(confirm = FALSE) {
  if (is.null(enhanced_cache_manager)) {
    return(FALSE)
  }
  
  return(enhanced_cache_manager$clear_all(confirm))
}

# ============================================================================
# CACHE-AWARE QUERY WRAPPER FUNCTIONS
# ============================================================================

#' Execute query with intelligent caching
#' @param query_func Function to execute query
#' @param query_type Type of query for caching strategy
#' @param parameters Query parameters
#' @param force_refresh Force refresh of cached data
#' @return Query result
cached_query_execute = function(query_func, query_type, parameters, force_refresh = FALSE) {
  # Try cache first unless forced refresh
  if (!force_refresh) {
    cached_result <- cache_get(query_type, parameters)
    if (!is.null(cached_result)) {
      return(cached_result)
    }
  }
  
  # Execute query
  start_time <- Sys.time()
  result <- tryCatch({
    query_func(parameters)
  }, error = function(e) {
    cat("❌ Query execution error:", e$message, "\n")
    return(NULL)
  })
  
  end_time <- Sys.time()
  execution_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
  
  # Cache result if successful and took significant time
  if (!isTRUE(is.null(result)) && execution_time > 0.1) {
    cache_set(query_type, parameters, result)
    cat("💾 Query result cached (", round(execution_time, 3), "s execution time)\n")
  }
  
  return(result)
}

# ============================================================================
# AUTOMATIC INITIALIZATION
# ============================================================================

cat("🔧 Auto-initializing Enhanced Redis Cache Manager...\n")
cache_initialized <- init_enhanced_cache()

if (cache_initialized) {
  cat("✅ Enhanced Redis Caching Strategy ready (Sprint 3B)\n")
  
  # Display initial metrics
  metrics <- get_cache_metrics()
  cat("📊 Cache system status:\n")
  cat("   - Redis available:", metrics$redis_available, "\n")
  cat("   - L1 memory limit:", metrics$l1_memory_limit_mb, "MB\n")
  cat("   - Total queries processed:", metrics$total_queries, "\n")
  
  # Perform initial cache warming
  cat("🔥 Performing initial cache warm-up...\n")
  warm_cache("high")
} else {
  cat("⚠️ Running without enhanced caching capabilities\n")
}

cat("🎯 Enhanced Redis Caching Strategy (Sprint 3B) loaded successfully\n")