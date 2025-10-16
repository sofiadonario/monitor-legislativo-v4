# ============================================================================
# HTTP CACHE MIDDLEWARE
# ============================================================================
# Wraps API handlers with intelligent HTTP caching (ETag, Redis)
# Implements RFC 7232 conditional requests

source("api/lib/redis.R")
source("api/lib/cache.R")

# HTTP cache middleware wrapper
with_http_cache <- function(handler, ttl = 120, vary_headers = c("Authorization")) {
  function(req, res, ...) {
    # Only cache GET requests
    if (toupper(req$REQUEST_METHOD) != "GET") {
      return(handler(req, res, ...))
    }

    # Extract request parameters
    params <- as.list(req$args)
    path <- req$PATH_INFO

    # Extract vary headers for cache key
    vary <- setNames(
      as.list(req$HEADERS[vary_headers]),
      vary_headers
    )

    # Get database connection
    con <- tryCatch(
      get("con_pg", envir = .GlobalEnv),
      error = function(e) {
        # Fallback: try to get from parent environment
        tryCatch(
          get("con_pg", envir = parent.frame(2)),
          error = function(e2) NULL
        )
      }
    )

    if (is.null(con)) {
      warning("No database connection available for cache timestamp")
      # Proceed without caching
      return(handler(req, res, ...))
    }

    # Get last ingestion timestamp for cache invalidation
    last_ts <- get_last_ingest_ts(con)

    # Build ETag and cache key
    etag <- build_etag(path, c(params, vary), last_ts)
    key <- build_cache_key(path, c(params, vary), last_ts)

    # Check If-None-Match header (ETag validation)
    inm <- req$HEADERS[["if-none-match"]]
    if (!is.null(inm) && identical(inm, etag)) {
      # ETag matches - return 304 Not Modified
      res$status <- 304
      res$setHeader("ETag", etag)
      res$setHeader("Cache-Control", sprintf("public, max-age=%d", ttl))
      res$setHeader("Vary", paste(vary_headers, collapse = ", "))

      cache_stats$hit()

      return(list())
    }

    # Try to get from Redis cache
    cached <- redis_get(key)

    if (!is.null(cached)) {
      # Cache hit!
      cache_stats$hit()

      # Parse cached JSON
      result <- tryCatch(
        fromJSON(cached, simplifyVector = FALSE),
        error = function(e) {
          warning(sprintf("Failed to parse cached response: %s", e$message))
          cache_stats$error()
          NULL
        }
      )

      if (!is.null(result)) {
        # Set cache headers
        res$setHeader("ETag", etag)
        res$setHeader("Cache-Control", sprintf("public, max-age=%d", ttl))
        res$setHeader("Vary", paste(vary_headers, collapse = ", "))
        res$setHeader("X-Cache", "HIT")

        return(result)
      }
    }

    # Cache miss - execute handler
    cache_stats$miss()

    out <- handler(req, res, ...)

    # Get response status
    status <- res$status
    if (is.null(status)) status <- 200

    # Cache successful responses
    if (status >= 200 && status < 300) {
      payload <- tryCatch(
        toJSON(out, auto_unbox = TRUE, null = "null", digits = 9),
        error = function(e) {
          warning(sprintf("Failed to serialize response for caching: %s", e$message))
          cache_stats$error()
          NULL
        }
      )

      if (!is.null(payload)) {
        # Store in Redis with TTL
        redis_set(key, payload, ttl)
      }

      # Set cache headers
      res$setHeader("ETag", etag)
      res$setHeader("Cache-Control", sprintf("public, max-age=%d", ttl))
      res$setHeader("Vary", paste(vary_headers, collapse = ", "))
      res$setHeader("X-Cache", "MISS")
    }

    out
  }
}

# Cache middleware with automatic TTL based on path
with_smart_cache <- function(handler, vary_headers = c("Authorization")) {
  function(req, res, ...) {
    path <- req$PATH_INFO

    # Determine TTL based on path
    ttl <- get_cache_ttl(path)

    # Use standard cache middleware
    with_http_cache(handler, ttl, vary_headers)(req, res, ...)
  }
}

# No-cache middleware for sensitive endpoints
with_no_cache <- function(handler) {
  function(req, res, ...) {
    out <- handler(req, res, ...)

    # Set no-cache headers
    res$setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private")
    res$setHeader("Pragma", "no-cache")
    res$setHeader("Expires", "0")

    out
  }
}

# Cache warming endpoint
cache_warm_handler <- function(req, res) {
  con <- get("con_pg", envir = .GlobalEnv)

  if (is.null(con)) {
    res$status <- 500
    return(list(
      error = "internal_error",
      message = "Database connection not available"
    ))
  }

  tryCatch(
    {
      warm_cache(con)

      list(
        status = "success",
        message = "Cache warmed successfully"
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "internal_error",
        message = sprintf("Cache warming failed: %s", e$message)
      )
    }
  )
}

# Cache stats endpoint
cache_stats_handler <- function(req, res) {
  app_stats <- cache_stats$get()
  redis_info <- redis_stats()

  list(
    application = app_stats,
    redis = redis_info,
    timestamp = Sys.time()
  )
}

# Cache clear endpoint
cache_clear_handler <- function(req, res, pattern = "*") {
  # Validate pattern
  if (is.null(pattern) || pattern == "") {
    pattern <- "*"
  }

  # Clear cache
  deleted <- redis_clear_pattern(pattern)

  # Reset app cache stats
  cache_stats$reset()

  # Reset ingest timestamp cache
  reset_ingest_cache()

  list(
    status = "success",
    deleted_keys = deleted,
    pattern = pattern,
    message = sprintf("Cleared %d cache entries matching pattern '%s'", deleted, pattern)
  )
}
