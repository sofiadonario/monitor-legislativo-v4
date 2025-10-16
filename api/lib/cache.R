# ============================================================================
# CACHE UTILITIES
# ============================================================================
# Cache key generation and timestamp tracking for Legislative Monitor API

library(digest)
library(jsonlite)
library(DBI)

# Get last ingestion timestamp for cache invalidation
get_last_ingest_ts <- local({
  .ts <- NULL
  .loaded <- FALSE

  function(con) {
    # Return cached timestamp if available
    if (.loaded && !is.null(.ts)) return(.ts)

    # Query database for last ingestion time
    query <- "SELECT COALESCE(MAX(ingested_at), NOW()::timestamp) AS ts FROM ingest_control;"

    .ts <<- tryCatch(
      {
        result <- dbGetQuery(con, query)
        if (nrow(result) > 0) {
          result$ts[[1]]
        } else {
          Sys.time()
        }
      },
      error = function(e) {
        warning(sprintf("Failed to get last ingest timestamp: %s", e$message))
        Sys.time()
      }
    )

    .loaded <<- TRUE
    .ts
  }
})

# Reset cached timestamp (call after new data ingestion)
reset_ingest_cache <- function() {
  env <- environment(get_last_ingest_ts)
  env$.loaded <- FALSE
  env$.ts <- NULL
}

# Normalize parameters for consistent cache keys
normalize_params <- function(path, params, extra = list()) {
  # Sort parameters alphabetically for consistency
  if (length(params) > 0) {
    params <- params[order(names(params))]
  }

  # Create normalized representation
  toJSON(
    list(
      path = path,
      params = params,
      extra = extra
    ),
    auto_unbox = TRUE,
    null = "null",
    digits = 9
  )
}

# Build cache key from request parameters
build_cache_key <- function(path, params, last_ts) {
  normalized <- normalize_params(
    path,
    params,
    list(last_ts = as.character(last_ts))
  )

  # Use xxhash64 for fast hashing
  hash <- digest(normalized, algo = "xxhash64")

  paste0("cache:", hash)
}

# Build ETag for HTTP caching
build_etag <- function(path, params, last_ts) {
  normalized <- normalize_params(
    path,
    params,
    list(last_ts = as.character(last_ts))
  )

  # Use SHA1 for ETag (more collision-resistant)
  hash <- digest(normalized, algo = "sha1")

  # Weak ETag format
  paste0('W/"', hash, '"')
}

# Build cache key for user-specific data
build_user_cache_key <- function(path, params, user_id, last_ts) {
  normalized <- normalize_params(
    path,
    params,
    list(
      user_id = user_id,
      last_ts = as.character(last_ts)
    )
  )

  hash <- digest(normalized, algo = "xxhash64")

  paste0("cache:user:", user_id, ":", hash)
}

# Parse cache key to extract metadata (for debugging)
parse_cache_key <- function(key) {
  parts <- strsplit(key, ":")[[1]]

  if (length(parts) < 2) {
    return(list(type = "unknown", hash = key))
  }

  list(
    type = parts[1],
    subtype = if (length(parts) > 2) parts[2] else NULL,
    hash = parts[length(parts)]
  )
}

# Get cache TTL based on data type
get_cache_ttl <- function(path) {
  # Default TTLs for different endpoints
  ttls <- list(
    "/search" = 300, # 5 minutes
    "/document" = 3600, # 1 hour
    "/aggregations" = 600, # 10 minutes
    "/stats" = 300, # 5 minutes
    "/map" = 1800, # 30 minutes
    "/export" = 60 # 1 minute (exports are resource-intensive)
  )

  # Match path to TTL
  for (pattern in names(ttls)) {
    if (grepl(pattern, path, fixed = TRUE)) {
      return(ttls[[pattern]])
    }
  }

  # Default TTL
  120 # 2 minutes
}

# Cache statistics
cache_stats <- local({
  .hits <- 0
  .misses <- 0
  .errors <- 0

  list(
    hit = function() {
      .hits <<- .hits + 1
    },
    miss = function() {
      .misses <<- .misses + 1
    },
    error = function() {
      .errors <<- .errors + 1
    },
    get = function() {
      total <- .hits + .misses
      list(
        hits = .hits,
        misses = .misses,
        errors = .errors,
        total = total,
        hit_rate = if (total > 0) round(100 * .hits / total, 2) else 0
      )
    },
    reset = function() {
      .hits <<- 0
      .misses <<- 0
      .errors <<- 0
    }
  )
})

# Warm cache for common queries
warm_cache <- function(con) {
  cat("Warming cache with common queries...\n")

  # Common search terms for Brazilian legislative context
  common_terms <- c(
    "transporte",
    "mobilidade",
    "saúde",
    "educação",
    "segurança"
  )

  # Common jurisdictions
  jurisdictions <- c("federal", "state", "municipal")

  # Warm cache for each combination
  for (term in common_terms) {
    for (juris in jurisdictions) {
      # This would call your actual search function
      # For now, just create the cache keys
      key <- build_cache_key(
        "/search",
        list(q = term, jurisdiction = juris),
        get_last_ingest_ts(con)
      )

      cat(sprintf("  Cache key created: %s\n", key))
    }
  }

  cat("✅ Cache warming complete\n")
}
