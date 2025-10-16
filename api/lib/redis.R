# ============================================================================
# REDIS CONNECTION MANAGER
# ============================================================================
# Singleton Redis connection for caching
# Falls back gracefully if Redis is unavailable

# Check if redux is available
redis_available <- function() {
  requireNamespace("redux", quietly = TRUE)
}

# Singleton Redis connection
redis_conn <- local({
  .conn <- NULL

  function() {
    # Return existing connection if available
    if (!is.null(.conn)) return(.conn)

    # Check if redux package is installed
    if (!redis_available()) {
      warning("redis: redux package not available, caching disabled")
      return(NULL)
    }

    # Get Redis configuration from environment
    host <- Sys.getenv("REDIS_HOST", "127.0.0.1")
    port <- as.integer(Sys.getenv("REDIS_PORT", "6379"))
    password <- Sys.getenv("REDIS_PASSWORD", "")
    db <- as.integer(Sys.getenv("REDIS_DB", "0"))

    # Build Redis URL
    redis_url <- Sys.getenv("REDIS_URL", "")
    if (redis_url == "") {
      redis_url <- sprintf("redis://%s:%d/%d", host, port, db)
    }

    # Attempt to connect
    tryCatch(
      {
        library(redux)
        .conn <<- hiredis(
          url = redis_url,
          password = if (nzchar(password)) password else NULL
        )

        # Test connection
        .conn$PING()

        cat(sprintf("✅ Redis connected: %s:%d (db %d)\n", host, port, db))
        .conn
      },
      error = function(e) {
        warning(sprintf("redis: connection failed: %s", e$message))
        .conn <<- NULL
        NULL
      }
    )
  }
})

# Check if Redis is connected
redis_is_connected <- function() {
  conn <- redis_conn()
  if (is.null(conn)) return(FALSE)

  tryCatch(
    {
      conn$PING()
      TRUE
    },
    error = function(e) {
      FALSE
    }
  )
}

# Safe Redis GET with fallback
redis_get <- function(key) {
  conn <- redis_conn()
  if (is.null(conn)) return(NULL)

  tryCatch(
    conn$GET(key),
    error = function(e) {
      warning(sprintf("redis GET failed for key %s: %s", key, e$message))
      NULL
    }
  )
}

# Safe Redis SET with fallback
redis_set <- function(key, value, ttl = NULL) {
  conn <- redis_conn()
  if (is.null(conn)) return(FALSE)

  tryCatch(
    {
      conn$SET(key, value)
      if (!is.null(ttl)) {
        conn$EXPIRE(key, ttl)
      }
      TRUE
    },
    error = function(e) {
      warning(sprintf("redis SET failed for key %s: %s", key, e$message))
      FALSE
    }
  )
}

# Safe Redis DEL
redis_del <- function(key) {
  conn <- redis_conn()
  if (is.null(conn)) return(FALSE)

  tryCatch(
    {
      conn$DEL(key)
      TRUE
    },
    error = function(e) {
      warning(sprintf("redis DEL failed for key %s: %s", key, e$message))
      FALSE
    }
  )
}

# Clear cache by pattern
redis_clear_pattern <- function(pattern = "*") {
  conn <- redis_conn()
  if (is.null(conn)) return(0)

  tryCatch(
    {
      keys <- conn$KEYS(pattern)
      if (length(keys) == 0) return(0)

      deleted <- 0
      for (key in keys) {
        if (redis_del(key)) deleted <- deleted + 1
      }
      deleted
    },
    error = function(e) {
      warning(sprintf("redis CLEAR failed: %s", e$message))
      0
    }
  )
}

# Get Redis stats
redis_stats <- function() {
  conn <- redis_conn()
  if (is.null(conn)) {
    return(list(
      connected = FALSE,
      message = "Redis not available"
    ))
  }

  tryCatch(
    {
      info <- conn$INFO("stats")
      list(
        connected = TRUE,
        total_connections = info$total_connections_received,
        total_commands = info$total_commands_processed,
        keyspace_hits = info$keyspace_hits,
        keyspace_misses = info$keyspace_misses,
        hit_rate = if (info$keyspace_hits + info$keyspace_misses > 0) {
          round(100 * info$keyspace_hits / (info$keyspace_hits + info$keyspace_misses), 2)
        } else {
          0
        }
      )
    },
    error = function(e) {
      list(
        connected = FALSE,
        error = e$message
      )
    }
  )
}
