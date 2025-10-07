# auth_state_manager.R - Externalized Authentication State Management
# ============================================================================
# Purpose: Manage API keys and rate limiting state externally for scalability
# Created: 2025
# ============================================================================

library(R6)
library(DBI)
library(jsonlite)

#' AuthStateManager - External authentication state management
#'
#' @field backend Storage backend type: "database", "redis", "file"
#' @field connection Backend connection object
AuthStateManager <- R6::R6Class("AuthStateManager",
  public = list(
    backend = NULL,
    connection = NULL,

    #' Initialize AuthStateManager
    #'
    #' @param backend Storage backend type
    #' @param connection Backend connection object
    initialize = function(backend = "file", connection = NULL) {
      self$backend <- backend
      self$connection <- connection
      private$init_backend()
    },

    #' Get API key details
    #'
    #' @param api_key The API key to lookup
    #' @return API key details or NULL if not found
    get_api_key = function(api_key) {
      switch(self$backend,
        "database" = private$get_key_from_db(api_key),
        "redis" = private$get_key_from_redis(api_key),
        "file" = private$get_key_from_file(api_key),
        NULL
      )
    },

    #' Store or update API key
    #'
    #' @param api_key The API key
    #' @param details API key details
    store_api_key = function(api_key, details) {
      switch(self$backend,
        "database" = private$store_key_in_db(api_key, details),
        "redis" = private$store_key_in_redis(api_key, details),
        "file" = private$store_key_in_file(api_key, details),
        FALSE
      )
    },

    #' Check rate limit for API key
    #'
    #' @param api_key The API key
    #' @param limit_per_minute Rate limit per minute
    #' @return TRUE if within limit, FALSE if exceeded
    check_rate_limit = function(api_key, limit_per_minute = 100) {
      switch(self$backend,
        "database" = private$check_rate_limit_db(api_key, limit_per_minute),
        "redis" = private$check_rate_limit_redis(api_key, limit_per_minute),
        "file" = private$check_rate_limit_file(api_key, limit_per_minute),
        TRUE
      )
    },

    #' Increment API key usage
    #'
    #' @param api_key The API key
    increment_usage = function(api_key) {
      switch(self$backend,
        "database" = private$increment_usage_db(api_key),
        "redis" = private$increment_usage_redis(api_key),
        "file" = private$increment_usage_file(api_key),
        FALSE
      )
    },

    #' Get daily quota status
    #'
    #' @param api_key The API key
    #' @return List with used and remaining quota
    get_quota_status = function(api_key) {
      switch(self$backend,
        "database" = private$get_quota_db(api_key),
        "redis" = private$get_quota_redis(api_key),
        "file" = private$get_quota_file(api_key),
        list(used = 0, remaining = 0, quota = 0)
      )
    },

    #' Reset daily quotas (call via scheduled job)
    reset_daily_quotas = function() {
      switch(self$backend,
        "database" = private$reset_quotas_db(),
        "redis" = private$reset_quotas_redis(),
        "file" = private$reset_quotas_file(),
        FALSE
      )
    }
  ),

  private = list(
    state_file = "auth_state.json",
    rate_limits = list(),
    quotas = list(),

    #' Initialize backend
    init_backend = function() {
      if (self$backend == "database" && !is.null(self$connection)) {
        private$init_db_tables()
      } else if (self$backend == "file") {
        private$init_file_backend()
      }
    },

    #' Initialize database tables
    init_db_tables = function() {
      tryCatch({
        # Create API keys table if not exists
        DBI::dbExecute(self$connection, "
          CREATE TABLE IF NOT EXISTS api_keys (
            api_key VARCHAR(255) PRIMARY KEY,
            name VARCHAR(255),
            tier VARCHAR(50),
            rate_limit_per_minute INT,
            quota_per_day INT,
            permissions TEXT,
            created_at TIMESTAMP,
            last_used TIMESTAMP,
            usage_count INT DEFAULT 0,
            daily_usage INT DEFAULT 0,
            last_reset DATE
          )
        ")

        # Create rate limit tracking table
        DBI::dbExecute(self$connection, "
          CREATE TABLE IF NOT EXISTS rate_limits (
            api_key VARCHAR(255),
            timestamp TIMESTAMP,
            PRIMARY KEY (api_key, timestamp)
          )
        ")

        # Create index for performance
        DBI::dbExecute(self$connection, "
          CREATE INDEX IF NOT EXISTS idx_rate_limits_key_time
          ON rate_limits(api_key, timestamp)
        ")
      }, error = function(e) {
        warning(paste("Failed to initialize database tables:", e$message))
      })
    },

    #' Initialize file backend
    init_file_backend = function() {
      if (!file.exists(private$state_file)) {
        initial_state <- list(
          api_keys = list(),
          rate_limits = list(),
          quotas = list(),
          last_reset = Sys.Date()
        )
        write(toJSON(initial_state, pretty = TRUE), private$state_file)
      }
    },

    #' Get API key from database
    get_key_from_db = function(api_key) {
      tryCatch({
        result <- DBI::dbGetQuery(self$connection,
          "SELECT * FROM api_keys WHERE api_key = ?",
          params = list(api_key)
        )

        if (nrow(result) > 0) {
          # Update last_used timestamp
          DBI::dbExecute(self$connection,
            "UPDATE api_keys SET last_used = ? WHERE api_key = ?",
            params = list(Sys.time(), api_key)
          )

          return(as.list(result[1,]))
        }
        NULL
      }, error = function(e) {
        warning(paste("Database query failed:", e$message))
        NULL
      })
    },

    #' Get API key from file
    get_key_from_file = function(api_key) {
      state <- fromJSON(private$state_file)
      if (api_key %in% names(state$api_keys)) {
        key_data <- state$api_keys[[api_key]]
        # Update last_used
        key_data$last_used <- as.character(Sys.time())
        state$api_keys[[api_key]] <- key_data
        write(toJSON(state, pretty = TRUE), private$state_file)
        return(key_data)
      }
      NULL
    },

    #' Store API key in database
    store_key_in_db = function(api_key, details) {
      tryCatch({
        DBI::dbExecute(self$connection, "
          INSERT INTO api_keys (api_key, name, tier, rate_limit_per_minute,
                               quota_per_day, permissions, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT (api_key) DO UPDATE SET
            name = EXCLUDED.name,
            tier = EXCLUDED.tier,
            rate_limit_per_minute = EXCLUDED.rate_limit_per_minute,
            quota_per_day = EXCLUDED.quota_per_day,
            permissions = EXCLUDED.permissions
        ", params = list(
          api_key,
          details$name,
          details$tier,
          details$rate_limit_per_minute,
          details$quota_per_day,
          paste(details$permissions, collapse = ","),
          Sys.time()
        ))
        TRUE
      }, error = function(e) {
        warning(paste("Failed to store API key:", e$message))
        FALSE
      })
    },

    #' Store API key in file
    store_key_in_file = function(api_key, details) {
      state <- fromJSON(private$state_file)
      details$created_at <- as.character(Sys.time())
      state$api_keys[[api_key]] <- details
      write(toJSON(state, pretty = TRUE), private$state_file)
      TRUE
    },

    #' Check rate limit in database
    check_rate_limit_db = function(api_key, limit_per_minute) {
      tryCatch({
        # Count requests in last minute
        one_minute_ago <- Sys.time() - 60

        # Clean old entries
        DBI::dbExecute(self$connection,
          "DELETE FROM rate_limits WHERE timestamp < ?",
          params = list(one_minute_ago)
        )

        # Count recent requests
        result <- DBI::dbGetQuery(self$connection, "
          SELECT COUNT(*) as request_count
          FROM rate_limits
          WHERE api_key = ? AND timestamp >= ?
        ", params = list(api_key, one_minute_ago))

        if (result$request_count[1] < limit_per_minute) {
          # Add new request
          DBI::dbExecute(self$connection,
            "INSERT INTO rate_limits (api_key, timestamp) VALUES (?, ?)",
            params = list(api_key, Sys.time())
          )
          return(TRUE)
        }
        FALSE
      }, error = function(e) {
        warning(paste("Rate limit check failed:", e$message))
        TRUE # Allow on error
      })
    },

    #' Check rate limit in file
    check_rate_limit_file = function(api_key, limit_per_minute) {
      state <- fromJSON(private$state_file)

      # Initialize if needed
      if (!api_key %in% names(state$rate_limits)) {
        state$rate_limits[[api_key]] <- list()
      }

      # Clean old timestamps
      one_minute_ago <- Sys.time() - 60
      timestamps <- as.POSIXct(state$rate_limits[[api_key]])
      timestamps <- timestamps[timestamps >= one_minute_ago]

      if (length(timestamps) < limit_per_minute) {
        # Add new timestamp
        timestamps <- c(timestamps, Sys.time())
        state$rate_limits[[api_key]] <- as.character(timestamps)
        write(toJSON(state, pretty = TRUE), private$state_file)
        return(TRUE)
      }
      FALSE
    },

    #' Increment usage in database
    increment_usage_db = function(api_key) {
      tryCatch({
        DBI::dbExecute(self$connection, "
          UPDATE api_keys
          SET usage_count = usage_count + 1,
              daily_usage = daily_usage + 1
          WHERE api_key = ?
        ", params = list(api_key))
        TRUE
      }, error = function(e) {
        warning(paste("Failed to increment usage:", e$message))
        FALSE
      })
    },

    #' Increment usage in file
    increment_usage_file = function(api_key) {
      state <- fromJSON(private$state_file)
      if (api_key %in% names(state$api_keys)) {
        state$api_keys[[api_key]]$usage_count <-
          as.numeric(state$api_keys[[api_key]]$usage_count) + 1
        state$api_keys[[api_key]]$daily_usage <-
          as.numeric(state$api_keys[[api_key]]$daily_usage) + 1
        write(toJSON(state, pretty = TRUE), private$state_file)
        return(TRUE)
      }
      FALSE
    },

    #' Get quota from database
    get_quota_db = function(api_key) {
      tryCatch({
        result <- DBI::dbGetQuery(self$connection, "
          SELECT daily_usage, quota_per_day
          FROM api_keys
          WHERE api_key = ?
        ", params = list(api_key))

        if (nrow(result) > 0) {
          return(list(
            used = result$daily_usage[1],
            quota = result$quota_per_day[1],
            remaining = max(0, result$quota_per_day[1] - result$daily_usage[1])
          ))
        }
        list(used = 0, quota = 0, remaining = 0)
      }, error = function(e) {
        warning(paste("Failed to get quota:", e$message))
        list(used = 0, quota = 0, remaining = 0)
      })
    },

    #' Get quota from file
    get_quota_file = function(api_key) {
      state <- fromJSON(private$state_file)
      if (api_key %in% names(state$api_keys)) {
        key_data <- state$api_keys[[api_key]]
        used <- as.numeric(key_data$daily_usage %||% 0)
        quota <- as.numeric(key_data$quota_per_day %||% 10000)
        return(list(
          used = used,
          quota = quota,
          remaining = max(0, quota - used)
        ))
      }
      list(used = 0, quota = 0, remaining = 0)
    },

    #' Reset quotas in database
    reset_quotas_db = function() {
      tryCatch({
        DBI::dbExecute(self$connection, "
          UPDATE api_keys
          SET daily_usage = 0,
              last_reset = ?
        ", params = list(Sys.Date()))
        TRUE
      }, error = function(e) {
        warning(paste("Failed to reset quotas:", e$message))
        FALSE
      })
    },

    #' Reset quotas in file
    reset_quotas_file = function() {
      state <- fromJSON(private$state_file)

      # Check if reset needed (once per day)
      last_reset <- as.Date(state$last_reset %||% "1970-01-01")
      if (last_reset < Sys.Date()) {
        # Reset all daily usage counters
        for (key in names(state$api_keys)) {
          state$api_keys[[key]]$daily_usage <- 0
        }
        state$last_reset <- as.character(Sys.Date())
        write(toJSON(state, pretty = TRUE), private$state_file)
        return(TRUE)
      }
      FALSE
    }
  )
)

#' Null coalescing operator
`%||%` <- function(a, b) if (is.null(a)) b else a