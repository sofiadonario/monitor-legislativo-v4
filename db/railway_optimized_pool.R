# ============================================================================
# RAILWAY-OPTIMIZED CONNECTION POOLING FOR SPRINT 3B
# ============================================================================
# 
# Production-ready connection pooling system optimized for Railway's PostgreSQL
# with 2GB memory constraints and high availability requirements.
#
# Features:
# - Adaptive connection sizing based on memory constraints
# - Connection health monitoring with auto-recovery
# - Graceful degradation under resource pressure
# - Performance metrics and monitoring
# - Circuit breaker pattern for connection failures
# - Connection leak prevention and resource cleanup
# ============================================================================

cat("🚀 Loading Railway-Optimized Connection Pooling System (Sprint 3B)\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
  library(R6)
})

# ============================================================================
# RAILWAY CONNECTION POOL MANAGER CLASS
# ============================================================================

RailwayConnectionPoolManager <- R6Class(
  "RailwayConnectionPoolManager",
  
  private = list(
    .pool = NULL,
    .config = NULL,
    .metrics = NULL,
    .circuit_breaker = NULL,
    .health_check_interval = 30,
    .last_health_check = NULL,
    .connection_failures = 0,
    .max_failures = 5,
    .recovery_time = 60,
    .memory_threshold_mb = 1600  # 80% of 2GB Railway limit
  ),
  
  public = list(
    # Initialize the pool manager
    initialize = function(config = NULL) {
      cat("🔧 Initializing Railway-Optimized Connection Pool Manager\n")
      
      private$.config <- config %||% self$get_railway_config()
      private$.metrics <- list(
        connections_created = 0,
        connections_destroyed = 0,
        active_connections = 0,
        queries_executed = 0,
        total_query_time = 0,
        connection_errors = 0,
        last_error = NULL,
        created_at = Sys.time()
      )
      
      private$.circuit_breaker <- list(
        state = "closed",  # closed, open, half_open
        failures = 0,
        last_failure = NULL,
        next_attempt = NULL
      )
      
      # Initialize the connection pool
      self$create_pool()
    },
    
    # Get Railway database configuration
    get_railway_config = function() {
      # Try environment variables first (Railway standard)
      database_url <- Sys.getenv("DATABASE_URL", unset = NA)
      if (!is.na(database_url)) {
        config <- self$parse_database_url(database_url)
        if (!is.null(config)) {
          cat("✅ Using DATABASE_URL configuration\n")
          return(config)
        }
      }
      
      # Fallback to individual environment variables
      config <- list(
        host = Sys.getenv("PGHOST", "postgres.railway.internal"),
        port = as.integer(Sys.getenv("PGPORT", "5432")),
        dbname = Sys.getenv("PGDATABASE", "railway"),
        user = Sys.getenv("PGUSER", "postgres"),
        password = Sys.getenv("PGPASSWORD", "")
      )
      
      if (config$password == "") {
        cat("❌ Missing database credentials in environment variables\n")
        return(NULL)
      }
      
      cat("✅ Using individual environment variable configuration\n")
      return(config)
    },
    
    # Parse Railway DATABASE_URL
    parse_database_url = function(url) {
      if (is.null(url) || url == "") return(NULL)
      
      tryCatch({
        # Support both postgres:// and postgresql://
        if (!grepl("^postgres(?:ql)?://", url)) return(NULL)
        
        # Remove protocol
        clean_url <- sub("^postgres(?:ql)?://", "", url)
        
        # Parse components
        parts <- regmatches(clean_url, regexec("^([^:]+):([^@]+)@([^:]+):([^/]+)/(.+)$", clean_url))[[1]]
        
        if (length(parts) != 6) return(NULL)
        
        return(list(
          user = parts[2],
          password = parts[3],
          host = parts[4],
          port = as.integer(parts[5]),
          dbname = parts[6]
        ))
      }, error = function(e) {
        cat("⚠️ Error parsing DATABASE_URL:", e$message, "\n")
        return(NULL)
      })
    },
    
    # Create optimized connection pool for Railway
    create_pool = function() {
      if (is.null(private$.config)) {
        cat("❌ No valid database configuration available\n")
        return(FALSE)
      }
      
      # Check circuit breaker
      if (private$.circuit_breaker$state == "open") {
        if (Sys.time() < private$.circuit_breaker$next_attempt) {
          cat("⚡ Circuit breaker OPEN - skipping connection attempt\n")
          return(FALSE)
        } else {
          cat("🔄 Circuit breaker transitioning to HALF_OPEN\n")
          private$.circuit_breaker$state <- "half_open"
        }
      }
      
      tryCatch({
        cat("🔧 Creating Railway-optimized connection pool...\n")
        
        # Calculate optimal pool size based on Railway constraints
        pool_config <- self$calculate_optimal_pool_size()
        
        private$.pool <- dbPool(
          drv = RPostgres::Postgres(),
          host = private$.config$host,
          port = private$.config$port,
          dbname = private$.config$dbname,
          user = private$.config$user,
          password = private$.config$password,
          
          # Railway-optimized pool settings
          minSize = pool_config$min_size,
          maxSize = pool_config$max_size,
          idleTimeout = pool_config$idle_timeout,
          
          # Railway-specific connection settings
          sslmode = "prefer",
          connect_timeout = 30,
          application_name = "monitor_legislativo_sprint3b",
          
          # Performance optimizations
          options = "-c jit=off -c log_statement=none -c synchronous_commit=off",
          
          # Connection validation
          validateQuery = "SELECT 1",
          
          # Resource management
          onDestroy = function() {
            private$.metrics$connections_destroyed <- private$.metrics$connections_destroyed + 1
          },
          
          onValidate = function(conn) {
            tryCatch({
              result <- dbGetQuery(conn, "SELECT 1")
              return(nrow(result) == 1)
            }, error = function(e) {
              private$.connection_failures <- private$.connection_failures + 1
              return(FALSE)
            })
          }
        )
        
        # Test the pool
        test_result <- self$test_pool_connectivity()
        if (test_result) {
          private$.circuit_breaker$state <- "closed"
          private$.circuit_breaker$failures <- 0
          private$.metrics$connections_created <- private$.metrics$connections_created + 1
          
          cat("✅ Railway connection pool created successfully\n")
          cat("📊 Pool config: min=", pool_config$min_size, ", max=", pool_config$max_size, 
              ", idle_timeout=", pool_config$idle_timeout/1000, "s\n")
          return(TRUE)
        } else {
          self$handle_connection_failure("Pool connectivity test failed")
          return(FALSE)
        }
        
      }, error = function(e) {
        self$handle_connection_failure(paste("Pool creation error:", e$message))
        return(FALSE)
      })
    },
    
    # Calculate optimal pool size based on Railway constraints
    calculate_optimal_pool_size = function() {
      # Monitor current memory usage
      gc_info <- gc(verbose = FALSE)
      memory_used_mb <- sum(gc_info[, 2]) * 8 / 1024  # Convert to MB (approximate)
      
      # Calculate available memory for connections
      available_memory_mb <- private$.memory_threshold_mb - memory_used_mb
      
      # Estimate memory per connection (based on PostgreSQL overhead + R objects)
      memory_per_connection_mb <- 50  # Conservative estimate
      
      # Calculate safe connection limits
      max_connections_by_memory <- max(1, floor(available_memory_mb / memory_per_connection_mb))
      
      # Railway-specific limits (conservative for 2GB environment)
      max_connections_railway <- 8
      
      # Choose the most restrictive limit
      max_size <- min(max_connections_by_memory, max_connections_railway, 6)
      min_size <- max(1, min(2, max_size))
      
      # Adaptive idle timeout based on memory pressure
      idle_timeout <- if (memory_used_mb > 1200) {
        180000  # 3 minutes under memory pressure
      } else if (memory_used_mb > 800) {
        300000  # 5 minutes normal operation
      } else {
        600000  # 10 minutes with plenty of memory
      }
      
      cat("💾 Memory analysis: used=", round(memory_used_mb), "MB, available=", 
          round(available_memory_mb), "MB\n")
      cat("🔧 Calculated pool limits: min=", min_size, ", max=", max_size, "\n")
      
      return(list(
        min_size = min_size,
        max_size = max_size,
        idle_timeout = idle_timeout
      ))
    },
    
    # Test pool connectivity
    test_pool_connectivity = function() {
      if (is.null(private$.pool)) return(FALSE)
      
      tryCatch({
        conn <- poolCheckout(private$.pool)
        
        # Test basic connectivity
        result <- dbGetQuery(conn, "SELECT version() as version, current_database() as db")
        
        # Test document table access
        doc_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM information_schema.tables 
                                       WHERE table_name IN ('documents', 'brazilian_legislative_complete', 'lexml_parsed_enhanced')")
        
        poolReturn(conn)
        
        if (nrow(result) == 1 && nrow(doc_count) == 1) {
          cat("✅ Pool connectivity test passed\n")
          cat("📊 PostgreSQL version: ", substr(result$version, 1, 50), "\n")
          cat("📊 Database: ", result$db, "\n")
          cat("📊 Available document tables: ", doc_count$count, "\n")
          return(TRUE)
        }
        
        return(FALSE)
        
      }, error = function(e) {
        cat("❌ Pool connectivity test failed:", e$message, "\n")
        return(FALSE)
      })
    },
    
    # Handle connection failures with circuit breaker
    handle_connection_failure = function(error_msg) {
      private$.connection_failures <- private$.connection_failures + 1
      private$.metrics$connection_errors <- private$.metrics$connection_errors + 1
      private$.metrics$last_error <- error_msg
      private$.circuit_breaker$failures <- private$.circuit_breaker$failures + 1
      private$.circuit_breaker$last_failure <- Sys.time()
      
      cat("❌ Connection failure #", private$.connection_failures, ":", error_msg, "\n")
      
      # Trip circuit breaker if too many failures
      if (private$.circuit_breaker$failures >= private$.max_failures) {
        private$.circuit_breaker$state <- "open"
        private$.circuit_breaker$next_attempt <- Sys.time() + private$.recovery_time
        
        cat("⚡ Circuit breaker OPENED - will retry in", private$.recovery_time, "seconds\n")
        
        # Close existing pool to free resources
        self$close_pool()
      }
    },
    
    # Get a database connection with health check
    get_connection = function() {
      # Perform periodic health checks
      if (is.null(private$.last_health_check) || 
          difftime(Sys.time(), private$.last_health_check, units = "secs") > private$.health_check_interval) {
        self$perform_health_check()
      }
      
      if (is.null(private$.pool)) {
        cat("⚠️ No active pool available, attempting reconnection...\n")
        if (!self$create_pool()) {
          return(NULL)
        }
      }
      
      tryCatch({
        conn <- poolCheckout(private$.pool)
        private$.metrics$active_connections <- private$.metrics$active_connections + 1
        return(conn)
      }, error = function(e) {
        self$handle_connection_failure(paste("Connection checkout error:", e$message))
        return(NULL)
      })
    },
    
    # Return a database connection
    return_connection = function(conn) {
      if (!is.null(conn)) {
        tryCatch({
          poolReturn(conn)
          private$.metrics$active_connections <- max(0, private$.metrics$active_connections - 1)
        }, error = function(e) {
          cat("⚠️ Error returning connection:", e$message, "\n")
        })
      }
    },
    
    # Execute query with performance monitoring
    execute_query = function(query, params = NULL) {
      start_time <- Sys.time()
      conn <- self$get_connection()
      
      if (is.null(conn)) {
        cat("❌ No database connection available for query\n")
        return(NULL)
      }
      
      tryCatch({
        # Execute query
        if (is.null(params)) {
          result <- dbGetQuery(conn, query)
        } else {
          result <- dbGetQuery(conn, query, params = params)
        }
        
        # Update metrics
        end_time <- Sys.time()
        query_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
        private$.metrics$queries_executed <- private$.metrics$queries_executed + 1
        private$.metrics$total_query_time <- private$.metrics$total_query_time + query_time
        
        if (query_time > 2) {
          cat("🐌 Slow query detected (", round(query_time, 2), "s):", 
              substr(gsub("\\s+", " ", query), 1, 80), "...\n")
        }
        
        self$return_connection(conn)
        return(result)
        
      }, error = function(e) {
        self$return_connection(conn)
        self$handle_connection_failure(paste("Query execution error:", e$message))
        return(NULL)
      })
    },
    
    # Perform health check
    perform_health_check = function() {
      private$.last_health_check <- Sys.time()
      
      if (is.null(private$.pool)) {
        cat("💔 Health check: No active pool\n")
        return(FALSE)
      }
      
      tryCatch({
        # Quick connectivity test
        result <- self$execute_query("SELECT 1 as health_check, pg_backend_pid() as pid")
        
        if (!is.null(result) && nrow(result) == 1) {
          cat("💚 Health check passed (PID: ", result$pid, ")\n")
          
          # Check for connection leaks
          pool_info <- pool::poolStatus(private$.pool)
          if (!is.null(pool_info) && pool_info$activeConnections > pool_info$totalConnections * 0.8) {
            cat("⚠️ High connection usage detected - potential leak\n")
          }
          
          return(TRUE)
        } else {
          cat("💛 Health check failed - recreating pool\n")
          self$create_pool()
          return(FALSE)
        }
        
      }, error = function(e) {
        cat("💔 Health check error:", e$message, "\n")
        return(FALSE)
      })
    },
    
    # Get pool metrics
    get_metrics = function() {
      pool_status <- NULL
      if (!is.null(private$.pool)) {
        pool_status <- tryCatch({
          pool::poolStatus(private$.pool)
        }, error = function(e) NULL)
      }
      
      avg_query_time <- 0
      if (private$.metrics$queries_executed > 0) {
        avg_query_time <- private$.metrics$total_query_time / private$.metrics$queries_executed
      }
      
      return(list(
        # Connection metrics
        connections_created = private$.metrics$connections_created,
        connections_destroyed = private$.metrics$connections_destroyed,
        active_connections = private$.metrics$active_connections,
        connection_errors = private$.metrics$connection_errors,
        connection_failures = private$.connection_failures,
        
        # Query metrics
        queries_executed = private$.metrics$queries_executed,
        total_query_time = round(private$.metrics$total_query_time, 2),
        avg_query_time = round(avg_query_time, 3),
        
        # Pool status
        pool_active = !is.null(private$.pool),
        pool_status = pool_status,
        circuit_breaker_state = private$.circuit_breaker$state,
        
        # System metrics
        last_health_check = private$.last_health_check,
        last_error = private$.metrics$last_error,
        uptime_seconds = as.numeric(difftime(Sys.time(), private$.metrics$created_at, units = "secs"))
      ))
    },
    
    # Close pool and cleanup resources
    close_pool = function() {
      if (!is.null(private$.pool)) {
        tryCatch({
          poolClose(private$.pool)
          private$.pool <- NULL
          cat("🔒 Connection pool closed successfully\n")
        }, error = function(e) {
          cat("⚠️ Error closing pool:", e$message, "\n")
        })
      }
    },
    
    # Destructor
    finalize = function() {
      self$close_pool()
    }
  )
)

# ============================================================================
# GLOBAL POOL MANAGER INSTANCE
# ============================================================================

# Create global pool manager instance
railway_pool_manager <- NULL

#' Initialize Railway connection pool manager
#' @param config Optional database configuration
#' @return Boolean indicating success
init_railway_pool <- function(config = NULL) {
  cat("🚀 Initializing Railway Connection Pool Manager (Sprint 3B)\n")
  
  railway_pool_manager <<- RailwayConnectionPoolManager$new(config)
  
  if (!is.null(railway_pool_manager)) {
    metrics <- railway_pool_manager$get_metrics()
    if (metrics$pool_active) {
      cat("✅ Railway connection pool initialized successfully\n")
      return(TRUE)
    }
  }
  
  cat("❌ Failed to initialize Railway connection pool\n")
  return(FALSE)
}

#' Get connection from Railway pool
#' @return Database connection or NULL
get_railway_connection <- function() {
  if (is.null(railway_pool_manager)) {
    cat("⚠️ Railway pool manager not initialized\n")
    return(NULL)
  }
  
  return(railway_pool_manager$get_connection())
}

#' Return connection to Railway pool
#' @param conn Database connection
return_railway_connection <- function(conn) {
  if (!is.null(railway_pool_manager)) {
    railway_pool_manager$return_connection(conn)
  }
}

#' Execute query using Railway pool
#' @param query SQL query
#' @param params Optional query parameters
#' @return Query result or NULL
execute_railway_query <- function(query, params = NULL) {
  if (is.null(railway_pool_manager)) {
    cat("⚠️ Railway pool manager not initialized\n")
    return(NULL)
  }
  
  return(railway_pool_manager$execute_query(query, params))
}

#' Get Railway pool metrics
#' @return List with pool metrics
get_railway_pool_metrics <- function() {
  if (is.null(railway_pool_manager)) {
    return(list(error = "Pool manager not initialized"))
  }
  
  return(railway_pool_manager$get_metrics())
}

#' Close Railway connection pool
close_railway_pool <- function() {
  if (!is.null(railway_pool_manager)) {
    railway_pool_manager$close_pool()
    railway_pool_manager <<- NULL
    cat("🔒 Railway connection pool closed\n")
  }
}

# ============================================================================
# AUTOMATIC INITIALIZATION
# ============================================================================

# Auto-initialize the pool manager
cat("🔧 Auto-initializing Railway connection pool...\n")
pool_initialized <- init_railway_pool()

if (pool_initialized) {
  cat("✅ Railway-Optimized Connection Pooling System ready (Sprint 3B)\n")
  
  # Display initial metrics
  metrics <- get_railway_pool_metrics()
  cat("📊 Initial pool status:\n")
  cat("   - Pool active:", metrics$pool_active, "\n")
  cat("   - Circuit breaker:", metrics$circuit_breaker_state, "\n")
  cat("   - Connection errors:", metrics$connection_errors, "\n")
} else {
  cat("⚠️ Running without optimized connection pooling\n")
}

# Set up cleanup on exit
reg.finalizer(globalenv(), function(e) {
  close_railway_pool()
}, onexit = TRUE)

cat("🎯 Railway Connection Pooling System (Sprint 3B) loaded successfully\n")