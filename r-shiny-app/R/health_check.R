# Health Check Module for Monitor Legislativo v4
# Provides health check endpoint for monitoring and deployment

library(jsonlite)
library(httr)

#' Check database connectivity
#' @return List with database health status
check_database_health <- function() {
  tryCatch({
    # Test database connection
    if (is.null(db_pool)) {
      return(list(
        status = "error",
        message = "Database connection pool not initialized",
        timestamp = Sys.time()
      ))
    }
    
    # Test basic query
    result <- dbGetQuery(db_pool, "SELECT 1 as test")
    if (nrow(result) == 1 && result$test == 1) {
      # Get additional database info
      doc_count <- dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documents")$count
      
      return(list(
        status = "healthy",
        message = "Database connection active",
        document_count = doc_count,
        timestamp = Sys.time()
      ))
    } else {
      return(list(
        status = "error",
        message = "Database query failed",
        timestamp = Sys.time()
      ))
    }
    
  }, error = function(e) {
    return(list(
      status = "error",
      message = paste("Database error:", e$message),
      timestamp = Sys.time()
    ))
  })
}

#' Check cache system health
#' @return List with cache health status
check_cache_health <- function() {
  tryCatch({
    # Test cache operations
    test_key <- "health_check_test"
    test_data <- "cache_test_data"
    
    # Test cache write
    store_cached_result(test_key, test_data, use_file_cache = FALSE)
    
    # Test cache read
    cached_result <- get_cached_result(test_key, use_file_cache = FALSE)
    
    if (cached_result == test_data) {
      cache_stats <- get_cache_stats()
      return(list(
        status = "healthy",
        message = "Cache system operational",
        cache_stats = cache_stats,
        timestamp = Sys.time()
      ))
    } else {
      return(list(
        status = "warning",
        message = "Cache read/write test failed",
        timestamp = Sys.time()
      ))
    }
    
  }, error = function(e) {
    return(list(
      status = "error",
      message = paste("Cache error:", e$message),
      timestamp = Sys.time()
    ))
  })
}

#' Check file system health
#' @return List with file system health status
check_filesystem_health <- function() {
  tryCatch({
    # Check required directories
    required_dirs <- c("data", "data/cache", "exports", "logs", "temp")
    missing_dirs <- c()
    
    for (dir in required_dirs) {
      if (!dir.exists(dir)) {
        missing_dirs <- c(missing_dirs, dir)
      }
    }
    
    # Check disk space (approximate)
    temp_file <- tempfile()
    file.create(temp_file)
    file_info <- file.info(temp_file)
    unlink(temp_file)
    
    if (length(missing_dirs) == 0) {
      return(list(
        status = "healthy",
        message = "File system operational",
        required_directories = "all present",
        timestamp = Sys.time()
      ))
    } else {
      return(list(
        status = "warning",
        message = paste("Missing directories:", paste(missing_dirs, collapse = ", ")),
        missing_directories = missing_dirs,
        timestamp = Sys.time()
      ))
    }
    
  }, error = function(e) {
    return(list(
      status = "error",
      message = paste("File system error:", e$message),
      timestamp = Sys.time()
    ))
  })
}

#' Check memory usage
#' @return List with memory health status
check_memory_health <- function() {
  tryCatch({
    # Get memory usage information
    memory_info <- gc()
    
    # Get current memory usage
    used_memory <- sum(memory_info[, "used"])
    max_memory <- as.numeric(Sys.getenv("R_MAX_MEMORY", "2048"))  # Default 2GB
    
    memory_percent <- (used_memory / (max_memory * 1024)) * 100
    
    status <- if (memory_percent > 90) {
      "critical"
    } else if (memory_percent > 70) {
      "warning"
    } else {
      "healthy"
    }
    
    return(list(
      status = status,
      message = paste("Memory usage:", round(memory_percent, 1), "%"),
      used_memory_mb = round(used_memory / 1024, 1),
      max_memory_mb = max_memory,
      timestamp = Sys.time()
    ))
    
  }, error = function(e) {
    return(list(
      status = "error",
      message = paste("Memory check error:", e$message),
      timestamp = Sys.time()
    ))
  })
}

#' Comprehensive health check
#' @return List with overall health status
perform_health_check <- function() {
  start_time <- Sys.time()
  
  # Run all health checks
  db_health <- check_database_health()
  cache_health <- check_cache_health()
  fs_health <- check_filesystem_health()
  memory_health <- check_memory_health()
  
  # Determine overall status
  all_statuses <- c(db_health$status, cache_health$status, fs_health$status, memory_health$status)
  
  overall_status <- if ("error" %in% all_statuses) {
    "error"
  } else if ("critical" %in% all_statuses) {
    "critical"
  } else if ("warning" %in% all_statuses) {
    "warning"
  } else {
    "healthy"
  }
  
  end_time <- Sys.time()
  
  return(list(
    overall_status = overall_status,
    timestamp = end_time,
    check_duration_ms = round(as.numeric(end_time - start_time) * 1000, 2),
    components = list(
      database = db_health,
      cache = cache_health,
      filesystem = fs_health,
      memory = memory_health
    ),
    application_info = list(
      version = "Monitor Legislativo v4",
      environment = Sys.getenv("R_CONFIG_ACTIVE", "development"),
      port = Sys.getenv("PORT", "3838"),
      r_version = R.version.string
    )
  ))
}

#' Create health check endpoint response
#' @param format Response format ("json" or "html")
#' @return Formatted health check response
create_health_response <- function(format = "json") {
  health_data <- perform_health_check()
  
  if (format == "json") {
    return(toJSON(health_data, pretty = TRUE, auto_unbox = TRUE))
  } else if (format == "html") {
    # Simple HTML response
    status_color <- switch(health_data$overall_status,
      "healthy" = "green",
      "warning" = "orange",
      "critical" = "red",
      "error" = "red"
    )
    
    html_response <- paste0(
      "<html><head><title>Monitor Legislativo Health Check</title></head><body>",
      "<h1>Monitor Legislativo v4 Health Check</h1>",
      "<p><strong>Overall Status:</strong> <span style='color:", status_color, "'>", 
      toupper(health_data$overall_status), "</span></p>",
      "<p><strong>Timestamp:</strong> ", health_data$timestamp, "</p>",
      "<p><strong>Check Duration:</strong> ", health_data$check_duration_ms, " ms</p>",
      "<h2>Component Status</h2>",
      "<ul>",
      "<li><strong>Database:</strong> ", health_data$components$database$status, " - ", health_data$components$database$message, "</li>",
      "<li><strong>Cache:</strong> ", health_data$components$cache$status, " - ", health_data$components$cache$message, "</li>",
      "<li><strong>File System:</strong> ", health_data$components$filesystem$status, " - ", health_data$components$filesystem$message, "</li>",
      "<li><strong>Memory:</strong> ", health_data$components$memory$status, " - ", health_data$components$memory$message, "</li>",
      "</ul>",
      "<h2>Application Info</h2>",
      "<ul>",
      "<li><strong>Version:</strong> ", health_data$application_info$version, "</li>",
      "<li><strong>Environment:</strong> ", health_data$application_info$environment, "</li>",
      "<li><strong>Port:</strong> ", health_data$application_info$port, "</li>",
      "<li><strong>R Version:</strong> ", health_data$application_info$r_version, "</li>",
      "</ul>",
      "</body></html>"
    )
    
    return(html_response)
  } else {
    # Simple text response
    return(paste("Monitor Legislativo v4 - Status:", health_data$overall_status))
  }
}

#' Log health check result
#' @param health_data Health check result
log_health_check <- function(health_data) {
  tryCatch({
    # Create logs directory if it doesn't exist
    if (!dir.exists("logs")) {
      dir.create("logs", recursive = TRUE)
    }
    
    # Create log entry
    log_entry <- paste0(
      "[", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "] ",
      "HEALTH_CHECK - Status: ", health_data$overall_status, 
      " - Duration: ", health_data$check_duration_ms, "ms",
      " - DB: ", health_data$components$database$status,
      " - Cache: ", health_data$components$cache$status,
      " - FS: ", health_data$components$filesystem$status,
      " - Memory: ", health_data$components$memory$status
    )
    
    # Write to log file
    log_file <- file.path("logs", "health_check.log")
    write(log_entry, file = log_file, append = TRUE)
    
  }, error = function(e) {
    cat("Error logging health check:", e$message, "\n")
  })
}

#' Health check middleware for Shiny (if supported)
#' @param req HTTP request object
#' @param res HTTP response object
health_check_middleware <- function(req, res) {
  if (req$PATH_INFO == "/health") {
    health_data <- perform_health_check()
    log_health_check(health_data)
    
    # Set appropriate HTTP status code
    status_code <- switch(health_data$overall_status,
      "healthy" = 200,
      "warning" = 200,
      "critical" = 503,
      "error" = 503
    )
    
    # Return JSON response
    res$status <- status_code
    res$headers$`Content-Type` <- "application/json"
    res$body <- create_health_response("json")
    
    return(res)
  }
  
  return(NULL)
}