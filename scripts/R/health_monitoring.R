# Health Monitoring System for Brazilian Legislative Monitor v4
# Optimized for Cloud Run deployment and production monitoring

# Load required libraries
library(shiny)
library(DBI)
library(pool)
library(jsonlite)
library(httr)

# Initialize global variables for monitoring
monitoring_data <- new.env()
monitoring_data$start_time <- Sys.time()
monitoring_data$request_count <- 0
monitoring_data$error_count <- 0
monitoring_data$db_status <- "unknown"
monitoring_data$memory_usage <- list()

#' Database Health Check
#' @description Checks Cloud SQL PostgreSQL connection and basic queries
#' @return list with status and details
check_database_health <- function() {
    tryCatch({
        # Check if database environment variables exist
        required_vars <- c("DATABASE_URL", "PGHOST", "PGDATABASE", "PGUSER")
        missing_vars <- required_vars[!nzchar(Sys.getenv(required_vars))]
        
        if (length(missing_vars) > 0) {
            return(list(
                status = "error",
                message = paste("Missing environment variables:", paste(missing_vars, collapse = ", ")),
                details = NULL
            ))
        }
        
        # Test database connection
        con <- dbConnect(
            RPostgres::Postgres(),
            host = Sys.getenv("PGHOST"),
            dbname = Sys.getenv("PGDATABASE"),
            user = Sys.getenv("PGUSER"),
            password = Sys.getenv("PGPASSWORD"),
            port = as.integer(Sys.getenv("PGPORT", "5432"))
        )
        
        # Test basic query
        result <- dbGetQuery(con, "SELECT 1 as test, NOW() as timestamp")
        
        # Get connection info
        db_info <- dbGetInfo(con)
        
        # Close connection
        dbDisconnect(con)
        
        monitoring_data$db_status <- "healthy"
        
        return(list(
            status = "healthy",
            message = "Database connection successful",
            details = list(
                timestamp = result$timestamp,
                host = Sys.getenv("PGHOST"),
                database = Sys.getenv("PGDATABASE"),
                connection_time = as.numeric(Sys.time() - start_time, units = "secs")
            )
        ))
        
    }, error = function(e) {
        monitoring_data$db_status <- "error"
        return(list(
            status = "error",
            message = paste("Database connection failed:", e$message),
            details = list(
                error = e$message,
                timestamp = Sys.time()
            )
        ))
    })
}

#' Application Health Check
#' @description Checks core application functionality
#' @return list with status and details
check_application_health <- function() {
    tryCatch({
        # Check essential files
        essential_files <- c(
            "app.R",
            "modules/maps/map_ui.R",
            "modules/maps/map_server.R",
            "data/brazil_states.R"
        )
        
        missing_files <- essential_files[!file.exists(essential_files)]
        
        if (length(missing_files) > 0) {
            return(list(
                status = "warning",
                message = "Some essential files missing",
                details = list(missing_files = missing_files)
            ))
        }
        
        # Check R package availability
        required_packages <- c("shiny", "shinydashboard", "DBI", "RPostgres", 
                              "dplyr", "ggplot2", "plotly", "leaflet", "DT")
        
        package_status <- sapply(required_packages, function(pkg) {
            tryCatch({
                require(pkg, character.only = TRUE, quietly = TRUE)
            }, error = function(e) FALSE)
        })
        
        missing_packages <- names(package_status)[!package_status]
        
        if (length(missing_packages) > 0) {
            return(list(
                status = "error",
                message = "Required packages missing",
                details = list(missing_packages = missing_packages)
            ))
        }
        
        # Check memory usage
        memory_info <- gc()
        memory_used <- sum(memory_info[, "used"] * c(8, 8)) / 1024 / 1024  # Convert to MB
        
        return(list(
            status = "healthy",
            message = "Application core functionality OK",
            details = list(
                uptime_seconds = as.numeric(Sys.time() - monitoring_data$start_time, units = "secs"),
                memory_mb = round(memory_used, 2),
                request_count = monitoring_data$request_count,
                error_count = monitoring_data$error_count,
                packages_loaded = length(.packages())
            )
        ))
        
    }, error = function(e) {
        return(list(
            status = "error",
            message = paste("Application health check failed:", e$message),
            details = list(error = e$message)
        ))
    })
}

#' System Resource Check
#' @description Monitors system resources for Cloud Run deployment
#' @return list with resource usage information
check_system_resources <- function() {
    tryCatch({
        # Memory usage
        memory_info <- gc()
        memory_used <- sum(memory_info[, "used"] * c(8, 8)) / 1024 / 1024  # MB

        # Check available disk space
        disk_info <- system("df -h .", intern = TRUE)

        # Cloud Run specific checks
        cloud_run_env <- Sys.getenv("K_SERVICE") != ""
        port <- Sys.getenv("PORT", "3838")
        
        # Store memory usage for trending
        current_time <- as.numeric(Sys.time())
        if (length(monitoring_data$memory_usage) > 100) {
            # Keep only last 100 measurements
            monitoring_data$memory_usage <- tail(monitoring_data$memory_usage, 99)
        }
        monitoring_data$memory_usage <- c(monitoring_data$memory_usage, 
                                        list(list(time = current_time, memory = memory_used)))
        
        # Determine status based on resource usage
        status <- "healthy"
        warnings <- c()
        
        if (memory_used > 1500) {  # > 1.5GB
            status <- "warning"
            warnings <- c(warnings, "High memory usage")
        }
        
        if (memory_used > 1900) {  # > 1.9GB (close to Cloud Run limit)
            status <- "error"
            warnings <- c(warnings, "Critical memory usage")
        }

        return(list(
            status = status,
            message = if (length(warnings) > 0) paste(warnings, collapse = ", ") else "System resources OK",
            details = list(
                memory_mb = round(memory_used, 2),
                memory_limit_mb = if (cloud_run_env) 2048 else "unlimited",
                port = port,
                cloud_run_service = Sys.getenv("K_SERVICE", "unknown"),
                uptime_seconds = as.numeric(Sys.time() - monitoring_data$start_time, units = "secs"),
                timezone = Sys.timezone(),
                r_version = R.version.string
            )
        ))
        
    }, error = function(e) {
        return(list(
            status = "error",
            message = paste("System resource check failed:", e$message),
            details = list(error = e$message)
        ))
    })
}

#' Comprehensive Health Check
#' @description Runs all health checks and returns consolidated status
#' @return list with overall health status
comprehensive_health_check <- function() {
    start_time <- Sys.time()
    
    # Run individual health checks
    db_health <- check_database_health()
    app_health <- check_application_health()
    system_health <- check_system_resources()
    
    # Determine overall status
    statuses <- c(db_health$status, app_health$status, system_health$status)
    
    overall_status <- if ("error" %in% statuses) {
        "unhealthy"
    } else if ("warning" %in% statuses) {
        "degraded"
    } else {
        "healthy"
    }
    
    # Calculate health check duration
    check_duration <- as.numeric(Sys.time() - start_time, units = "secs")
    
    return(list(
        status = overall_status,
        timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"),
        check_duration_seconds = round(check_duration, 3),
        service = "Brazilian Legislative Monitor v4",
        version = "4.0.0",
        environment = Sys.getenv("K_SERVICE", "development"),
        checks = list(
            database = db_health,
            application = app_health,
            system = system_health
        )
    ))
}

#' Health Endpoint Handler
#' @description Creates a health endpoint for Cloud Run and monitoring systems
#' @param req Shiny request object (if called from Shiny)
#' @return JSON response with health status
health_endpoint_handler <- function(req = NULL) {
    # Increment request counter
    monitoring_data$request_count <- monitoring_data$request_count + 1
    
    tryCatch({
        health_data <- comprehensive_health_check()
        
        # Return appropriate HTTP status
        http_status <- switch(health_data$status,
            "healthy" = 200,
            "degraded" = 200,  # Still operational
            "unhealthy" = 503  # Service unavailable
        )
        
        if (is.null(req)) {
            # Return for direct call
            return(health_data)
        } else {
            # Return for Shiny HTTP request
            return(list(
                status = http_status,
                headers = list("Content-Type" = "application/json"),
                body = jsonlite::toJSON(health_data, auto_unbox = TRUE, pretty = TRUE)
            ))
        }
        
    }, error = function(e) {
        monitoring_data$error_count <- monitoring_data$error_count + 1
        
        error_response <- list(
            status = "unhealthy",
            timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"),
            service = "Brazilian Legislative Monitor v4",
            error = e$message
        )
        
        if (is.null(req)) {
            return(error_response)
        } else {
            return(list(
                status = 500,
                headers = list("Content-Type" = "application/json"),
                body = jsonlite::toJSON(error_response, auto_unbox = TRUE, pretty = TRUE)
            ))
        }
    })
}

#' Monitoring Dashboard Data
#' @description Provides data for internal monitoring dashboard
#' @return list with monitoring metrics
get_monitoring_metrics <- function() {
    uptime_seconds <- as.numeric(Sys.time() - monitoring_data$start_time, units = "secs")
    
    # Calculate memory trend
    memory_trend <- if (length(monitoring_data$memory_usage) > 1) {
        recent_memory <- sapply(tail(monitoring_data$memory_usage, 10), function(x) x$memory)
        list(
            current = tail(recent_memory, 1),
            average = mean(recent_memory),
            trend = if (length(recent_memory) > 1) {
                lm(recent_memory ~ seq_along(recent_memory))$coefficients[2]
            } else 0
        )
    } else {
        list(current = 0, average = 0, trend = 0)
    }
    
    return(list(
        uptime_hours = round(uptime_seconds / 3600, 2),
        requests_total = monitoring_data$request_count,
        errors_total = monitoring_data$error_count,
        error_rate = if (monitoring_data$request_count > 0) {
            round(monitoring_data$error_count / monitoring_data$request_count * 100, 2)
        } else 0,
        memory_trend = memory_trend,
        database_status = monitoring_data$db_status,
        last_health_check = format(Sys.time(), "%Y-%m-%d %H:%M:%S")
    ))
}

#' Initialize Monitoring
#' @description Sets up monitoring system on application startup
initialize_monitoring <- function() {
    monitoring_data$start_time <- Sys.time()
    monitoring_data$request_count <- 0
    monitoring_data$error_count <- 0
    monitoring_data$memory_usage <- list()
    
    cat("🔍 Health monitoring system initialized\n")
    cat("📊 Monitoring data available at /health endpoint\n")
    cat("🕐 Started at:", format(monitoring_data$start_time, "%Y-%m-%d %H:%M:%S"), "\n")
}

# Export functions for use in main application
if (!exists(".monitoring_initialized")) {
    initialize_monitoring()
    .monitoring_initialized <- TRUE
}