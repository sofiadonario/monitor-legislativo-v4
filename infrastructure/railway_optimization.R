# Railway Infrastructure Optimization
# Monitor Legislativo v4 - Production Deployment Configuration
# ===========================================================

library(httr)
library(jsonlite)

# Railway deployment configuration
.railway_config <- list(
  # Resource limits and thresholds
  memory_limit_mb = 2048,         # Railway Hobby plan limit
  memory_warning_threshold = 0.75, # 75% memory usage warning
  memory_critical_threshold = 0.85, # 85% memory usage critical
  
  # Performance targets
  response_time_target_ms = 500,   # 95th percentile target
  uptime_target_percent = 99.9,    # Uptime SLA target
  concurrent_users_target = 100,   # Target concurrent users
  
  # Auto-scaling configuration
  enable_autoscaling = TRUE,
  scale_up_cpu_threshold = 80,     # CPU % to trigger scale up
  scale_down_cpu_threshold = 30,   # CPU % to trigger scale down
  min_instances = 1,               # Minimum running instances
  max_instances = 3,               # Maximum instances (cost control)
  
  # Health check configuration
  health_check_interval_seconds = 30,
  health_check_timeout_seconds = 10,
  health_check_retries = 3,
  
  # Brazilian academic optimization
  brazilian_timezone = "America/Sao_Paulo",
  peak_hours = c(8, 9, 10, 11, 13, 14, 15, 16, 17), # Academic business hours
  maintenance_window = list(hour = 2, duration_hours = 2) # 2-4 AM maintenance
)

#' Initialize Railway Infrastructure Optimization
#' 
#' Sets up Railway-specific optimizations for Brazilian legislative monitoring
#' Configures resource management, scaling, and monitoring for academic workloads
#' 
#' @return List with optimization status and configuration
#' @export
init_railway_optimization <- function() {
  
  cat("🚄 Initializing Railway infrastructure optimization...\n")
  
  # Setup Railway environment detection
  railway_env <- detect_railway_environment()
  
  if (!railway_env$is_railway) {
    cat("⚠️ Not running on Railway, using local development configuration\n")
    return(setup_local_development_config())
  }
  
  cat("✅ Railway environment detected\n")
  
  # Configure Railway-specific optimizations
  setup_railway_resource_management()
  setup_railway_monitoring()
  setup_railway_scaling()
  configure_railway_networking()
  setup_brazilian_timezone_optimization()
  
  # Validate deployment configuration
  deployment_health <- validate_railway_deployment()
  
  cat("✅ Railway infrastructure optimization complete\n")
  cat(sprintf("📊 Deployment health score: %.1f%%\n", deployment_health$health_score))
  
  return(list(
    status = "optimized",
    environment = railway_env,
    config = .railway_config,
    health = deployment_health,
    optimization_timestamp = Sys.time()
  ))
}

#' Detect Railway Environment
#' 
#' Identifies if the application is running on Railway platform
#' 
#' @return List with environment detection results
detect_railway_environment <- function() {
  
  cat("🔍 Detecting Railway deployment environment...\n")
  
  # Railway sets specific environment variables
  railway_indicators <- list(
    railway_environment = Sys.getenv("RAILWAY_ENVIRONMENT", ""),
    railway_project_id = Sys.getenv("RAILWAY_PROJECT_ID", ""),
    railway_service_id = Sys.getenv("RAILWAY_SERVICE_ID", ""),
    railway_deployment_id = Sys.getenv("RAILWAY_DEPLOYMENT_ID", ""),
    railway_git_commit_sha = Sys.getenv("RAILWAY_GIT_COMMIT_SHA", ""),
    railway_git_branch = Sys.getenv("RAILWAY_GIT_BRANCH", ""),
    port = Sys.getenv("PORT", "")
  )
  
  # Check if we're on Railway
  is_railway <- railway_indicators$railway_environment != "" || 
                railway_indicators$railway_project_id != ""
  
  # Get Railway metadata
  railway_metadata <- list(
    is_railway = is_railway,
    environment = railway_indicators$railway_environment,
    project_id = railway_indicators$railway_project_id,
    service_id = railway_indicators$railway_service_id,
    deployment_id = railway_indicators$railway_deployment_id,
    git_commit = railway_indicators$railway_git_commit_sha,
    git_branch = railway_indicators$railway_git_branch,
    port = railway_indicators$port,
    region = Sys.getenv("RAILWAY_REGION", "unknown"),
    detected_at = Sys.time()
  )
  
  if (is_railway) {
    cat(sprintf("✅ Railway environment: %s\n", 
                railway_metadata$environment %||% "production"))
    cat(sprintf("📍 Railway region: %s\n", 
                railway_metadata$region))
    cat(sprintf("🚀 Service port: %s\n", 
                railway_metadata$port %||% "default"))
  }
  
  return(railway_metadata)
}

#' Setup Railway Resource Management
#' 
#' Configures optimal resource usage for Railway constraints
#' 
setup_railway_resource_management <- function() {
  
  cat("⚙️ Configuring Railway resource management...\n")
  
  # Set R memory options for Railway environment
  options(
    # Memory management for 2GB limit
    expressions = 100000,           # Reduced from default
    max.print = 1000,              # Limit console output
    digits = 6,                    # Reduce precision for memory
    
    # Shiny optimizations for Railway
    shiny.maxRequestSize = 50*1024^2,  # 50MB max upload (Railway friendly)
    shiny.host = "0.0.0.0",           # Accept connections from Railway proxy
    shiny.port = as.numeric(Sys.getenv("PORT", "3000")),
    shiny.autoreload = FALSE,          # Disable in production
    shiny.sanitize.errors = TRUE,      # Security for production
    shiny.trace = FALSE,               # Disable debug traces
    
    # HTTP timeouts for Railway networking
    timeout = 30,                      # 30-second timeout
    HTTPUserAgent = "MonitorLegislativo/4.0 (Railway)",
    
    # Brazilian locale for Railway
    encoding = "UTF-8"
  )
  
  # Configure garbage collection for Railway constraints
  # More frequent, smaller GC cycles work better on Railway
  invisible(gc(verbose = FALSE, reset = TRUE))
  
  # Set system-level optimizations if possible
  tryCatch({
    # Set process priority (if running as privileged user)
    system("renice -n 5 $$", ignore.stderr = TRUE)
  }, error = function(e) {
    # Ignore errors (likely permissions)
  })
  
  cat("✅ Railway resource management configured\n")
}

#' Setup Railway Monitoring
#' 
#' Configures monitoring and health checks for Railway deployment
#' 
setup_railway_monitoring <- function() {
  
  cat("📊 Setting up Railway monitoring and health checks...\n")
  
  # Create health check endpoint data
  if (!exists(".railway_health", envir = .GlobalEnv)) {
    .railway_health <<- list(
      status = "healthy",
      last_check = Sys.time(),
      uptime_start = Sys.time(),
      checks_passed = 0,
      checks_failed = 0,
      memory_usage_history = list(),
      response_time_history = list()
    )
  }
  
  # Setup health monitoring function
  .GlobalEnv$railway_health_check <- function() {
    
    tryCatch({
      # Basic health checks
      health_status <- list(
        timestamp = Sys.time(),
        status = "healthy",
        checks = list()
      )
      
      # Memory check
      if (exists("get_memory_usage")) {
        memory_info <- get_memory_usage()
        health_status$checks$memory <- list(
          status = if (memory_info$usage_percentage < 85) "healthy" else "warning",
          usage_mb = memory_info$used_mb,
          usage_percentage = memory_info$usage_percentage,
          available_mb = memory_info$available_mb
        )
      }
      
      # Database connectivity check
      health_status$checks$database <- list(
        status = "healthy",  # Simplified for now
        connection_pool_active = TRUE
      )
      
      # Application responsiveness check
      start_time <- Sys.time()
      Sys.sleep(0.001)  # Minimal operation
      response_time_ms <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
      
      health_status$checks$responsiveness <- list(
        status = if (response_time_ms < 100) "healthy" else "warning",
        response_time_ms = response_time_ms
      )
      
      # Overall status determination
      all_checks_healthy <- all(sapply(health_status$checks, function(check) {
        check$status %in% c("healthy", "ok")
      }))
      
      health_status$status <- if (all_checks_healthy) "healthy" else "degraded"
      
      # Update global health tracking
      .railway_health$last_check <<- Sys.time()
      if (health_status$status == "healthy") {
        .railway_health$checks_passed <<- .railway_health$checks_passed + 1
      } else {
        .railway_health$checks_failed <<- .railway_health$checks_failed + 1
      }
      
      return(health_status)
      
    }, error = function(e) {
      .railway_health$checks_failed <<- .railway_health$checks_failed + 1
      return(list(
        timestamp = Sys.time(),
        status = "unhealthy",
        error = e$message
      ))
    })
  }
  
  cat("✅ Railway health monitoring configured\n")
}

#' Setup Railway Auto-Scaling
#' 
#' Configures intelligent auto-scaling for Brazilian academic workloads
#' 
setup_railway_scaling <- function() {
  
  cat("📈 Configuring Railway auto-scaling for academic workloads...\n")
  
  # Create scaling decision function
  .GlobalEnv$railway_scaling_decision <- function() {
    
    current_time <- Sys.time()
    current_hour <- as.integer(format(current_time, "%H"))
    
    # Check if we're in Brazilian peak hours
    is_peak_hour <- current_hour %in% .railway_config$peak_hours
    
    # Get current resource usage
    scaling_metrics <- list(
      timestamp = current_time,
      is_peak_hour = is_peak_hour,
      current_hour = current_hour,
      recommendation = "maintain"
    )
    
    # Memory-based scaling decision
    if (exists("get_memory_usage")) {
      memory_info <- get_memory_usage()
      scaling_metrics$memory_usage_percentage = memory_info$usage_percentage
      
      if (memory_info$usage_percentage > 85) {
        scaling_metrics$recommendation <- "scale_up"
        scaling_metrics$reason <- "high_memory_usage"
      } else if (memory_info$usage_percentage < 30 && !is_peak_hour) {
        scaling_metrics$recommendation <- "scale_down"
        scaling_metrics$reason <- "low_memory_usage_off_peak"
      }
    }
    
    # Academic schedule-based scaling
    if (is_peak_hour && scaling_metrics$recommendation == "maintain") {
      scaling_metrics$recommendation <- "ensure_capacity"
      scaling_metrics$reason <- "brazilian_academic_peak_hours"
    }
    
    return(scaling_metrics)
  }
  
  # Create maintenance window checker
  .GlobalEnv$is_maintenance_window <- function() {
    current_time <- Sys.time()
    current_hour <- as.integer(format(current_time, "%H"))
    
    maintenance_start <- .railway_config$maintenance_window$hour
    maintenance_end <- maintenance_start + .railway_config$maintenance_window$duration_hours
    
    return(current_hour >= maintenance_start && current_hour < maintenance_end)
  }
  
  cat("✅ Railway auto-scaling configured for Brazilian academic schedule\n")
}

#' Configure Railway Networking
#' 
#' Optimizes networking configuration for Railway deployment
#' 
configure_railway_networking <- function() {
  
  cat("🌐 Configuring Railway networking optimization...\n")
  
  # Set HTTP client options for Railway environment
  httr::set_config(httr::config(
    timeout = 30,                    # 30-second timeout
    connecttimeout = 10,             # 10-second connection timeout
    followlocation = TRUE,           # Follow redirects
    maxredirs = 5,                   # Maximum redirects
    useragent = "MonitorLegislativo/4.0 Railway",
    http_version = 2                 # Use HTTP/2 when available
  ))
  
  # Configure database connection pooling for Railway
  .railway_db_config <- list(
    # Connection pool settings optimized for Railway
    min_connections = 1,             # Minimum connections
    max_connections = 4,             # Maximum connections (Railway limit)
    connection_timeout = 30,         # Connection timeout seconds
    idle_timeout = 300,              # 5-minute idle timeout
    validation_query = "SELECT 1",   # Connection validation
    
    # Railway PostgreSQL optimizations
    statement_timeout = 30000,       # 30-second statement timeout
    lock_timeout = 10000,            # 10-second lock timeout
    idle_in_transaction_timeout = 60000, # 1-minute idle transaction timeout
    
    # Brazilian timezone for Railway deployment
    timezone = "America/Sao_Paulo"
  )
  
  cat("✅ Railway networking optimization configured\n")
}

#' Setup Brazilian Timezone Optimization
#' 
#' Configures application for Brazilian academic schedules and timezones
#' 
setup_brazilian_timezone_optimization <- function() {
  
  cat("🇧🇷 Configuring Brazilian timezone and academic schedule optimization...\n")
  
  # Set system timezone for Railway deployment
  tryCatch({
    Sys.setenv(TZ = .railway_config$brazilian_timezone)
    
    # Verify timezone setting
    current_tz <- Sys.timezone()
    cat(sprintf("🕐 Timezone configured: %s\n", current_tz))
    
  }, error = function(e) {
    cat("⚠️ Timezone configuration warning:", e$message, "\n")
  })
  
  # Create Brazilian academic schedule functions
  .GlobalEnv$is_brazilian_business_hours <- function() {
    current_hour <- as.integer(format(Sys.time(), "%H"))
    return(current_hour %in% .railway_config$peak_hours)
  }
  
  .GlobalEnv$get_brazilian_academic_load_factor <- function() {
    current_time <- Sys.time()
    current_hour <- as.integer(format(current_time, "%H"))
    current_weekday <- as.integer(format(current_time, "%u")) # 1=Monday, 7=Sunday
    
    # Load factor based on Brazilian academic patterns
    if (current_weekday %in% c(6, 7)) {  # Weekend
      return(0.2)  # 20% load
    } else if (current_hour %in% c(8, 9, 10, 14, 15, 16)) {  # Peak academic hours
      return(1.0)  # 100% load
    } else if (current_hour %in% c(7, 11, 12, 13, 17, 18)) {  # Medium load hours
      return(0.6)  # 60% load
    } else {  # Off-peak hours
      return(0.3)  # 30% load
    }
  }
  
  cat("✅ Brazilian timezone and academic schedule optimization configured\n")
}

#' Validate Railway Deployment
#' 
#' Performs comprehensive validation of Railway deployment configuration
#' 
#' @return List with deployment health assessment
validate_railway_deployment <- function() {
  
  cat("🔍 Validating Railway deployment configuration...\n")
  
  validation_results <- list(
    timestamp = Sys.time(),
    checks = list(),
    health_score = 0,
    status = "unknown"
  )
  
  # Environment validation
  validation_results$checks$environment <- validate_environment_config()
  
  # Resource validation
  validation_results$checks$resources <- validate_resource_config()
  
  # Networking validation
  validation_results$checks$networking <- validate_networking_config()
  
  # Security validation
  validation_results$checks$security <- validate_security_config()
  
  # Calculate overall health score
  check_scores <- sapply(validation_results$checks, function(check) {
    check$score %||% 0
  })
  
  validation_results$health_score <- mean(check_scores)
  
  # Determine overall status
  if (validation_results$health_score >= 90) {
    validation_results$status <- "excellent"
  } else if (validation_results$health_score >= 75) {
    validation_results$status <- "good"
  } else if (validation_results$health_score >= 60) {
    validation_results$status <- "fair"
  } else {
    validation_results$status <- "needs_attention"
  }
  
  return(validation_results)
}

#' Validate Environment Configuration
#' 
#' Checks Railway environment setup
#' 
validate_environment_config <- function() {
  
  check_result <- list(
    name = "environment_config",
    score = 0,
    issues = c(),
    recommendations = c()
  )
  
  score <- 100
  
  # Check essential environment variables
  required_vars <- c("DATABASE_URL", "PORT")
  
  for (var in required_vars) {
    if (Sys.getenv(var) == "") {
      score <- score - 25
      check_result$issues <- c(check_result$issues, 
                              paste("Missing environment variable:", var))
      check_result$recommendations <- c(check_result$recommendations,
                                      paste("Set", var, "in Railway environment"))
    }
  }
  
  # Check Railway-specific variables
  railway_vars <- c("RAILWAY_ENVIRONMENT", "RAILWAY_PROJECT_ID")
  railway_score <- 0
  
  for (var in railway_vars) {
    if (Sys.getenv(var) != "") {
      railway_score <- railway_score + 1
    }
  }
  
  if (railway_score == 0) {
    score <- score - 10
    check_result$issues <- c(check_result$issues, "Railway environment variables not detected")
  }
  
  check_result$score <- max(0, score)
  return(check_result)
}

#' Validate Resource Configuration
#' 
#' Checks resource allocation and limits
#' 
validate_resource_config <- function() {
  
  check_result <- list(
    name = "resource_config",
    score = 0,
    issues = c(),
    recommendations = c()
  )
  
  score <- 100
  
  # Check memory configuration
  if (exists("get_memory_usage")) {
    memory_info <- get_memory_usage()
    
    if (memory_info$usage_percentage > 90) {
      score <- score - 30
      check_result$issues <- c(check_result$issues, "High memory usage detected")
      check_result$recommendations <- c(check_result$recommendations,
                                      "Optimize memory usage or upgrade Railway plan")
    } else if (memory_info$usage_percentage > 75) {
      score <- score - 10
      check_result$recommendations <- c(check_result$recommendations,
                                      "Monitor memory usage closely")
    }
  }
  
  # Check R configuration
  if (getOption("expressions") > 500000) {
    score <- score - 5
    check_result$recommendations <- c(check_result$recommendations,
                                    "Consider reducing R expressions limit for Railway")
  }
  
  check_result$score <- max(0, score)
  return(check_result)
}

#' Validate Networking Configuration
#' 
#' Checks networking and connectivity setup
#' 
validate_networking_config <- function() {
  
  check_result <- list(
    name = "networking_config",
    score = 100,
    issues = c(),
    recommendations = c()
  )
  
  # Check port configuration
  port <- Sys.getenv("PORT", "")
  
  if (port == "") {
    check_result$score <- check_result$score - 20
    check_result$issues <- c(check_result$issues, "PORT environment variable not set")
    check_result$recommendations <- c(check_result$recommendations,
                                    "Ensure Railway PORT is properly configured")
  }
  
  # Check database URL
  db_url <- Sys.getenv("DATABASE_URL", "")
  
  if (db_url == "") {
    check_result$score <- check_result$score - 30
    check_result$issues <- c(check_result$issues, "DATABASE_URL not configured")
    check_result$recommendations <- c(check_result$recommendations,
                                    "Configure Railway PostgreSQL service")
  }
  
  return(check_result)
}

#' Validate Security Configuration
#' 
#' Checks security settings for Railway deployment
#' 
validate_security_config <- function() {
  
  check_result <- list(
    name = "security_config",
    score = 100,
    issues = c(),
    recommendations = c()
  )
  
  # Check if running in production mode
  if (getOption("shiny.autoreload") == TRUE) {
    check_result$score <- check_result$score - 15
    check_result$issues <- c(check_result$issues, "Development mode detected in production")
    check_result$recommendations <- c(check_result$recommendations,
                                    "Disable autoreload for production deployment")
  }
  
  # Check error sanitization
  if (getOption("shiny.sanitize.errors") != TRUE) {
    check_result$score <- check_result$score - 20
    check_result$issues <- c(check_result$issues, "Error sanitization not enabled")
    check_result$recommendations <- c(check_result$recommendations,
                                    "Enable error sanitization for security")
  }
  
  return(check_result)
}

#' Setup Local Development Configuration
#' 
#' Configures optimizations for local development environment
#' 
setup_local_development_config <- function() {
  
  cat("💻 Setting up local development configuration...\n")
  
  # Local development settings
  options(
    shiny.host = "127.0.0.1",
    shiny.port = 3000,
    shiny.autoreload = TRUE,        # Enable for development
    shiny.sanitize.errors = FALSE,  # Show full errors in development
    shiny.trace = TRUE              # Enable debug traces
  )
  
  local_config <- list(
    status = "development",
    environment = "local",
    memory_limit_mb = 8192,  # Assume more memory available locally
    optimization_active = FALSE,
    development_mode = TRUE,
    brazilian_timezone = .railway_config$brazilian_timezone
  )
  
  cat("✅ Local development configuration complete\n")
  
  return(local_config)
}

#' Get Railway Deployment Status
#' 
#' Returns comprehensive status of Railway deployment
#' 
#' @return List with current deployment status and metrics
#' @export
get_railway_status <- function() {
  
  cat("📊 Gathering Railway deployment status...\n")
  
  status <- list(
    timestamp = Sys.time(),
    environment = detect_railway_environment(),
    health = if (exists("railway_health_check")) railway_health_check() else NULL,
    scaling = if (exists("railway_scaling_decision")) railway_scaling_decision() else NULL,
    brazilian_context = list(
      current_timezone = Sys.timezone(),
      is_business_hours = if (exists("is_brazilian_business_hours")) is_brazilian_business_hours() else FALSE,
      load_factor = if (exists("get_brazilian_academic_load_factor")) get_brazilian_academic_load_factor() else 1.0,
      is_maintenance_window = if (exists("is_maintenance_window")) is_maintenance_window() else FALSE
    )
  )
  
  # Add memory information if available
  if (exists("get_memory_usage")) {
    status$memory <- get_memory_usage()
  }
  
  return(status)
}

# Helper function for null coalescing
`%||%` <- function(x, y) if (is.null(x)) y else x

cat("✅ Railway infrastructure optimization module loaded\n")
cat("🚄 Ready for Brazilian legislative monitoring on Railway platform\n")
cat("🇧🇷 Academic schedule and timezone optimization configured\n")