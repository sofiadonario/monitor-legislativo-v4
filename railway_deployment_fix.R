# RAILWAY DEPLOYMENT FIX - COMPREHENSIVE ERROR HANDLING AND OPTIMIZATION
# =======================================================================
# Production-ready deployment fixes for Railway platform
# Addresses module loading failures, memory constraints, and environment issues

# RAILWAY ENVIRONMENT DETECTION
# =============================
is_railway_environment <- function() {
  return(
    !is.na(Sys.getenv("RAILWAY_SERVICE_NAME", NA)) ||
    !is.na(Sys.getenv("RAILWAY_ENVIRONMENT_NAME", NA)) ||
    !is.na(Sys.getenv("PORT", NA)) ||
    file.exists("/.railway")
  )
}

# MEMORY MANAGEMENT FOR RAILWAY
# =============================
setup_railway_memory_management <- function() {
  if (is_railway_environment()) {
    # Set conservative memory limits for Railway
    options(
      shiny.maxRequestSize = 50*1024^2,  # 50MB max request
      warn = 1,  # Show warnings immediately
      max.print = 1000,  # Limit print output
      scipen = 999  # Avoid scientific notation
    )
    
    # Force garbage collection
    gc(verbose = FALSE)
    
    cat("Railway Memory Management: ENABLED\n")
    cat("Max Request Size: 50MB\n")
  }
}

# SAFE SOURCE FUNCTION WITH FALLBACKS
# ===================================
safe_source <- function(file_path, description = "", required = FALSE, silent = TRUE) {
  tryCatch({
    if (!file.exists(file_path)) {
      if (required) {
        stop(paste("Required file not found:", file_path))
      } else {
        if (!silent) cat("Optional file not found:", file_path, "- skipping\n")
        return(FALSE)
      }
    }
    
    # Check file size to avoid memory issues
    file_info <- file.info(file_path)
    if (!is.na(file_info$size) && file_info$size > 1024*1024) {  # 1MB limit
      warning(paste("Large file detected:", file_path, "- may cause memory issues"))
    }
    
    source(file_path, local = FALSE)
    if (!silent) cat("✅", description, "loaded successfully from", file_path, "\n")
    return(TRUE)
    
  }, error = function(e) {
    error_msg <- paste("Failed to load", description, "from", file_path, ":", e$message)
    
    if (required) {
      stop(error_msg)
    } else {
      if (!silent) cat("⚠️", error_msg, "\n")
      return(FALSE)
    }
  })
}

# PROGRESSIVE PACKAGE LOADING
# ===========================
load_packages_progressively <- function() {
  # Core packages (required)
  core_packages <- c("shiny", "shinydashboard", "DT", "plotly", "dplyr", "RColorBrewer")
  
  # Optional packages (graceful fallbacks)
  optional_packages <- c(
    "stringr", "scales", "lubridate", "tidyr", "echarts4r", 
    "htmltools", "leaflet", "sf", "geobr", "geojsonio", 
    "R.utils", "jsonlite", "shinyjs", "yaml", "magrittr"
  )
  
  cat("Loading core packages...\n")
  for (pkg in core_packages) {
    tryCatch({
      suppressPackageStartupMessages(library(pkg, character.only = TRUE))
      cat("✅", pkg, "\n")
    }, error = function(e) {
      stop(paste("CRITICAL: Core package", pkg, "failed to load:", e$message))
    })
  }
  
  cat("\nLoading optional packages...\n")
  loaded_optional <- 0
  for (pkg in optional_packages) {
    tryCatch({
      suppressPackageStartupMessages(library(pkg, character.only = TRUE))
      cat("✅", pkg, "\n")
      loaded_optional <- loaded_optional + 1
    }, error = function(e) {
      cat("⚠️", pkg, "not available (fallback mode)\n")
    })
  }
  
  cat("\nPackage loading summary:\n")
  cat("Core packages: ALL LOADED\n")
  cat("Optional packages:", loaded_optional, "of", length(optional_packages), "loaded\n")
  
  return(list(
    core_loaded = TRUE,
    optional_count = loaded_optional,
    total_optional = length(optional_packages)
  ))
}

# MONITORING SYSTEM WITH FALLBACKS
# ================================
load_monitoring_system <- function() {
  monitoring_files <- c(
    list(path = "monitoring/logger.R", desc = "Logger", required = FALSE),
    list(path = "monitoring/app_monitor.R", desc = "App Monitor", required = FALSE),
    list(path = "monitoring/telemetry.R", desc = "Telemetry", required = FALSE),
    list(path = "monitoring/monitoring_ui.R", desc = "Monitoring UI", required = FALSE)
  )
  
  loaded_count <- 0
  failed_modules <- c()
  
  for (module in monitoring_files) {
    if (safe_source(module$path, module$desc, module$required, silent = FALSE)) {
      loaded_count <- loaded_count + 1
    } else {
      failed_modules <- c(failed_modules, module$desc)
    }
  }
  
  # Initialize monitoring if available
  monitoring_initialized <- FALSE
  if (loaded_count > 0) {
    tryCatch({
      if (exists("init_logger")) {
        init_logger(list(
          enabled = TRUE,
          railway_compatible = TRUE,
          sanitize_sensitive = TRUE,
          default_level = if (is_railway_environment()) "WARN" else "INFO"
        ))
      }
      
      if (exists("init_telemetry")) init_telemetry()
      if (exists("start_monitoring")) start_monitoring()
      if (exists("log_app_start")) log_app_start()
      
      monitoring_initialized <- TRUE
      cat("🔍 Monitoring system initialized successfully\n")
      
    }, error = function(e) {
      cat("⚠️ Monitoring initialization failed:", e$message, "\n")
    })
  }
  
  return(list(
    loaded = loaded_count > 0,
    modules_loaded = loaded_count,
    total_modules = length(monitoring_files),
    failed_modules = failed_modules,
    initialized = monitoring_initialized
  ))
}

# AUTHENTICATION SYSTEM WITH FALLBACKS
# ====================================
load_auth_system <- function() {
  auth_files <- c(
    list(path = "auth/auth_utils.R", desc = "Auth Utils", required = FALSE),
    list(path = "auth/login_ui.R", desc = "Login UI", required = FALSE),
    list(path = "auth/oauth_middleware.R", desc = "OAuth Middleware", required = FALSE)
  )
  
  loaded_count <- 0
  for (module in auth_files) {
    if (safe_source(module$path, module$desc, module$required, silent = FALSE)) {
      loaded_count <- loaded_count + 1
    }
  }
  
  # Check auth configuration
  auth_configured := FALSE
  if (loaded_count > 0 && exists("auth_config")) {
    auth_configured <- tryCatch({
      config <- get("auth_config")
      is.list(config) && !is.null(config$enabled)
    }, error = function(e) FALSE)
  }
  
  cat("🔐 Authentication system:", 
      if (loaded_count > 0) "LOADED" else "DISABLED", 
      if (auth_configured) "(CONFIGURED)" else "(NOT CONFIGURED)", "\n")
  
  return(list(
    loaded = loaded_count > 0,
    modules_loaded = loaded_count,
    configured = auth_configured
  ))
}

# GEOSPATIAL MODULES WITH FALLBACKS
# =================================
load_geospatial_modules <- function() {
  geo_files <- c(
    list(path = "scripts/R/geospatial_utils.R", desc = "Geospatial Utils", required = FALSE),
    list(path = "scripts/R/choropleth_generator.R", desc = "Choropleth Generator", required = FALSE)
  )
  
  loaded_count <- 0
  for (module in geo_files) {
    if (safe_source(module$path, module$desc, module$required, silent = FALSE)) {
      loaded_count <- loaded_count + 1
    }
  }
  
  cat("🗺️ Geospatial modules:", if (loaded_count > 0) "LOADED" else "FALLBACK MODE", "\n")
  
  return(list(
    loaded = loaded_count > 0,
    modules_loaded = loaded_count
  ))
}

# DATABASE MODULES WITH FALLBACKS
# ===============================
load_database_modules <- function() {
  db_files <- c(
    list(path = "db/connection_manager.R", desc = "Connection Manager", required = FALSE),
    list(path = "db/secure_connection.R", desc = "Secure Connection", required = FALSE),
    list(path = "db/query_builder.R", desc = "Query Builder", required = FALSE)
  )
  
  loaded_count <- 0
  for (module in db_files) {
    if (safe_source(module$path, module$desc, module$required, silent = FALSE)) {
      loaded_count <- loaded_count + 1
    }
  }
  
  cat("🗄️ Database modules:", if (loaded_count > 0) "LOADED" else "FALLBACK MODE", "\n")
  
  return(list(
    loaded = loaded_count > 0,
    modules_loaded = loaded_count
  ))
}

# MAIN DEPLOYMENT FIX FUNCTION
# ============================
apply_railway_deployment_fixes <- function() {
  cat("🚂 RAILWAY DEPLOYMENT FIXES STARTING\n")
  cat("=====================================\n")
  
  start_time <- Sys.time()
  
  # 1. Setup Railway-specific environment
  setup_railway_memory_management()
  
  # 2. Load packages progressively
  package_status <- load_packages_progressively()
  
  # 3. Load health check system
  health_loaded <- safe_source("health_check.R", "Health Check System", required = FALSE, silent = FALSE)
  
  # 4. Load monitoring system with fallbacks
  monitoring_status <- load_monitoring_system()
  
  # 5. Load authentication system with fallbacks
  auth_status <- load_auth_system()
  
  # 6. Load geospatial modules with fallbacks
  geo_status <- load_geospatial_modules()
  
  # 7. Load database modules with fallbacks
  db_status <- load_database_modules()
  
  # 8. Load data modules (essential)
  data_loaded <- safe_source("modules/data_loader.R", "Data Loader", required = FALSE, silent = FALSE)
  
  # 9. Load UI/Server modules
  ui_modules <- c(
    "modules/ui_components.R",
    "modules/server_components.R"
  )
  
  ui_loaded_count <- 0
  for (module_path in ui_modules) {
    if (safe_source(module_path, basename(module_path), required = FALSE, silent = FALSE)) {
      ui_loaded_count <- ui_loaded_count + 1
    }
  }
  
  # Final garbage collection
  gc(verbose = FALSE)
  
  duration <- round(as.numeric(difftime(Sys.time(), start_time, units = "secs")), 2)
  
  # Summary report
  cat("\n🚂 RAILWAY DEPLOYMENT FIXES COMPLETED\n")
  cat("=====================================\n")
  cat("Duration:", duration, "seconds\n")
  cat("Environment: Railway =", is_railway_environment(), "\n")
  cat("Core packages: ✅ ALL LOADED\n")
  cat("Optional packages:", package_status$optional_count, "of", package_status$total_optional, "\n")
  cat("Health check:", if (health_loaded) "✅ LOADED" else "⚠️ FALLBACK", "\n")
  cat("Monitoring:", if (monitoring_status$loaded) "✅ LOADED" else "⚠️ FALLBACK", "\n")
  cat("Authentication:", if (auth_status$loaded) "✅ LOADED" else "⚠️ FALLBACK", "\n")
  cat("Geospatial:", if (geo_status$loaded) "✅ LOADED" else "⚠️ FALLBACK", "\n")
  cat("Database:", if (db_status$loaded) "✅ LOADED" else "⚠️ FALLBACK", "\n")
  cat("Data loader:", if (data_loaded) "✅ LOADED" else "⚠️ FALLBACK", "\n")
  cat("UI modules:", ui_loaded_count, "loaded\n")
  
  # Create global status for reference
  assign("RAILWAY_DEPLOYMENT_STATUS", list(
    applied = TRUE,
    timestamp = Sys.time(),
    duration_seconds = duration,
    is_railway = is_railway_environment(),
    packages = package_status,
    health_check = health_loaded,
    monitoring = monitoring_status,
    auth = auth_status,
    geospatial = geo_status,
    database = db_status,
    data_loader = data_loaded,
    ui_modules = ui_loaded_count
  ), envir = .GlobalEnv)
  
  if (monitoring_status$initialized && exists("log_info")) {
    log_info("Railway deployment fixes applied successfully", list(
      duration_seconds = duration,
      modules_loaded = monitoring_status$modules_loaded + auth_status$modules_loaded + geo_status$modules_loaded
    ))
  }
  
  cat("\n✅ Railway deployment optimizations complete!\n")
  cat("Application ready for Railway platform\n")
  
  return(invisible(TRUE))
}

# ERROR RECOVERY FUNCTIONS
# =======================
recover_from_module_failure <- function(module_name) {
  cat("🔧 Recovering from", module_name, "failure...\n")
  
  # Force garbage collection
  gc(verbose = FALSE)
  
  # Reset any problematic global variables
  problematic_vars <- c("MONITOR_STATE", "AUTH_STATE", "DB_POOL")
  for (var in problematic_vars) {
    if (exists(var, envir = .GlobalEnv)) {
      tryCatch({
        rm(list = var, envir = .GlobalEnv)
      }, error = function(e) {})
    }
  }
  
  cat("Module failure recovery completed\n")
}

# RAILWAY-SPECIFIC OPTIMIZATIONS
# ==============================
apply_railway_optimizations <- function() {
  if (is_railway_environment()) {
    # Reduce R's memory footprint
    options(
      expressions = 5000,  # Reduce expression stack
      keep.source = FALSE,  # Don't keep source references
      show.error.messages = TRUE,
      warn = 1
    )
    
    # Disable unnecessary features
    options(
      shiny.trace = FALSE,
      shiny.testmode = FALSE,
      shiny.autoreload = FALSE
    )
    
    cat("Railway-specific optimizations applied\n")
  }
}

# Initialize deployment fixes
apply_railway_optimizations()

cat("🚂 Railway Deployment Fix module loaded and ready\n")
cat("Call apply_railway_deployment_fixes() to start the deployment process\n")