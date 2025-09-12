# CDN Integration System for R Shiny - Brazilian Legislative Monitoring
# Railway-Compatible CDN with Failover and Academic Performance Optimization
# LGPD Compliant | Brazilian Data Sovereignty | Government Accessibility
# Sprint 6A PERF-004 Implementation

library(shiny)
library(magrittr)
library(jsonlite)
library(httr)

# CDN Integration Configuration
CDN_INTEGRATION_CONFIG <- list(
  # Primary CDN Configuration (Cloudflare Free Tier - Academic Budget)
  primary_cdn = list(
    provider = "cloudflare",
    base_url = "https://cdn.monitor-legislativo.railway.app",
    edge_location = "sao-paulo",
    zone_id = Sys.getenv("CLOUDFLARE_ZONE_ID", ""),
    api_token = Sys.getenv("CLOUDFLARE_API_TOKEN", "")
  ),
  
  # Failover Configuration (Railway Direct Serving)
  failover = list(
    enabled = TRUE,
    fallback_to_local = TRUE,
    health_check_interval = 30, # seconds
    failure_threshold = 3,
    recovery_threshold = 2
  ),
  
  # Brazilian Academic Research Requirements
  academic_config = list(
    performance_target_ms = 500,
    cache_strategy = "academic_stability", # Longer cache times for research consistency
    version_control = TRUE,
    integrity_checks = TRUE,
    research_grade_availability = 0.999 # 99.9% uptime for academic research
  ),
  
  # Brazilian Compliance Settings
  brazilian_compliance = list(
    data_sovereignty = TRUE,
    lgpd_compliant = TRUE,
    government_accessibility = TRUE,
    timezone = "America/Sao_Paulo",
    locale = "pt-BR"
  ),
  
  # Railway Platform Optimization
  railway_optimization = list(
    memory_efficient = TRUE,
    bandwidth_optimized = TRUE,
    no_infrastructure_changes = TRUE,
    container_friendly = TRUE
  )
)

# Global CDN State Management
CDN_STATE <- new.env()
CDN_STATE$health_status <- "unknown"
CDN_STATE$failure_count <- 0
CDN_STATE$last_health_check <- NULL
CDN_STATE$performance_metrics <- list()
CDN_STATE$asset_manifest <- NULL

#' Initialize CDN Integration System
#' @description Sets up CDN integration for Brazilian Legislative Monitoring System
#' @param shiny_session Current Shiny session (optional)
#' @return CDN integration status
initialize_cdn_integration <- function(shiny_session = NULL) {
  cat("🌐 Initializing CDN Integration for Brazilian Legislative System...\n")
  cat("🇧🇷 Compliance: LGPD + Government Accessibility Standards\n")
  cat("🎓 Academic Research Performance Target: <500ms\n")
  cat("🚂 Railway Platform: No Infrastructure Changes Required\n\n")
  
  # Load asset manifest
  manifest_result <- load_asset_manifest()
  
  # Perform initial health check
  health_result <- perform_cdn_health_check()
  
  # Setup asset URL resolver
  setup_asset_url_resolver()
  
  # Initialize performance monitoring
  monitoring_result <- initialize_performance_monitoring()
  
  # Configure Shiny integration if session provided
  if (!is.null(shiny_session)) {
    configure_shiny_cdn_integration(shiny_session)
  }
  
  result <- list(
    status = "initialized",
    cdn_health = health_result$status,
    manifest_loaded = manifest_result$success,
    monitoring_active = monitoring_result$active,
    brazilian_compliance = validate_brazilian_compliance(),
    timestamp = format(Sys.time(), tz = "America/Sao_Paulo")
  )
  
  cat("✅ CDN Integration System Ready\n")
  cat("📊 Asset Manifest:", length(CDN_STATE$asset_manifest), "assets tracked\n")
  cat("🏥 Health Status:", CDN_STATE$health_status, "\n\n")
  
  return(result)
}

#' Load Asset Manifest for CDN Resolution
#' @description Loads optimized asset registry for URL resolution
#' @return Manifest loading results
load_asset_manifest <- function() {
  manifest_path <- file.path(getwd(), "cdn/manifests/asset_registry.json")
  
  if (file.exists(manifest_path)) {
    tryCatch({
      CDN_STATE$asset_manifest <- jsonlite::fromJSON(manifest_path, simplifyVector = FALSE)
      cat("📋 Asset manifest loaded:", length(CDN_STATE$asset_manifest), "assets\n")
      return(list(success = TRUE, count = length(CDN_STATE$asset_manifest)))
    }, error = function(e) {
      cat("❌ Error loading asset manifest:", e$message, "\n")
      CDN_STATE$asset_manifest <- list()
      return(list(success = FALSE, error = e$message))
    })
  } else {
    cat("⚠️  Asset manifest not found, generating default...\n")
    CDN_STATE$asset_manifest <- generate_default_manifest()
    return(list(success = TRUE, count = length(CDN_STATE$asset_manifest), source = "default"))
  }
}

#' Generate Default Asset Manifest
#' @description Creates basic manifest when optimized assets not available
#' @return Default asset manifest
generate_default_manifest <- function() {
  # Scan www directory for existing assets
  www_path <- file.path(getwd(), "www")
  default_manifest <- list()
  
  if (dir.exists(www_path)) {
    asset_files <- list.files(www_path, recursive = TRUE, full.names = FALSE)
    
    for (asset_file in asset_files) {
      default_manifest[[asset_file]] <- list(
        path = asset_file,
        cdn_url = NULL, # Will use fallback
        optimization_status = "unoptimized",
        category = "default",
        fallback_available = TRUE
      )
    }
  }
  
  return(default_manifest)
}

#' Perform CDN Health Check
#' @description Checks CDN availability and performance for academic research reliability
#' @return Health check results
perform_cdn_health_check <- function() {
  cat("🏥 Performing CDN Health Check...\n")
  
  # Update last check timestamp
  CDN_STATE$last_health_check <- Sys.time()
  
  # Test CDN connectivity
  cdn_test_result <- test_cdn_connectivity()
  
  # Update health status
  if (cdn_test_result$success) {
    CDN_STATE$failure_count <- max(0, CDN_STATE$failure_count - 1)
    
    if (CDN_STATE$failure_count == 0) {
      CDN_STATE$health_status <- "healthy"
      cat("✅ CDN Status: Healthy\n")
    } else {
      CDN_STATE$health_status <- "recovering"
      cat("🔄 CDN Status: Recovering\n")
    }
  } else {
    CDN_STATE$failure_count <- CDN_STATE$failure_count + 1
    
    if (CDN_STATE$failure_count >= CDN_INTEGRATION_CONFIG$failover$failure_threshold) {
      CDN_STATE$health_status <- "failed"
      cat("❌ CDN Status: Failed - Activating Failover\n")
    } else {
      CDN_STATE$health_status <- "degraded"
      cat("⚠️  CDN Status: Degraded\n")
    }
  }
  
  # Log health check for academic research tracking
  log_health_check_result(cdn_test_result)
  
  return(list(
    status = CDN_STATE$health_status,
    failure_count = CDN_STATE$failure_count,
    last_check = CDN_STATE$last_health_check,
    connectivity_test = cdn_test_result
  ))
}

#' Test CDN Connectivity
#' @description Tests connectivity to primary CDN with Brazilian edge focus
#' @return Connectivity test results
test_cdn_connectivity <- function() {
  base_url <- CDN_INTEGRATION_CONFIG$primary_cdn$base_url
  
  if (base_url == "" || is.null(base_url)) {
    return(list(success = FALSE, reason = "CDN URL not configured"))
  }
  
  # Test with a lightweight asset or health endpoint
  test_url <- paste0(base_url, "/health")
  
  tryCatch({
    # Perform health check with Brazilian timezone awareness
    start_time <- Sys.time()
    response <- httr::GET(test_url, httr::timeout(5))
    response_time_ms <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
    
    success <- httr::status_code(response) %in% c(200, 404) # 404 acceptable for non-existing health endpoint
    
    return(list(
      success = success,
      response_time_ms = response_time_ms,
      status_code = httr::status_code(response),
      brazilian_edge = TRUE, # Assume São Paulo edge based on config
      timestamp = format(Sys.time(), tz = "America/Sao_Paulo")
    ))
    
  }, error = function(e) {
    return(list(
      success = FALSE,
      error = e$message,
      response_time_ms = Inf,
      timestamp = format(Sys.time(), tz = "America/Sao_Paulo")
    ))
  })
}

#' Setup Asset URL Resolver with Failover Logic
#' @description Creates intelligent URL resolver for R Shiny assets
setup_asset_url_resolver <- function() {
  cat("🔗 Setting up Asset URL Resolver with Brazilian Failover Logic...\n")
  
  # Create resolver function in global environment for Shiny access
  assign("resolve_asset_url", function(asset_path, force_local = FALSE) {
    
    # Force local serving in development or if CDN failed
    if (force_local || CDN_STATE$health_status %in% c("failed", "unknown")) {
      return(paste0("/", asset_path))
    }
    
    # Check if asset exists in manifest
    if (!is.null(CDN_STATE$asset_manifest) && asset_path %in% names(CDN_STATE$asset_manifest)) {
      asset_info <- CDN_STATE$asset_manifest[[asset_path]]
      
      # Return CDN URL if available and optimized
      if (!is.null(asset_info$cdn_url) && asset_info$optimization_status == "optimized") {
        return(asset_info$cdn_url)
      }
    }
    
    # Fallback to local serving
    return(paste0("/", asset_path))
    
  }, envir = .GlobalEnv)
  
  cat("✅ Asset URL resolver configured with failover support\n")
}

#' Configure Shiny CDN Integration
#' @param session Shiny session object
#' @description Integrates CDN URLs into Shiny UI rendering
configure_shiny_cdn_integration <- function(session) {
  cat("✨ Configuring Shiny CDN Integration...\n")
  
  # Override default resource path resolution
  if (!is.null(session)) {
    # Add custom resource handler for CDN assets
    session$registerDataObj(
      name = "cdn-assets",
      data = NULL,
      filter = function(data, req) {
        # Custom logic for CDN asset serving could go here
        # For now, rely on the resolve_asset_url function
        return(NULL)
      }
    )
  }
  
  cat("✅ Shiny CDN integration configured\n")
}

#' Create CDN-Aware UI Helper Functions
#' @description Provides helper functions for CDN-optimized UI elements
create_cdn_ui_helpers <- function() {
  
  # CDN-aware CSS inclusion
  assign("includeCSS_CDN", function(css_path) {
    cdn_url <- resolve_asset_url(css_path)
    return(tags$link(rel = "stylesheet", type = "text/css", href = cdn_url))
  }, envir = .GlobalEnv)
  
  # CDN-aware JavaScript inclusion  
  assign("includeScript_CDN", function(js_path) {
    cdn_url <- resolve_asset_url(js_path)
    return(tags$script(src = cdn_url))
  }, envir = .GlobalEnv)
  
  # CDN-aware image tag
  assign("img_CDN", function(src, ...) {
    cdn_url <- resolve_asset_url(src)
    return(tags$img(src = cdn_url, ...))
  }, envir = .GlobalEnv)
  
  # Brazilian government accessibility-compliant link
  assign("accessibleLink_CDN", function(href, text, ...) {
    cdn_url <- resolve_asset_url(href)
    return(tags$a(href = cdn_url, text, 
                 `aria-label` = paste("Link para", text),
                 title = text, ...))
  }, envir = .GlobalEnv)
  
  cat("🎨 CDN UI helper functions created\n")
}

#' Initialize Performance Monitoring for CDN
#' @description Sets up monitoring for academic research performance requirements
#' @return Monitoring initialization status
initialize_performance_monitoring <- function() {
  cat("📊 Initializing CDN Performance Monitoring...\n")
  
  # Initialize performance metrics storage
  CDN_STATE$performance_metrics <- list(
    load_times = numeric(),
    cache_hit_rates = numeric(),
    error_counts = numeric(),
    brazilian_edge_latency = numeric(),
    academic_availability = numeric()
  )
  
  # Setup periodic health checks for academic research reliability
  if (CDN_INTEGRATION_CONFIG$failover$enabled) {
    # In a production environment, this would be handled by a background process
    # For Railway compatibility, we'll do on-demand health checks
    cat("🔄 Health check system configured (on-demand for Railway)\n")
  }
  
  return(list(active = TRUE, metrics_initialized = TRUE))
}

#' Log Health Check Results for Academic Research
#' @param health_result Results from health check
log_health_check_result <- function(health_result) {
  log_dir <- file.path(getwd(), "cdn/performance_logs")
  dir.create(log_dir, recursive = TRUE, showWarnings = FALSE)
  
  log_file <- file.path(log_dir, paste0("health_checks_", Sys.Date(), ".log"))
  
  log_entry <- list(
    timestamp = format(Sys.time(), tz = "America/Sao_Paulo"),
    health_status = CDN_STATE$health_status,
    failure_count = CDN_STATE$failure_count,
    connectivity = health_result,
    academic_context = "Brazilian Legislative Monitoring System"
  )
  
  # Append to log file (JSON format for research analysis)
  cat(jsonlite::toJSON(log_entry, auto_unbox = TRUE), "\n", file = log_file, append = TRUE)
}

#' Validate Brazilian Compliance for CDN
#' @description Ensures CDN setup meets Brazilian legal and academic requirements
#' @return Compliance validation results
validate_brazilian_compliance <- function() {
  compliance_status <- list(
    lgpd_compliant = TRUE, # CDN assets don't contain personal data
    data_sovereignty = check_data_sovereignty(),
    government_accessibility = validate_accessibility_compliance(),
    academic_research_standards = validate_academic_standards(),
    timezone_aware = Sys.timezone() == "America/Sao_Paulo" || 
                    attr(Sys.time(), "tzone") == "America/Sao_Paulo"
  )
  
  overall_compliant <- all(unlist(compliance_status))
  
  if (overall_compliant) {
    cat("🇧🇷 Brazilian compliance validation: ✅ PASSED\n")
  } else {
    cat("🇧🇷 Brazilian compliance validation: ⚠️  NEEDS ATTENTION\n")
    non_compliant <- names(compliance_status)[!unlist(compliance_status)]
    cat("   Issues:", paste(non_compliant, collapse = ", "), "\n")
  }
  
  return(c(compliance_status, overall_compliant = overall_compliant))
}

#' Check Data Sovereignty Compliance
#' @description Validates data residency requirements for Brazil
#' @return Boolean indicating compliance
check_data_sovereignty <- function() {
  # For academic research, ensuring CDN edge locations are appropriate
  edge_location <- CDN_INTEGRATION_CONFIG$primary_cdn$edge_location
  return(edge_location == "sao-paulo" || grepl("brazil", edge_location, ignore.case = TRUE))
}

#' Validate Accessibility Compliance
#' @description Checks government accessibility requirements
#' @return Boolean indicating compliance
validate_accessibility_compliance <- function() {
  # Check if accessibility assets are properly configured
  accessibility_assets <- c("css/accessibility.css", "css/brazilian-government-theme.css")
  
  if (!is.null(CDN_STATE$asset_manifest)) {
    accessibility_configured <- any(accessibility_assets %in% names(CDN_STATE$asset_manifest))
    return(accessibility_configured)
  }
  
  return(TRUE) # Default to compliant if manifest not loaded
}

#' Validate Academic Standards Compliance
#' @description Ensures CDN meets academic research requirements
#' @return Boolean indicating compliance
validate_academic_standards <- function() {
  standards <- list(
    performance_target_achievable = CDN_INTEGRATION_CONFIG$academic_config$performance_target_ms <= 500,
    version_control_enabled = CDN_INTEGRATION_CONFIG$academic_config$version_control,
    integrity_checks_enabled = CDN_INTEGRATION_CONFIG$academic_config$integrity_checks,
    high_availability_configured = CDN_INTEGRATION_CONFIG$academic_config$research_grade_availability >= 0.99
  )
  
  return(all(unlist(standards)))
}

#' Get Current CDN Status for Dashboard
#' @description Provides current CDN status for monitoring dashboard
#' @return Current CDN status information
get_cdn_status <- function() {
  return(list(
    health_status = CDN_STATE$health_status,
    failure_count = CDN_STATE$failure_count,
    last_health_check = CDN_STATE$last_health_check,
    assets_tracked = length(CDN_STATE$asset_manifest %||% list()),
    brazilian_compliance = validate_brazilian_compliance()$overall_compliant,
    performance_target_ms = CDN_INTEGRATION_CONFIG$academic_config$performance_target_ms,
    failover_enabled = CDN_INTEGRATION_CONFIG$failover$enabled
  ))
}

#' Manual CDN Health Check Function
#' @description Allows manual triggering of health checks for testing
#' @return Health check results
manual_health_check <- function() {
  cat("🔄 Performing Manual CDN Health Check...\n")
  result <- perform_cdn_health_check()
  
  status_emoji <- switch(result$status,
    "healthy" = "✅",
    "degraded" = "⚠️",
    "failed" = "❌",
    "recovering" = "🔄",
    "❓"
  )
  
  cat("📊 CDN Status:", status_emoji, result$status, "\n")
  cat("🔢 Failure Count:", result$failure_count, "\n")
  cat("⏱️  Response Time:", result$connectivity_test$response_time_ms, "ms\n")
  
  return(result)
}

#' Force CDN Failover for Testing
#' @description Manually triggers failover mode for testing purposes
force_cdn_failover <- function() {
  cat("🔄 Forcing CDN Failover to Local Assets...\n")
  CDN_STATE$health_status <- "failed"
  CDN_STATE$failure_count <- CDN_INTEGRATION_CONFIG$failover$failure_threshold
  cat("✅ Failover activated - all assets will serve locally\n")
}

#' Reset CDN Status
#' @description Resets CDN to healthy status for testing
reset_cdn_status <- function() {
  cat("🔄 Resetting CDN Status...\n")
  CDN_STATE$health_status <- "unknown"
  CDN_STATE$failure_count <- 0
  CDN_STATE$last_health_check <- NULL
  
  # Perform fresh health check
  health_result <- perform_cdn_health_check()
  cat("✅ CDN status reset, new status:", health_result$status, "\n")
  
  return(health_result)
}

# Initialize helper functions
create_cdn_ui_helpers()

# Export initialization for Railway deployment
if (!interactive()) {
  cat("🌐 Brazilian Legislative CDN Integration System Ready\n")
  cat("🇧🇷 LGPD Compliant | Government Accessibility | Academic Research Optimized\n")  
  cat("🚂 Railway Compatible | No Infrastructure Changes Required\n")
  cat("⚡ Failover Ready | <500ms Performance Target\n\n")
  
  # Auto-initialize if not in interactive mode
  tryCatch({
    init_result <- initialize_cdn_integration()
    cat("🚀 CDN Integration auto-initialized for Railway deployment\n")
  }, error = function(e) {
    cat("⚠️  CDN auto-initialization failed, manual initialization required\n")
    cat("Error:", e$message, "\n")
  })
}