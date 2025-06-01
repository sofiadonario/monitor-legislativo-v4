# ============================================================================
# COMPREHENSIVE SECURITY HEADERS SYSTEM - SPRINT 6B (API-004)
# ============================================================================
# 
# Advanced security headers implementation for Brazilian Legislative API
# Implements HSTS, CSP, XSS protection, clickjacking prevention, and LGPD-compliant
# privacy headers optimized for API usage and Brazilian government compliance
# 
# Features:
# - HTTP Strict Transport Security (HSTS) with preload support
# - Content Security Policy (CSP) optimized for API usage
# - X-Frame-Options for clickjacking protection
# - X-Content-Type-Options for MIME type security
# - X-XSS-Protection for cross-site scripting prevention
# - Referrer-Policy for privacy protection
# - Permissions-Policy for feature control
# - LGPD-compliant privacy and security headers
# - Brazilian government security compliance
# - Mobile and web application compatibility
# - Dynamic security policies based on API tier
# ============================================================================

cat("🛡️ Loading Comprehensive Security Headers System\n")

# Security Headers Configuration
SECURITY_HEADERS_CONFIG <- list(
  # Global security headers settings
  enabled = TRUE,
  environment_aware = TRUE, # Adjust policies based on environment
  
  # HTTP Strict Transport Security (HSTS)
  hsts = list(
    enabled = TRUE,
    max_age = 31536000, # 1 year
    include_subdomains = TRUE,
    preload = TRUE, # Include in HSTS preload list
    upgrade_insecure_requests = TRUE
  ),
  
  # Content Security Policy (CSP)
  csp = list(
    enabled = TRUE,
    # API-optimized CSP policy
    default_src = "'none'", # Deny all by default for API
    script_src = "'none'", # No scripts needed for API
    style_src = "'none'", # No styles needed for API
    img_src = "data:", # Allow data URIs for API documentation
    font_src = "'none'", # No fonts needed for API
    connect_src = "'self'", # Allow same-origin connections
    media_src = "'none'", # No media for API
    object_src = "'none'", # No objects/plugins
    frame_src = "'none'", # No frames
    frame_ancestors = "'none'", # Prevent framing (clickjacking)
    base_uri = "'self'", # Restrict base URI
    form_action = "'none'", # No forms for API
    upgrade_insecure_requests = TRUE,
    report_uri = "/api/v1/security/csp-report", # CSP violation reporting
    report_to = "csp-violations"
  ),
  
  # X-Frame-Options
  frame_options = list(
    enabled = TRUE,
    policy = "DENY" # Completely prevent framing
  ),
  
  # X-Content-Type-Options
  content_type_options = list(
    enabled = TRUE,
    nosniff = TRUE # Prevent MIME type sniffing
  ),
  
  # X-XSS-Protection
  xss_protection = list(
    enabled = TRUE,
    mode = "block", # Block rather than sanitize
    report_uri = "/api/v1/security/xss-report"
  ),
  
  # Referrer Policy
  referrer_policy = list(
    enabled = TRUE,
    policy = "strict-origin-when-cross-origin" # Privacy-focused
  ),
  
  # Permissions Policy (Feature Policy)
  permissions_policy = list(
    enabled = True,
    # Deny all unnecessary features for API
    accelerometer = "none",
    ambient_light_sensor = "none",
    autoplay = "none",
    battery = "none",
    bluetooth = "none",
    camera = "none",
    display_capture = "none",
    document_domain = "none",
    encrypted_media = "none",
    execution_while_not_rendered = "none",
    execution_while_out_of_viewport = "none",
    fullscreen = "none",
    geolocation = "none",
    gyroscope = "none",
    hid = "none",
    identity_credentials_get = "none",
    idle_detection = "none",
    local_fonts = "none",
    magnetometer = "none",
    microphone = "none",
    midi = "none",
    navigation_override = "none",
    payment = "none",
    picture_in_picture = "none",
    publickey_credentials_create = "none",
    publickey_credentials_get = "none",
    screen_wake_lock = "none",
    serial = "none",
    speaker_selection = "none",
    storage_access = "none",
    usb = "none",
    web_share = "none",
    window_management = "none"
  ),
  
  # LGPD and Brazilian Privacy Compliance Headers
  lgpd_privacy = list(
    enabled = TRUE,
    data_protection_officer = TRUE,
    privacy_policy_url = "https://monitorlegislativo.gov.br/privacy",
    data_processing_lawful_basis = "legitimate-interest",
    data_retention_period = "5-years",
    data_subject_rights_available = TRUE,
    brazilian_data_localization = TRUE
  ),
  
  # Brazilian Government Security Compliance
  brazilian_government = list(
    enabled = TRUE,
    security_classification = "publico", # público, reservado, secreto, ultrassecreto
    government_compliance = "lgpd,marco-civil",
    audit_trail_enabled = TRUE,
    digital_sovereignty = "brazil"
  ),
  
  # Additional Security Headers
  additional_headers = list(
    # Server information hiding
    server_header = "Monitor-Legislativo-API/1.0",
    
    # Cross-domain policies
    cross_domain_policies = "none",
    
    # Download options (IE-specific)
    download_options = "noopen",
    
    # Content type enforcement
    content_type_enforcement = TRUE,
    
    # Cache control for sensitive data
    cache_control_sensitive = "no-cache, no-store, must-revalidate, private",
    
    # Timing attack mitigation
    timing_allow_origin = "none"
  ),
  
  # Tier-specific security policies
  tier_policies = list(
    demo = list(
      csp_report_only = TRUE, # Don't block, only report for demo
      hsts_max_age = 3600, # 1 hour for demo
      additional_headers = c("X-Demo-Environment" = "true")
    ),
    academic = list(
      csp_report_only = FALSE,
      hsts_max_age = 86400, # 24 hours for academic
      additional_headers = c("X-Academic-Research-Allowed" = "true")
    ),
    premium = list(
      csp_report_only = FALSE,
      hsts_max_age = 31536000, # 1 year for premium
      additional_headers = c("X-Premium-Security-Level" = "enhanced")
    )
  )
)

# Security Headers Manager
SecurityHeadersManager <- list(
  # Set all security headers based on configuration
  set_all_security_headers = function(req, res, tier = "demo") {
    if (!SECURITY_HEADERS_CONFIG$enabled) {
      return()
    }
    
    # Set basic security headers
    SecurityHeadersManager$set_hsts_header(res, tier)
    SecurityHeadersManager$set_csp_header(res, tier)
    SecurityHeadersManager$set_frame_options_header(res)
    SecurityHeadersManager$set_content_type_options_header(res)
    SecurityHeadersManager$set_xss_protection_header(res)
    SecurityHeadersManager$set_referrer_policy_header(res)
    SecurityHeadersManager$set_permissions_policy_header(res)
    
    # Set LGPD compliance headers
    SecurityHeadersManager$set_lgpd_privacy_headers(res)
    
    # Set Brazilian government compliance headers
    SecurityHeadersManager$set_brazilian_government_headers(res)
    
    # Set additional security headers
    SecurityHeadersManager$set_additional_security_headers(res)
    
    # Set tier-specific headers
    SecurityHeadersManager$set_tier_specific_headers(res, tier)
    
    # Log security headers application
    if (exists("log_security_headers_event")) {
      log_security_headers_event("HEADERS_APPLIED", list(
        tier = tier,
        environment = Sys.getenv("ENVIRONMENT", "development"),
        headers_count = length(res$headers)
      ), req)
    }
  },
  
  # Set HTTP Strict Transport Security header
  set_hsts_header = function(res, tier) {
    if (!SECURITY_HEADERS_CONFIG$hsts$enabled) {
      return()
    }
    
    # Get tier-specific max age
    tier_policy <- SECURITY_HEADERS_CONFIG$tier_policies[[tier]]
    max_age <- if (!is.null(tier_policy$hsts_max_age)) {
      tier_policy$hsts_max_age
    } else {
      SECURITY_HEADERS_CONFIG$hsts$max_age
    }
    
    # Build HSTS header value
    hsts_value <- paste0("max-age=", max_age)
    
    if (SECURITY_HEADERS_CONFIG$hsts$include_subdomains) {
      hsts_value <- paste0(hsts_value, "; includeSubDomains")
    }
    
    if (SECURITY_HEADERS_CONFIG$hsts$preload) {
      hsts_value <- paste0(hsts_value, "; preload")
    }
    
    res$setHeader("Strict-Transport-Security", hsts_value)
    
    # Set upgrade insecure requests if enabled
    if (SECURITY_HEADERS_CONFIG$hsts$upgrade_insecure_requests) {
      res$setHeader("Content-Security-Policy", "upgrade-insecure-requests")
    }
  },
  
  # Set Content Security Policy header
  set_csp_header = function(res, tier) {
    if (!SECURITY_HEADERS_CONFIG$csp$enabled) {
      return()
    }
    
    # Build CSP policy
    csp_config <- SECURITY_HEADERS_CONFIG$csp
    csp_directives <- c()
    
    # Add all CSP directives
    if (!is.null(csp_config$default_src)) {
      csp_directives <- c(csp_directives, paste("default-src", csp_config$default_src))
    }
    if (!is.null(csp_config$script_src)) {
      csp_directives <- c(csp_directives, paste("script-src", csp_config$script_src))
    }
    if (!is.null(csp_config$style_src)) {
      csp_directives <- c(csp_directives, paste("style-src", csp_config$style_src))
    }
    if (!is.null(csp_config$img_src)) {
      csp_directives <- c(csp_directives, paste("img-src", csp_config$img_src))
    }
    if (!is.null(csp_config$connect_src)) {
      csp_directives <- c(csp_directives, paste("connect-src", csp_config$connect_src))
    }
    if (!is.null(csp_config$frame_ancestors)) {
      csp_directives <- c(csp_directives, paste("frame-ancestors", csp_config$frame_ancestors))
    }
    if (!is.null(csp_config$base_uri)) {
      csp_directives <- c(csp_directives, paste("base-uri", csp_config$base_uri))
    }
    
    # Add upgrade insecure requests
    if (csp_config$upgrade_insecure_requests) {
      csp_directives <- c(csp_directives, "upgrade-insecure-requests")
    }
    
    # Add report URI if configured
    if (!is.null(csp_config$report_uri)) {
      csp_directives <- c(csp_directives, paste("report-uri", csp_config$report_uri))
    }
    
    csp_policy <- paste(csp_directives, collapse = "; ")
    
    # Check if should use report-only mode
    tier_policy <- SECURITY_HEADERS_CONFIG$tier_policies[[tier]]
    if (!is.null(tier_policy$csp_report_only) && tier_policy$csp_report_only) {
      res$setHeader("Content-Security-Policy-Report-Only", csp_policy)
    } else {
      res$setHeader("Content-Security-Policy", csp_policy)
    }
  },
  
  # Set X-Frame-Options header
  set_frame_options_header = function(res) {
    if (!SECURITY_HEADERS_CONFIG$frame_options$enabled) {
      return()
    }
    
    res$setHeader("X-Frame-Options", SECURITY_HEADERS_CONFIG$frame_options$policy)
  },
  
  # Set X-Content-Type-Options header
  set_content_type_options_header = function(res) {
    if (!SECURITY_HEADERS_CONFIG$content_type_options$enabled) {
      return()
    }
    
    if (SECURITY_HEADERS_CONFIG$content_type_options$nosniff) {
      res$setHeader("X-Content-Type-Options", "nosniff")
    }
  },
  
  # Set X-XSS-Protection header
  set_xss_protection_header = function(res) {
    if (!SECURITY_HEADERS_CONFIG$xss_protection$enabled) {
      return()
    }
    
    xss_value <- "1"
    if (SECURITY_HEADERS_CONFIG$xss_protection$mode == "block") {
      xss_value <- "1; mode=block"
    }
    
    if (!is.null(SECURITY_HEADERS_CONFIG$xss_protection$report_uri)) {
      xss_value <- paste0(xss_value, "; report=", SECURITY_HEADERS_CONFIG$xss_protection$report_uri)
    }
    
    res$setHeader("X-XSS-Protection", xss_value)
  },
  
  # Set Referrer-Policy header
  set_referrer_policy_header = function(res) {
    if (!SECURITY_HEADERS_CONFIG$referrer_policy$enabled) {
      return()
    }
    
    res$setHeader("Referrer-Policy", SECURITY_HEADERS_CONFIG$referrer_policy$policy)
  },
  
  # Set Permissions-Policy header
  set_permissions_policy_header = function(res) {
    if (!SECURITY_HEADERS_CONFIG$permissions_policy$enabled) {
      return()
    }
    
    permissions_config <- SECURITY_HEADERS_CONFIG$permissions_policy
    permissions_directives <- c()
    
    # Build permissions policy directives
    for (feature in names(permissions_config)) {
      if (feature != "enabled" && !is.null(permissions_config[[feature]])) {
        # Convert snake_case to kebab-case
        feature_name <- gsub("_", "-", feature)
        permissions_directives <- c(permissions_directives, 
                                   paste0(feature_name, "=(", permissions_config[[feature]], ")"))
      }
    }
    
    if (length(permissions_directives) > 0) {
      permissions_policy <- paste(permissions_directives, collapse = ", ")
      res$setHeader("Permissions-Policy", permissions_policy)
    }
  },
  
  # Set LGPD privacy compliance headers
  set_lgpd_privacy_headers = function(res) {
    if (!SECURITY_HEADERS_CONFIG$lgpd_privacy$enabled) {
      return()
    }
    
    lgpd_config <- SECURITY_HEADERS_CONFIG$lgpd_privacy
    
    # Core LGPD compliance headers
    res$setHeader("X-Data-Protection", "LGPD-Compliant")
    
    if (!is.null(lgpd_config$privacy_policy_url)) {
      res$setHeader("X-Privacy-Policy", lgpd_config$privacy_policy_url)
    }
    
    if (!is.null(lgpd_config$data_processing_lawful_basis)) {
      res$setHeader("X-Data-Processing-Lawful-Basis", lgpd_config$data_processing_lawful_basis)
    }
    
    if (!is.null(lgpd_config$data_retention_period)) {
      res$setHeader("X-Data-Retention-Period", lgpd_config$data_retention_period)
    }
    
    if (lgpd_config$data_subject_rights_available) {
      res$setHeader("X-Data-Subject-Rights", "access,rectification,deletion,portability,restriction")
    }
    
    if (lgpd_config$brazilian_data_localization) {
      res$setHeader("X-Data-Location", "Brazil")
      res$setHeader("X-Data-Sovereignty", "BR")
    }
    
    if (lgpd_config$data_protection_officer) {
      res$setHeader("X-Data-Protection-Officer", "available")
      res$setHeader("X-DPO-Contact", "dpo@monitorlegislativo.gov.br")
    }
  },
  
  # Set Brazilian government compliance headers
  set_brazilian_government_headers = function(res) {
    if (!SECURITY_HEADERS_CONFIG$brazilian_government$enabled) {
      return()
    }
    
    gov_config <- SECURITY_HEADERS_CONFIG$brazilian_government
    
    # Government security classification
    if (!is.null(gov_config$security_classification)) {
      res$setHeader("X-Security-Classification", gov_config$security_classification)
    }
    
    # Compliance frameworks
    if (!is.null(gov_config$government_compliance)) {
      res$setHeader("X-Government-Compliance", gov_config$government_compliance)
    }
    
    # Digital sovereignty
    if (!is.null(gov_config$digital_sovereignty)) {
      res$setHeader("X-Digital-Sovereignty", gov_config$digital_sovereignty)
    }
    
    # Audit trail
    if (gov_config$audit_trail_enabled) {
      res$setHeader("X-Audit-Trail", "enabled")
    }
    
    # Brazilian government specific headers
    res$setHeader("X-BR-Government-API", "true")
    res$setHeader("X-BR-Legislative-Data", "authentic")
    res$setHeader("X-BR-Transparency", "lei-12527-2011") # Lei de Acesso à Informação
  },
  
  # Set additional security headers
  set_additional_security_headers = function(res) {
    additional_config <- SECURITY_HEADERS_CONFIG$additional_headers
    
    # Server header
    if (!is.null(additional_config$server_header)) {
      res$setHeader("Server", additional_config$server_header)
    }
    
    # Cross-domain policies
    if (!is.null(additional_config$cross_domain_policies)) {
      res$setHeader("X-Permitted-Cross-Domain-Policies", additional_config$cross_domain_policies)
    }
    
    # Download options
    if (!is.null(additional_config$download_options)) {
      res$setHeader("X-Download-Options", additional_config$download_options)
    }
    
    # Content type enforcement
    if (additional_config$content_type_enforcement) {
      res$setHeader("X-Content-Type-Options", "nosniff")
    }
    
    # Cache control for sensitive data
    if (!is.null(additional_config$cache_control_sensitive)) {
      # Apply to sensitive endpoints
      res$setHeader("Cache-Control", additional_config$cache_control_sensitive)
    }
  },
  
  # Set tier-specific headers
  set_tier_specific_headers = function(res, tier) {
    tier_policy <- SECURITY_HEADERS_CONFIG$tier_policies[[tier]]
    
    if (!is.null(tier_policy$additional_headers)) {
      for (header_name in names(tier_policy$additional_headers)) {
        res$setHeader(header_name, tier_policy$additional_headers[[header_name]])
      }
    }
  }
)

# Security Headers Analytics and Reporting
SecurityHeadersAnalytics <- list(
  # Get security headers compliance report
  get_compliance_report = function(period_days = 30) {
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(list(error = "Database not available"))
    }
    
    tryCatch({
      # Headers application statistics
      headers_stats_query <- "
        SELECT 
          api_tier,
          COUNT(*) as total_requests,
          COUNT(CASE WHEN security_headers_applied = true THEN 1 END) as headers_applied_count,
          AVG(CASE WHEN security_headers_applied = true THEN 1 ELSE 0 END) * 100 as compliance_percentage
        FROM security_headers_log
        WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
        GROUP BY api_tier
        ORDER BY compliance_percentage DESC
      "
      headers_stats <- DBI::dbGetQuery(secure_db_pool, sprintf(headers_stats_query, period_days))
      
      # CSP violations summary
      csp_violations_query <- "
        SELECT 
          violation_type,
          COUNT(*) as violation_count,
          COUNT(DISTINCT source_ip) as unique_ips
        FROM csp_violation_reports
        WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
        GROUP BY violation_type
        ORDER BY violation_count DESC
      "
      csp_violations <- DBI::dbGetQuery(secure_db_pool, sprintf(csp_violations_query, period_days))
      
      return(list(
        period_days = period_days,
        compliance_by_tier = headers_stats,
        csp_violations_summary = csp_violations,
        report_generated = Sys.time()
      ))
      
    }, error = function(e) {
      return(list(error = paste("Failed to generate compliance report:", e$message)))
    })
  },
  
  # Log security headers events
  log_security_headers_event = function(event_type, details, req) {
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(FALSE)
    }
    
    tryCatch({
      api_key_id <- req$api_key_id %||% 0
      tier <- req$api_tier %||% "unknown"
      client_ip <- req$HTTP_X_FORWARDED_FOR %||% req$HTTP_X_REAL_IP %||% req$REMOTE_ADDR %||% "unknown"
      
      DBI::dbExecute(secure_db_pool,
        "INSERT INTO security_headers_log (api_key_id, api_tier, source_ip, event_type, security_headers_applied, details) 
         VALUES ($1, $2, $3, $4, $5, $6)",
        list(api_key_id, tier, client_ip, event_type, TRUE, jsonlite::toJSON(details, auto_unbox = TRUE)))
      
      return(TRUE)
    }, error = function(e) {
      cat("Warning: Failed to log security headers event:", e$message, "\n")
      return(FALSE)
    })
  }
)

# CSP Violation Report Handler
handle_csp_violation_report <- function(req, res) {
  tryCatch({
    violation_report <- jsonlite::fromJSON(req$postBody, simplifyVector = FALSE)
    
    # Log CSP violation
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      client_ip <- req$HTTP_X_FORWARDED_FOR %||% req$HTTP_X_REAL_IP %||% req$REMOTE_ADDR %||% "unknown"
      
      DBI::dbExecute(secure_db_pool,
        "INSERT INTO csp_violation_reports (source_ip, violation_type, blocked_uri, document_uri, violated_directive, report_data) 
         VALUES ($1, $2, $3, $4, $5, $6)",
        list(
          client_ip,
          violation_report$`csp-report`$`violated-directive` %||% "unknown",
          violation_report$`csp-report`$`blocked-uri` %||% "unknown",
          violation_report$`csp-report`$`document-uri` %||% "unknown",
          violation_report$`csp-report`$`violated-directive` %||% "unknown",
          jsonlite::toJSON(violation_report, auto_unbox = TRUE)
        ))
    }
    
    res$status <- 204 # No Content
    return("")
    
  }, error = function(e) {
    cat("Error handling CSP violation report:", e$message, "\n")
    res$status <- 400
    return(list(error = "Invalid CSP report"))
  })
}

# Main security headers filter
#* @filter security_headers
function(req, res) {
  # Get API key information (should be set by authentication middleware)
  tier <- req$api_tier %||% "demo"
  
  # Apply all security headers
  SecurityHeadersManager$set_all_security_headers(req, res, tier)
  
  # Continue processing
  plumber::forward()
}

# Initialize security headers system
initialize_security_headers_system <- function() {
  # Ensure required tables exist
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    security_headers_schema <- "
      CREATE TABLE IF NOT EXISTS security_headers_log (
        id SERIAL PRIMARY KEY,
        api_key_id INTEGER DEFAULT 0,
        api_tier VARCHAR(50),
        source_ip VARCHAR(45),
        event_type VARCHAR(100),
        security_headers_applied BOOLEAN DEFAULT false,
        details JSONB,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS csp_violation_reports (
        id SERIAL PRIMARY KEY,
        source_ip VARCHAR(45),
        violation_type VARCHAR(100),
        blocked_uri TEXT,
        document_uri TEXT,
        violated_directive VARCHAR(200),
        report_data JSONB,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE INDEX IF NOT EXISTS idx_security_headers_log_timestamp ON security_headers_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_security_headers_log_tier ON security_headers_log(api_tier);
      CREATE INDEX IF NOT EXISTS idx_csp_violations_timestamp ON csp_violation_reports(timestamp);
    "
    
    tryCatch({
      DBI::dbExecute(secure_db_pool, security_headers_schema)
      cat("✅ Security headers logging tables initialized\n")
    }, error = function(e) {
      cat("⚠️ Failed to initialize security headers tables:", e$message, "\n")
    })
  }
  
  cat("✅ Comprehensive Security Headers System initialized\n")
  cat("  🔒 HSTS with preload support enabled\n")
  cat("  🛡️ API-optimized Content Security Policy active\n")
  cat("  🚫 Clickjacking protection (X-Frame-Options) enabled\n")
  cat("  🔍 MIME type sniffing protection active\n")
  cat("  ⚖️ LGPD-compliant privacy headers enabled\n")
  cat("  🏛️ Brazilian government compliance headers active\n")
  cat("  📊 Security headers analytics and reporting enabled\n")
  
  return(TRUE)
}

# Auto-initialize
initialize_security_headers_system()

# Export functions for external use
log_security_headers_event <- SecurityHeadersAnalytics$log_security_headers_event

cat("✅ Comprehensive Security Headers System Loaded\n")