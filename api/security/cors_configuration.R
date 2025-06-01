# ============================================================================
# COMPREHENSIVE CORS CONFIGURATION - SPRINT 6B (API-004)
# ============================================================================
# 
# Advanced Cross-Origin Resource Sharing configuration for Brazilian Legislative API
# Implements dynamic CORS based on API key tiers, Brazilian academic institution
# domain whitelisting, and LGPD-compliant cross-origin policies
# 
# Features:
# - Brazilian academic institution domain whitelist
# - Dynamic CORS based on API key tier (Demo, Academic, Premium)
# - Government domain support for official integrations
# - Mobile and web application support
# - Preflight request optimization
# - LGPD-compliant cross-origin policies
# - Intelligent origin validation with security logging
# - Development and testing environment support
# ============================================================================

cat("🌐 Loading Comprehensive CORS Configuration\n")

# Load required dependencies
if (file.exists("api/security/domain_whitelist.R")) {
  source("api/security/domain_whitelist.R")
}

# CORS Configuration Structure
CORS_CONFIG <- list(
  # Global CORS settings
  enabled = TRUE,
  credentials_allowed = FALSE, # Security: Do not allow credentials by default
  max_age = 86400, # 24 hours
  expose_headers = c("X-RateLimit-Remaining", "X-RateLimit-Reset", "X-Daily-Quota-Remaining", 
                     "X-API-Tier", "X-Usage-Statistics", "X-Response-Time", "X-Total-Count",
                     "X-Data-Protection", "X-LGPD-Compliant"),
  
  # Tier-specific CORS configurations
  tier_configs = list(
    demo = list(
      allowed_origins = c("http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:3000"),
      allowed_methods = c("GET", "OPTIONS"),
      allowed_headers = c("Content-Type", "Authorization", "X-API-Key", "X-Requested-With"),
      max_age = 3600, # 1 hour for demo
      custom_headers_allowed = FALSE
    ),
    
    academic = list(
      allowed_origins = "dynamic", # Will be populated with academic domains
      allowed_methods = c("GET", "POST", "OPTIONS"),
      allowed_headers = c("Content-Type", "Authorization", "X-API-Key", "X-Requested-With",
                         "X-Research-Project", "X-Institution", "X-Academic-Purpose"),
      max_age = 43200, # 12 hours for academic
      custom_headers_allowed = TRUE
    ),
    
    premium = list(
      allowed_origins = "dynamic", # Will be populated based on premium user configuration
      allowed_methods = c("GET", "POST", "PUT", "DELETE", "OPTIONS"),
      allowed_headers = c("Content-Type", "Authorization", "X-API-Key", "X-Requested-With",
                         "X-Custom-Header", "X-Application-Id", "X-Client-Version"),
      max_age = 86400, # 24 hours for premium
      custom_headers_allowed = TRUE
    )
  ),
  
  # Development and testing configurations
  development = list(
    localhost_patterns = c(
      "http://localhost:\\d+",
      "http://127\\.0\\.0\\.1:\\d+",
      "http://0\\.0\\.0\\.0:\\d+",
      "https://.*\\.railway\\.app",
      "https://.*\\.herokuapp\\.com",
      "https://.*\\.vercel\\.app",
      "https://.*\\.netlify\\.app"
    ),
    allowed_in_dev = TRUE,
    dev_max_age = 300 # 5 minutes for development
  ),
  
  # Security settings
  security = list(
    strict_origin_validation = TRUE,
    log_cors_violations = TRUE,
    block_suspicious_origins = TRUE,
    suspicious_patterns = c(
      ".*malicious.*",
      ".*phishing.*",
      ".*spam.*",
      ".*bot.*",
      ".*crawler.*"
    ),
    max_origin_length = 253, # Standard domain name limit
    require_https_in_production = TRUE
  ),
  
  # LGPD and Brazilian compliance
  lgpd_compliance = list(
    enabled = TRUE,
    privacy_headers = TRUE,
    data_localization_headers = TRUE,
    consent_management_headers = TRUE,
    brazilian_only_mode = FALSE # If true, only allows Brazilian domains
  )
)

# Brazilian Academic and Government Domain Validator
BrazilianDomainValidator <- list(
  # Check if domain is a recognized Brazilian academic institution
  is_brazilian_academic = function(domain) {
    if (exists("BRAZILIAN_ACADEMIC_DOMAINS")) {
      # Direct domain match
      if (domain %in% BRAZILIAN_ACADEMIC_DOMAINS$universities ||
          domain %in% BRAZILIAN_ACADEMIC_DOMAINS$research_institutes ||
          domain %in% BRAZILIAN_ACADEMIC_DOMAINS$government_education) {
        return(list(valid = TRUE, type = "direct", category = "academic"))
      }
      
      # Pattern matching for subdomains
      for (base_domain in c(BRAZILIAN_ACADEMIC_DOMAINS$universities,
                           BRAZILIAN_ACADEMIC_DOMAINS$research_institutes)) {
        if (grepl(paste0("\\.", gsub("\\.", "\\\\.", base_domain), "$"), domain)) {
          return(list(valid = TRUE, type = "subdomain", category = "academic", base = base_domain))
        }
      }
    }
    
    return(list(valid = FALSE, type = "unknown"))
  },
  
  # Check if domain is a recognized Brazilian government institution
  is_brazilian_government = function(domain) {
    if (exists("BRAZILIAN_GOVERNMENT_DOMAINS")) {
      # Direct match or pattern match for .gov.br domains
      if (domain %in% BRAZILIAN_GOVERNMENT_DOMAINS ||
          grepl("\\.gov\\.br$", domain) ||
          grepl("\\.leg\\.br$", domain) ||
          grepl("\\.jus\\.br$", domain)) {
        return(list(valid = TRUE, type = "government"))
      }
    }
    
    return(list(valid = FALSE, type = "unknown"))
  },
  
  # Comprehensive Brazilian domain validation
  validate_brazilian_domain = function(domain) {
    # Academic validation
    academic_result <- BrazilianDomainValidator$is_brazilian_academic(domain)
    if (academic_result$valid) {
      return(academic_result)
    }
    
    # Government validation
    gov_result <- BrazilianDomainValidator$is_brazilian_government(domain)
    if (gov_result$valid) {
      return(gov_result)
    }
    
    # General Brazilian domain patterns
    if (grepl("\\.br$", domain)) {
      return(list(valid = TRUE, type = "brazilian_general", category = "commercial"))
    }
    
    return(list(valid = FALSE, type = "foreign"))
  }
)

# CORS Origin Validator
CORSOriginValidator <- list(
  # Validate origin format and security
  validate_origin_format = function(origin) {
    if (is.null(origin) || nchar(origin) == 0) {
      return(list(valid = FALSE, error = "Empty origin"))
    }
    
    # Check length
    if (nchar(origin) > CORS_CONFIG$security$max_origin_length) {
      return(list(valid = FALSE, error = "Origin too long"))
    }
    
    # Check for suspicious patterns
    for (pattern in CORS_CONFIG$security$suspicious_patterns) {
      if (grepl(pattern, origin, ignore.case = TRUE)) {
        return(list(valid = FALSE, error = "Suspicious origin pattern", pattern = pattern))
      }
    }
    
    # Validate URL format
    if (!grepl("^https?://[a-zA-Z0-9.-]+(?::[0-9]+)?$", origin)) {
      return(list(valid = FALSE, error = "Invalid origin format"))
    }
    
    # Extract domain
    domain_match <- regexpr("://([^:/?#]+)", origin, perl = TRUE)
    if (domain_match == -1) {
      return(list(valid = FALSE, error = "Cannot extract domain"))
    }
    
    domain <- substr(origin, attr(domain_match, "capture.start")[1], 
                     attr(domain_match, "capture.start")[1] + attr(domain_match, "capture.length")[1] - 1)
    
    # Production HTTPS requirement
    if (Sys.getenv("ENVIRONMENT") == "production" && 
        CORS_CONFIG$security$require_https_in_production && 
        !grepl("^https://", origin)) {
      return(list(valid = FALSE, error = "HTTPS required in production"))
    }
    
    return(list(valid = TRUE, domain = domain, origin = origin))
  },
  
  # Check if origin is allowed for specific tier
  is_origin_allowed_for_tier = function(origin, tier, api_key_data = NULL) {
    # Validate origin format first
    format_validation <- CORSOriginValidator$validate_origin_format(origin)
    if (!format_validation$valid) {
      return(format_validation)
    }
    
    domain <- format_validation$domain
    tier_config <- CORS_CONFIG$tier_configs[[tier]]
    
    if (is.null(tier_config)) {
      return(list(valid = FALSE, error = "Invalid API tier"))
    }
    
    # Check tier-specific configurations
    if (tier == "demo") {
      # Demo tier: only localhost and development domains
      allowed_origins <- tier_config$allowed_origins
      
      if (origin %in% allowed_origins) {
        return(list(valid = TRUE, type = "demo_localhost"))
      }
      
      # Check development patterns if enabled
      if (CORS_CONFIG$development$allowed_in_dev) {
        for (pattern in CORS_CONFIG$development$localhost_patterns) {
          if (grepl(pattern, origin)) {
            return(list(valid = TRUE, type = "demo_development"))
          }
        }
      }
      
      return(list(valid = FALSE, error = "Origin not allowed for demo tier"))
      
    } else if (tier == "academic") {
      # Academic tier: Brazilian academic institutions + development
      
      # Check if it's a Brazilian academic domain
      brazilian_validation <- BrazilianDomainValidator$validate_brazilian_domain(domain)
      if (brazilian_validation$valid && brazilian_validation$category == "academic") {
        return(list(valid = TRUE, type = "academic_brazilian", details = brazilian_validation))
      }
      
      # Check development domains
      if (CORS_CONFIG$development$allowed_in_dev) {
        for (pattern in CORS_CONFIG$development$localhost_patterns) {
          if (grepl(pattern, origin)) {
            return(list(valid = TRUE, type = "academic_development"))
          }
        }
      }
      
      # Check if domain is explicitly allowed in API key configuration
      if (!is.null(api_key_data$allowed_domains)) {
        if (domain %in% api_key_data$allowed_domains) {
          return(list(valid = TRUE, type = "academic_custom"))
        }
      }
      
      return(list(valid = FALSE, error = "Origin not allowed for academic tier"))
      
    } else if (tier == "premium") {
      # Premium tier: Custom domain configuration + all academic domains
      
      # Check custom allowed domains in API key configuration
      if (!is.null(api_key_data$allowed_domains)) {
        if (domain %in% api_key_data$allowed_domains || "*" %in% api_key_data$allowed_domains) {
          return(list(valid = TRUE, type = "premium_custom"))
        }
      }
      
      # Check Brazilian domains (government and academic)
      brazilian_validation <- BrazilianDomainValidator$validate_brazilian_domain(domain)
      if (brazilian_validation$valid) {
        return(list(valid = TRUE, type = "premium_brazilian", details = brazilian_validation))
      }
      
      # Check development domains
      if (CORS_CONFIG$development$allowed_in_dev) {
        for (pattern in CORS_CONFIG$development$localhost_patterns) {
          if (grepl(pattern, origin)) {
            return(list(valid = TRUE, type = "premium_development"))
          }
        }
      }
      
      return(list(valid = FALSE, error = "Origin not allowed for premium tier"))
    }
    
    return(list(valid = FALSE, error = "Unknown validation path"))
  }
)

# CORS Header Manager
CORSHeaderManager <- list(
  # Set CORS headers based on validation result
  set_cors_headers = function(req, res, tier, origin_validation, api_key_data = NULL) {
    if (!CORS_CONFIG$enabled) {
      return()
    }
    
    origin <- req$HTTP_ORIGIN
    tier_config <- CORS_CONFIG$tier_configs[[tier]]
    
    # Set Access-Control-Allow-Origin
    if (origin_validation$valid) {
      res$setHeader("Access-Control-Allow-Origin", origin)
      
      # Log successful CORS validation
      if (exists("log_cors_event")) {
        log_cors_event("CORS_ALLOWED", list(
          origin = origin,
          tier = tier,
          type = origin_validation$type,
          domain = origin_validation$details$domain %||% "unknown"
        ), req)
      }
    } else {
      # Log CORS violation
      if (CORS_CONFIG$security$log_cors_violations && exists("log_cors_event")) {
        log_cors_event("CORS_BLOCKED", list(
          origin = origin,
          tier = tier,
          error = origin_validation$error,
          reason = origin_validation$pattern %||% "unknown"
        ), req)
      }
      
      # Don't set CORS headers for invalid origins
      return()
    }
    
    # Set allowed methods
    if (!is.null(tier_config$allowed_methods)) {
      res$setHeader("Access-Control-Allow-Methods", 
                    paste(tier_config$allowed_methods, collapse = ", "))
    }
    
    # Set allowed headers
    if (!is.null(tier_config$allowed_headers)) {
      res$setHeader("Access-Control-Allow-Headers", 
                    paste(tier_config$allowed_headers, collapse = ", "))
    }
    
    # Set exposed headers
    if (!is.null(CORS_CONFIG$expose_headers)) {
      res$setHeader("Access-Control-Expose-Headers", 
                    paste(CORS_CONFIG$expose_headers, collapse = ", "))
    }
    
    # Set max age
    max_age <- tier_config$max_age %||% CORS_CONFIG$max_age
    if (CORS_CONFIG$development$allowed_in_dev && 
        grepl("development", origin_validation$type %||% "")) {
      max_age <- CORS_CONFIG$development$dev_max_age
    }
    res$setHeader("Access-Control-Max-Age", as.character(max_age))
    
    # Set credentials policy
    res$setHeader("Access-Control-Allow-Credentials", 
                  if (CORS_CONFIG$credentials_allowed) "true" else "false")
    
    # LGPD compliance headers for cross-origin requests
    if (CORS_CONFIG$lgpd_compliance$enabled) {
      CORSHeaderManager$set_lgpd_cors_headers(res, origin_validation)
    }
  },
  
  # Set LGPD-compliant CORS headers
  set_lgpd_cors_headers = function(res, origin_validation) {
    if (!CORS_CONFIG$lgpd_compliance$privacy_headers) {
      return()
    }
    
    # Privacy compliance headers
    res$setHeader("X-CORS-Privacy-Compliant", "LGPD")
    res$setHeader("X-Data-Processing-Lawful", "legitimate-interest")
    res$setHeader("X-Cross-Origin-Data-Policy", "minimal-processing")
    
    # Brazilian data localization information
    if (CORS_CONFIG$lgpd_compliance$data_localization_headers) {
      res$setHeader("X-Data-Location", "Brazil")
      res$setHeader("X-Data-Sovereignty", "BR")
    }
    
    # Indicate consent management capabilities
    if (CORS_CONFIG$lgpd_compliance$consent_management_headers) {
      res$setHeader("X-Consent-Management-Available", "true")
      res$setHeader("X-Data-Subject-Rights", "access,rectification,deletion,portability")
    }
    
    # Brazilian-specific compliance
    if (!is.null(origin_validation$details) && 
        origin_validation$details$type == "brazilian_general") {
      res$setHeader("X-BR-LGPD-Compliant", "true")
      res$setHeader("X-BR-Data-Protection-Officer", "available")
    }
  },
  
  # Handle preflight requests
  handle_preflight = function(req, res, tier, api_key_data = NULL) {
    origin <- req$HTTP_ORIGIN
    
    if (is.null(origin)) {
      res$status <- 400
      return(list(error = "Missing origin header in preflight request"))
    }
    
    # Validate origin
    origin_validation <- CORSOriginValidator$is_origin_allowed_for_tier(origin, tier, api_key_data)
    
    if (!origin_validation$valid) {
      res$status <- 403
      return(list(error = "Origin not allowed for preflight request"))
    }
    
    # Set CORS headers for preflight
    CORSHeaderManager$set_cors_headers(req, res, tier, origin_validation, api_key_data)
    
    # Preflight-specific headers
    res$setHeader("Content-Length", "0")
    res$setHeader("Content-Type", "text/plain")
    
    # Success response for preflight
    res$status <- 204 # No Content
    return("")
  }
)

# CORS Statistics and Analytics
CORSAnalytics <- list(
  # Get CORS usage statistics
  get_cors_statistics = function(period_days = 30) {
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(list(error = "Database not available"))
    }
    
    tryCatch({
      # CORS requests by tier
      tier_stats_query <- "
        SELECT 
          api_tier as tier,
          COUNT(*) as cors_requests,
          COUNT(DISTINCT origin) as unique_origins
        FROM cors_log
        WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
        AND cors_allowed = true
        GROUP BY api_tier
        ORDER BY cors_requests DESC
      "
      tier_stats <- DBI::dbGetQuery(secure_db_pool, sprintf(tier_stats_query, period_days))
      
      # Top origins by requests
      top_origins_query <- "
        SELECT 
          origin,
          COUNT(*) as requests,
          COUNT(DISTINCT api_key_id) as unique_api_keys
        FROM cors_log
        WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
        AND cors_allowed = true
        GROUP BY origin
        ORDER BY requests DESC
        LIMIT 20
      "
      top_origins <- DBI::dbGetQuery(secure_db_pool, sprintf(top_origins_query, period_days))
      
      # CORS violations summary
      violations_query <- "
        SELECT 
          violation_reason,
          COUNT(*) as count,
          COUNT(DISTINCT origin) as unique_origins_blocked
        FROM cors_log
        WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
        AND cors_allowed = false
        GROUP BY violation_reason
        ORDER BY count DESC
      "
      violations <- DBI::dbGetQuery(secure_db_pool, sprintf(violations_query, period_days))
      
      return(list(
        period_days = period_days,
        tier_statistics = tier_stats,
        top_allowed_origins = top_origins,
        cors_violations = violations,
        total_cors_requests = sum(tier_stats$cors_requests, na.rm = TRUE)
      ))
      
    }, error = function(e) {
      return(list(error = paste("Failed to get CORS statistics:", e$message)))
    })
  },
  
  # Log CORS events
  log_cors_event = function(event_type, details, req) {
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(FALSE)
    }
    
    tryCatch({
      origin <- req$HTTP_ORIGIN %||% "unknown"
      api_key_id <- req$api_key_id %||% 0
      tier <- req$api_tier %||% "unknown"
      
      DBI::dbExecute(secure_db_pool,
        "INSERT INTO cors_log (api_key_id, origin, api_tier, event_type, cors_allowed, details) 
         VALUES ($1, $2, $3, $4, $5, $6)",
        list(api_key_id, origin, tier, event_type, 
             event_type == "CORS_ALLOWED", jsonlite::toJSON(details, auto_unbox = TRUE)))
      
      return(TRUE)
    }, error = function(e) {
      cat("Warning: Failed to log CORS event:", e$message, "\n")
      return(FALSE)
    })
  }
)

# Main CORS Filter Function
#* @filter cors
function(req, res) {
  # Skip CORS processing if disabled
  if (!CORS_CONFIG$enabled) {
    plumber::forward()
    return()
  }
  
  origin <- req$HTTP_ORIGIN
  
  # Skip if no origin header (same-origin requests)
  if (is.null(origin)) {
    plumber::forward()
    return()
  }
  
  # Get API key information (should be set by authentication middleware)
  tier <- req$api_tier %||% "demo"
  api_key_data <- req$api_key_data
  
  # Handle preflight OPTIONS requests
  if (req$REQUEST_METHOD == "OPTIONS") {
    result <- CORSHeaderManager$handle_preflight(req, res, tier, api_key_data)
    if (is.list(result) && !is.null(result$error)) {
      res$setHeader("Content-Type", "application/json")
      return(jsonlite::toJSON(list(
        error = TRUE,
        message = result$error,
        code = res$status %||% 403
      ), auto_unbox = TRUE))
    } else {
      return(result)
    }
  }
  
  # Validate origin for actual requests
  origin_validation <- CORSOriginValidator$is_origin_allowed_for_tier(origin, tier, api_key_data)
  
  # Set appropriate CORS headers
  CORSHeaderManager$set_cors_headers(req, res, tier, origin_validation, api_key_data)
  
  # Block request if origin is not allowed
  if (!origin_validation$valid) {
    res$status <- 403
    res$setHeader("Content-Type", "application/json")
    
    error_response <- list(
      error = TRUE,
      message = "CORS: Origin not allowed",
      details = list(
        origin = origin,
        tier = tier,
        reason = origin_validation$error
      ),
      code = 403,
      timestamp = Sys.time()
    )
    
    return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
  }
  
  # Continue processing if CORS validation passed
  plumber::forward()
}

# Initialization function
initialize_cors_system <- function() {
  # Ensure required tables exist
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    cors_schema <- "
      CREATE TABLE IF NOT EXISTS cors_log (
        id SERIAL PRIMARY KEY,
        api_key_id INTEGER DEFAULT 0,
        origin VARCHAR(255),
        api_tier VARCHAR(50),
        event_type VARCHAR(100),
        cors_allowed BOOLEAN DEFAULT false,
        details JSONB,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE INDEX IF NOT EXISTS idx_cors_log_timestamp ON cors_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_cors_log_origin ON cors_log(origin);
      CREATE INDEX IF NOT EXISTS idx_cors_log_tier ON cors_log(api_tier);
    "
    
    tryCatch({
      DBI::dbExecute(secure_db_pool, cors_schema)
      cat("✅ CORS logging tables initialized\n")
    }, error = function(e) {
      cat("⚠️ Failed to initialize CORS logging tables:", e$message, "\n")
    })
  }
  
  cat("✅ Comprehensive CORS Configuration System initialized\n")
  cat("  🌐 Multi-tier CORS validation enabled\n")
  cat("  🏛️ Brazilian academic domain whitelist active\n")
  cat("  🔒 Security validation and logging enabled\n")
  cat("  📊 CORS analytics and monitoring active\n")
  cat("  ⚖️ LGPD-compliant cross-origin policies enabled\n")
  
  return(TRUE)
}

# Auto-initialize
initialize_cors_system()

# Export functions for external use
log_cors_event <- CORSAnalytics$log_cors_event

cat("✅ Comprehensive CORS Configuration Loaded\n")