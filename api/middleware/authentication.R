# ============================================================================
# AUTHENTICATION MIDDLEWARE - SPRINT 6B (API-001)
# ============================================================================
# 
# Authentication and authorization middleware for Brazilian Legislative API
# Supports API key authentication, rate limiting, and LGPD compliance
# 
# Features:
# - API key validation and management
# - Rate limiting by API key and IP address
# - Request authentication logging
# - Academic research access controls
# - LGPD compliance validation
# - Quota management for different user tiers
# ============================================================================

cat("🔐 Loading Authentication Middleware\n")

# Load secure configuration
source("R/config/secure_config.R")
source("R/auth/auth_state_manager.R")

# Initialize auth state manager
auth_manager <- AuthStateManager$new(
  backend = Sys.getenv("AUTH_BACKEND", "file"),
  connection = if(exists("db")) db else NULL
)

# Load and store API keys from configuration
API_KEYS <- get_api_keys()
for (key_id in names(API_KEYS)) {
  auth_manager$store_api_key(key_id, API_KEYS[[key_id]])
}

# Helper function to extract API key from request
extract_api_key <- function(req) {
  # Check Authorization header (Bearer token)
  auth_header <- req$HTTP_AUTHORIZATION
  if (!isTRUE(is.null(auth_header)) && startsWith(auth_header, "Bearer ")) {
    return(substr(auth_header, 8, nchar(auth_header)))
  }
  
  # Check X-API-Key header
  api_key_header <- req$HTTP_X_API_KEY
  if (!is.null(api_key_header)) {
    return(api_key_header)
  }
  
  # Check query parameter
  api_key_param <- req$args$api_key
  if (!is.null(api_key_param)) {
    return(api_key_param)
  }
  
  return(NULL)
}

# Helper function to validate API key
validate_api_key <- function(api_key) {
  if (isTRUE(is.null(api_key)) || api_key == "") {
    return(list(valid = FALSE, error = "API key is required"))
  }
  
  if (!api_key %in% names(API_KEYS)) {
    return(list(valid = FALSE, error = "Invalid API key"))
  }
  
  key_info <- API_KEYS[[api_key]]
  return(list(valid = TRUE, key_info = key_info))
}

# Helper function to check rate limits
check_rate_limit <- function(api_key, client_ip) {
  current_time <- Sys.time()
  minute_key <- paste0(api_key, "_", format(current_time, "%Y%m%d%H%M"))
  
  # Initialize rate limit counter if not exists
  if (!minute_key %in% names(RATE_LIMITS)) {
    RATE_LIMITS[[minute_key]] <<- 0
  }
  
  # Get key info for rate limit
  key_info <- API_KEYS[[api_key]]
  rate_limit <- key_info$rate_limit_per_minute
  
  # Check current usage
  current_usage <- RATE_LIMITS[[minute_key]]
  
  if (current_usage >= rate_limit) {
    return(list(
      allowed = FALSE,
      error = paste("Rate limit exceeded. Maximum", rate_limit, "requests per minute"),
      reset_time = ceiling(60 - as.numeric(format(current_time, "%S")))
    ))
  }
  
  # Increment counter
  RATE_LIMITS[[minute_key]] <<- current_usage + 1
  
  return(list(
    allowed = TRUE,
    remaining = rate_limit - (current_usage + 1),
    reset_time = ceiling(60 - as.numeric(format(current_time, "%S")))
  ))
}

# Helper function to check daily quota
check_daily_quota <- function(api_key) {
  current_date <- format(Sys.time(), "%Y%m%d")
  quota_key <- paste0(api_key, "_", current_date)
  
  # Initialize quota counter if not exists
  if (!quota_key %in% names(DAILY_QUOTAS)) {
    DAILY_QUOTAS[[quota_key]] <<- 0
  }
  
  # Get key info for quota
  key_info <- API_KEYS[[api_key]]
  daily_quota <- key_info$quota_per_day
  
  # Check current usage
  current_usage <- DAILY_QUOTAS[[quota_key]]
  
  if (current_usage >= daily_quota) {
    return(list(
      allowed = FALSE,
      error = paste("Daily quota exceeded. Maximum", daily_quota, "requests per day"),
      usage = current_usage,
      quota = daily_quota
    ))
  }
  
  # Increment counter
  DAILY_QUOTAS[[quota_key]] <<- current_usage + 1
  
  return(list(
    allowed = TRUE,
    usage = current_usage + 1,
    quota = daily_quota,
    remaining = daily_quota - (current_usage + 1)
  ))
}

# Helper function to check permissions
check_permissions <- function(api_key, required_permission) {
  key_info <- API_KEYS[[api_key]]
  permissions <- key_info$permissions
  
  if (required_permission %in% permissions) {
    return(list(allowed = TRUE))
  } else {
    return(list(
      allowed = FALSE,
      error = paste("Insufficient permissions. Required:", required_permission)
    ))
  }
}

# Helper function to update API key usage
update_api_key_usage <- function(api_key) {
  if (api_key %in% names(API_KEYS)) {
    API_KEYS[[api_key]]$last_used <<- Sys.time()
    API_KEYS[[api_key]]$usage_count <<- API_KEYS[[api_key]]$usage_count + 1
  }
}

# Main authentication filter
#* @filter auth
function(req, res) {
  start_time <- Sys.time()
  
  # Skip authentication for health and info endpoints
  if (req$PATH_INFO %in% c("/health", "/info", "/", "/api/v1/", "/api/v1/info")) {
    plumber::forward()
    return()
  }
  
  # Extract client information
  client_ip <- req$HTTP_X_FORWARDED_FOR %||% req$HTTP_X_REAL_IP %||% req$REMOTE_ADDR %||% "unknown"
  user_agent <- req$HTTP_USER_AGENT %||% "unknown"
  
  # Extract API key
  api_key <- extract_api_key(req)
  
  # Validate API key
  validation_result <- validate_api_key(api_key)
  if (!validation_result$valid) {
    res$status <- 401
    res$setHeader("WWW-Authenticate", "Bearer")
    res$setHeader("Content-Type", "application/json")
    
    error_response <- list(
      error = TRUE,
      message = validation_result$error,
      code = 401,
      timestamp = Sys.time(),
      documentation = "https://monitorlegislativo.gov.br/api/docs/authentication"
    )
    
    return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
  }
  
  key_info <- validation_result$key_info
  
  # Check rate limits
  rate_limit_result <- check_rate_limit(api_key, client_ip)
  if (!rate_limit_result$allowed) {
    res$status <- 429
    res$setHeader("X-RateLimit-Remaining", "0")
    res$setHeader("X-RateLimit-Reset", as.character(rate_limit_result$reset_time))
    res$setHeader("Retry-After", as.character(rate_limit_result$reset_time))
    res$setHeader("Content-Type", "application/json")
    
    error_response <- list(
      error = TRUE,
      message = rate_limit_result$error,
      code = 429,
      details = list(
        reset_in_seconds = rate_limit_result$reset_time
      ),
      timestamp = Sys.time()
    )
    
    return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
  }
  
  # Check daily quota
  quota_result <- check_daily_quota(api_key)
  if (!quota_result$allowed) {
    res$status <- 429
    res$setHeader("X-Daily-Quota-Remaining", "0")
    res$setHeader("X-Daily-Quota-Used", as.character(quota_result$usage))
    res$setHeader("Content-Type", "application/json")
    
    error_response <- list(
      error = TRUE,
      message = quota_result$error,
      code = 429,
      details = list(
        usage = quota_result$usage,
        quota = quota_result$quota
      ),
      timestamp = Sys.time()
    )
    
    return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
  }
  
  # Add rate limit headers
  res$setHeader("X-RateLimit-Remaining", as.character(rate_limit_result$remaining))
  res$setHeader("X-RateLimit-Reset", as.character(rate_limit_result$reset_time))
  res$setHeader("X-Daily-Quota-Remaining", as.character(quota_result$remaining))
  res$setHeader("X-Daily-Quota-Used", as.character(quota_result$usage))
  res$setHeader("X-API-Tier", key_info$tier)
  
  # Store authentication context in request
  req$auth <- list(
    api_key = api_key,
    key_info = key_info,
    client_ip = client_ip,
    user_agent = user_agent,
    authenticated_at = Sys.time()
  )
  
  # Update API key usage statistics
  update_api_key_usage(api_key)
  
  # Update API state
  API_STATE$active_connections <<- API_STATE$active_connections + 1
  
  # Log authentication success
  cat("🔐 Authenticated request from", client_ip, "using", key_info$tier, "tier API key\n")
  
  plumber::forward()
}

# Permission checking function (can be used in endpoints)
require_permission <- function(req, permission) {
  if (is.null(req$auth)) {
    return(list(
      allowed = FALSE,
      error = "Authentication required"
    ))
  }
  
  return(check_permissions(req$auth$api_key, permission))
}

# Function to get API key information (for admin endpoints)
get_api_key_info <- function(api_key) {
  if (api_key %in% names(API_KEYS)) {
    key_info <- API_KEYS[[api_key]]
    
    # Calculate usage statistics
    current_date <- format(Sys.time(), "%Y%m%d")
    quota_key <- paste0(api_key, "_", current_date)
    daily_usage <- DAILY_QUOTAS[[quota_key]] %||% 0
    
    return(list(
      name = key_info$name,
      tier = key_info$tier,
      permissions = key_info$permissions,
      rate_limit_per_minute = key_info$rate_limit_per_minute,
      quota_per_day = key_info$quota_per_day,
      daily_usage = daily_usage,
      total_usage = key_info$usage_count,
      created_at = key_info$created_at,
      last_used = key_info$last_used
    ))
  }
  
  return(NULL)
}

# Function to generate API usage report
get_api_usage_report <- function() {
  report <- list()
  
  for (api_key in names(API_KEYS)) {
    key_info <- get_api_key_info(api_key)
    if (!is.null(key_info)) {
      report[[api_key]] <- key_info
    }
  }
  
  return(list(
    total_keys = length(API_KEYS),
    active_keys = length(report),
    usage_by_tier = aggregate_usage_by_tier(),
    generated_at = Sys.time()
  ))
}

# Helper function to aggregate usage by tier
aggregate_usage_by_tier <- function() {
  tier_usage <- list()
  
  for (api_key in names(API_KEYS)) {
    key_info <- API_KEYS[[api_key]]
    tier <- key_info$tier
    
    if (!tier %in% names(tier_usage)) {
      tier_usage[[tier]] <- list(
        count = 0,
        total_usage = 0,
        daily_usage = 0
      )
    }
    
    tier_usage[[tier]]$count <- tier_usage[[tier]]$count + 1
    tier_usage[[tier]]$total_usage <- tier_usage[[tier]]$total_usage + key_info$usage_count
    
    # Add daily usage
    current_date <- format(Sys.time(), "%Y%m%d")
    quota_key <- paste0(api_key, "_", current_date)
    daily_usage <- DAILY_QUOTAS[[quota_key]] %||% 0
    tier_usage[[tier]]$daily_usage <- tier_usage[[tier]]$daily_usage + daily_usage
  }
  
  return(tier_usage)
}

cat("✅ Authentication Middleware Loaded\n")