# OAuth2 Authentication System for Monitor Legislativo v4
# LGPD-Compliant User Authentication and Session Management
# Integrates with Google and Microsoft Academic accounts

library(DBI)
library(RPostgres)
library(pool)
library(httr)
library(jsonlite)
library(digest)
library(uuid)
library(shiny)
library(shinydashboard)

# Load configuration
source("utils.R")

# Global authentication state
.auth_state <- new.env(parent = emptyenv())
.auth_state$current_user <- NULL
.auth_state$current_session <- NULL
.auth_state$csrf_token <- NULL

#' OAuth2 Configuration for Academic Providers
get_oauth_config <- function(provider) {
  config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
  app_config <- config::get(config = config_env)
  
  if (provider == "google") {
    return(list(
      client_id = Sys.getenv("GOOGLE_CLIENT_ID"),
      client_secret = Sys.getenv("GOOGLE_CLIENT_SECRET"),
      auth_url = "https://accounts.google.com/o/oauth2/auth",
      token_url = "https://oauth2.googleapis.com/token",
      user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo",
      scope = "openid email profile",
      redirect_uri = paste0(Sys.getenv("APP_URL", "http://localhost:3838"), "/auth/callback")
    ))
  } else if (provider == "microsoft") {
    return(list(
      client_id = Sys.getenv("MICROSOFT_CLIENT_ID"),
      client_secret = Sys.getenv("MICROSOFT_CLIENT_SECRET"),
      auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
      token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token",
      user_info_url = "https://graph.microsoft.com/v1.0/me",
      scope = "openid email profile",
      redirect_uri = paste0(Sys.getenv("APP_URL", "http://localhost:3838"), "/auth/callback")
    ))
  }
  
  stop(paste("Unsupported OAuth provider:", provider))
}

#' Generate OAuth2 authorization URL
#' @param provider OAuth provider ('google' or 'microsoft')
#' @param state CSRF protection state parameter
#' @return Authorization URL
generate_auth_url <- function(provider, state) {
  config <- get_oauth_config(provider)
  
  params <- list(
    client_id = config$client_id,
    redirect_uri = config$redirect_uri,
    scope = config$scope,
    response_type = "code",
    state = state,
    access_type = "offline",  # For refresh tokens
    prompt = "consent"        # Force consent screen
  )
  
  # Microsoft-specific parameters
  if (provider == "microsoft") {
    params$response_mode <- "query"
  }
  
  query_string <- paste(names(params), params, sep = "=", collapse = "&")
  paste0(config$auth_url, "?", URLencode(query_string))
}

#' Exchange authorization code for access token
#' @param provider OAuth provider
#' @param auth_code Authorization code from callback
#' @return Token response or NULL on error
exchange_code_for_token <- function(provider, auth_code) {
  tryCatch({
    config <- get_oauth_config(provider)
    
    # Prepare token request
    token_request <- list(
      grant_type = "authorization_code",
      client_id = config$client_id,
      client_secret = config$client_secret,
      redirect_uri = config$redirect_uri,
      code = auth_code
    )
    
    # Exchange code for token
    response <- POST(
      config$token_url,
      body = token_request,
      encode = "form",
      add_headers("Content-Type" = "application/x-www-form-urlencoded")
    )
    
    if (status_code(response) == 200) {
      token_data <- content(response, "parsed")
      log_event(paste("OAuth2 token exchange successful for provider:", provider))
      return(token_data)
    } else {
      log_event(paste("OAuth2 token exchange failed:", status_code(response)), "ERROR")
      return(NULL)
    }
    
  }, error = function(e) {
    log_event(paste("OAuth2 token exchange error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Get user information from OAuth provider
#' @param provider OAuth provider
#' @param access_token Access token
#' @return User information or NULL on error
get_user_info <- function(provider, access_token) {
  tryCatch({
    config <- get_oauth_config(provider)
    
    response <- GET(
      config$user_info_url,
      add_headers(Authorization = paste("Bearer", access_token))
    )
    
    if (status_code(response) == 200) {
      user_data <- content(response, "parsed")
      
      # Standardize user data format
      if (provider == "google") {
        return(list(
          email = user_data$email,
          full_name = user_data$name,
          avatar_url = user_data$picture,
          oauth_subject_id = user_data$id,
          email_verified = user_data$verified_email %||% FALSE
        ))
      } else if (provider == "microsoft") {
        return(list(
          email = user_data$mail %||% user_data$userPrincipalName,
          full_name = user_data$displayName,
          avatar_url = NULL,  # Microsoft Graph requires separate call
          oauth_subject_id = user_data$id,
          email_verified = TRUE  # Microsoft accounts are pre-verified
        ))
      }
    } else {
      log_event(paste("Failed to get user info:", status_code(response)), "ERROR")
      return(NULL)
    }
    
  }, error = function(e) {
    log_event(paste("Get user info error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Create or update user in database
#' @param user_info User information from OAuth provider
#' @param provider OAuth provider name
#' @return User record or NULL on error
create_or_update_user <- function(user_info, provider) {
  if (is.null(.db_pool)) {
    log_event("Database not initialized for user creation", "ERROR")
    return(NULL)
  }
  
  tryCatch({
    # Check if user exists
    existing_user <- dbGetQuery(.db_pool, 
      "SELECT * FROM users WHERE oauth_provider = $1 AND oauth_subject_id = $2",
      params = list(provider, user_info$oauth_subject_id)
    )
    
    if (nrow(existing_user) > 0) {
      # Update existing user
      user_id <- existing_user$id[1]
      
      dbExecute(.db_pool,
        "UPDATE users SET 
         email = $1, full_name = $2, avatar_url = $3, 
         email_verified = $4, last_login = CURRENT_TIMESTAMP,
         updated_at = CURRENT_TIMESTAMP
         WHERE id = $5",
        params = list(
          user_info$email, user_info$full_name, user_info$avatar_url,
          user_info$email_verified, user_id
        )
      )
      
      log_event(paste("Updated existing user:", user_info$email))
      
    } else {
      # Create new user - requires LGPD consent
      user_id <- UUIDgenerate()
      
      # Extract institutional affiliation from email domain
      email_domain <- sub(".*@", "", user_info$email)
      
      # Get institutional info if available
      institution_info <- dbGetQuery(.db_pool,
        "SELECT institution_name FROM trusted_domains WHERE domain = $1",
        params = list(email_domain)
      )
      
      institutional_affiliation <- if (nrow(institution_info) > 0) {
        institution_info$institution_name[1]
      } else {
        NULL
      }
      
      # Insert new user with default LGPD consent (will need explicit consent)
      dbExecute(.db_pool,
        "INSERT INTO users (
          id, email, full_name, institutional_affiliation, oauth_provider, 
          oauth_subject_id, avatar_url, email_verified, consent_version,
          data_processing_consent, marketing_consent
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        params = list(
          user_id, user_info$email, user_info$full_name,
          institutional_affiliation, provider, user_info$oauth_subject_id,
          user_info$avatar_url, user_info$email_verified, "1.0",
          FALSE, FALSE  # Require explicit consent
        )
      )
      
      log_event(paste("Created new user:", user_info$email))
    }
    
    # Get complete user record with roles
    user_record <- dbGetQuery(.db_pool,
      "SELECT u.*, array_agg(ur.role_name) as roles,
              array_agg(ur.permissions) as role_permissions
       FROM users u
       LEFT JOIN user_role_assignments ura ON u.id = ura.user_id AND ura.is_active = true
       LEFT JOIN user_roles ur ON ura.role_id = ur.id
       WHERE u.id = $1
       GROUP BY u.id",
      params = list(user_id)
    )
    
    return(user_record)
    
  }, error = function(e) {
    log_event(paste("User creation/update error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Create secure session for authenticated user
#' @param user_record User database record
#' @param token_data OAuth token data
#' @param request_info Request information (IP, User-Agent)
#' @return Session information or NULL on error
create_user_session <- function(user_record, token_data, request_info = list()) {
  if (is.null(.db_pool)) {
    return(NULL)
  }
  
  tryCatch({
    # Generate secure session ID and CSRF token
    session_id <- digest(paste(UUIDgenerate(), Sys.time(), runif(1)), algo = "sha256")
    csrf_token <- digest(paste(UUIDgenerate(), session_id), algo = "sha256")
    
    # Hash tokens for database storage
    access_token_hash <- if (!is.null(token_data$access_token)) {
      digest(token_data$access_token, algo = "sha256")
    } else NULL
    
    refresh_token_hash <- if (!is.null(token_data$refresh_token)) {
      digest(token_data$refresh_token, algo = "sha256")
    } else NULL
    
    # Calculate session expiry (8 hours default)
    expires_at <- Sys.time() + as.difftime(8, units = "hours")
    
    # Create session record
    dbExecute(.db_pool,
      "INSERT INTO user_sessions (
        session_id, user_id, access_token_hash, refresh_token_hash,
        csrf_token, ip_address, user_agent, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      params = list(
        session_id, user_record$id[1], access_token_hash, refresh_token_hash,
        csrf_token, request_info$ip_address, request_info$user_agent, expires_at
      )
    )
    
    # Clean up old sessions for this user (keep last 5)
    dbExecute(.db_pool,
      "UPDATE user_sessions SET is_active = false, revoked_reason = 'replaced'
       WHERE user_id = $1 AND session_id != $2 AND is_active = true
       AND session_id NOT IN (
         SELECT session_id FROM user_sessions 
         WHERE user_id = $1 AND is_active = true 
         ORDER BY created_at DESC LIMIT 5
       )",
      params = list(user_record$id[1], session_id)
    )
    
    session_info <- list(
      session_id = session_id,
      csrf_token = csrf_token,
      user_id = user_record$id[1],
      expires_at = expires_at
    )
    
    log_event(paste("Created session for user:", user_record$email[1]))
    return(session_info)
    
  }, error = function(e) {
    log_event(paste("Session creation error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Validate user session
#' @param session_id Session identifier
#' @param csrf_token CSRF token for validation
#' @return User information or NULL if invalid
validate_session <- function(session_id, csrf_token = NULL) {
  if (is.null(.db_pool) || is.null(session_id)) {
    return(NULL)
  }
  
  tryCatch({
    # Get session with user information
    session_query <- "
      SELECT s.*, u.email, u.full_name, u.institutional_affiliation,
             u.account_status, u.data_processing_consent,
             array_agg(ur.role_name) as roles,
             string_agg(ur.permissions::text, '|||') as permissions_json
      FROM user_sessions s
      JOIN users u ON s.user_id = u.id
      LEFT JOIN user_role_assignments ura ON u.id = ura.user_id AND ura.is_active = true
      LEFT JOIN user_roles ur ON ura.role_id = ur.id
      WHERE s.session_id = $1 AND s.is_active = true 
      AND s.expires_at > CURRENT_TIMESTAMP
      AND u.account_status = 'active'
      GROUP BY s.session_id, s.user_id, s.access_token_hash, s.refresh_token_hash,
               s.csrf_token, s.ip_address, s.user_agent, s.created_at,
               s.last_activity, s.expires_at, s.is_active, s.revoked_at,
               s.revoked_reason, u.email, u.full_name, u.institutional_affiliation,
               u.account_status, u.data_processing_consent
    "
    
    session_data <- dbGetQuery(.db_pool, session_query, params = list(session_id))
    
    if (nrow(session_data) == 0) {
      return(NULL)
    }
    
    session_record <- session_data[1, ]
    
    # Validate CSRF token if provided
    if (!is.null(csrf_token) && session_record$csrf_token != csrf_token) {
      log_event("CSRF token validation failed", "WARN")
      return(NULL)
    }
    
    # Check if user has given data processing consent (LGPD requirement)
    if (!session_record$data_processing_consent) {
      log_event("User has not given LGPD data processing consent", "WARN")
      # Still return user info but flag needs consent
      session_record$needs_consent <- TRUE
    }
    
    # Update last activity
    dbExecute(.db_pool,
      "UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = $1",
      params = list(session_id)
    )
    
    # Parse permissions
    if (!is.na(session_record$permissions_json) && session_record$permissions_json != "") {
      permissions_list <- strsplit(session_record$permissions_json, "\\|\\|\\|")[[1]]
      session_record$permissions <- lapply(permissions_list, function(p) {
        tryCatch(fromJSON(p), error = function(e) list())
      })
    } else {
      session_record$permissions <- list()
    }
    
    log_event(paste("Session validated for user:", session_record$email))
    return(session_record)
    
  }, error = function(e) {
    log_event(paste("Session validation error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Log user data access for LGPD compliance
#' @param user_id User identifier
#' @param session_id Session identifier
#' @param action_type Type of action performed
#' @param resource_type Type of resource accessed
#' @param resource_ids List of resource IDs
#' @param search_criteria Search terms used
log_data_access <- function(user_id, session_id, action_type, resource_type, 
                           resource_ids = NULL, search_criteria = NULL) {
  if (is.null(.db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    dbExecute(.db_pool,
      "INSERT INTO data_access_log (
        user_id, session_id, action_type, resource_type,
        resource_ids, search_criteria, legal_basis
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
      params = list(
        user_id, session_id, action_type, resource_type,
        resource_ids, search_criteria, "legitimate_interest"
      )
    )
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Data access logging error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Revoke user session (logout)
#' @param session_id Session to revoke
#' @param reason Reason for revocation
revoke_session <- function(session_id, reason = "user_logout") {
  if (is.null(.db_pool) || is.null(session_id)) {
    return(FALSE)
  }
  
  tryCatch({
    dbExecute(.db_pool,
      "UPDATE user_sessions 
       SET is_active = false, revoked_at = CURRENT_TIMESTAMP, revoked_reason = $2
       WHERE session_id = $1",
      params = list(session_id, reason)
    )
    
    log_event(paste("Session revoked:", session_id, "- reason:", reason))
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Session revocation error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Check if user has specific permission
#' @param user_session User session information
#' @param permission Permission to check
#' @return TRUE if user has permission
has_permission <- function(user_session, permission) {
  if (is.null(user_session) || is.null(user_session$permissions)) {
    return(FALSE)
  }
  
  # Check each role's permissions
  for (role_perms in user_session$permissions) {
    if (is.list(role_perms) && isTRUE(role_perms[[permission]])) {
      return(TRUE)
    }
  }
  
  return(FALSE)
}

#' Get current authenticated user
get_current_user <- function() {
  return(.auth_state$current_user)
}

#' Set current authenticated user
set_current_user <- function(user_session) {
  .auth_state$current_user <- user_session
  .auth_state$current_session <- user_session$session_id
  .auth_state$csrf_token <- user_session$csrf_token
}

#' Clear current authentication state
clear_auth_state <- function() {
  .auth_state$current_user <- NULL
  .auth_state$current_session <- NULL
  .auth_state$csrf_token <- NULL
}

#' LGPD: Record user consent
#' @param user_id User identifier
#' @param consent_type Type of consent
#' @param consent_given Boolean consent status
record_lgpd_consent <- function(user_id, consent_type, consent_given) {
  if (is.null(.db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    if (consent_type == "data_processing") {
      dbExecute(.db_pool,
        "UPDATE users 
         SET data_processing_consent = $2, last_consent_update = CURRENT_TIMESTAMP
         WHERE id = $1",
        params = list(user_id, consent_given)
      )
    } else if (consent_type == "marketing") {
      dbExecute(.db_pool,
        "UPDATE users 
         SET marketing_consent = $2, last_consent_update = CURRENT_TIMESTAMP
         WHERE id = $1",
        params = list(user_id, consent_given)
      )
    }
    
    # Log consent change
    log_data_access(user_id, NULL, "consent_update", "user_profile", NULL, 
                   paste("consent_type:", consent_type, "consent_given:", consent_given))
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Consent recording error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Initialize authentication system
init_auth_system <- function() {
  tryCatch({
    # Verify OAuth configuration
    google_configured <- nchar(Sys.getenv("GOOGLE_CLIENT_ID")) > 0
    microsoft_configured <- nchar(Sys.getenv("MICROSOFT_CLIENT_ID")) > 0
    
    if (!google_configured && !microsoft_configured) {
      log_event("No OAuth providers configured", "WARN")
      return(FALSE)
    }
    
    # Verify database tables exist
    if (!is.null(.db_pool)) {
      tables_check <- dbGetQuery(.db_pool,
        "SELECT table_name FROM information_schema.tables 
         WHERE table_schema = 'public' AND table_name IN ('users', 'user_sessions', 'user_roles')"
      )
      
      if (nrow(tables_check) < 3) {
        log_event("Authentication database tables not found", "ERROR")
        return(FALSE)
      }
    }
    
    log_event("Authentication system initialized successfully")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Auth system initialization error:", e$message), "ERROR")
    return(FALSE)
  })
}

# Cleanup function for expired sessions and data (LGPD compliance)
cleanup_expired_data <- function() {
  if (is.null(.db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    # Clean expired sessions
    expired_sessions <- dbGetQuery(.db_pool, "SELECT cleanup_expired_sessions()")
    log_event(paste("Cleaned", expired_sessions[[1]], "expired sessions"))
    
    # Clean old access logs (older than 5 years per LGPD)
    old_logs <- dbExecute(.db_pool,
      "DELETE FROM data_access_log WHERE timestamp < (CURRENT_TIMESTAMP - INTERVAL '5 years')"
    )
    
    # Process data retention cleanup
    retention_cleanup <- dbGetQuery(.db_pool, "SELECT cleanup_expired_data()")
    log_event(paste("LGPD retention cleanup processed", retention_cleanup[[1]], "records"))
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Cleanup error:", e$message), "ERROR")
    return(FALSE)
  })
}

log_event("OAuth2 Authentication System loaded - LGPD compliant")