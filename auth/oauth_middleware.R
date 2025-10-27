# OAuth Middleware for Monitor Legislativo v4
# ==========================================
# Production-ready OAuth authentication system for Railway deployment
# Supports Google and Microsoft OAuth providers with enterprise security

library(httr)
library(jsonlite)
library(digest)
library(uuid)

# OAuth Configuration Manager
# ===========================

#' Initialize OAuth configuration from config.yml
#' @param config Configuration object loaded from config.yml
#' @return List of OAuth configurations
init_oauth_config <- function(config = NULL) {
  if (is.null(config)) {
    tryCatch({
      config <- yaml::read_yaml("config/config.yml")
      env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
      config <- config[[env]]
    }, error = function(e) {
      stop("Failed to load OAuth configuration: ", e$message)
    })
  }
  
  oauth_config <- list(
    google = list(
      enabled = config$oauth$google$enabled,
      client_id = config$oauth$google$client_id,
      client_secret = config$oauth$google$client_secret,
      authorization_url = "https://accounts.google.com/o/oauth2/auth",
      token_url = "https://oauth2.googleapis.com/token",
      userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo",
      scope = "openid email profile",
      redirect_uri = paste0(config$app$base_url, "/auth/google/callback")
    ),
    microsoft = list(
      enabled = config$oauth$microsoft$enabled,
      client_id = config$oauth$microsoft$client_id,
      client_secret = config$oauth$microsoft$client_secret,
      tenant_id = config$oauth$microsoft$tenant_id,
      authorization_url = paste0("https://login.microsoftonline.com/", 
                               config$oauth$microsoft$tenant_id, 
                               "/oauth2/v2.0/authorize"),
      token_url = paste0("https://login.microsoftonline.com/", 
                        config$oauth$microsoft$tenant_id, 
                        "/oauth2/v2.0/token"),
      userinfo_url = "https://graph.microsoft.com/v1.0/me",
      scope = "openid email profile User.Read",
      redirect_uri = paste0(config$app$base_url, "/auth/microsoft/callback")
    ),
    security = config$security
  )
  
  return(oauth_config)
}

# Session Management System
# ========================

#' Generate secure session token
#' @return Character string containing secure session token
generate_session_token <- function() {
  paste0(
    digest(paste(Sys.time(), runif(1), sep = "_"), algo = "sha256"),
    "_",
    UUIDgenerate()
  )
}

#' Create user session
#' @param user_info List containing user information from OAuth provider
#' @param provider Character string indicating OAuth provider ("google" or "microsoft")
#' @param session Shiny session object
#' @param oauth_config OAuth configuration list
#' @return List containing session information
create_user_session <- function(user_info, provider, session, oauth_config) {
  session_token <- generate_session_token()
  
  # Extract user information based on provider
  if (provider == "google") {
    user_data <- list(
      id = user_info$id,
      email = user_info$email,
      name = user_info$name,
      picture = user_info$picture,
      provider = "google",
      verified_email = user_info$verified_email
    )
  } else if (provider == "microsoft") {
    user_data <- list(
      id = user_info$id,
      email = user_info$mail %||% user_info$userPrincipalName,
      name = user_info$displayName,
      picture = NULL, # Microsoft Graph requires separate call for photo
      provider = "microsoft",
      verified_email = TRUE # Microsoft accounts are pre-verified
    )
  }
  
  # Determine user role (implement your role logic here)
  user_data$role <- determine_user_role(user_data$email)
  
  # Create session data
  session_data <- list(
    token = session_token,
    user = user_data,
    created_at = Sys.time(),
    last_activity = Sys.time(),
    expires_at = Sys.time() + (oauth_config$security$session_timeout_hours * 3600),
    ip_address = session$clientData$ip_address %||% "unknown"
  )
  
  # Store session (implement secure storage)
  store_user_session(session_token, session_data)
  
  # Set session cookies/tokens
  session$userData$auth_token <- session_token
  session$userData$user_info <- user_data
  session$userData$authenticated <- TRUE
  
  # Log authentication event
  log_auth_event("login", user_data, session)
  
  return(session_data)
}

#' Determine user role based on email domain or other criteria
#' @param email User email address
#' @return Character string indicating user role
determine_user_role <- function(email) {
  # Implement your role determination logic
  # Example: Check email domains for institutional access
  if (grepl("@mackenzie\\.br$", email, ignore.case = TRUE)) {
    return("admin")
  } else if (grepl("@(edu\\.|ac\\.|university|mackenzie)", email, ignore.case = TRUE)) {
    return("researcher")
  } else {
    return("user")
  }
}

#' Store user session securely
#' @param session_token Session token
#' @param session_data Session data to store
store_user_session <- function(session_token, session_data) {
  # In production, use Redis or secure database storage
  # For now, using environment variables (temporary solution)
  
  # Create session storage directory if it doesn't exist
  session_dir <- "cache/sessions"
  if (!dir.exists(session_dir)) {
    dir.create(session_dir, recursive = TRUE, mode = "0700")
  }
  
  # Store session data securely
  session_file <- file.path(session_dir, paste0(session_token, ".rds"))
  saveRDS(session_data, session_file)
  
  # Set restrictive permissions
  tryCatch({
    Sys.chmod(session_file, "600")
  }, error = function(e) {
    # Windows doesn't support chmod - skip silently
  })
}

#' Retrieve user session
#' @param session_token Session token
#' @return Session data or NULL if not found/expired
get_user_session <- function(session_token) {
  if (isTRUE(is.null(session_token)) || session_token == "") {
    return(NULL)
  }
  
  session_file <- file.path("cache/sessions", paste0(session_token, ".rds"))
  
  if (!file.exists(session_file)) {
    return(NULL)
  }
  
  tryCatch({
    session_data <- readRDS(session_file)
    
    # Check if session is expired
    if (Sys.time() > session_data$expires_at) {
      # Clean up expired session
      unlink(session_file)
      return(NULL)
    }
    
    # Check inactivity timeout
    inactivity_timeout <- 2 * 3600  # 2 hours default
    if (Sys.time() - session_data$last_activity > inactivity_timeout) {
      unlink(session_file)
      return(NULL)
    }
    
    # Update last activity
    session_data$last_activity <- Sys.time()
    saveRDS(session_data, session_file)
    
    return(session_data)
  }, error = function(e) {
    return(NULL)
  })
}

#' Validate user session
#' @param session Shiny session object
#' @return Boolean indicating if session is valid
validate_user_session <- function(session) {
  auth_token <- session$userData$auth_token
  
  if (is.null(auth_token)) {
    return(FALSE)
  }
  
  session_data <- get_user_session(auth_token)
  
  if (is.null(session_data)) {
    # Clear invalid session data
    session$userData$auth_token <- NULL
    session$userData$user_info <- NULL
    session$userData$authenticated <- FALSE
    return(FALSE)
  }
  
  # Update session data in Shiny session
  session$userData$user_info <- session_data$user
  session$userData$authenticated <- TRUE
  
  return(TRUE)
}

#' Destroy user session
#' @param session Shiny session object
destroy_user_session <- function(session) {
  auth_token <- session$userData$auth_token
  
  if (!is.null(auth_token)) {
    # Remove session file
    session_file <- file.path("cache/sessions", paste0(auth_token, ".rds"))
    if (file.exists(session_file)) {
      unlink(session_file)
    }
    
    # Log logout event
    if (!is.null(session$userData$user_info)) {
      log_auth_event("logout", session$userData$user_info, session)
    }
  }
  
  # Clear session data
  session$userData$auth_token <- NULL
  session$userData$user_info <- NULL
  session$userData$authenticated <- FALSE
}

# OAuth Flow Implementation
# ========================

#' Generate OAuth authorization URL
#' @param provider OAuth provider ("google" or "microsoft")
#' @param oauth_config OAuth configuration
#' @param session Shiny session object (for CSRF protection)
#' @return Authorization URL
generate_oauth_url <- function(provider, oauth_config, session) {
  config <- oauth_config[[provider]]
  
  if (!config$enabled) {
    stop(paste("OAuth provider", provider, "is not enabled"))
  }
  
  # Generate state parameter for CSRF protection
  state <- generate_session_token()
  session$userData$oauth_state <- state
  
  # Build authorization URL
  params <- list(
    client_id = config$client_id,
    response_type = "code",
    scope = config$scope,
    redirect_uri = config$redirect_uri,
    state = state,
    access_type = "offline"  # For refresh tokens
  )
  
  if (provider == "google") {
    params$prompt <- "consent"
  }
  
  query_string <- paste(
    names(params),
    sapply(params, URLencode, reserved = TRUE),
    sep = "=",
    collapse = "&"
  )
  
  return(paste0(config$authorization_url, "?", query_string))
}

#' Exchange authorization code for access token
#' @param provider OAuth provider
#' @param code Authorization code
#' @param oauth_config OAuth configuration
#' @return Token response or NULL on failure
exchange_code_for_token <- function(provider, code, oauth_config) {
  config <- oauth_config[[provider]]
  
  tryCatch({
    response <- POST(
      config$token_url,
      body = list(
        grant_type = "authorization_code",
        client_id = config$client_id,
        client_secret = config$client_secret,
        redirect_uri = config$redirect_uri,
        code = code
      ),
      encode = "form",
      add_headers(
        "Accept" = "application/json",
        "Content-Type" = "application/x-www-form-urlencoded"
      )
    )
    
    if (status_code(response) == 200) {
      return(content(response, "parsed"))
    } else {
      warning(paste("Token exchange failed:", status_code(response), content(response, "text")))
      return(NULL)
    }
  }, error = function(e) {
    warning(paste("Token exchange error:", e$message))
    return(NULL)
  })
}

#' Fetch user information using access token
#' @param provider OAuth provider
#' @param access_token Access token
#' @param oauth_config OAuth configuration
#' @return User information or NULL on failure
fetch_user_info <- function(provider, access_token, oauth_config) {
  config <- oauth_config[[provider]]
  
  tryCatch({
    response <- GET(
      config$userinfo_url,
      add_headers(
        Authorization = paste("Bearer", access_token),
        Accept = "application/json"
      )
    )
    
    if (status_code(response) == 200) {
      return(content(response, "parsed"))
    } else {
      warning(paste("User info fetch failed:", status_code(response)))
      return(NULL)
    }
  }, error = function(e) {
    warning(paste("User info fetch error:", e$message))
    return(NULL)
  })
}

# Role-Based Access Control
# ========================

#' Check if user has required role
#' @param session Shiny session object
#' @param required_role Required role for access
#' @return Boolean indicating if user has required role
check_user_role <- function(session, required_role) {
  if (!session$userData$authenticated) {
    return(FALSE)
  }
  
  user_role <- session$userData$user_info$role
  
  # Role hierarchy: admin > researcher > user
  role_levels <- list(user = 1, researcher = 2, admin = 3)
  
  user_level <- role_levels[[user_role]] %||% 0
  required_level <- role_levels[[required_role]] %||% 99
  
  return(user_level >= required_level)
}

#' Require authentication for access
#' @param session Shiny session object
#' @param redirect_url URL to redirect to after authentication
require_auth <- function(session, redirect_url = NULL) {
  if (!validate_user_session(session)) {
    # Store redirect URL for post-authentication redirect
    if (!is.null(redirect_url)) {
      session$userData$post_auth_redirect <- redirect_url
    }
    return(FALSE)
  }
  return(TRUE)
}

# Utility Functions
# ================

#' Null coalescing operator
#' @param x First value
#' @param y Second value (used if x is NULL)
`%||%` <- function(x, y) {
  if (is.null(x)) y else x
}

#' Log authentication events
#' @param event Event type ("login", "logout", "access_denied")
#' @param user_info User information
#' @param session Shiny session object
log_auth_event <- function(event, user_info, session) {
  log_entry <- list(
    timestamp = Sys.time(),
    event = event,
    user_id = user_info$id %||% "unknown",
    email = user_info$email %||% "unknown",
    provider = user_info$provider %||% "unknown",
    ip_address = session$clientData$ip_address %||% "unknown",
    user_agent = "session_authenticated"
  )
  
  # Create logs directory if it doesn't exist
  if (!dir.exists("logs")) {
    dir.create("logs", recursive = TRUE)
  }
  
  # Write to audit log
  audit_log_file <- file.path("logs", "auth_audit.log")
  
  tryCatch({
    log_line <- paste(
      format(log_entry$timestamp, "%Y-%m-%d %H:%M:%S"),
      log_entry$event,
      log_entry$email,
      log_entry$provider,
      log_entry$ip_address,
      sep = " | "
    )
    
    write(log_line, file = audit_log_file, append = TRUE)
  }, error = function(e) {
    # Silent error handling for logging
  })
}

#' Clean up expired sessions (maintenance function)
cleanup_expired_sessions <- function() {
  session_dir <- "cache/sessions"
  
  if (!dir.exists(session_dir)) {
    return()
  }
  
  session_files <- list.files(session_dir, pattern = "\\.rds$", full.names = TRUE)
  
  for (file in session_files) {
    tryCatch({
      session_data <- readRDS(file)
      if (Sys.time() > session_data$expires_at) {
        unlink(file)
      }
    }, error = function(e) {
      # Remove corrupted session files
      unlink(file)
    })
  }
}

# Initialize OAuth system
# ======================

#' Initialize OAuth middleware
#' @param config Configuration object
init_oauth_middleware <- function(config = NULL) {
  # Load configuration
  oauth_config <<- init_oauth_config(config)
  
  # Create necessary directories
  if (!dir.exists("cache/sessions")) {
    dir.create("cache/sessions", recursive = TRUE, mode = "0700")
  }
  
  if (!dir.exists("logs")) {
    dir.create("logs", recursive = TRUE)
  }
  
  # Schedule periodic cleanup (in a real app, use a proper scheduler)
  # For now, just clean up on init
  cleanup_expired_sessions()
  
  cat("✅ OAuth middleware initialized successfully\n")
  cat("   Google OAuth:", if(oauth_config$google$enabled) "ENABLED" else "DISABLED", "\n")
  cat("   Microsoft OAuth:", if(oauth_config$microsoft$enabled) "ENABLED" else "DISABLED", "\n")
  
  return(oauth_config)
}

# Export key functions for use in the main app
oauth_middleware <- list(
  init = init_oauth_middleware,
  generate_oauth_url = generate_oauth_url,
  exchange_code_for_token = exchange_code_for_token,
  fetch_user_info = fetch_user_info,
  create_user_session = create_user_session,
  validate_user_session = validate_user_session,
  destroy_user_session = destroy_user_session,
  check_user_role = check_user_role,
  require_auth = require_auth,
  cleanup_expired_sessions = cleanup_expired_sessions
)