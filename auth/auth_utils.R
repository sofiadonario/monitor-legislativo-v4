# Authentication Utilities for Monitor Legislativo v4
# ===================================================
# Helper functions for authentication integration

library(shiny)
library(yaml)

# Configuration and Initialization
# ===============================

#' Load and validate authentication configuration
#' @return List containing validated auth configuration
load_auth_config <- function() {
  tryCatch({
    # Load configuration
    config <- yaml::read_yaml("config/config.yml")
    env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
    config <- config[[env]]
    
    # Validate OAuth configuration
    auth_config <- list(
      enabled = FALSE,
      google_enabled = FALSE,
      microsoft_enabled = FALSE,
      config = config
    )
    
    # Check Google OAuth
    if (!is.null(config$oauth$google) && 
        nchar(config$oauth$google$client_id) > 0 && 
        nchar(config$oauth$google$client_secret) > 0) {
      auth_config$google_enabled <- TRUE
      auth_config$enabled <- TRUE
    }
    
    # Check Microsoft OAuth
    if (!is.null(config$oauth$microsoft) && 
        nchar(config$oauth$microsoft$client_id) > 0 && 
        nchar(config$oauth$microsoft$client_secret) > 0) {
      auth_config$microsoft_enabled <- TRUE
      auth_config$enabled <- TRUE
    }
    
    return(auth_config)
    
  }, error = function(e) {
    warning("Failed to load auth configuration: ", e$message)
    return(list(
      enabled = FALSE,
      google_enabled = FALSE,
      microsoft_enabled = FALSE,
      config = NULL,
      error = e$message
    ))
  })
}

#' Initialize authentication system
#' @return Authentication configuration object
init_auth_system <- function() {
  
  # Load configuration
  auth_config <- load_auth_config()
  
  if (!auth_config$enabled) {
    cat("⚠️ OAuth authentication is disabled - no valid providers configured\n")
    cat("   To enable authentication, configure OAuth providers in config/config.yml\n")
    cat("   Required environment variables:\n")
    cat("   - GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET (for Google OAuth)\n")
    cat("   - MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET (for Microsoft OAuth)\n")
    return(auth_config)
  }
  
  # Load authentication modules
  tryCatch({
    source("auth/oauth_middleware.R", local = TRUE)
    source("auth/login_ui.R", local = TRUE)
    
    # Initialize OAuth middleware
    oauth_config <- oauth_middleware$init(auth_config$config)
    auth_config$oauth_config <- oauth_config
    
    cat("✅ Authentication system initialized successfully\n")
    cat("   Google OAuth:", if(auth_config$google_enabled) "ENABLED" else "DISABLED", "\n")
    cat("   Microsoft OAuth:", if(auth_config$microsoft_enabled) "ENABLED" else "DISABLED", "\n")
    
    return(auth_config)
    
  }, error = function(e) {
    warning("Failed to initialize authentication system: ", e$message)
    auth_config$enabled <- FALSE
    auth_config$error <- e$message
    return(auth_config)
  })
}

# Authentication Middleware Functions
# ==================================

#' Check if user is authenticated
#' @param session Shiny session object
#' @param redirect_to_login Boolean, whether to redirect to login on failure
#' @return Boolean indicating authentication status
is_authenticated <- function(session, redirect_to_login = FALSE) {
  
  # Skip authentication if system is disabled
  if (!exists("auth_config") || !auth_config$enabled) {
    return(TRUE)
  }
  
  # Check session authentication
  authenticated <- !is.null(session$userData$authenticated) && 
                   session$userData$authenticated == TRUE
  
  if (authenticated && exists("oauth_middleware")) {
    # Validate session is still valid
    authenticated <- oauth_middleware$validate_user_session(session)
  }
  
  # Handle redirection if not authenticated
  if (!authenticated && redirect_to_login) {
    # Store current URL for post-auth redirect
    current_url <- session$clientData$url_search
    if (!is.null(current_url) && current_url != "") {
      session$userData$post_auth_redirect <- current_url
    }
    
    # Redirect to login (this will be handled by the UI logic)
    session$userData$require_login <- TRUE
  }
  
  return(authenticated)
}

#' Get current user information
#' @param session Shiny session object
#' @return User information list or NULL
get_current_user <- function(session) {
  if (!is_authenticated(session)) {
    return(NULL)
  }
  
  return(session$userData$user_info)
}

#' Check if user has required role
#' @param session Shiny session object
#' @param required_role Required role ("user", "researcher", "admin")
#' @return Boolean indicating if user has required role
has_role <- function(session, required_role) {
  if (!is_authenticated(session)) {
    return(FALSE)
  }
  
  if (exists("oauth_middleware")) {
    return(oauth_middleware$check_user_role(session, required_role))
  }
  
  # Fallback role check
  user_info <- get_current_user(session)
  if (is.null(user_info)) {
    return(FALSE)
  }
  
  user_role <- user_info$role %||% "user"
  role_levels <- list(user = 1, researcher = 2, admin = 3)
  
  user_level <- role_levels[[user_role]] %||% 0
  required_level <- role_levels[[required_role]] %||% 99
  
  return(user_level >= required_level)
}

#' Require authentication wrapper for server functions
#' @param session Shiny session object
#' @param required_role Required role (optional)
#' @param server_function Function to execute if authenticated
#' @return Result of server_function or NULL if not authenticated
require_auth <- function(session, server_function, required_role = NULL) {
  
  # Check authentication
  if (!is_authenticated(session, redirect_to_login = TRUE)) {
    return(NULL)
  }
  
  # Check role if required
  if (!is.null(required_role) && !has_role(session, required_role)) {
    showNotification(
      "Acesso negado: privilégios insuficientes.",
      type = "error",
      duration = 5
    )
    return(NULL)
  }
  
  # Execute server function
  return(server_function())
}

# UI Helper Functions
# ==================

#' Create protected UI content
#' @param session Shiny session object
#' @param authenticated_ui UI to show when authenticated
#' @param login_ui UI to show when not authenticated (optional)
#' @return Conditional UI content
protected_ui <- function(session, authenticated_ui, login_ui = NULL) {
  
  # If authentication is disabled, always show authenticated UI
  if (!exists("auth_config") || !auth_config$enabled) {
    return(authenticated_ui)
  }
  
  if (is_authenticated(session)) {
    return(authenticated_ui)
  } else {
    if (is.null(login_ui)) {
      # Use default login UI
      return(auth_module$ui("auth", auth_config$oauth_config))
    } else {
      return(login_ui)
    }
  }
}

#' Create user info header for authenticated users
#' @param session Shiny session object
#' @return HTML content for user header or empty div
user_header_ui <- function(session) {
  
  if (!is_authenticated(session)) {
    return(div())
  }
  
  user_info <- get_current_user(session)
  if (is.null(user_info)) {
    return(div())
  }
  
  # Create user info display
  div(
    class = "user-header",
    style = "display: flex; align-items: center; justify-content: space-between; padding: 10px 15px; background: #f8f9fa; border-bottom: 1px solid #dee2e6;",
    
    # User info
    div(
      style = "display: flex; align-items: center;",
      
      # Avatar
      if (!is.null(user_info$picture)) {
        img(
          src = user_info$picture,
          style = "width: 32px; height: 32px; border-radius: 50%; margin-right: 10px;",
          alt = "User Avatar"
        )
      } else {
        div(
          style = "width: 32px; height: 32px; border-radius: 50%; background: #007bff; color: white; display: flex; align-items: center; justify-content: center; margin-right: 10px; font-weight: bold; font-size: 14px;",
          substr(user_info$name, 1, 1)
        )
      },
      
      # User details
      div(
        strong(user_info$name, style = "color: #333; font-size: 14px;"),
        br(),
        span(
          paste("Função:", switch(user_info$role,
            "admin" = "Administrador",
            "researcher" = "Pesquisador", 
            "user" = "Usuário",
            "Usuário"
          )),
          style = "color: #666; font-size: 12px;"
        )
      )
    ),
    
    # Logout button
    auth_module$logout_button_ui("auth")
  )
}

# Security and Audit Functions
# ============================

#' Log user activity for audit purposes
#' @param session Shiny session object
#' @param action Action performed
#' @param details Additional details (optional)
log_user_activity <- function(session, action, details = NULL) {
  
  user_info <- get_current_user(session)
  
  log_entry <- list(
    timestamp = Sys.time(),
    action = action,
    user_id = user_info$id %||% "anonymous",
    user_email = user_info$email %||% "unknown",
    ip_address = session$clientData$ip_address %||% "unknown",
    user_agent = session$clientData$user_agent %||% "unknown",
    details = details
  )
  
  # Create logs directory if it doesn't exist
  if (!dir.exists("logs")) {
    dir.create("logs", recursive = TRUE)
  }
  
  # Write to activity log
  activity_log_file <- file.path("logs", "user_activity.log")
  
  tryCatch({
    log_line <- paste(
      format(log_entry$timestamp, "%Y-%m-%d %H:%M:%S"),
      log_entry$action,
      log_entry$user_email,
      log_entry$ip_address,
      if(!is.null(details)) paste("Details:", details) else "",
      sep = " | "
    )
    
    write(log_line, file = activity_log_file, append = TRUE)
  }, error = function(e) {
    # Silent error handling for logging
  })
}

#' Create access control wrapper for sensitive operations
#' @param session Shiny session object
#' @param operation_name Name of the operation for logging
#' @param required_role Required role for access
#' @param operation Function to execute
#' @return Result of operation or error
secure_operation <- function(session, operation_name, required_role = "user", operation) {
  
  # Log access attempt
  log_user_activity(session, paste("ACCESS_ATTEMPT", operation_name))
  
  # Check authentication and authorization
  if (!is_authenticated(session)) {
    log_user_activity(session, paste("ACCESS_DENIED", operation_name), "Not authenticated")
    showNotification("Acesso negado: autenticação necessária", type = "error")
    return(NULL)
  }
  
  if (!has_role(session, required_role)) {
    log_user_activity(session, paste("ACCESS_DENIED", operation_name), "Insufficient privileges")
    showNotification("Acesso negado: privilégios insuficientes", type = "error")
    return(NULL)
  }
  
  # Execute operation
  tryCatch({
    result <- operation()
    log_user_activity(session, paste("ACCESS_GRANTED", operation_name))
    return(result)
  }, error = function(e) {
    log_user_activity(session, paste("OPERATION_ERROR", operation_name), e$message)
    showNotification(paste("Erro na operação:", e$message), type = "error")
    return(NULL)
  })
}

# Utility Functions
# ================

#' Null coalescing operator
`%||%` <- function(x, y) {
  if (is.null(x)) y else x
}

#' Safe URL building
#' @param base_url Base URL
#' @param path Path to append
#' @return Complete URL
build_url <- function(base_url, path) {
  # Remove trailing slash from base_url
  base_url <- gsub("/$", "", base_url)
  # Remove leading slash from path
  path <- gsub("^/", "", path)
  # Combine
  paste0(base_url, "/", path)
}

# Export authentication utilities
auth_utils <- list(
  load_auth_config = load_auth_config,
  init_auth_system = init_auth_system,
  is_authenticated = is_authenticated,
  get_current_user = get_current_user,
  has_role = has_role,
  require_auth = require_auth,
  protected_ui = protected_ui,
  user_header_ui = user_header_ui,
  log_user_activity = log_user_activity,
  secure_operation = secure_operation
)

# Initialize auth system on load
auth_config <- init_auth_system()

cat("🔐 Authentication utilities loaded successfully\n")