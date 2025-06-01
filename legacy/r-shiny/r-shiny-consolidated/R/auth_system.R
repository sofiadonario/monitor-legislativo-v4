# OAuth2 Authentication System for Monitor Legislativo v4
# Comprehensive authentication with institutional SSO support

library(shiny)
library(httr2)
library(jose)
library(DBI)
library(RSQLite)
library(digest)
library(jsonlite)
library(lubridate)
library(DT)
library(htmltools)

# Authentication configuration
AUTH_CONFIG <- list(
  oauth_providers = list(
    "google" = list(
      name = "Google",
      client_id = Sys.getenv("GOOGLE_CLIENT_ID"),
      client_secret = Sys.getenv("GOOGLE_CLIENT_SECRET"),
      authorize_url = "https://accounts.google.com/o/oauth2/auth",
      token_url = "https://oauth2.googleapis.com/token",
      userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo",
      scope = "openid email profile"
    ),
    "azure" = list(
      name = "Microsoft Azure AD",
      client_id = Sys.getenv("AZURE_CLIENT_ID"),
      client_secret = Sys.getenv("AZURE_CLIENT_SECRET"),
      tenant_id = Sys.getenv("AZURE_TENANT_ID"),
      authorize_url = paste0("https://login.microsoftonline.com/", Sys.getenv("AZURE_TENANT_ID"), "/oauth2/v2.0/authorize"),
      token_url = paste0("https://login.microsoftonline.com/", Sys.getenv("AZURE_TENANT_ID"), "/oauth2/v2.0/token"),
      userinfo_url = "https://graph.microsoft.com/v1.0/me",
      scope = "openid email profile User.Read"
    ),
    "github" = list(
      name = "GitHub",
      client_id = Sys.getenv("GITHUB_CLIENT_ID"),
      client_secret = Sys.getenv("GITHUB_CLIENT_SECRET"),
      authorize_url = "https://github.com/login/oauth/authorize",
      token_url = "https://github.com/login/oauth/access_token",
      userinfo_url = "https://api.github.com/user",
      scope = "user:email"
    )
  ),
  
  session_config = list(
    timeout_minutes = 480,  # 8 hours
    refresh_threshold_minutes = 60,  # Refresh 1 hour before expiry
    max_sessions_per_user = 3,
    secure_cookies = TRUE,
    same_site = "Strict"
  ),
  
  security_config = list(
    password_min_length = 8,
    password_require_special = TRUE,
    password_require_number = TRUE,
    password_require_uppercase = TRUE,
    max_login_attempts = 5,
    lockout_duration_minutes = 15,
    jwt_secret = Sys.getenv("JWT_SECRET", "default-secret-change-in-production"),
    encryption_algorithm = "HS256"
  ),
  
  user_roles = list(
    "admin" = list(
      name = "Administrador",
      permissions = c("read", "write", "delete", "manage_users", "system_config"),
      description = "Acesso completo ao sistema"
    ),
    "researcher" = list(
      name = "Pesquisador",
      permissions = c("read", "write", "export_data", "advanced_analytics"),
      description = "Acesso de pesquisa avançada"
    ),
    "analyst" = list(
      name = "Analista",
      permissions = c("read", "basic_analytics", "export_basic"),
      description = "Acesso de análise básica"
    ),
    "viewer" = list(
      name = "Visualizador",
      permissions = c("read"),
      description = "Acesso somente leitura"
    )
  ),
  
  institutional_domains = list(
    "usp.br" = list(institution = "Universidade de São Paulo", default_role = "researcher"),
    "unicamp.br" = list(institution = "UNICAMP", default_role = "researcher"),
    "ufrj.br" = list(institution = "UFRJ", default_role = "researcher"),
    "gov.br" = list(institution = "Governo Federal", default_role = "analyst"),
    "senado.leg.br" = list(institution = "Senado Federal", default_role = "analyst"),
    "camara.leg.br" = list(institution = "Câmara dos Deputados", default_role = "analyst"),
    "mackenzie.br" = list(institution = "Universidade Presbiteriana Mackenzie", default_role = "researcher")
  )
)

#' Initialize authentication database
#' @return Database connection
init_auth_db <- function() {
  tryCatch({
    # Create data directory if it doesn't exist
    data_dir <- "data"
    if (!dir.exists(data_dir)) {
      dir.create(data_dir, recursive = TRUE)
    }
    
    # Connect to SQLite database
    db_path <- file.path(data_dir, "auth.sqlite")
    con <- dbConnect(SQLite(), db_path)
    
    # Create users table
    dbExecute(con, "
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        institution TEXT,
        provider TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        profile_picture TEXT,
        preferences TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        is_active BOOLEAN DEFAULT 1,
        is_verified BOOLEAN DEFAULT 0
      )
    ")
    
    # Create sessions table
    dbExecute(con, "
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        user_agent TEXT,
        ip_address TEXT,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    ")
    
    # Create audit_log table
    dbExecute(con, "
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource TEXT,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    ")
    
    # Create login_attempts table
    dbExecute(con, "
      CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        success BOOLEAN NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        failure_reason TEXT
      )
    ")
    
    log_event("Authentication database initialized successfully")
    return(con)
    
  }, error = function(e) {
    log_event(paste("Error initializing auth database:", e$message), "ERROR")
    return(NULL)
  })
}

#' Generate OAuth2 authorization URL
#' @param provider OAuth provider name
#' @param redirect_uri Redirect URI after authorization
#' @param state Security state parameter
#' @return Authorization URL
generate_oauth_url <- function(provider, redirect_uri, state = NULL) {
  if (!provider %in% names(AUTH_CONFIG$oauth_providers)) {
    stop("Unsupported OAuth provider: ", provider)
  }
  
  config <- AUTH_CONFIG$oauth_providers[[provider]]
  
  if (is.null(state)) {
    state <- paste0(sample(c(letters, LETTERS, 0:9), 32, replace = TRUE), collapse = "")
  }
  
  params <- list(
    client_id = config$client_id,
    redirect_uri = redirect_uri,
    scope = config$scope,
    response_type = "code",
    state = state
  )
  
  # Add provider-specific parameters
  if (provider == "azure") {
    params$response_mode = "query"
  }
  
  # Build URL
  url <- paste0(
    config$authorize_url,
    "?",
    paste(names(params), sapply(params, utils::URLencode, reserved = TRUE), sep = "=", collapse = "&")
  )
  
  return(list(url = url, state = state))
}

#' Exchange authorization code for access token
#' @param provider OAuth provider name
#' @param code Authorization code
#' @param redirect_uri Redirect URI
#' @return Token response
exchange_oauth_code <- function(provider, code, redirect_uri) {
  if (!provider %in% names(AUTH_CONFIG$oauth_providers)) {
    stop("Unsupported OAuth provider: ", provider)
  }
  
  config <- AUTH_CONFIG$oauth_providers[[provider]]
  
  tryCatch({
    # Prepare token request
    token_data <- list(
      client_id = config$client_id,
      client_secret = config$client_secret,
      code = code,
      redirect_uri = redirect_uri,
      grant_type = "authorization_code"
    )
    
    # Make token request
    response <- request(config$token_url) %>%
      req_method("POST") %>%
      req_headers("Accept" = "application/json") %>%
      req_body_form(!!!token_data) %>%
      req_perform()
    
    if (resp_status(response) == 200) {
      token_info <- resp_body_json(response)
      log_event(paste("OAuth token exchange successful for provider:", provider))
      return(token_info)
    } else {
      log_event(paste("OAuth token exchange failed for provider:", provider, "Status:", resp_status(response)), "ERROR")
      return(NULL)
    }
    
  }, error = function(e) {
    log_event(paste("Error in OAuth token exchange:", e$message), "ERROR")
    return(NULL)
  })
}

#' Get user info from OAuth provider
#' @param provider OAuth provider name
#' @param access_token Access token
#' @return User information
get_oauth_user_info <- function(provider, access_token) {
  if (!provider %in% names(AUTH_CONFIG$oauth_providers)) {
    stop("Unsupported OAuth provider: ", provider)
  }
  
  config <- AUTH_CONFIG$oauth_providers[[provider]]
  
  tryCatch({
    # Make user info request
    response <- request(config$userinfo_url) %>%
      req_headers("Authorization" = paste("Bearer", access_token)) %>%
      req_perform()
    
    if (resp_status(response) == 200) {
      user_info <- resp_body_json(response)
      
      # Normalize user info across providers
      normalized_info <- list(
        email = user_info$email,
        name = user_info$name %||% paste(user_info$given_name, user_info$family_name),
        provider_id = as.character(user_info$id %||% user_info$sub),
        profile_picture = user_info$picture %||% user_info$avatar_url,
        provider = provider
      )
      
      log_event(paste("User info retrieved successfully for provider:", provider))
      return(normalized_info)
    } else {
      log_event(paste("Failed to get user info from provider:", provider, "Status:", resp_status(response)), "ERROR")
      return(NULL)
    }
    
  }, error = function(e) {
    log_event(paste("Error getting OAuth user info:", e$message), "ERROR")
    return(NULL)
  })
}

#' Create or update user in database
#' @param con Database connection
#' @param user_info User information from OAuth
#' @return User record
create_or_update_user <- function(con, user_info) {
  if (is.null(con) || is.null(user_info)) return(NULL)
  
  tryCatch({
    # Determine institutional role based on email domain
    email_domain <- sub(".*@", "", user_info$email)
    institution_info <- AUTH_CONFIG$institutional_domains[[email_domain]]
    
    default_role <- if (!is.null(institution_info)) {
      institution_info$default_role
    } else {
      "viewer"
    }
    
    institution <- if (!is.null(institution_info)) {
      institution_info$institution
    } else {
      "External"
    }
    
    # Check if user exists
    existing_user <- dbGetQuery(con, 
      "SELECT * FROM users WHERE email = ? AND provider = ?", 
      params = list(user_info$email, user_info$provider)
    )
    
    if (nrow(existing_user) > 0) {
      # Update existing user
      dbExecute(con, "
        UPDATE users 
        SET name = ?, provider_id = ?, profile_picture = ?, 
            institution = ?, updated_at = CURRENT_TIMESTAMP, 
            last_login = CURRENT_TIMESTAMP
        WHERE id = ?
      ", params = list(
        user_info$name,
        user_info$provider_id,
        user_info$profile_picture,
        institution,
        existing_user$id[1]
      ))
      
      user_record <- dbGetQuery(con, "SELECT * FROM users WHERE id = ?", params = list(existing_user$id[1]))
      log_event(paste("User updated:", user_info$email))
    } else {
      # Create new user
      dbExecute(con, "
        INSERT INTO users (email, name, role, institution, provider, provider_id, profile_picture, last_login, is_verified)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 1)
      ", params = list(
        user_info$email,
        user_info$name,
        default_role,
        institution,
        user_info$provider,
        user_info$provider_id,
        user_info$profile_picture
      ))
      
      user_id <- dbGetQuery(con, "SELECT last_insert_rowid() as id")$id[1]
      user_record <- dbGetQuery(con, "SELECT * FROM users WHERE id = ?", params = list(user_id))
      log_event(paste("New user created:", user_info$email))
    }
    
    return(user_record)
    
  }, error = function(e) {
    log_event(paste("Error creating/updating user:", e$message), "ERROR")
    return(NULL)
  })
}

#' Create user session
#' @param con Database connection
#' @param user_id User ID
#' @param access_token Access token
#' @param refresh_token Refresh token (optional)
#' @param user_agent User agent string
#' @param ip_address IP address
#' @return Session ID
create_user_session <- function(con, user_id, access_token, refresh_token = NULL, user_agent = NULL, ip_address = NULL) {
  if (is.null(con) || is.null(user_id)) return(NULL)
  
  tryCatch({
    # Generate session ID
    session_id <- paste0(
      digest(paste(user_id, Sys.time(), runif(1)), algo = "sha256"),
      "-",
      format(Sys.time(), "%Y%m%d%H%M%S")
    )
    
    # Calculate expiry time
    expires_at <- Sys.time() + minutes(AUTH_CONFIG$session_config$timeout_minutes)
    
    # Clean up old sessions for user (keep only recent ones)
    old_sessions <- dbGetQuery(con, 
      "SELECT id FROM sessions WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT -1 OFFSET ?",
      params = list(user_id, AUTH_CONFIG$session_config$max_sessions_per_user - 1)
    )
    
    if (nrow(old_sessions) > 0) {
      dbExecute(con, 
        paste("UPDATE sessions SET is_active = 0 WHERE id IN (", 
              paste(rep("?", nrow(old_sessions)), collapse = ","), ")"),
        params = as.list(old_sessions$id)
      )
    }
    
    # Create new session
    dbExecute(con, "
      INSERT INTO sessions (id, user_id, access_token, refresh_token, expires_at, user_agent, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    ", params = list(
      session_id,
      user_id,
      access_token,
      refresh_token,
      format(expires_at, "%Y-%m-%d %H:%M:%S"),
      user_agent,
      ip_address
    ))
    
    log_event(paste("Session created for user ID:", user_id))
    return(session_id)
    
  }, error = function(e) {
    log_event(paste("Error creating session:", e$message), "ERROR")
    return(NULL)
  })
}

#' Validate session
#' @param con Database connection
#' @param session_id Session ID
#' @return User information if valid, NULL otherwise
validate_session <- function(con, session_id) {
  if (is.null(con) || is.null(session_id)) return(NULL)
  
  tryCatch({
    # Get session with user info
    session_info <- dbGetQuery(con, "
      SELECT s.*, u.email, u.name, u.role, u.institution, u.profile_picture, u.is_active as user_active
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.id = ? AND s.is_active = 1 AND s.expires_at > CURRENT_TIMESTAMP AND u.is_active = 1
    ", params = list(session_id))
    
    if (nrow(session_info) > 0) {
      # Update last activity
      dbExecute(con, "UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = ?", 
                params = list(session_id))
      
      return(list(
        session_id = session_info$id[1],
        user_id = session_info$user_id[1],
        email = session_info$email[1],
        name = session_info$name[1],
        role = session_info$role[1],
        institution = session_info$institution[1],
        profile_picture = session_info$profile_picture[1],
        permissions = AUTH_CONFIG$user_roles[[session_info$role[1]]]$permissions %||% c("read")
      ))
    } else {
      return(NULL)
    }
    
  }, error = function(e) {
    log_event(paste("Error validating session:", e$message), "ERROR")
    return(NULL)
  })
}

#' Invalidate session
#' @param con Database connection
#' @param session_id Session ID
#' @return Success boolean
invalidate_session <- function(con, session_id) {
  if (is.null(con) || is.null(session_id)) return(FALSE)
  
  tryCatch({
    result <- dbExecute(con, "UPDATE sessions SET is_active = 0 WHERE id = ?", params = list(session_id))
    log_event(paste("Session invalidated:", session_id))
    return(result > 0)
  }, error = function(e) {
    log_event(paste("Error invalidating session:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Log audit event
#' @param con Database connection
#' @param user_id User ID (optional)
#' @param action Action performed
#' @param resource Resource affected (optional)
#' @param details Additional details (optional)
#' @param ip_address IP address (optional)
#' @param user_agent User agent (optional)
log_audit_event <- function(con, user_id = NULL, action, resource = NULL, details = NULL, ip_address = NULL, user_agent = NULL) {
  if (is.null(con)) return(FALSE)
  
  tryCatch({
    dbExecute(con, "
      INSERT INTO audit_log (user_id, action, resource, details, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?)
    ", params = list(
      user_id,
      action,
      resource,
      details,
      ip_address,
      user_agent
    ))
    
    return(TRUE)
  }, error = function(e) {
    log_event(paste("Error logging audit event:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Check user permissions
#' @param user_info User information
#' @param required_permission Required permission
#' @return Boolean indicating if user has permission
has_permission <- function(user_info, required_permission) {
  if (is.null(user_info) || is.null(user_info$permissions)) return(FALSE)
  return(required_permission %in% user_info$permissions)
}

#' Create authentication UI components
#' @param id Module ID
#' @return Authentication UI
auth_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "auth-container",
    
    # Login modal
    div(
      id = ns("login_modal"),
      class = "modal fade",
      tabindex = "-1",
      role = "dialog",
      
      div(
        class = "modal-dialog modal-dialog-centered",
        role = "document",
        
        div(
          class = "modal-content",
          style = "border-radius: 12px; border: none; box-shadow: 0 10px 40px rgba(0,0,0,0.1);",
          
          div(
            class = "modal-header",
            style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-bottom: none; border-radius: 12px 12px 0 0;",
            
            h4("🔐 Acesso ao Monitor Legislativo v4", class = "modal-title"),
            tags$button(
              type = "button",
              class = "btn-close btn-close-white",
              `data-bs-dismiss` = "modal"
            )
          ),
          
          div(
            class = "modal-body",
            style = "padding: 2rem;",
            
            div(
              class = "text-center mb-4",
              p("Faça login com sua conta institucional para acessar o sistema", class = "text-muted")
            ),
            
            # OAuth provider buttons
            div(
              class = "oauth-providers",
              
              # Google login
              conditionalPanel(
                condition = paste0("'", Sys.getenv("GOOGLE_CLIENT_ID"), "' != ''"),
                actionButton(
                  ns("login_google"),
                  HTML("
                    <i class='fab fa-google me-2'></i>
                    Continuar com Google
                  "),
                  class = "btn btn-outline-danger w-100 mb-3",
                  style = "padding: 12px; font-weight: 500;"
                )
              ),
              
              # Microsoft Azure login
              conditionalPanel(
                condition = paste0("'", Sys.getenv("AZURE_CLIENT_ID"), "' != ''"),
                actionButton(
                  ns("login_azure"),
                  HTML("
                    <i class='fab fa-microsoft me-2'></i>
                    Continuar com Microsoft
                  "),
                  class = "btn btn-outline-primary w-100 mb-3",
                  style = "padding: 12px; font-weight: 500;"
                )
              ),
              
              # GitHub login
              conditionalPanel(
                condition = paste0("'", Sys.getenv("GITHUB_CLIENT_ID"), "' != ''"),
                actionButton(
                  ns("login_github"),
                  HTML("
                    <i class='fab fa-github me-2'></i>
                    Continuar com GitHub
                  "),
                  class = "btn btn-outline-dark w-100 mb-3",
                  style = "padding: 12px; font-weight: 500;"
                )
              )
            ),
            
            # Institutional access info
            div(
              class = "institutional-info mt-4 p-3",
              style = "background: #f8f9fa; border-radius: 8px; border-left: 4px solid #0d6efd;",
              
              h6("🏛️ Acesso Institucional", class = "mb-2"),
              p(
                "Usuários de instituições acadêmicas e governamentais têm acesso automático com permissões apropriadas.",
                class = "mb-1 small text-muted"
              ),
              p(
                "Instituições suportadas: USP, UNICAMP, UFRJ, Governo Federal, Senado, Câmara, Mackenzie",
                class = "mb-0 small text-muted"
              )
            )
          ),
          
          div(
            class = "modal-footer",
            style = "border-top: 1px solid #eee; padding: 1rem 2rem;",
            
            p(
              "Ao fazer login, você concorda com os termos de uso do sistema.",
              class = "small text-muted mb-0"
            )
          )
        )
      )
    ),
    
    # User menu (shown when authenticated)
    conditionalPanel(
      condition = paste0("output['", ns("is_authenticated"), "']"),
      
      div(
        class = "user-menu dropdown",
        
        tags$button(
          class = "btn btn-outline-primary dropdown-toggle",
          type = "button",
          id = ns("user_menu_button"),
          `data-bs-toggle` = "dropdown",
          
          uiOutput(ns("user_avatar_menu"), inline = TRUE)
        ),
        
        div(
          class = "dropdown-menu dropdown-menu-end",
          style = "min-width: 250px;",
          
          div(
            class = "dropdown-header",
            uiOutput(ns("user_info_header"))
          ),
          
          div(class = "dropdown-divider"),
          
          actionLink(
            ns("user_profile"),
            HTML("<i class='fas fa-user me-2'></i>Perfil"),
            class = "dropdown-item"
          ),
          
          actionLink(
            ns("user_preferences"),
            HTML("<i class='fas fa-cog me-2'></i>Preferências"),
            class = "dropdown-item"
          ),
          
          conditionalPanel(
            condition = paste0("output['", ns("has_admin_permissions"), "']"),
            
            div(class = "dropdown-divider"),
            
            actionLink(
              ns("admin_panel"),
              HTML("<i class='fas fa-users-cog me-2'></i>Administração"),
              class = "dropdown-item"
            )
          ),
          
          div(class = "dropdown-divider"),
          
          actionLink(
            ns("logout"),
            HTML("<i class='fas fa-sign-out-alt me-2'></i>Sair"),
            class = "dropdown-item text-danger"
          )
        )
      )
    ),
    
    # Login button (shown when not authenticated)
    conditionalPanel(
      condition = paste0("!output['", ns("is_authenticated"), "']"),
      
      actionButton(
        ns("show_login"),
        HTML("<i class='fas fa-sign-in-alt me-2'></i>Entrar"),
        class = "btn btn-primary",
        `data-bs-toggle` = "modal",
        `data-bs-target` = paste0("#", ns("login_modal"))
      )
    )
  )
}

#' Authentication server module
#' @param id Module ID
#' @param auth_db Database connection (reactive)
auth_server <- function(id, auth_db) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values for authentication state
    auth_values <- reactiveValues(
      user = NULL,
      session_id = NULL,
      is_authenticated = FALSE
    )
    
    # Get database connection
    con <- reactive({ auth_db() })
    
    # Check for existing session on startup
    observe({
      session_cookie <- session$request$HTTP_COOKIE
      if (!is.null(session_cookie)) {
        # Extract session ID from cookie
        cookie_match <- regmatches(session_cookie, regexpr("monitor_session_id=([^;]+)", session_cookie))
        if (length(cookie_match) > 0) {
          session_id <- sub("monitor_session_id=", "", cookie_match[1])
          
          # Validate session
          user_info <- validate_session(con(), session_id)
          if (!is.null(user_info)) {
            auth_values$user <- user_info
            auth_values$session_id <- session_id
            auth_values$is_authenticated <- TRUE
            
            log_audit_event(
              con(), user_info$user_id, "session_resumed", 
              details = "Session resumed from cookie"
            )
          }
        }
      }
    })
    
    # OAuth login handlers
    observeEvent(input$login_google, {
      initiate_oauth_flow("google")
    })
    
    observeEvent(input$login_azure, {
      initiate_oauth_flow("azure")
    })
    
    observeEvent(input$login_github, {
      initiate_oauth_flow("github")
    })
    
    # Logout handler
    observeEvent(input$logout, {
      if (!is.null(auth_values$session_id)) {
        invalidate_session(con(), auth_values$session_id)
        
        log_audit_event(
          con(), auth_values$user$user_id, "logout",
          details = "User initiated logout"
        )
      }
      
      # Clear authentication state
      auth_values$user <- NULL
      auth_values$session_id <- NULL
      auth_values$is_authenticated <- FALSE
      
      # Clear session cookie
      session$sendCustomMessage(
        type = "clearCookie",
        message = list(name = "monitor_session_id")
      )
      
      showNotification("Logout realizado com sucesso", type = "success")
    })
    
    # Helper function to initiate OAuth flow
    initiate_oauth_flow <- function(provider) {
      tryCatch({
        redirect_uri <- paste0(
          session$clientData$url_protocol, "//",
          session$clientData$url_hostname,
          if (session$clientData$url_port != "") paste0(":", session$clientData$url_port),
          "/auth/callback"
        )
        
        oauth_result <- generate_oauth_url(provider, redirect_uri)
        
        # Store state in session for validation
        session$userData$oauth_state <- oauth_result$state
        session$userData$oauth_provider <- provider
        
        # Redirect to OAuth provider
        session$sendCustomMessage(
          type = "redirect",
          message = list(url = oauth_result$url)
        )
        
      }, error = function(e) {
        log_event(paste("Error initiating OAuth flow:", e$message), "ERROR")
        showNotification("Erro ao iniciar processo de login", type = "error")
      })
    }
    
    # Handle OAuth callback (this would typically be handled by a separate endpoint)
    observe({
      query_params <- parseQueryString(session$clientData$url_search)
      
      if (!is.null(query_params$code) && !is.null(query_params$state)) {
        # Validate state parameter
        if (query_params$state == session$userData$oauth_state) {
          process_oauth_callback(
            session$userData$oauth_provider,
            query_params$code,
            paste0(
              session$clientData$url_protocol, "//",
              session$clientData$url_hostname,
              if (session$clientData$url_port != "") paste0(":", session$clientData$url_port),
              "/auth/callback"
            )
          )
        } else {
          showNotification("Erro de segurança: state inválido", type = "error")
        }
      }
    })
    
    # Process OAuth callback
    process_oauth_callback <- function(provider, code, redirect_uri) {
      tryCatch({
        # Exchange code for token
        token_info <- exchange_oauth_code(provider, code, redirect_uri)
        
        if (!is.null(token_info) && !is.null(token_info$access_token)) {
          # Get user information
          user_info <- get_oauth_user_info(provider, token_info$access_token)
          
          if (!is.null(user_info)) {
            # Create or update user
            user_record <- create_or_update_user(con(), user_info)
            
            if (!is.null(user_record)) {
              # Create session
              session_id <- create_user_session(
                con(),
                user_record$id[1],
                token_info$access_token,
                token_info$refresh_token,
                session$clientData$user_agent,
                session$clientData$url_hostname
              )
              
              if (!is.null(session_id)) {
                # Set authentication state
                auth_values$user <- list(
                  user_id = user_record$id[1],
                  email = user_record$email[1],
                  name = user_record$name[1],
                  role = user_record$role[1],
                  institution = user_record$institution[1],
                  profile_picture = user_record$profile_picture[1],
                  permissions = AUTH_CONFIG$user_roles[[user_record$role[1]]]$permissions %||% c("read")
                )
                auth_values$session_id <- session_id
                auth_values$is_authenticated <- TRUE
                
                # Set session cookie
                session$sendCustomMessage(
                  type = "setCookie",
                  message = list(
                    name = "monitor_session_id",
                    value = session_id,
                    days = 30
                  )
                )
                
                log_audit_event(
                  con(), user_record$id[1], "login_success", 
                  details = paste("OAuth login via", provider)
                )
                
                showNotification(
                  paste("Login realizado com sucesso! Bem-vindo,", user_record$name[1]),
                  type = "success"
                )
              }
            }
          }
        }
        
      }, error = function(e) {
        log_event(paste("Error processing OAuth callback:", e$message), "ERROR")
        showNotification("Erro no processo de autenticação", type = "error")
      })
    }
    
    # ========================================================================
    # OUTPUTS
    # ========================================================================
    
    output$is_authenticated <- reactive({
      auth_values$is_authenticated
    })
    outputOptions(output, "is_authenticated", suspendWhenHidden = FALSE)
    
    output$has_admin_permissions <- reactive({
      has_permission(auth_values$user, "manage_users")
    })
    outputOptions(output, "has_admin_permissions", suspendWhenHidden = FALSE)
    
    output$user_avatar_menu <- renderUI({
      if (!is.null(auth_values$user)) {
        tagList(
          if (!is.null(auth_values$user$profile_picture)) {
            tags$img(
              src = auth_values$user$profile_picture,
              style = "width: 24px; height: 24px; border-radius: 50%; margin-right: 8px;"
            )
          },
          span(auth_values$user$name)
        )
      }
    })
    
    output$user_info_header <- renderUI({
      if (!is.null(auth_values$user)) {
        div(
          div(
            style = "font-weight: 600; color: #333;",
            auth_values$user$name
          ),
          div(
            style = "font-size: 0.875rem; color: #666;",
            auth_values$user$email
          ),
          div(
            style = "font-size: 0.75rem; color: #999;",
            paste(
              AUTH_CONFIG$user_roles[[auth_values$user$role]]$name,
              "-",
              auth_values$user$institution
            )
          )
        )
      }
    })
    
    # Return authentication state for use by other modules
    return(reactive({
      list(
        is_authenticated = auth_values$is_authenticated,
        user = auth_values$user,
        session_id = auth_values$session_id
      )
    }))
  })
}

#' Check if user has specific permission
#' @param auth_state Authentication state from auth_server
#' @param permission Required permission
#' @return Reactive boolean
require_permission <- function(auth_state, permission) {
  reactive({
    auth_info <- auth_state()
    if (!auth_info$is_authenticated) return(FALSE)
    return(has_permission(auth_info$user, permission))
  })
}

#' Authentication middleware for protecting content
#' @param auth_state Authentication state from auth_server
#' @param content UI content to protect
#' @param required_permission Required permission (optional)
#' @return Protected UI content
protect_content <- function(auth_state, content, required_permission = NULL) {
  auth_info <- auth_state()
  
  if (!auth_info$is_authenticated) {
    return(
      div(
        class = "text-center py-5",
        icon("lock", class = "fa-3x text-muted mb-3"),
        h4("Acesso Restrito", class = "text-muted"),
        p("Faça login para acessar este conteúdo", class = "text-muted")
      )
    )
  }
  
  if (!is.null(required_permission) && !has_permission(auth_info$user, required_permission)) {
    return(
      div(
        class = "text-center py-5",
        icon("ban", class = "fa-3x text-warning mb-3"),
        h4("Permissão Insuficiente", class = "text-warning"),
        p("Você não tem permissão para acessar este conteúdo", class = "text-muted")
      )
    )
  }
  
  return(content)
}

# Initialize authentication system on module load
auth_db_connection <- NULL

.onLoad <- function(libname, pkgname) {
  auth_db_connection <<- init_auth_db()
}