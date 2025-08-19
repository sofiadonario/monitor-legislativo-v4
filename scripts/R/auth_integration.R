# Authentication Integration for Monitor Legislativo v4
# Integrates OAuth2 authentication with existing R/Shiny application
# Provides secure access control and RBAC for different user types

library(shiny)
library(shinydashboard)
library(DT)

# Source authentication modules
source("auth_system.R")
source("lgpd_compliance.R")

#' Authentication UI wrapper for main application
auth_wrapper_ui <- function(ui_content) {
  fluidPage(
    # Include CSS for authentication
    tags$head(
      tags$style(HTML("
        .login-container {
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .login-card {
          background: white;
          border-radius: 15px;
          padding: 40px;
          box-shadow: 0 15px 35px rgba(0,0,0,0.1);
          max-width: 400px;
          width: 100%;
        }
        .oauth-button {
          width: 100%;
          margin: 10px 0;
          padding: 12px 20px;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.3s ease;
        }
        .google-btn {
          background: #4285f4;
          color: white;
        }
        .google-btn:hover {
          background: #357ae8;
        }
        .microsoft-btn {
          background: #00a1f1;
          color: white;
        }
        .microsoft-btn:hover {
          background: #0078d7;
        }
        .consent-modal {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: rgba(0,0,0,0.8);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 9999;
        }
        .permission-denied {
          text-align: center;
          margin-top: 50px;
        }
        .user-menu {
          position: absolute;
          top: 10px;
          right: 10px;
          z-index: 1000;
        }
      "))
    ),
    
    # Conditional UI based on authentication state
    uiOutput("auth_ui_content")
  )
}

#' Generate login UI
login_ui <- function() {
  div(
    class = "login-container",
    div(
      class = "login-card text-center",
      
      # Logo and title
      img(src = "mackenzie-logo.png", height = "80px", style = "margin-bottom: 20px;"),
      h2("Monitor Legislativo v4", style = "color: #333; margin-bottom: 10px;"),
      p("Plataforma Acadêmica de Pesquisa Legislativa", style = "color: #666; margin-bottom: 30px;"),
      
      # Login instructions
      div(
        class = "login-instructions",
        style = "margin-bottom: 30px; padding: 15px; background: #f8f9fa; border-radius: 8px;",
        h5("Acesso Restrito", style = "color: #495057;"),
        p("Use sua conta institucional para acessar a plataforma:", style = "margin-bottom: 10px;"),
        tags$ul(
          style = "text-align: left; color: #6c757d;",
          tags$li("Universidades brasileiras (@usp.br, @unicamp.br, etc.)"),
          tags$li("Institutos de pesquisa (@cnpq.br, @ipea.gov.br)"),
          tags$li("Órgãos governamentais (@gov.br)")
        )
      ),
      
      # OAuth login buttons
      div(
        class = "oauth-buttons",
        
        # Google OAuth
        if (nchar(Sys.getenv("GOOGLE_CLIENT_ID")) > 0) {
          actionButton(
            "login_google",
            HTML('<i class="fab fa-google"></i> Entrar com Google'),
            class = "oauth-button google-btn"
          )
        },
        
        # Microsoft OAuth
        if (nchar(Sys.getenv("MICROSOFT_CLIENT_ID")) > 0) {
          actionButton(
            "login_microsoft", 
            HTML('<i class="fab fa-microsoft"></i> Entrar com Microsoft'),
            class = "oauth-button microsoft-btn"
          )
        }
      ),
      
      # Footer information
      div(
        class = "login-footer",
        style = "margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;",
        p("Desenvolvido pela Universidade Presbiteriana Mackenzie", 
          style = "color: #999; font-size: 12px;"),
        p(
          tags$a("Política de Privacidade", href = "#", onclick = "showPrivacyPolicy()"),
          " • ",
          tags$a("Suporte Técnico", href = "mailto:suporte@mackenzie.br"),
          style = "color: #999; font-size: 12px;"
        )
      )
    )
  )
}

#' Generate authenticated user menu
user_menu_ui <- function(user_session) {
  if (is.null(user_session)) {
    return(div())
  }
  
  div(
    class = "user-menu",
    dropdown(
      tags$span(
        class = "user-info",
        if (!is.null(user_session$avatar_url)) {
          img(src = user_session$avatar_url, 
              style = "width: 32px; height: 32px; border-radius: 50%; margin-right: 8px;")
        },
        user_session$full_name,
        style = "color: white; margin-right: 10px;"
      ),
      
      div(
        style = "min-width: 200px;",
        h6("Informações da Conta", style = "margin: 10px 0 5px 0; color: #666;"),
        p(strong("E-mail: "), user_session$email, style = "margin: 0; font-size: 12px;"),
        p(strong("Função: "), paste(user_session$roles, collapse = ", "), 
          style = "margin: 0 0 10px 0; font-size: 12px;"),
        
        div(style = "border-top: 1px solid #ddd; margin: 10px 0;"),
        
        actionLink("show_privacy_dashboard", 
                  HTML('<i class="fas fa-user-shield"></i> Privacidade & LGPD')),
        br(),
        actionLink("show_account_settings", 
                  HTML('<i class="fas fa-cog"></i> Configurações')),
        br(),
        actionLink("logout_user", 
                  HTML('<i class="fas fa-sign-out-alt"></i> Sair'),
                  style = "color: #dc3545;")
      ),
      
      icon = icon("user"),
      style = "primary",
      size = "sm",
      right = TRUE
    )
  )
}

#' Check user authentication and permissions
check_auth_access <- function(required_permission = NULL) {
  # Get current session from URL parameters or cookies
  session_id <- NULL
  query_params <- parseQueryString(isolate(session$clientData$url_search))
  
  # Try to get session from query parameter (for OAuth callback)
  if (!is.null(query_params$session)) {
    session_id <- query_params$session
  } else {
    # Try to get from stored session
    session_id <- isolate(input$current_session_id)
  }
  
  if (is.null(session_id)) {
    return(list(authenticated = FALSE, user = NULL, needs_login = TRUE))
  }
  
  # Validate session
  user_session <- validate_session(session_id)
  if (is.null(user_session)) {
    return(list(authenticated = FALSE, user = NULL, needs_login = TRUE))
  }
  
  # Check LGPD compliance
  compliance_check <- check_lgpd_compliance(user_session, "platform_access")
  if (!compliance_check$compliant) {
    return(list(
      authenticated = TRUE, 
      user = user_session, 
      needs_consent = TRUE,
      consent_message = compliance_check$message
    ))
  }
  
  # Check specific permission if required
  if (!is.null(required_permission)) {
    if (!has_permission(user_session, required_permission)) {
      return(list(
        authenticated = TRUE,
        user = user_session,
        access_denied = TRUE,
        missing_permission = required_permission
      ))
    }
  }
  
  # Update authentication state
  set_current_user(user_session)
  
  return(list(authenticated = TRUE, user = user_session))
}

#' Handle OAuth callback
handle_oauth_callback <- function(provider, auth_code, state) {
  tryCatch({
    # Verify state parameter for CSRF protection
    if (is.null(state) || nchar(state) < 10) {
      log_event("Invalid OAuth state parameter", "WARN")
      return(list(success = FALSE, message = "Parâmetro de segurança inválido"))
    }
    
    # Exchange authorization code for token
    token_data <- exchange_code_for_token(provider, auth_code)
    if (is.null(token_data)) {
      return(list(success = FALSE, message = "Erro na autenticação OAuth"))
    }
    
    # Get user information
    user_info <- get_user_info(provider, token_data$access_token)
    if (is.null(user_info)) {
      return(list(success = FALSE, message = "Erro ao obter informações do usuário"))
    }
    
    # Check if email is from trusted domain
    email_domain <- sub(".*@", "", user_info$email)
    trusted_domain <- dbGetQuery(.db_pool,
      "SELECT * FROM trusted_domains WHERE domain = $1 AND verification_status = 'verified'",
      params = list(email_domain)
    )
    
    if (nrow(trusted_domain) == 0) {
      log_event(paste("Login attempt from untrusted domain:", email_domain), "WARN")
      return(list(
        success = FALSE, 
        message = paste("Domínio não autorizado:", email_domain, 
                       "\nApenas contas institucionais são aceitas.")
      ))
    }
    
    # Create or update user
    user_record <- create_or_update_user(user_info, provider)
    if (is.null(user_record)) {
      return(list(success = FALSE, message = "Erro ao criar conta de usuário"))
    }
    
    # Create session
    request_info <- list(
      ip_address = "session_ip_authenticated",
      user_agent = "session_created"
    )
    
    session_info <- create_user_session(user_record, token_data, request_info)
    if (is.null(session_info)) {
      return(list(success = FALSE, message = "Erro ao criar sessão"))
    }
    
    # Log successful login
    log_data_access(
      user_record$id[1], session_info$session_id, 
      "login", "authentication", NULL, 
      paste("provider:", provider, "domain:", email_domain)
    )
    
    return(list(
      success = TRUE,
      session_id = session_info$session_id,
      user = user_record,
      redirect_url = "/?authenticated=true"
    ))
    
  }, error = function(e) {
    log_event(paste("OAuth callback error:", e$message), "ERROR")
    return(list(success = FALSE, message = "Erro interno de autenticação"))
  })
}

#' Generate permission denied UI
permission_denied_ui <- function(missing_permission, user_session) {
  div(
    class = "permission-denied",
    
    div(
      class = "alert alert-warning",
      style = "max-width: 600px; margin: 0 auto;",
      
      h3("Acesso Negado", style = "color: #856404;"),
      p("Você não possui permissão para acessar este recurso."),
      p(strong("Função atual: "), paste(user_session$roles, collapse = ", ")),
      p(strong("Permissão necessária: "), missing_permission),
      
      div(
        style = "margin-top: 20px;",
        p("Para solicitar acesso adicional, entre em contato com:"),
        p(strong("E-mail: "), "admin@mackenzie.br"),
        p(strong("Telefone: "), "(11) 2114-8000")
      ),
      
      actionButton(
        "return_dashboard",
        "Voltar ao Dashboard",
        class = "btn btn-primary",
        style = "margin-top: 20px;"
      )
    )
  )
}

#' Role-based feature filtering
filter_features_by_role <- function(user_session) {
  if (is.null(user_session)) {
    return(list())
  }
  
  features <- list()
  
  # Basic features for all authenticated users
  features$basic_search <- TRUE
  features$view_documents <- TRUE
  
  # Role-specific features
  if ("admin" %in% user_session$roles) {
    features$manage_users <- TRUE
    features$manage_system <- TRUE
    features$export_unlimited <- TRUE
    features$view_analytics <- TRUE
    features$manage_lgpd <- TRUE
  }
  
  if ("researcher" %in% user_session$roles) {
    features$advanced_search <- TRUE
    features$export_data <- TRUE
    features$view_analytics <- TRUE
    features$citation_tools <- TRUE
    features$api_access <- TRUE
  }
  
  if ("policymaker" %in% user_session$roles) {
    features$executive_dashboard <- TRUE
    features$geographic_analysis <- TRUE
    features$export_reports <- TRUE
    features$trend_analysis <- TRUE
  }
  
  if ("citizen" %in% user_session$roles) {
    features$limited_export <- TRUE
  }
  
  return(features)
}

#' Generate role-appropriate navigation menu
generate_navigation_menu <- function(user_session) {
  if (is.null(user_session)) {
    return(dashboardSidebar(disable = TRUE))
  }
  
  features <- filter_features_by_role(user_session)
  menu_items <- list()
  
  # Dashboard (always available)
  menu_items <- append(menu_items, list(
    menuItem("Dashboard", tabName = "dashboard", icon = icon("tachometer-alt"))
  ))
  
  # Search & Browse
  menu_items <- append(menu_items, list(
    menuItem("Busca de Documentos", tabName = "search", icon = icon("search"))
  ))
  
  # Advanced features based on role
  if (features$advanced_search) {
    menu_items <- append(menu_items, list(
      menuItem("Pesquisa Avançada", tabName = "advanced_search", icon = icon("filter"))
    ))
  }
  
  if (features$view_analytics) {
    menu_items <- append(menu_items, list(
      menuItem("Analytics", tabName = "analytics", icon = icon("chart-line"))
    ))
  }
  
  if (features$geographic_analysis) {
    menu_items <- append(menu_items, list(
      menuItem("Análise Geográfica", tabName = "geographic", icon = icon("map-marked-alt"))
    ))
  }
  
  if (features$export_data || features$export_reports) {
    menu_items <- append(menu_items, list(
      menuItem("Exportar Dados", tabName = "export", icon = icon("download"))
    ))
  }
  
  # Admin features
  if (features$manage_users) {
    menu_items <- append(menu_items, list(
      menuItem("Administração", icon = icon("cogs"),
        menuSubItem("Usuários", tabName = "admin_users"),
        menuSubItem("Sistema", tabName = "admin_system"),
        menuSubItem("LGPD", tabName = "admin_lgpd")
      )
    ))
  }
  
  # Privacy dashboard (always available)
  menu_items <- append(menu_items, list(
    menuItem("Privacidade", tabName = "privacy", icon = icon("user-shield"))
  ))
  
  # Create sidebar with dynamic menu
  dashboardSidebar(
    sidebarMenu(
      id = "main_menu",
      menu_items
    )
  )
}

#' Audit log function for security events
log_security_event <- function(user_id, event_type, details = NULL, ip_address = NULL) {
  if (is.null(.db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    # Log to data_access_log table
    log_data_access(
      user_id, NULL, event_type, "security_event", NULL, details
    )
    
    # Also log to application log for monitoring
    log_event(paste("SECURITY:", event_type, "user:", user_id, "details:", details), "WARN")
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Security event logging error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Session timeout check
check_session_timeout <- function(session_id) {
  if (is.null(.db_pool) || is.null(session_id)) {
    return(TRUE)  # Assume expired if can't check
  }
  
  tryCatch({
    session_data <- dbGetQuery(.db_pool,
      "SELECT expires_at, last_activity FROM user_sessions 
       WHERE session_id = $1 AND is_active = true",
      params = list(session_id)
    )
    
    if (nrow(session_data) == 0) {
      return(TRUE)  # Session not found, expired
    }
    
    # Check if session has expired
    if (Sys.time() > as.POSIXct(session_data$expires_at[1])) {
      # Mark session as expired
      revoke_session(session_id, "expired")
      return(TRUE)
    }
    
    # Check for inactivity timeout (2 hours)
    last_activity <- as.POSIXct(session_data$last_activity[1])
    if (difftime(Sys.time(), last_activity, units = "hours") > 2) {
      revoke_session(session_id, "inactivity_timeout")
      return(TRUE)
    }
    
    return(FALSE)  # Session is still valid
    
  }, error = function(e) {
    log_event(paste("Session timeout check error:", e$message), "ERROR")
    return(TRUE)  # Assume expired on error
  })
}

#' Initialize authentication integration
init_auth_integration <- function() {
  tryCatch({
    # Initialize authentication system
    auth_initialized <- init_auth_system()
    
    if (!auth_initialized) {
      log_event("Authentication system initialization failed", "ERROR")
      return(FALSE)
    }
    
    # Schedule cleanup tasks
    # Note: In production, these should be run via cron jobs
    # cleanup_expired_data()
    
    log_event("Authentication integration initialized successfully")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Auth integration initialization error:", e$message), "ERROR")
    return(FALSE)
  })
}

log_event("Authentication Integration Module loaded")