# Login UI Module for Monitor Legislativo v4
# ==========================================
# Professional authentication interface with OAuth integration

library(shiny)
library(shinydashboard)
library(htmltools)

# Authentication UI Module
# =======================

#' Login page UI
#' @param id Module namespace ID
#' @param oauth_config OAuth configuration object
#' @return HTML content for login page
login_ui <- function(id, oauth_config = NULL) {
  ns <- NS(id)
  
  # Check if OAuth providers are configured
  google_enabled <- !is.null(oauth_config) && oauth_config$google$enabled
  microsoft_enabled <- !is.null(oauth_config) && oauth_config$microsoft$enabled
  
  # Professional login page
  div(
    class = "login-page",
    
    # Custom CSS for professional appearance
    tags$head(
      tags$style(HTML("
        .login-page {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .login-container {
          background: white;
          border-radius: 15px;
          box-shadow: 0 15px 35px rgba(0,0,0,0.1);
          padding: 40px;
          width: 100%;
          max-width: 450px;
          margin: 20px;
        }
        
        .login-header {
          text-align: center;
          margin-bottom: 30px;
        }
        
        .login-title {
          color: #333;
          font-size: 28px;
          font-weight: 600;
          margin-bottom: 8px;
        }
        
        .login-subtitle {
          color: #666;
          font-size: 16px;
          margin-bottom: 20px;
        }
        
        .mackenzie-logo {
          width: 120px;
          height: auto;
          margin-bottom: 20px;
        }
        
        .oauth-buttons {
          margin-bottom: 30px;
        }
        
        .oauth-btn {
          width: 100%;
          margin-bottom: 15px;
          padding: 12px 20px;
          border: 2px solid #e1e5e9;
          border-radius: 8px;
          background: white;
          color: #333;
          font-size: 16px;
          font-weight: 500;
          text-decoration: none;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.3s ease;
          cursor: pointer;
        }
        
        .oauth-btn:hover {
          border-color: #007bff;
          box-shadow: 0 5px 15px rgba(0,123,255,0.2);
          color: #007bff;
          text-decoration: none;
        }
        
        .oauth-btn-google {
          border-color: #db4437;
          color: #db4437;
        }
        
        .oauth-btn-google:hover {
          background: #db4437;
          color: white;
          border-color: #db4437;
        }
        
        .oauth-btn-microsoft {
          border-color: #0078d4;
          color: #0078d4;
        }
        
        .oauth-btn-microsoft:hover {
          background: #0078d4;
          color: white;
          border-color: #0078d4;
        }
        
        .oauth-icon {
          width: 20px;
          height: 20px;
          margin-right: 12px;
        }
        
        .divider {
          text-align: center;
          margin: 25px 0;
          position: relative;
        }
        
        .divider::before {
          content: '';
          position: absolute;
          top: 50%;
          left: 0;
          right: 0;
          height: 1px;
          background: #e1e5e9;
        }
        
        .divider span {
          background: white;
          color: #666;
          padding: 0 15px;
          font-size: 14px;
        }
        
        .security-notice {
          background: #f8f9fa;
          border-left: 4px solid #007bff;
          padding: 15px;
          border-radius: 5px;
          margin-top: 20px;
          font-size: 14px;
          color: #666;
        }
        
        .error-message {
          background: #f8d7da;
          border: 1px solid #f5c6cb;
          color: #721c24;
          padding: 12px 15px;
          border-radius: 5px;
          margin-bottom: 20px;
          display: none;
        }
        
        .loading-spinner {
          display: none;
          text-align: center;
          margin: 20px 0;
        }
        
        .spinner {
          border: 3px solid #f3f3f3;
          border-top: 3px solid #007bff;
          border-radius: 50%;
          width: 30px;
          height: 30px;
          animation: spin 1s linear infinite;
          margin: 0 auto;
        }
        
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        .footer-text {
          text-align: center;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #e1e5e9;
          color: #666;
          font-size: 13px;
        }
        
        .footer-links {
          margin-top: 10px;
        }
        
        .footer-links a {
          color: #007bff;
          text-decoration: none;
          margin: 0 10px;
          font-size: 13px;
        }
        
        .footer-links a:hover {
          text-decoration: underline;
        }
        
        .status-indicator {
          display: inline-block;
          width: 8px;
          height: 8px;
          border-radius: 50%;
          margin-right: 8px;
        }
        
        .status-online { background: #28a745; }
        .status-offline { background: #dc3545; }
        
        @media (max-width: 768px) {
          .login-container {
            margin: 10px;
            padding: 30px 20px;
          }
          
          .login-title {
            font-size: 24px;
          }
        }
      "))
    ),
    
    # Login container
    div(
      class = "login-container",
      
      # Header section
      div(
        class = "login-header",
        
        # University logo (if available)
        conditionalPanel(
          condition = "false", # Enable if you have a logo
          img(
            src = "assets/mackenzie-logo.png",
            class = "mackenzie-logo",
            alt = "Universidade Presbiteriana Mackenzie"
          )
        ),
        
        h1("Monitor Legislativo", class = "login-title"),
        p("Plataforma Acadêmica de Monitoramento Legislativo", class = "login-subtitle"),
        
        # System status indicator
        div(
          style = "margin-top: 15px; font-size: 14px; color: #666;",
          span(class = "status-indicator status-online"),
          "Sistema Online e Seguro"
        )
      ),
      
      # Error message container
      div(
        id = ns("error_message"),
        class = "error-message"
      ),
      
      # Loading spinner
      div(
        id = ns("loading_spinner"),
        class = "loading-spinner",
        div(class = "spinner"),
        p("Processando autenticação...", style = "margin-top: 10px; color: #666;")
      ),
      
      # OAuth buttons section
      div(
        class = "oauth-buttons",
        
        # Google OAuth button
        conditionalPanel(
          condition = google_enabled,
          actionButton(
            ns("google_login"),
            HTML('
              <svg class="oauth-icon" viewBox="0 0 24 24">
                <path fill="#4285f4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34a853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#fbbc05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                <path fill="#ea4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
              </svg>
              Continuar com Google
            '),
            class = "oauth-btn oauth-btn-google"
          )
        ),
        
        # Microsoft OAuth button
        conditionalPanel(
          condition = microsoft_enabled,
          actionButton(
            ns("microsoft_login"),
            HTML('
              <svg class="oauth-icon" viewBox="0 0 24 24">
                <path fill="#f35325" d="M1 1h10v10H1z"/>
                <path fill="#81bc06" d="M13 1h10v10H13z"/>
                <path fill="#05a6f0" d="M1 13h10v10H1z"/>
                <path fill="#ffba08" d="M13 13h10v10H13z"/>
              </svg>
              Continuar com Microsoft
            '),
            class = "oauth-btn oauth-btn-microsoft"
          )
        ),
        
        # No OAuth providers message
        conditionalPanel(
          condition = !google_enabled && !microsoft_enabled,
          div(
            style = "text-align: center; color: #dc3545; padding: 20px;",
            h4("Autenticação Não Configurada"),
            p("Os provedores OAuth não estão configurados. Entre em contato com o administrador do sistema.")
          )
        )
      ),
      
      # Security notice
      div(
        class = "security-notice",
        HTML("
          <strong>🔒 Acesso Seguro:</strong> Este sistema utiliza autenticação OAuth2 
          para garantir a segurança dos seus dados. Suas credenciais nunca são 
          armazenadas em nossos servidores.
        ")
      ),
      
      # Footer
      div(
        class = "footer-text",
        "Universidade Presbiteriana Mackenzie",
        div(
          class = "footer-links",
          a(href = "#", "Política de Privacidade"),
          a(href = "#", "Termos de Uso"),
          a(href = "#", "Suporte")
        )
      )
    ),
    
    # JavaScript for enhanced UX
    tags$script(HTML(paste0("
      $(document).ready(function() {
        // Show loading spinner on OAuth button clicks
        $('#", ns("google_login"), ", #", ns("microsoft_login"), "').click(function() {
          $('#", ns("loading_spinner"), "').show();
          $(this).prop('disabled', true);
        });
        
        // Hide error message on new attempts
        $('#", ns("google_login"), ", #", ns("microsoft_login"), "').click(function() {
          $('#", ns("error_message"), "').hide();
        });
      });
      
      // Function to show error message
      function showLoginError(message) {
        $('#", ns("error_message"), "').text(message).show();
        $('#", ns("loading_spinner"), "').hide();
        $('#", ns("google_login"), ", #", ns("microsoft_login"), "').prop('disabled', false);
      }
      
      // Function to hide loading
      function hideLoginLoading() {
        $('#", ns("loading_spinner"), "').hide();
        $('#", ns("google_login"), ", #", ns("microsoft_login"), "').prop('disabled', false);
      }
    ")))
  )
}

#' User info display UI (shown after authentication)
#' @param user_info User information object
#' @return HTML content for user info display
user_info_ui <- function(user_info) {
  div(
    class = "user-info-display",
    style = "padding: 10px; background: #f8f9fa; border-radius: 5px; margin-bottom: 20px;",
    
    # User avatar and info
    div(
      style = "display: flex; align-items: center;",
      
      # Avatar
      if (!is.null(user_info$picture)) {
        img(
          src = user_info$picture,
          style = "width: 40px; height: 40px; border-radius: 50%; margin-right: 15px;",
          alt = "User Avatar"
        )
      } else {
        div(
          style = "width: 40px; height: 40px; border-radius: 50%; background: #007bff; color: white; display: flex; align-items: center; justify-content: center; margin-right: 15px; font-weight: bold;",
          substr(user_info$name, 1, 1)
        )
      },
      
      # User details
      div(
        h5(user_info$name, style = "margin: 0; color: #333;"),
        p(user_info$email, style = "margin: 0; color: #666; font-size: 14px;"),
        span(
          paste("Função:", switch(user_info$role,
            "admin" = "Administrador",
            "researcher" = "Pesquisador",
            "user" = "Usuário",
            "Usuário"
          )),
          style = "font-size: 12px; color: #007bff; background: #e3f2fd; padding: 2px 8px; border-radius: 12px;"
        )
      )
    )
  )
}

#' Logout button UI
#' @param id Module namespace ID
#' @return Logout button HTML
logout_button_ui <- function(id) {
  ns <- NS(id)
  
  actionButton(
    ns("logout"),
    "Sair",
    icon = icon("sign-out-alt"),
    class = "btn btn-outline-danger btn-sm",
    style = "margin-left: 10px;"
  )
}

# Authentication Module Server Logic
# =================================

#' Authentication server module
#' @param id Module namespace ID
#' @param oauth_config OAuth configuration
#' @return Server function for authentication module
auth_server <- function(id, oauth_config) {
  moduleServer(id, function(input, output, session) {
    
    # Load OAuth middleware
    if (!exists("oauth_middleware")) {
      source("auth/oauth_middleware.R", local = TRUE)
    }
    
    # Reactive values for authentication state
    auth_state <- reactiveValues(
      authenticated = FALSE,
      user_info = NULL,
      error_message = NULL
    )
    
    # Check initial authentication state
    observe({
      if (oauth_middleware$validate_user_session(session)) {
        auth_state$authenticated <- TRUE
        auth_state$user_info <- session$userData$user_info
      }
    })
    
    # Google OAuth login
    observeEvent(input$google_login, {
      tryCatch({
        oauth_url <- oauth_middleware$generate_oauth_url("google", oauth_config, session)
        
        # Redirect to OAuth provider
        runjs(paste0("window.location.href = '", oauth_url, "';"))
      }, error = function(e) {
        auth_state$error_message <- paste("Erro na autenticação Google:", e$message)
        runjs("hideLoginLoading(); showLoginError('Erro na autenticação Google. Tente novamente.');")
      })
    })
    
    # Microsoft OAuth login
    observeEvent(input$microsoft_login, {
      tryCatch({
        oauth_url <- oauth_middleware$generate_oauth_url("microsoft", oauth_config, session)
        
        # Redirect to OAuth provider
        runjs(paste0("window.location.href = '", oauth_url, "';"))
      }, error = function(e) {
        auth_state$error_message <- paste("Erro na autenticação Microsoft:", e$message)
        runjs("hideLoginLoading(); showLoginError('Erro na autenticação Microsoft. Tente novamente.');")
      })
    })
    
    # Logout handler
    observeEvent(input$logout, {
      oauth_middleware$destroy_user_session(session)
      auth_state$authenticated <- FALSE
      auth_state$user_info <- NULL
      
      # Redirect to login page
      shinyjs::runjs("window.location.reload();")
    })
    
    # Return authentication state
    return(auth_state)
  })
}

# OAuth Callback Handler
# =====================

#' Handle OAuth callback
#' @param session Shiny session object
#' @param provider OAuth provider ("google" or "microsoft")
#' @param code Authorization code
#' @param state CSRF state parameter
#' @param oauth_config OAuth configuration
#' @return Boolean indicating success
handle_oauth_callback <- function(session, provider, code, state, oauth_config) {
  
  # Validate CSRF state
  if (is.null(session$userData$oauth_state) || session$userData$oauth_state != state) {
    return(list(success = FALSE, error = "CSRF validation failed"))
  }
  
  # Clear CSRF state
  session$userData$oauth_state <- NULL
  
  # Exchange code for token
  token_response <- oauth_middleware$exchange_code_for_token(provider, code, oauth_config)
  
  if (is.null(token_response)) {
    return(list(success = FALSE, error = "Token exchange failed"))
  }
  
  # Fetch user information
  user_info <- oauth_middleware$fetch_user_info(provider, token_response$access_token, oauth_config)
  
  if (is.null(user_info)) {
    return(list(success = FALSE, error = "Failed to fetch user information"))
  }
  
  # Create user session
  session_data <- oauth_middleware$create_user_session(user_info, provider, session, oauth_config)
  
  if (is.null(session_data)) {
    return(list(success = FALSE, error = "Failed to create user session"))
  }
  
  return(list(success = TRUE, user_info = session_data$user))
}

# Export module functions
auth_module <- list(
  ui = login_ui,
  server = auth_server,
  user_info_ui = user_info_ui,
  logout_button_ui = logout_button_ui,
  handle_oauth_callback = handle_oauth_callback
)