# Authentication Module for Academic Legislative Monitor
# Simple authentication system for academic use

library(shiny)
library(shinydashboard)
library(digest)
library(futile.logger)

# Default academic credentials (change in production)
# Load secure configuration
source("R/config/secure_config.R")

# Load credentials from environment or configuration file
.auth_credentials <- get_auth_credentials()

#' Authenticate user credentials
#' @param username Username
#' @param password Plain text password
#' @return List with authentication result
authenticate_user <- function(username, password) {
  
  if (isTRUE(is.null(username)) || isTRUE(is.null(password)) || 
      username == "" || password == "") {
    return(list(
      success = FALSE,
      message = "Username and password are required"
    ))
  }
  
  # Check if user exists
  if (!username %in% names(.auth_credentials)) {
    flog.warn("Failed login attempt for unknown user: %s", username)
    return(list(
      success = FALSE,
      message = "Invalid username or password"
    ))
  }
  
  # Verify password
  password_hash <- digest(password, algo = "sha256")
  stored_hash <- .auth_credentials[[username]]$password_hash
  
  if (password_hash == stored_hash) {
    flog.info("Successful login for user: %s", username)
    return(list(
      success = TRUE,
      user = list(
        username = username,
        role = .auth_credentials[[username]]$role,
        name = .auth_credentials[[username]]$name,
        login_time = Sys.time()
      )
    ))
  } else {
    flog.warn("Failed login attempt for user: %s", username)
    return(list(
      success = FALSE,
      message = "Invalid username or password"
    ))
  }
}

#' Check if user is authenticated
#' @param session Shiny session object
#' @return TRUE if authenticated, FALSE otherwise
is_authenticated <- function(session) {
  
  if (is.null(session$userData$authenticated)) {
    return(FALSE)
  }
  
  return(session$userData$authenticated == TRUE)
}

#' Check if user has admin role
#' @param session Shiny session object
#' @return TRUE if admin, FALSE otherwise
is_admin <- function(session) {
  
  if (!is_authenticated(session)) {
    return(FALSE)
  }
  
  if (is.null(session$userData$user$role)) {
    return(FALSE)
  }
  
  return(session$userData$user$role == "admin")
}

#' Create login UI
#' @return Shiny UI for login page
create_login_ui <- function() {
  
  fluidPage(
    tags$head(
      tags$style(HTML("
        .login-container {
          max-width: 400px;
          margin: 100px auto;
          padding: 30px;
          background: white;
          border-radius: 10px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .login-header {
          text-align: center;
          margin-bottom: 30px;
          color: #2c3e50;
        }
        .login-form {
          margin-bottom: 20px;
        }
        .login-info {
          background: #e3f2fd;
          padding: 15px;
          border-radius: 5px;
          margin-top: 20px;
          font-size: 14px;
        }
        body {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          font-family: 'Segoe UI', sans-serif;
        }
      "))
    ),
    
    div(class = "login-container",
      div(class = "login-header",
        h2("🏛️ Monitor Legislativo Acadêmico"),
        h4("Sistema de Autenticação")
      ),
      
      div(class = "login-form",
        textInput(
          "username",
          "Usuário:",
          placeholder = "Digite seu usuário",
          width = "100%"
        ),
        
        passwordInput(
          "password", 
          "Senha:",
          placeholder = "Digite sua senha",
          width = "100%"
        ),
        
        br(),
        
        actionButton(
          "login_btn",
          "🔐 Entrar",
          class = "btn-primary btn-block",
          style = "width: 100%; margin-bottom: 10px;"
        ),
        
        div(id = "login_message", style = "margin-top: 10px;")
      ),
      
      div(class = "login-info",
        h5("ℹ️ Informações de Acesso"),
        p(strong("Para fins acadêmicos:")),
        tags$ul(
          tags$li("👨‍💼 admin / admin123 (Administrador)"),
          tags$li("👨‍🔬 researcher / research123 (Pesquisador)"),
          tags$li("👨‍🎓 student / student123 (Estudante)")
        ),
        br(),
        p(em("Nota: Em ambiente de produção, use credenciais institucionais seguras."))
      )
    )
  )
}

#' Handle login process
#' @param input Shiny input object
#' @param output Shiny output object  
#' @param session Shiny session object
handle_login <- function(input, output, session) {
  
  observeEvent(input$login_btn, {
    
    # Validate inputs
    if (isTRUE(is.null(input$username)) || isTRUE(is.null(input$password)) ||
        input$username == "" || input$password == "") {
      
      output$login_message <- renderUI({
        div(class = "alert alert-warning",
            "❌ Por favor, preencha usuário e senha.")
      })
      return()
    }
    
    # Attempt authentication
    auth_result <- authenticate_user(input$username, input$password)
    
    if (auth_result$success) {
      # Store authentication state
      session$userData$authenticated <- TRUE
      session$userData$user <- auth_result$user
      
      # Show success message briefly
      output$login_message <- renderUI({
        div(class = "alert alert-success",
            paste("✅ Login realizado com sucesso! Bem-vindo,", auth_result$user$name))
      })
      
      # Log successful authentication
      flog.info("User authenticated successfully: %s", auth_result$user$username)
      
      # The UI will update automatically via the observe() in app.R
      
    } else {
      # Show error message
      output$login_message <- renderUI({
        div(class = "alert alert-danger",
            paste("❌", auth_result$message))
      })
      
      # Clear password field
      updateTextInput(session, "password", value = "")
    }
  })
}

#' Create logout functionality
#' @param session Shiny session object
logout_user <- function(session) {
  
  if (is_authenticated(session)) {
    username <- session$userData$user$username
    flog.info("User logged out: %s", username)
  }
  
  # Clear authentication state
  session$userData$authenticated <- FALSE
  session$userData$user <- NULL
  
  # The UI will update automatically via the observe() in app.R
}

#' Create user info display
#' @param session Shiny session object
#' @return UI element with user info
create_user_info_ui <- function(session) {
  
  if (!is_authenticated(session)) {
    return(NULL)
  }
  
  user <- session$userData$user
  
  tagList(
    div(style = "float: right; margin-right: 15px; color: white;",
      span("👤", user$name, " | "),
      actionLink("logout_link", "🚪 Sair", style = "color: white;")
    )
  )
}

#' Require authentication wrapper
#' @param ui UI to show if authenticated
#' @param session Shiny session object
#' @return UI with authentication check
require_auth <- function(ui, session) {
  
  if (is_authenticated(session)) {
    return(ui)
  } else {
    return(create_login_ui())
  }
}

#' Session timeout check (optional)
#' @param session Shiny session object
#' @param timeout_minutes Timeout in minutes (default 30)
check_session_timeout <- function(session, timeout_minutes = 30) {
  
  if (!is_authenticated(session)) {
    return(FALSE)
  }
  
  if (is.null(session$userData$user$login_time)) {
    return(FALSE)
  }
  
  login_time <- session$userData$user$login_time
  current_time <- Sys.time()
  
  time_diff <- as.numeric(difftime(current_time, login_time, units = "mins"))
  
  if (time_diff > timeout_minutes) {
    flog.info("Session timeout for user: %s", session$userData$user$username)
    logout_user(session)
    return(FALSE)
  }
  
  return(TRUE)
}