#!/usr/bin/env Rscript

# Simple Authentication Test
# This script tests the authentication flow in isolation

library(shiny)
library(shinydashboard)
library(digest)

# Simple credentials for testing
test_credentials <- list(
  "admin" = list(
    password_hash = digest("admin123", algo = "sha256"),
    role = "admin",
    name = "Administrator"
  )
)

# Simple authentication function
test_authenticate <- function(username, password) {
  if (is.null(username) || is.null(password) || username == "" || password == "") {
    return(list(success = FALSE, message = "Username and password required"))
  }
  
  if (!username %in% names(test_credentials)) {
    return(list(success = FALSE, message = "Invalid credentials"))
  }
  
  password_hash <- digest(password, algo = "sha256")
  stored_hash <- test_credentials[[username]]$password_hash
  
  if (password_hash == stored_hash) {
    return(list(
      success = TRUE,
      user = list(
        username = username,
        role = test_credentials[[username]]$role,
        name = test_credentials[[username]]$name
      )
    ))
  } else {
    return(list(success = FALSE, message = "Invalid credentials"))
  }
}

# Simple login UI
create_test_login_ui <- function() {
  fluidPage(
    h2("Test Login"),
    br(),
    textInput("username", "Username:", placeholder = "admin"),
    passwordInput("password", "Password:", placeholder = "admin123"),
    br(),
    actionButton("login_btn", "Login", class = "btn-primary"),
    br(), br(),
    uiOutput("login_message")
  )
}

# Simple main UI
create_test_main_ui <- function() {
  dashboardPage(
    dashboardHeader(title = "Test Dashboard"),
    dashboardSidebar(
      sidebarMenu(
        menuItem("Dashboard", tabName = "dashboard", icon = icon("dashboard"))
      )
    ),
    dashboardBody(
      tabItems(
        tabItem(tabName = "dashboard",
          fluidRow(
            box(
              title = "Success!",
              status = "primary",
              solidHeader = TRUE,
              width = 12,
              h3("🎉 Authentication Working!"),
              p("You have successfully logged in."),
              p("The main dashboard is loading correctly."),
              actionButton("logout_btn", "Logout", class = "btn-warning")
            )
          )
        )
      )
    )
  )
}

# UI
ui <- fluidPage(
  uiOutput("ui")
)

# Server
server <- function(input, output, session) {
  
  # Initialize authentication state
  auth_state <- reactiveVal(FALSE)
  user_data <- reactiveVal(NULL)
  
  # UI switching based on authentication
  output$ui <- renderUI({
    if (auth_state()) {
      create_test_main_ui()
    } else {
      create_test_login_ui()
    }
  })
  
  # Handle login
  observeEvent(input$login_btn, {
    cat("\n=== LOGIN ATTEMPT ===\n")
    cat("Username:", input$username, "\n")
    cat("Password provided:", !is.null(input$password) && input$password != "", "\n")
    
    auth_result <- test_authenticate(input$username, input$password)
    
    cat("Auth result:", auth_result$success, "\n")
    
    if (auth_result$success) {
      cat("Setting auth_state to TRUE\n")
      auth_state(TRUE)
      user_data(auth_result$user)
      
      output$login_message <- renderUI({
        div(style = "color: green;", "✅ Login successful! Loading dashboard...")
      })
      
    } else {
      output$login_message <- renderUI({
        div(style = "color: red;", paste("❌", auth_result$message))
      })
    }
  })
  
  # Handle logout
  observeEvent(input$logout_btn, {
    cat("\n=== LOGOUT ===\n")
    auth_state(FALSE)
    user_data(NULL)
  })
  
  # Debug output
  observe({
    cat("Auth state changed to:", auth_state(), "\n")
  })
}

# Run the app
cat("\n=== STARTING TEST AUTH APP ===\n")
cat("URL: http://localhost:3838\n")
cat("Login: admin / admin123\n")
cat("==================================\n\n")

shinyApp(ui = ui, server = server)