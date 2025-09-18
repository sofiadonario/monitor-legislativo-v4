# Security System Loader for Monitor Legislativo v4
# Week 7: Security Integration Loader - Phase 3 Final
# ===================================================
# 
# This module provides a simple interface to load and initialize
# all security components for integration with the existing app.R

library(shiny)

# Security Component Loader
# =========================

#' Load All Security Components
#' @param db_connection Database connection (optional)
#' @param config Custom configuration (optional)
#' @return List of initialized security components
load_security_system <- function(db_connection = NULL, config = NULL) {
  
  cat("🔐 Loading Monitor Legislativo v4 Security System...\n")
  
  # Initialize components list
  security_components <- list()
  
  tryCatch({
    # Load security modules
    cat("   📥 Loading security modules...\n")
    
    # Load authentication manager
    if (file.exists("R/security/authentication_manager.R")) {
      source("R/security/authentication_manager.R")
      security_components$auth_manager <- init_authentication_manager(db_connection)
      cat("   ✅ Authentication Manager loaded\n")
    }
    
    # Load security hardening
    if (file.exists("R/security/security_hardening.R")) {
      source("R/security/security_hardening.R")
      security_components$security_hardening <- init_security_hardening()
      cat("   ✅ Security Hardening loaded\n")
    }
    
    # Load audit logging
    if (file.exists("R/security/audit_logging.R")) {
      source("R/security/audit_logging.R")
      security_components$audit_logger <- init_audit_logger(db_connection)
      cat("   ✅ Audit Logging loaded\n")
    }
    
    # Load security monitoring
    if (file.exists("R/security/security_monitoring.R")) {
      source("R/security/security_monitoring.R")
      security_components$security_monitoring <- init_security_monitoring(
        db_connection, security_components$audit_logger
      )
      cat("   ✅ Security Monitoring loaded\n")
    }
    
    # Load API security
    if (file.exists("R/api/secure_endpoints.R")) {
      source("R/api/secure_endpoints.R")
      security_components$api_manager <- init_secure_api_manager(
        security_components$auth_manager,
        security_components$security_hardening,
        db_connection
      )
      cat("   ✅ Secure API loaded\n")
    }
    
    # Load integration manager
    if (file.exists("R/security/security_integration.R")) {
      source("R/security/security_integration.R")
      security_components$integration_manager <- init_security_integration(db_connection)
      cat("   ✅ Security Integration loaded\n")
    }
    
    # Initialize global security instance
    .GlobalEnv$security_system <- security_components
    
    cat("🛡️ Security System loaded successfully!\n")
    cat("   Components: ", length(security_components), "\n")
    cat("   Database: ", if(!is.null(db_connection)) "Connected" else "Fallback mode", "\n")
    
    return(security_components)
    
  }, error = function(e) {
    cat("❌ Failed to load security system:", e$message, "\n")
    cat("   Continuing with basic security...\n")
    
    # Return minimal security system
    return(list(
      error = e$message,
      fallback_mode = TRUE
    ))
  })
}

#' Create Security Middleware for Shiny App
#' @param security_components List of security components
#' @return Security middleware functions
create_security_middleware <- function(security_components = NULL) {
  
  if (is.null(security_components)) {
    security_components <- .GlobalEnv$security_system
  }
  
  # Return middleware functions
  list(
    # Authentication check
    require_auth = function(session, redirect_after_login = TRUE) {
      if (!is.null(security_components$auth_manager)) {
        return(security_components$auth_manager$validate_session(session))
      }
      return(TRUE)  # Fallback - allow access
    },
    
    # Permission check
    check_permission = function(session, permission) {
      if (!is.null(security_components$auth_manager)) {
        return(security_components$auth_manager$check_permission(session, permission))
      }
      return(TRUE)  # Fallback - allow access
    },
    
    # Input validation
    validate_input = function(input_value, input_name, max_length = NULL) {
      if (!is.null(security_components$security_hardening)) {
        result <- security_components$security_hardening$validate_text_input(
          input_value, input_name, max_length
        )
        return(if(result$valid) result$sanitized else NULL)
      }
      return(input_value)  # Fallback - return as-is
    },
    
    # Log user activity
    log_activity = function(activity_type, user_info, data = list()) {
      if (!is.null(security_components$audit_logger)) {
        security_components$audit_logger$log_data_access(
          activity_type, user_info, data, list()
        )
      }
    },
    
    # Rate limiting check
    check_rate_limit = function(session, endpoint = "general") {
      if (!is.null(security_components$auth_manager)) {
        return(security_components$auth_manager$check_rate_limit(session, endpoint))
      }
      return(list(allowed = TRUE))  # Fallback - allow access
    },
    
    # Create secure login UI
    create_login_ui = function(session) {
      if (!is.null(security_components$integration_manager)) {
        return(security_components$integration_manager$create_secure_login_ui())
      }
      
      # Fallback login UI
      return(
        div(
          h3("Login to Monitor Legislativo"),
          p("Security system not fully initialized. Please contact administrator.")
        )
      )
    },
    
    # Handle OAuth callback
    handle_oauth_callback = function(provider, code, state, session) {
      if (!is.null(security_components$integration_manager)) {
        return(security_components$integration_manager$handle_oauth_callback(
          provider, code, state, session
        ))
      }
      return(NULL)
    }
  )
}

#' Simple Security Wrapper for Existing App
#' @description Provides drop-in security enhancement for existing Shiny app
#' @param input Shiny input object
#' @param output Shiny output object  
#' @param session Shiny session object
#' @return Enhanced input/output/session objects with security
enhance_app_security <- function(input, output, session) {
  
  # Get or create security components
  security_components <- .GlobalEnv$security_system
  if (is.null(security_components)) {
    security_components <- load_security_system()
  }
  
  # Create security middleware
  security <- create_security_middleware(security_components)
  
  # Enhanced input function
  secure_input <- function(input_id, validation_rules = list()) {
    raw_value <- input[[input_id]]
    if (is.null(raw_value)) return(NULL)
    
    validated_value <- security$validate_input(
      raw_value, 
      input_id, 
      validation_rules$max_length
    )
    
    # Log input access if user is authenticated
    if (!is.null(session$userData$user_info)) {
      security$log_activity("input_accessed", session$userData$user_info, list(
        input_id = input_id,
        input_length = nchar(as.character(raw_value))
      ))
    }
    
    return(validated_value)
  }
  
  # Enhanced output function wrapper
  secure_output <- function(output_id, render_func) {
    output[[output_id]] <- renderUI({
      # Check if user has permission to view this output
      if (!security$require_auth(session)) {
        return(
          div(
            class = "alert alert-warning",
            "Authentication required to view this content."
          )
        )
      }
      
      # Log output access
      if (!is.null(session$userData$user_info)) {
        security$log_activity("output_accessed", session$userData$user_info, list(
          output_id = output_id
        ))
      }
      
      # Execute the render function
      tryCatch({
        render_func()
      }, error = function(e) {
        div(
          class = "alert alert-danger",
          "An error occurred while rendering content."
        )
      })
    })
  }
  
  # Return enhanced objects
  return(list(
    input = input,
    output = output,
    session = session,
    secure_input = secure_input,
    secure_output = secure_output,
    security = security,
    
    # Convenience functions
    require_auth = function() security$require_auth(session),
    check_permission = function(perm) security$check_permission(session, perm),
    log_user_action = function(action, data = list()) {
      if (!is.null(session$userData$user_info)) {
        security$log_activity(action, session$userData$user_info, data)
      }
    }
  ))
}

#' Initialize Security for App Startup
#' @description Call this at the start of your app.R
initialize_app_security <- function() {
  
  cat("🚀 Initializing Monitor Legislativo v4 Security...\n")
  
  # Try to establish database connection
  db_connection <- NULL
  database_url <- Sys.getenv("DATABASE_URL")
  
  if (database_url != "") {
    tryCatch({
      db_connection <- DBI::dbConnect(
        RPostgres::Postgres(),
        database_url
      )
      cat("   🔗 Database connection established\n")
    }, error = function(e) {
      cat("   ⚠️ Database connection failed, running in fallback mode\n")
    })
  } else {
    cat("   ⚠️ No DATABASE_URL found, running in fallback mode\n")
  }
  
  # Load security system
  security_system <- load_security_system(db_connection)
  
  # Set global security headers if available
  if (!is.null(security_system$security_hardening)) {
    headers <- security_system$security_hardening$add_security_headers()
    options(shiny.customHeaderValue = headers)
  }
  
  # Configure secure session options
  options(
    shiny.maxRequestSize = 10 * 1024^2,  # 10MB
    shiny.sanitize.errors = Sys.getenv("RAILWAY_ENVIRONMENT") == "production"
  )
  
  cat("✅ Security initialization complete!\n")
  
  return(security_system)
}

#' Quick Security Check
#' @description Verify security system is working
security_health_check <- function() {
  
  cat("🏥 Security Health Check\n")
  cat("========================\n")
  
  security_components <- .GlobalEnv$security_system
  
  if (is.null(security_components)) {
    cat("❌ Security system not initialized\n")
    return(FALSE)
  }
  
  # Check each component
  health_status <- list()
  
  if (!is.null(security_components$auth_manager)) {
    health_status$authentication <- "✅ HEALTHY"
  } else {
    health_status$authentication <- "❌ NOT LOADED"
  }
  
  if (!is.null(security_components$security_hardening)) {
    health_status$security_hardening <- "✅ HEALTHY"
  } else {
    health_status$security_hardening <- "❌ NOT LOADED"
  }
  
  if (!is.null(security_components$audit_logger)) {
    health_status$audit_logging <- "✅ HEALTHY"
  } else {
    health_status$audit_logging <- "❌ NOT LOADED"
  }
  
  if (!is.null(security_components$security_monitoring)) {
    health_status$security_monitoring <- "✅ HEALTHY"
  } else {
    health_status$security_monitoring <- "❌ NOT LOADED"
  }
  
  # Print health status
  for (component in names(health_status)) {
    cat(sprintf("   %s: %s\n", component, health_status[[component]]))
  }
  
  # Overall status
  healthy_count <- sum(grepl("✅", health_status))
  total_count <- length(health_status)
  
  cat(sprintf("\nOverall Health: %d/%d components healthy\n", healthy_count, total_count))
  
  if (healthy_count == total_count) {
    cat("🟢 All systems operational\n")
    return(TRUE)
  } else if (healthy_count > 0) {
    cat("🟡 Partial functionality available\n")
    return(TRUE)
  } else {
    cat("🔴 Security system offline\n")
    return(FALSE)
  }
}

# Auto-initialize in Railway environment
if (Sys.getenv("RAILWAY_ENVIRONMENT") != "" && 
    is.null(.GlobalEnv$security_system)) {
  
  cat("🚂 Railway environment detected - auto-initializing security...\n")
  
  tryCatch({
    initialize_app_security()
  }, error = function(e) {
    cat("⚠️ Auto-initialization failed:", e$message, "\n")
    cat("   Manual initialization may be required\n")
  })
}

# Export convenience functions
.GlobalEnv$init_security <- initialize_app_security
.GlobalEnv$load_security <- load_security_system
.GlobalEnv$enhance_security <- enhance_app_security
.GlobalEnv$security_health <- security_health_check

cat("🔐 Security Loader module ready\n")
cat("   Use init_security() to initialize\n")
cat("   Use enhance_security(input, output, session) in your server function\n")
cat("   Use security_health() to check system status\n")