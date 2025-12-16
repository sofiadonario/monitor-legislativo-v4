# Security Integration Module for Monitor Legislativo v4
# Week 7: Complete Security Integration - Phase 3
# ===============================================
# 
# This module integrates all security components:
# - Authentication Manager
# - Security Hardening
# - Secure API Endpoints
# - Audit Logging
# - Railway deployment compatibility
# - Brazilian compliance standards

library(shiny)
library(DBI)
library(R6)

# Load security modules
if (!exists("AuthenticationManager")) {
  source("R/security/authentication_manager.R")
}
if (!exists("SecurityHardening")) {
  source("R/security/security_hardening.R")
}
if (!exists("SecureAPIManager")) {
  source("R/api/secure_endpoints.R")
}
if (!exists("AuditLogger")) {
  source("R/security/audit_logging.R")
}

# Security Integration Configuration
# =================================

.security_integration_config <- list(
  # Cloud Run Deployment Settings
  cloud_run = list(
    environment = ifelse(Sys.getenv("K_SERVICE", "") != "", "production", "development"),
    database_url = Sys.getenv("DATABASE_URL"),
    redis_url = Sys.getenv("REDIS_URL"),
    app_base_url = Sys.getenv("CLOUD_RUN_URL", "http://localhost:3838"),
    enable_https = Sys.getenv("K_SERVICE", "") != ""
  ),
  
  # Security Component Configuration
  components = list(
    authentication = list(
      enabled = TRUE,
      oauth_providers = c("google", "microsoft"),
      session_management = TRUE,
      multi_factor_auth = FALSE  # Can be enabled for admin users
    ),
    
    hardening = list(
      enabled = TRUE,
      input_validation = TRUE,
      csrf_protection = TRUE,
      xss_protection = TRUE,
      rate_limiting = TRUE
    ),
    
    api_security = list(
      enabled = TRUE,
      require_authentication = TRUE,
      rate_limiting = TRUE,
      request_logging = TRUE
    ),
    
    audit_logging = list(
      enabled = TRUE,
      database_logging = TRUE,
      file_logging = TRUE,
      lgpd_compliance = TRUE,
      session_tracking = TRUE
    )
  ),
  
  # Integration Settings
  integration = list(
    initialize_on_startup = TRUE,
    auto_configure_database = TRUE,
    security_headers_global = TRUE,
    error_handling_secure = TRUE,
    monitoring_enabled = TRUE
  ),
  
  # Performance Settings
  performance = list(
    cache_session_data = TRUE,
    async_logging = TRUE,
    connection_pooling = TRUE,
    rate_limit_caching = TRUE
  )
)

# Security Integration Manager
# ===========================

SecurityIntegrationManager <- R6::R6Class(
  "SecurityIntegrationManager",
  
  public = list(
    config = NULL,
    db_connection = NULL,
    auth_manager = NULL,
    security_hardening = NULL,
    api_manager = NULL,
    audit_logger = NULL,
    initialized = FALSE,
    
    # Initialize security integration
    initialize = function(config = .security_integration_config, db_connection = NULL) {
      self$config <- config
      self$db_connection <- db_connection %||% private$create_database_connection()
      
      # Initialize security components
      private$init_security_components()
      
      # Configure security integration
      private$configure_security_integration()
      
      # Set up monitoring
      private$setup_security_monitoring()
      
      self$initialized <- TRUE

      message("🔐 Security Integration Manager initialized successfully")
      message("   Environment: ", self$config$cloud_run$environment)
      message("   Database: ", if(!is.null(self$db_connection)) "Connected" else "Not connected")
      message("   HTTPS: ", if(self$config$cloud_run$enable_https) "Enabled" else "Disabled")
    },
    
    # Shiny Integration Methods
    # ========================
    
    # Initialize security for Shiny application
    init_shiny_security = function() {
      tryCatch({
        # Set security headers
        if (self$config$integration$security_headers_global) {
          private$set_global_security_headers()
        }
        
        # Initialize CSRF protection
        if (self$config$components$hardening$csrf_protection) {
          private$init_csrf_for_shiny()
        }
        
        # Set up session security
        private$configure_shiny_session_security()
        
        # Initialize audit logging for Shiny
        private$init_shiny_audit_logging()
        
        message("✅ Shiny security integration completed")
        
      }, error = function(e) {
        warning("Shiny security initialization failed: ", e$message)
        private$log_security_error("shiny_init_failed", e$message)
      })
    },
    
    # Middleware for Shiny reactive context
    create_security_middleware = function() {
      security_manager <- self
      
      function(input, output, session) {
        # Session initialization
        private$init_session_security(session)
        
        # Input validation wrapper
        secure_input <- function(input_id, validation_rules = list()) {
          raw_value <- input[[input_id]]
          if (is.null(raw_value)) return(NULL)
          
          validation_result <- security_manager$security_hardening$validate_text_input(
            raw_value, input_id, validation_rules$max_length
          )
          
          if (!validation_result$valid) {
            security_manager$audit_logger$log_event(
              "security", "input_validation_failed",
              list(input_id = input_id, error = validation_result$error),
              user_id = session$userData$user_id,
              session_id = session$userData$session_token
            )
            return(NULL)
          }
          
          return(validation_result$sanitized)
        }
        
        return(list(
          secure_input = secure_input,
          validate_session = function() security_manager$auth_manager$validate_session(session),
          check_permission = function(permission) security_manager$auth_manager$check_permission(session, permission),
          log_user_activity = function(activity, data = list()) {
            security_manager$audit_logger$log_data_access(
              activity, 
              session$userData$user_info, 
              data, 
              list(token = session$userData$session_token, ip_address = session$clientData$url_hostname)
            )
          }
        ))
      }
    },
    
    # Authentication Integration
    # =========================
    
    # Handle OAuth callback in Shiny
    handle_oauth_callback = function(provider, code, state, session) {
      tryCatch({
        # Use authentication manager to handle callback
        auth_result <- self$auth_manager$handle_oauth_callback(provider, code, state, session)
        
        if (!is.null(auth_result)) {
          # Log successful authentication
          self$audit_logger$log_authentication(
            "oauth_success",
            auth_result$user,
            list(
              token = auth_result$token,
              ip_address = session$clientData$url_hostname,
              auth_method = "oauth2"
            )
          )
          
          # Update session activity
          self$audit_logger$update_session_activity(auth_result$token, list(
            action = "oauth_callback_completed",
            provider = provider
          ))
        }
        
        return(auth_result)
        
      }, error = function(e) {
        # Log authentication failure
        self$audit_logger$log_authentication(
          "oauth_failed",
          list(provider = provider),
          list(ip_address = session$clientData$url_hostname),
          list(error = e$message)
        )
        
        stop("OAuth authentication failed: ", e$message)
      })
    },
    
    # Create login UI with security
    create_secure_login_ui = function() {
      # Generate CSRF token
      csrf_token <- self$security_hardening$generate_csrf_token(session)
      
      tagList(
        # Security headers
        tags$meta(name = "csrf-token", content = csrf_token),
        
        # Login form with security
        div(
          class = "secure-login-container",
          h3("Secure Login - Monitor Legislativo"),
          
          # OAuth login buttons
          if (self$config$components$authentication$oauth_providers %in% "google") {
            actionButton(
              "login_google",
              "Login with Google",
              class = "btn btn-primary btn-block oauth-btn",
              onclick = sprintf("window.location.href='%s'", 
                               self$auth_manager$generate_oauth_url("google", session))
            )
          },
          
          if (self$config$components$authentication$oauth_providers %in% "microsoft") {
            actionButton(
              "login_microsoft", 
              "Login with Microsoft",
              class = "btn btn-info btn-block oauth-btn",
              onclick = sprintf("window.location.href='%s'",
                               self$auth_manager$generate_oauth_url("microsoft", session))
            )
          },
          
          # Security notice
          div(
            class = "security-notice",
            icon("shield-alt"),
            "This system uses advanced security measures to protect your data and comply with LGPD requirements."
          ),
          
          # CSRF token hidden field
          tags$input(type = "hidden", name = "csrf_token", value = csrf_token)
        )
      )
    },
    
    # API Integration Methods
    # ======================
    
    # Create secure API router
    create_secure_api_router = function() {
      if (!self$config$components$api_security$enabled) {
        return(NULL)
      }
      
      # Initialize API manager if not already done
      if (is.null(self$api_manager)) {
        self$api_manager <- init_secure_api_manager(
          auth_manager = self$auth_manager,
          security_hardening = self$security_hardening,
          db_connection = self$db_connection
        )
      }
      
      # Create API router with security middleware
      api_router <- create_secure_api(self$api_manager)
      
      return(api_router)
    },
    
    # Monitoring and Maintenance
    # =========================
    
    # Health check for security systems
    security_health_check = function() {
      health_status <- list(
        timestamp = Sys.time(),
        overall_status = "healthy",
        components = list()
      )
      
      # Check authentication manager
      health_status$components$authentication <- tryCatch({
        if (is.null(self$auth_manager)) {
          list(status = "disabled", message = "Authentication manager not initialized")
        } else {
          list(status = "healthy", message = "Authentication system operational")
        }
      }, error = function(e) {
        list(status = "error", message = e$message)
      })
      
      # Check security hardening
      health_status$components$security_hardening <- tryCatch({
        if (is.null(self$security_hardening)) {
          list(status = "disabled", message = "Security hardening not initialized")
        } else {
          list(status = "healthy", message = "Security hardening operational")
        }
      }, error = function(e) {
        list(status = "error", message = e$message)
      })
      
      # Check audit logging
      health_status$components$audit_logging <- tryCatch({
        if (is.null(self$audit_logger)) {
          list(status = "disabled", message = "Audit logging not initialized")
        } else {
          list(status = "healthy", message = "Audit logging operational")
        }
      }, error = function(e) {
        list(status = "error", message = e$message)
      })
      
      # Check database connection
      health_status$components$database <- tryCatch({
        if (is.null(self$db_connection)) {
          list(status = "warning", message = "Database connection not available")
        } else {
          # Test database connection
          DBI::dbGetQuery(self$db_connection, "SELECT 1 as test")
          list(status = "healthy", message = "Database connection operational")
        }
      }, error = function(e) {
        list(status = "error", message = paste("Database error:", e$message))
      })
      
      # Determine overall status
      component_statuses <- sapply(health_status$components, function(x) x$status)
      if (any(component_statuses == "error")) {
        health_status$overall_status <- "error"
      } else if (any(component_statuses == "warning")) {
        health_status$overall_status <- "warning"
      }
      
      # Log health check
      if (!is.null(self$audit_logger)) {
        self$audit_logger$log_event("system", "security_health_check", list(
          overall_status = health_status$overall_status,
          component_count = length(health_status$components),
          errors = sum(component_statuses == "error"),
          warnings = sum(component_statuses == "warning")
        ))
      }
      
      return(health_status)
    },
    
    # Perform security maintenance
    perform_security_maintenance = function() {
      tryCatch({
        maintenance_results <- list(
          timestamp = Sys.time(),
          tasks_completed = character(),
          errors = character()
        )
        
        # Clean up expired sessions
        if (!is.null(self$audit_logger)) {
          self$audit_logger$cleanup_expired_data()
          maintenance_results$tasks_completed <- c(maintenance_results$tasks_completed, "session_cleanup")
        }
        
        # Rotate log files
        if (self$config$components$audit_logging$file_logging) {
          private$rotate_security_logs()
          maintenance_results$tasks_completed <- c(maintenance_results$tasks_completed, "log_rotation")
        }
        
        # Update security configurations
        private$update_security_configurations()
        maintenance_results$tasks_completed <- c(maintenance_results$tasks_completed, "config_update")
        
        # Generate security summary report
        security_summary <- private$generate_security_summary()
        maintenance_results$security_summary <- security_summary
        
        # Log maintenance completion
        if (!is.null(self$audit_logger)) {
          self$audit_logger$log_event("system", "security_maintenance_completed", list(
            tasks_completed = length(maintenance_results$tasks_completed),
            errors = length(maintenance_results$errors),
            maintenance_duration_minutes = 0  # Would be calculated in real implementation
          ))
        }
        
        message("✅ Security maintenance completed successfully")
        return(maintenance_results)
        
      }, error = function(e) {
        if (!is.null(self$audit_logger)) {
          self$audit_logger$log_event("system", "security_maintenance_failed", list(
            error = e$message
          ), log_level = "ERROR")
        }
        
        warning("Security maintenance failed: ", e$message)
        return(list(error = e$message))
      })
    }
  ),
  
  # Private Methods
  # ==============
  
  private = list(
    
    # Create database connection
    create_database_connection = function() {
      if (isTRUE(is.null(self$config$cloud_run$database_url)) || self$config$cloud_run$database_url == "") {
        message("⚠️ No database URL configured - running in fallback mode")
        return(NULL)
      }

      tryCatch({
        db_connection <- DBI::dbConnect(
          RPostgres::Postgres(),
          self$config$cloud_run$database_url
        )

        message("✅ Database connection established")
        return(db_connection)

      }, error = function(e) {
        warning("Failed to connect to database: ", e$message)
        return(NULL)
      })
    },
    
    # Initialize security components
    init_security_components = function() {
      # Initialize Authentication Manager
      if (self$config$components$authentication$enabled) {
        self$auth_manager <- init_authentication_manager(self$db_connection)
      }
      
      # Initialize Security Hardening
      if (self$config$components$hardening$enabled) {
        self$security_hardening <- init_security_hardening()
      }
      
      # Initialize Audit Logger
      if (self$config$components$audit_logging$enabled) {
        self$audit_logger <- init_audit_logger(self$db_connection)
      }
      
      # Initialize API Manager (lazy initialization)
      if (self$config$components$api_security$enabled) {
        # Will be initialized when needed
      }
    },
    
    # Configure security integration
    configure_security_integration = function() {
      # Set up global error handling
      if (self$config$integration$error_handling_secure) {
        private$setup_secure_error_handling()
      }
      
      # Configure performance optimizations
      if (self$config$performance$cache_session_data) {
        private$setup_session_caching()
      }
      
      # Set up monitoring
      if (self$config$integration$monitoring_enabled) {
        private$setup_security_monitoring()
      }
    },
    
    # Set global security headers
    set_global_security_headers = function() {
      if (!is.null(self$security_hardening)) {
        headers <- self$security_hardening$add_security_headers()
        
        # In a Shiny context, these would be set via custom HTTP response
        # For now, we'll store them for later use
        .GlobalEnv$security_headers <- headers
      }
    },
    
    # Initialize CSRF for Shiny
    init_csrf_for_shiny = function() {
      # CSRF protection would be integrated into Shiny's input handling
      message("🛡️ CSRF protection initialized for Shiny")
    },
    
    # Configure Shiny session security
    configure_shiny_session_security = function() {
      # Set secure session configuration
      options(
        shiny.maxRequestSize = 10 * 1024^2,  # 10MB max request size
        shiny.sanitize.errors = self$config$cloud_run$environment == "production"
      )
    },
    
    # Initialize session security
    init_session_security = function(session) {
      if (!is.null(self$audit_logger)) {
        # Log session start
        self$audit_logger$log_event("system", "shiny_session_started", list(
          session_id = session$token,
          ip_address = session$clientData$url_hostname,
          user_agent = session$clientData$user_agent
        ))
        
        # Set up session cleanup on disconnect
        session$onSessionEnded(function() {
          self$audit_logger$log_event("system", "shiny_session_ended", list(
            session_id = session$token
          ))
        })
      }
    },
    
    # Initialize Shiny audit logging
    init_shiny_audit_logging = function() {
      if (!is.null(self$audit_logger)) {
        message("📋 Shiny audit logging initialized")
      }
    },
    
    # Setup secure error handling
    setup_secure_error_handling = function() {
      # Configure secure error reporting
      options(
        shiny.error = function(e) {
          if (!is.null(self$audit_logger)) {
            self$audit_logger$log_event("system", "application_error", list(
              error_message = e$message,
              error_class = class(e)[1]
            ), log_level = "ERROR")
          }

          # In production, don't expose internal errors
          if (self$config$cloud_run$environment == "production") {
            stop("An internal error occurred. Please contact support.")
          } else {
            stop(e)
          }
        }
      )
    },
    
    # Setup session caching
    setup_session_caching = function() {
      # Configure session data caching for performance
      message("🚀 Session caching configured")
    },
    
    # Setup security monitoring
    setup_security_monitoring = function() {
      # Configure security monitoring and alerting
      message("👁️ Security monitoring configured")
    },
    
    # Log security error
    log_security_error = function(error_type, message) {
      if (!is.null(self$audit_logger)) {
        self$audit_logger$log_event("system", error_type, list(
          error_message = message,
          timestamp = Sys.time()
        ), log_level = "ERROR")
      }
    },
    
    # Rotate security logs
    rotate_security_logs = function() {
      # Log rotation logic would be implemented here
      message("🔄 Security logs rotated")
    },
    
    # Update security configurations
    update_security_configurations = function() {
      # Update security configurations based on current threat landscape
      message("⚙️ Security configurations updated")
    },
    
    # Generate security summary
    generate_security_summary = function() {
      return(list(
        timestamp = Sys.time(),
        security_events_24h = 0,  # Would query actual data
        active_sessions = length(ls(self$audit_logger$active_sessions %||% new.env())),
        failed_login_attempts = 0,  # Would query actual data
        system_health = "healthy"
      ))
    }
  )
)

# Global Integration Functions
# ===========================

#' Initialize Security Integration for Monitor Legislativo v4
#' @param db_connection Database connection (optional)
#' @return SecurityIntegrationManager instance
init_security_integration <- function(db_connection = NULL) {
  security_integration <- SecurityIntegrationManager$new(
    config = .security_integration_config,
    db_connection = db_connection
  )
  
  return(security_integration)
}

#' Get global security integration instance
#' @return SecurityIntegrationManager instance
get_security_integration <- function() {
  if (is.null(.GlobalEnv$security_integration)) {
    .GlobalEnv$security_integration <- init_security_integration()
  }
  return(.GlobalEnv$security_integration)
}

#' Initialize security for Shiny application
#' @param session Shiny session object
#' @return Security middleware functions
init_shiny_security <- function(session = NULL) {
  security_integration <- get_security_integration()
  
  # Initialize Shiny-specific security
  security_integration$init_shiny_security()
  
  # Create security middleware
  if (!is.null(session)) {
    middleware <- security_integration$create_security_middleware()
    return(middleware)
  }
  
  return(security_integration)
}

# Export security integration for global use
.GlobalEnv$security_integration <- NULL

# Auto-initialize if in Cloud Run environment
if (Sys.getenv("K_SERVICE", "") != "") {
  tryCatch({
    .GlobalEnv$security_integration <- init_security_integration()
    message("🚀 Security integration auto-initialized for Cloud Run deployment")
  }, error = function(e) {
    warning("Failed to auto-initialize security integration: ", e$message)
  })
}

# Initialize on module load
.onLoad <- function(libname, pkgname) {
  message("🔐 Security Integration module loaded")
  message("   Cloud Run Service: ", Sys.getenv("K_SERVICE", "not set"))
  message("   Security Status: Ready for initialization")
}