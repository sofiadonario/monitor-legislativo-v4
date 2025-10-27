# Enhanced Authentication Manager for Monitor Legislativo v4
# Week 7: Authentication & User Management - Phase 3 Implementation
# ==================================================================
# 
# This module provides comprehensive authentication management including:
# - OAuth2 integration for institutional access
# - Role-based access control (RBAC)
# - Session management with security controls
# - Brazilian academic institution support
# - Railway deployment compatibility

library(shiny)
library(httr)
library(jsonlite)
library(digest)
library(uuid)
library(DBI)
library(lubridate)

# Global Authentication Configuration
# ==================================

.auth_config <- list(
  # OAuth2 Providers Configuration
  oauth2 = list(
    google = list(
      enabled = TRUE,
      client_id = Sys.getenv("GOOGLE_CLIENT_ID"),
      client_secret = Sys.getenv("GOOGLE_CLIENT_SECRET"),
      scope = "openid email profile",
      authorization_endpoint = "https://accounts.google.com/o/oauth2/auth",
      token_endpoint = "https://oauth2.googleapis.com/token",
      userinfo_endpoint = "https://www.googleapis.com/oauth2/v2/userinfo"
    ),
    microsoft = list(
      enabled = TRUE,
      client_id = Sys.getenv("MICROSOFT_CLIENT_ID"),
      client_secret = Sys.getenv("MICROSOFT_CLIENT_SECRET"),
      tenant = Sys.getenv("MICROSOFT_TENANT_ID", "common"),
      scope = "openid email profile User.Read",
      authorization_endpoint = paste0("https://login.microsoftonline.com/", 
                                    Sys.getenv("MICROSOFT_TENANT_ID", "common"), 
                                    "/oauth2/v2.0/authorize"),
      token_endpoint = paste0("https://login.microsoftonline.com/", 
                            Sys.getenv("MICROSOFT_TENANT_ID", "common"), 
                            "/oauth2/v2.0/token"),
      userinfo_endpoint = "https://graph.microsoft.com/v1.0/me"
    )
  ),
  
  # Brazilian Academic Institutions
  academic_institutions = list(
    federal_universities = c(
      "usp.br", "unicamp.br", "ufrj.br", "ufmg.br", "ufrgs.br", "ufsc.br",
      "unb.br", "ufpe.br", "ufba.br", "ufc.br", "ufpr.br", "ufpb.br",
      "ufscar.br", "ufes.br", "ufmt.br", "ufms.br", "ufpa.br", "ufal.br"
    ),
    state_universities = c(
      "usp.br", "unicamp.br", "unesp.br", "uerj.br", "uel.br", "uem.br",
      "uece.br", "uesb.br", "unioeste.br", "udesc.br", "uepg.br"
    ),
    private_universities = c(
      "mackenzie.br", "puc-rio.br", "pucsp.br", "pucrs.br", "pucminas.br",
      "unisinos.br", "fgv.br", "insper.edu.br", "puc-campinas.edu.br"
    ),
    research_institutions = c(
      "cnpq.br", "capes.gov.br", "fapesp.br", "faperj.br", "fapemig.br",
      "embrapa.br", "fiocruz.br", "ipea.gov.br", "ibge.gov.br"
    )
  ),
  
  # Role-Based Access Control Configuration
  rbac = list(
    roles = list(
      guest = list(
        level = 0,
        permissions = c("view_public_documents", "basic_search"),
        session_timeout_minutes = 30,
        rate_limit_per_hour = 60
      ),
      student = list(
        level = 1,
        permissions = c("view_public_documents", "basic_search", "advanced_search", 
                       "export_citations", "view_statistics"),
        session_timeout_minutes = 120,
        rate_limit_per_hour = 300,
        requires_verification = TRUE
      ),
      researcher = list(
        level = 2,
        permissions = c("view_public_documents", "basic_search", "advanced_search",
                       "export_citations", "view_statistics", "bulk_export",
                       "api_access", "analytics_dashboard"),
        session_timeout_minutes = 240,
        rate_limit_per_hour = 1000,
        requires_verification = TRUE
      ),
      faculty = list(
        level = 3,
        permissions = c("view_public_documents", "basic_search", "advanced_search",
                       "export_citations", "view_statistics", "bulk_export",
                       "api_access", "analytics_dashboard", "admin_tools"),
        session_timeout_minutes = 480,
        rate_limit_per_hour = 2000,
        requires_verification = TRUE
      ),
      admin = list(
        level = 4,
        permissions = c("all_permissions", "user_management", "system_config",
                       "security_monitoring", "audit_logs"),
        session_timeout_minutes = 480,
        rate_limit_per_hour = 5000,
        requires_mfa = TRUE
      )
    )
  ),
  
  # Security Configuration
  security = list(
    session_config = list(
      secure_cookies = TRUE,
      httponly_cookies = TRUE,
      samesite = "Strict",
      max_concurrent_sessions = 3,
      idle_timeout_minutes = 60,
      absolute_timeout_hours = 12
    ),
    
    csrf_protection = list(
      enabled = TRUE,
      token_lifetime_minutes = 60,
      require_referrer_check = TRUE
    ),
    
    rate_limiting = list(
      window_minutes = 60,
      burst_multiplier = 2,
      geographic_restrictions = list(
        brazil_multiplier = 1.0,
        other_countries_multiplier = 0.5
      )
    ),
    
    audit_logging = list(
      log_all_access = TRUE,
      log_failed_attempts = TRUE,
      log_role_changes = TRUE,
      retention_days = 365
    )
  )
)

# Authentication Manager Class
# ===========================

AuthenticationManager <- R6::R6Class(
  "AuthenticationManager",
  
  public = list(
    config = NULL,
    db_connection = NULL,
    
    # Initialize the authentication manager
    initialize = function(config = .auth_config, db_connection = NULL) {
      self$config <- config
      self$db_connection <- db_connection
      
      # Initialize security components
      private$init_security_tables()
      private$init_csrf_protection()
      
      message("✅ Authentication Manager initialized successfully")
    },
    
    # OAuth2 Authentication Methods
    # ============================
    
    # Generate OAuth2 authorization URL
    generate_oauth_url = function(provider, session, redirect_uri = NULL) {
      tryCatch({
        if (!provider %in% names(self$config$oauth2)) {
          stop("Unsupported OAuth2 provider: ", provider)
        }
        
        provider_config <- self$config$oauth2[[provider]]
        if (!provider_config$enabled) {
          stop("OAuth2 provider disabled: ", provider)
        }
        
        # Generate CSRF state token
        csrf_token <- private$generate_csrf_token(session)
        session$userData$oauth_state <- csrf_token
        
        # Set redirect URI
        if (is.null(redirect_uri)) {
          redirect_uri <- paste0(Sys.getenv("APP_BASE_URL", "http://localhost:3838"), 
                               "/auth/", provider, "/callback")
        }
        
        # Build authorization URL
        params <- list(
          client_id = provider_config$client_id,
          response_type = "code",
          scope = provider_config$scope,
          redirect_uri = redirect_uri,
          state = csrf_token,
          access_type = "offline"
        )
        
        query_string <- paste(
          names(params), 
          sapply(params, URLencode, reserved = TRUE),
          sep = "=", 
          collapse = "&"
        )
        
        auth_url <- paste0(provider_config$authorization_endpoint, "?", query_string)
        
        # Log authorization attempt
        private$log_security_event("oauth_authorization_started", list(
          provider = provider,
          user_ip = session$clientData$url_hostname,
          csrf_token = csrf_token
        ))
        
        return(auth_url)
        
      }, error = function(e) {
        private$log_security_event("oauth_authorization_error", list(
          provider = provider,
          error = e$message
        ))
        stop("Failed to generate OAuth URL: ", e$message)
      })
    },
    
    # Handle OAuth2 callback
    handle_oauth_callback = function(provider, code, state, session) {
      tryCatch({
        # Validate CSRF state
        if (!private$validate_csrf_token(state, session)) {
          stop("Invalid CSRF state token")
        }
        
        # Exchange code for tokens
        tokens <- private$exchange_authorization_code(provider, code)
        if (is.null(tokens)) {
          stop("Failed to exchange authorization code")
        }
        
        # Fetch user information
        user_info <- private$fetch_user_info(provider, tokens$access_token)
        if (is.null(user_info)) {
          stop("Failed to fetch user information")
        }
        
        # Process user authentication
        user_session <- self$authenticate_user(user_info, provider, session)
        
        return(user_session)
        
      }, error = function(e) {
        private$log_security_event("oauth_callback_error", list(
          provider = provider,
          error = e$message,
          user_ip = session$clientData$url_hostname
        ))
        stop("OAuth callback failed: ", e$message)
      })
    },
    
    # User Management Methods
    # ======================
    
    # Authenticate user and create session
    authenticate_user = function(user_info, provider, session) {
      tryCatch({
        # Determine user role based on email domain
        user_role <- private$determine_user_role(user_info$email)
        
        # Check if user requires verification
        requires_verification <- self$config$rbac$roles[[user_role]]$requires_verification
        
        # Create or update user record
        user_id <- private$create_or_update_user(user_info, provider, user_role)
        
        # Create secure session
        session_data <- private$create_user_session(user_id, user_info, user_role, session)
        
        # Set session data in Shiny session
        session$userData$authenticated <- TRUE
        session$userData$user_id <- user_id
        session$userData$user_info <- user_info
        session$userData$user_role <- user_role
        session$userData$session_token <- session_data$token
        session$userData$requires_verification <- requires_verification
        
        # Log successful authentication
        private$log_security_event("user_authenticated", list(
          user_id = user_id,
          email = user_info$email,
          provider = provider,
          role = user_role,
          ip_address = session$clientData$url_hostname
        ))
        
        return(session_data)
        
      }, error = function(e) {
        private$log_security_event("authentication_error", list(
          email = user_info$email %||% "unknown",
          provider = provider,
          error = e$message
        ))
        stop("User authentication failed: ", e$message)
      })
    },
    
    # Validate user session
    validate_session = function(session) {
      tryCatch({
        if (!isTRUE(session$userData$authenticated)) {
          return(FALSE)
        }
        
        session_token <- session$userData$session_token
        if (is.null(session_token)) {
          return(FALSE)
        }
        
        # Validate session in database
        session_valid <- private$validate_session_token(session_token, session)
        
        if (!session_valid) {
          # Clear invalid session
          self$logout_user(session)
          return(FALSE)
        }
        
        # Update session activity
        private$update_session_activity(session_token)
        
        return(TRUE)
        
      }, error = function(e) {
        private$log_security_event("session_validation_error", list(
          error = e$message,
          ip_address = session$clientData$url_hostname
        ))
        return(FALSE)
      })
    },
    
    # Check user permissions
    check_permission = function(session, required_permission) {
      if (!self$validate_session(session)) {
        return(FALSE)
      }
      
      user_role <- session$userData$user_role
      if (is.null(user_role)) {
        return(FALSE)
      }
      
      role_config <- self$config$rbac$roles[[user_role]]
      if (is.null(role_config)) {
        return(FALSE)
      }
      
      # Check if user has required permission
      has_permission <- required_permission %in% role_config$permissions ||
                       "all_permissions" %in% role_config$permissions
      
      # Log permission check
      if (!has_permission) {
        private$log_security_event("permission_denied", list(
          user_id = session$userData$user_id,
          required_permission = required_permission,
          user_role = user_role
        ))
      }
      
      return(has_permission)
    },
    
    # Logout user
    logout_user = function(session) {
      tryCatch({
        session_token <- session$userData$session_token
        user_id <- session$userData$user_id
        
        if (!is.null(session_token)) {
          # Invalidate session in database
          private$invalidate_session(session_token)
        }
        
        # Clear session data
        session$userData$authenticated <- FALSE
        session$userData$user_id <- NULL
        session$userData$user_info <- NULL
        session$userData$user_role <- NULL
        session$userData$session_token <- NULL
        session$userData$requires_verification <- NULL
        
        # Log logout event
        private$log_security_event("user_logout", list(
          user_id = user_id,
          session_token = session_token
        ))
        
        return(TRUE)
        
      }, error = function(e) {
        private$log_security_event("logout_error", list(
          error = e$message
        ))
        return(FALSE)
      })
    },
    
    # Rate Limiting Methods
    # ====================
    
    # Check rate limit for user
    check_rate_limit = function(session, endpoint = "general") {
      if (!self$validate_session(session)) {
        return(list(allowed = FALSE, reason = "Invalid session"))
      }
      
      user_id <- session$userData$user_id
      user_role <- session$userData$user_role
      
      if (isTRUE(is.null(user_id)) || isTRUE(is.null(user_role))) {
        return(list(allowed = FALSE, reason = "Missing user information"))
      }
      
      role_config <- self$config$rbac$roles[[user_role]]
      rate_limit <- role_config$rate_limit_per_hour
      
      # Check current usage
      current_usage <- private$get_user_rate_limit_usage(user_id, endpoint)
      
      if (current_usage >= rate_limit) {
        private$log_security_event("rate_limit_exceeded", list(
          user_id = user_id,
          endpoint = endpoint,
          current_usage = current_usage,
          rate_limit = rate_limit
        ))
        
        return(list(
          allowed = FALSE, 
          reason = "Rate limit exceeded",
          current_usage = current_usage,
          rate_limit = rate_limit
        ))
      }
      
      # Record API usage
      private$record_api_usage(user_id, endpoint)
      
      return(list(
        allowed = TRUE,
        current_usage = current_usage + 1,
        rate_limit = rate_limit
      ))
    }
  ),
  
  # Private Methods
  # ==============
  
  private = list(
    
    # Initialize security database tables
    init_security_tables = function() {
      if (is.null(self$db_connection)) {
        return()
      }
      
      tryCatch({
        # Users table
        DBI::dbExecute(self$db_connection, "
          CREATE TABLE IF NOT EXISTS auth_users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255),
            provider VARCHAR(50),
            provider_id VARCHAR(255),
            role VARCHAR(50) DEFAULT 'student',
            verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
          )
        ")
        
        # Sessions table
        DBI::dbExecute(self$db_connection, "
          CREATE TABLE IF NOT EXISTS auth_sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES auth_users(id) ON DELETE CASCADE,
            token VARCHAR(255) UNIQUE NOT NULL,
            ip_address INET,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            active BOOLEAN DEFAULT TRUE
          )
        ")
        
        # Security events table
        DBI::dbExecute(self$db_connection, "
          CREATE TABLE IF NOT EXISTS auth_security_events (
            id SERIAL PRIMARY KEY,
            event_type VARCHAR(100) NOT NULL,
            user_id INTEGER REFERENCES auth_users(id),
            ip_address INET,
            event_data JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        ")
        
        # Rate limiting table
        DBI::dbExecute(self$db_connection, "
          CREATE TABLE IF NOT EXISTS auth_rate_limits (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES auth_users(id) ON DELETE CASCADE,
            endpoint VARCHAR(100),
            request_count INTEGER DEFAULT 0,
            window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        ")
        
        message("✅ Security database tables initialized")
        
      }, error = function(e) {
        warning("Failed to initialize security tables: ", e$message)
      })
    },
    
    # Generate CSRF token
    generate_csrf_token = function(session) {
      token_data <- paste(
        Sys.time(),
        session$token,
        runif(1),
        sep = "_"
      )
      
      csrf_token <- digest(token_data, algo = "sha256")
      return(csrf_token)
    },
    
    # Validate CSRF token
    validate_csrf_token = function(token, session) {
      stored_token <- session$userData$oauth_state
      return(!isTRUE(is.null(stored_token)) && stored_token == token)
    },
    
    # Initialize CSRF protection
    init_csrf_protection = function() {
      # CSRF protection configuration
      if (self$config$security$csrf_protection$enabled) {
        message("✅ CSRF protection enabled")
      }
    },
    
    # Exchange authorization code for tokens
    exchange_authorization_code = function(provider, code) {
      provider_config <- self$config$oauth2[[provider]]
      
      tryCatch({
        response <- POST(
          provider_config$token_endpoint,
          body = list(
            grant_type = "authorization_code",
            client_id = provider_config$client_id,
            client_secret = provider_config$client_secret,
            code = code,
            redirect_uri = paste0(Sys.getenv("APP_BASE_URL", "http://localhost:3838"), 
                                "/auth/", provider, "/callback")
          ),
          encode = "form"
        )
        
        if (status_code(response) == 200) {
          return(content(response, "parsed"))
        } else {
          warning("Token exchange failed: ", status_code(response))
          return(NULL)
        }
        
      }, error = function(e) {
        warning("Token exchange error: ", e$message)
        return(NULL)
      })
    },
    
    # Fetch user information from OAuth provider
    fetch_user_info = function(provider, access_token) {
      provider_config <- self$config$oauth2[[provider]]
      
      tryCatch({
        response <- GET(
          provider_config$userinfo_endpoint,
          add_headers(Authorization = paste("Bearer", access_token))
        )
        
        if (status_code(response) == 200) {
          return(content(response, "parsed"))
        } else {
          warning("User info fetch failed: ", status_code(response))
          return(NULL)
        }
        
      }, error = function(e) {
        warning("User info fetch error: ", e$message)
        return(NULL)
      })
    },
    
    # Determine user role based on email domain
    determine_user_role = function(email) {
      if (isTRUE(is.null(email)) || email == "") {
        return("guest")
      }
      
      domain <- tolower(sub(".*@", "", email))
      
      # Check academic institutions
      all_academic_domains <- c(
        self$config$academic_institutions$federal_universities,
        self$config$academic_institutions$state_universities,
        self$config$academic_institutions$private_universities,
        self$config$academic_institutions$research_institutions
      )
      
      if (domain %in% all_academic_domains) {
        # Check if it's a research institution (higher privilege)
        if (domain %in% self$config$academic_institutions$research_institutions ||
            domain %in% c("mackenzie.br", "fgv.br", "insper.edu.br")) {
          return("researcher")
        } else {
          return("student")
        }
      }
      
      # Check for admin domains
      if (domain == "mackenzie.br" && grepl("@admin\\.", email)) {
        return("admin")
      }
      
      # Default role
      return("student")
    },
    
    # Create or update user record
    create_or_update_user = function(user_info, provider, role) {
      if (is.null(self$db_connection)) {
        return(paste0("user_", digest(user_info$email, algo = "md5")))
      }
      
      tryCatch({
        # Check if user exists
        existing_user <- DBI::dbGetQuery(
          self$db_connection,
          "SELECT id FROM auth_users WHERE email = $1",
          params = list(user_info$email)
        )
        
        if (nrow(existing_user) > 0) {
          # Update existing user
          user_id <- existing_user$id[1]
          DBI::dbExecute(
            self$db_connection,
            "UPDATE auth_users SET 
             name = $1, provider = $2, provider_id = $3, role = $4,
             updated_at = CURRENT_TIMESTAMP, last_login = CURRENT_TIMESTAMP
             WHERE id = $5",
            params = list(
              user_info$name %||% user_info$email,
              provider,
              user_info$id %||% user_info$email,
              role,
              user_id
            )
          )
        } else {
          # Create new user
          user_id <- DBI::dbGetQuery(
            self$db_connection,
            "INSERT INTO auth_users (email, name, provider, provider_id, role, last_login)
             VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
             RETURNING id",
            params = list(
              user_info$email,
              user_info$name %||% user_info$email,
              provider,
              user_info$id %||% user_info$email,
              role
            )
          )$id[1]
        }
        
        return(user_id)
        
      }, error = function(e) {
        warning("Failed to create/update user: ", e$message)
        return(paste0("user_", digest(user_info$email, algo = "md5")))
      })
    },
    
    # Create user session
    create_user_session = function(user_id, user_info, role, session) {
      session_token <- paste0(
        digest(paste(Sys.time(), user_id, runif(1), sep = "_"), algo = "sha256"),
        "_",
        UUIDgenerate()
      )
      
      role_config <- self$config$rbac$roles[[role]]
      session_timeout <- role_config$session_timeout_minutes * 60
      
      session_data <- list(
        token = session_token,
        user_id = user_id,
        user_info = user_info,
        role = role,
        created_at = Sys.time(),
        expires_at = Sys.time() + session_timeout,
        ip_address = session$clientData$url_hostname %||% "unknown"
      )
      
      # Store session in database
      if (!is.null(self$db_connection)) {
        tryCatch({
          DBI::dbExecute(
            self$db_connection,
            "INSERT INTO auth_sessions (user_id, token, ip_address, expires_at)
             VALUES ($1, $2, $3, $4)",
            params = list(
              user_id,
              session_token,
              session_data$ip_address,
              session_data$expires_at
            )
          )
        }, error = function(e) {
          warning("Failed to store session: ", e$message)
        })
      }
      
      return(session_data)
    },
    
    # Validate session token
    validate_session_token = function(session_token, session) {
      if (is.null(self$db_connection)) {
        return(TRUE)  # Fallback mode
      }
      
      tryCatch({
        session_data <- DBI::dbGetQuery(
          self$db_connection,
          "SELECT * FROM auth_sessions 
           WHERE token = $1 AND active = TRUE AND expires_at > CURRENT_TIMESTAMP",
          params = list(session_token)
        )
        
        return(nrow(session_data) > 0)
        
      }, error = function(e) {
        warning("Session validation error: ", e$message)
        return(FALSE)
      })
    },
    
    # Update session activity
    update_session_activity = function(session_token) {
      if (is.null(self$db_connection)) {
        return()
      }
      
      tryCatch({
        DBI::dbExecute(
          self$db_connection,
          "UPDATE auth_sessions SET last_activity = CURRENT_TIMESTAMP WHERE token = $1",
          params = list(session_token)
        )
      }, error = function(e) {
        warning("Failed to update session activity: ", e$message)
      })
    },
    
    # Invalidate session
    invalidate_session = function(session_token) {
      if (is.null(self$db_connection)) {
        return()
      }
      
      tryCatch({
        DBI::dbExecute(
          self$db_connection,
          "UPDATE auth_sessions SET active = FALSE WHERE token = $1",
          params = list(session_token)
        )
      }, error = function(e) {
        warning("Failed to invalidate session: ", e$message)
      })
    },
    
    # Get user rate limit usage
    get_user_rate_limit_usage = function(user_id, endpoint) {
      if (is.null(self$db_connection)) {
        return(0)
      }
      
      tryCatch({
        window_start <- Sys.time() - (self$config$security$rate_limiting$window_minutes * 60)
        
        result <- DBI::dbGetQuery(
          self$db_connection,
          "SELECT COALESCE(SUM(request_count), 0) as usage
           FROM auth_rate_limits
           WHERE user_id = $1 AND endpoint = $2 AND window_start >= $3",
          params = list(user_id, endpoint, window_start)
        )
        
        return(as.numeric(result$usage[1]))
        
      }, error = function(e) {
        warning("Failed to get rate limit usage: ", e$message)
        return(0)
      })
    },
    
    # Record API usage
    record_api_usage = function(user_id, endpoint) {
      if (is.null(self$db_connection)) {
        return()
      }
      
      tryCatch({
        DBI::dbExecute(
          self$db_connection,
          "INSERT INTO auth_rate_limits (user_id, endpoint, request_count, window_start)
           VALUES ($1, $2, 1, CURRENT_TIMESTAMP)
           ON CONFLICT (user_id, endpoint) DO UPDATE SET
           request_count = auth_rate_limits.request_count + 1",
          params = list(user_id, endpoint)
        )
      }, error = function(e) {
        warning("Failed to record API usage: ", e$message)
      })
    },
    
    # Log security events
    log_security_event = function(event_type, event_data) {
      # Console logging
      message(sprintf("[SECURITY] %s: %s", event_type, jsonlite::toJSON(event_data, auto_unbox = TRUE)))
      
      # Database logging
      if (!is.null(self$db_connection)) {
        tryCatch({
          DBI::dbExecute(
            self$db_connection,
            "INSERT INTO auth_security_events (event_type, user_id, ip_address, event_data)
             VALUES ($1, $2, $3, $4)",
            params = list(
              event_type,
              event_data$user_id,
              event_data$ip_address,
              jsonlite::toJSON(event_data, auto_unbox = TRUE)
            )
          )
        }, error = function(e) {
          warning("Failed to log security event: ", e$message)
        })
      }
    }
  )
)

# Utility Functions
# ================

#' Initialize Authentication Manager
#' @param db_connection Database connection (optional)
#' @return AuthenticationManager instance
init_authentication_manager <- function(db_connection = NULL) {
  auth_manager <- AuthenticationManager$new(config = .auth_config, db_connection = db_connection)
  return(auth_manager)
}

#' Null coalescing operator
`%||%` <- function(x, y) if (is.null(x)) y else x

# Export authentication manager for global use
.GlobalEnv$auth_manager <- NULL

# Initialize on module load
.onLoad <- function(libname, pkgname) {
  message("🔐 Enhanced Authentication Manager module loaded")
}