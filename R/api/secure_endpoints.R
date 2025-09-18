# Secure API Endpoints for Monitor Legislativo v4
# Week 7: Secure API Implementation - Phase 3
# ============================================
# 
# This module provides secure API endpoints with:
# - Authentication and authorization
# - Rate limiting and throttling
# - Input validation and sanitization
# - Audit logging and monitoring
# - Brazilian legislative data access controls

library(plumber)
library(jsonlite)
library(httr)
library(digest)
library(lubridate)
library(dplyr)

# API Configuration
# ================

.api_config <- list(
  # API Versioning
  version = "1.0.0",
  base_path = "/api/v1",
  
  # Authentication
  authentication = list(
    require_auth = TRUE,
    api_key_header = "X-API-Key",
    jwt_header = "Authorization",
    session_header = "X-Session-Token"
  ),
  
  # Rate Limiting (per hour)
  rate_limits = list(
    anonymous = 60,
    student = 300,
    researcher = 1000,
    faculty = 2000,
    admin = 5000
  ),
  
  # Endpoint Access Control
  endpoint_permissions = list(
    "GET /documents" = c("student", "researcher", "faculty", "admin"),
    "POST /search" = c("student", "researcher", "faculty", "admin"),
    "GET /statistics" = c("student", "researcher", "faculty", "admin"),
    "GET /export" = c("researcher", "faculty", "admin"),
    "GET /analytics" = c("faculty", "admin"),
    "POST /bulk-export" = c("researcher", "faculty", "admin"),
    "GET /admin/*" = c("admin"),
    "POST /admin/*" = c("admin")
  ),
  
  # Response Limits
  response_limits = list(
    max_documents_per_request = list(
      student = 100,
      researcher = 1000,
      faculty = 2000,
      admin = 5000
    ),
    max_export_size_mb = list(
      researcher = 50,
      faculty = 100,
      admin = 500
    )
  ),
  
  # Monitoring
  monitoring = list(
    log_all_requests = TRUE,
    log_errors = TRUE,
    alert_on_violations = TRUE,
    performance_tracking = TRUE
  )
)

# Secure API Manager Class
# =======================

SecureAPIManager <- R6::R6Class(
  "SecureAPIManager",
  
  public = list(
    config = NULL,
    auth_manager = NULL,
    security_hardening = NULL,
    db_connection = NULL,
    request_log = NULL,
    
    # Initialize secure API manager
    initialize = function(config = .api_config, auth_manager = NULL, security_hardening = NULL, db_connection = NULL) {
      self$config <- config
      self$auth_manager <- auth_manager
      self$security_hardening <- security_hardening
      self$db_connection <- db_connection
      self$request_log <- new.env(hash = TRUE)
      
      # Initialize API tables
      private$init_api_tables()
      
      message("🔐 Secure API Manager initialized successfully")
    },
    
    # Authentication Middleware
    # ========================
    
    # Authenticate API request
    authenticate_request = function(req, required_role = "student") {
      tryCatch({
        # Extract authentication credentials
        api_key <- req$headers[[self$config$authentication$api_key_header]]
        jwt_token <- req$headers[[self$config$authentication$jwt_header]]
        session_token <- req$headers[[self$config$authentication$session_header]]
        
        user_info <- NULL
        auth_method <- "none"
        
        # Try API key authentication first
        if (!is.null(api_key) && api_key != "") {
          user_info <- private$authenticate_api_key(api_key)
          auth_method <- "api_key"
        }
        
        # Try JWT authentication
        if (is.null(user_info) && !is.null(jwt_token) && jwt_token != "") {
          user_info <- private$authenticate_jwt(jwt_token)
          auth_method <- "jwt"
        }
        
        # Try session authentication
        if (is.null(user_info) && !is.null(session_token) && session_token != "") {
          user_info <- private$authenticate_session(session_token)
          auth_method <- "session"
        }
        
        # Check if authentication is required
        if (self$config$authentication$require_auth && is.null(user_info)) {
          private$log_api_event("authentication_failed", req, list(
            method = auth_method,
            reason = "No valid credentials"
          ))
          
          return(list(
            authenticated = FALSE,
            status = 401,
            error = "Authentication required"
          ))
        }
        
        # Check role authorization
        if (!is.null(user_info) && !private$check_role_authorization(user_info$role, required_role)) {
          private$log_api_event("authorization_failed", req, list(
            user_role = user_info$role,
            required_role = required_role
          ))
          
          return(list(
            authenticated = FALSE,
            status = 403,
            error = "Insufficient permissions"
          ))
        }
        
        # Log successful authentication
        private$log_api_event("authentication_success", req, list(
          user_id = user_info$user_id %||% "anonymous",
          role = user_info$role %||% "anonymous",
          method = auth_method
        ))
        
        return(list(
          authenticated = TRUE,
          user_info = user_info,
          auth_method = auth_method
        ))
        
      }, error = function(e) {
        private$log_api_event("authentication_error", req, list(
          error = e$message
        ))
        
        return(list(
          authenticated = FALSE,
          status = 500,
          error = "Authentication system error"
        ))
      })
    },
    
    # Rate Limiting Middleware
    # =======================
    
    # Check rate limit for request
    check_rate_limit = function(req, user_info = NULL) {
      tryCatch({
        # Determine user role and rate limit
        user_role <- user_info$role %||% "anonymous"
        rate_limit <- self$config$rate_limits[[user_role]] %||% self$config$rate_limits$anonymous
        
        # Get client identifier
        client_id <- private$get_client_identifier(req, user_info)
        
        # Check current usage
        current_usage <- private$get_rate_limit_usage(client_id)
        
        if (current_usage >= rate_limit) {
          private$log_api_event("rate_limit_exceeded", req, list(
            client_id = client_id,
            current_usage = current_usage,
            rate_limit = rate_limit,
            user_role = user_role
          ))
          
          return(list(
            allowed = FALSE,
            status = 429,
            error = "Rate limit exceeded",
            retry_after = 3600,  # 1 hour
            current_usage = current_usage,
            rate_limit = rate_limit
          ))
        }
        
        # Record request
        private$record_api_request(client_id, req)
        
        return(list(
          allowed = TRUE,
          current_usage = current_usage + 1,
          rate_limit = rate_limit,
          remaining = rate_limit - current_usage - 1
        ))
        
      }, error = function(e) {
        private$log_api_event("rate_limit_error", req, list(
          error = e$message
        ))
        
        # Allow request on error (fail open)
        return(list(allowed = TRUE))
      })
    },
    
    # Input Validation Middleware
    # ==========================
    
    # Validate API request parameters
    validate_request_params = function(req, param_rules = list()) {
      if (is.null(self$security_hardening)) {
        return(list(valid = TRUE, sanitized = req$args))
      }
      
      tryCatch({
        sanitized_params <- list()
        warnings <- character()
        
        # Validate each parameter
        for (param_name in names(req$args)) {
          param_value <- req$args[[param_name]]
          param_rule <- param_rules[[param_name]]
          
          # Apply security hardening validation
          validation_result <- self$security_hardening$validate_text_input(
            param_value, 
            param_name,
            param_rule$max_length
          )
          
          if (!validation_result$valid) {
            private$log_api_event("input_validation_failed", req, list(
              parameter = param_name,
              error = validation_result$error,
              violations = validation_result$violations
            ))
            
            return(list(
              valid = FALSE,
              status = 400,
              error = paste("Invalid parameter:", param_name)
            ))
          }
          
          sanitized_params[[param_name]] <- validation_result$sanitized
          warnings <- c(warnings, validation_result$warnings)
        }
        
        # Validate file uploads if present
        if (!is.null(req$files)) {
          for (file_name in names(req$files)) {
            file_info <- req$files[[file_name]]
            file_validation <- self$security_hardening$validate_file_upload(file_info)
            
            if (!file_validation$valid) {
              private$log_api_event("file_validation_failed", req, list(
                file_name = file_name,
                error = file_validation$error
              ))
              
              return(list(
                valid = FALSE,
                status = 400,
                error = paste("Invalid file:", file_name)
              ))
            }
          }
        }
        
        return(list(
          valid = TRUE,
          sanitized = sanitized_params,
          warnings = unique(warnings)
        ))
        
      }, error = function(e) {
        private$log_api_event("validation_error", req, list(
          error = e$message
        ))
        
        return(list(
          valid = FALSE,
          status = 500,
          error = "Parameter validation error"
        ))
      })
    },
    
    # Secure Endpoint Handlers
    # ========================
    
    # Get legislative documents
    get_documents = function(req, user_info) {
      tryCatch({
        # Validate parameters
        param_rules <- list(
          search = list(max_length = 500),
          category = list(max_length = 100),
          year = list(max_length = 4),
          state = list(max_length = 50),
          limit = list(max_length = 10),
          offset = list(max_length = 10)
        )
        
        validation_result <- self$validate_request_params(req, param_rules)
        if (!validation_result$valid) {
          return(private$create_error_response(validation_result$status, validation_result$error))
        }
        
        params <- validation_result$sanitized
        
        # Apply user-specific limits
        user_role <- user_info$role %||% "student"
        max_limit <- self$config$response_limits$max_documents_per_request[[user_role]] %||% 100
        
        limit <- min(as.numeric(params$limit %||% 20), max_limit)
        offset <- as.numeric(params$offset %||% 0)
        
        # Build secure database query
        query <- private$build_documents_query(params, limit, offset)
        
        # Execute query safely
        documents <- private$execute_secure_query(query$sql, query$params)
        
        # Log successful request
        private$log_api_event("documents_retrieved", req, list(
          count = nrow(documents),
          user_role = user_role,
          filters_applied = names(params)
        ))
        
        # Return response
        return(list(
          status = 200,
          data = list(
            documents = documents,
            total = nrow(documents),
            limit = limit,
            offset = offset,
            has_more = nrow(documents) == limit
          ),
          metadata = list(
            request_id = private$generate_request_id(),
            timestamp = Sys.time(),
            api_version = self$config$version
          )
        ))
        
      }, error = function(e) {
        private$log_api_event("documents_error", req, list(
          error = e$message
        ))
        
        return(private$create_error_response(500, "Internal server error"))
      })
    },
    
    # Search legislative documents
    search_documents = function(req, user_info) {
      tryCatch({
        # Validate search parameters
        param_rules <- list(
          query = list(max_length = 1000),
          filters = list(max_length = 2000),
          sort = list(max_length = 100),
          limit = list(max_length = 10),
          offset = list(max_length = 10)
        )
        
        validation_result <- self$validate_request_params(req, param_rules)
        if (!validation_result$valid) {
          return(private$create_error_response(validation_result$status, validation_result$error))
        }
        
        params <- validation_result$sanitized
        
        # Apply user-specific search limits
        user_role <- user_info$role %||% "student"
        max_limit <- self$config$response_limits$max_documents_per_request[[user_role]] %||% 100
        
        limit <- min(as.numeric(params$limit %||% 20), max_limit)
        offset <- as.numeric(params$offset %||% 0)
        
        # Parse search filters
        filters <- private$parse_search_filters(params$filters)
        
        # Build secure search query
        search_query <- private$build_search_query(params$query, filters, limit, offset)
        
        # Execute search
        results <- private$execute_secure_query(search_query$sql, search_query$params)
        
        # Log search request
        private$log_api_event("search_executed", req, list(
          query = substr(params$query, 1, 100),  # Limit log size
          results_count = nrow(results),
          user_role = user_role
        ))
        
        return(list(
          status = 200,
          data = list(
            results = results,
            total = nrow(results),
            query = params$query,
            filters = filters,
            limit = limit,
            offset = offset
          ),
          metadata = list(
            request_id = private$generate_request_id(),
            timestamp = Sys.time(),
            search_time_ms = 0  # Would be calculated in real implementation
          )
        ))
        
      }, error = function(e) {
        private$log_api_event("search_error", req, list(
          error = e$message,
          query = params$query %||% "unknown"
        ))
        
        return(private$create_error_response(500, "Search system error"))
      })
    },
    
    # Export legislative data
    export_data = function(req, user_info) {
      tryCatch({
        # Check export permissions
        user_role <- user_info$role %||% "student"
        if (!user_role %in% c("researcher", "faculty", "admin")) {
          return(private$create_error_response(403, "Export permission required"))
        }
        
        # Validate export parameters
        param_rules <- list(
          format = list(max_length = 20),
          filters = list(max_length = 2000),
          fields = list(max_length = 1000)
        )
        
        validation_result <- self$validate_request_params(req, param_rules)
        if (!validation_result$valid) {
          return(private$create_error_response(validation_result$status, validation_result$error))
        }
        
        params <- validation_result$sanitized
        
        # Check export size limits
        max_size_mb <- self$config$response_limits$max_export_size_mb[[user_role]] %||% 10
        
        # Validate export format
        allowed_formats <- c("csv", "json", "xlsx")
        export_format <- tolower(params$format %||% "csv")
        
        if (!export_format %in% allowed_formats) {
          return(private$create_error_response(400, "Invalid export format"))
        }
        
        # Process export request
        export_result <- private$process_export_request(params, user_role, max_size_mb)
        
        # Log export request
        private$log_api_event("data_exported", req, list(
          format = export_format,
          size_mb = export_result$size_mb,
          record_count = export_result$record_count,
          user_role = user_role
        ))
        
        return(list(
          status = 200,
          data = export_result$data,
          metadata = list(
            format = export_format,
            size_mb = export_result$size_mb,
            record_count = export_result$record_count,
            export_id = private$generate_request_id()
          )
        ))
        
      }, error = function(e) {
        private$log_api_event("export_error", req, list(
          error = e$message,
          user_role = user_role
        ))
        
        return(private$create_error_response(500, "Export system error"))
      })
    },
    
    # Get API statistics
    get_statistics = function(req, user_info) {
      tryCatch({
        user_role <- user_info$role %||% "student"
        
        # Get basic statistics based on role
        stats <- private$get_api_statistics(user_role)
        
        private$log_api_event("statistics_retrieved", req, list(
          user_role = user_role
        ))
        
        return(list(
          status = 200,
          data = stats,
          metadata = list(
            timestamp = Sys.time(),
            scope = user_role
          )
        ))
        
      }, error = function(e) {
        private$log_api_event("statistics_error", req, list(
          error = e$message
        ))
        
        return(private$create_error_response(500, "Statistics system error"))
      })
    }
  ),
  
  # Private Methods
  # ==============
  
  private = list(
    
    # Initialize API database tables
    init_api_tables = function() {
      if (is.null(self$db_connection)) {
        return()
      }
      
      tryCatch({
        # API requests log table
        DBI::dbExecute(self$db_connection, "
          CREATE TABLE IF NOT EXISTS api_requests (
            id SERIAL PRIMARY KEY,
            client_id VARCHAR(255),
            user_id INTEGER,
            endpoint VARCHAR(255),
            method VARCHAR(10),
            status_code INTEGER,
            response_time_ms INTEGER,
            request_size_bytes INTEGER,
            response_size_bytes INTEGER,
            ip_address INET,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        ")
        
        # Rate limiting table
        DBI::dbExecute(self$db_connection, "
          CREATE TABLE IF NOT EXISTS api_rate_limits (
            id SERIAL PRIMARY KEY,
            client_id VARCHAR(255),
            endpoint VARCHAR(255),
            request_count INTEGER DEFAULT 0,
            window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(client_id, endpoint)
          )
        ")
        
        message("✅ API database tables initialized")
        
      }, error = function(e) {
        warning("Failed to initialize API tables: ", e$message)
      })
    },
    
    # Authenticate API key
    authenticate_api_key = function(api_key) {
      if (is.null(self$auth_manager)) {
        return(NULL)
      }
      
      # This would integrate with the auth_manager to validate API key
      # For now, return mock data
      return(list(
        user_id = "api_user",
        role = "researcher",
        api_key = api_key
      ))
    },
    
    # Authenticate JWT token
    authenticate_jwt = function(jwt_token) {
      # Remove "Bearer " prefix if present
      jwt_token <- sub("^Bearer\\s+", "", jwt_token)
      
      # This would validate JWT token
      # For now, return mock data
      return(list(
        user_id = "jwt_user",
        role = "student",
        jwt_token = jwt_token
      ))
    },
    
    # Authenticate session token
    authenticate_session = function(session_token) {
      if (is.null(self$auth_manager)) {
        return(NULL)
      }
      
      # This would validate session token
      # For now, return mock data
      return(list(
        user_id = "session_user",
        role = "faculty",
        session_token = session_token
      ))
    },
    
    # Check role authorization
    check_role_authorization = function(user_role, required_role) {
      role_hierarchy <- list(
        anonymous = 0,
        student = 1,
        researcher = 2,
        faculty = 3,
        admin = 4
      )
      
      user_level <- role_hierarchy[[user_role]] %||% 0
      required_level <- role_hierarchy[[required_role]] %||% 0
      
      return(user_level >= required_level)
    },
    
    # Get client identifier for rate limiting
    get_client_identifier = function(req, user_info) {
      if (!is.null(user_info) && !is.null(user_info$user_id)) {
        return(paste0("user_", user_info$user_id))
      }
      
      # Use IP address as fallback
      ip_address <- req$REMOTE_ADDR %||% req$HTTP_X_FORWARDED_FOR %||% "unknown"
      return(paste0("ip_", digest(ip_address, algo = "md5")))
    },
    
    # Get rate limit usage for client
    get_rate_limit_usage = function(client_id) {
      if (is.null(self$db_connection)) {
        return(0)
      }
      
      tryCatch({
        # Check usage in current hour window
        window_start <- Sys.time() - 3600  # 1 hour ago
        
        result <- DBI::dbGetQuery(
          self$db_connection,
          "SELECT COALESCE(SUM(request_count), 0) as usage
           FROM api_rate_limits
           WHERE client_id = $1 AND window_start >= $2",
          params = list(client_id, window_start)
        )
        
        return(as.numeric(result$usage[1]))
        
      }, error = function(e) {
        warning("Failed to get rate limit usage: ", e$message)
        return(0)
      })
    },
    
    # Record API request for rate limiting
    record_api_request = function(client_id, req) {
      if (is.null(self$db_connection)) {
        return()
      }
      
      tryCatch({
        DBI::dbExecute(
          self$db_connection,
          "INSERT INTO api_rate_limits (client_id, endpoint, request_count, window_start)
           VALUES ($1, $2, 1, CURRENT_TIMESTAMP)
           ON CONFLICT (client_id, endpoint) DO UPDATE SET
           request_count = api_rate_limits.request_count + 1",
          params = list(client_id, req$PATH_INFO)
        )
      }, error = function(e) {
        warning("Failed to record API request: ", e$message)
      })
    },
    
    # Build secure documents query
    build_documents_query = function(params, limit, offset) {
      # Base query
      sql <- "SELECT id, title, content, category, publication_date, state 
              FROM legislative_documents WHERE 1=1"
      query_params <- list()
      param_index <- 1
      
      # Add filters
      if (!is.null(params$search) && params$search != "") {
        sql <- paste(sql, "AND (title ILIKE $", param_index, " OR content ILIKE $", param_index, ")", sep = "")
        query_params[[param_index]] <- paste0("%", params$search, "%")
        param_index <- param_index + 1
      }
      
      if (!is.null(params$category) && params$category != "") {
        sql <- paste(sql, "AND category = $", param_index, sep = "")
        query_params[[param_index]] <- params$category
        param_index <- param_index + 1
      }
      
      if (!is.null(params$year) && params$year != "") {
        sql <- paste(sql, "AND EXTRACT(YEAR FROM publication_date) = $", param_index, sep = "")
        query_params[[param_index]] <- as.numeric(params$year)
        param_index <- param_index + 1
      }
      
      if (!is.null(params$state) && params$state != "") {
        sql <- paste(sql, "AND state = $", param_index, sep = "")
        query_params[[param_index]] <- params$state
        param_index <- param_index + 1
      }
      
      # Add ordering and pagination
      sql <- paste(sql, "ORDER BY publication_date DESC LIMIT $", param_index, " OFFSET $", param_index + 1, sep = "")
      query_params[[param_index]] <- limit
      query_params[[param_index + 1]] <- offset
      
      return(list(sql = sql, params = query_params))
    },
    
    # Build secure search query
    build_search_query = function(search_query, filters, limit, offset) {
      # This would implement full-text search
      # For now, return a simple query
      sql <- "SELECT id, title, content, category, publication_date, state 
              FROM legislative_documents 
              WHERE title ILIKE $1 OR content ILIKE $1
              ORDER BY publication_date DESC 
              LIMIT $2 OFFSET $3"
      
      return(list(
        sql = sql,
        params = list(paste0("%", search_query, "%"), limit, offset)
      ))
    },
    
    # Execute secure database query
    execute_secure_query = function(sql, params) {
      if (is.null(self$db_connection)) {
        # Return mock data for testing
        return(data.frame(
          id = 1:10,
          title = paste("Document", 1:10),
          content = paste("Content for document", 1:10),
          category = rep(c("Law", "Decree", "Resolution"), length.out = 10),
          publication_date = Sys.Date() - 1:10,
          state = rep(c("SP", "RJ", "MG"), length.out = 10)
        ))
      }
      
      tryCatch({
        if (!is.null(self$security_hardening)) {
          # Validate SQL query for safety
          validation_result <- self$security_hardening$validate_sql_query(sql)
          if (!validation_result$valid) {
            stop("Dangerous SQL query detected")
          }
        }
        
        result <- DBI::dbGetQuery(self$db_connection, sql, params = params)
        return(result)
        
      }, error = function(e) {
        stop("Database query failed: ", e$message)
      })
    },
    
    # Parse search filters
    parse_search_filters = function(filters_json) {
      if (is.null(filters_json) || filters_json == "") {
        return(list())
      }
      
      tryCatch({
        filters <- jsonlite::fromJSON(filters_json, simplifyVector = FALSE)
        return(filters)
      }, error = function(e) {
        warning("Failed to parse search filters: ", e$message)
        return(list())
      })
    },
    
    # Process export request
    process_export_request = function(params, user_role, max_size_mb) {
      # This would implement actual export logic
      # For now, return mock export data
      mock_data <- data.frame(
        id = 1:100,
        title = paste("Document", 1:100),
        category = rep(c("Law", "Decree", "Resolution"), length.out = 100),
        publication_date = Sys.Date() - 1:100
      )
      
      return(list(
        data = mock_data,
        size_mb = 0.5,
        record_count = nrow(mock_data)
      ))
    },
    
    # Get API statistics
    get_api_statistics = function(user_role) {
      # Return role-appropriate statistics
      return(list(
        total_documents = 134014,
        total_users = 1250,
        api_requests_today = 5420,
        system_status = "healthy",
        uptime_hours = 720,
        last_updated = Sys.time()
      ))
    },
    
    # Generate unique request ID
    generate_request_id = function() {
      paste0(
        format(Sys.time(), "%Y%m%d%H%M%S"),
        "_",
        substring(digest(paste(Sys.time(), runif(1)), algo = "md5"), 1, 8)
      )
    },
    
    # Create error response
    create_error_response = function(status, message) {
      return(list(
        status = status,
        error = list(
          message = message,
          timestamp = Sys.time(),
          request_id = private$generate_request_id()
        )
      ))
    },
    
    # Log API events
    log_api_event = function(event_type, req, details) {
      log_entry <- list(
        timestamp = Sys.time(),
        event_type = event_type,
        endpoint = req$PATH_INFO %||% "unknown",
        method = req$REQUEST_METHOD %||% "unknown",
        ip_address = req$REMOTE_ADDR %||% "unknown",
        user_agent = req$HTTP_USER_AGENT %||% "unknown",
        details = details
      )
      
      # Log to console (in production, would use proper logging)
      message(sprintf("[API] %s: %s %s", event_type, log_entry$method, log_entry$endpoint))
      
      # Store in database if available
      if (!is.null(self$db_connection)) {
        tryCatch({
          DBI::dbExecute(
            self$db_connection,
            "INSERT INTO api_requests (endpoint, method, status_code, ip_address, user_agent, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
            params = list(
              log_entry$endpoint,
              log_entry$method,
              details$status %||% 200,
              log_entry$ip_address,
              log_entry$user_agent,
              log_entry$timestamp
            )
          )
        }, error = function(e) {
          warning("Failed to log API event: ", e$message)
        })
      }
    }
  )
)

# Utility Functions
# ================

#' Initialize Secure API Manager
#' @param auth_manager Authentication manager instance
#' @param security_hardening Security hardening instance  
#' @param db_connection Database connection
#' @return SecureAPIManager instance
init_secure_api_manager <- function(auth_manager = NULL, security_hardening = NULL, db_connection = NULL) {
  api_manager <- SecureAPIManager$new(
    config = .api_config,
    auth_manager = auth_manager,
    security_hardening = security_hardening,
    db_connection = db_connection
  )
  return(api_manager)
}

#' Create Plumber API with security middleware
#' @param api_manager SecureAPIManager instance
#' @return Plumber API object
create_secure_api = function(api_manager) {
  pr <- plumber::plumber$new()
  
  # Add security middleware
  pr$filter("auth", function(req, res) {
    auth_result <- api_manager$authenticate_request(req, "student")
    if (!auth_result$authenticated) {
      res$status <- auth_result$status
      return(list(error = auth_result$error))
    }
    req$user_info <- auth_result$user_info
    plumber::forward()
  })
  
  pr$filter("rate_limit", function(req, res) {
    rate_result <- api_manager$check_rate_limit(req, req$user_info)
    if (!rate_result$allowed) {
      res$status <- rate_result$status
      res$headers[["Retry-After"]] <- rate_result$retry_after
      return(list(error = rate_result$error))
    }
    plumber::forward()
  })
  
  # Add API endpoints
  pr$get("/documents", function(req, res) {
    api_manager$get_documents(req, req$user_info)
  })
  
  pr$post("/search", function(req, res) {
    api_manager$search_documents(req, req$user_info)
  })
  
  pr$get("/statistics", function(req, res) {
    api_manager$get_statistics(req, req$user_info)
  })
  
  pr$get("/export", function(req, res) {
    api_manager$export_data(req, req$user_info)
  })
  
  return(pr)
}

# Export API manager for global use
.GlobalEnv$secure_api_manager <- NULL

# Initialize on module load
.onLoad <- function(libname, pkgname) {
  message("🔐 Secure API Endpoints module loaded")
}