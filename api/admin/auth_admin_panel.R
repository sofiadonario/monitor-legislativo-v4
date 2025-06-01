# ============================================================================
# AUTHENTICATION ADMIN PANEL - SPRINT 6B (API-002)
# ============================================================================
# 
# Comprehensive administrative interface for managing the Brazilian Legislative API
# authentication system, including user management, API key lifecycle, and analytics
# 
# Features:
# - User account management and verification
# - API key lifecycle administration
# - Usage analytics and reporting
# - Security event monitoring
# - LGPD compliance management
# - System configuration
# - Bulk operations and maintenance
# - Academic institution management
# ============================================================================

cat("⚙️ Loading Authentication Admin Panel\n")

# Source required authentication modules
auth_modules <- c(
  "api/auth/authentication_system.R",
  "api/auth/api_key_management.R",
  "api/auth/user_registration.R",
  "api/auth/middleware_integration.R"
)

for (module in auth_modules) {
  if (file.exists(module)) {
    source(module)
  } else {
    cat("⚠️ Authentication module not found:", module, "\n")
  }
}

# Admin Panel Configuration
ADMIN_CONFIG <- list(
  # Access control
  admin_roles = c("super_admin", "admin", "moderator", "support"),
  admin_permissions = list(
    super_admin = c("all"),
    admin = c("user_management", "api_key_management", "analytics", "security", "system_config"),
    moderator = c("user_verification", "api_key_management", "analytics"),
    support = c("user_support", "analytics_read")
  ),
  
  # UI Configuration
  items_per_page = 50,
  max_export_records = 10000,
  
  # Security
  admin_session_timeout_minutes = 30,
  require_mfa = TRUE,
  audit_all_actions = TRUE
)

# ============================================================================
# USER MANAGEMENT ENDPOINTS
# ============================================================================

# Get all users with filtering and pagination
#* @get /admin/users
#* @param page:int Page number (default: 1)
#* @param limit:int Items per page (default: 50)
#* @param status:str Filter by status (active, suspended, deleted, pending)
#* @param tier:str Filter by tier (demo, academic, premium)
#* @param academic_status:str Filter by academic status
#* @param search:str Search in name, email, or institution
#* @tag admin
#* @serializer unboxedJSON
admin_get_users <- function(req, page = 1, limit = 50, status = NULL, tier = NULL, academic_status = NULL, search = NULL) {
  # Check admin permissions
  if (!check_admin_permission(req, "user_management")) {
    return(error_response("Insufficient permissions", 403))
  }
  
  tryCatch({
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(error_response("Database connection not available", 500))
    }
    
    # Build query with filters
    where_conditions <- c("1=1")
    params <- list()
    param_count <- 0
    
    if (!is.null(status)) {
      param_count <- param_count + 1
      where_conditions <- c(where_conditions, paste0("status = $", param_count))
      params[[param_count]] <- status
    }
    
    if (!is.null(tier)) {
      param_count <- param_count + 1
      where_conditions <- c(where_conditions, paste0("tier = $", param_count))
      params[[param_count]] <- tier
    }
    
    if (!is.null(academic_status)) {
      param_count <- param_count + 1
      where_conditions <- c(where_conditions, paste0("academic_status = $", param_count))
      params[[param_count]] <- academic_status
    }
    
    if (!is.null(search) && nchar(search) > 0) {
      param_count <- param_count + 1
      where_conditions <- c(where_conditions, paste0("(first_name ILIKE $", param_count, " OR last_name ILIKE $", param_count, " OR email ILIKE $", param_count, " OR institution_name ILIKE $", param_count, ")"))
      params[[param_count]] <- paste0("%", search, "%")
    }
    
    # Pagination
    limit <- min(as.numeric(limit), 100)
    offset <- (as.numeric(page) - 1) * limit
    param_count <- param_count + 1
    params[[param_count]] <- limit
    param_count <- param_count + 1
    params[[param_count]] <- offset
    
    # Main query
    query <- paste0("
      SELECT 
        id, email, first_name, last_name, title, institution_name,
        institution_country, department, position, research_field,
        tier, status, academic_status, verification_method,
        created_at, last_login_at, login_count, email_verified,
        consent_data_processing, consent_email_communication
      FROM users 
      WHERE ", paste(where_conditions, collapse = " AND "), "
      ORDER BY created_at DESC
      LIMIT $", param_count - 1, " OFFSET $", param_count
    )
    
    users <- DBI::dbGetQuery(secure_db_pool, query, params)
    
    # Get total count
    count_query <- paste0("
      SELECT COUNT(*) as total 
      FROM users 
      WHERE ", paste(head(where_conditions, -1), collapse = " AND ")
    )
    total_result <- DBI::dbGetQuery(secure_db_pool, count_query, head(params, -2))
    total_count <- total_result$total[1]
    
    # Log admin action
    log_admin_action(req, "users_list", paste("Retrieved", nrow(users), "users"))
    
    return(success_response(
      data = users,
      meta = list(
        page = as.numeric(page),
        limit = limit,
        total = total_count,
        total_pages = ceiling(total_count / limit),
        filters = list(status = status, tier = tier, academic_status = academic_status, search = search)
      ),
      message = paste("Retrieved", nrow(users), "users")
    ))
    
  }, error = function(e) {
    return(error_response(paste("Error retrieving users:", e$message), 500))
  })
}

# Get specific user details
#* @get /admin/users/<user_id>
#* @param user_id User ID
#* @tag admin
#* @serializer unboxedJSON
admin_get_user <- function(req, user_id) {
  if (!check_admin_permission(req, "user_management")) {
    return(error_response("Insufficient permissions", 403))
  }
  
  tryCatch({
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(error_response("Database connection not available", 500))
    }
    
    # Get user details
    user_query <- "
      SELECT u.*, 
        (SELECT COUNT(*) FROM api_keys WHERE user_id = u.id AND status = 'active') as active_api_keys,
        (SELECT SUM(total_requests) FROM api_keys WHERE user_id = u.id) as total_requests
      FROM users u 
      WHERE u.id = $1
    "
    user_result <- DBI::dbGetQuery(secure_db_pool, user_query, list(user_id))
    
    if (nrow(user_result) == 0) {
      return(error_response("User not found", 404))
    }
    
    user <- user_result[1, ]
    
    # Get user's API keys
    api_keys_query <- "
      SELECT id, api_key_prefix, api_key_suffix, key_name, tier, status, 
             total_requests, last_used_at, created_at, expires_at
      FROM api_keys 
      WHERE user_id = $1 
      ORDER BY created_at DESC
    "
    api_keys <- DBI::dbGetQuery(secure_db_pool, api_keys_query, list(user_id))
    
    # Get recent usage (last 30 days)
    usage_query <- "
      SELECT DATE(timestamp) as date, COUNT(*) as requests
      FROM api_usage_log 
      WHERE user_id = $1 AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
    "
    recent_usage <- DBI::dbGetQuery(secure_db_pool, usage_query, list(user_id))
    
    # Get verification documents
    docs_query <- "
      SELECT id, document_type, original_filename, verification_status, 
             upload_timestamp, reviewed_at, review_notes
      FROM user_verification_documents 
      WHERE user_id = $1 
      ORDER BY upload_timestamp DESC
    "
    verification_docs <- DBI::dbGetQuery(secure_db_pool, docs_query, list(user_id))
    
    # Log admin action
    log_admin_action(req, "user_view", paste("Viewed user", user_id))
    
    return(success_response(
      data = list(
        user = user,
        api_keys = api_keys,
        recent_usage = recent_usage,
        verification_documents = verification_docs
      ),
      message = "User details retrieved successfully"
    ))
    
  }, error = function(e) {
    return(error_response(paste("Error retrieving user:", e$message), 500))
  })
}

# Update user status and tier
#* @put /admin/users/<user_id>/status
#* @param user_id User ID
#* @param req Request object with JSON body
#* @tag admin
#* @serializer unboxedJSON
admin_update_user_status <- function(req, user_id) {
  if (!check_admin_permission(req, "user_management")) {
    return(error_response("Insufficient permissions", 403))
  }
  
  # Parse request body
  body <- tryCatch({
    jsonlite::fromJSON(req$postBody)
  }, error = function(e) {
    return(list())
  })
  
  new_status <- body$status
  new_tier <- body$tier
  new_academic_status <- body$academic_status
  admin_notes <- body$notes %||% ""
  
  if (is.null(new_status) && is.null(new_tier) && is.null(new_academic_status)) {
    return(error_response("At least one of status, tier, or academic_status must be provided", 400))
  }
  
  tryCatch({
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(error_response("Database connection not available", 500))
    }
    
    # Build update query
    update_fields <- c()
    params <- list()
    param_count <- 0
    
    if (!is.null(new_status)) {
      param_count <- param_count + 1
      update_fields <- c(update_fields, paste0("status = $", param_count))
      params[[param_count]] <- new_status
    }
    
    if (!is.null(new_tier)) {
      param_count <- param_count + 1
      update_fields <- c(update_fields, paste0("tier = $", param_count))
      params[[param_count]] <- new_tier
    }
    
    if (!is.null(new_academic_status)) {
      param_count <- param_count + 1
      update_fields <- c(update_fields, paste0("academic_status = $", param_count))
      params[[param_count]] <- new_academic_status
      
      if (new_academic_status == "verified") {
        param_count <- param_count + 1
        update_fields <- c(update_fields, paste0("verified_at = CURRENT_TIMESTAMP, verified_by = $", param_count))
        params[[param_count]] <- extract_admin_id(req)
      }
    }
    
    if (nchar(admin_notes) > 0) {
      param_count <- param_count + 1
      update_fields <- c(update_fields, paste0("notes = CONCAT(COALESCE(notes, ''), ' | Admin update: ', $", param_count, " at ', CURRENT_TIMESTAMP)"))
      params[[param_count]] <- admin_notes
    }
    
    param_count <- param_count + 1
    params[[param_count]] <- user_id
    
    update_query <- paste0("
      UPDATE users SET ", paste(update_fields, collapse = ", "), ", updated_at = CURRENT_TIMESTAMP
      WHERE id = $", param_count, "
    ")
    
    rows_affected <- DBI::dbExecute(secure_db_pool, update_query, params)
    
    if (rows_affected > 0) {
      # Log admin action
      log_admin_action(req, "user_update", paste("Updated user", user_id, "- Status:", new_status, "Tier:", new_tier, "Academic:", new_academic_status))
      
      return(success_response(
        data = list(user_id = user_id, updated = TRUE),
        message = "User updated successfully"
      ))
    } else {
      return(error_response("User not found", 404))
    }
    
  }, error = function(e) {
    return(error_response(paste("Error updating user:", e$message), 500))
  })
}

# ============================================================================
# API KEY MANAGEMENT ENDPOINTS
# ============================================================================

# Get all API keys with filtering
#* @get /admin/api-keys
#* @param page:int Page number (default: 1)
#* @param limit:int Items per page (default: 50)
#* @param status:str Filter by status
#* @param tier:str Filter by tier
#* @param user_id:int Filter by user ID
#* @tag admin
#* @serializer unboxedJSON
admin_get_api_keys <- function(req, page = 1, limit = 50, status = NULL, tier = NULL, user_id = NULL) {
  if (!check_admin_permission(req, "api_key_management")) {
    return(error_response("Insufficient permissions", 403))
  }
  
  tryCatch({
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(error_response("Database connection not available", 500))
    }
    
    # Build query with filters
    where_conditions <- c("1=1")
    params <- list()
    param_count <- 0
    
    if (!is.null(status)) {
      param_count <- param_count + 1
      where_conditions <- c(where_conditions, paste0("ak.status = $", param_count))
      params[[param_count]] <- status
    }
    
    if (!is.null(tier)) {
      param_count <- param_count + 1
      where_conditions <- c(where_conditions, paste0("ak.tier = $", param_count))
      params[[param_count]] <- tier
    }
    
    if (!is.null(user_id)) {
      param_count <- param_count + 1
      where_conditions <- c(where_conditions, paste0("ak.user_id = $", param_count))
      params[[param_count]] <- as.numeric(user_id)
    }
    
    # Pagination
    limit <- min(as.numeric(limit), 100)
    offset <- (as.numeric(page) - 1) * limit
    param_count <- param_count + 1
    params[[param_count]] <- limit
    param_count <- param_count + 1
    params[[param_count]] <- offset
    
    query <- paste0("
      SELECT 
        ak.id, ak.api_key_prefix, ak.api_key_suffix, ak.key_name,
        ak.tier, ak.status, ak.total_requests, ak.last_used_at,
        ak.created_at, ak.expires_at, ak.user_id,
        u.email as user_email, u.first_name || ' ' || u.last_name as user_name
      FROM api_keys ak
      JOIN users u ON ak.user_id = u.id
      WHERE ", paste(where_conditions, collapse = " AND "), "
      ORDER BY ak.created_at DESC
      LIMIT $", param_count - 1, " OFFSET $", param_count
    )
    
    api_keys <- DBI::dbGetQuery(secure_db_pool, query, params)
    
    # Get total count
    count_query <- paste0("
      SELECT COUNT(*) as total 
      FROM api_keys ak
      JOIN users u ON ak.user_id = u.id
      WHERE ", paste(head(where_conditions, -1), collapse = " AND ")
    )
    total_result <- DBI::dbGetQuery(secure_db_pool, count_query, head(params, -2))
    total_count <- total_result$total[1]
    
    log_admin_action(req, "api_keys_list", paste("Retrieved", nrow(api_keys), "API keys"))
    
    return(success_response(
      data = api_keys,
      meta = list(
        page = as.numeric(page),
        limit = limit,
        total = total_count,
        total_pages = ceiling(total_count / limit),
        filters = list(status = status, tier = tier, user_id = user_id)
      ),
      message = paste("Retrieved", nrow(api_keys), "API keys")
    ))
    
  }, error = function(e) {
    return(error_response(paste("Error retrieving API keys:", e$message), 500))
  })
}

# Revoke API key
#* @delete /admin/api-keys/<key_id>
#* @param key_id API key ID
#* @param req Request object
#* @tag admin
#* @serializer unboxedJSON
admin_revoke_api_key <- function(req, key_id) {
  if (!check_admin_permission(req, "api_key_management")) {
    return(error_response("Insufficient permissions", 403))
  }
  
  # Parse request body for reason
  body <- tryCatch({
    jsonlite::fromJSON(req$postBody)
  }, error = function(e) {
    return(list())
  })
  
  reason <- body$reason %||% "Revoked by administrator"
  
  tryCatch({
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(error_response("Database connection not available", 500))
    }
    
    # Get API key info first
    key_query <- "SELECT api_key_hash, user_id FROM api_keys WHERE id = $1"
    key_result <- DBI::dbGetQuery(secure_db_pool, key_query, list(key_id))
    
    if (nrow(key_result) == 0) {
      return(error_response("API key not found", 404))
    }
    
    # Revoke the key
    revoke_query <- "
      UPDATE api_keys 
      SET status = 'revoked',
          notes = CONCAT(COALESCE(notes, ''), ' | Revoked by admin: ', $1, ' at ', CURRENT_TIMESTAMP)
      WHERE id = $2
    "
    
    rows_affected <- DBI::dbExecute(secure_db_pool, revoke_query, list(reason, key_id))
    
    if (rows_affected > 0) {
      log_admin_action(req, "api_key_revoke", paste("Revoked API key", key_id, "- Reason:", reason))
      
      return(success_response(
        data = list(key_id = key_id, revoked = TRUE),
        message = "API key revoked successfully"
      ))
    } else {
      return(error_response("Failed to revoke API key", 500))
    }
    
  }, error = function(e) {
    return(error_response(paste("Error revoking API key:", e$message), 500))
  })
}

# ============================================================================
# ANALYTICS AND REPORTING ENDPOINTS
# ============================================================================

# Get system analytics dashboard
#* @get /admin/analytics/dashboard
#* @param period:str Time period (7d, 30d, 90d, 1y)
#* @tag admin
#* @serializer unboxedJSON
admin_get_dashboard_analytics <- function(req, period = "30d") {
  if (!check_admin_permission(req, "analytics")) {
    return(error_response("Insufficient permissions", 403))
  }
  
  tryCatch({
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(error_response("Database connection not available", 500))
    }
    
    # Parse period
    days <- switch(period,
      "7d" = 7,
      "30d" = 30,
      "90d" = 90,
      "1y" = 365,
      30
    )
    
    # User statistics
    user_stats_query <- "
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_users,
        COUNT(CASE WHEN academic_status = 'verified' THEN 1 END) as verified_academic_users,
        COUNT(CASE WHEN created_at >= CURRENT_TIMESTAMP - INTERVAL '%s days' THEN 1 END) as new_users_period
      FROM users
    "
    user_stats <- DBI::dbGetQuery(secure_db_pool, sprintf(user_stats_query, days))
    
    # API key statistics
    api_key_stats_query <- "
      SELECT 
        COUNT(*) as total_api_keys,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_api_keys,
        COUNT(CASE WHEN tier = 'demo' THEN 1 END) as demo_keys,
        COUNT(CASE WHEN tier = 'academic' THEN 1 END) as academic_keys,
        COUNT(CASE WHEN tier = 'premium' THEN 1 END) as premium_keys
      FROM api_keys
    "
    api_key_stats <- DBI::dbGetQuery(secure_db_pool, api_key_stats_query)
    
    # Usage statistics
    usage_stats_query <- "
      SELECT 
        COUNT(*) as total_requests,
        COUNT(DISTINCT user_id) as active_users,
        AVG(response_time_ms) as avg_response_time,
        COUNT(CASE WHEN response_code >= 400 THEN 1 END) as error_requests
      FROM api_usage_log
      WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
    "
    usage_stats <- DBI::dbGetQuery(secure_db_pool, sprintf(usage_stats_query, days))
    
    # Daily usage trend
    daily_usage_query <- "
      SELECT 
        DATE(timestamp) as date,
        COUNT(*) as requests,
        COUNT(DISTINCT user_id) as unique_users,
        AVG(response_time_ms) as avg_response_time
      FROM api_usage_log
      WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
    "
    daily_usage <- DBI::dbGetQuery(secure_db_pool, sprintf(daily_usage_query, days))
    
    # Top endpoints
    endpoint_usage_query <- "
      SELECT 
        endpoint,
        COUNT(*) as requests,
        AVG(response_time_ms) as avg_response_time
      FROM api_usage_log
      WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
      GROUP BY endpoint
      ORDER BY requests DESC
      LIMIT 10
    "
    endpoint_usage <- DBI::dbGetQuery(secure_db_pool, sprintf(endpoint_usage_query, days))
    
    # Recent security events
    security_events_query <- "
      SELECT 
        event_type,
        severity,
        COUNT(*) as count
      FROM security_events
      WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
      GROUP BY event_type, severity
      ORDER BY count DESC
    "
    security_events <- DBI::dbGetQuery(secure_db_pool, sprintf(security_events_query, days))
    
    log_admin_action(req, "dashboard_view", paste("Viewed dashboard analytics for", period))
    
    return(success_response(
      data = list(
        period = period,
        user_statistics = user_stats[1, ],
        api_key_statistics = api_key_stats[1, ],
        usage_statistics = usage_stats[1, ],
        daily_usage_trend = daily_usage,
        top_endpoints = endpoint_usage,
        security_events = security_events
      ),
      message = "Dashboard analytics retrieved successfully"
    ))
    
  }, error = function(e) {
    return(error_response(paste("Error retrieving analytics:", e$message), 500))
  })
}

# ============================================================================
# SECURITY MONITORING ENDPOINTS
# ============================================================================

# Get security events
#* @get /admin/security/events
#* @param page:int Page number (default: 1)
#* @param limit:int Items per page (default: 50)
#* @param severity:str Filter by severity (low, medium, high, critical)
#* @param event_type:str Filter by event type
#* @tag admin
#* @serializer unboxedJSON
admin_get_security_events <- function(req, page = 1, limit = 50, severity = NULL, event_type = NULL) {
  if (!check_admin_permission(req, "security")) {
    return(error_response("Insufficient permissions", 403))
  }
  
  tryCatch({
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(error_response("Database connection not available", 500))
    }
    
    # Build query with filters
    where_conditions <- c("1=1")
    params <- list()
    param_count <- 0
    
    if (!is.null(severity)) {
      param_count <- param_count + 1
      where_conditions <- c(where_conditions, paste0("severity = $", param_count))
      params[[param_count]] <- severity
    }
    
    if (!is.null(event_type)) {
      param_count <- param_count + 1
      where_conditions <- c(where_conditions, paste0("event_type = $", param_count))
      params[[param_count]] <- event_type
    }
    
    # Pagination
    limit <- min(as.numeric(limit), 100)
    offset <- (as.numeric(page) - 1) * limit
    param_count <- param_count + 1
    params[[param_count]] <- limit
    param_count <- param_count + 1
    params[[param_count]] <- offset
    
    query <- paste0("
      SELECT 
        id, event_type, severity, timestamp, source_ip,
        description, response_action, resolved, user_id
      FROM security_events
      WHERE ", paste(where_conditions, collapse = " AND "), "
      ORDER BY timestamp DESC
      LIMIT $", param_count - 1, " OFFSET $", param_count
    )
    
    events <- DBI::dbGetQuery(secure_db_pool, query, params)
    
    # Get total count
    count_query <- paste0("
      SELECT COUNT(*) as total 
      FROM security_events
      WHERE ", paste(head(where_conditions, -1), collapse = " AND ")
    )
    total_result <- DBI::dbGetQuery(secure_db_pool, count_query, head(params, -2))
    total_count <- total_result$total[1]
    
    log_admin_action(req, "security_events_view", paste("Viewed", nrow(events), "security events"))
    
    return(success_response(
      data = events,
      meta = list(
        page = as.numeric(page),
        limit = limit,
        total = total_count,
        total_pages = ceiling(total_count / limit),
        filters = list(severity = severity, event_type = event_type)
      ),
      message = paste("Retrieved", nrow(events), "security events")
    ))
    
  }, error = function(e) {
    return(error_response(paste("Error retrieving security events:", e$message), 500))
  })
}

# ============================================================================
# SYSTEM CONFIGURATION ENDPOINTS
# ============================================================================

# Get system configuration
#* @get /admin/config
#* @tag admin
#* @serializer unboxedJSON
admin_get_system_config <- function(req) {
  if (!check_admin_permission(req, "system_config")) {
    return(error_response("Insufficient permissions", 403))
  }
  
  tryCatch({
    if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
      return(error_response("Database connection not available", 500))
    }
    
    config_query <- "SELECT config_key, config_value, config_type, description FROM system_config ORDER BY config_key"
    config_result <- DBI::dbGetQuery(secure_db_pool, config_query)
    
    # Get tier limits
    tier_limits_query <- "SELECT * FROM api_tier_limits ORDER BY tier"
    tier_limits <- DBI::dbGetQuery(secure_db_pool, tier_limits_query)
    
    log_admin_action(req, "config_view", "Viewed system configuration")
    
    return(success_response(
      data = list(
        system_config = config_result,
        tier_limits = tier_limits
      ),
      message = "System configuration retrieved successfully"
    ))
    
  }, error = function(e) {
    return(error_response(paste("Error retrieving configuration:", e$message), 500))
  })
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Check admin permissions
check_admin_permission <- function(req, required_permission) {
  # For now, simplified check - in production, implement proper admin authentication
  if (is.null(req$auth)) {
    return(FALSE)
  }
  
  # Check if user has admin permission (placeholder)
  # In production, check against admin roles table
  admin_permissions <- req$auth$permissions %||% c()
  return("admin" %in% admin_permissions || "all" %in% admin_permissions)
}

# Extract admin ID from request
extract_admin_id <- function(req) {
  return(req$auth$user_id %||% "system")
}

# Log admin actions for audit trail
log_admin_action <- function(req, action, description) {
  admin_id <- extract_admin_id(req)
  client_ip <- extract_client_ip(req)
  
  audit_entry <- list(
    timestamp = Sys.time(),
    admin_id = admin_id,
    action = action,
    description = description,
    client_ip = client_ip,
    user_agent = req$HTTP_USER_AGENT %||% "unknown"
  )
  
  cat("👨‍💼 Admin Action [", action, "]:", description, "by", admin_id, "from", client_ip, "\n")
  
  # In production, store in dedicated admin audit table
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    tryCatch({
      DBI::dbExecute(secure_db_pool,
        "INSERT INTO security_events (event_type, severity, description, source_ip, user_id) VALUES ($1, $2, $3, $4, $5)",
        list("admin_action", "medium", paste("Admin action:", action, "-", description), client_ip, admin_id))
    }, error = function(e) {
      cat("Warning: Failed to log admin action:", e$message, "\n")
    })
  }
}

# Placeholder for additional helper functions
success_response <- function(data, message = "Success", meta = NULL) {
  response <- list(
    error = FALSE,
    message = message,
    data = data,
    timestamp = Sys.time()
  )
  
  if (!is.null(meta)) {
    response$meta <- meta
  }
  
  return(response)
}

error_response <- function(message, code = 500) {
  return(list(
    error = TRUE,
    message = message,
    code = code,
    timestamp = Sys.time()
  ))
}

cat("✅ Authentication Admin Panel Loaded\n")
cat("👨‍💼 Available admin endpoints:\n")
cat("  - GET  /admin/users (User management)\n")
cat("  - GET  /admin/users/<id> (User details)\n")
cat("  - PUT  /admin/users/<id>/status (Update user)\n")
cat("  - GET  /admin/api-keys (API key management)\n")
cat("  - DELETE /admin/api-keys/<id> (Revoke API key)\n")
cat("  - GET  /admin/analytics/dashboard (Analytics dashboard)\n")
cat("  - GET  /admin/security/events (Security monitoring)\n")
cat("  - GET  /admin/config (System configuration)\n")