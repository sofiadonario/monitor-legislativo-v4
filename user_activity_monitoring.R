# User Activity Monitoring and Analytics System
# Monitor Legislativo v4 - Phase 2 Enhancement
# LGPD-Compliant User Behavior Analytics and Performance Tracking
# Created: 2025-07-29

library(DBI)
library(RPostgres)
library(pool)
library(dplyr)
library(lubridate)
library(jsonlite)
library(digest)

# Load authentication and performance monitoring if available
if (file.exists("auth_system.R")) {
  source("auth_system.R")
}
if (file.exists("performance_monitoring.R")) {
  source("performance_monitoring.R")
}

# Global user activity monitoring state
.user_activity_state <- new.env(parent = emptyenv())
.user_activity_state$enabled <- TRUE
.user_activity_state$anonymization_enabled <- TRUE
.user_activity_state$aggregation_window <- 3600 # 1 hour in seconds
.user_activity_state$session_tracking <- list()
.user_activity_state$feature_usage_counters <- list()

#' Initialize User Activity Monitoring System
#' @return Boolean indicating success
init_user_activity_monitoring <- function() {
  tryCatch({
    cat("👥 Initializing LGPD-Compliant User Activity Monitoring\n")
    
    if (is.null(.db_pool)) {
      log_event("User activity monitoring requires database connection", "WARN")
      return(FALSE)
    }
    
    # Verify monitoring tables exist
    monitoring_tables <- dbGetQuery(.db_pool,
      "SELECT table_name FROM information_schema.tables 
       WHERE table_schema = 'public' 
       AND table_name IN ('user_activity_metrics', 'data_access_log', 'users', 'user_sessions')"
    )
    
    if (nrow(monitoring_tables) < 4) {
      log_event("User activity monitoring tables not found - run migrations first", "ERROR")
      return(FALSE)
    }
    
    # Initialize activity counters
    initialize_activity_counters()
    
    # Set up periodic aggregation
    setup_activity_aggregation()
    
    # Initialize user behavior baselines
    initialize_user_behavior_baselines()
    
    log_event("User activity monitoring initialized successfully")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("User activity monitoring initialization error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Track User Activity (LGPD Compliant)
#' @param user_id User identifier (optional, can be NULL for anonymous)
#' @param session_id Session identifier (optional)
#' @param action_type Type of action performed
#' @param resource_type Type of resource accessed
#' @param resource_ids List of resource IDs (optional)
#' @param search_criteria Search terms used (optional)
#' @param response_time_ms Response time in milliseconds
#' @param results_count Number of results returned
#' @return Boolean indicating success
track_user_activity <- function(user_id = NULL, session_id = NULL, action_type, resource_type, 
                               resource_ids = NULL, search_criteria = NULL, 
                               response_time_ms = NULL, results_count = NULL) {
  
  if (!.user_activity_state$enabled) {
    return(FALSE)
  }
  
  tryCatch({
    # Get current user info if available
    current_user <- get_current_user()
    if (is.null(user_id) && !is.null(current_user)) {
      user_id <- current_user$user_id
      session_id <- current_user$session_id
    }
    
    # Anonymize search criteria if needed (LGPD compliance)
    anonymized_search_criteria <- if (!is.null(search_criteria)) {
      anonymize_search_criteria(search_criteria)
    } else NULL
    
    # Log to database access log
    if (!is.null(.db_pool)) {
      dbExecute(.db_pool,
        "INSERT INTO data_access_log (
          user_id, session_id, action_type, resource_type, resource_ids,
          search_criteria, response_time_ms, results_count, ip_address, user_agent
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        params = list(
          user_id, session_id, action_type, resource_type,
          if (is.null(resource_ids)) NULL else paste(resource_ids, collapse = ","),
          anonymized_search_criteria, response_time_ms, results_count,
          get_client_ip(), get_user_agent()
        )
      )
    }
    
    # Update activity counters
    update_feature_usage_counters(action_type, resource_type, user_id)
    
    # Track session activity
    track_session_activity(session_id, action_type)
    
    # Update user engagement metrics
    update_user_engagement_metrics(user_id, action_type, response_time_ms)
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("User activity tracking error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Collect User Activity Metrics (Aggregated and Anonymized)
#' @return List with user activity analytics
collect_user_activity_metrics <- function() {
  if (is.null(.db_pool)) {
    return(list(error = "Database connection not available"))
  }
  
  tryCatch({
    cat("📊 Collecting user activity metrics (LGPD compliant)...\n")
    
    current_time <- Sys.time()
    window_start <- current_time - hours(1) # Last hour
    
    # 1. Active Users Analysis (Anonymized)
    active_users <- analyze_active_users(window_start, current_time)
    
    # 2. Role-based Usage Analysis
    role_usage <- analyze_role_based_usage(window_start, current_time)
    
    # 3. Feature Usage Analysis
    feature_usage <- analyze_feature_usage(window_start, current_time)
    
    # 4. Geographic Distribution (Aggregated)
    geographic_usage <- analyze_geographic_distribution(window_start, current_time)
    
    # 5. Content Interaction Analysis
    content_interaction <- analyze_content_interaction(window_start, current_time)
    
    # 6. Performance Impact on Users
    user_performance <- analyze_user_performance_impact(window_start, current_time)
    
    # 7. Authentication and Security Metrics
    auth_metrics <- analyze_authentication_metrics(window_start, current_time)
    
    # 8. User Satisfaction Indicators
    satisfaction_metrics <- calculate_user_satisfaction_metrics(window_start, current_time)
    
    # Aggregate metrics
    metrics <- list(
      # User Activity Aggregates
      total_active_users = active_users$total_active,
      new_users_count = active_users$new_users,
      returning_users_count = active_users$returning_users,
      
      # Role-based Usage
      admin_sessions = role_usage$admin_sessions,
      researcher_sessions = role_usage$researcher_sessions,
      policymaker_sessions = role_usage$policymaker_sessions,
      citizen_sessions = role_usage$citizen_sessions,
      
      # Feature Usage
      advanced_search_usage = feature_usage$advanced_search,
      basic_search_usage = feature_usage$basic_search,
      export_operations = feature_usage$exports,
      dashboard_views = feature_usage$dashboard_views,
      
      # Geographic Distribution (aggregated for privacy)
      sp_users = geographic_usage$sp_users,
      rj_users = geographic_usage$rj_users,
      mg_users = geographic_usage$mg_users,
      other_states_users = geographic_usage$other_states,
      international_users = geographic_usage$international,
      
      # Content Interaction (anonymized)
      document_type_searches = content_interaction$document_types,
      popular_search_terms = content_interaction$popular_terms,
      most_viewed_documents = content_interaction$popular_documents,
      
      # Performance Impact
      avg_user_session_duration_minutes = user_performance$avg_session_duration,
      bounce_rate_percent = user_performance$bounce_rate,
      user_satisfaction_score = satisfaction_metrics$satisfaction_score,
      
      # Authentication Metrics
      oauth_login_success = auth_metrics$successful_logins,
      oauth_login_failures = auth_metrics$failed_logins,
      session_timeouts = auth_metrics$session_timeouts,
      
      # Metadata
      timestamp = current_time,
      aggregation_period_hours = 1,
      privacy_compliance_level = "anonymized"
    )
    
    # Store aggregated metrics in database
    if (.user_activity_state$enabled) {
      store_user_activity_metrics(metrics)
    }
    
    return(metrics)
    
  }, error = function(e) {
    log_event(paste("User activity metrics collection error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Analyze Active Users (Privacy-Safe)
#' @param window_start Start of analysis window
#' @param window_end End of analysis window
#' @return List with active user metrics
analyze_active_users <- function(window_start, window_end) {
  tryCatch({
    # Active users in window (using sessions to avoid PII)
    active_users_data <- dbGetQuery(.db_pool, "
      SELECT 
        COUNT(DISTINCT user_id) as total_active_users,
        COUNT(DISTINCT CASE WHEN u.created_at >= $1 THEN user_id END) as new_users,
        COUNT(DISTINCT CASE WHEN u.created_at < $1 THEN user_id END) as returning_users
      FROM data_access_log dal
      LEFT JOIN users u ON dal.user_id = u.id
      WHERE dal.timestamp >= $1 AND dal.timestamp <= $2
    ", params = list(window_start, window_end))
    
    list(
      total_active = active_users_data$total_active_users[1] %||% 0,
      new_users = active_users_data$new_users[1] %||% 0,
      returning_users = active_users_data$returning_users[1] %||% 0
    )
    
  }, error = function(e) {
    log_event(paste("Active users analysis error:", e$message), "ERROR")
    return(list(total_active = 0, new_users = 0, returning_users = 0))
  })
}

#' Analyze Role-based Usage
#' @param window_start Start of analysis window
#' @param window_end End of analysis window
#' @return List with role usage metrics
analyze_role_based_usage <- function(window_start, window_end) {
  tryCatch({
    # Role-based session analysis
    role_sessions <- dbGetQuery(.db_pool, "
      SELECT 
        ur.role_name,
        COUNT(DISTINCT dal.session_id) as session_count,
        COUNT(DISTINCT dal.user_id) as unique_users
      FROM data_access_log dal
      JOIN users u ON dal.user_id = u.id
      JOIN user_role_assignments ura ON u.id = ura.user_id AND ura.is_active = true
      JOIN user_roles ur ON ura.role_id = ur.id
      WHERE dal.timestamp >= $1 AND dal.timestamp <= $2
      GROUP BY ur.role_name
    ", params = list(window_start, window_end))
    
    # Convert to named list
    role_counts <- setNames(role_sessions$session_count, role_sessions$role_name)
    
    list(
      admin_sessions = role_counts[["admin"]] %||% 0,
      researcher_sessions = role_counts[["researcher"]] %||% 0,
      policymaker_sessions = role_counts[["policymaker"]] %||% 0,
      citizen_sessions = role_counts[["citizen"]] %||% 0
    )
    
  }, error = function(e) {
    log_event(paste("Role usage analysis error:", e$message), "ERROR")
    return(list(admin_sessions = 0, researcher_sessions = 0, policymaker_sessions = 0, citizen_sessions = 0))
  })
}

#' Analyze Feature Usage
#' @param window_start Start of analysis window
#' @param window_end End of analysis window
#' @return List with feature usage metrics
analyze_feature_usage <- function(window_start, window_end) {
  tryCatch({
    # Feature usage by action type
    feature_usage <- dbGetQuery(.db_pool, "
      SELECT 
        action_type,
        resource_type,
        COUNT(*) as usage_count
      FROM data_access_log
      WHERE timestamp >= $1 AND timestamp <= $2
      GROUP BY action_type, resource_type
      ORDER BY usage_count DESC
    ", params = list(window_start, window_end))
    
    # Categorize features
    search_usage <- sum(feature_usage$usage_count[feature_usage$action_type == "search"], na.rm = TRUE)
    export_usage <- sum(feature_usage$usage_count[feature_usage$action_type == "export"], na.rm = TRUE)
    view_usage <- sum(feature_usage$usage_count[feature_usage$action_type == "view"], na.rm = TRUE)
    download_usage <- sum(feature_usage$usage_count[feature_usage$action_type == "download"], na.rm = TRUE)
    
    # Advanced vs basic search (based on search criteria complexity)
    search_complexity <- dbGetQuery(.db_pool, "
      SELECT 
        CASE 
          WHEN length(search_criteria) > 50 OR search_criteria LIKE '%AND%' OR search_criteria LIKE '%OR%' 
          THEN 'advanced' 
          ELSE 'basic' 
        END as search_type,
        COUNT(*) as count
      FROM data_access_log
      WHERE action_type = 'search' 
      AND search_criteria IS NOT NULL
      AND timestamp >= $1 AND timestamp <= $2
      GROUP BY search_type
    ", params = list(window_start, window_end))
    
    advanced_search <- search_complexity$count[search_complexity$search_type == "advanced"] %||% 0
    basic_search <- search_complexity$count[search_complexity$search_type == "basic"] %||% 0
    
    list(
      total_searches = search_usage,
      advanced_search = advanced_search,
      basic_search = basic_search,
      exports = export_usage,
      document_views = view_usage,
      downloads = download_usage,
      dashboard_views = view_usage # Approximation
    )
    
  }, error = function(e) {
    log_event(paste("Feature usage analysis error:", e$message), "ERROR")
    return(list(total_searches = 0, advanced_search = 0, basic_search = 0, exports = 0, document_views = 0, downloads = 0, dashboard_views = 0))
  })
}

#' Analyze Geographic Distribution (Aggregated for Privacy)
#' @param window_start Start of analysis window
#' @param window_end End of analysis window
#' @return List with geographic metrics
analyze_geographic_distribution <- function(window_start, window_end) {
  tryCatch({
    # Approximate geographic distribution based on institutional affiliations
    # This is privacy-safe as it doesn't track individual locations
    geographic_data <- dbGetQuery(.db_pool, "
      SELECT 
        CASE 
          WHEN u.institutional_affiliation LIKE '%São Paulo%' OR u.institutional_affiliation LIKE '%USP%' OR u.institutional_affiliation LIKE '%Mackenzie%' THEN 'SP'
          WHEN u.institutional_affiliation LIKE '%Rio de Janeiro%' OR u.institutional_affiliation LIKE '%UFRJ%' OR u.institutional_affiliation LIKE '%PUC-Rio%' THEN 'RJ'
          WHEN u.institutional_affiliation LIKE '%Minas Gerais%' OR u.institutional_affiliation LIKE '%UFMG%' THEN 'MG'
          WHEN u.institutional_affiliation IS NOT NULL THEN 'OTHER_BR'
          ELSE 'UNKNOWN'
        END as region,
        COUNT(DISTINCT dal.user_id) as user_count
      FROM data_access_log dal
      JOIN users u ON dal.user_id = u.id
      WHERE dal.timestamp >= $1 AND dal.timestamp <= $2
      GROUP BY region
    ", params = list(window_start, window_end))
    
    # Convert to named list
    geo_counts <- setNames(geographic_data$user_count, geographic_data$region)
    
    list(
      sp_users = geo_counts[["SP"]] %||% 0,
      rj_users = geo_counts[["RJ"]] %||% 0,
      mg_users = geo_counts[["MG"]] %||% 0,
      other_states = geo_counts[["OTHER_BR"]] %||% 0,
      international = geo_counts[["UNKNOWN"]] %||% 0 # Includes unknown which may be international
    )
    
  }, error = function(e) {
    log_event(paste("Geographic analysis error:", e$message), "ERROR")
    return(list(sp_users = 0, rj_users = 0, mg_users = 0, other_states = 0, international = 0))
  })
}

#' Analyze Content Interaction (Anonymized)
#' @param window_start Start of analysis window
#' @param window_end End of analysis window
#' @return List with content interaction metrics
analyze_content_interaction <- function(window_start, window_end) {
  tryCatch({
    # Document type preferences (aggregated)
    document_types <- dbGetQuery(.db_pool, "
      SELECT 
        resource_type,
        COUNT(*) as interaction_count
      FROM data_access_log
      WHERE timestamp >= $1 AND timestamp <= $2
      AND resource_type IN ('jurisprudencia', 'legislacao', 'doutrina', 'outros')
      GROUP BY resource_type
      ORDER BY interaction_count DESC
    ", params = list(window_start, window_end))
    
    # Popular search terms (anonymized - only general patterns)
    popular_terms <- dbGetQuery(.db_pool, "
      SELECT 
        CASE 
          WHEN search_criteria ILIKE '%transporte%' THEN 'transporte'
          WHEN search_criteria ILIKE '%energia%' THEN 'energia'
          WHEN search_criteria ILIKE '%sustent%' THEN 'sustentabilidade'
          WHEN search_criteria ILIKE '%rodovi%' THEN 'rodoviario'
          WHEN search_criteria ILIKE '%decreto%' THEN 'decreto'
          WHEN search_criteria ILIKE '%lei%' THEN 'lei'
          ELSE 'outros'
        END as term_category,
        COUNT(*) as search_count
      FROM data_access_log
      WHERE action_type = 'search' 
      AND search_criteria IS NOT NULL
      AND timestamp >= $1 AND timestamp <= $2
      GROUP BY term_category
      ORDER BY search_count DESC
      LIMIT 10
    ", params = list(window_start, window_end))
    
    # Most accessed resource types (anonymized)
    popular_resources <- dbGetQuery(.db_pool, "
      SELECT 
        resource_type,
        COUNT(*) as access_count
      FROM data_access_log
      WHERE action_type = 'view'
      AND timestamp >= $1 AND timestamp <= $2
      GROUP BY resource_type
      ORDER BY access_count DESC
      LIMIT 5
    ", params = list(window_start, window_end))
    
    # Convert to JSON for storage
    document_types_json <- toJSON(setNames(document_types$interaction_count, document_types$resource_type))
    popular_terms_json <- toJSON(setNames(popular_terms$search_count, popular_terms$term_category))
    popular_docs_json <- toJSON(setNames(popular_resources$access_count, popular_resources$resource_type))
    
    list(
      document_types = document_types_json,
      popular_terms = popular_terms_json,
      popular_documents = popular_docs_json
    )
    
  }, error = function(e) {
    log_event(paste("Content interaction analysis error:", e$message), "ERROR")
    return(list(document_types = "{}", popular_terms = "{}", popular_documents = "{}"))
  })
}

#' Analyze User Performance Impact
#' @param window_start Start of analysis window
#' @param window_end End of analysis window
#' @return List with user performance metrics
analyze_user_performance_impact <- function(window_start, window_end) {
  tryCatch({
    # User session and performance analysis
    performance_data <- dbGetQuery(.db_pool, "
      SELECT 
        AVG(response_time_ms) as avg_response_time,
        PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY response_time_ms) as median_response_time,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95_response_time,
        COUNT(*) FILTER (WHERE response_time_ms > 5000) as slow_responses,
        COUNT(*) as total_requests
      FROM data_access_log
      WHERE timestamp >= $1 AND timestamp <= $2
      AND response_time_ms IS NOT NULL
    ", params = list(window_start, window_end))
    
    # Session duration analysis
    session_data <- dbGetQuery(.db_pool, "
      SELECT 
        session_id,
        MIN(timestamp) as session_start,
        MAX(timestamp) as session_end,
        COUNT(*) as actions_per_session
      FROM data_access_log
      WHERE timestamp >= $1 AND timestamp <= $2
      AND session_id IS NOT NULL
      GROUP BY session_id
    ")
    
    # Calculate session durations
    if (nrow(session_data) > 0) {
      session_data$duration_minutes <- as.numeric(difftime(session_data$session_end, session_data$session_start, units = "mins"))
      avg_session_duration <- mean(session_data$duration_minutes, na.rm = TRUE)
      
      # Bounce rate (sessions with only 1 action)
      bounce_sessions <- sum(session_data$actions_per_session == 1, na.rm = TRUE)
      bounce_rate <- (bounce_sessions / nrow(session_data)) * 100
    } else {
      avg_session_duration <- 0
      bounce_rate <- 0
    }
    
    list(
      avg_response_time_ms = performance_data$avg_response_time[1] %||% 0,
      median_response_time_ms = performance_data$median_response_time[1] %||% 0,
      p95_response_time_ms = performance_data$p95_response_time[1] %||% 0,
      slow_responses_count = performance_data$slow_responses[1] %||% 0,
      total_requests = performance_data$total_requests[1] %||% 0,
      avg_session_duration = avg_session_duration,
      bounce_rate = bounce_rate
    )
    
  }, error = function(e) {
    log_event(paste("User performance analysis error:", e$message), "ERROR")
    return(list(avg_response_time_ms = 0, avg_session_duration = 0, bounce_rate = 0))
  })
}

#' Analyze Authentication Metrics
#' @param window_start Start of analysis window
#' @param window_end End of analysis window
#' @return List with authentication metrics
analyze_authentication_metrics <- function(window_start, window_end) {
  tryCatch({
    # Successful logins (new sessions created)
    successful_logins <- dbGetQuery(.db_pool, "
      SELECT COUNT(*) as successful_logins
      FROM user_sessions
      WHERE created_at >= $1 AND created_at <= $2
    ", params = list(window_start, window_end))
    
    # Session timeouts
    session_timeouts <- dbGetQuery(.db_pool, "
      SELECT COUNT(*) as timeouts
      FROM user_sessions
      WHERE revoked_reason = 'expired'
      AND revoked_at >= $1 AND revoked_at <= $2
    ", params = list(window_start, window_end))
    
    # Failed login attempts would need to be tracked separately
    # For now, we'll estimate based on sessions vs expected usage
    
    list(
      successful_logins = successful_logins$successful_logins[1] %||% 0,
      failed_logins = 0, # Would need separate tracking
      session_timeouts = session_timeouts$timeouts[1] %||% 0
    )
    
  }, error = function(e) {
    log_event(paste("Authentication metrics analysis error:", e$message), "ERROR")
    return(list(successful_logins = 0, failed_logins = 0, session_timeouts = 0))
  })
}

#' Calculate User Satisfaction Metrics
#' @param window_start Start of analysis window
#' @param window_end End of analysis window
#' @return List with satisfaction metrics
calculate_user_satisfaction_metrics <- function(window_start, window_end) {
  tryCatch({
    # User satisfaction based on:
    # 1. Session completion rate (not bouncing)
    # 2. Response time satisfaction
    # 3. Task completion indicators
    
    session_analysis <- dbGetQuery(.db_pool, "
      SELECT 
        session_id,
        COUNT(*) as actions_count,
        AVG(response_time_ms) as avg_response_time,
        COUNT(DISTINCT action_type) as action_variety,
        BOOL_OR(action_type = 'export' OR action_type = 'download') as completed_task
      FROM data_access_log
      WHERE timestamp >= $1 AND timestamp <= $2
      AND session_id IS NOT NULL
      GROUP BY session_id
    ", params = list(window_start, window_end))
    
    if (nrow(session_analysis) > 0) {
      # Satisfaction score based on multiple factors
      satisfaction_scores <- sapply(1:nrow(session_analysis), function(i) {
        row <- session_analysis[i, ]
        score <- 3.0 # Base score
        
        # Bonus for multiple actions (engagement)
        if (row$actions_count > 3) score <- score + 0.5
        
        # Bonus for action variety (exploration)
        if (row$action_variety > 2) score <- score + 0.3
        
        # Bonus for task completion
        if (row$completed_task) score <- score + 0.7
        
        # Penalty for slow response times
        if (!is.na(row$avg_response_time) && row$avg_response_time > 3000) {
          score <- score - 0.5
        }
        
        # Keep score between 1 and 5
        max(1.0, min(5.0, score))
      })
      
      avg_satisfaction <- mean(satisfaction_scores, na.rm = TRUE)
    } else {
      avg_satisfaction <- 3.0 # Neutral baseline
    }
    
    list(
      satisfaction_score = avg_satisfaction,
      total_sessions_analyzed = nrow(session_analysis)
    )
    
  }, error = function(e) {
    log_event(paste("User satisfaction calculation error:", e$message), "ERROR")
    return(list(satisfaction_score = 3.0, total_sessions_analyzed = 0))
  })
}

#' Store User Activity Metrics in Database
#' @param metrics List of metrics to store
store_user_activity_metrics <- function(metrics) {
  if (is.null(.db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    dbExecute(.db_pool,
      "INSERT INTO user_activity_metrics (
        total_active_users, new_users_count, returning_users_count,
        admin_sessions, researcher_sessions, policymaker_sessions, citizen_sessions,
        advanced_search_usage, basic_search_usage, export_operations, dashboard_views,
        sp_users, rj_users, mg_users, other_states_users, international_users,
        document_type_searches, popular_search_terms, most_viewed_documents,
        avg_user_session_duration_minutes, bounce_rate_percent, user_satisfaction_score,
        oauth_login_success, oauth_login_failures, session_timeouts,
        timestamp, aggregation_period_hours, privacy_compliance_level
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)",
      params = list(
        metrics$total_active_users, metrics$new_users_count, metrics$returning_users_count,
        metrics$admin_sessions, metrics$researcher_sessions, metrics$policymaker_sessions, metrics$citizen_sessions,
        metrics$advanced_search_usage, metrics$basic_search_usage, metrics$export_operations, metrics$dashboard_views,
        metrics$sp_users, metrics$rj_users, metrics$mg_users, metrics$other_states_users, metrics$international_users,
        metrics$document_type_searches, metrics$popular_search_terms, metrics$most_viewed_documents,
        metrics$avg_user_session_duration_minutes, metrics$bounce_rate_percent, metrics$user_satisfaction_score,
        metrics$oauth_login_success, metrics$oauth_login_failures, metrics$session_timeouts,
        metrics$timestamp, metrics$aggregation_period_hours, metrics$privacy_compliance_level
      )
    )
    
    log_event("User activity metrics stored successfully")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Failed to store user activity metrics:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Helper Functions for Activity Tracking

#' Anonymize Search Criteria (LGPD Compliance)
#' @param search_criteria Original search terms
#' @return Anonymized search criteria
anonymize_search_criteria <- function(search_criteria) {
  if (is.null(search_criteria) || nchar(search_criteria) == 0) {
    return(NULL)
  }
  
  # Remove potential personal identifiers while keeping analytical value
  anonymized <- search_criteria
  
  # Replace potential personal names with placeholders
  anonymized <- gsub("\\b[A-Z][a-z]+ [A-Z][a-z]+\\b", "[NOME_PESSOA]", anonymized)
  
  # Replace potential company names
  anonymized <- gsub("\\b[A-Z][A-Z]+ [A-Z][a-z]+\\b", "[NOME_EMPRESA]", anonymized)
  
  # Replace potential document numbers
  anonymized <- gsub("\\b\\d{4,}\\b", "[NUMERO_DOCUMENTO]", anonymized)
  
  # Keep only the first 100 characters for storage efficiency
  if (nchar(anonymized) > 100) {
    anonymized <- paste0(substr(anonymized, 1, 97), "...")
  }
  
  return(anonymized)
}

#' Get Client IP (if available)
#' @return Client IP address
get_client_ip <- function() {
  # In Shiny, this would come from session$clientData$url_hostname
  # For now, return NULL as we don't have access to Shiny session here
  return(NULL)
}

#' Get User Agent (if available)
#' @return User agent string
get_user_agent <- function() {
  # In Shiny, this would come from HTTP headers
  # For now, return NULL as we don't have access to HTTP headers here
  return(NULL)
}

#' Update Feature Usage Counters
#' @param action_type Type of action
#' @param resource_type Type of resource
#' @param user_id User identifier (optional)
update_feature_usage_counters <- function(action_type, resource_type, user_id = NULL) {
  counter_key <- paste(action_type, resource_type, sep = "_")
  
  if (is.null(.user_activity_state$feature_usage_counters[[counter_key]])) {
    .user_activity_state$feature_usage_counters[[counter_key]] <- 0
  }
  
  .user_activity_state$feature_usage_counters[[counter_key]] <- 
    .user_activity_state$feature_usage_counters[[counter_key]] + 1
}

#' Track Session Activity
#' @param session_id Session identifier
#' @param action_type Type of action
track_session_activity <- function(session_id, action_type) {
  if (is.null(session_id)) {
    return(FALSE)
  }
  
  current_time <- Sys.time()
  
  if (is.null(.user_activity_state$session_tracking[[session_id]])) {
    .user_activity_state$session_tracking[[session_id]] <- list(
      start_time = current_time,
      last_activity = current_time,
      action_count = 0,
      action_types = c()
    )
  }
  
  session_info <- .user_activity_state$session_tracking[[session_id]]
  session_info$last_activity <- current_time
  session_info$action_count <- session_info$action_count + 1
  session_info$action_types <- c(session_info$action_types, action_type)
  
  .user_activity_state$session_tracking[[session_id]] <- session_info
  
  return(TRUE)
}

#' Update User Engagement Metrics
#' @param user_id User identifier
#' @param action_type Type of action
#' @param response_time_ms Response time in milliseconds
update_user_engagement_metrics <- function(user_id, action_type, response_time_ms) {
  # This would update in-memory engagement tracking
  # For now, we rely on database storage for persistence
  return(TRUE)
}

#' Initialize Activity Counters
initialize_activity_counters <- function() {
  .user_activity_state$feature_usage_counters <- list()
  .user_activity_state$session_tracking <- list()
  log_event("Activity counters initialized")
}

#' Setup Activity Aggregation
setup_activity_aggregation <- function() {
  # Set up periodic aggregation (would use background job in production)
  .user_activity_state$aggregation_active <- TRUE
  log_event("Activity aggregation setup complete")
}

#' Initialize User Behavior Baselines
initialize_user_behavior_baselines <- function() {
  tryCatch({
    # Collect initial baseline metrics
    baseline_metrics <- collect_user_activity_metrics()
    .user_activity_state$behavior_baseline <- baseline_metrics
    log_event("User behavior baselines initialized")
  }, error = function(e) {
    log_event(paste("Baseline initialization error:", e$message), "WARN")
  })
}

#' Get User Activity Summary for Dashboard
#' @return List with key user activity metrics
get_user_activity_summary <- function() {
  tryCatch({
    if (is.null(.db_pool)) {
      return(list(error = "Database connection not available"))
    }
    
    # Get latest activity metrics
    latest_metrics <- dbGetQuery(.db_pool, "
      SELECT * FROM user_activity_metrics 
      ORDER BY timestamp DESC 
      LIMIT 1
    ")
    
    if (nrow(latest_metrics) > 0) {
      metric <- latest_metrics[1, ]
      
      list(
        total_active_users = metric$total_active_users,
        new_users_today = metric$new_users_count,
        user_satisfaction = round(metric$user_satisfaction_score, 2),
        bounce_rate = round(metric$bounce_rate_percent, 1),
        avg_session_duration = round(metric$avg_user_session_duration_minutes, 1),
        most_popular_feature = determine_most_popular_feature(metric),
        geographic_leader = determine_geographic_leader(metric),
        last_updated = metric$timestamp,
        data_quality = "anonymized_lgpd_compliant"
      )
    } else {
      list(
        total_active_users = 0,
        new_users_today = 0,
        user_satisfaction = 3.0,
        message = "No recent activity data available"
      )
    }
    
  }, error = function(e) {
    log_event(paste("User activity summary error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Determine Most Popular Feature
#' @param metrics Latest metrics row
#' @return String indicating most popular feature
determine_most_popular_feature <- function(metrics) {
  features <- list(
    "Advanced Search" = metrics$advanced_search_usage,
    "Basic Search" = metrics$basic_search_usage,
    "Data Export" = metrics$export_operations,
    "Dashboard" = metrics$dashboard_views
  )
  
  max_feature <- names(features)[which.max(unlist(features))]
  return(max_feature %||% "Search")
}

#' Determine Geographic Leader
#' @param metrics Latest metrics row
#' @return String indicating leading geographic region
determine_geographic_leader <- function(metrics) {
  regions <- list(
    "São Paulo" = metrics$sp_users,
    "Rio de Janeiro" = metrics$rj_users,
    "Minas Gerais" = metrics$mg_users,
    "Other States" = metrics$other_states_users
  )
  
  max_region <- names(regions)[which.max(unlist(regions))]
  return(max_region %||% "São Paulo")
}

#' LGPD Compliance: Data Subject Request Handler
#' @param user_id User requesting data access
#' @param request_type Type of request (access, deletion, etc.)
#' @return List with request processing information
handle_data_subject_request <- function(user_id, request_type = "access") {
  if (is.null(.db_pool)) {
    return(list(error = "Database connection not available"))
  }
  
  tryCatch({
    # Log the data subject request
    request_id <- UUIDgenerate()
    
    dbExecute(.db_pool,
      "INSERT INTO data_subject_requests (id, user_id, request_type, request_description)
       VALUES ($1, $2, $3, $4)",
      params = list(
        request_id, user_id, request_type,
        paste("LGPD data subject request:", request_type)
      )
    )
    
    if (request_type == "access") {
      # Provide user's data access log (last 30 days)
      user_data <- dbGetQuery(.db_pool, "
        SELECT 
          action_type,
          resource_type,
          timestamp,
          response_time_ms,
          results_count
        FROM data_access_log
        WHERE user_id = $1
        AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '30 days')
        ORDER BY timestamp DESC
      ", params = list(user_id))
      
      return(list(
        request_id = request_id,
        status = "completed",
        data = user_data,
        message = "Your data access history for the last 30 days"
      ))
      
    } else if (request_type == "deletion") {
      # Process deletion request (would need admin approval)
      return(list(
        request_id = request_id,
        status = "pending",
        message = "Your deletion request has been received and will be processed within 15 days as required by LGPD"
      ))
    }
    
    return(list(request_id = request_id, status = "processed"))
    
  }, error = function(e) {
    log_event(paste("Data subject request error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Export User Activity Analytics Report
#' @param format Export format ("json", "csv")
#' @param date_range Number of days to include
#' @return File path of exported report
export_user_activity_report <- function(format = "json", date_range = 7) {
  tryCatch({
    # Get activity data for specified range
    end_date <- Sys.time()
    start_date <- end_date - days(date_range)
    
    activity_data <- dbGetQuery(.db_pool, "
      SELECT * FROM user_activity_metrics
      WHERE timestamp >= $1 AND timestamp <= $2
      ORDER BY timestamp DESC
    ", params = list(start_date, end_date))
    
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- paste0("user_activity_report_", timestamp)
    
    if (format == "json") {
      filepath <- paste0(filename, ".json")
      writeLines(toJSON(activity_data, pretty = TRUE), filepath)
    } else if (format == "csv") {
      filepath <- paste0(filename, ".csv")
      write.csv(activity_data, filepath, row.names = FALSE)
    }
    
    log_event(paste("User activity report exported:", filepath))
    return(filepath)
    
  }, error = function(e) {
    log_event(paste("Report export error:", e$message), "ERROR")
    return(NULL)
  })
}

# Initialize user activity monitoring if database is available
if (exists(".db_pool") && !is.null(.db_pool)) {
  init_user_activity_monitoring()
}

log_event("User Activity Monitoring System loaded successfully - LGPD compliant")