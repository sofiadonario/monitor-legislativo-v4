# TELEMETRY SYSTEM FOR R SHINY RAILWAY DEPLOYMENT
# ===============================================
# Privacy-compliant user interaction analytics and feature usage tracking
# LGPD compliant with opt-in consent and data anonymization

library(shiny)
library(DT)
library(plotly)

# Source dependencies
source("monitoring/logger.R")

# Telemetry Configuration
TELEMETRY_CONFIG <- list(
  enabled = Sys.getenv("TELEMETRY_ENABLED", "true") == "true",
  consent_required = TRUE,
  anonymize_data = TRUE,
  data_retention_days = as.numeric(Sys.getenv("TELEMETRY_RETENTION_DAYS", "90")),
  privacy_level = Sys.getenv("PRIVACY_LEVEL", "strict"), # strict, moderate, minimal
  feature_tracking = TRUE,
  performance_tracking = TRUE,
  error_tracking = TRUE,
  user_journey_tracking = TRUE,
  batch_size = 50,
  flush_interval_seconds = 300 # 5 minutes
)

# Privacy levels configuration
PRIVACY_LEVELS <- list(
  strict = list(
    track_ip = FALSE,
    track_user_agent = FALSE,
    track_session_duration = TRUE,
    track_page_views = TRUE,
    track_clicks = TRUE,
    anonymize_immediately = TRUE
  ),
  moderate = list(
    track_ip = FALSE,
    track_user_agent = TRUE,
    track_session_duration = TRUE,
    track_page_views = TRUE,
    track_clicks = TRUE,
    anonymize_immediately = FALSE
  ),
  minimal = list(
    track_ip = FALSE,
    track_user_agent = FALSE,
    track_session_duration = FALSE,
    track_page_views = FALSE,
    track_clicks = FALSE,
    anonymize_immediately = TRUE
  )
)

# Global telemetry state (non-reactive for stability)
TELEMETRY_STATE <- list(
  initialized = FALSE,
  user_consent = list(),
  session_data = list(),
  feature_usage = data.frame(
    timestamp = character(0),
    session_id = character(0),
    feature = character(0),
    action = character(0),
    duration_ms = numeric(0),
    success = logical(0),
    stringsAsFactors = FALSE
  ),
  user_journeys = list(),
  performance_events = data.frame(
    timestamp = character(0),
    session_id = character(0),
    event_type = character(0),
    duration_ms = numeric(0),
    metadata = character(0),
    stringsAsFactors = FALSE
  ),
  error_events = data.frame(
    timestamp = character(0),
    session_id = character(0),
    error_type = character(0),
    error_message = character(0),
    context = character(0),
    stringsAsFactors = FALSE
  ),
  pending_events = list()
)

# Privacy and consent management
request_user_consent <- function(session) {
  if (!TELEMETRY_CONFIG$consent_required) {
    return(TRUE)
  }
  
  # Check if consent already given for this session
  session_id <- session$token
  if (!is.null(TELEMETRY_STATE$user_consent[[session_id]])) {
    return(TELEMETRY_STATE$user_consent[[session_id]]$granted)
  }
  
  # Show consent modal (would be implemented in UI)
  showModal(modalDialog(
    title = "Privacy Notice - Data Collection Consent",
    div(
      h4("We respect your privacy"),
      p("This application collects anonymous usage data to improve user experience and performance. We follow LGPD compliance standards."),
      br(),
      h5("What we collect:"),
      tags$ul(
        tags$li("Feature usage patterns (anonymized)"),
        tags$li("Performance metrics"),
        tags$li("Error reports (no personal data)"),
        tags$li("Session duration and navigation patterns")
      ),
      br(),
      h5("What we DON'T collect:"),
      tags$ul(
        tags$li("Personal information"),
        tags$li("IP addresses"),
        tags$li("Individual identification data"),
        tags$li("Document content you search or view")
      ),
      br(),
      p("You can withdraw consent at any time through the settings menu."),
      br(),
      p(tags$strong("Do you consent to anonymous data collection for improving this service?"))
    ),
    footer = tagList(
      actionButton("consent_yes", "Yes, I consent", class = "btn-primary"),
      actionButton("consent_no", "No, thanks", class = "btn-secondary")
    ),
    easyClose = FALSE
  ))
  
  return(FALSE) # Will be updated by modal response
}

# Store user consent
store_user_consent <- function(session, granted = TRUE) {
  session_id <- session$token
  
  TELEMETRY_STATE$user_consent[[session_id]] <- list(
    granted = granted,
    timestamp = Sys.time(),
    ip_hash = if (TELEMETRY_CONFIG$anonymize_data) "session_ip_anonymized" else NA
  )
  
  log_info("User consent recorded", list(
    session_id = anonymize_session_id(session_id),
    consent_granted = granted,
    privacy_level = TELEMETRY_CONFIG$privacy_level
  ), session)
  
  return(granted)
}

# Data anonymization functions
anonymize_session_id <- function(session_id) {
  if (!TELEMETRY_CONFIG$anonymize_data) return(session_id)
  return(substr(digest::digest(session_id), 1, 8))
}

anonymize_user_data <- function(data) {
  if (!TELEMETRY_CONFIG$anonymize_data) return(data)
  
  # Remove or hash any potentially identifying fields
  if ("session_id" %in% names(data)) {
    data$session_id <- anonymize_session_id(data$session_id)
  }
  
  return(data)
}

# Session tracking
start_session_tracking <- function(session) {
  if (!is_telemetry_enabled(session)) return(invisible(NULL))
  
  session_id <- session$token
  anon_session_id <- anonymize_session_id(session_id)
  
  privacy_settings <- PRIVACY_LEVELS[[TELEMETRY_CONFIG$privacy_level]]
  
  session_data <- list(
    session_id = anon_session_id,
    start_time = Sys.time(),
    user_agent = if (privacy_settings$track_user_agent) "tracking_enabled" else NA,
    screen_resolution = paste(session$clientData$pixelratio, 
                             session$clientData$output_width, 
                             session$clientData$output_height, sep = "x"),
    page_views = 0,
    feature_interactions = 0,
    errors_encountered = 0
  )
  
  TELEMETRY_STATE$session_data[[session_id]] <- session_data
  
  log_info("Session tracking started", list(
    session_id = anon_session_id,
    privacy_level = TELEMETRY_CONFIG$privacy_level
  ), session)
}

end_session_tracking <- function(session) {
  session_id <- session$token
  
  if (session_id %in% names(TELEMETRY_STATE$session_data)) {
    session_data <- TELEMETRY_STATE$session_data[[session_id]]
    session_data$end_time <- Sys.time()
    session_data$duration_seconds <- as.numeric(difftime(session_data$end_time, session_data$start_time, units = "secs"))
    
    # Log session summary
    log_info("Session ended", list(
      session_id = anonymize_session_id(session_id),
      duration_seconds = round(session_data$duration_seconds, 2),
      page_views = session_data$page_views,
      feature_interactions = session_data$feature_interactions,
      errors_encountered = session_data$errors_encountered
    ), session)
    
    # Clean up session data
    TELEMETRY_STATE$session_data[[session_id]] <- NULL
  }
}

# Feature usage tracking
track_feature_usage <- function(feature_name, action = "used", session = NULL, 
                               duration_ms = NULL, success = TRUE, metadata = list()) {
  if (!is_telemetry_enabled(session)) return(invisible(NULL))
  
  session_id <- if (!is.null(session)) session$token else "unknown"
  anon_session_id <- anonymize_session_id(session_id)
  
  # Update session data
  if (session_id %in% names(TELEMETRY_STATE$session_data)) {
    TELEMETRY_STATE$session_data[[session_id]]$feature_interactions <- 
      TELEMETRY_STATE$session_data[[session_id]]$feature_interactions + 1
  }
  
  # Record feature usage
  new_usage <- data.frame(
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
    session_id = anon_session_id,
    feature = feature_name,
    action = action,
    duration_ms = if (!is.null(duration_ms)) duration_ms else NA,
    success = success,
    stringsAsFactors = FALSE
  )
  
  TELEMETRY_STATE$feature_usage <- rbind(TELEMETRY_STATE$feature_usage, new_usage)
  
  # Add to pending events for batch processing
  event <- list(
    type = "feature_usage",
    data = anonymize_user_data(c(as.list(new_usage), metadata))
  )
  TELEMETRY_STATE$pending_events <- append(TELEMETRY_STATE$pending_events, list(event))
  
  log_debug("Feature usage tracked", list(
    feature = feature_name,
    action = action,
    session_id = anon_session_id,
    success = success
  ), session)
}

# User journey tracking
start_user_journey <- function(journey_name, session = NULL) {
  if (!is_telemetry_enabled(session)) return(invisible(NULL))
  
  session_id <- if (!is.null(session)) session$token else "unknown"
  anon_session_id <- anonymize_session_id(session_id)
  
  journey <- list(
    name = journey_name,
    session_id = anon_session_id,
    start_time = Sys.time(),
    steps = list(),
    completed = FALSE
  )
  
  journey_key <- paste(anon_session_id, journey_name, sep = "_")
  TELEMETRY_STATE$user_journeys[[journey_key]] <- journey
  
  log_debug("User journey started", list(
    journey = journey_name,
    session_id = anon_session_id
  ), session)
  
  return(journey_key)
}

add_journey_step <- function(journey_key, step_name, metadata = list()) {
  if (journey_key %in% names(TELEMETRY_STATE$user_journeys)) {
    step <- list(
      name = step_name,
      timestamp = Sys.time(),
      metadata = metadata
    )
    
    TELEMETRY_STATE$user_journeys[[journey_key]]$steps <- 
      append(TELEMETRY_STATE$user_journeys[[journey_key]]$steps, list(step))
    
    log_debug("Journey step added", list(
      journey_key = journey_key,
      step = step_name
    ))
  }
}

complete_user_journey <- function(journey_key, success = TRUE) {
  if (journey_key %in% names(TELEMETRY_STATE$user_journeys)) {
    journey <- TELEMETRY_STATE$user_journeys[[journey_key]]
    journey$completed = TRUE
    journey$success = success
    journey$end_time = Sys.time()
    journey$duration_seconds = as.numeric(difftime(journey$end_time, journey$start_time, units = "secs"))
    
    # Add to pending events
    event <- list(
      type = "user_journey",
      data = anonymize_user_data(journey)
    )
    TELEMETRY_STATE$pending_events <- append(TELEMETRY_STATE$pending_events, list(event))
    
    log_info("User journey completed", list(
      journey = journey$name,
      session_id = journey$session_id,
      duration_seconds = round(journey$duration_seconds, 2),
      steps_count = length(journey$steps),
      success = success
    ))
    
    # Clean up
    TELEMETRY_STATE$user_journeys[[journey_key]] <- NULL
  }
}

# Performance event tracking
track_performance_event <- function(event_type, duration_ms, session = NULL, metadata = list()) {
  if (!is_telemetry_enabled(session) || !TELEMETRY_CONFIG$performance_tracking) return(invisible(NULL))
  
  session_id <- if (!is.null(session)) session$token else "unknown"
  anon_session_id <- anonymize_session_id(session_id)
  
  new_event <- data.frame(
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
    session_id = anon_session_id,
    event_type = event_type,
    duration_ms = duration_ms,
    metadata = jsonlite::toJSON(metadata, auto_unbox = TRUE),
    stringsAsFactors = FALSE
  )
  
  TELEMETRY_STATE$performance_events <- rbind(TELEMETRY_STATE$performance_events, new_event)
  
  # Check for performance issues
  if (duration_ms > 5000) { # More than 5 seconds
    log_warn("Slow performance detected", list(
      event_type = event_type,
      duration_ms = duration_ms,
      session_id = anon_session_id
    ), session)
  }
  
  # Keep only recent events
  if (nrow(TELEMETRY_STATE$performance_events) > 10000) {
    TELEMETRY_STATE$performance_events <- tail(TELEMETRY_STATE$performance_events, 5000)
  }
}

# Error event tracking
track_error_event <- function(error_type, error_message, session = NULL, context = list()) {
  if (!is_telemetry_enabled(session) || !TELEMETRY_CONFIG$error_tracking) return(invisible(NULL))
  
  session_id <- if (!is.null(session)) session$token else "unknown"
  anon_session_id <- anonymize_session_id(session_id)
  
  # Update session error count
  if (session_id %in% names(TELEMETRY_STATE$session_data)) {
    TELEMETRY_STATE$session_data[[session_id]]$errors_encountered <- 
      TELEMETRY_STATE$session_data[[session_id]]$errors_encountered + 1
  }
  
  new_error <- data.frame(
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
    session_id = anon_session_id,
    error_type = error_type,
    error_message = substr(error_message, 1, 500), # Limit message length
    context = jsonlite::toJSON(sanitize_log_data(context), auto_unbox = TRUE),
    stringsAsFactors = FALSE
  )
  
  TELEMETRY_STATE$error_events <- rbind(TELEMETRY_STATE$error_events, new_error)
  
  # Keep only recent errors
  if (nrow(TELEMETRY_STATE$error_events) > 5000) {
    TELEMETRY_STATE$error_events <- tail(TELEMETRY_STATE$error_events, 2000)
  }
}

# Analytics and insights
get_feature_usage_analytics <- function(days = 7) {
  if (nrow(TELEMETRY_STATE$feature_usage) == 0) {
    return(list(
      total_interactions = 0,
      unique_features = 0,
      top_features = data.frame(),
      success_rate = 0
    ))
  }
  
  # Filter by time window
  cutoff_time <- Sys.time() - days * 24 * 60 * 60
  recent_usage <- TELEMETRY_STATE$feature_usage[
    as.POSIXct(TELEMETRY_STATE$feature_usage$timestamp) >= cutoff_time,
  ]
  
  if (nrow(recent_usage) == 0) {
    return(list(
      total_interactions = 0,
      unique_features = 0,
      top_features = data.frame(),
      success_rate = 0
    ))
  }
  
  # Calculate analytics
  analytics <- list(
    total_interactions = nrow(recent_usage),
    unique_features = length(unique(recent_usage$feature)),
    unique_sessions = length(unique(recent_usage$session_id)),
    success_rate = mean(recent_usage$success, na.rm = TRUE)
  )
  
  # Top features
  feature_counts <- table(recent_usage$feature)
  analytics$top_features <- data.frame(
    feature = names(feature_counts),
    usage_count = as.numeric(feature_counts),
    stringsAsFactors = FALSE
  )[order(-as.numeric(feature_counts)),]
  
  # Usage patterns by hour
  recent_usage$hour <- format(as.POSIXct(recent_usage$timestamp), "%H")
  hour_counts <- table(recent_usage$hour)
  analytics$hourly_patterns <- data.frame(
    hour = names(hour_counts),
    usage_count = as.numeric(hour_counts),
    stringsAsFactors = FALSE
  )
  
  return(analytics)
}

get_performance_analytics <- function(days = 7) {
  if (nrow(TELEMETRY_STATE$performance_events) == 0) {
    return(list(
      total_events = 0,
      avg_duration_ms = 0,
      slow_events_count = 0
    ))
  }
  
  # Filter by time window
  cutoff_time <- Sys.time() - days * 24 * 60 * 60
  recent_events <- TELEMETRY_STATE$performance_events[
    as.POSIXct(TELEMETRY_STATE$performance_events$timestamp) >= cutoff_time,
  ]
  
  analytics <- list(
    total_events = nrow(recent_events),
    avg_duration_ms = mean(recent_events$duration_ms, na.rm = TRUE),
    median_duration_ms = median(recent_events$duration_ms, na.rm = TRUE),
    slow_events_count = sum(recent_events$duration_ms > 5000, na.rm = TRUE),
    slow_events_rate = mean(recent_events$duration_ms > 5000, na.rm = TRUE)
  )
  
  return(analytics)
}

# Utility functions
is_telemetry_enabled <- function(session = NULL) {
  if (!TELEMETRY_CONFIG$enabled) return(FALSE)
  
  if (!is.null(session) && TELEMETRY_CONFIG$consent_required) {
    session_id <- session$token
    consent <- TELEMETRY_STATE$user_consent[[session_id]]
    return(!is.null(consent) && consent$granted)
  }
  
  return(TRUE)
}

# Data cleanup and maintenance
cleanup_old_telemetry_data <- function() {
  cutoff_time <- Sys.time() - TELEMETRY_CONFIG$data_retention_days * 24 * 60 * 60
  
  # Clean feature usage data
  TELEMETRY_STATE$feature_usage <- TELEMETRY_STATE$feature_usage[
    as.POSIXct(TELEMETRY_STATE$feature_usage$timestamp) >= cutoff_time,
  ]
  
  # Clean performance events
  TELEMETRY_STATE$performance_events <- TELEMETRY_STATE$performance_events[
    as.POSIXct(TELEMETRY_STATE$performance_events$timestamp) >= cutoff_time,
  ]
  
  # Clean error events
  TELEMETRY_STATE$error_events <- TELEMETRY_STATE$error_events[
    as.POSIXct(TELEMETRY_STATE$error_events$timestamp) >= cutoff_time,
  ]
  
  log_info("Telemetry data cleanup completed", list(
    retention_days = TELEMETRY_CONFIG$data_retention_days,
    cutoff_time = cutoff_time
  ))
}

# Initialize telemetry system
init_telemetry <- function() {
  if (!TELEMETRY_CONFIG$enabled) {
    log_info("Telemetry system disabled")
    return(invisible(NULL))
  }
  
  TELEMETRY_STATE$initialized <- TRUE
  
  # Schedule periodic cleanup
  observe({
    invalidateLater(24 * 60 * 60 * 1000) # Daily cleanup
    cleanup_old_telemetry_data()
  })
  
  log_info("Telemetry system initialized", list(
    privacy_level = TELEMETRY_CONFIG$privacy_level,
    consent_required = TELEMETRY_CONFIG$consent_required,
    retention_days = TELEMETRY_CONFIG$data_retention_days
  ))
  
  invisible(TRUE)
}

# Export telemetry functions
list(
  # Initialization
  init_telemetry = init_telemetry,
  
  # Consent management
  request_user_consent = request_user_consent,
  store_user_consent = store_user_consent,
  
  # Session tracking
  start_session_tracking = start_session_tracking,
  end_session_tracking = end_session_tracking,
  
  # Feature tracking
  track_feature_usage = track_feature_usage,
  
  # Journey tracking
  start_user_journey = start_user_journey,
  add_journey_step = add_journey_step,
  complete_user_journey = complete_user_journey,
  
  # Performance tracking
  track_performance_event = track_performance_event,
  
  # Error tracking
  track_error_event = track_error_event,
  
  # Analytics
  get_feature_usage_analytics = get_feature_usage_analytics,
  get_performance_analytics = get_performance_analytics,
  
  # Utilities
  is_telemetry_enabled = is_telemetry_enabled,
  cleanup_old_telemetry_data = cleanup_old_telemetry_data,
  
  # State access
  TELEMETRY_STATE = TELEMETRY_STATE,
  TELEMETRY_CONFIG = TELEMETRY_CONFIG
)