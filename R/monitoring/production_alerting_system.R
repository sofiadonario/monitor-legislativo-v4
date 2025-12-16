# MONITOR LEGISLATIVO V4 - PRODUCTION ALERTING SYSTEM
# =====================================================
# Advanced Alerting and Incident Management for Railway Production
# Brazilian Academic Institution Alert Management with LGPD Compliance

#' Production Alerting System
#'
#' Comprehensive alerting system for Monitor Legislativo v4 production deployment
#' Designed for Railway platform with Brazilian academic institution requirements
#'
#' @description Features:
#' - Real-time alert generation and management
#' - Multi-channel alert delivery (logs, webhooks, email)
#' - LGPD-compliant alert handling
#' - Brazilian timezone awareness
#' - Budget-optimized alerting for Railway $15-30/month tier
#' - Academic workflow priority alerts
#' - Automated incident escalation
#'
#' @author Monitor Legislativo v4 Team
#' @version 4.0-production

library(jsonlite)
library(httr)
library(digest)

# Alerting System Configuration
# =============================
alerting_config <- list(
  # Alert severity levels
  severity_levels = c("info", "warning", "critical", "emergency"),

  # Alert types
  alert_types = c(
    "system", "performance", "security", "database",
    "application", "compliance", "academic", "cloud_run"
  ),

  # Delivery channels
  delivery_channels = list(
    log_file = TRUE,
    console = TRUE,
    webhook = Sys.getenv("WEBHOOK_URL", "") != "",
    email = FALSE,  # Disabled for budget tier
    sms = FALSE     # Disabled for budget tier
  ),

  # Alert thresholds (Cloud Run $15-30/month optimized)
  thresholds = list(
    memory_warning = 75,      # % - Cloud Run memory warning
    memory_critical = 90,     # % - Cloud Run memory critical
    cpu_warning = 80,         # % - CPU usage warning
    cpu_critical = 95,        # % - CPU usage critical
    response_time_warning = 3000,  # ms - Response time warning
    response_time_critical = 5000, # ms - Response time critical
    error_rate_warning = 2,   # % - Error rate warning
    error_rate_critical = 5,  # % - Error rate critical
    disk_usage_warning = 85,  # % - Disk usage warning
    session_limit_warning = 60, # Active sessions warning (80% of 75)
    db_connection_warning = 8   # Database connections warning
  ),

  # Alert timing
  alert_intervals = list(
    health_check = 30,        # seconds - Health check frequency
    performance_check = 60,   # seconds - Performance check frequency
    compliance_check = 300,   # seconds - Compliance check frequency
    cooldown_period = 900     # seconds - 15 minutes cooldown for duplicate alerts
  ),

  # Brazilian academic context
  academic_settings = list(
    timezone = "America/Sao_Paulo",
    business_hours = list(start = 8, end = 18),
    academic_hours = list(start = 6, end = 23),
    escalation_hours = list(start = 9, end = 17),
    weekend_reduced_monitoring = TRUE
  ),

  # LGPD compliance
  compliance_settings = list(
    log_retention_days = 30,
    anonymize_user_data = TRUE,
    audit_trail_required = TRUE,
    data_minimization = TRUE
  ),

  # Cloud Run specific
  cloud_run_settings = list(
    environment = ifelse(Sys.getenv("K_SERVICE", "") != "", "production", "development"),
    service_id = Sys.getenv("K_SERVICE", ""),
    project_id = Sys.getenv("GOOGLE_CLOUD_PROJECT", ""),
    webhook_retries = 3,
    budget_alerts = TRUE,
    cost_threshold_warning = 20,  # USD - 20 USD warning
    cost_threshold_critical = 25  # USD - 25 USD critical
  )
)

cat("🚨 PRODUCTION ALERTING SYSTEM INITIALIZED\n")
cat("==========================================\n")
cat("🇧🇷 Brazilian Academic Context | 🛡️ LGPD Compliant\n")
cat("☁️ Cloud Run Optimized | 💰 Budget: $15-30/month\n\n")

# Alert Management State
# ======================
alert_state <- list(
  active_alerts = list(),
  alert_history = list(),
  cooldown_registry = list(),
  escalation_registry = list(),
  performance_baseline = list(),
  incident_counter = 0,
  last_health_check = NULL,
  system_start_time = Sys.time()
)

# Core Alert Functions
# ====================

#' Generate Alert ID
#'
#' @param alert_type Type of alert
#' @param severity Severity level
#' @param source Source of the alert
#' @return Unique alert ID
generate_alert_id <- function(alert_type, severity, source) {
  content <- paste(alert_type, severity, source, format(Sys.time(), "%Y%m%d%H%M"))
  return(substr(digest(content, algo = "md5"), 1, 8))
}

#' Create Production Alert
#'
#' @param alert_type Type of alert (system, performance, security, etc.)
#' @param severity Severity level (info, warning, critical, emergency)
#' @param title Alert title
#' @param message Detailed alert message
#' @param source Source component that generated the alert
#' @param metric_value Current metric value (optional)
#' @param threshold Threshold that was exceeded (optional)
#' @param auto_resolve Whether alert can be auto-resolved
#' @return Alert object
create_production_alert <- function(alert_type, severity, title, message,
                                  source = "system", metric_value = NULL,
                                  threshold = NULL, auto_resolve = TRUE) {

  # Validate inputs
  if (!alert_type %in% alerting_config$alert_types) {
    stop("Invalid alert type: ", alert_type)
  }
  if (!severity %in% alerting_config$severity_levels) {
    stop("Invalid severity level: ", severity)
  }

  # Generate unique alert ID
  alert_id <- generate_alert_id(alert_type, severity, source)

  # Check cooldown period
  cooldown_key <- paste(alert_type, severity, source, sep = "_")
  if (cooldown_key %in% names(alert_state$cooldown_registry)) {
    last_alert_time <- alert_state$cooldown_registry[[cooldown_key]]
    time_since_last <- as.numeric(difftime(Sys.time(), last_alert_time, units = "secs"))

    if (time_since_last < alerting_config$alert_intervals$cooldown_period) {
      cat("🔇 Alert suppressed (cooldown):", title, "\n")
      return(NULL)
    }
  }

  # Create alert object
  alert <- list(
    id = alert_id,
    type = alert_type,
    severity = severity,
    title = title,
    message = message,
    source = source,
    metric_value = metric_value,
    threshold = threshold,
    auto_resolve = auto_resolve,
    timestamp = Sys.time(),
    timestamp_brt = format(Sys.time(), "%Y-%m-%d %H:%M:%S", tz = alerting_config$academic_settings$timezone),
    environment = alerting_config$cloud_run_settings$environment,
    cloud_run_service = alerting_config$cloud_run_settings$service_id,
    resolved = FALSE,
    resolution_time = NULL,
    escalated = FALSE,
    escalation_time = NULL,
    attempts = 1,
    tags = determine_alert_tags(alert_type, severity, source)
  )

  # Add to active alerts
  alert_state$active_alerts[[alert_id]] <<- alert
  alert_state$alert_history[[length(alert_state$alert_history) + 1]] <<- alert

  # Update cooldown registry
  alert_state$cooldown_registry[[cooldown_key]] <<- Sys.time()

  # Process alert delivery
  deliver_alert(alert)

  # Check for escalation
  check_escalation_required(alert)

  cat("🚨", format(Sys.time(), "%H:%M:%S"), "-", severity, "-", title, "\n")

  return(alert)
}

#' Determine Alert Tags
#'
#' @param alert_type Type of alert
#' @param severity Severity level
#' @param source Source of alert
#' @return Vector of tags
determine_alert_tags <- function(alert_type, severity, source) {
  tags <- c(alert_type, severity, source)

  # Add contextual tags
  current_hour <- as.integer(format(Sys.time(), "%H", tz = alerting_config$academic_settings$timezone))

  if (current_hour >= alerting_config$academic_settings$academic_hours$start &&
      current_hour <= alerting_config$academic_settings$academic_hours$end) {
    tags <- c(tags, "academic_hours")
  }

  if (current_hour >= alerting_config$academic_settings$business_hours$start &&
      current_hour <= alerting_config$academic_settings$business_hours$end) {
    tags <- c(tags, "business_hours")
  }

  # Weekend detection
  current_weekday <- as.integer(format(Sys.time(), "%u"))  # 1=Monday, 7=Sunday
  if (current_weekday >= 6) {
    tags <- c(tags, "weekend")
  }

  # Add Cloud Run environment tag
  tags <- c(tags, paste0("cloud_run_", alerting_config$cloud_run_settings$environment))

  return(unique(tags))
}

#' Deliver Alert Through Configured Channels
#'
#' @param alert Alert object to deliver
deliver_alert <- function(alert) {
  delivery_results <- list()

  # Log file delivery
  if (alerting_config$delivery_channels$log_file) {
    delivery_results$log_file <- deliver_to_log_file(alert)
  }

  # Console delivery
  if (alerting_config$delivery_channels$console) {
    delivery_results$console <- deliver_to_console(alert)
  }

  # Webhook delivery (if configured)
  if (alerting_config$delivery_channels$webhook) {
    delivery_results$webhook <- deliver_to_webhook(alert)
  }

  # Cloud Run environment variable (for Cloud Run monitoring)
  delivery_results$cloud_run_env <- deliver_to_cloud_run_env(alert)

  # Store delivery results
  alert$delivery_results <- delivery_results
  alert_state$active_alerts[[alert$id]] <<- alert

  return(delivery_results)
}

#' Deliver Alert to Log File
#'
#' @param alert Alert object
#' @return Success status
deliver_to_log_file <- function(alert) {
  tryCatch({
    # Ensure alert log directory exists
    alert_log_dir <- "monitoring/alerts"
    if (!dir.exists(alert_log_dir)) {
      dir.create(alert_log_dir, recursive = TRUE)
    }

    # Determine log file based on severity
    log_file <- switch(alert$severity,
      "critical" = file.path(alert_log_dir, "critical_alerts.log"),
      "emergency" = file.path(alert_log_dir, "emergency_alerts.log"),
      file.path(alert_log_dir, "production_alerts.log")
    )

    # Create LGPD-compliant log entry
    log_entry <- list(
      timestamp = alert$timestamp_brt,
      alert_id = alert$id,
      type = alert$type,
      severity = alert$severity,
      title = alert$title,
      message = if (alerting_config$compliance_settings$data_minimization) {
        # Sanitize message for LGPD compliance
        sanitize_message_for_lgpd(alert$message)
      } else {
        alert$message
      },
      source = alert$source,
      environment = alert$environment,
      metric_value = alert$metric_value,
      threshold = alert$threshold,
      tags = alert$tags
    )

    # Write to log file
    log_line <- jsonlite::toJSON(log_entry, auto_unbox = TRUE)
    cat(log_line, "\n", file = log_file, append = TRUE)

    return(TRUE)

  }, error = function(e) {
    cat("❌ Failed to write alert to log file:", e$message, "\n")
    return(FALSE)
  })
}

#' Deliver Alert to Console
#'
#' @param alert Alert object
#' @return Success status
deliver_to_console <- function(alert) {
  # Severity icons
  severity_icon <- switch(alert$severity,
    "info" = "ℹ️",
    "warning" = "⚠️",
    "critical" = "🚨",
    "emergency" = "🆘",
    "🔔"
  )

  # Color codes for console output
  color_code <- switch(alert$severity,
    "info" = "\033[36m",      # Cyan
    "warning" = "\033[33m",   # Yellow
    "critical" = "\033[31m",  # Red
    "emergency" = "\033[35m", # Magenta
    "\033[0m"                 # Reset
  )

  reset_code <- "\033[0m"

  console_message <- sprintf(
    "%s%s [%s] %s: %s%s\n   Source: %s | Metric: %s | Time: %s",
    color_code,
    severity_icon,
    toupper(alert$severity),
    alert$title,
    alert$message,
    reset_code,
    alert$source,
    ifelse(is.null(alert$metric_value), "N/A", alert$metric_value),
    alert$timestamp_brt
  )

  cat(console_message, "\n")

  return(TRUE)
}

#' Deliver Alert to Webhook
#'
#' @param alert Alert object
#' @return Success status
deliver_to_webhook <- function(alert) {
  webhook_url <- Sys.getenv("WEBHOOK_URL", "")
  if (webhook_url == "") {
    return(FALSE)
  }

  tryCatch({
    # Prepare webhook payload
    webhook_payload <- list(
      alert_id = alert$id,
      type = alert$type,
      severity = alert$severity,
      title = alert$title,
      message = alert$message,
      source = alert$source,
      timestamp = format(alert$timestamp, "%Y-%m-%dT%H:%M:%SZ"),
      environment = alert$environment,
      cloud_run_service = alert$cloud_run_service,
      metric_value = alert$metric_value,
      threshold = alert$threshold,
      tags = alert$tags,
      brazilian_time = alert$timestamp_brt,
      academic_context = list(
        timezone = alerting_config$academic_settings$timezone,
        academic_hours = "academic_hours" %in% alert$tags,
        business_hours = "business_hours" %in% alert$tags
      )
    )

    # Send webhook with retries
    max_retries <- alerting_config$railway_settings$webhook_retries
    for (attempt in 1:max_retries) {
      response <- httr::POST(
        url = webhook_url,
        body = webhook_payload,
        encode = "json",
        httr::add_headers("Content-Type" = "application/json"),
        httr::timeout(10)
      )

      if (httr::status_code(response) %in% c(200, 201, 202)) {
        cat("✅ Webhook delivered successfully (attempt", attempt, ")\n")
        return(TRUE)
      } else {
        cat("⚠️ Webhook delivery failed (attempt", attempt, "): status", httr::status_code(response), "\n")
        if (attempt < max_retries) {
          Sys.sleep(2^attempt)  # Exponential backoff
        }
      }
    }

    cat("❌ Webhook delivery failed after", max_retries, "attempts\n")
    return(FALSE)

  }, error = function(e) {
    cat("❌ Webhook delivery error:", e$message, "\n")
    return(FALSE)
  })
}

#' Deliver Alert to Cloud Run Environment Variables
#'
#' @param alert Alert object
#' @return Success status
deliver_to_cloud_run_env <- function(alert) {
  tryCatch({
    # Set environment variables for Cloud Run monitoring
    Sys.setenv(LAST_ALERT_ID = alert$id)
    Sys.setenv(LAST_ALERT_SEVERITY = alert$severity)
    Sys.setenv(LAST_ALERT_TYPE = alert$type)
    Sys.setenv(LAST_ALERT_TIME = as.character(alert$timestamp))
    Sys.setenv(LAST_ALERT_MESSAGE = substr(alert$title, 1, 100))  # Truncate for env var limits

    # Critical alerts get special treatment
    if (alert$severity %in% c("critical", "emergency")) {
      Sys.setenv(CRITICAL_ALERT_ACTIVE = "true")
      Sys.setenv(CRITICAL_ALERT_COUNT = as.character(length(
        Filter(function(a) a$severity %in% c("critical", "emergency") && !a$resolved,
               alert_state$active_alerts)
      )))
    }

    return(TRUE)

  }, error = function(e) {
    cat("⚠️ Failed to set Cloud Run environment variables:", e$message, "\n")
    return(FALSE)
  })
}

#' Sanitize Message for LGPD Compliance
#'
#' @param message Original message
#' @return Sanitized message
sanitize_message_for_lgpd <- function(message) {
  # Remove potential personal identifiers
  sanitized <- message

  # Remove IP addresses
  sanitized <- gsub("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b", "[IP_REDACTED]", sanitized, perl = TRUE)

  # Remove email patterns
  sanitized <- gsub("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "[EMAIL_REDACTED]", sanitized)

  # Remove potential user IDs (sequences of digits/alphanumeric)
  sanitized <- gsub("\\b[a-fA-F0-9]{8,}\\b", "[ID_REDACTED]", sanitized)

  return(sanitized)
}

#' Check if Escalation is Required
#'
#' @param alert Alert object
check_escalation_required <- function(alert) {
  # Escalation criteria
  should_escalate <- FALSE

  # Emergency alerts always escalate
  if (alert$severity == "emergency") {
    should_escalate <- TRUE
  }

  # Critical alerts during business hours
  if (alert$severity == "critical" && "business_hours" %in% alert$tags) {
    should_escalate <- TRUE
  }

  # Multiple critical alerts
  critical_count <- length(Filter(function(a) a$severity %in% c("critical", "emergency") && !a$resolved,
                                 alert_state$active_alerts))
  if (critical_count >= 3) {
    should_escalate <- TRUE
  }

  # System-wide outage indicators
  if (alert$type == "system" && alert$severity == "critical") {
    should_escalate <- TRUE
  }

  if (should_escalate && !alert$escalated) {
    escalate_alert(alert)
  }
}

#' Escalate Alert
#'
#' @param alert Alert object to escalate
escalate_alert <- function(alert) {
  alert$escalated <- TRUE
  alert$escalation_time <- Sys.time()

  # Add to escalation registry
  alert_state$escalation_registry[[alert$id]] <<- alert

  # Update active alert
  alert_state$active_alerts[[alert$id]] <<- alert

  # Create escalation alert
  escalation_title <- paste("ESCALATED:", alert$title)
  escalation_message <- sprintf(
    "Alert %s has been escalated due to severity or conditions. Original: %s",
    alert$id, alert$message
  )

  # Log escalation
  cat("🆘 ALERT ESCALATED:", alert$id, "-", alert$title, "\n")

  # Send escalation notification (if configured)
  if (alerting_config$delivery_channels$webhook) {
    deliver_escalation_webhook(alert)
  }
}

#' Deliver Escalation Webhook
#'
#' @param alert Escalated alert object
deliver_escalation_webhook <- function(alert) {
  webhook_url <- Sys.getenv("ESCALATION_WEBHOOK_URL", Sys.getenv("WEBHOOK_URL", ""))
  if (webhook_url == "") {
    return(FALSE)
  }

  escalation_payload <- list(
    type = "escalation",
    original_alert = alert,
    escalation_time = format(alert$escalation_time, "%Y-%m-%dT%H:%M:%SZ"),
    escalation_reason = "severity_or_conditions",
    environment = alert$environment,
    urgent = TRUE
  )

  tryCatch({
    response <- httr::POST(
      url = webhook_url,
      body = escalation_payload,
      encode = "json",
      httr::add_headers("Content-Type" = "application/json"),
      httr::timeout(10)
    )

    return(httr::status_code(response) %in% c(200, 201, 202))

  }, error = function(e) {
    cat("❌ Escalation webhook failed:", e$message, "\n")
    return(FALSE)
  })
}

# Predefined Alert Functions
# ===========================

#' System Health Alert
#'
#' @param severity Severity level
#' @param component System component
#' @param status Health status
#' @param details Additional details
alert_system_health <- function(severity, component, status, details = "") {
  title <- sprintf("System Health: %s %s", component, status)
  message <- sprintf("Component %s is %s. %s", component, status, details)

  create_production_alert(
    alert_type = "system",
    severity = severity,
    title = title,
    message = message,
    source = "health_monitor"
  )
}

#' Performance Alert
#'
#' @param metric_name Name of the performance metric
#' @param current_value Current metric value
#' @param threshold_value Threshold that was exceeded
#' @param severity Severity level
alert_performance <- function(metric_name, current_value, threshold_value, severity) {
  title <- sprintf("Performance: %s Threshold Exceeded", metric_name)
  message <- sprintf("%s is %s, exceeding threshold of %s",
                    metric_name, current_value, threshold_value)

  create_production_alert(
    alert_type = "performance",
    severity = severity,
    title = title,
    message = message,
    source = "performance_monitor",
    metric_value = current_value,
    threshold = threshold_value
  )
}

#' Resource Alert
#'
#' @param resource_type Type of resource (memory, cpu, disk)
#' @param usage_percent Current usage percentage
#' @param threshold Threshold percentage
alert_resource_usage <- function(resource_type, usage_percent, threshold) {
  severity <- if (usage_percent > alerting_config$thresholds[[paste0(resource_type, "_critical")]]) {
    "critical"
  } else {
    "warning"
  }

  title <- sprintf("Resource Usage: %s at %s%%", tools::toTitleCase(resource_type), round(usage_percent, 1))
  message <- sprintf("%s usage is %s%%, exceeding %s threshold of %s%%",
                    tools::toTitleCase(resource_type), round(usage_percent, 1),
                    severity, threshold)

  create_production_alert(
    alert_type = "system",
    severity = severity,
    title = title,
    message = message,
    source = "resource_monitor",
    metric_value = usage_percent,
    threshold = threshold
  )
}

#' Database Alert
#'
#' @param db_metric Database metric name
#' @param current_value Current value
#' @param threshold Threshold value
#' @param severity Severity level
alert_database <- function(db_metric, current_value, threshold, severity) {
  title <- sprintf("Database: %s Issue", tools::toTitleCase(db_metric))
  message <- sprintf("Database %s is %s, threshold: %s", db_metric, current_value, threshold)

  create_production_alert(
    alert_type = "database",
    severity = severity,
    title = title,
    message = message,
    source = "database_monitor",
    metric_value = current_value,
    threshold = threshold
  )
}

#' Security Alert
#'
#' @param security_event Type of security event
#' @param severity Severity level
#' @param details Event details
alert_security <- function(security_event, severity, details) {
  title <- sprintf("Security: %s", security_event)
  message <- sprintf("Security event detected: %s. Details: %s", security_event, details)

  create_production_alert(
    alert_type = "security",
    severity = severity,
    title = title,
    message = message,
    source = "security_monitor"
  )
}

#' LGPD Compliance Alert
#'
#' @param compliance_issue Description of compliance issue
#' @param severity Severity level
#' @param recommendation Recommended action
alert_lgpd_compliance <- function(compliance_issue, severity, recommendation = "") {
  title <- sprintf("LGPD Compliance: %s", compliance_issue)
  message <- sprintf("LGPD compliance issue: %s. Recommendation: %s",
                    compliance_issue, recommendation)

  create_production_alert(
    alert_type = "compliance",
    severity = severity,
    title = title,
    message = message,
    source = "compliance_monitor"
  )
}

#' Academic Workflow Alert
#'
#' @param workflow_issue Description of academic workflow issue
#' @param severity Severity level
#' @param impact Impact description
alert_academic_workflow <- function(workflow_issue, severity, impact = "") {
  title <- sprintf("Academic Workflow: %s", workflow_issue)
  message <- sprintf("Academic workflow issue: %s. Impact: %s", workflow_issue, impact)

  create_production_alert(
    alert_type = "academic",
    severity = severity,
    title = title,
    message = message,
    source = "academic_monitor"
  )
}

#' Cloud Run Infrastructure Alert
#'
#' @param cloud_run_issue Description of Cloud Run issue
#' @param severity Severity level
#' @param service_impact Service impact description
alert_cloud_run_infrastructure <- function(cloud_run_issue, severity, service_impact = "") {
  title <- sprintf("Cloud Run Infrastructure: %s", cloud_run_issue)
  message <- sprintf("Cloud Run infrastructure issue: %s. Service impact: %s",
                    cloud_run_issue, service_impact)

  create_production_alert(
    alert_type = "cloud_run",
    severity = severity,
    title = title,
    message = message,
    source = "cloud_run_monitor"
  )
}

# Alert Resolution Functions
# ===========================

#' Resolve Alert
#'
#' @param alert_id ID of alert to resolve
#' @param resolution_note Optional resolution note
resolve_alert <- function(alert_id, resolution_note = "") {
  if (alert_id %in% names(alert_state$active_alerts)) {
    alert <- alert_state$active_alerts[[alert_id]]
    alert$resolved <- TRUE
    alert$resolution_time <- Sys.time()
    alert$resolution_note <- resolution_note

    # Update alert in state
    alert_state$active_alerts[[alert_id]] <<- NULL  # Remove from active
    alert_state$alert_history[[length(alert_state$alert_history) + 1]] <<- alert

    cat("✅ Alert resolved:", alert_id, "-", alert$title, "\n")

    # Clear Cloud Run environment variables for critical alerts
    if (alert$severity %in% c("critical", "emergency")) {
      active_critical <- length(Filter(function(a) a$severity %in% c("critical", "emergency") && !a$resolved,
                                      alert_state$active_alerts))
      if (active_critical == 0) {
        Sys.setenv(CRITICAL_ALERT_ACTIVE = "false")
        Sys.setenv(CRITICAL_ALERT_COUNT = "0")
      }
    }

    return(TRUE)
  } else {
    cat("⚠️ Alert not found:", alert_id, "\n")
    return(FALSE)
  }
}

#' Auto-resolve Alerts
#'
#' @description Automatically resolve alerts that can be auto-resolved
auto_resolve_alerts <- function() {
  resolved_count <- 0

  for (alert_id in names(alert_state$active_alerts)) {
    alert <- alert_state$active_alerts[[alert_id]]

    if (alert$auto_resolve) {
      # Check if conditions for auto-resolution are met
      if (should_auto_resolve(alert)) {
        resolve_alert(alert_id, "Auto-resolved: conditions normalized")
        resolved_count <- resolved_count + 1
      }
    }
  }

  if (resolved_count > 0) {
    cat("🔄 Auto-resolved", resolved_count, "alerts\n")
  }

  return(resolved_count)
}

#' Check if Alert Should be Auto-resolved
#'
#' @param alert Alert object to check
#' @return Logical indicating if alert should be auto-resolved
should_auto_resolve <- function(alert) {
  # Auto-resolve logic based on alert type and current conditions
  # This would be implemented based on specific monitoring data

  # For now, simple time-based auto-resolution for some alert types
  alert_age_minutes <- as.numeric(difftime(Sys.time(), alert$timestamp, units = "mins"))

  # Auto-resolve info alerts after 30 minutes
  if (alert$severity == "info" && alert_age_minutes > 30) {
    return(TRUE)
  }

  # Auto-resolve warning alerts after 2 hours if conditions are normal
  if (alert$severity == "warning" && alert_age_minutes > 120) {
    # Check if current conditions are normal (simplified)
    return(TRUE)
  }

  return(FALSE)
}

# Alert Summary and Reporting
# ===========================

#' Get Alert Summary
#'
#' @return Summary of current alert status
get_alert_summary <- function() {
  active_alerts <- alert_state$active_alerts
  total_active <- length(active_alerts)

  severity_counts <- table(sapply(active_alerts, function(a) a$severity))
  type_counts <- table(sapply(active_alerts, function(a) a$type))

  summary <- list(
    timestamp = Sys.time(),
    total_active_alerts = total_active,
    severity_breakdown = as.list(severity_counts),
    type_breakdown = as.list(type_counts),
    escalated_alerts = length(alert_state$escalation_registry),
    recent_alerts_24h = length(Filter(function(a) {
      as.numeric(difftime(Sys.time(), a$timestamp, units = "hours")) <= 24
    }, alert_state$alert_history)),
    system_uptime_hours = round(as.numeric(difftime(Sys.time(), alert_state$system_start_time, units = "hours")), 1),
    environment = alerting_config$cloud_run_settings$environment
  )

  return(summary)
}

#' Generate Alert Report
#'
#' @param hours_back Number of hours to include in report (default: 24)
#' @return Detailed alert report
generate_alert_report <- function(hours_back = 24) {
  cutoff_time <- Sys.time() - (hours_back * 3600)

  recent_alerts <- Filter(function(a) a$timestamp >= cutoff_time, alert_state$alert_history)

  report <- list(
    report_timestamp = Sys.time(),
    report_period_hours = hours_back,
    total_alerts = length(recent_alerts),
    alerts_by_severity = table(sapply(recent_alerts, function(a) a$severity)),
    alerts_by_type = table(sapply(recent_alerts, function(a) a$type)),
    alerts_by_hour = table(format(sapply(recent_alerts, function(a) a$timestamp), "%H")),
    resolved_alerts = length(Filter(function(a) a$resolved, recent_alerts)),
    escalated_alerts = length(Filter(function(a) a$escalated, recent_alerts)),
    top_alert_sources = head(sort(table(sapply(recent_alerts, function(a) a$source)), decreasing = TRUE), 5),
    system_summary = get_alert_summary()
  )

  return(report)
}

# Initialize Alerting System
# ===========================

#' Initialize Production Alerting System
#'
#' @return Success status
initialize_alerting_system <- function() {
  cat("🚀 Initializing Production Alerting System...\n")

  # Create alert directories
  alert_dirs <- c(
    "monitoring/alerts",
    "monitoring/logs",
    "monitoring/reports"
  )

  for (dir in alert_dirs) {
    if (!dir.exists(dir)) {
      dir.create(dir, recursive = TRUE)
    }
  }

  # Set system start time
  alert_state$system_start_time <<- Sys.time()

  # Create initial system health alert
  create_production_alert(
    alert_type = "system",
    severity = "info",
    title = "Alerting System Initialized",
    message = sprintf("Production alerting system started at %s",
                     format(Sys.time(), "%Y-%m-%d %H:%M:%S")),
    source = "alerting_system",
    auto_resolve = FALSE
  )

  cat("✅ Production alerting system initialized successfully\n")
  cat("   Environment:", alerting_config$cloud_run_settings$environment, "\n")
  cat("   Timezone:", alerting_config$academic_settings$timezone, "\n")
  cat("   LGPD Compliance: Enabled\n")
  cat("   Delivery Channels:", paste(names(which(unlist(alerting_config$delivery_channels))), collapse = ", "), "\n\n")

  return(TRUE)
}

# Export alerting system
production_alerting <- list(
  config = alerting_config,
  create_alert = create_production_alert,
  resolve_alert = resolve_alert,
  auto_resolve = auto_resolve_alerts,
  get_summary = get_alert_summary,
  generate_report = generate_alert_report,
  initialize = initialize_alerting_system,

  # Specific alert functions
  alert_system_health = alert_system_health,
  alert_performance = alert_performance,
  alert_resource_usage = alert_resource_usage,
  alert_database = alert_database,
  alert_security = alert_security,
  alert_lgpd_compliance = alert_lgpd_compliance,
  alert_academic_workflow = alert_academic_workflow,
  alert_cloud_run_infrastructure = alert_cloud_run_infrastructure
)

# Auto-initialize if in production
if (Sys.getenv("K_SERVICE", "") != "" ||
    Sys.getenv("R_CONFIG_ACTIVE", "") == "production") {
  initialize_alerting_system()
}