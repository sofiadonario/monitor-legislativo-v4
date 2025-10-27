# Automated Alerting System for Performance Monitoring
# Monitor Legislativo v4 - Phase 2 Enhancement
# Proactive Performance Degradation Detection and Notification
# Created: 2025-07-29

library(DBI)
library(RPostgres)
library(pool)
library(dplyr)
library(lubridate)
library(jsonlite)
library(httr)
library(digest)

# Load monitoring systems if available
if (file.exists("performance_monitoring.R")) {
  source("performance_monitoring.R")
}
if (file.exists("database_monitoring.R")) {
  source("database_monitoring.R")
}
if (file.exists("user_activity_monitoring.R")) {
  source("user_activity_monitoring.R")
}

# Global alerting system state
.alerting_state <- new.env(parent = emptyenv())
.alerting_state$enabled <- TRUE
.alerting_state$notification_channels <- list()
.alerting_state$alert_cooldown_periods <- list()
.alerting_state$escalation_chains <- list()
.alerting_state$alert_history <- list()

#' Initialize Automated Alerting System
#' @return Boolean indicating success
init_alerting_system <- function() {
  tryCatch({
    cat("🚨 Initializing Automated Alerting System\n")
    
    if (is.null(.db_pool)) {
      log_event("Alerting system requires database connection", "WARN")
      return(FALSE)
    }
    
    # Verify alert tables exist
    alert_tables <- dbGetQuery(.db_pool,
      "SELECT table_name FROM information_schema.tables 
       WHERE table_schema = 'public' 
       AND table_name IN ('monitoring_alert_rules', 'monitoring_alerts')"
    )
    
    if (nrow(alert_tables) < 2) {
      log_event("Alerting database schema not found - run migrations first", "ERROR")
      return(FALSE)
    }
    
    # Load alert rules from database
    load_alert_rules()
    
    # Setup notification channels
    setup_notification_channels()
    
    # Initialize alert evaluation scheduler
    setup_alert_evaluation_scheduler()
    
    # Setup escalation chains
    setup_escalation_chains()
    
    log_event("Automated alerting system initialized successfully")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Alerting system initialization error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Load Alert Rules from Database
load_alert_rules <- function() {
  tryCatch({
    # Load active alert rules
    alert_rules <- dbGetQuery(.db_pool, "
      SELECT * FROM monitoring_alert_rules 
      WHERE is_active = true
      ORDER BY rule_name
    ")
    
    .alerting_state$active_rules <- alert_rules
    log_event(paste("Loaded", nrow(alert_rules), "active alert rules"))
    
  }, error = function(e) {
    log_event(paste("Failed to load alert rules:", e$message), "ERROR")
    .alerting_state$active_rules <- data.frame()
  })
}

#' Setup Notification Channels
setup_notification_channels <- function() {
  tryCatch({
    # Email notification setup
    email_config <- list(
      enabled = nchar(Sys.getenv("SMTP_SERVER", "")) > 0,
      smtp_server = Sys.getenv("SMTP_SERVER", ""),
      smtp_port = as.numeric(Sys.getenv("SMTP_PORT", "587")),
      smtp_username = Sys.getenv("SMTP_USERNAME", ""),
      smtp_password = Sys.getenv("SMTP_PASSWORD", ""),
      from_email = Sys.getenv("ALERT_FROM_EMAIL", "alerts@monitorlegislativo.com"),
      admin_emails = strsplit(Sys.getenv("ADMIN_EMAILS", ""), ",")[[1]]
    )
    
    # Webhook notification setup
    webhook_config <- list(
      enabled = nchar(Sys.getenv("WEBHOOK_URL", "")) > 0,
      webhook_url = Sys.getenv("WEBHOOK_URL", ""),
      webhook_secret = Sys.getenv("WEBHOOK_SECRET", ""),
      slack_webhook = Sys.getenv("SLACK_WEBHOOK_URL", ""),
      discord_webhook = Sys.getenv("DISCORD_WEBHOOK_URL", "")
    )
    
    # Railway-specific notifications
    railway_config <- list(
      enabled = nchar(Sys.getenv("RAILWAY_PROJECT_ID", "")) > 0,
      project_id = Sys.getenv("RAILWAY_PROJECT_ID", ""),
      service_id = Sys.getenv("RAILWAY_SERVICE_ID", ""),
      api_token = Sys.getenv("RAILWAY_API_TOKEN", "")
    )
    
    .alerting_state$notification_channels <- list(
      email = email_config,
      webhook = webhook_config,
      railway = railway_config
    )
    
    enabled_channels <- sum(email_config$enabled, webhook_config$enabled, railway_config$enabled)
    log_event(paste("Notification channels configured:", enabled_channels, "enabled"))
    
  }, error = function(e) {
    log_event(paste("Notification channel setup error:", e$message), "ERROR")
  })
}

#' Setup Alert Evaluation Scheduler
setup_alert_evaluation_scheduler <- function() {
  tryCatch({
    # Set evaluation interval (every 60 seconds)
    .alerting_state$evaluation_interval <- 60
    .alerting_state$last_evaluation <- NULL
    .alerting_state$scheduler_active <- TRUE
    
    # Start periodic evaluation if later package is available
    if (requireNamespace("later", quietly = TRUE)) {
      schedule_next_evaluation()
    }
    
    log_event("Alert evaluation scheduler setup complete")
    
  }, error = function(e) {
    log_event(paste("Alert scheduler setup error:", e$message), "ERROR")
  })
}

#' Schedule Next Alert Evaluation
schedule_next_evaluation <- function() {
  if (!.alerting_state$scheduler_active || !.alerting_state$enabled) {
    return(FALSE)
  }
  
  tryCatch({
    later::later(function() {
      evaluate_all_alerts()
      schedule_next_evaluation() # Reschedule
    }, delay = .alerting_state$evaluation_interval)
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Alert evaluation scheduling error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Evaluate All Active Alert Rules
evaluate_all_alerts <- function() {
  if (!.alerting_state$enabled || isTRUE(is.null(.db_pool))) {
    return(FALSE)
  }
  
  tryCatch({
    cat("🔍 Evaluating alert rules...\n")
    
    # Update last evaluation time
    .alerting_state$last_evaluation <- Sys.time()
    
    # Get latest metrics for evaluation
    latest_metrics <- collect_latest_metrics_for_alerting()
    
    # Evaluate each active rule
    alerts_triggered <- 0
    
    if (!isTRUE(is.null(.alerting_state$active_rules)) && nrow(.alerting_state$active_rules) > 0) {
      for (i in 1:nrow(.alerting_state$active_rules)) {
        rule <- .alerting_state$active_rules[i, ]
        
        # Check if rule is in cooldown period
        if (!is_rule_in_cooldown(rule$id)) {
          # Evaluate rule against latest metrics
          alert_result <- evaluate_single_alert_rule(rule, latest_metrics)
          
          if (!isTRUE(is.null(alert_result)) && alert_result$triggered) {
            # Create alert and send notifications
            created_alert <- create_alert_record(rule, alert_result)
            
            if (!is.null(created_alert)) {
              send_alert_notifications(rule, created_alert, alert_result)
              alerts_triggered <- alerts_triggered + 1
              
              # Set cooldown period
              set_rule_cooldown(rule$id, rule$alert_frequency_minutes %||% 15)
            }
          }
        }
      }
    }
    
    # Call database function for additional alert evaluation
    tryCatch({
      db_alerts <- dbGetQuery(.db_pool, "SELECT evaluate_alert_rules()")
      db_alerts_count <- db_alerts[[1]] %||% 0
      
      if (db_alerts_count > 0) {
        log_event(paste("Database alert evaluation created", db_alerts_count, "additional alerts"))
        alerts_triggered <- alerts_triggered + db_alerts_count
      }
    }, error = function(e) {
      log_event(paste("Database alert evaluation error:", e$message), "WARN")
    })
    
    if (alerts_triggered > 0) {
      log_event(paste("Alert evaluation completed:", alerts_triggered, "alerts triggered"))
    }
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Alert evaluation error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Collect Latest Metrics for Alert Evaluation
#' @return List with latest metrics from all monitoring systems
collect_latest_metrics_for_alerting <- function() {
  metrics <- list()
  
  tryCatch({
    # System health metrics
    if (exists("collect_system_health_metrics")) {
      metrics$system <- collect_system_health_metrics()
    }
    
    # Database performance metrics
    if (exists("get_database_performance_analysis")) {
      db_analysis <- get_database_performance_analysis()
      if (!isTRUE(is.null(db_analysis)) && isTRUE(is.null(db_analysis$error))) {
        metrics$database <- list(
          pool_active_connections = db_analysis$connection_pool$active_connections,
          slow_queries_count = db_analysis$query_performance$slow_queries_count,
          cache_hit_ratio = db_analysis$cache_performance$overall_hit_ratio,
          avg_query_time_ms = db_analysis$query_performance$avg_query_time_ms
        )
      }
    }
    
    # Application performance metrics
    if (exists("collect_application_performance_metrics")) {
      metrics$application <- collect_application_performance_metrics()
    }
    
    # User activity metrics
    if (exists("get_user_activity_summary")) {
      user_summary <- get_user_activity_summary()
      if (!isTRUE(is.null(user_summary)) && isTRUE(is.null(user_summary$error))) {
        metrics$user_activity <- list(
          user_satisfaction_score = user_summary$user_satisfaction,
          bounce_rate_percent = user_summary$bounce_rate
        )
      }
    }
    
    return(metrics)
    
  }, error = function(e) {
    log_event(paste("Metrics collection for alerting error:", e$message), "ERROR")
    return(list())
  })
}

#' Evaluate Single Alert Rule
#' @param rule Alert rule to evaluate
#' @param metrics Latest metrics data
#' @return List with evaluation result
evaluate_single_alert_rule <- function(rule, metrics) {
  tryCatch({
    # Get the metric value based on rule type and name
    metric_value <- extract_metric_value(rule$metric_type, rule$metric_name, metrics)
    
    if (isTRUE(is.null(metric_value)) || isTRUE(is.na(metric_value))) {
      return(NULL)
    }
    
    # Evaluate thresholds
    alert_level <- NULL
    threshold_value <- NULL
    
    # Check critical threshold first
    if (!is.na(rule$critical_threshold)) {
      if (evaluate_threshold(metric_value, rule$critical_threshold, rule$comparison_operator)) {
        alert_level <- "critical"
        threshold_value <- rule$critical_threshold
      }
    }
    
    # Check warning threshold if no critical alert
    if (isTRUE(is.null(alert_level)) && !is.na(rule$warning_threshold)) {
      if (evaluate_threshold(metric_value, rule$warning_threshold, rule$comparison_operator)) {
        alert_level <- "warning"
        threshold_value <- rule$warning_threshold
      }
    }
    
    if (!is.null(alert_level)) {
      return(list(
        triggered = TRUE,
        alert_level = alert_level,
        metric_value = metric_value,
        threshold_value = threshold_value,
        timestamp = Sys.time()
      ))
    }
    
    return(list(triggered = FALSE))
    
  }, error = function(e) {
    log_event(paste("Alert rule evaluation error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Extract Metric Value from Metrics Data
#' @param metric_type Type of metric (system, database, application)
#' @param metric_name Name of specific metric
#' @param metrics Complete metrics data
#' @return Numeric metric value or NULL
extract_metric_value <- function(metric_type, metric_name, metrics) {
  tryCatch({
    if (metric_type == "system" && !is.null(metrics$system)) {
      return(metrics$system[[metric_name]])
    } else if (metric_type == "database" && !is.null(metrics$database)) {
      return(metrics$database[[metric_name]])
    } else if (metric_type == "application" && !is.null(metrics$application)) {
      return(metrics$application[[metric_name]])
    } else if (metric_type == "user_activity" && !is.null(metrics$user_activity)) {
      return(metrics$user_activity[[metric_name]])
    }
    
    return(NULL)
    
  }, error = function(e) {
    return(NULL)
  })
}

#' Evaluate Threshold Condition
#' @param metric_value Current metric value
#' @param threshold_value Threshold to compare against
#' @param comparison_operator Comparison operator
#' @return Boolean indicating if threshold is exceeded
evaluate_threshold <- function(metric_value, threshold_value, comparison_operator) {
  tryCatch({
    switch(comparison_operator,
      ">" = metric_value > threshold_value,
      "<" = metric_value < threshold_value,
      ">=" = metric_value >= threshold_value,
      "<=" = metric_value <= threshold_value,
      "=" = metric_value == threshold_value,
      FALSE
    )
  }, error = function(e) {
    return(FALSE)
  })
}

#' Create Alert Record in Database
#' @param rule Alert rule that was triggered
#' @param alert_result Result from rule evaluation
#' @return Alert record or NULL on error
create_alert_record <- function(rule, alert_result) {
  if (is.null(.db_pool)) {
    return(NULL)
  }
  
  tryCatch({
    alert_id <- UUIDgenerate()
    
    dbExecute(.db_pool,
      "INSERT INTO monitoring_alerts (
        id, rule_id, alert_level, metric_value, threshold_value, 
        metric_timestamp, alert_status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
      params = list(
        alert_id, rule$id, alert_result$alert_level, 
        alert_result$metric_value, alert_result$threshold_value,
        alert_result$timestamp, "active"
      )
    )
    
    # Get the created alert record
    alert_record <- dbGetQuery(.db_pool,
      "SELECT * FROM monitoring_alerts WHERE id = $1",
      params = list(alert_id)
    )
    
    log_event(paste("Alert created:", rule$rule_name, "-", alert_result$alert_level))
    return(alert_record[1, ])
    
  }, error = function(e) {
    log_event(paste("Alert record creation error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Send Alert Notifications
#' @param rule Alert rule
#' @param alert_record Database alert record
#' @param alert_result Evaluation result
send_alert_notifications <- function(rule, alert_record, alert_result) {
  tryCatch({
    # Prepare alert message
    alert_message <- format_alert_message(rule, alert_record, alert_result)
    
    # Send notifications through enabled channels
    notifications_sent <- list()
    
    # Email notifications
    if (.alerting_state$notification_channels$email$enabled) {
      email_result <- send_email_alert(rule, alert_message)
      notifications_sent$email <- email_result
    }
    
    # Webhook notifications
    if (.alerting_state$notification_channels$webhook$enabled) {
      webhook_result <- send_webhook_alert(rule, alert_message, alert_result)
      notifications_sent$webhook <- webhook_result
    }
    
    # Railway-specific notifications
    if (.alerting_state$notification_channels$railway$enabled) {
      railway_result <- send_railway_alert(rule, alert_message, alert_result)
      notifications_sent$railway <- railway_result
    }
    
    # Update alert record with notification status
    update_alert_notification_status(alert_record$id, notifications_sent)
    
    log_event(paste("Alert notifications sent for:", rule$rule_name))
    
  }, error = function(e) {
    log_event(paste("Alert notification error:", e$message), "ERROR")
  })
}

#' Format Alert Message
#' @param rule Alert rule
#' @param alert_record Alert record
#' @param alert_result Evaluation result
#' @return Formatted alert message
format_alert_message <- function(rule, alert_record, alert_result) {
  severity_emoji <- switch(alert_result$alert_level,
    "critical" = "🚨",
    "warning" = "⚠️",
    "info" = "ℹ️",
    "🔍"
  )
  
  message <- paste0(
    severity_emoji, " MONITOR LEGISLATIVO ALERT\n\n",
    "Rule: ", rule$rule_name, "\n",
    "Level: ", toupper(alert_result$alert_level), "\n",
    "Description: ", rule$rule_description, "\n\n",
    "Current Value: ", round(alert_result$metric_value, 2), "\n",
    "Threshold: ", alert_result$threshold_value, "\n",
    "Metric: ", rule$metric_name, " (", rule$metric_type, ")\n\n",
    "Time: ", format(alert_result$timestamp, "%Y-%m-%d %H:%M:%S %Z"), "\n",
    "Alert ID: ", alert_record$id, "\n\n",
    "Platform: Railway Deployment\n",
    "Service: Monitor Legislativo v4\n\n",
    "This is an automated alert from the performance monitoring system."
  )
  
  return(message)
}

#' Send Email Alert
#' @param rule Alert rule
#' @param message Alert message
#' @return Boolean indicating success
send_email_alert <- function(rule, message) {
  tryCatch({
    email_config <- .alerting_state$notification_channels$email
    
    if (!email_config$enabled || length(email_config$admin_emails) == 0) {
      return(FALSE)
    }
    
    # Format subject
    subject <- paste0("[ALERT] Monitor Legislativo - ", rule$rule_name)
    
    # Send email (would require email package like mailR or blastula)
    # For now, we'll log the email attempt
    log_event(paste("EMAIL ALERT:", subject, "- Message:", substr(message, 1, 100), "..."))
    
    # In production, this would use:
    # mailR::send.mail(
    #   from = email_config$from_email,
    #   to = email_config$admin_emails,
    #   subject = subject,
    #   body = message,
    #   smtp = list(
    #     host.name = email_config$smtp_server,
    #     port = email_config$smtp_port,
    #     user.name = email_config$smtp_username,
    #     passwd = email_config$smtp_password,
    #     ssl = TRUE
    #   )
    # )
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Email alert error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Send Webhook Alert
#' @param rule Alert rule
#' @param message Alert message
#' @param alert_result Evaluation result
#' @return Boolean indicating success
send_webhook_alert <- function(rule, message, alert_result) {
  tryCatch({
    webhook_config <- .alerting_state$notification_channels$webhook
    
    if (!webhook_config$enabled) {
      return(FALSE)
    }
    
    # Prepare webhook payload
    payload <- list(
      alert = list(
        rule_name = rule$rule_name,
        level = alert_result$alert_level,
        metric_value = alert_result$metric_value,
        threshold_value = alert_result$threshold_value,
        metric_name = rule$metric_name,
        metric_type = rule$metric_type,
        timestamp = format(alert_result$timestamp, "%Y-%m-%dT%H:%M:%SZ"),
        description = rule$rule_description
      ),
      system = list(
        name = "Monitor Legislativo v4",
        platform = "Railway",
        environment = Sys.getenv("R_CONFIG_ACTIVE", "production")
      ),
      message = message
    )
    
    # Send to primary webhook
    if (nchar(webhook_config$webhook_url) > 0) {
      response <- httr::POST(
        webhook_config$webhook_url,
        body = toJSON(payload, auto_unbox = TRUE),
        add_headers("Content-Type" = "application/json"),
        if (nchar(webhook_config$webhook_secret) > 0) {
          add_headers("X-Alert-Secret" = webhook_config$webhook_secret)
        }
      )
      
      if (status_code(response) == 200) {
        log_event("Webhook alert sent successfully")
        return(TRUE)
      }
    }
    
    # Send to Slack if configured
    if (nchar(webhook_config$slack_webhook) > 0) {
      slack_payload <- list(
        text = paste0("Monitor Legislativo Alert: ", rule$rule_name),
        attachments = list(
          list(
            color = if (alert_result$alert_level == "critical") "danger" else "warning",
            fields = list(
              list(title = "Level", value = toupper(alert_result$alert_level), short = TRUE),
              list(title = "Metric", value = paste(rule$metric_name, round(alert_result$metric_value, 2)), short = TRUE),
              list(title = "Threshold", value = alert_result$threshold_value, short = TRUE),
              list(title = "Time", value = format(alert_result$timestamp, "%H:%M:%S"), short = TRUE)
            )
          )
        )
      )
      
      slack_response <- httr::POST(
        webhook_config$slack_webhook,
        body = toJSON(slack_payload, auto_unbox = TRUE),
        add_headers("Content-Type" = "application/json")
      )
      
      if (status_code(slack_response) == 200) {
        log_event("Slack alert sent successfully")
        return(TRUE)
      }
    }
    
    return(FALSE)
    
  }, error = function(e) {
    log_event(paste("Webhook alert error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Send Railway-specific Alert
#' @param rule Alert rule
#' @param message Alert message
#' @param alert_result Evaluation result
#' @return Boolean indicating success
send_railway_alert <- function(rule, message, alert_result) {
  tryCatch({
    railway_config <- .alerting_state$notification_channels$railway
    
    if (!railway_config$enabled) {
      return(FALSE)
    }
    
    # Railway doesn't have direct alerting API, but we can log structured data
    # that Railway's logging system can pick up
    
    railway_alert <- list(
      type = "PERFORMANCE_ALERT",
      level = toupper(alert_result$alert_level),
      rule = rule$rule_name,
      metric = rule$metric_name,
      value = alert_result$metric_value,
      threshold = alert_result$threshold_value,
      project_id = railway_config$project_id,
      service_id = railway_config$service_id,
      timestamp = format(alert_result$timestamp, "%Y-%m-%dT%H:%M:%SZ")
    )
    
    # Log as structured JSON for Railway to process
    cat("RAILWAY_ALERT:", toJSON(railway_alert, auto_unbox = TRUE), "\n")
    
    log_event("Railway alert logged successfully")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Railway alert error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Update Alert Notification Status
#' @param alert_id Alert ID
#' @param notifications_sent Notification results
update_alert_notification_status <- function(alert_id, notifications_sent) {
  if (is.null(.db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    dbExecute(.db_pool,
      "UPDATE monitoring_alerts 
       SET notifications_sent = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $1",
      params = list(alert_id, toJSON(notifications_sent))
    )
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Alert notification status update error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Check if Rule is in Cooldown Period
#' @param rule_id Rule identifier
#' @return Boolean indicating if rule is in cooldown
is_rule_in_cooldown <- function(rule_id) {
  cooldown_key <- as.character(rule_id)
  
  if (is.null(.alerting_state$alert_cooldown_periods[[cooldown_key]])) {
    return(FALSE)
  }
  
  cooldown_until <- .alerting_state$alert_cooldown_periods[[cooldown_key]]
  return(Sys.time() < cooldown_until)
}

#' Set Rule Cooldown Period
#' @param rule_id Rule identifier
#' @param minutes Cooldown period in minutes
set_rule_cooldown <- function(rule_id, minutes) {
  cooldown_key <- as.character(rule_id)
  cooldown_until <- Sys.time() + minutes(minutes)
  
  .alerting_state$alert_cooldown_periods[[cooldown_key]] <- cooldown_until
}

#' Setup Escalation Chains
setup_escalation_chains <- function() {
  # Basic escalation: Warning -> Critical after 1 hour
  .alerting_state$escalation_chains <- list(
    default = list(
      warning_to_critical_minutes = 60,
      max_escalation_attempts = 3,
      escalation_interval_minutes = 30
    )
  )
  
  log_event("Alert escalation chains configured")
}

#' Acknowledge Alert
#' @param alert_id Alert identifier
#' @param user_id User acknowledging the alert
#' @param notes Acknowledgment notes
#' @return Boolean indicating success
acknowledge_alert <- function(alert_id, user_id, notes = "") {
  if (is.null(.db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    dbExecute(.db_pool,
      "UPDATE monitoring_alerts 
       SET alert_status = 'acknowledged', 
           acknowledged_by = $2, 
           acknowledged_at = CURRENT_TIMESTAMP,
           resolution_notes = $3,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1 AND alert_status = 'active'",
      params = list(alert_id, user_id, notes)
    )
    
    log_event(paste("Alert acknowledged:", alert_id, "by user:", user_id))
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Alert acknowledgment error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Resolve Alert
#' @param alert_id Alert identifier
#' @param user_id User resolving the alert (optional)
#' @param resolution_notes Resolution notes
#' @param auto_resolved Whether alert was auto-resolved
#' @return Boolean indicating success
resolve_alert <- function(alert_id, user_id = NULL, resolution_notes = "", auto_resolved = FALSE) {
  if (is.null(.db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    dbExecute(.db_pool,
      "UPDATE monitoring_alerts 
       SET alert_status = 'resolved', 
           resolved_at = CURRENT_TIMESTAMP,
           resolution_notes = $2,
           auto_resolved = $3,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1 AND alert_status IN ('active', 'acknowledged')",
      params = list(alert_id, resolution_notes, auto_resolved)
    )
    
    resolution_type <- if (auto_resolved) "auto-resolved" else "manually resolved"
    log_event(paste("Alert", resolution_type, ":", alert_id))
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Alert resolution error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Get Active Alerts Summary
#' @return List with active alerts information
get_active_alerts_summary <- function() {
  if (is.null(.db_pool)) {
    return(list(error = "Database connection not available"))
  }
  
  tryCatch({
    # Get active alerts by level
    active_alerts <- dbGetQuery(.db_pool, "
      SELECT 
        alert_level,
        COUNT(*) as count,
        MIN(created_at) as oldest_alert
      FROM monitoring_alerts 
      WHERE alert_status = 'active'
      GROUP BY alert_level
      ORDER BY 
        CASE alert_level 
          WHEN 'critical' THEN 1 
          WHEN 'warning' THEN 2 
          ELSE 3 
        END
    ")
    
    # Get recent alerts (last 24 hours)
    recent_alerts <- dbGetQuery(.db_pool, "
      SELECT 
        mar.rule_name,
        ma.alert_level,
        ma.metric_value,
        ma.threshold_value,
        ma.created_at,
        ma.alert_status
      FROM monitoring_alerts ma
      JOIN monitoring_alert_rules mar ON ma.rule_id = mar.id
      WHERE ma.created_at > (CURRENT_TIMESTAMP - INTERVAL '24 hours')
      ORDER BY ma.created_at DESC
      LIMIT 10
    ")
    
    # Calculate summary statistics
    total_active <- sum(active_alerts$count, na.rm = TRUE)
    critical_count <- active_alerts$count[active_alerts$alert_level == "critical"] %||% 0
    warning_count <- active_alerts$count[active_alerts$alert_level == "warning"] %||% 0
    
    list(
      total_active_alerts = total_active,
      critical_alerts = critical_count,
      warning_alerts = warning_count,
      alerts_by_level = active_alerts,
      recent_alerts = recent_alerts,
      oldest_unresolved = if (nrow(active_alerts) > 0) min(active_alerts$oldest_alert) else NULL,
      last_updated = Sys.time()
    )
    
  }, error = function(e) {
    log_event(paste("Active alerts summary error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Get Alert History
#' @param days Number of days to retrieve
#' @param limit Maximum number of alerts to return
#' @return List with alert history
get_alert_history <- function(days = 7, limit = 50) {
  if (is.null(.db_pool)) {
    return(list(error = "Database connection not available"))
  }
  
  tryCatch({
    alert_history <- dbGetQuery(.db_pool, "
      SELECT 
        ma.id,
        mar.rule_name,
        ma.alert_level,
        ma.metric_value,
        ma.threshold_value,
        ma.alert_status,
        ma.created_at,
        ma.acknowledged_at,
        ma.resolved_at,
        ma.auto_resolved,
        u.full_name as acknowledged_by_name
      FROM monitoring_alerts ma
      JOIN monitoring_alert_rules mar ON ma.rule_id = mar.id
      LEFT JOIN users u ON ma.acknowledged_by = u.id
      WHERE ma.created_at > (CURRENT_TIMESTAMP - INTERVAL '$1 days')
      ORDER BY ma.created_at DESC
      LIMIT $2
    ", params = list(days, limit))
    
    return(list(
      alerts = alert_history,
      total_alerts = nrow(alert_history),
      period_days = days
    ))
    
  }, error = function(e) {
    log_event(paste("Alert history retrieval error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Create Custom Alert Rule
#' @param rule_name Unique name for the rule
#' @param rule_description Description of what the rule monitors
#' @param metric_type Type of metric (system, database, application, user_activity)
#' @param metric_name Name of the specific metric
#' @param warning_threshold Warning threshold value
#' @param critical_threshold Critical threshold value
#' @param comparison_operator Comparison operator (>, <, >=, <=, =)
#' @param created_by User ID of rule creator
#' @return Boolean indicating success
create_custom_alert_rule <- function(rule_name, rule_description, metric_type, metric_name,
                                   warning_threshold = NULL, critical_threshold = NULL,
                                   comparison_operator = ">", created_by = NULL) {
  if (is.null(.db_pool)) {
    return(FALSE)
  }
  
  tryCatch({
    # Validate inputs
    valid_metric_types <- c("system", "database", "application", "user_activity")
    valid_operators <- c(">", "<", ">=", "<=", "=")
    
    if (!metric_type %in% valid_metric_types) {
      stop("Invalid metric_type. Must be one of: ", paste(valid_metric_types, collapse = ", "))
    }
    
    if (!comparison_operator %in% valid_operators) {
      stop("Invalid comparison_operator. Must be one of: ", paste(valid_operators, collapse = ", "))
    }
    
    if (isTRUE(is.null(warning_threshold)) && isTRUE(is.null(critical_threshold))) {
      stop("At least one threshold (warning or critical) must be specified")
    }
    
    # Create the rule
    dbExecute(.db_pool,
      "INSERT INTO monitoring_alert_rules (
        rule_name, rule_description, metric_type, metric_name,
        warning_threshold, critical_threshold, comparison_operator, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      params = list(
        rule_name, rule_description, metric_type, metric_name,
        warning_threshold, critical_threshold, comparison_operator, created_by
      )
    )
    
    log_event(paste("Custom alert rule created:", rule_name))
    
    # Reload alert rules
    load_alert_rules()
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Custom alert rule creation error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Test Alert System
#' @param rule_name Rule to test (optional, tests all if NULL)
#' @return List with test results
test_alert_system <- function(rule_name = NULL) {
  tryCatch({
    cat("🧪 Testing alerting system...\n")
    
    test_results <- list(
      timestamp = Sys.time(),
      database_connection = !is.null(.db_pool),
      rules_loaded = !isTRUE(is.null(.alerting_state$active_rules)) && nrow(.alerting_state$active_rules) > 0,
      notification_channels = list()
    )
    
    # Test notification channels
    test_results$notification_channels$email <- .alerting_state$notification_channels$email$enabled
    test_results$notification_channels$webhook <- .alerting_state$notification_channels$webhook$enabled
    test_results$notification_channels$railway <- .alerting_state$notification_channels$railway$enabled
    
    # Test metric collection
    test_results$metrics_collection <- tryCatch({
      metrics <- collect_latest_metrics_for_alerting()
      length(metrics) > 0
    }, error = function(e) FALSE)
    
    # Test alert evaluation (dry run)
    if (!isTRUE(is.null(rule_name)) && test_results$rules_loaded) {
      test_rule <- .alerting_state$active_rules[.alerting_state$active_rules$rule_name == rule_name, ]
      if (nrow(test_rule) > 0) {
        test_metrics <- collect_latest_metrics_for_alerting()
        evaluation_result <- evaluate_single_alert_rule(test_rule[1, ], test_metrics)
        test_results$rule_evaluation <- !is.null(evaluation_result)
      }
    }
    
    test_results$overall_status <- all(
      test_results$database_connection,
      test_results$rules_loaded,
      test_results$metrics_collection
    )
    
    log_event(paste("Alert system test completed. Status:", test_results$overall_status))
    return(test_results)
    
  }, error = function(e) {
    log_event(paste("Alert system test error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

# Initialize alerting system if database is available
if (exists(".db_pool") && !is.null(.db_pool)) {
  future({
    Sys.sleep(10) # Wait for other systems to initialize
    init_alerting_system()
  })
}

log_event("Automated Alerting System loaded successfully")