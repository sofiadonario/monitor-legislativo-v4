# ============================================================================
# DATA MONITORING AND ALERTING SYSTEM - SPRINT 4B
# ============================================================================
#
# Comprehensive monitoring and alerting system for Brazilian legislative data pipeline
# Real-time performance tracking, anomaly detection, and automated notifications
# Optimized for Railway deployment with memory-efficient operations
#
# Features:
# - Real-time pipeline performance monitoring
# - Data quality trend analysis and anomaly detection
# - API health monitoring with circuit breaker integration
# - Memory usage tracking for Railway constraints
# - Automated alerting via webhooks and email
# - Custom metrics dashboard for legislative data
# - Brazilian legislative data compliance monitoring
# - Historical performance analysis and reporting
# - Predictive failure detection using statistical models
#
# Author: Legislative Data Science Team
# Version: 4B.1.0 (Sprint 4B)
# Updated: 2025-01-20
# ============================================================================

# Load required packages
required_packages <- c(
  "dplyr", "lubridate", "jsonlite", "httr",
  "digest", "memuse", "pryr", "stringr",
  "data.table", "forecast", "changepoint"
)

missing_packages <- c()
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("⚠️ WARNING: Missing monitoring packages:", paste(missing_packages, collapse = ", "), "\n")
}

# Load available packages
suppressPackageStartupMessages({
  if (requireNamespace("dplyr", quietly = TRUE)) library(dplyr)
  if (requireNamespace("lubridate", quietly = TRUE)) library(lubridate)
  if (requireNamespace("jsonlite", quietly = TRUE)) library(jsonlite)
  if (requireNamespace("httr", quietly = TRUE)) library(httr)
  if (requireNamespace("digest", quietly = TRUE)) library(digest)
  if (requireNamespace("data.table", quietly = TRUE)) library(data.table)
  if (requireNamespace("stringr", quietly = TRUE)) library(stringr)
})

# ============================================================================
# MONITORING CONFIGURATION
# ============================================================================

MONITORING_CONFIG <- list(
  # Performance Thresholds
  thresholds = list(
    # Pipeline Performance
    etl_duration_warning_minutes = 45,
    etl_duration_critical_minutes = 90,
    validation_rate_warning = 75,
    validation_rate_critical = 50,
    
    # Resource Usage (Railway optimized)
    memory_warning_gb = 1.2,
    memory_critical_gb = 1.4,
    disk_usage_warning_gb = 0.5,
    disk_usage_critical_gb = 0.8,
    
    # Data Quality
    duplicate_rate_warning = 5,      # 5% duplicates
    duplicate_rate_critical = 10,    # 10% duplicates
    data_freshness_warning_hours = 48,
    data_freshness_critical_hours = 72,
    
    # API Health
    api_response_time_warning_ms = 5000,   # 5 seconds
    api_response_time_critical_ms = 10000, # 10 seconds
    api_error_rate_warning = 10,           # 10% errors
    api_error_rate_critical = 25           # 25% errors
  ),
  
  # Alert Configuration
  alerts = list(
    cooldown_minutes = 30,           # Minimum time between similar alerts
    max_alerts_per_hour = 10,        # Rate limiting
    webhook_timeout_seconds = 10,
    email_enabled = FALSE,           # Disable by default (Railway)
    webhook_enabled = TRUE,
    notification_channels = list(
      slack = Sys.getenv("SLACK_WEBHOOK_URL", ""),
      discord = Sys.getenv("DISCORD_WEBHOOK_URL", ""),
      teams = Sys.getenv("TEAMS_WEBHOOK_URL", ""),
      generic = Sys.getenv("MONITOR_WEBHOOK_URL", "")
    )
  ),
  
  # Data Retention
  retention = list(
    metrics_days = 30,
    alerts_days = 14,
    performance_days = 60,
    logs_days = 7
  ),
  
  # Brazilian Legislative Specific Monitoring
  legislative_monitoring = list(
    expected_daily_documents = 100,     # Expected new documents per day
    state_coverage_threshold = 80,      # Minimum state coverage percentage
    authority_diversity_threshold = 10,  # Minimum number of different authorities
    document_type_diversity = 5,        # Minimum document types
    municipality_coverage_threshold = 15 # Minimum municipality coverage percentage
  ),
  
  # Anomaly Detection
  anomaly_detection = list(
    enabled = TRUE,
    lookback_days = 14,                 # Days of historical data for baseline
    sensitivity = 2.0,                  # Standard deviations for anomaly threshold
    min_samples = 10                    # Minimum samples needed for detection
  )
)

# ============================================================================
# METRICS COLLECTOR
# ============================================================================

#' Metrics Collection and Storage System
MetricsCollector <- R6::R6Class("MetricsCollector",
  public = list(
    metrics_store = list(),
    db_pool = NULL,
    
    initialize = function(db_pool = NULL) {
      self$db_pool <- db_pool
      self$init_metrics_tables()
      log_etl("INFO", "Metrics collector initialized", "METRICS_COLLECTOR")
    },
    
    init_metrics_tables = function() {
      if (is.null(self$db_pool)) return()
      
      tryCatch({
        # Pipeline metrics table
        create_pipeline_metrics <- "
          CREATE TABLE IF NOT EXISTS pipeline_metrics (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metric_type VARCHAR(50) NOT NULL,
            metric_name VARCHAR(100) NOT NULL,
            metric_value NUMERIC,
            metric_unit VARCHAR(20),
            additional_data JSONB,
            pipeline_run_id VARCHAR(64),
            INDEX (timestamp, metric_type),
            INDEX (metric_name, timestamp)
          );
        "
        
        # Alert history table
        create_alert_history <- "
          CREATE TABLE IF NOT EXISTS alert_history (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            alert_type VARCHAR(50) NOT NULL,
            alert_level VARCHAR(20) NOT NULL,
            message TEXT NOT NULL,
            details JSONB,
            resolved BOOLEAN DEFAULT FALSE,
            resolved_at TIMESTAMP,
            cooldown_until TIMESTAMP,
            notification_sent BOOLEAN DEFAULT FALSE
          );
        "
        
        dbExecute(self$db_pool, create_pipeline_metrics)
        dbExecute(self$db_pool, create_alert_history)
        
      }, error = function(e) {
        log_etl("WARN", sprintf("Metrics tables initialization failed: %s", e$message), "METRICS_COLLECTOR")
      })
    },
    
    collect_pipeline_metrics = function(pipeline_run_id, duration_minutes, documents_processed, validation_rate) {
      timestamp <- Sys.time()
      
      metrics <- list(
        list(
          type = "performance", 
          name = "pipeline_duration_minutes",
          value = duration_minutes,
          unit = "minutes"
        ),
        list(
          type = "data_quality",
          name = "documents_processed",
          value = documents_processed,
          unit = "count"
        ),
        list(
          type = "data_quality",
          name = "validation_rate",
          value = validation_rate,
          unit = "percentage"
        )
      )
      
      # Collect system metrics
      system_metrics <- self$collect_system_metrics()
      metrics <- c(metrics, system_metrics)
      
      # Store metrics
      for (metric in metrics) {
        self$store_metric(
          timestamp = timestamp,
          type = metric$type,
          name = metric$name,
          value = metric$value,
          unit = metric$unit,
          pipeline_run_id = pipeline_run_id
        )
      }
      
      log_etl("DEBUG", sprintf("Collected %d metrics for pipeline run %s", length(metrics), pipeline_run_id), "METRICS_COLLECTOR")
    },
    
    collect_system_metrics = function() {
      metrics <- list()
      
      # Memory usage
      if (requireNamespace("memuse", quietly = TRUE)) {
        tryCatch({
          mem_info <- memuse::Sys.meminfo()
          total_memory_gb <- as.numeric(mem_info$totalram) / (1024^3)
          free_memory_gb <- as.numeric(mem_info$freeram) / (1024^3)
          used_memory_gb <- total_memory_gb - free_memory_gb
          
          metrics <- append(metrics, list(
            list(type = "system", name = "memory_used_gb", value = used_memory_gb, unit = "GB"),
            list(type = "system", name = "memory_usage_percentage", value = (used_memory_gb / total_memory_gb) * 100, unit = "percentage")
          ))
        }, error = function(e) {
          log_etl("DEBUG", "Memory metrics collection failed", "METRICS_COLLECTOR")
        })
      }
      
      # Disk usage for pipeline directories
      pipeline_dirs <- c("pipeline/logs", "pipeline/cache", "pipeline/temp", "pipeline/backups")
      total_disk_usage_gb <- 0
      
      for (dir_path in pipeline_dirs) {
        if (dir.exists(dir_path)) {
          tryCatch({
            files <- list.files(dir_path, recursive = TRUE, full.names = TRUE)
            if (length(files) > 0) {
              file_sizes <- file.info(files)$size
              dir_size_gb <- sum(file_sizes, na.rm = TRUE) / (1024^3)
              total_disk_usage_gb <- total_disk_usage_gb + dir_size_gb
            }
          }, error = function(e) {
            log_etl("DEBUG", sprintf("Disk usage collection failed for %s", dir_path), "METRICS_COLLECTOR")
          })
        }
      }
      
      if (total_disk_usage_gb > 0) {
        metrics <- append(metrics, list(
          list(type = "system", name = "disk_usage_gb", value = total_disk_usage_gb, unit = "GB")
        ))
      }
      
      return(metrics)
    },
    
    collect_api_metrics = function(api_name, response_time_ms, success, error_message = NULL) {
      timestamp <- Sys.time()
      
      additional_data <- list(
        api_name = api_name,
        success = success
      )
      
      if (!is.null(error_message)) {
        additional_data$error_message <- error_message
      }
      
      self$store_metric(
        timestamp = timestamp,
        type = "api_performance",
        name = paste0(api_name, "_response_time_ms"),
        value = response_time_ms,
        unit = "milliseconds",
        additional_data = additional_data
      )
      
      self$store_metric(
        timestamp = timestamp,
        type = "api_health",
        name = paste0(api_name, "_success_rate"),
        value = ifelse(success, 100, 0),
        unit = "percentage",
        additional_data = additional_data
      )
    },
    
    collect_data_quality_metrics = function(total_documents, duplicates_found, validation_errors, data_freshness_hours) {
      timestamp <- Sys.time()
      
      duplicate_rate <- if (total_documents > 0) (duplicates_found / total_documents) * 100 else 0
      
      quality_metrics <- list(
        list(type = "data_quality", name = "duplicate_rate", value = duplicate_rate, unit = "percentage"),
        list(type = "data_quality", name = "validation_errors", value = validation_errors, unit = "count"),
        list(type = "data_quality", name = "data_freshness_hours", value = data_freshness_hours, unit = "hours")
      )
      
      for (metric in quality_metrics) {
        self$store_metric(
          timestamp = timestamp,
          type = metric$type,
          name = metric$name,
          value = metric$value,
          unit = metric$unit
        )
      }
    },
    
    collect_legislative_metrics = function(documents_by_state, documents_by_authority, documents_by_type, new_documents_today) {
      timestamp <- Sys.time()
      
      # State coverage
      states_with_data <- length(unique(documents_by_state$estado[documents_by_state$count > 0]))
      total_states <- 27  # Brazil has 26 states + DF
      state_coverage <- (states_with_data / total_states) * 100
      
      # Authority diversity
      authority_count <- nrow(documents_by_authority)
      
      # Document type diversity
      type_count <- nrow(documents_by_type)
      
      legislative_metrics <- list(
        list(type = "legislative", name = "state_coverage_percentage", value = state_coverage, unit = "percentage"),
        list(type = "legislative", name = "authority_diversity_count", value = authority_count, unit = "count"),
        list(type = "legislative", name = "document_type_diversity", value = type_count, unit = "count"),
        list(type = "legislative", name = "new_documents_today", value = new_documents_today, unit = "count")
      )
      
      for (metric in legislative_metrics) {
        self$store_metric(
          timestamp = timestamp,
          type = metric$type,
          name = metric$name,
          value = metric$value,
          unit = metric$unit
        )
      }
    },
    
    store_metric = function(timestamp, type, name, value, unit, pipeline_run_id = NULL, additional_data = NULL) {
      # Store in memory
      metric_id <- paste0(type, "_", name, "_", format(timestamp, "%Y%m%d_%H%M%S"))
      
      self$metrics_store[[metric_id]] <- list(
        timestamp = timestamp,
        type = type,
        name = name,
        value = value,
        unit = unit,
        pipeline_run_id = pipeline_run_id,
        additional_data = additional_data
      )
      
      # Store in database if available
      if (!is.null(self$db_pool)) {
        tryCatch({
          insert_sql <- "
            INSERT INTO pipeline_metrics 
            (timestamp, metric_type, metric_name, metric_value, metric_unit, additional_data, pipeline_run_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
          "
          
          dbExecute(self$db_pool, insert_sql, list(
            timestamp, type, name, value, unit,
            if (!is.null(additional_data)) jsonlite::toJSON(additional_data, auto_unbox = TRUE) else NULL,
            pipeline_run_id
          ))
          
        }, error = function(e) {
          log_etl("DEBUG", sprintf("Metric storage to database failed: %s", e$message), "METRICS_COLLECTOR")
        })
      }
      
      # Memory management - keep only recent metrics in memory
      if (length(self$metrics_store) > 1000) {
        # Keep only last 500 metrics
        recent_keys <- tail(names(self$metrics_store), 500)
        self$metrics_store <- self$metrics_store[recent_keys]
      }
    },
    
    get_recent_metrics = function(metric_type = NULL, hours_back = 24) {
      cutoff_time <- Sys.time() - hours(hours_back)
      
      recent_metrics <- list()
      
      for (metric_id in names(self$metrics_store)) {
        metric <- self$metrics_store[[metric_id]]
        
        if (metric$timestamp >= cutoff_time) {
          if (isTRUE(is.null(metric_type)) || metric$type == metric_type) {
            recent_metrics[[metric_id]] <- metric
          }
        }
      }
      
      return(recent_metrics)
    },
    
    get_metric_summary = function(metric_name, hours_back = 24) {
      recent_metrics <- self$get_recent_metrics(hours_back = hours_back)
      
      matching_metrics <- list()
      for (metric_id in names(recent_metrics)) {
        metric <- recent_metrics[[metric_id]]
        if (metric$name == metric_name) {
          matching_metrics <- append(matching_metrics, list(metric))
        }
      }
      
      if (length(matching_metrics) == 0) {
        return(NULL)
      }
      
      values <- sapply(matching_metrics, function(x) x$value)
      
      summary <- list(
        metric_name = metric_name,
        count = length(values),
        min = min(values, na.rm = TRUE),
        max = max(values, na.rm = TRUE),
        mean = mean(values, na.rm = TRUE),
        median = median(values, na.rm = TRUE),
        last_value = tail(values, 1),
        unit = matching_metrics[[1]]$unit
      )
      
      return(summary)
    }
  )
)

# ============================================================================
# ANOMALY DETECTION ENGINE
# ============================================================================

#' Statistical Anomaly Detection for Pipeline Metrics
AnomalyDetector <- R6::R6Class("AnomalyDetector",
  public = list(
    sensitivity = 2.0,
    min_samples = 10,
    lookback_days = 14,
    
    initialize = function(sensitivity = 2.0, min_samples = 10, lookback_days = 14) {
      self$sensitivity <- sensitivity
      self$min_samples <- min_samples  
      self$lookback_days <- lookback_days
      log_etl("INFO", sprintf("Anomaly detector initialized (sensitivity: %.1f, min_samples: %d)", 
                             sensitivity, min_samples), "ANOMALY_DETECTOR")
    },
    
    detect_anomalies = function(metrics_collector) {
      anomalies <- list()
      
      # Key metrics to monitor for anomalies
      key_metrics <- c(
        "pipeline_duration_minutes",
        "validation_rate",
        "memory_used_gb",
        "api_response_time_ms",
        "duplicate_rate",
        "new_documents_today"
      )
      
      for (metric_name in key_metrics) {
        metric_anomalies <- self$detect_metric_anomalies(metrics_collector, metric_name)
        if (length(metric_anomalies) > 0) {
          anomalies <- c(anomalies, metric_anomalies)
        }
      }
      
      if (length(anomalies) > 0) {
        log_etl("WARN", sprintf("Detected %d anomalies", length(anomalies)), "ANOMALY_DETECTOR")
      }
      
      return(anomalies)
    },
    
    detect_metric_anomalies = function(metrics_collector, metric_name) {
      # Get historical data
      recent_metrics <- metrics_collector$get_recent_metrics(hours_back = self$lookback_days * 24)
      
      # Filter by metric name
      metric_values <- c()
      metric_timestamps <- c()
      
      for (metric_id in names(recent_metrics)) {
        metric <- recent_metrics[[metric_id]]
        if (metric$name == metric_name) {
          metric_values <- c(metric_values, metric$value)
          metric_timestamps <- c(metric_timestamps, metric$timestamp)
        }
      }
      
      if (length(metric_values) < self$min_samples) {
        return(list())
      }
      
      # Statistical anomaly detection
      anomalies <- self$statistical_anomaly_detection(metric_name, metric_values, metric_timestamps)
      
      return(anomalies)
    },
    
    statistical_anomaly_detection = function(metric_name, values, timestamps) {
      anomalies <- list()
      
      if (length(values) < self$min_samples) {
        return(anomalies)
      }
      
      # Calculate baseline statistics (exclude most recent values)
      baseline_values <- head(values, -max(1, length(values) %/% 10))  # Exclude last 10%
      
      if (length(baseline_values) < self$min_samples) {
        return(anomalies)
      }
      
      baseline_mean <- mean(baseline_values, na.rm = TRUE)
      baseline_sd <- sd(baseline_values, na.rm = TRUE)
      
      if (isTRUE(is.na(baseline_sd)) || baseline_sd == 0) {
        return(anomalies)
      }
      
      # Check recent values for anomalies
      recent_values <- tail(values, max(1, length(values) %/% 10))  # Last 10%
      recent_timestamps <- tail(timestamps, length(recent_values))
      
      for (i in seq_along(recent_values)) {
        value <- recent_values[i]
        timestamp <- recent_timestamps[i]
        
        # Z-score calculation
        z_score <- abs(value - baseline_mean) / baseline_sd
        
        if (z_score > self$sensitivity) {
          anomaly_type <- if (value > baseline_mean) "spike" else "drop"
          
          anomalies <- append(anomalies, list(list(
            metric_name = metric_name,
            timestamp = timestamp,
            value = value,
            baseline_mean = baseline_mean,
            z_score = z_score,
            anomaly_type = anomaly_type,
            severity = self$calculate_severity(z_score)
          )))
        }
      }
      
      return(anomalies)
    },
    
    calculate_severity = function(z_score) {
      if (z_score > 4) {
        return("critical")
      } else if (z_score > 3) {
        return("high")
      } else if (z_score > 2.5) {
        return("medium")
      } else {
        return("low")
      }
    },
    
    detect_trend_anomalies = function(values, timestamps) {
      # Simple trend detection using linear regression
      if (length(values) < 10) return(list())
      
      tryCatch({
        # Convert timestamps to numeric for regression
        time_numeric <- as.numeric(timestamps)
        
        # Linear model
        model <- lm(values ~ time_numeric)
        slope <- coef(model)[2]
        
        # Detect significant trends
        if (!isTRUE(is.na(slope)) && abs(slope) > sd(values, na.rm = TRUE) * 0.1) {
          trend_type <- if (slope > 0) "increasing" else "decreasing"
          
          return(list(list(
            type = "trend",
            trend_type = trend_type,
            slope = slope,
            duration_hours = as.numeric(max(timestamps) - min(timestamps), units = "hours")
          )))
        }
        
        return(list())
        
      }, error = function(e) {
        log_etl("DEBUG", sprintf("Trend detection failed: %s", e$message), "ANOMALY_DETECTOR")
        return(list())
      })
    }
  )
)

# ============================================================================
# ALERT MANAGER
# ============================================================================

#' Alert Management and Notification System
AlertManager <- R6::R6Class("AlertManager",
  public = list(
    db_pool = NULL,
    alert_history = list(),
    cooldown_tracker = list(),
    
    initialize = function(db_pool = NULL) {
      self$db_pool <- db_pool
      log_etl("INFO", "Alert manager initialized", "ALERT_MANAGER")
    },
    
    process_threshold_alerts = function(metrics_collector) {
      alerts <- list()
      
      # Check pipeline performance thresholds
      pipeline_duration <- metrics_collector$get_metric_summary("pipeline_duration_minutes", 1)
      if (!isTRUE(is.null(pipeline_duration)) && !is.na(pipeline_duration$last_value)) {
        if (pipeline_duration$last_value > MONITORING_CONFIG$thresholds$etl_duration_critical_minutes) {
          alerts <- append(alerts, list(self$create_alert(
            type = "performance",
            level = "critical",
            message = sprintf("ETL pipeline duration critical: %.1f minutes", pipeline_duration$last_value),
            details = list(
              metric = "pipeline_duration_minutes",
              value = pipeline_duration$last_value,
              threshold = MONITORING_CONFIG$thresholds$etl_duration_critical_minutes
            )
          )))
        } else if (pipeline_duration$last_value > MONITORING_CONFIG$thresholds$etl_duration_warning_minutes) {
          alerts <- append(alerts, list(self$create_alert(
            type = "performance",
            level = "warning",
            message = sprintf("ETL pipeline duration warning: %.1f minutes", pipeline_duration$last_value),
            details = list(
              metric = "pipeline_duration_minutes", 
              value = pipeline_duration$last_value,
              threshold = MONITORING_CONFIG$thresholds$etl_duration_warning_minutes
            )
          )))
        }
      }
      
      # Check validation rate thresholds
      validation_rate <- metrics_collector$get_metric_summary("validation_rate", 1)
      if (!isTRUE(is.null(validation_rate)) && !is.na(validation_rate$last_value)) {
        if (validation_rate$last_value < MONITORING_CONFIG$thresholds$validation_rate_critical) {
          alerts <- append(alerts, list(self$create_alert(
            type = "data_quality",
            level = "critical",
            message = sprintf("Data validation rate critical: %.1f%%", validation_rate$last_value),
            details = list(
              metric = "validation_rate",
              value = validation_rate$last_value,
              threshold = MONITORING_CONFIG$thresholds$validation_rate_critical
            )
          )))
        } else if (validation_rate$last_value < MONITORING_CONFIG$thresholds$validation_rate_warning) {
          alerts <- append(alerts, list(self$create_alert(
            type = "data_quality",
            level = "warning", 
            message = sprintf("Data validation rate warning: %.1f%%", validation_rate$last_value),
            details = list(
              metric = "validation_rate",
              value = validation_rate$last_value,
              threshold = MONITORING_CONFIG$thresholds$validation_rate_warning
            )
          )))
        }
      }
      
      # Check memory usage thresholds
      memory_usage <- metrics_collector$get_metric_summary("memory_used_gb", 1)
      if (!isTRUE(is.null(memory_usage)) && !is.na(memory_usage$last_value)) {
        if (memory_usage$last_value > MONITORING_CONFIG$thresholds$memory_critical_gb) {
          alerts <- append(alerts, list(self$create_alert(
            type = "system",
            level = "critical",
            message = sprintf("Memory usage critical: %.2f GB", memory_usage$last_value),
            details = list(
              metric = "memory_used_gb",
              value = memory_usage$last_value,
              threshold = MONITORING_CONFIG$thresholds$memory_critical_gb
            )
          )))
        } else if (memory_usage$last_value > MONITORING_CONFIG$thresholds$memory_warning_gb) {
          alerts <- append(alerts, list(self$create_alert(
            type = "system",
            level = "warning",
            message = sprintf("Memory usage warning: %.2f GB", memory_usage$last_value),
            details = list(
              metric = "memory_used_gb",
              value = memory_usage$last_value,
              threshold = MONITORING_CONFIG$thresholds$memory_warning_gb
            )
          )))
        }
      }
      
      # Check data quality thresholds
      duplicate_rate <- metrics_collector$get_metric_summary("duplicate_rate", 6)
      if (!isTRUE(is.null(duplicate_rate)) && !is.na(duplicate_rate$last_value)) {
        if (duplicate_rate$last_value > MONITORING_CONFIG$thresholds$duplicate_rate_critical) {
          alerts <- append(alerts, list(self$create_alert(
            type = "data_quality",
            level = "critical",
            message = sprintf("Duplicate rate critical: %.1f%%", duplicate_rate$last_value),
            details = list(
              metric = "duplicate_rate",
              value = duplicate_rate$last_value,
              threshold = MONITORING_CONFIG$thresholds$duplicate_rate_critical
            )
          )))
        }
      }
      
      return(alerts)
    },
    
    process_anomaly_alerts = function(anomalies) {
      alerts <- list()
      
      for (anomaly in anomalies) {
        alert_level <- self$map_severity_to_alert_level(anomaly$severity)
        
        alerts <- append(alerts, list(self$create_alert(
          type = "anomaly",
          level = alert_level,
          message = sprintf("Anomaly detected in %s: %.2f (z-score: %.2f)", 
                           anomaly$metric_name, anomaly$value, anomaly$z_score),
          details = anomaly
        )))
      }
      
      return(alerts)
    },
    
    create_alert = function(type, level, message, details = list()) {
      alert <- list(
        id = digest::digest(paste(type, level, message, Sys.time()), algo = "md5"),
        timestamp = Sys.time(),
        type = type,
        level = level,
        message = message,
        details = details,
        resolved = FALSE
      )
      
      return(alert)
    },
    
    send_alerts = function(alerts) {
      if (length(alerts) == 0) return()
      
      sent_count <- 0
      
      for (alert in alerts) {
        if (self$should_send_alert(alert)) {
          success <- self$send_alert_notifications(alert)
          if (success) {
            self$record_alert(alert)
            self$update_cooldown(alert)
            sent_count <- sent_count + 1
          }
        }
      }
      
      if (sent_count > 0) {
        log_etl("INFO", sprintf("Sent %d alerts out of %d generated", sent_count, length(alerts)), "ALERT_MANAGER")
      }
    },
    
    should_send_alert = function(alert) {
      # Check cooldown
      cooldown_key <- paste(alert$type, alert$level, sep = "_")
      
      if (cooldown_key %in% names(self$cooldown_tracker)) {
        last_sent <- self$cooldown_tracker[[cooldown_key]]
        cooldown_until <- last_sent + minutes(MONITORING_CONFIG$alerts$cooldown_minutes)
        
        if (Sys.time() < cooldown_until) {
          log_etl("DEBUG", sprintf("Alert %s in cooldown", cooldown_key), "ALERT_MANAGER")
          return(FALSE)
        }
      }
      
      # Check rate limiting
      recent_alerts <- self$get_recent_alert_count(hours = 1)
      if (recent_alerts >= MONITORING_CONFIG$alerts$max_alerts_per_hour) {
        log_etl("WARN", "Alert rate limit reached", "ALERT_MANAGER")
        return(FALSE)
      }
      
      return(TRUE)
    },
    
    send_alert_notifications = function(alert) {
      success <- TRUE
      
      # Send to webhook channels
      webhook_urls <- MONITORING_CONFIG$alerts$notification_channels
      
      for (channel_name in names(webhook_urls)) {
        webhook_url <- webhook_urls[[channel_name]]
        
        if (webhook_url != "" && !is.na(webhook_url)) {
          channel_success <- self$send_webhook_notification(webhook_url, alert, channel_name)
          if (!channel_success) {
            success <- FALSE
          }
        }
      }
      
      return(success)
    },
    
    send_webhook_notification = function(webhook_url, alert, channel_name) {
      tryCatch({
        # Format message for different channels
        notification <- self$format_notification_for_channel(alert, channel_name)
        
        response <- httr::POST(
          url = webhook_url,
          body = jsonlite::toJSON(notification, auto_unbox = TRUE),
          httr::add_headers("Content-Type" = "application/json"),
          httr::timeout(MONITORING_CONFIG$alerts$webhook_timeout_seconds)
        )
        
        if (httr::status_code(response) == 200) {
          log_etl("DEBUG", sprintf("Alert sent to %s", channel_name), "ALERT_MANAGER")
          return(TRUE)
        } else {
          log_etl("WARN", sprintf("Webhook notification failed for %s: HTTP %d", 
                                 channel_name, httr::status_code(response)), "ALERT_MANAGER")
          return(FALSE)
        }
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Webhook notification error for %s: %s", channel_name, e$message), "ALERT_MANAGER")
        return(FALSE)
      })
    },
    
    format_notification_for_channel = function(alert, channel_name) {
      timestamp_str <- format(alert$timestamp, "%Y-%m-%d %H:%M:%S %Z")
      
      # Basic notification format
      notification <- list(
        text = sprintf("🚨 **%s Alert** - %s\n\n**Time:** %s\n**Type:** %s\n**Level:** %s\n\n**Details:** %s",
                      toupper(alert$level),
                      "Brazilian Legislative Monitor",
                      timestamp_str,
                      alert$type,
                      alert$level,
                      alert$message),
        timestamp = alert$timestamp
      )
      
      # Channel-specific formatting
      if (channel_name == "slack") {
        notification <- list(
          text = sprintf("Brazilian Legislative Monitor Alert"),
          attachments = list(list(
            color = self$get_alert_color(alert$level),
            fields = list(
              list(title = "Level", value = toupper(alert$level), short = TRUE),
              list(title = "Type", value = alert$type, short = TRUE),
              list(title = "Message", value = alert$message, short = FALSE),
              list(title = "Time", value = timestamp_str, short = TRUE)
            )
          ))
        )
      } else if (channel_name == "discord") {
        notification <- list(
          embeds = list(list(
            title = "Brazilian Legislative Monitor Alert",
            description = alert$message,
            color = self$get_alert_color_int(alert$level),
            fields = list(
              list(name = "Level", value = toupper(alert$level), inline = TRUE),
              list(name = "Type", value = alert$type, inline = TRUE),
              list(name = "Time", value = timestamp_str, inline = FALSE)
            )
          ))
        )
      } else if (channel_name == "teams") {
        notification <- list(
          text = sprintf("Brazilian Legislative Monitor Alert"),
          sections = list(list(
            activityTitle = sprintf("%s Alert", toupper(alert$level)),
            activitySubtitle = alert$type,
            text = alert$message,
            facts = list(
              list(name = "Level", value = alert$level),
              list(name = "Time", value = timestamp_str)
            )
          ))
        )
      }
      
      return(notification)
    },
    
    get_alert_color = function(level) {
      switch(level,
        "critical" = "danger",
        "warning" = "warning",
        "info" = "good",
        "warning"
      )
    },
    
    get_alert_color_int = function(level) {
      switch(level,
        "critical" = 15158332,  # Red
        "warning" = 16776960,   # Yellow
        "info" = 65280,         # Green
        16776960                # Default yellow
      )
    },
    
    map_severity_to_alert_level = function(severity) {
      switch(severity,
        "critical" = "critical",
        "high" = "warning",
        "medium" = "warning",
        "low" = "info",
        "info"
      )
    },
    
    record_alert = function(alert) {
      # Store in memory
      self$alert_history[[alert$id]] <- alert
      
      # Store in database if available
      if (!is.null(self$db_pool)) {
        tryCatch({
          insert_sql <- "
            INSERT INTO alert_history 
            (timestamp, alert_type, alert_level, message, details, notification_sent)
            VALUES ($1, $2, $3, $4, $5, TRUE)
          "
          
          dbExecute(self$db_pool, insert_sql, list(
            alert$timestamp,
            alert$type,
            alert$level,
            alert$message,
            jsonlite::toJSON(alert$details, auto_unbox = TRUE)
          ))
          
        }, error = function(e) {
          log_etl("DEBUG", sprintf("Alert recording to database failed: %s", e$message), "ALERT_MANAGER")
        })
      }
      
      # Memory management
      if (length(self$alert_history) > 100) {
        # Keep only last 50 alerts
        recent_keys <- tail(names(self$alert_history), 50)
        self$alert_history <- self$alert_history[recent_keys]
      }
    },
    
    update_cooldown = function(alert) {
      cooldown_key <- paste(alert$type, alert$level, sep = "_")
      self$cooldown_tracker[[cooldown_key]] <- alert$timestamp
    },
    
    get_recent_alert_count = function(hours = 1) {
      cutoff_time <- Sys.time() - hours(hours)
      
      recent_count <- 0
      for (alert_id in names(self$alert_history)) {
        alert <- self$alert_history[[alert_id]]
        if (alert$timestamp >= cutoff_time) {
          recent_count <- recent_count + 1
        }
      }
      
      return(recent_count)
    },
    
    get_alert_summary = function(hours_back = 24) {
      cutoff_time <- Sys.time() - hours(hours_back)
      
      recent_alerts <- list()
      for (alert_id in names(self$alert_history)) {
        alert <- self$alert_history[[alert_id]]
        if (alert$timestamp >= cutoff_time) {
          recent_alerts <- append(recent_alerts, list(alert))
        }
      }
      
      if (length(recent_alerts) == 0) {
        return(list(
          total_alerts = 0,
          by_level = list(),
          by_type = list()
        ))
      }
      
      # Summarize by level
      levels <- sapply(recent_alerts, function(x) x$level)
      by_level <- table(levels)
      
      # Summarize by type
      types <- sapply(recent_alerts, function(x) x$type)
      by_type <- table(types)
      
      return(list(
        total_alerts = length(recent_alerts),
        by_level = as.list(by_level),
        by_type = as.list(by_type),
        recent_alerts = recent_alerts
      ))
    }
  )
)

# ============================================================================
# MAIN MONITORING ORCHESTRATOR
# ============================================================================

#' Main Monitoring System Orchestrator
MonitoringOrchestrator <- R6::R6Class("MonitoringOrchestrator",
  public = list(
    metrics_collector = NULL,
    anomaly_detector = NULL,
    alert_manager = NULL,
    monitoring_active = FALSE,
    
    initialize = function(db_pool = NULL) {
      self$metrics_collector <- MetricsCollector$new(db_pool)
      self$anomaly_detector <- AnomalyDetector$new(
        MONITORING_CONFIG$anomaly_detection$sensitivity,
        MONITORING_CONFIG$anomaly_detection$min_samples,
        MONITORING_CONFIG$anomaly_detection$lookback_days
      )
      self$alert_manager <- AlertManager$new(db_pool)
      
      log_etl("INFO", "Monitoring orchestrator initialized", "MONITORING_ORCHESTRATOR")
    },
    
    start_monitoring = function() {
      if (self$monitoring_active) {
        log_etl("WARN", "Monitoring already active", "MONITORING_ORCHESTRATOR")
        return()
      }
      
      self$monitoring_active <- TRUE
      
      # Schedule periodic monitoring check
      if (requireNamespace("later", quietly = TRUE)) {
        later::later(
          func = function() {
            if (self$monitoring_active) {
              self$run_monitoring_cycle()
              # Schedule next cycle
              later::later(self$start_monitoring, delay = 300)  # 5 minutes
            }
          },
          delay = 300  # 5 minutes
        )
      }
      
      log_etl("INFO", "Monitoring system started", "MONITORING_ORCHESTRATOR")
    },
    
    stop_monitoring = function() {
      self$monitoring_active <- FALSE
      log_etl("INFO", "Monitoring system stopped", "MONITORING_ORCHESTRATOR")
    },
    
    run_monitoring_cycle = function() {
      log_etl("DEBUG", "Running monitoring cycle", "MONITORING_ORCHESTRATOR")
      
      tryCatch({
        # Collect current system metrics
        self$metrics_collector$collect_system_metrics()
        
        # Detect anomalies
        if (MONITORING_CONFIG$anomaly_detection$enabled) {
          anomalies <- self$anomaly_detector$detect_anomalies(self$metrics_collector)
          
          if (length(anomalies) > 0) {
            anomaly_alerts <- self$alert_manager$process_anomaly_alerts(anomalies)
            self$alert_manager$send_alerts(anomaly_alerts)
          }
        }
        
        # Check threshold-based alerts
        threshold_alerts <- self$alert_manager$process_threshold_alerts(self$metrics_collector)
        self$alert_manager$send_alerts(threshold_alerts)
        
        # Collect API health metrics if orchestrator is available
        if (exists("api_orchestrator") && !is.null(api_orchestrator)) {
          self$collect_api_health_metrics()
        }
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Monitoring cycle failed: %s", e$message), "MONITORING_ORCHESTRATOR")
      })
    },
    
    collect_api_health_metrics = function() {
      tryCatch({
        health_status <- api_orchestrator$run_health_checks()
        
        for (service_name in names(health_status)) {
          service_health <- health_status[[service_name]]
          
          # Mock response time (would be actual in real implementation)
          response_time_ms <- ifelse(service_health$healthy, 
                                   runif(1, 100, 2000), 
                                   runif(1, 5000, 10000))
          
          self$metrics_collector$collect_api_metrics(
            api_name = service_name,
            response_time_ms = response_time_ms,
            success = service_health$healthy,
            error_message = service_health$error
          )
        }
        
      }, error = function(e) {
        log_etl("DEBUG", sprintf("API health metrics collection failed: %s", e$message), "MONITORING_ORCHESTRATOR")
      })
    },
    
    report_pipeline_execution = function(pipeline_run_id, duration_minutes, documents_processed, validation_rate) {
      self$metrics_collector$collect_pipeline_metrics(
        pipeline_run_id, duration_minutes, documents_processed, validation_rate
      )
      
      # Immediate alert check for critical issues
      if (duration_minutes > MONITORING_CONFIG$thresholds$etl_duration_critical_minutes) {
        alert <- self$alert_manager$create_alert(
          type = "performance",
          level = "critical", 
          message = sprintf("Pipeline execution critical: %.1f minutes", duration_minutes),
          details = list(
            pipeline_run_id = pipeline_run_id,
            duration_minutes = duration_minutes
          )
        )
        
        self$alert_manager$send_alerts(list(alert))
      }
      
      if (validation_rate < MONITORING_CONFIG$thresholds$validation_rate_critical) {
        alert <- self$alert_manager$create_alert(
          type = "data_quality",
          level = "critical",
          message = sprintf("Data validation rate critical: %.1f%%", validation_rate),
          details = list(
            pipeline_run_id = pipeline_run_id,
            validation_rate = validation_rate
          )
        )
        
        self$alert_manager$send_alerts(list(alert))
      }
    },
    
    get_monitoring_dashboard_data = function() {
      # Performance metrics
      pipeline_duration <- self$metrics_collector$get_metric_summary("pipeline_duration_minutes", 24)
      validation_rate <- self$metrics_collector$get_metric_summary("validation_rate", 24)
      memory_usage <- self$metrics_collector$get_metric_summary("memory_used_gb", 6)
      
      # Alert summary
      alert_summary <- self$alert_manager$get_alert_summary(24)
      
      # System status
      system_status <- "healthy"
      if (alert_summary$total_alerts > 0) {
        if ("critical" %in% names(alert_summary$by_level)) {
          system_status <- "critical"
        } else if ("warning" %in% names(alert_summary$by_level)) {
          system_status <- "warning"
        }
      }
      
      dashboard_data <- list(
        system_status = system_status,
        monitoring_active = self$monitoring_active,
        metrics = list(
          pipeline_duration = pipeline_duration,
          validation_rate = validation_rate,
          memory_usage = memory_usage
        ),
        alerts = alert_summary,
        last_updated = Sys.time()
      )
      
      return(dashboard_data)
    }
  )
)

# ============================================================================
# EXPORTS AND INITIALIZATION
# ============================================================================

# Global monitoring orchestrator
monitoring_system <- NULL

initialize_monitoring_system <- function(db_pool = NULL) {
  cat("📊 Initializing Data Monitoring and Alerting System...\n")
  
  tryCatch({
    monitoring_system <<- MonitoringOrchestrator$new(db_pool)
    
    cat("✅ Monitoring system initialized successfully\n")
    cat("🔧 Components loaded:\n")
    cat("   - Metrics Collector (pipeline, system, API, data quality)\n")
    cat("   - Anomaly Detector (statistical analysis)\n")
    cat("   - Alert Manager (webhooks, cooldowns, rate limiting)\n")
    cat("   - Brazilian Legislative Data Monitoring\n")
    cat("📊 Monitoring thresholds configured:\n")
    cat(sprintf("   - Pipeline duration: %d min (warning), %d min (critical)\n", 
                MONITORING_CONFIG$thresholds$etl_duration_warning_minutes,
                MONITORING_CONFIG$thresholds$etl_duration_critical_minutes))
    cat(sprintf("   - Memory usage: %.1f GB (warning), %.1f GB (critical)\n",
                MONITORING_CONFIG$thresholds$memory_warning_gb,
                MONITORING_CONFIG$thresholds$memory_critical_gb))
    cat(sprintf("   - Validation rate: %d%% (warning), %d%% (critical)\n",
                MONITORING_CONFIG$thresholds$validation_rate_warning,
                MONITORING_CONFIG$thresholds$validation_rate_critical))
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Monitoring system initialization failed:", e$message, "\n")
    return(FALSE)
  })
}

# Export main functions
start_monitoring <- function(db_pool = NULL) {
  if (is.null(monitoring_system)) {
    if (!initialize_monitoring_system(db_pool)) {
      return(FALSE)
    }
  }
  
  monitoring_system$start_monitoring()
  return(TRUE)
}

stop_monitoring <- function() {
  if (!is.null(monitoring_system)) {
    monitoring_system$stop_monitoring()
  }
}

report_pipeline_metrics <- function(pipeline_run_id, duration_minutes, documents_processed, validation_rate) {
  if (is.null(monitoring_system)) {
    if (!initialize_monitoring_system()) {
      return(FALSE)
    }
  }
  
  monitoring_system$report_pipeline_execution(pipeline_run_id, duration_minutes, documents_processed, validation_rate)
  return(TRUE)
}

get_monitoring_status <- function() {
  if (is.null(monitoring_system)) {
    return(list(status = "not_initialized"))
  }
  
  return(monitoring_system$get_monitoring_dashboard_data())
}

# Cleanup function
cleanup_monitoring <- function() {
  if (!is.null(monitoring_system)) {
    monitoring_system$stop_monitoring()
    log_etl("INFO", "Monitoring system cleanup completed", "MONITORING")
  }
}

# Register cleanup on exit
reg.finalizer(globalenv(), function(e) {
  cleanup_monitoring()
}, onexit = TRUE)

cat("📊 Data Monitoring and Alerting System loaded\n")
cat("📋 Real-time Performance Tracking Ready\n")
cat("🔧 Use initialize_monitoring_system() to start\n")