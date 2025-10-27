# ============================================================================
# REAL-TIME MONITORING API - SPRINT 7A (API-005)
# ============================================================================
# 
# Real-time monitoring endpoints for Brazilian Legislative Monitoring System
# Provides live legislative activity feeds, change detection, and real-time notifications
#
# Enhanced Features:
# - Real-time legislative activity monitoring
# - Document change detection and notifications
# - Live search trend analysis
# - System health and performance monitoring
# - User activity feeds and engagement tracking
# - Webhook integration for real-time updates
# - LGPD-compliant monitoring with privacy controls
# ============================================================================

cat("📡 Loading Real-Time Monitoring API - Sprint 7A (API-005)\n")

# Load required libraries for real-time monitoring
required_packages <- c("dplyr", "lubridate", "jsonlite", "digest", "stringr")
for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE, quietly = TRUE))
  }
}

# Monitoring configuration
MONITORING_CONFIG <- list(
  real_time = list(
    update_intervals = list(
      legislative_activity = 300, # 5 minutes
      search_trends = 900, # 15 minutes
      system_health = 60, # 1 minute
      user_activity = 600 # 10 minutes
    ),
    retention_periods = list(
      activity_feed = 7, # days
      trends_data = 30, # days
      health_metrics = 3, # days
      change_logs = 90 # days
    )
  ),
  alerts = list(
    thresholds = list(
      high_activity = 100, # documents per hour
      system_load = 0.8, # 80% utilization
      error_rate = 0.05, # 5% error rate
      response_time = 3.0 # 3 seconds
    ),
    notification_channels = c("webhook", "email", "dashboard")
  ),
  privacy = list(
    anonymize_user_data = TRUE,
    aggregate_minimum = 5,
    lgpd_compliant = TRUE
  )
)

# Real-time data simulation (in production would connect to live data sources)
generate_live_activity_feed <- function(limit = 50, since = NULL) {
  current_time <- Sys.time()
  
  # Generate activity events
  activities <- lapply(1:limit, function(i) {
    event_time <- current_time - as.difftime(sample(1:3600, 1), units = "secs") # Last hour
    
    # Filter by 'since' parameter if provided
    if (!isTRUE(is.null(since)) && event_time < as.POSIXct(since)) {
      return(NULL)
    }
    
    event_type <- sample(c("document_added", "document_updated", "search_performed", 
                          "citation_generated", "export_completed"), 1, 
                        prob = c(0.2, 0.15, 0.4, 0.15, 0.1))
    
    activity <- list(
      id = digest(paste(event_time, event_type, i), algo = "md5"),
      timestamp = event_time,
      type = event_type,
      severity = sample(c("info", "low", "medium", "high"), 1, prob = c(0.6, 0.2, 0.15, 0.05))
    )
    
    # Event-specific data
    if (event_type == "document_added") {
      activity$data <- list(
        document_id = paste0("doc_", sample(1000:9999, 1)),
        document_type = sample(c("Lei", "Decreto", "Portaria", "Resolução"), 1),
        state = sample(c("SP", "RJ", "DF", "MG", "RS", "PR", "BA"), 1),
        title = paste("Novo documento:", sample(c("Lei", "Decreto"), 1), "sobre", 
                     sample(c("educação", "saúde", "infraestrutura", "meio ambiente"), 1))
      )
      
    } else if (event_type == "document_updated") {
      activity$data <- list(
        document_id = paste0("doc_", sample(1000:9999, 1)),
        changes = sample(c("metadata", "content", "classification"), 1),
        updated_fields = sample(c("title", "summary", "subjects", "url"), sample(1:3, 1))
      )
      
    } else if (event_type == "search_performed") {
      activity$data <- list(
        query = sample(c("lei", "decreto", "educação", "saúde", "direito constitucional"), 1),
        results_count = sample(10:500, 1),
        processing_time = round(runif(1, 0.1, 2.0), 3),
        user_type = sample(c("academic", "government", "public", "commercial"), 1, 
                          prob = c(0.4, 0.3, 0.2, 0.1))
      )
      
    } else if (event_type == "citation_generated") {
      activity$data <- list(
        document_id = paste0("doc_", sample(1000:9999, 1)),
        citation_format = sample(c("abnt", "apa", "chicago", "mla"), 1, prob = c(0.6, 0.2, 0.1, 0.1)),
        bulk_request = runif(1) > 0.8 # 20% are bulk requests
      )
      
    } else if (event_type == "export_completed") {
      activity$data <- list(
        export_format = sample(c("json", "csv", "xml", "excel"), 1),
        records_exported = sample(100:10000, 1),
        processing_time = round(runif(1, 5, 300), 1), # seconds
        file_size_mb = round(runif(1, 1, 50), 2)
      )
    }
    
    return(activity)
  })
  
  # Filter out NULL activities and sort by timestamp
  activities <- activities[!sapply(activities, is.null)]
  activities <- activities[order(sapply(activities, function(x) x$timestamp), decreasing = TRUE)]
  
  return(activities)
}

generate_trend_data <- function(metric_type = "search_trends", timeframe = "1h") {
  current_time <- Sys.time()
  
  if (metric_type == "search_trends") {
    # Generate search trend data
    time_points <- seq(from = current_time - as.difftime(1, units = "hours"),
                      to = current_time,
                      by = "10 min")
    
    trends <- lapply(time_points, function(time_point) {
      list(
        timestamp = time_point,
        top_queries = list(
          "lei" = sample(20:100, 1),
          "decreto" = sample(15:80, 1),
          "direito" = sample(10:60, 1),
          "educação" = sample(8:45, 1),
          "saúde" = sample(5:30, 1)
        ),
        total_searches = sample(200:800, 1),
        unique_users = sample(50:200, 1),
        avg_results_per_search = round(runif(1, 15, 50), 1)
      )
    })
    
  } else if (metric_type == "document_activity") {
    # Generate document activity trends
    time_points <- seq(from = current_time - as.difftime(1, units = "hours"),
                      to = current_time,
                      by = "15 min")
    
    trends <- lapply(time_points, function(time_point) {
      list(
        timestamp = time_point,
        documents_added = sample(0:5, 1),
        documents_updated = sample(0:10, 1),
        documents_accessed = sample(50:300, 1),
        popular_states = list(
          "SP" = sample(20:80, 1),
          "RJ" = sample(15:60, 1),
          "DF" = sample(10:40, 1)
        )
      )
    })
    
  } else if (metric_type == "system_performance") {
    # Generate system performance trends
    time_points <- seq(from = current_time - as.difftime(1, units = "hours"),
                      to = current_time,
                      by = "5 min")
    
    trends <- lapply(time_points, function(time_point) {
      list(
        timestamp = time_point,
        response_time_ms = sample(200:2000, 1),
        requests_per_second = sample(10:100, 1),
        error_rate = round(runif(1, 0.001, 0.05), 4),
        cpu_usage = round(runif(1, 0.2, 0.8), 3),
        memory_usage = round(runif(1, 0.3, 0.7), 3),
        active_users = sample(20:200, 1)
      )
    })
  }
  
  return(trends)
}

# GET /api/v1/monitoring/live-feed - Real-time legislative activity feed
#* @get /api/v1/monitoring/live-feed
#* @param limit:int Maximum number of activities (default: 50, max: 200)
#* @param since:str ISO timestamp to filter activities since (optional)
#* @param activity_types:str[] Filter by activity types
#* @param severity:str Filter by severity level (info, low, medium, high)
#* @param format:str Response format (feed, timeline, compact)
#* @tag monitoring
#* @serializer unboxedJSON
function(limit = 50, since = NULL, activity_types = NULL, severity = NULL, format = "feed") {
  API_STATE$request_count <<- API_STATE$request_count + 1
  start_time <- Sys.time()
  
  # Validate parameters
  limit <- min(max(as.numeric(limit), 1), 200)
  
  # Parse activity types
  if (is.character(activity_types)) {
    activity_types <- strsplit(activity_types, ",")[[1]]
  }
  
  tryCatch({
    # Generate live activity feed
    activities <- generate_live_activity_feed(limit * 2, since) # Get more to allow for filtering
    
    # Apply filters
    if (!isTRUE(is.null(activity_types)) && length(activity_types) > 0) {
      activities <- activities[sapply(activities, function(a) a$type %in% activity_types)]
    }
    
    if (!is.null(severity)) {
      activities <- activities[sapply(activities, function(a) a$severity == severity)]
    }
    
    # Limit results
    if (length(activities) > limit) {
      activities <- activities[1:limit]
    }
    
    # Format response based on requested format
    formatted_response <- switch(format,
      "timeline" = list(
        timeline = lapply(activities, function(activity) {
          list(
            timestamp = activity$timestamp,
            event = paste(activity$type, "-", activity$severity),
            description = switch(activity$type,
              "document_added" = paste("New", activity$data$document_type, "added from", activity$data$state),
              "document_updated" = paste("Document updated:", paste(activity$data$updated_fields, collapse = ", ")),
              "search_performed" = paste("Search:", activity$data$query, "(", activity$data$results_count, "results)"),
              "citation_generated" = paste("Citation generated:", activity$data$citation_format, "format"),
              "export_completed" = paste("Export completed:", activity$data$records_exported, "records"),
              paste("Activity:", activity$type)
            ),
            metadata = activity$data
          )
        })
      ),
      "compact" = list(
        activities = lapply(activities, function(activity) {
          list(
            id = activity$id,
            time = activity$timestamp,
            type = activity$type,
            severity = activity$severity,
            summary = switch(activity$type,
              "document_added" = paste("+", activity$data$document_type),
              "document_updated" = "Updated",
              "search_performed" = paste("Search:", activity$data$results_count),
              "citation_generated" = "Citation",
              "export_completed" = "Export",
              activity$type
            )
          )
        })
      ),
      # Default "feed" format
      list(
        activities = activities,
        activity_summary = list(
          total_activities = length(activities),
          activity_breakdown = as.list(table(sapply(activities, function(a) a$type))),
          severity_breakdown = as.list(table(sapply(activities, function(a) a$severity))),
          time_range = list(
            latest = if (length(activities) > 0) max(sapply(activities, function(a) a$timestamp)) else NULL,
            earliest = if (length(activities) > 0) min(sapply(activities, function(a) a$timestamp)) else NULL
          )
        )
      )
    )
    
    # Add real-time statistics
    real_time_stats <- list(
      current_timestamp = Sys.time(),
      activity_rate_per_hour = length(activities), # Simplified calculation
      system_status = "operational",
      last_update = Sys.time(),
      next_update = Sys.time() + as.difftime(MONITORING_CONFIG$real_time$update_intervals$legislative_activity, units = "secs")
    )
    
    processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    return(success_response(
      data = c(formatted_response, list(real_time_stats = real_time_stats)),
      meta = list(
        limit = limit,
        since_filter = since,
        activity_types_filter = activity_types,
        severity_filter = severity,
        format = format,
        processing_time = round(processing_time, 3),
        data_freshness = "real-time"
      ),
      message = paste("Real-time activity feed:", length(activities), "activities")
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Live feed error:", e$message),
      code = 500
    ))
  })
}

# GET /api/v1/monitoring/trends - Real-time trend analysis
#* @get /api/v1/monitoring/trends
#* @param metric:str Trend metric (search_trends, document_activity, system_performance, user_engagement)
#* @param timeframe:str Analysis timeframe (1h, 6h, 24h, 7d)
#* @param granularity:str Data granularity (1m, 5m, 15m, 1h)
#* @param include_predictions:bool Include trend predictions
#* @tag monitoring
#* @serializer unboxedJSON
function(metric = "search_trends", timeframe = "1h", granularity = "15m", include_predictions = FALSE) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  start_time <- Sys.time()
  
  # Validate parameters
  valid_metrics <- c("search_trends", "document_activity", "system_performance", "user_engagement")
  if (!metric %in% valid_metrics) {
    return(error_response(
      paste("Invalid metric. Valid options:", paste(valid_metrics, collapse = ", ")),
      400
    ))
  }
  
  tryCatch({
    # Generate trend data
    trend_data <- generate_trend_data(metric, timeframe)
    
    # Calculate trend analysis
    trend_analysis <- list()
    
    if (metric == "search_trends") {
      # Analyze search trends
      all_searches <- sapply(trend_data, function(x) x$total_searches)
      trend_analysis <- list(
        average_searches_per_period = round(mean(all_searches), 1),
        peak_searches = max(all_searches),
        trend_direction = if (tail(all_searches, 1) > head(all_searches, 1)) "increasing" else "decreasing",
        popular_queries = {
          # Aggregate top queries across time periods
          all_queries <- list()
          for (period in trend_data) {
            for (query in names(period$top_queries)) {
              if (query %in% names(all_queries)) {
                all_queries[[query]] <- all_queries[[query]] + period$top_queries[[query]]
              } else {
                all_queries[[query]] <- period$top_queries[[query]]
              }
            }
          }
          all_queries[order(-unlist(all_queries))]
        },
        search_velocity = round(mean(sapply(trend_data, function(x) x$total_searches)) / 
                               (as.numeric(timeframe) * 60), 2) # searches per minute
      )
      
    } else if (metric == "document_activity") {
      # Analyze document activity trends
      all_additions <- sapply(trend_data, function(x) x$documents_added)
      all_updates <- sapply(trend_data, function(x) x$documents_updated)
      all_accessed <- sapply(trend_data, function(x) x$documents_accessed)
      
      trend_analysis <- list(
        avg_documents_added = round(mean(all_additions), 1),
        avg_documents_updated = round(mean(all_updates), 1),
        avg_documents_accessed = round(mean(all_accessed), 1),
        activity_score = round(mean(all_additions + all_updates + (all_accessed/10)), 1),
        most_active_states = {
          # Aggregate state activity
          state_activity <- list()
          for (period in trend_data) {
            if (!is.null(period$popular_states)) {
              for (state in names(period$popular_states)) {
                if (state %in% names(state_activity)) {
                  state_activity[[state]] <- state_activity[[state]] + period$popular_states[[state]]
                } else {
                  state_activity[[state]] <- period$popular_states[[state]]
                }
              }
            }
          }
          state_activity[order(-unlist(state_activity))]
        }
      )
      
    } else if (metric == "system_performance") {
      # Analyze system performance trends
      all_response_times <- sapply(trend_data, function(x) x$response_time_ms)
      all_rps <- sapply(trend_data, function(x) x$requests_per_second)
      all_error_rates <- sapply(trend_data, function(x) x$error_rate)
      all_cpu <- sapply(trend_data, function(x) x$cpu_usage)
      
      trend_analysis <- list(
        avg_response_time_ms = round(mean(all_response_times), 1),
        peak_response_time_ms = max(all_response_times),
        avg_requests_per_second = round(mean(all_rps), 1),
        peak_rps = max(all_rps),
        avg_error_rate = round(mean(all_error_rates), 4),
        avg_cpu_usage = round(mean(all_cpu), 3),
        performance_score = round(100 - (mean(all_response_times)/20 + mean(all_error_rates)*1000 + mean(all_cpu)*50), 1),
        alerts = {
          alerts <- list()
          if (mean(all_response_times) > MONITORING_CONFIG$alerts$thresholds$response_time * 1000) {
            alerts <- c(alerts, "High response times detected")
          }
          if (mean(all_error_rates) > MONITORING_CONFIG$alerts$thresholds$error_rate) {
            alerts <- c(alerts, "Elevated error rate")
          }
          if (mean(all_cpu) > MONITORING_CONFIG$alerts$thresholds$system_load) {
            alerts <- c(alerts, "High CPU utilization")
          }
          if (length(alerts) == 0) alerts <- c("All metrics within normal ranges")
          alerts
        }
      )
    }
    
    # Generate predictions if requested
    predictions <- NULL
    if (include_predictions && length(trend_data) > 3) {
      if (metric == "search_trends") {
        recent_searches <- tail(sapply(trend_data, function(x) x$total_searches), 3)
        trend_slope <- (recent_searches[3] - recent_searches[1]) / 2
        
        predictions <- list(
          next_period_searches = round(tail(recent_searches, 1) + trend_slope),
          trend_confidence = if (abs(trend_slope) < 50) "high" else "moderate",
          recommendation = if (trend_slope > 50) "Scale search infrastructure" else "Maintain current capacity"
        )
        
      } else if (metric == "system_performance") {
        recent_response_times <- tail(sapply(trend_data, function(x) x$response_time_ms), 3)
        avg_trend <- mean(diff(recent_response_times))
        
        predictions <- list(
          next_period_response_time = round(tail(recent_response_times, 1) + avg_trend),
          performance_trend = if (avg_trend > 100) "degrading" else if (avg_trend < -100) "improving" else "stable",
          recommendation = if (avg_trend > 200) "Performance optimization needed" else "Performance within acceptable range"
        )
      }
    }
    
    processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    return(success_response(
      data = list(
        trend_data = trend_data,
        trend_analysis = trend_analysis,
        predictions = predictions,
        monitoring_metadata = list(
          metric = metric,
          timeframe = timeframe,
          granularity = granularity,
          data_points = length(trend_data),
          analysis_timestamp = Sys.time(),
          next_update = Sys.time() + as.difftime(MONITORING_CONFIG$real_time$update_intervals[[paste0(metric, "_activity")]] %||% 900, units = "secs")
        )
      ),
      meta = list(
        metric = metric,
        timeframe = timeframe,
        processing_time = round(processing_time, 3),
        predictions_included = include_predictions,
        real_time_data = TRUE
      ),
      message = paste("Real-time trends for", metric, "over", timeframe)
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Trends analysis error:", e$message),
      code = 500
    ))
  })
}

# GET /api/v1/monitoring/health - Real-time system health monitoring
#* @get /api/v1/monitoring/health
#* @param include_details:bool Include detailed component health
#* @param alert_level:str Filter alerts by level (all, warning, critical)
#* @param component:str Focus on specific component (api, database, cache, search)
#* @tag monitoring
#* @serializer unboxedJSON
function(include_details = TRUE, alert_level = "all", component = "all") {
  API_STATE$request_count <<- API_STATE$request_count + 1
  start_time <- Sys.time()
  
  tryCatch({
    current_time <- Sys.time()
    
    # Generate system health metrics
    health_metrics <- list(
      overall_status = "operational",
      last_updated = current_time,
      uptime_percentage = round(runif(1, 99.5, 99.9), 2)
    )
    
    # Component health details
    if (include_details) {
      components <- list(
        api = list(
          status = sample(c("healthy", "warning", "critical"), 1, prob = c(0.8, 0.15, 0.05)),
          response_time_ms = sample(200:2000, 1),
          requests_per_second = sample(10:100, 1),
          error_rate = round(runif(1, 0.001, 0.05), 4),
          last_check = current_time
        ),
        database = list(
          status = sample(c("healthy", "warning"), 1, prob = c(0.9, 0.1)),
          connection_count = sample(5:45, 1),
          query_time_ms = sample(50:500, 1),
          disk_usage_percent = sample(40:80, 1),
          last_check = current_time
        ),
        cache = list(
          status = "healthy",
          hit_rate = round(runif(1, 0.75, 0.95), 3),
          memory_usage_percent = sample(30:70, 1),
          operations_per_second = sample(100:1000, 1),
          last_check = current_time
        ),
        search = list(
          status = sample(c("healthy", "warning"), 1, prob = c(0.85, 0.15)),
          index_size_mb = sample(500:2000, 1),
          search_time_ms = sample(100:1500, 1),
          indexing_rate = "normal",
          last_check = current_time
        )
      )
      
      # Filter by component if specified
      if (component != "all" && component %in% names(components)) {
        filtered_components <- list()
        filtered_components[[component]] <- components[[component]]
        components <- filtered_components
      }
      
      health_metrics$components <- components
      
      # Determine overall status based on components
      component_statuses <- sapply(components, function(x) x$status)
      if (any(component_statuses == "critical")) {
        health_metrics$overall_status <- "critical"
      } else if (any(component_statuses == "warning")) {
        health_metrics$overall_status <- "warning"
      }
    }
    
    # Generate alerts
    alerts <- list()
    
    if (include_details && exists("components")) {
      for (comp_name in names(components)) {
        comp <- components[[comp_name]]
        
        if (comp$status == "warning") {
          alert <- list(
            component = comp_name,
            severity = "warning",
            message = paste(stringr::str_to_title(comp_name), "component showing warning signs"),
            timestamp = current_time,
            details = switch(comp_name,
              "api" = if (comp$response_time_ms > 1500) "High response times" else "Elevated error rate",
              "database" = if (comp$query_time_ms > 300) "Slow queries" else "High connection count",
              "cache" = if (comp$hit_rate < 0.8) "Low hit rate" else "High memory usage",
              "search" = if (comp$search_time_ms > 1000) "Slow search performance" else "Index issues",
              "Component warning"
            )
          )
          alerts <- c(alerts, list(alert))
          
        } else if (comp$status == "critical") {
          alert <- list(
            component = comp_name,
            severity = "critical",
            message = paste(stringr::str_to_title(comp_name), "component critical"),
            timestamp = current_time,
            details = paste("Immediate attention required for", comp_name)
          )
          alerts <- c(alerts, list(alert))
        }
      }
    }
    
    # Add system-level alerts
    if (health_metrics$uptime_percentage < 99.0) {
      alerts <- c(alerts, list(list(
        component = "system",
        severity = "warning", 
        message = "System uptime below threshold",
        timestamp = current_time,
        details = paste("Uptime:", health_metrics$uptime_percentage, "%")
      )))
    }
    
    # Filter alerts by level
    if (alert_level != "all" && length(alerts) > 0) {
      alerts <- alerts[sapply(alerts, function(a) a$severity == alert_level)]
    }
    
    # Health recommendations
    recommendations <- list()
    if (length(alerts) > 0) {
      if (any(sapply(alerts, function(a) a$component == "api"))) {
        recommendations <- c(recommendations, "Consider API performance optimization")
      }
      if (any(sapply(alerts, function(a) a$component == "database"))) {
        recommendations <- c(recommendations, "Review database query performance")
      }
      if (any(sapply(alerts, function(a) a$component == "cache"))) {
        recommendations <- c(recommendations, "Optimize caching strategy")
      }
    } else {
      recommendations <- c("All systems operating normally")
    }
    
    # Real-time metrics
    real_time_metrics <- list(
      current_load = round(runif(1, 0.2, 0.8), 3),
      active_connections = sample(20:100, 1),
      memory_usage = round(runif(1, 0.3, 0.7), 3),
      disk_io_ops = sample(100:500, 1),
      network_traffic_mbps = round(runif(1, 10, 100), 1)
    )
    
    processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    return(success_response(
      data = list(
        system_health = health_metrics,
        alerts = alerts,
        recommendations = recommendations,
        real_time_metrics = real_time_metrics,
        monitoring_info = list(
          monitoring_active = TRUE,
          last_health_check = current_time,
          next_health_check = current_time + as.difftime(MONITORING_CONFIG$real_time$update_intervals$system_health, units = "secs"),
          alert_count = length(alerts),
          critical_alerts = sum(sapply(alerts, function(a) a$severity == "critical"))
        )
      ),
      meta = list(
        component_filter = component,
        alert_level_filter = alert_level,
        details_included = include_details,
        processing_time = round(processing_time, 3),
        health_score = switch(health_metrics$overall_status,
          "healthy" = 100,
          "warning" = 75,
          "critical" = 25,
          50
        )
      ),
      message = paste("System health:", health_metrics$overall_status, "with", length(alerts), "alerts")
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Health monitoring error:", e$message),
      code = 500
    ))
  })
}

# POST /api/v1/monitoring/webhooks - Configure real-time webhooks
#* @post /api/v1/monitoring/webhooks
#* @param req Request object containing webhook configuration
#* @tag monitoring
#* @serializer unboxedJSON
function(req) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  start_time <- Sys.time()
  
  # Parse request body
  body <- tryCatch({
    jsonlite::fromJSON(req$postBody)
  }, error = function(e) {
    return(list())
  })
  
  # Extract webhook parameters
  webhook_url <- body$url %||% ""
  event_types <- body$event_types %||% c("document_added", "high_activity", "system_alert")
  secret_token <- body$secret_token %||% ""
  active <- body$active %||% TRUE
  filters <- body$filters %||% list()
  
  if (nchar(trimws(webhook_url)) == 0) {
    return(error_response("Webhook URL is required", 400))
  }
  
  # Validate URL format
  if (!grepl("^https?://", webhook_url)) {
    return(error_response("Webhook URL must be a valid HTTP/HTTPS URL", 400))
  }
  
  tryCatch({
    # Generate webhook configuration
    webhook_id <- digest(paste(webhook_url, Sys.time(), runif(1)), algo = "md5")
    
    webhook_config <- list(
      webhook_id = webhook_id,
      url = webhook_url,
      event_types = event_types,
      active = active,
      created_at = Sys.time(),
      filters = filters,
      delivery_settings = list(
        timeout_seconds = 30,
        retry_attempts = 3,
        retry_backoff = "exponential"
      ),
      security = list(
        secret_token_provided = nchar(secret_token) > 0,
        signature_validation = TRUE,
        tls_verification = TRUE
      )
    )
    
    # Simulate webhook registration (in production would store in database)
    webhook_status <- list(
      registered = TRUE,
      test_delivery = "pending",
      last_successful_delivery = NULL,
      total_deliveries = 0,
      failed_deliveries = 0
    )
    
    # Test webhook delivery (simulate)
    test_payload <- list(
      event = "webhook_test",
      timestamp = Sys.time(),
      webhook_id = webhook_id,
      message = "Webhook configuration test"
    )
    
    # Simulate test delivery result
    test_result <- list(
      success = sample(c(TRUE, FALSE), 1, prob = c(0.9, 0.1)),
      response_code = if (runif(1) > 0.1) 200 else sample(c(400, 401, 404, 500), 1),
      response_time_ms = sample(100:2000, 1),
      delivered_at = Sys.time()
    )
    
    webhook_status$test_delivery <- if (test_result$success) "successful" else "failed"
    webhook_status$last_test_result <- test_result
    
    # Event type information
    available_events <- list(
      "document_added" = "New document added to the system",
      "document_updated" = "Existing document modified",
      "high_activity" = "Unusual activity level detected",
      "system_alert" = "System health alerts",
      "search_trends" = "Significant changes in search patterns",
      "export_completed" = "Large export jobs completed",
      "api_errors" = "API error rate thresholds exceeded"
    )
    
    processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    return(success_response(
      data = list(
        webhook_config = webhook_config,
        webhook_status = webhook_status,
        available_events = available_events,
        setup_instructions = list(
          endpoint_requirements = c(
            "Accept POST requests with JSON payload",
            "Return HTTP 200 status for successful processing",
            "Implement signature validation using provided secret"
          ),
          payload_format = list(
            event = "string - event type identifier",
            timestamp = "ISO 8601 timestamp",
            data = "object - event-specific data",
            webhook_id = "string - webhook identifier"
          ),
          security_notes = c(
            "Verify webhook signatures using HMAC-SHA256",
            "Use HTTPS endpoints only",
            "Implement proper error handling and logging"
          )
        )
      ),
      meta = list(
        webhook_id = webhook_id,
        processing_time = round(processing_time, 3),
        test_delivery_status = webhook_status$test_delivery,
        active_webhooks_count = 1 # Would get actual count from database
      ),
      message = "Webhook configuration created and test delivery attempted"
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Webhook configuration error:", e$message),
      code = 500
    ))
  })
}

# GET /api/v1/monitoring/activity-summary - Real-time activity summary
#* @get /api/v1/monitoring/activity-summary
#* @param timeframe:str Summary timeframe (5m, 15m, 1h, 6h, 24h)
#* @param include_comparisons:bool Include period-over-period comparisons
#* @tag monitoring
#* @serializer unboxedJSON
function(timeframe = "1h", include_comparisons = TRUE) {
  API_STATE$request_count <<- API_STATE$request_count + 1
  start_time <- Sys.time()
  
  tryCatch({
    current_time <- Sys.time()
    
    # Generate activity summary based on timeframe
    activity_summary <- list(
      timeframe = timeframe,
      period_start = current_time - switch(timeframe,
        "5m" = as.difftime(5, units = "mins"),
        "15m" = as.difftime(15, units = "mins"), 
        "1h" = as.difftime(1, units = "hours"),
        "6h" = as.difftime(6, units = "hours"),
        "24h" = as.difftime(24, units = "hours"),
        as.difftime(1, units = "hours")
      ),
      period_end = current_time
    )
    
    # Core activity metrics
    activity_summary$metrics <- list(
      total_api_requests = sample(1000:10000, 1),
      unique_users = sample(100:1000, 1),
      documents_accessed = sample(500:5000, 1),
      searches_performed = sample(200:2000, 1),
      citations_generated = sample(50:500, 1),
      exports_completed = sample(10:100, 1),
      average_response_time_ms = sample(200:1500, 1),
      error_rate = round(runif(1, 0.005, 0.03), 4)
    )
    
    # Activity breakdown
    activity_summary$breakdown <- list(
      by_endpoint = list(
        "/api/v1/legislation/advanced" = sample(300:3000, 1),
        "/api/v1/search/advanced" = sample(200:2000, 1),
        "/api/v1/geographic/ibge-integration" = sample(100:1000, 1),
        "/api/v1/citations/generate" = sample(50:500, 1),
        "/api/v1/analytics/dashboard" = sample(30:300, 1)
      ),
      by_user_type = list(
        academic = sample(200:2000, 1),
        government = sample(150:1500, 1),
        public = sample(100:1000, 1),
        commercial = sample(50:500, 1)
      ),
      by_geographic_origin = list(
        domestic = sample(800:8000, 1),
        international = sample(50:500, 1)
      )
    )
    
    # Period comparisons
    comparisons <- NULL
    if (include_comparisons) {
      # Simulate previous period metrics
      previous_requests <- sample(900:9500, 1)
      previous_users <- sample(90:950, 1)
      previous_response_time <- sample(250:1600, 1)
      
      comparisons <- list(
        requests_change = list(
          current = activity_summary$metrics$total_api_requests,
          previous = previous_requests,
          change_percent = round((activity_summary$metrics$total_api_requests - previous_requests) / previous_requests * 100, 1),
          trend = if (activity_summary$metrics$total_api_requests > previous_requests) "increasing" else "decreasing"
        ),
        users_change = list(
          current = activity_summary$metrics$unique_users,
          previous = previous_users,
          change_percent = round((activity_summary$metrics$unique_users - previous_users) / previous_users * 100, 1),
          trend = if (activity_summary$metrics$unique_users > previous_users) "increasing" else "decreasing"
        ),
        performance_change = list(
          current_response_time = activity_summary$metrics$average_response_time_ms,
          previous_response_time = previous_response_time,
          change_percent = round((activity_summary$metrics$average_response_time_ms - previous_response_time) / previous_response_time * 100, 1),
          trend = if (activity_summary$metrics$average_response_time_ms < previous_response_time) "improving" else "degrading"
        )
      )
    }
    
    # Activity insights
    insights <- list(
      peak_activity_detected = activity_summary$metrics$total_api_requests > 5000,
      performance_status = if (activity_summary$metrics$average_response_time_ms < 1000) "good" 
                          else if (activity_summary$metrics$average_response_time_ms < 2000) "acceptable" 
                          else "needs_attention",
      user_engagement = if (activity_summary$metrics$unique_users > 500) "high" else "moderate",
      error_status = if (activity_summary$metrics$error_rate < 0.01) "excellent" 
                    else if (activity_summary$metrics$error_rate < 0.02) "good" 
                    else "elevated",
      recommendations = c(
        if (activity_summary$metrics$average_response_time_ms > 1500) "Consider performance optimization",
        if (activity_summary$metrics$error_rate > 0.02) "Investigate error causes",
        if (activity_summary$metrics$unique_users < 200) "Review user engagement strategies"
      )
    )
    
    # Remove NULL recommendations
    insights$recommendations <- insights$recommendations[!sapply(insights$recommendations, is.null)]
    if (length(insights$recommendations) == 0) {
      insights$recommendations <- c("System performing within normal parameters")
    }
    
    processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    return(success_response(
      data = list(
        activity_summary = activity_summary,
        comparisons = comparisons,
        insights = insights,
        monitoring_metadata = list(
          generated_at = current_time,
          data_freshness = "real-time",
          next_update = current_time + as.difftime(300, units = "secs"), # 5 minutes
          monitoring_status = "active"
        )
      ),
      meta = list(
        timeframe = timeframe,
        comparisons_included = include_comparisons,
        processing_time = round(processing_time, 3),
        summary_score = round(mean(c(
          if (insights$performance_status == "good") 100 else if (insights$performance_status == "acceptable") 75 else 50,
          if (insights$user_engagement == "high") 100 else 75,
          if (insights$error_status == "excellent") 100 else if (insights$error_status == "good") 85 else 60
        )), 1)
      ),
      message = paste("Activity summary for", timeframe, "timeframe")
    ))
    
  }, error = function(e) {
    return(error_response(
      message = paste("Activity summary error:", e$message),
      code = 500
    ))
  })
}

cat("✅ Real-Time Monitoring API Loaded - Sprint 7A (API-005)\n")