# Analytics and Reporting for Monitor Legislativo v4
# Usage analytics, cost tracking, performance reporting, and automated reports

library(shiny)
library(echarts4r)
library(dplyr)
library(lubridate)
library(jsonlite)
library(DT)
library(future)
library(promises)

# Analytics configuration
ANALYTICS_CONFIG <- list(
  usage_tracking = list(
    enabled = TRUE,
    track_search_queries = TRUE,
    track_document_views = TRUE,
    track_exports = TRUE,
    track_geographic_queries = TRUE,
    track_user_sessions = TRUE,
    anonymize_data = TRUE,
    retention_days = 90
  ),
  
  cost_tracking = list(
    enabled = TRUE,
    track_api_calls = TRUE,
    track_compute_usage = TRUE,
    track_storage_usage = TRUE,
    cost_per_api_call = 0.001,  # $0.001 per API call
    cost_per_compute_hour = 0.10,  # $0.10 per compute hour
    cost_per_gb_storage = 0.02,  # $0.02 per GB per month
    budget_alert_threshold = 20.00  # $20 monthly budget
  ),
  
  performance_reporting = list(
    enabled = TRUE,
    generate_daily_reports = TRUE,
    generate_weekly_reports = TRUE,
    generate_monthly_reports = FALSE,
    report_formats = c("html", "json"),
    include_charts = TRUE,
    email_reports = FALSE
  ),
  
  business_intelligence = list(
    track_research_patterns = TRUE,
    track_popular_documents = TRUE,
    track_geographic_hotspots = TRUE,
    track_vocabulary_usage = TRUE,
    generate_insights = TRUE,
    ml_predictions = FALSE  # Disabled for now
  ),
  
  data_export = list(
    formats = c("csv", "json", "xlsx"),
    include_metadata = TRUE,
    aggregate_data = TRUE,
    anonymized_exports = TRUE
  )
)

# Global analytics state
analytics_state <- list(
  usage_data = list(),
  cost_data = list(),
  performance_data = list(),
  reports = list(),
  insights = list()
)

#' Initialize analytics and reporting system
#' @param config Optional configuration override
#' @return Initialization status
initialize_analytics <- function(config = NULL) {
  if (!is.null(config)) {
    ANALYTICS_CONFIG <<- modifyList(ANALYTICS_CONFIG, config)
  }
  
  log_event("Initializing analytics and reporting system...", "INFO")
  
  # Initialize analytics state
  analytics_state$usage_data <<- list()
  analytics_state$cost_data <<- list()
  analytics_state$performance_data <<- list()
  analytics_state$reports <<- list()
  analytics_state$insights <<- list()
  
  # Start automated reporting if enabled
  if (ANALYTICS_CONFIG$performance_reporting$enabled) {
    start_automated_reporting()
  }
  
  log_event("Analytics and reporting system initialized", "INFO")
  
  return(list(
    status = "success",
    usage_tracking = ANALYTICS_CONFIG$usage_tracking$enabled,
    cost_tracking = ANALYTICS_CONFIG$cost_tracking$enabled,
    performance_reporting = ANALYTICS_CONFIG$performance_reporting$enabled
  ))
}

#' Track usage event
#' @param event_type Type of usage event
#' @param event_data Event data
#' @param user_id Optional user ID (anonymized)
track_usage_event <- function(event_type, event_data = NULL, user_id = NULL) {
  if (!ANALYTICS_CONFIG$usage_tracking$enabled) {
    return()
  }
  
  # Anonymize user ID if required
  if (ANALYTICS_CONFIG$usage_tracking$anonymize_data && !is.null(user_id)) {
    user_id <- digest::digest(user_id, algo = "md5")
  }
  
  usage_event <- list(
    timestamp = Sys.time(),
    event_type = event_type,
    event_data = event_data,
    user_id = user_id,
    session_id = Sys.getpid()  # Use process ID as session identifier
  )
  
  # Store usage event
  analytics_state$usage_data <<- append(analytics_state$usage_data, list(usage_event), after = 0)
  
  # Limit usage data size
  max_events <- ANALYTICS_CONFIG$usage_tracking$retention_days * 24 * 10  # ~10 events per hour
  if (length(analytics_state$usage_data) > max_events) {
    analytics_state$usage_data <<- head(analytics_state$usage_data, max_events)
  }
  
  # Track specific event types
  switch(event_type,
    "search_query" = track_search_analytics(event_data),
    "document_view" = track_document_analytics(event_data),
    "export_request" = track_export_analytics(event_data),
    "geographic_query" = track_geographic_analytics(event_data)
  )
}

#' Track search analytics
#' @param search_data Search event data
track_search_analytics <- function(search_data) {
  if (!ANALYTICS_CONFIG$usage_tracking$track_search_queries) {
    return()
  }
  
  # Extract search insights
  search_insights <- list(
    query_length = nchar(search_data$query %||% ""),
    has_filters = !is.null(search_data$filters) && length(search_data$filters) > 0,
    result_count = search_data$result_count %||% 0,
    response_time_ms = search_data$response_time_ms %||% 0,
    search_type = search_data$search_type %||% "basic"
  )
  
  # Store search-specific analytics
  search_event <- list(
    timestamp = Sys.time(),
    type = "search_analytics",
    data = search_insights
  )
  
  analytics_state$usage_data <<- append(analytics_state$usage_data, list(search_event), after = 0)
}

#' Track document analytics
#' @param document_data Document event data
track_document_analytics <- function(document_data) {
  if (!ANALYTICS_CONFIG$usage_tracking$track_document_views) {
    return()
  }
  
  # Extract document insights
  doc_insights <- list(
    document_type = document_data$tipo %||% "unknown",
    document_state = document_data$estado %||% "unknown",
    view_duration_seconds = document_data$view_duration %||% 0,
    actions_taken = document_data$actions %||% list()
  )
  
  # Store document-specific analytics
  doc_event <- list(
    timestamp = Sys.time(),
    type = "document_analytics",
    data = doc_insights
  )
  
  analytics_state$usage_data <<- append(analytics_state$usage_data, list(doc_event), after = 0)
}

#' Track export analytics
#' @param export_data Export event data
track_export_analytics <- function(export_data) {
  if (!ANALYTICS_CONFIG$usage_tracking$track_exports) {
    return()
  }
  
  # Extract export insights
  export_insights <- list(
    format = export_data$format %||% "unknown",
    template = export_data$template %||% "unknown",
    record_count = export_data$record_count %||% 0,
    file_size_mb = export_data$file_size_mb %||% 0,
    generation_time_ms = export_data$generation_time_ms %||% 0
  )
  
  # Store export-specific analytics
  export_event <- list(
    timestamp = Sys.time(),
    type = "export_analytics",
    data = export_insights
  )
  
  analytics_state$usage_data <<- append(analytics_state$usage_data, list(export_event), after = 0)
}

#' Track geographic analytics
#' @param geo_data Geographic event data
track_geographic_analytics <- function(geo_data) {
  if (!ANALYTICS_CONFIG$usage_tracking$track_geographic_queries) {
    return()
  }
  
  # Extract geographic insights
  geo_insights <- list(
    states_selected = length(geo_data$states %||% c()),
    map_interactions = geo_data$interactions %||% 0,
    zoom_level = geo_data$zoom_level %||% 0,
    area_queried = geo_data$area_type %||% "unknown"
  )
  
  # Store geographic-specific analytics
  geo_event <- list(
    timestamp = Sys.time(),
    type = "geographic_analytics",
    data = geo_insights
  )
  
  analytics_state$usage_data <<- append(analytics_state$usage_data, list(geo_event), after = 0)
}

#' Track cost event
#' @param cost_type Type of cost event
#' @param amount Cost amount
#' @param details Cost details
track_cost_event <- function(cost_type, amount, details = NULL) {
  if (!ANALYTICS_CONFIG$cost_tracking$enabled) {
    return()
  }
  
  cost_event <- list(
    timestamp = Sys.time(),
    cost_type = cost_type,
    amount = amount,
    details = details,
    cumulative_daily = NULL,
    cumulative_monthly = NULL
  )
  
  # Calculate cumulative costs
  cost_event$cumulative_daily <- calculate_daily_costs(cost_type)
  cost_event$cumulative_monthly <- calculate_monthly_costs(cost_type)
  
  # Store cost event
  analytics_state$cost_data <<- append(analytics_state$cost_data, list(cost_event), after = 0)
  
  # Check budget alerts
  check_budget_alerts(cost_event$cumulative_monthly)
  
  # Limit cost data size (keep 1 year of data)
  max_cost_events <- 365 * 24  # Daily cost events
  if (length(analytics_state$cost_data) > max_cost_events) {
    analytics_state$cost_data <<- head(analytics_state$cost_data, max_cost_events)
  }
}

#' Calculate daily costs by type
#' @param cost_type Cost type to calculate
#' @return Daily cumulative cost
calculate_daily_costs <- function(cost_type) {
  today <- Sys.Date()
  
  daily_costs <- Filter(function(x) {
    as.Date(x$timestamp) == today && x$cost_type == cost_type
  }, analytics_state$cost_data)
  
  sum(sapply(daily_costs, function(x) x$amount))
}

#' Calculate monthly costs by type
#' @param cost_type Cost type to calculate
#' @return Monthly cumulative cost
calculate_monthly_costs <- function(cost_type) {
  current_month <- format(Sys.Date(), "%Y-%m")
  
  monthly_costs <- Filter(function(x) {
    format(as.Date(x$timestamp), "%Y-%m") == current_month && x$cost_type == cost_type
  }, analytics_state$cost_data)
  
  sum(sapply(monthly_costs, function(x) x$amount))
}

#' Check budget alerts
#' @param monthly_total Monthly total cost
check_budget_alerts <- function(monthly_total) {
  threshold <- ANALYTICS_CONFIG$cost_tracking$budget_alert_threshold
  
  if (monthly_total > threshold) {
    log_event(paste("BUDGET ALERT: Monthly cost", monthly_total, "exceeds threshold", threshold), "WARN")
    
    # Trigger budget alert
    if (exists("trigger_alert")) {
      trigger_alert(
        type = "budget",
        severity = "warning",
        message = paste("Monthly budget exceeded:", monthly_total, "USD"),
        details = list(
          current_spend = monthly_total,
          budget_limit = threshold,
          overage = monthly_total - threshold
        )
      )
    }
  }
}

#' Generate usage analytics report
#' @param period Report period ("daily", "weekly", "monthly")
#' @param format Report format ("html", "json")
#' @return Generated report
generate_usage_report <- function(period = "daily", format = "html") {
  # Calculate date range
  end_date <- Sys.Date()
  start_date <- switch(period,
    "daily" = end_date - 1,
    "weekly" = end_date - 7,
    "monthly" = end_date - 30,
    end_date - 1
  )
  
  # Filter usage data by period
  period_data <- Filter(function(x) {
    as.Date(x$timestamp) >= start_date && as.Date(x$timestamp) <= end_date
  }, analytics_state$usage_data)
  
  if (length(period_data) == 0) {
    return(list(
      status = "no_data",
      message = paste("No usage data available for", period, "period")
    ))
  }
  
  # Calculate usage statistics
  report_data <- list(
    period = period,
    start_date = start_date,
    end_date = end_date,
    total_events = length(period_data),
    event_breakdown = table(sapply(period_data, function(x) x$event_type)),
    daily_activity = calculate_daily_activity(period_data),
    top_searches = extract_top_searches(period_data),
    popular_documents = extract_popular_documents(period_data),
    geographic_activity = extract_geographic_activity(period_data)
  )
  
  # Generate report in requested format
  if (format == "html") {
    return(generate_html_usage_report(report_data))
  } else if (format == "json") {
    return(toJSON(report_data, pretty = TRUE, auto_unbox = TRUE))
  }
  
  return(report_data)
}

#' Generate cost analytics report
#' @param period Report period
#' @param format Report format
#' @return Generated cost report
generate_cost_report <- function(period = "monthly", format = "html") {
  # Calculate date range
  end_date <- Sys.Date()
  start_date <- switch(period,
    "daily" = end_date - 1,
    "weekly" = end_date - 7,
    "monthly" = end_date - 30,
    end_date - 30
  )
  
  # Filter cost data by period
  period_costs <- Filter(function(x) {
    as.Date(x$timestamp) >= start_date && as.Date(x$timestamp) <= end_date
  }, analytics_state$cost_data)
  
  if (length(period_costs) == 0) {
    return(list(
      status = "no_data",
      message = paste("No cost data available for", period, "period")
    ))
  }
  
  # Calculate cost statistics
  total_cost <- sum(sapply(period_costs, function(x) x$amount))
  cost_by_type <- aggregate_costs_by_type(period_costs)
  daily_costs <- calculate_daily_cost_breakdown(period_costs)
  
  report_data <- list(
    period = period,
    start_date = start_date,
    end_date = end_date,
    total_cost = round(total_cost, 4),
    budget_remaining = ANALYTICS_CONFIG$cost_tracking$budget_alert_threshold - total_cost,
    cost_by_type = cost_by_type,
    daily_breakdown = daily_costs,
    cost_trends = calculate_cost_trends(period_costs)
  )
  
  # Generate report in requested format
  if (format == "html") {
    return(generate_html_cost_report(report_data))
  } else if (format == "json") {
    return(toJSON(report_data, pretty = TRUE, auto_unbox = TRUE))
  }
  
  return(report_data)
}

#' Generate performance analytics report
#' @param period Report period
#' @param format Report format
#' @return Generated performance report
generate_performance_report <- function(period = "daily", format = "html") {
  # Get performance data from monitoring system
  if (exists("monitoring_state") && !is.null(monitoring_state$performance_metrics)) {
    performance_data <- monitoring_state$performance_metrics
  } else {
    return(list(
      status = "no_data",
      message = "No performance data available"
    ))
  }
  
  # Calculate date range
  end_date <- Sys.Date()
  start_date <- switch(period,
    "daily" = end_date - 1,
    "weekly" = end_date - 7,
    "monthly" = end_date - 30,
    end_date - 1
  )
  
  # Filter performance data by period
  period_data <- Filter(function(x) {
    as.Date(x$timestamp) >= start_date && as.Date(x$timestamp) <= end_date
  }, performance_data)
  
  if (length(period_data) == 0) {
    return(list(
      status = "no_data",
      message = paste("No performance data available for", period, "period")
    ))
  }
  
  # Calculate performance statistics
  report_data <- list(
    period = period,
    start_date = start_date,
    end_date = end_date,
    avg_memory_usage = calculate_avg_memory_usage(period_data),
    avg_query_time = calculate_avg_query_time(period_data),
    cache_performance = calculate_cache_performance(period_data),
    system_uptime = calculate_uptime_percentage(period_data),
    performance_trends = calculate_performance_trends(period_data)
  )
  
  # Generate report in requested format
  if (format == "html") {
    return(generate_html_performance_report(report_data))
  } else if (format == "json") {
    return(toJSON(report_data, pretty = TRUE, auto_unbox = TRUE))
  }
  
  return(report_data)
}

#' Generate HTML usage report
#' @param report_data Report data
#' @return HTML report
generate_html_usage_report <- function(report_data) {
  html_content <- paste0("
    <html>
    <head>
      <title>Monitor Legislativo - Usage Report (", report_data$period, ")</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .metric { background: white; border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .metric-value { font-size: 2em; font-weight: bold; color: #0d6efd; }
        .metric-label { color: #6c757d; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background-color: #f8f9fa; }
      </style>
    </head>
    <body>
      <div class='header'>
        <h1>Monitor Legislativo - Usage Analytics</h1>
        <p>Period: ", format(report_data$start_date, "%Y-%m-%d"), " to ", format(report_data$end_date, "%Y-%m-%d"), "</p>
        <p>Generated: ", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "</p>
      </div>
      
      <div class='metric'>
        <div class='metric-value'>", format(report_data$total_events, big.mark = ","), "</div>
        <div class='metric-label'>Total Events</div>
      </div>
      
      <h2>Event Breakdown</h2>
      <table>
        <tr><th>Event Type</th><th>Count</th></tr>
  ")
  
  # Add event breakdown table
  for (event_type in names(report_data$event_breakdown)) {
    html_content <- paste0(html_content, 
      "<tr><td>", event_type, "</td><td>", report_data$event_breakdown[event_type], "</td></tr>"
    )
  }
  
  html_content <- paste0(html_content, "
      </table>
      
      <h2>Top Search Queries</h2>
      <table>
        <tr><th>Query</th><th>Count</th></tr>
  ")
  
  # Add top searches (if available)
  if (!is.null(report_data$top_searches) && length(report_data$top_searches) > 0) {
    for (i in 1:min(10, length(report_data$top_searches))) {
      search <- report_data$top_searches[[i]]
      html_content <- paste0(html_content,
        "<tr><td>", search$query, "</td><td>", search$count, "</td></tr>"
      )
    }
  } else {
    html_content <- paste0(html_content, "<tr><td colspan='2'>No search data available</td></tr>")
  }
  
  html_content <- paste0(html_content, "
      </table>
    </body>
    </html>
  ")
  
  return(html_content)
}

#' Generate HTML cost report
#' @param report_data Report data
#' @return HTML cost report
generate_html_cost_report <- function(report_data) {
  html_content <- paste0("
    <html>
    <head>
      <title>Monitor Legislativo - Cost Report (", report_data$period, ")</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .metric { background: white; border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .metric-value { font-size: 2em; font-weight: bold; color: #198754; }
        .metric-label { color: #6c757d; }
        .budget-alert { color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background-color: #f8f9fa; }
      </style>
    </head>
    <body>
      <div class='header'>
        <h1>Monitor Legislativo - Cost Analytics</h1>
        <p>Period: ", format(report_data$start_date, "%Y-%m-%d"), " to ", format(report_data$end_date, "%Y-%m-%d"), "</p>
        <p>Generated: ", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "</p>
      </div>
      
      <div class='metric'>
        <div class='metric-value", if(report_data$budget_remaining < 0) " budget-alert" else "", "'>$", sprintf("%.4f", report_data$total_cost), "</div>
        <div class='metric-label'>Total Cost</div>
      </div>
      
      <div class='metric'>
        <div class='metric-value", if(report_data$budget_remaining < 0) " budget-alert" else "", "'>$", sprintf("%.2f", report_data$budget_remaining), "</div>
        <div class='metric-label'>Budget Remaining</div>
      </div>
      
      <h2>Cost Breakdown by Type</h2>
      <table>
        <tr><th>Cost Type</th><th>Amount</th></tr>
  ")
  
  # Add cost breakdown table
  for (cost_type in names(report_data$cost_by_type)) {
    html_content <- paste0(html_content,
      "<tr><td>", cost_type, "</td><td>$", sprintf("%.4f", report_data$cost_by_type[[cost_type]]), "</td></tr>"
    )
  }
  
  html_content <- paste0(html_content, "
      </table>
    </body>
    </html>
  ")
  
  return(html_content)
}

#' Generate HTML performance report
#' @param report_data Report data
#' @return HTML performance report
generate_html_performance_report <- function(report_data) {
  html_content <- paste0("
    <html>
    <head>
      <title>Monitor Legislativo - Performance Report (", report_data$period, ")</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .metric { background: white; border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .metric-value { font-size: 2em; font-weight: bold; color: #0d6efd; }
        .metric-label { color: #6c757d; }
      </style>
    </head>
    <body>
      <div class='header'>
        <h1>Monitor Legislativo - Performance Report</h1>
        <p>Period: ", format(report_data$start_date, "%Y-%m-%d"), " to ", format(report_data$end_date, "%Y-%m-%d"), "</p>
        <p>Generated: ", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "</p>
      </div>
      
      <div class='metric'>
        <div class='metric-value'>", sprintf("%.1f", report_data$avg_memory_usage), " MB</div>
        <div class='metric-label'>Average Memory Usage</div>
      </div>
      
      <div class='metric'>
        <div class='metric-value'>", sprintf("%.1f", report_data$avg_query_time), " ms</div>
        <div class='metric-label'>Average Query Time</div>
      </div>
      
      <div class='metric'>
        <div class='metric-value'>", sprintf("%.1f", report_data$system_uptime), "%</div>
        <div class='metric-label'>System Uptime</div>
      </div>
    </body>
    </html>
  ")
  
  return(html_content)
}

#' Start automated reporting
start_automated_reporting <- function() {
  if (!ANALYTICS_CONFIG$performance_reporting$enabled) {
    return()
  }
  
  # Schedule daily reports
  if (ANALYTICS_CONFIG$performance_reporting$generate_daily_reports) {
    future({
      while (TRUE) {
        Sys.sleep(86400)  # 24 hours
        
        tryCatch({
          daily_report <- generate_usage_report("daily", "html")
          store_generated_report("daily_usage", daily_report)
          
          daily_cost_report <- generate_cost_report("daily", "html")
          store_generated_report("daily_cost", daily_cost_report)
          
          log_event("Daily reports generated successfully", "INFO")
        }, error = function(e) {
          log_event(paste("Daily report generation error:", e$message), "ERROR")
        })
      }
    })
  }
  
  # Schedule weekly reports
  if (ANALYTICS_CONFIG$performance_reporting$generate_weekly_reports) {
    future({
      while (TRUE) {
        Sys.sleep(604800)  # 7 days
        
        tryCatch({
          weekly_report <- generate_usage_report("weekly", "html")
          store_generated_report("weekly_usage", weekly_report)
          
          weekly_performance_report <- generate_performance_report("weekly", "html")
          store_generated_report("weekly_performance", weekly_performance_report)
          
          log_event("Weekly reports generated successfully", "INFO")
        }, error = function(e) {
          log_event(paste("Weekly report generation error:", e$message), "ERROR")
        })
      }
    })
  }
  
  log_event("Automated reporting scheduled", "INFO")
}

#' Store generated report
#' @param report_type Type of report
#' @param report_content Report content
store_generated_report <- function(report_type, report_content) {
  report_entry <- list(
    timestamp = Sys.time(),
    type = report_type,
    content = report_content,
    size_bytes = nchar(as.character(report_content))
  )
  
  analytics_state$reports <<- append(analytics_state$reports, list(report_entry), after = 0)
  
  # Limit stored reports (keep last 30 reports)
  if (length(analytics_state$reports) > 30) {
    analytics_state$reports <<- head(analytics_state$reports, 30)
  }
}

#' Get analytics dashboard data
#' @return Dashboard data for analytics
get_analytics_dashboard_data <- function() {
  # Get recent usage statistics
  recent_usage <- tail(analytics_state$usage_data, 100)
  recent_costs <- tail(analytics_state$cost_data, 50)
  
  dashboard_data <- list(
    usage_summary = list(
      total_events_today = length(Filter(function(x) as.Date(x$timestamp) == Sys.Date(), recent_usage)),
      total_events_week = length(Filter(function(x) as.Date(x$timestamp) >= Sys.Date() - 7, recent_usage)),
      most_common_event = get_most_common_event_type(recent_usage)
    ),
    
    cost_summary = list(
      total_cost_today = sum(sapply(Filter(function(x) as.Date(x$timestamp) == Sys.Date(), recent_costs), function(x) x$amount)),
      total_cost_month = sum(sapply(Filter(function(x) format(as.Date(x$timestamp), "%Y-%m") == format(Sys.Date(), "%Y-%m"), recent_costs), function(x) x$amount)),
      budget_utilization = (sum(sapply(recent_costs, function(x) x$amount)) / ANALYTICS_CONFIG$cost_tracking$budget_alert_threshold) * 100
    ),
    
    recent_reports = head(analytics_state$reports, 5),
    insights = generate_quick_insights()
  )
  
  return(dashboard_data)
}

#' Generate quick insights from analytics data
#' @return List of insights
generate_quick_insights <- function() {
  if (!ANALYTICS_CONFIG$business_intelligence$generate_insights) {
    return(list())
  }
  
  insights <- list()
  
  # Usage pattern insights
  recent_usage <- tail(analytics_state$usage_data, 1000)
  if (length(recent_usage) > 0) {
    event_counts <- table(sapply(recent_usage, function(x) x$event_type))
    
    if (length(event_counts) > 0) {
      most_popular <- names(event_counts)[which.max(event_counts)]
      insights$usage_pattern <- paste("Most popular feature:", most_popular, "with", max(event_counts), "uses")
    }
  }
  
  # Cost efficiency insights
  recent_costs <- tail(analytics_state$cost_data, 100)
  if (length(recent_costs) > 0) {
    daily_avg <- mean(sapply(recent_costs, function(x) x$amount))
    monthly_projection <- daily_avg * 30
    
    if (monthly_projection < ANALYTICS_CONFIG$cost_tracking$budget_alert_threshold) {
      insights$cost_efficiency <- paste("On track for monthly budget: projected $", sprintf("%.2f", monthly_projection))
    } else {
      insights$cost_efficiency <- paste("Budget alert: projected $", sprintf("%.2f", monthly_projection), "exceeds budget")
    }
  }
  
  return(insights)
}

# Helper functions for calculations
calculate_daily_activity <- function(usage_data) {
  if (length(usage_data) == 0) return(list())
  
  daily_counts <- table(as.Date(sapply(usage_data, function(x) x$timestamp)))
  return(as.list(daily_counts))
}

extract_top_searches <- function(usage_data) {
  search_events <- Filter(function(x) x$event_type == "search_query", usage_data)
  if (length(search_events) == 0) return(list())
  
  # Extract search queries (placeholder - would need actual query data)
  return(list(list(query = "transport", count = 10), list(query = "legislation", count = 8)))
}

extract_popular_documents <- function(usage_data) {
  doc_events <- Filter(function(x) x$event_type == "document_view", usage_data)
  if (length(doc_events) == 0) return(list())
  
  # Extract document popularity (placeholder)
  return(list(list(document = "Federal Constitution", views = 15)))
}

extract_geographic_activity <- function(usage_data) {
  geo_events <- Filter(function(x) x$event_type == "geographic_query", usage_data)
  if (length(geo_events) == 0) return(list())
  
  # Extract geographic activity (placeholder)
  return(list(list(state = "SP", queries = 20), list(state = "RJ", queries = 15)))
}

aggregate_costs_by_type <- function(cost_data) {
  if (length(cost_data) == 0) return(list())
  
  cost_types <- sapply(cost_data, function(x) x$cost_type)
  amounts <- sapply(cost_data, function(x) x$amount)
  
  return(as.list(tapply(amounts, cost_types, sum)))
}

calculate_daily_cost_breakdown <- function(cost_data) {
  if (length(cost_data) == 0) return(list())
  
  dates <- as.Date(sapply(cost_data, function(x) x$timestamp))
  amounts <- sapply(cost_data, function(x) x$amount)
  
  return(as.list(tapply(amounts, dates, sum)))
}

calculate_cost_trends <- function(cost_data) {
  if (length(cost_data) < 2) return(list(trend = "insufficient_data"))
  
  # Simple trend calculation (placeholder)
  recent_avg <- mean(sapply(tail(cost_data, 7), function(x) x$amount))
  older_avg <- mean(sapply(head(cost_data, 7), function(x) x$amount))
  
  trend <- if (recent_avg > older_avg) "increasing" else "decreasing"
  
  return(list(
    trend = trend,
    recent_avg = recent_avg,
    older_avg = older_avg,
    change_percent = ((recent_avg - older_avg) / older_avg) * 100
  ))
}

get_most_common_event_type <- function(usage_data) {
  if (length(usage_data) == 0) return("none")
  
  event_counts <- table(sapply(usage_data, function(x) x$event_type))
  
  if (length(event_counts) > 0) {
    return(names(event_counts)[which.max(event_counts)])
  }
  
  return("none")
}

# Performance calculation helpers
calculate_avg_memory_usage <- function(perf_data) {
  memory_values <- sapply(perf_data, function(x) x$system$memory_used_mb %||% 0)
  return(mean(memory_values[memory_values > 0]))
}

calculate_avg_query_time <- function(perf_data) {
  query_times <- sapply(perf_data, function(x) x$system$avg_query_time_ms %||% 0)
  return(mean(query_times[query_times > 0]))
}

calculate_cache_performance <- function(perf_data) {
  hit_rates <- sapply(perf_data, function(x) x$system$cache_hit_rate %||% 0)
  return(mean(hit_rates[hit_rates > 0]))
}

calculate_uptime_percentage <- function(perf_data) {
  # Simplified uptime calculation
  return(99.5)  # Placeholder
}

calculate_performance_trends <- function(perf_data) {
  if (length(perf_data) < 2) return(list(trend = "insufficient_data"))
  
  # Simple performance trend (placeholder)
  return(list(trend = "stable", variance = "low"))
}