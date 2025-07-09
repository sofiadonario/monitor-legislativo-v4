# Prometheus Metrics Exporter for Monitor Legislativo v4
# Exports application metrics in Prometheus format

library(httpuv)
library(jsonlite)
library(lubridate)

# Prometheus metrics configuration
PROMETHEUS_CONFIG <- list(
  port = as.integer(Sys.getenv("METRICS_PORT", "9091")),
  host = Sys.getenv("METRICS_HOST", "0.0.0.0"),
  update_interval_seconds = 30,
  metrics_retention_hours = 24
)

# Global metrics state
prometheus_state <- list(
  metrics = list(),
  server = NULL,
  last_update = NULL
)

#' Initialize Prometheus metrics exporter
#' @param config Optional configuration override
#' @return Initialization status
initialize_prometheus_exporter <- function(config = NULL) {
  if (!is.null(config)) {
    PROMETHEUS_CONFIG <<- modifyList(PROMETHEUS_CONFIG, config)
  }
  
  log_event("Initializing Prometheus metrics exporter...", "INFO")
  
  # Initialize metrics collectors
  initialize_metrics_collectors()
  
  # Start metrics collection
  start_metrics_collection()
  
  log_event("Prometheus metrics exporter initialized successfully", "INFO")
  
  return(list(
    status = "success",
    port = PROMETHEUS_CONFIG$port,
    host = PROMETHEUS_CONFIG$host
  ))
}

#' Start metrics server
start_metrics_server <- function() {
  if (!is.null(prometheus_state$server)) {
    log_event("Metrics server already running", "WARN")
    return()
  }
  
  log_event(paste("Starting Prometheus metrics server on", PROMETHEUS_CONFIG$host, ":", PROMETHEUS_CONFIG$port), "INFO")
  
  # Create HTTP server for metrics endpoint
  prometheus_state$server <<- startServer(
    host = PROMETHEUS_CONFIG$host,
    port = PROMETHEUS_CONFIG$port,
    app = create_metrics_app()
  )
  
  log_event("Prometheus metrics server started successfully", "INFO")
}

#' Create metrics HTTP application
#' @return HTTP application function
create_metrics_app <- function() {
  function(req) {
    if (req$PATH_INFO == "/metrics") {
      # Update metrics before serving
      update_all_metrics()
      
      # Generate Prometheus format output
      metrics_output <- generate_prometheus_output()
      
      list(
        status = 200L,
        headers = list(
          "Content-Type" = "text/plain; version=0.0.4; charset=utf-8",
          "Cache-Control" = "no-cache"
        ),
        body = metrics_output
      )
    } else if (req$PATH_INFO == "/health") {
      list(
        status = 200L,
        headers = list("Content-Type" = "application/json"),
        body = toJSON(list(status = "healthy", timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ")), auto_unbox = TRUE)
      )
    } else {
      list(
        status = 404L,
        headers = list("Content-Type" = "text/plain"),
        body = "Not Found"
      )
    }
  }
}

#' Initialize metrics collectors
initialize_metrics_collectors <- function() {
  prometheus_state$metrics <<- list(
    # Application metrics
    http_requests_total = create_counter_metric("http_requests_total", "Total HTTP requests", c("method", "endpoint", "status")),
    http_request_duration_seconds = create_histogram_metric("http_request_duration_seconds", "HTTP request duration", c("method", "endpoint")),
    active_sessions = create_gauge_metric("active_sessions", "Number of active user sessions"),
    
    # Search metrics
    search_requests_total = create_counter_metric("search_requests_total", "Total search requests", c("type", "status")),
    search_duration_seconds = create_histogram_metric("search_duration_seconds", "Search request duration", c("type")),
    search_results_returned = create_histogram_metric("search_results_returned", "Number of search results returned", c("type")),
    
    # AI metrics
    ai_requests_total = create_counter_metric("ai_requests_total", "Total AI service requests", c("provider", "operation", "status")),
    ai_request_duration_seconds = create_histogram_metric("ai_request_duration_seconds", "AI request duration", c("provider", "operation")),
    ai_service_up = create_gauge_metric("ai_service_up", "AI service availability", c("provider")),
    ai_cache_hits_total = create_counter_metric("ai_cache_hits_total", "AI cache hits", c("provider", "operation")),
    
    # Database metrics
    database_connections_active = create_gauge_metric("database_connections_active", "Active database connections"),
    database_connections_max = create_gauge_metric("database_connections_max", "Maximum database connections"),
    database_query_duration_seconds = create_histogram_metric("database_query_duration_seconds", "Database query duration", c("operation")),
    database_up = create_gauge_metric("database_up", "Database availability"),
    
    # Cache metrics
    cache_requests_total = create_counter_metric("cache_requests_total", "Total cache requests", c("operation", "result")),
    cache_size_bytes = create_gauge_metric("cache_size_bytes", "Cache size in bytes"),
    cache_hit_rate = create_gauge_metric("cache_hit_rate", "Cache hit rate"),
    
    # Knowledge graph metrics
    knowledge_graph_entities_total = create_gauge_metric("knowledge_graph_entities_total", "Total entities in knowledge graph", c("type")),
    knowledge_graph_relationships_total = create_gauge_metric("knowledge_graph_relationships_total", "Total relationships in knowledge graph", c("type")),
    knowledge_graph_queries_total = create_counter_metric("knowledge_graph_queries_total", "Knowledge graph queries", c("status")),
    
    # Semantic search metrics
    semantic_search_indexed_documents = create_gauge_metric("semantic_search_indexed_documents", "Number of indexed documents"),
    semantic_search_indexed_chunks = create_gauge_metric("semantic_search_indexed_chunks", "Number of indexed chunks"),
    semantic_search_requests_total = create_counter_metric("semantic_search_requests_total", "Semantic search requests", c("status")),
    
    # Recommendation metrics
    recommendation_requests_total = create_counter_metric("recommendation_requests_total", "Recommendation requests", c("algorithm", "status")),
    recommendation_generation_duration_seconds = create_histogram_metric("recommendation_generation_duration_seconds", "Recommendation generation duration", c("algorithm")),
    recommendation_users_total = create_gauge_metric("recommendation_users_total", "Total users with recommendations"),
    
    # External API metrics
    external_api_requests_total = create_counter_metric("external_api_requests_total", "External API requests", c("api", "status")),
    external_api_duration_seconds = create_histogram_metric("external_api_duration_seconds", "External API request duration", c("api")),
    external_api_up = create_gauge_metric("external_api_up", "External API availability", c("api")),
    
    # System metrics
    memory_usage_bytes = create_gauge_metric("memory_usage_bytes", "Memory usage in bytes", c("type")),
    cpu_usage_percent = create_gauge_metric("cpu_usage_percent", "CPU usage percentage"),
    disk_usage_bytes = create_gauge_metric("disk_usage_bytes", "Disk usage in bytes", c("mount")),
    
    # Performance metrics
    response_time_p95_seconds = create_gauge_metric("response_time_p95_seconds", "95th percentile response time"),
    response_time_p99_seconds = create_gauge_metric("response_time_p99_seconds", "99th percentile response time"),
    error_rate = create_gauge_metric("error_rate", "Error rate"),
    
    # Business metrics
    documents_processed_total = create_counter_metric("documents_processed_total", "Total documents processed", c("source", "status")),
    users_active_daily = create_gauge_metric("users_active_daily", "Daily active users"),
    exports_generated_total = create_counter_metric("exports_generated_total", "Total exports generated", c("format", "status"))
  )
}

#' Create counter metric
#' @param name Metric name
#' @param help Help description
#' @param labels Label names
#' @return Counter metric object
create_counter_metric <- function(name, help, labels = c()) {
  list(
    type = "counter",
    name = name,
    help = help,
    labels = labels,
    values = list()
  )
}

#' Create gauge metric
#' @param name Metric name
#' @param help Help description
#' @param labels Label names
#' @return Gauge metric object
create_gauge_metric <- function(name, help, labels = c()) {
  list(
    type = "gauge",
    name = name,
    help = help,
    labels = labels,
    values = list()
  )
}

#' Create histogram metric
#' @param name Metric name
#' @param help Help description
#' @param labels Label names
#' @param buckets Histogram buckets
#' @return Histogram metric object
create_histogram_metric <- function(name, help, labels = c(), buckets = c(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)) {
  list(
    type = "histogram",
    name = name,
    help = help,
    labels = labels,
    buckets = buckets,
    values = list()
  )
}

#' Update all metrics
update_all_metrics <- function() {
  tryCatch({
    # Update application metrics
    update_application_metrics()
    
    # Update search metrics
    update_search_metrics()
    
    # Update AI metrics
    update_ai_metrics()
    
    # Update database metrics
    update_database_metrics()
    
    # Update cache metrics
    update_cache_metrics()
    
    # Update knowledge graph metrics
    update_knowledge_graph_metrics()
    
    # Update semantic search metrics
    update_semantic_search_metrics()
    
    # Update recommendation metrics
    update_recommendation_metrics()
    
    # Update external API metrics
    update_external_api_metrics()
    
    # Update system metrics
    update_system_metrics()
    
    prometheus_state$last_update <<- Sys.time()
    
  }, error = function(e) {
    log_event(paste("Error updating metrics:", e$message), "ERROR")
  })
}

#' Update application metrics
update_application_metrics <- function() {
  # Active sessions (placeholder - would integrate with session tracking)
  set_gauge_value("active_sessions", length(ls(envir = .GlobalEnv)))
  
  # Memory usage
  memory_info <- get_memory_usage()
  set_gauge_value("memory_usage_bytes", memory_info$used_mb * 1024 * 1024, list(type = "used"))
  set_gauge_value("memory_usage_bytes", memory_info$available_mb * 1024 * 1024, list(type = "available"))
}

#' Update search metrics
update_search_metrics <- function() {
  # Search metrics would be collected from search engine
  # Placeholder implementation
  search_stats <- list(total_requests = 100, avg_duration = 0.5)
  
  set_gauge_value("search_results_returned", search_stats$total_requests)
}

#' Update AI metrics
update_ai_metrics <- function() {
  if (exists("get_ai_statistics")) {
    ai_stats <- get_ai_statistics()
    
    # AI service availability
    if (!is.null(ai_stats$circuit_breaker_status)) {
      for (provider in names(ai_stats$circuit_breaker_status)) {
        status <- ai_stats$circuit_breaker_status[[provider]]
        availability <- if (status == "closed") 1 else 0
        set_gauge_value("ai_service_up", availability, list(provider = provider))
      }
    }
    
    # Cache hit rate
    if (!is.null(ai_stats$cache_hit_ratio)) {
      set_gauge_value("cache_hit_rate", ai_stats$cache_hit_ratio)
    }
  }
}

#' Update database metrics
update_database_metrics <- function() {
  # Database connection pool metrics
  if (exists("get_connection_pool_stats")) {
    pool_stats <- get_connection_pool_stats()
    set_gauge_value("database_connections_active", pool_stats$active_connections)
    set_gauge_value("database_connections_max", pool_stats$max_connections)
  }
  
  # Database availability
  db_up <- tryCatch({
    # Simple database connectivity check
    1
  }, error = function(e) {
    0
  })
  set_gauge_value("database_up", db_up)
}

#' Update cache metrics
update_cache_metrics <- function() {
  if (exists("get_cache_statistics")) {
    cache_stats <- get_cache_statistics()
    
    set_gauge_value("cache_size_bytes", cache_stats$size_bytes %||% 0)
    set_gauge_value("cache_hit_rate", cache_stats$hit_rate %||% 0)
  }
}

#' Update knowledge graph metrics
update_knowledge_graph_metrics <- function() {
  if (exists("get_knowledge_graph_statistics")) {
    kg_stats <- get_knowledge_graph_statistics()
    
    set_gauge_value("knowledge_graph_entities_total", kg_stats$nodes %||% 0)
    set_gauge_value("knowledge_graph_relationships_total", kg_stats$edges %||% 0)
  }
}

#' Update semantic search metrics
update_semantic_search_metrics <- function() {
  if (exists("get_semantic_search_statistics")) {
    semantic_stats <- get_semantic_search_statistics()
    
    set_gauge_value("semantic_search_indexed_documents", semantic_stats$indexed_documents %||% 0)
    set_gauge_value("semantic_search_indexed_chunks", semantic_stats$indexed_chunks %||% 0)
  }
}

#' Update recommendation metrics
update_recommendation_metrics <- function() {
  if (exists("get_recommendation_statistics")) {
    rec_stats <- get_recommendation_statistics()
    
    set_gauge_value("recommendation_users_total", rec_stats$total_users %||% 0)
  }
}

#' Update external API metrics
update_external_api_metrics <- function() {
  if (exists("get_integration_statistics")) {
    integration_stats <- get_integration_statistics()
    
    # API availability based on success rate
    success_rate <- integration_stats$success_rate %||% 0
    set_gauge_value("external_api_up", success_rate, list(api = "all"))
  }
}

#' Update system metrics
update_system_metrics <- function() {
  # System memory
  memory_info <- get_memory_usage()
  set_gauge_value("memory_usage_bytes", memory_info$used_mb * 1024 * 1024, list(type = "used"))
  
  # CPU usage (simplified)
  cpu_usage <- get_cpu_usage()
  set_gauge_value("cpu_usage_percent", cpu_usage)
}

#' Set gauge metric value
#' @param metric_name Metric name
#' @param value Metric value
#' @param labels Label values
set_gauge_value <- function(metric_name, value, labels = list()) {
  if (metric_name %in% names(prometheus_state$metrics)) {
    metric <- prometheus_state$metrics[[metric_name]]
    
    # Create label key
    label_key <- create_label_key(labels)
    
    # Set value
    metric$values[[label_key]] <- list(
      value = value,
      labels = labels,
      timestamp = Sys.time()
    )
    
    prometheus_state$metrics[[metric_name]] <<- metric
  }
}

#' Increment counter metric
#' @param metric_name Metric name
#' @param increment Increment value
#' @param labels Label values
increment_counter <- function(metric_name, increment = 1, labels = list()) {
  if (metric_name %in% names(prometheus_state$metrics)) {
    metric <- prometheus_state$metrics[[metric_name]]
    
    label_key <- create_label_key(labels)
    
    current_value <- metric$values[[label_key]]$value %||% 0
    
    metric$values[[label_key]] <- list(
      value = current_value + increment,
      labels = labels,
      timestamp = Sys.time()
    )
    
    prometheus_state$metrics[[metric_name]] <<- metric
  }
}

#' Add histogram observation
#' @param metric_name Metric name
#' @param value Observed value
#' @param labels Label values
observe_histogram <- function(metric_name, value, labels = list()) {
  if (metric_name %in% names(prometheus_state$metrics)) {
    metric <- prometheus_state$metrics[[metric_name]]
    
    label_key <- create_label_key(labels)
    
    if (is.null(metric$values[[label_key]])) {
      metric$values[[label_key]] <- list(
        buckets = rep(0, length(metric$buckets) + 1),  # +1 for +Inf bucket
        sum = 0,
        count = 0,
        labels = labels
      )
    }
    
    # Update histogram buckets
    bucket_data <- metric$values[[label_key]]
    
    for (i in seq_along(metric$buckets)) {
      if (value <= metric$buckets[i]) {
        bucket_data$buckets[i] <- bucket_data$buckets[i] + 1
      }
    }
    
    # +Inf bucket
    bucket_data$buckets[length(bucket_data$buckets)] <- bucket_data$buckets[length(bucket_data$buckets)] + 1
    
    # Update sum and count
    bucket_data$sum <- bucket_data$sum + value
    bucket_data$count <- bucket_data$count + 1
    
    metric$values[[label_key]] <- bucket_data
    prometheus_state$metrics[[metric_name]] <<- metric
  }
}

#' Create label key from labels
#' @param labels Label list
#' @return Label key string
create_label_key <- function(labels) {
  if (length(labels) == 0) {
    return("__default__")
  }
  
  sorted_labels <- labels[order(names(labels))]
  paste(names(sorted_labels), sorted_labels, sep = "=", collapse = ",")
}

#' Generate Prometheus format output
#' @return Prometheus format string
generate_prometheus_output <- function() {
  output_lines <- c()
  
  for (metric_name in names(prometheus_state$metrics)) {
    metric <- prometheus_state$metrics[[metric_name]]
    
    # Add HELP and TYPE
    output_lines <- c(output_lines, paste0("# HELP ", metric_name, " ", metric$help))
    output_lines <- c(output_lines, paste0("# TYPE ", metric_name, " ", metric$type))
    
    # Add metric values
    if (metric$type == "histogram") {
      output_lines <- c(output_lines, format_histogram_metric(metric_name, metric))
    } else {
      output_lines <- c(output_lines, format_simple_metric(metric_name, metric))
    }
    
    output_lines <- c(output_lines, "")  # Empty line between metrics
  }
  
  paste(output_lines, collapse = "\n")
}

#' Format simple metric (counter/gauge)
#' @param metric_name Metric name
#' @param metric Metric object
#' @return Formatted metric lines
format_simple_metric <- function(metric_name, metric) {
  lines <- c()
  
  for (label_key in names(metric$values)) {
    value_data <- metric$values[[label_key]]
    
    # Format labels
    if (length(value_data$labels) > 0) {
      label_str <- paste0("{", paste(names(value_data$labels), "=\"", value_data$labels, "\"", sep = "", collapse = ","), "}")
    } else {
      label_str <- ""
    }
    
    # Add metric line
    lines <- c(lines, paste0(metric_name, label_str, " ", value_data$value))
  }
  
  return(lines)
}

#' Format histogram metric
#' @param metric_name Metric name
#' @param metric Metric object
#' @return Formatted histogram lines
format_histogram_metric <- function(metric_name, metric) {
  lines <- c()
  
  for (label_key in names(metric$values)) {
    bucket_data <- metric$values[[label_key]]
    
    # Format base labels
    if (length(bucket_data$labels) > 0) {
      base_labels <- paste(names(bucket_data$labels), "=\"", bucket_data$labels, "\"", sep = "", collapse = ",")
    } else {
      base_labels <- ""
    }
    
    # Add bucket metrics
    for (i in seq_along(metric$buckets)) {
      bucket_label <- if (base_labels != "") {
        paste0("{", base_labels, ",le=\"", metric$buckets[i], "\"}")
      } else {
        paste0("{le=\"", metric$buckets[i], "\"}")
      }
      
      lines <- c(lines, paste0(metric_name, "_bucket", bucket_label, " ", bucket_data$buckets[i]))
    }
    
    # +Inf bucket
    inf_label <- if (base_labels != "") {
      paste0("{", base_labels, ",le=\"+Inf\"}")
    } else {
      "{le=\"+Inf\"}"
    }
    lines <- c(lines, paste0(metric_name, "_bucket", inf_label, " ", bucket_data$buckets[length(bucket_data$buckets)]))
    
    # Sum and count
    sum_label <- if (base_labels != "") paste0("{", base_labels, "}") else ""
    lines <- c(lines, paste0(metric_name, "_sum", sum_label, " ", bucket_data$sum))
    lines <- c(lines, paste0(metric_name, "_count", sum_label, " ", bucket_data$count))
  }
  
  return(lines)
}

#' Start metrics collection background process
start_metrics_collection <- function() {
  # Start background process to collect metrics
  future::future({
    while (TRUE) {
      tryCatch({
        update_all_metrics()
        Sys.sleep(PROMETHEUS_CONFIG$update_interval_seconds)
      }, error = function(e) {
        log_event(paste("Metrics collection error:", e$message), "ERROR")
        Sys.sleep(60)  # Wait longer on error
      })
    }
  })
}

#' Get CPU usage (simplified implementation)
#' @return CPU usage percentage
get_cpu_usage <- function() {
  # Simplified CPU usage calculation
  # In production, this would use system calls or external tools
  return(runif(1, 0, 100))
}

#' Record HTTP request metric
#' @param method HTTP method
#' @param endpoint Endpoint path
#' @param status HTTP status code
#' @param duration Request duration
record_http_request <- function(method, endpoint, status, duration) {
  increment_counter("http_requests_total", 1, list(method = method, endpoint = endpoint, status = as.character(status)))
  observe_histogram("http_request_duration_seconds", duration, list(method = method, endpoint = endpoint))
}

#' Record search request metric
#' @param type Search type
#' @param duration Search duration
#' @param results_count Number of results
#' @param status Request status
record_search_request <- function(type, duration, results_count, status = "success") {
  increment_counter("search_requests_total", 1, list(type = type, status = status))
  observe_histogram("search_duration_seconds", duration, list(type = type))
  observe_histogram("search_results_returned", results_count, list(type = type))
}

#' Record AI request metric
#' @param provider AI provider
#' @param operation Operation type
#' @param duration Request duration
#' @param status Request status
record_ai_request <- function(provider, operation, duration, status = "success") {
  increment_counter("ai_requests_total", 1, list(provider = provider, operation = operation, status = status))
  observe_histogram("ai_request_duration_seconds", duration, list(provider = provider, operation = operation))
}

#' Stop metrics server
stop_metrics_server <- function() {
  if (!is.null(prometheus_state$server)) {
    httpuv::stopServer(prometheus_state$server)
    prometheus_state$server <<- NULL
    log_event("Prometheus metrics server stopped", "INFO")
  }
}