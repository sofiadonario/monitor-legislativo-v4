# DATA QUALITY MONITORING FRAMEWORK FOR MACKMONITOR
# Comprehensive statistical validation and monitoring system
# Senior Data Scientist Implementation - August 2, 2025

library(dplyr)
library(ggplot2)
library(lubridate)
library(jsonlite)
library(DBI)
library(stats)

# =============================================================================
# 1. DATA QUALITY METRICS CALCULATOR
# =============================================================================

DataQualityMetrics <- R6::R6Class(
  "DataQualityMetrics",
  
  public = list(
    db_pool = NULL,
    metrics_history = NULL,
    
    initialize = function(db_pool) {
      self$db_pool <- db_pool
      self$metrics_history <- data.frame()
    },
    
    #' Calculate comprehensive data quality metrics
    calculate_comprehensive_metrics = function() {
      cat("📊 Calculating comprehensive data quality metrics...\n")
      
      metrics <- list(
        timestamp = Sys.time(),
        completeness = self$calculate_completeness_metrics(),
        consistency = self$calculate_consistency_metrics(),
        accuracy = self$calculate_accuracy_metrics(),
        timeliness = self$calculate_timeliness_metrics(),
        validity = self$calculate_validity_metrics(),
        uniqueness = self$calculate_uniqueness_metrics()
      )
      
      # Log metrics to database
      self$log_metrics_to_database(metrics)
      
      # Update history
      self$metrics_history <- rbind(self$metrics_history, self$flatten_metrics(metrics))
      
      cat("✅ Data quality metrics calculated successfully\n")
      return(metrics)
    },
    
    #' Calculate data completeness metrics
    calculate_completeness_metrics = function() {
      query <- "
        SELECT 
          COUNT(*) as total_records,
          COUNT(titulo) as titulo_complete,
          COUNT(data_publicacao) as data_complete,
          COUNT(estado) as estado_complete,
          COUNT(ementa) as ementa_complete,
          COUNT(url) as url_complete,
          COUNT(urn) as urn_complete,
          COUNT(autor) as autor_complete,
          COUNT(authority) as authority_complete
        FROM documents_unified
      "
      
      result <- dbGetQuery(self$db_pool, query)
      total <- result$total_records[1]
      
      if (total == 0) return(list(error = "No data found"))
      
      completeness <- list(
        total_records = total,
        titulo_completeness = result$titulo_complete[1] / total,
        data_completeness = result$data_complete[1] / total,
        estado_completeness = result$estado_complete[1] / total,
        ementa_completeness = result$ementa_complete[1] / total,
        url_completeness = result$url_complete[1] / total,
        urn_completeness = result$urn_complete[1] / total,
        autor_completeness = result$autor_complete[1] / total,
        authority_completeness = result$authority_complete[1] / total,
        overall_completeness = mean(c(
          result$titulo_complete[1] / total,
          result$data_complete[1] / total,
          result$estado_complete[1] / total,
          result$ementa_complete[1] / total
        ))
      )
      
      return(completeness)
    },
    
    #' Calculate data consistency metrics across components
    calculate_consistency_metrics = function() {
      # Test consistency across different data access methods
      
      # Total count consistency
      total_unified <- dbGetQuery(self$db_pool, "SELECT COUNT(*) as count FROM documents_unified")$count[1]
      total_documents <- dbGetQuery(self$db_pool, "SELECT COUNT(*) as count FROM documents")$count[1]
      
      # Species distribution consistency
      species_unified <- dbGetQuery(self$db_pool, "
        SELECT species, COUNT(*) as count 
        FROM documents_unified 
        GROUP BY species ORDER BY species
      ")
      
      species_documents <- dbGetQuery(self$db_pool, "
        SELECT species, COUNT(*) as count 
        FROM documents 
        GROUP BY species ORDER BY species
      ")
      
      # State distribution consistency
      state_unified <- dbGetQuery(self$db_pool, "
        SELECT estado, COUNT(*) as count 
        FROM documents_unified 
        WHERE estado IS NOT NULL AND estado != ''
        GROUP BY estado ORDER BY estado
      ")
      
      # Calculate consistency ratios
      total_consistency <- min(total_unified, total_documents) / max(total_unified, total_documents)
      
      species_consistency <- if (nrow(species_unified) == nrow(species_documents)) {
        cor(species_unified$count, species_documents$count, use = "complete.obs")
      } else {
        0.0
      }
      
      consistency <- list(
        total_count_unified = total_unified,
        total_count_documents = total_documents,
        total_consistency_ratio = total_consistency,
        species_distribution_correlation = species_consistency,
        state_distribution_count = nrow(state_unified),
        consistency_score = mean(c(total_consistency, abs(species_consistency)), na.rm = TRUE)
      )
      
      return(consistency)
    },
    
    #' Calculate data accuracy metrics
    calculate_accuracy_metrics = function() {
      # Validate data against business rules
      
      query <- "
        SELECT 
          COUNT(*) as total_records,
          COUNT(CASE WHEN data_publicacao >= '1942-01-01' AND data_publicacao <= CURRENT_DATE + INTERVAL '1 year' THEN 1 END) as valid_dates,
          COUNT(CASE WHEN estado IN ('AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG','PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO') THEN 1 END) as valid_states,
          COUNT(CASE WHEN species IN ('Legislação','Jurisprudência','Doutrina','Outros','Proposições') THEN 1 END) as valid_species,
          COUNT(CASE WHEN transport_category IN ('Geral','Aéreo','Marítimo','Rodoviário') THEN 1 END) as valid_transport,
          COUNT(CASE WHEN LENGTH(titulo) >= 10 THEN 1 END) as valid_titles,
          COUNT(CASE WHEN url LIKE 'http%' OR url IS NULL THEN 1 END) as valid_urls
        FROM documents_unified
      "
      
      result <- dbGetQuery(self$db_pool, query)
      total <- result$total_records[1]
      
      if (total == 0) return(list(error = "No data found"))
      
      accuracy <- list(
        total_records = total,
        date_accuracy = result$valid_dates[1] / total,
        state_accuracy = result$valid_states[1] / total,
        species_accuracy = result$valid_species[1] / total,
        transport_accuracy = result$valid_transport[1] / total,
        title_accuracy = result$valid_titles[1] / total,
        url_accuracy = result$valid_urls[1] / total,
        overall_accuracy = mean(c(
          result$valid_dates[1] / total,
          result$valid_states[1] / total,
          result$valid_species[1] / total,
          result$valid_transport[1] / total
        ))
      )
      
      return(accuracy)
    },
    
    #' Calculate timeliness metrics
    calculate_timeliness_metrics = function() {
      query <- "
        SELECT 
          MIN(created_at) as oldest_created,
          MAX(created_at) as newest_created,
          MIN(data_publicacao) as oldest_document,
          MAX(data_publicacao) as newest_document,
          AVG(EXTRACT(EPOCH FROM (created_at - data_publicacao))) as avg_collection_delay_seconds
        FROM documents_unified
        WHERE created_at IS NOT NULL AND data_publicacao IS NOT NULL
      "
      
      result <- dbGetQuery(self$db_pool, query)
      
      timeliness <- list(
        data_collection_span_days = as.numeric(difftime(result$newest_created[1], result$oldest_created[1], units = "days")),
        document_temporal_span_years = as.numeric(difftime(result$newest_document[1], result$oldest_document[1], units = "days")) / 365.25,
        avg_collection_delay_days = result$avg_collection_delay_seconds[1] / (24 * 3600),
        data_freshness_score = 1 - min(1, as.numeric(difftime(Sys.time(), result$newest_created[1], units = "days")) / 30)
      )
      
      return(timeliness)
    },
    
    #' Calculate validity metrics
    calculate_validity_metrics = function() {
      # Statistical validation of data distributions
      
      query <- "
        SELECT 
          ano,
          species,
          transport_category,
          COUNT(*) as count
        FROM documents_unified
        WHERE ano IS NOT NULL AND ano BETWEEN 1942 AND EXTRACT(YEAR FROM CURRENT_DATE)
        GROUP BY ano, species, transport_category
        ORDER BY ano, species, transport_category
      "
      
      result <- dbGetQuery(self$db_pool, query)
      
      # Temporal distribution analysis
      temporal_dist <- result %>%
        group_by(ano) %>%
        summarise(total = sum(count), .groups = "drop")
      
      # Statistical tests for validity
      temporal_trend_test <- if (nrow(temporal_dist) > 2) {
        cor.test(temporal_dist$ano, temporal_dist$total, method = "spearman")$p.value < 0.05
      } else {
        FALSE
      }
      
      # Species distribution normality
      species_dist <- result %>%
        group_by(species) %>%
        summarise(total = sum(count), .groups = "drop")
      
      species_entropy <- -sum((species_dist$total / sum(species_dist$total)) * log(species_dist$total / sum(species_dist$total)))
      
      validity <- list(
        temporal_trend_significant = temporal_trend_test,
        species_diversity_entropy = species_entropy,
        temporal_coverage_years = nrow(temporal_dist),
        species_coverage_count = nrow(species_dist),
        validity_score = min(1, species_entropy / log(nrow(species_dist)))
      )
      
      return(validity)
    },
    
    #' Calculate uniqueness metrics
    calculate_uniqueness_metrics = function() {
      query <- "
        SELECT 
          COUNT(*) as total_records,
          COUNT(DISTINCT titulo) as unique_titles,
          COUNT(DISTINCT urn) as unique_urns,
          COUNT(DISTINCT url) as unique_urls,
          COUNT(DISTINCT CONCAT(titulo, data_publicacao, estado)) as unique_combinations
        FROM documents_unified
      "
      
      result <- dbGetQuery(self$db_pool, query)
      total <- result$total_records[1]
      
      if (total == 0) return(list(error = "No data found"))
      
      uniqueness <- list(
        total_records = total,
        title_uniqueness = result$unique_titles[1] / total,
        urn_uniqueness = result$unique_urns[1] / total,
        url_uniqueness = result$unique_urls[1] / total,
        combination_uniqueness = result$unique_combinations[1] / total,
        overall_uniqueness = mean(c(
          result$unique_titles[1] / total,
          result$unique_urns[1] / total,
          result$unique_combinations[1] / total
        ))
      )
      
      return(uniqueness)
    },
    
    #' Log metrics to database for historical tracking
    log_metrics_to_database = function(metrics) {
      tryCatch({
        # Flatten metrics for database storage
        flat_metrics <- self$flatten_metrics(metrics)
        
        insert_query <- "
          INSERT INTO data_consistency_log 
          (component_name, expected_count, actual_count, consistency_ratio, status, metadata)
          VALUES (?, ?, ?, ?, ?, ?)
        "
        
        dbExecute(self$db_pool, insert_query, params = list(
          "comprehensive_quality_check",
          279152,  # Expected count based on deployment
          flat_metrics$total_records,
          flat_metrics$consistency_score,
          if (flat_metrics$consistency_score > 0.95) "PASSED" else "WARNING",
          jsonlite::toJSON(metrics, auto_unbox = TRUE)
        ))
        
        cat("📝 Metrics logged to database\n")
      }, error = function(e) {
        cat("⚠️ Failed to log metrics:", e$message, "\n")
      })
    },
    
    #' Flatten nested metrics for easier analysis
    flatten_metrics = function(metrics) {
      flat <- list()
      
      for (category in names(metrics)) {
        if (category == "timestamp") {
          flat$timestamp <- metrics$timestamp
        } else if (is.list(metrics[[category]])) {
          for (metric in names(metrics[[category]])) {
            flat[[paste0(category, "_", metric)]] <- metrics[[category]][[metric]]
          }
        }
      }
      
      return(flat)
    },
    
    #' Generate data quality report
    generate_quality_report = function() {
      metrics <- self$calculate_comprehensive_metrics()
      
      report <- list(
        executive_summary = self$generate_executive_summary(metrics),
        detailed_metrics = metrics,
        recommendations = self$generate_recommendations(metrics),
        trend_analysis = self$analyze_trends()
      )
      
      return(report)
    },
    
    generate_executive_summary = function(metrics) {
      summary <- list(
        overall_score = round(mean(c(
          metrics$completeness$overall_completeness,
          metrics$consistency$consistency_score,
          metrics$accuracy$overall_accuracy,
          metrics$validity$validity_score,
          metrics$uniqueness$overall_uniqueness
        ), na.rm = TRUE) * 100, 2),
        
        total_documents = metrics$completeness$total_records,
        
        key_findings = list(
          completeness = paste0(round(metrics$completeness$overall_completeness * 100, 1), "% complete"),
          consistency = paste0(round(metrics$consistency$consistency_score * 100, 1), "% consistent"),
          accuracy = paste0(round(metrics$accuracy$overall_accuracy * 100, 1), "% accurate")
        ),
        
        status = if (mean(c(
          metrics$completeness$overall_completeness,
          metrics$consistency$consistency_score,
          metrics$accuracy$overall_accuracy
        ), na.rm = TRUE) > 0.85) "HEALTHY" else "NEEDS_ATTENTION"
      )
      
      return(summary)
    },
    
    generate_recommendations = function(metrics) {
      recommendations <- list()
      
      # Completeness recommendations
      if (metrics$completeness$overall_completeness < 0.8) {
        recommendations <- c(recommendations, "Improve data completeness, particularly for ementa and autor fields")
      }
      
      # Consistency recommendations
      if (metrics$consistency$consistency_score < 0.95) {
        recommendations <- c(recommendations, "Address data consistency issues between documents_unified and documents views")
      }
      
      # Accuracy recommendations
      if (metrics$accuracy$overall_accuracy < 0.9) {
        recommendations <- c(recommendations, "Implement stricter data validation rules for state codes and document types")
      }
      
      # Timeliness recommendations
      if (metrics$timeliness$data_freshness_score < 0.8) {
        recommendations <- c(recommendations, "Update data collection frequency to improve freshness")
      }
      
      # Uniqueness recommendations
      if (metrics$uniqueness$overall_uniqueness < 0.95) {
        recommendations <- c(recommendations, "Investigate and resolve duplicate records")
      }
      
      return(recommendations)
    },
    
    analyze_trends = function() {
      if (nrow(self$metrics_history) < 2) {
        return(list(message = "Insufficient historical data for trend analysis"))
      }
      
      # Analyze trends in key metrics
      trends <- list()
      
      if ("completeness_overall_completeness" %in% names(self$metrics_history)) {
        completeness_trend <- lm(completeness_overall_completeness ~ seq_along(completeness_overall_completeness), 
                               data = self$metrics_history)
        trends$completeness_trend <- coef(completeness_trend)[2]
      }
      
      if ("consistency_consistency_score" %in% names(self$metrics_history)) {
        consistency_trend <- lm(consistency_consistency_score ~ seq_along(consistency_consistency_score), 
                              data = self$metrics_history)
        trends$consistency_trend <- coef(consistency_trend)[2]
      }
      
      return(trends)
    }
  )
)

# =============================================================================
# 2. REAL-TIME MONITORING SYSTEM
# =============================================================================

DataQualityMonitor <- R6::R6Class(
  "DataQualityMonitor",
  
  public = list(
    db_pool = NULL,
    metrics_calculator = NULL,
    alert_thresholds = NULL,
    
    initialize = function(db_pool) {
      self$db_pool <- db_pool
      self$metrics_calculator <- DataQualityMetrics$new(db_pool)
      
      # Set alert thresholds
      self$alert_thresholds <- list(
        completeness_min = 0.8,
        consistency_min = 0.95,
        accuracy_min = 0.9,
        total_count_min = 100000,
        total_count_max = 500000
      )
    },
    
    #' Run comprehensive monitoring check
    run_monitoring_check = function() {
      cat("🔍 Running comprehensive data quality monitoring check...\n")
      
      start_time <- Sys.time()
      
      # Calculate metrics
      metrics <- self$metrics_calculator$calculate_comprehensive_metrics()
      
      # Check for alerts
      alerts <- self$check_for_alerts(metrics)
      
      # Log performance
      execution_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
      self$log_monitoring_performance(execution_time, alerts)
      
      # Generate monitoring report
      monitoring_report <- list(
        timestamp = Sys.time(),
        execution_time_seconds = execution_time,
        metrics = metrics,
        alerts = alerts,
        status = if (length(alerts) == 0) "HEALTHY" else "ALERTS_DETECTED"
      )
      
      cat("✅ Monitoring check completed in", round(execution_time, 2), "seconds\n")
      
      return(monitoring_report)
    },
    
    #' Check for data quality alerts
    check_for_alerts = function(metrics) {
      alerts <- list()
      
      # Completeness alerts
      if (metrics$completeness$overall_completeness < self$alert_thresholds$completeness_min) {
        alerts <- c(alerts, list(list(
          type = "COMPLETENESS_LOW",
          severity = "WARNING",
          message = paste0("Data completeness below threshold: ", 
                          round(metrics$completeness$overall_completeness * 100, 1), "%"),
          threshold = self$alert_thresholds$completeness_min,
          actual_value = metrics$completeness$overall_completeness
        )))
      }
      
      # Consistency alerts
      if (metrics$consistency$consistency_score < self$alert_thresholds$consistency_min) {
        alerts <- c(alerts, list(list(
          type = "CONSISTENCY_LOW",
          severity = "CRITICAL",
          message = paste0("Data consistency below threshold: ", 
                          round(metrics$consistency$consistency_score * 100, 1), "%"),
          threshold = self$alert_thresholds$consistency_min,
          actual_value = metrics$consistency$consistency_score
        )))
      }
      
      # Accuracy alerts
      if (metrics$accuracy$overall_accuracy < self$alert_thresholds$accuracy_min) {
        alerts <- c(alerts, list(list(
          type = "ACCURACY_LOW",
          severity = "WARNING",
          message = paste0("Data accuracy below threshold: ", 
                          round(metrics$accuracy$overall_accuracy * 100, 1), "%"),
          threshold = self$alert_thresholds$accuracy_min,
          actual_value = metrics$accuracy$overall_accuracy
        )))
      }
      
      # Total count alerts
      total_count <- metrics$completeness$total_records
      if (total_count < self$alert_thresholds$total_count_min || 
          total_count > self$alert_thresholds$total_count_max) {
        alerts <- c(alerts, list(list(
          type = "TOTAL_COUNT_ANOMALY",
          severity = "CRITICAL",
          message = paste0("Total document count outside expected range: ", 
                          format(total_count, big.mark = ",")),
          expected_range = paste0(format(self$alert_thresholds$total_count_min, big.mark = ","), 
                                " - ", format(self$alert_thresholds$total_count_max, big.mark = ",")),
          actual_value = total_count
        )))
      }
      
      return(alerts)
    },
    
    #' Log monitoring performance metrics
    log_monitoring_performance = function(execution_time, alerts) {
      tryCatch({
        insert_query <- "
          INSERT INTO query_performance_log 
          (query_type, execution_time_ms, rows_returned, metadata)
          VALUES (?, ?, ?, ?)
        "
        
        dbExecute(self$db_pool, insert_query, params = list(
          "monitoring_check",
          round(execution_time * 1000),
          length(alerts),
          jsonlite::toJSON(list(
            alert_count = length(alerts),
            timestamp = as.character(Sys.time())
          ), auto_unbox = TRUE)
        ))
      }, error = function(e) {
        cat("⚠️ Failed to log monitoring performance:", e$message, "\n")
      })
    },
    
    #' Schedule automated monitoring
    schedule_monitoring = function(interval_minutes = 15) {
      cat("⏰ Scheduling automated monitoring every", interval_minutes, "minutes\n")
      
      # This would integrate with a job scheduler in production
      # For now, we provide the framework
      
      monitoring_job <- function() {
        tryCatch({
          report <- self$run_monitoring_check()
          
          # Send alerts if any
          if (length(report$alerts) > 0) {
            self$send_alerts(report$alerts)
          }
          
        }, error = function(e) {
          cat("❌ Scheduled monitoring failed:", e$message, "\n")
        })
      }
      
      return(monitoring_job)
    },
    
    #' Send alerts (placeholder for integration)
    send_alerts = function(alerts) {
      cat("🚨 ALERTS DETECTED:\n")
      
      for (i in seq_along(alerts)) {
        alert <- alerts[[i]]
        cat("  ", alert$severity, ":", alert$type, "-", alert$message, "\n")
      }
      
      # In production, integrate with:
      # - Email notifications
      # - Slack/Teams webhooks
      # - SMS alerts for critical issues
      # - Dashboard notifications
    }
  )
)

# =============================================================================
# 3. DASHBOARD INTEGRATION FUNCTIONS
# =============================================================================

#' Get current data quality dashboard metrics
get_data_quality_dashboard_metrics <- function(db_pool = .unified_dac$db_pool) {
  if (is.null(db_pool)) {
    return(list(error = "Database pool not available"))
  }
  
  metrics_calc <- DataQualityMetrics$new(db_pool)
  metrics <- metrics_calc$calculate_comprehensive_metrics()
  
  # Return simplified metrics for dashboard display
  dashboard_metrics <- list(
    overall_score = round(mean(c(
      metrics$completeness$overall_completeness,
      metrics$consistency$consistency_score,
      metrics$accuracy$overall_accuracy
    ), na.rm = TRUE) * 100, 1),
    
    total_documents = format(metrics$completeness$total_records, big.mark = ","),
    
    completeness_score = round(metrics$completeness$overall_completeness * 100, 1),
    consistency_score = round(metrics$consistency$consistency_score * 100, 1),
    accuracy_score = round(metrics$accuracy$overall_accuracy * 100, 1),
    
    status = if (metrics$consistency$consistency_score > 0.95) "HEALTHY" else "ATTENTION_NEEDED",
    last_updated = format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  )
  
  return(dashboard_metrics)
}

#' Validate cross-component consistency
validate_dashboard_consistency <- function(overview_count, map_count, analytics_count) {
  tolerance <- 0.05  # 5% tolerance
  
  counts <- c(overview_count, map_count, analytics_count)
  max_count <- max(counts, na.rm = TRUE)
  min_count <- min(counts, na.rm = TRUE)
  
  if (max_count == 0) {
    return(list(
      consistent = FALSE,
      message = "No data found in components",
      consistency_ratio = 0
    ))
  }
  
  consistency_ratio <- min_count / max_count
  
  result <- list(
    consistent = consistency_ratio >= (1 - tolerance),
    consistency_ratio = round(consistency_ratio, 4),
    counts = list(
      overview = overview_count,
      map = map_count,
      analytics = analytics_count
    ),
    message = if (consistency_ratio >= (1 - tolerance)) {
      "Components are consistent"
    } else {
      paste0("Consistency issue detected. Ratio: ", round(consistency_ratio, 4))
    }
  )
  
  return(result)
}

# =============================================================================
# 4. INITIALIZATION
# =============================================================================

# Initialize global monitoring system if database is available
if (exists(".unified_dac") && !is.null(.unified_dac$db_pool)) {
  if (!exists(".data_quality_monitor", envir = .GlobalEnv)) {
    .data_quality_monitor <- DataQualityMonitor$new(.unified_dac$db_pool)
    assign(".data_quality_monitor", .data_quality_monitor, envir = .GlobalEnv)
    
    cat("✅ DATA QUALITY MONITORING FRAMEWORK INITIALIZED\n")
    cat("📊 Ready to monitor", .unified_dac$get_fallback_count(), "documents\n")
  }
} else {
  cat("⚠️ Database not available - monitoring framework in standby mode\n")
}

cat("✅ DATA QUALITY MONITORING FRAMEWORK LOADED\n")