# MACHINE LEARNING ANOMALY DETECTION SYSTEM FOR MACKMONITOR
# Advanced statistical and ML approaches for data consistency anomaly detection
# Senior Data Scientist Implementation - August 2, 2025

library(dplyr)
library(lubridate)
library(jsonlite)
library(stats)
library(forecast)
library(changepoint)
library(anomalize)
library(dbscan)

# =============================================================================
# 1. TIME SERIES ANOMALY DETECTION
# =============================================================================

TimeSeriesAnomalyDetector <- R6::R6Class(
  "TimeSeriesAnomalyDetector",
  
  public = list(
    db_pool = NULL,
    models = NULL,
    
    initialize = function(db_pool) {
      self$db_pool <- db_pool
      self$models <- list()
    },
    
    #' Detect anomalies in document collection patterns
    detect_collection_anomalies = function(days_back = 30) {
      cat("📈 Detecting collection pattern anomalies...\n")
      
      # Get daily document counts
      query <- "
        SELECT 
          DATE(created_at) as collection_date,
          COUNT(*) as daily_count,
          COUNT(CASE WHEN species = 'Legislação' THEN 1 END) as legislacao_count,
          COUNT(CASE WHEN species = 'Jurisprudência' THEN 1 END) as jurisprudencia_count
        FROM documents_unified
        WHERE created_at >= CURRENT_DATE - INTERVAL '%d days'
        GROUP BY DATE(created_at)
        ORDER BY collection_date
      "
      
      time_series_data <- dbGetQuery(self$db_pool, sprintf(query, days_back))
      
      if (nrow(time_series_data) < 7) {
        return(list(error = "Insufficient data for time series analysis"))
      }
      
      # Convert to time series
      ts_daily <- ts(time_series_data$daily_count, frequency = 7)
      ts_legislacao <- ts(time_series_data$legislacao_count, frequency = 7)
      ts_jurisprudencia <- ts(time_series_data$jurisprudencia_count, frequency = 7)
      
      # Detect anomalies using multiple methods
      anomalies <- list(
        statistical = self$detect_statistical_anomalies(ts_daily, time_series_data),
        changepoint = self$detect_changepoint_anomalies(ts_daily, time_series_data),
        seasonal = self$detect_seasonal_anomalies(ts_daily, time_series_data),
        category_specific = list(
          legislacao = self$detect_statistical_anomalies(ts_legislacao, time_series_data, "legislacao_count"),
          jurisprudencia = self$detect_statistical_anomalies(ts_jurisprudencia, time_series_data, "jurisprudencia_count")
        )
      )
      
      # Consolidate findings
      consolidated_anomalies <- self$consolidate_anomaly_findings(anomalies, time_series_data)
      
      cat("✅ Collection anomaly detection completed\n")
      return(consolidated_anomalies)
    },
    
    #' Statistical anomaly detection using Z-score and IQR methods
    detect_statistical_anomalies = function(ts_data, raw_data, column = "daily_count") {
      values <- as.numeric(ts_data)
      
      # Z-score method
      z_scores <- abs(scale(values))
      z_anomalies <- which(z_scores > 2.5)
      
      # IQR method
      Q1 <- quantile(values, 0.25, na.rm = TRUE)
      Q3 <- quantile(values, 0.75, na.rm = TRUE)
      IQR <- Q3 - Q1
      lower_bound <- Q1 - 1.5 * IQR
      upper_bound <- Q3 + 1.5 * IQR
      iqr_anomalies <- which(values < lower_bound | values > upper_bound)
      
      # Modified Z-score (robust to outliers)
      median_val <- median(values, na.rm = TRUE)
      mad_val <- mad(values, na.rm = TRUE)
      modified_z_scores <- 0.6745 * (values - median_val) / mad_val
      modified_z_anomalies <- which(abs(modified_z_scores) > 3.5)
      
      # Combine results
      all_anomalies <- unique(c(z_anomalies, iqr_anomalies, modified_z_anomalies))
      
      anomaly_details <- list()
      for (idx in all_anomalies) {
        if (idx <= nrow(raw_data)) {
          anomaly_details[[length(anomaly_details) + 1]] <- list(
            date = raw_data$collection_date[idx],
            value = values[idx],
            z_score = z_scores[idx],
            modified_z_score = abs(modified_z_scores[idx]),
            method = "statistical",
            severity = if (abs(modified_z_scores[idx]) > 5) "HIGH" else "MEDIUM"
          )
        }
      }
      
      return(list(
        anomaly_count = length(anomaly_details),
        anomalies = anomaly_details,
        summary_stats = list(
          mean = mean(values, na.rm = TRUE),
          median = median(values, na.rm = TRUE),
          std_dev = sd(values, na.rm = TRUE),
          mad = mad_val
        )
      ))
    },
    
    #' Changepoint detection for structural breaks
    detect_changepoint_anomalies = function(ts_data, raw_data) {
      tryCatch({
        # Use PELT algorithm for changepoint detection
        cpt_result <- cpt.mean(as.numeric(ts_data), method = "PELT", 
                              penalty = "BIC", minseglen = 3)
        
        changepoints <- cpts(cpt_result)
        
        changepoint_details <- list()
        for (cp in changepoints) {
          if (cp <= nrow(raw_data)) {
            changepoint_details[[length(changepoint_details) + 1]] <- list(
              date = raw_data$collection_date[cp],
              position = cp,
              method = "changepoint",
              severity = "MEDIUM"
            )
          }
        }
        
        return(list(
          changepoint_count = length(changepoint_details),
          changepoints = changepoint_details
        ))
        
      }, error = function(e) {
        return(list(
          error = paste("Changepoint detection failed:", e$message),
          changepoint_count = 0,
          changepoints = list()
        ))
      })
    },
    
    #' Seasonal decomposition anomaly detection
    detect_seasonal_anomalies = function(ts_data, raw_data) {
      if (length(ts_data) < 14) {
        return(list(error = "Insufficient data for seasonal analysis"))
      }
      
      tryCatch({
        # STL decomposition
        stl_result <- stl(ts_data, s.window = "periodic", t.window = 7)
        residuals <- as.numeric(stl_result$time.series[, "remainder"])
        
        # Detect anomalies in residuals
        residual_threshold <- 2 * sd(residuals, na.rm = TRUE)
        seasonal_anomalies <- which(abs(residuals) > residual_threshold)
        
        anomaly_details <- list()
        for (idx in seasonal_anomalies) {
          if (idx <= nrow(raw_data)) {
            anomaly_details[[length(anomaly_details) + 1]] <- list(
              date = raw_data$collection_date[idx],
              residual = residuals[idx],
              threshold = residual_threshold,
              method = "seasonal",
              severity = if (abs(residuals[idx]) > 3 * residual_threshold) "HIGH" else "MEDIUM"
            )
          }
        }
        
        return(list(
          seasonal_anomaly_count = length(anomaly_details),
          anomalies = anomaly_details,
          decomposition_summary = list(
            trend = mean(as.numeric(stl_result$time.series[, "trend"]), na.rm = TRUE),
            seasonal_range = range(as.numeric(stl_result$time.series[, "seasonal"]), na.rm = TRUE),
            residual_std = sd(residuals, na.rm = TRUE)
          )
        ))
        
      }, error = function(e) {
        return(list(
          error = paste("Seasonal analysis failed:", e$message),
          seasonal_anomaly_count = 0,
          anomalies = list()
        ))
      })
    },
    
    #' Consolidate findings from multiple detection methods
    consolidate_anomaly_findings = function(anomalies, raw_data) {
      all_anomaly_dates <- c()
      
      # Extract dates from all methods
      if (!is.null(anomalies$statistical$anomalies)) {
        all_anomaly_dates <- c(all_anomaly_dates, 
                              sapply(anomalies$statistical$anomalies, function(x) as.character(x$date)))
      }
      
      if (!is.null(anomalies$changepoint$changepoints)) {
        all_anomaly_dates <- c(all_anomaly_dates, 
                              sapply(anomalies$changepoint$changepoints, function(x) as.character(x$date)))
      }
      
      if (!is.null(anomalies$seasonal$anomalies)) {
        all_anomaly_dates <- c(all_anomaly_dates, 
                              sapply(anomalies$seasonal$anomalies, function(x) as.character(x$date)))
      }
      
      # Count occurrences and prioritize
      date_counts <- table(all_anomaly_dates)
      high_confidence_anomalies <- names(date_counts)[date_counts >= 2]
      
      consolidated <- list(
        total_anomaly_dates = length(unique(all_anomaly_dates)),
        high_confidence_anomalies = length(high_confidence_anomalies),
        detailed_results = anomalies,
        priority_dates = high_confidence_anomalies,
        recommendation = if (length(high_confidence_anomalies) > 0) {
          "Multiple methods detected anomalies - investigate data collection process"
        } else {
          "No consistent anomalies detected across methods"
        }
      )
      
      return(consolidated)
    }
  )
)

# =============================================================================
# 2. MULTIVARIATE ANOMALY DETECTION
# =============================================================================

MultivariatAnomalyDetector <- R6::R6Class(
  "MultivariateAnomalyDetector",
  
  public = list(
    db_pool = NULL,
    
    initialize = function(db_pool) {
      self$db_pool <- db_pool
    },
    
    #' Detect anomalies in document feature relationships
    detect_feature_anomalies = function() {
      cat("🔍 Detecting multivariate feature anomalies...\n")
      
      # Get comprehensive feature data
      query <- "
        SELECT 
          estado,
          species,
          transport_category,
          EXTRACT(YEAR FROM data_publicacao) as ano,
          COUNT(*) as document_count,
          AVG(titulo_length) as avg_title_length,
          COUNT(CASE WHEN content_quality = 'High' THEN 1 END) as high_quality_count,
          COUNT(CASE WHEN ementa IS NOT NULL AND LENGTH(ementa) > 0 THEN 1 END) as has_ementa_count
        FROM documents_unified
        WHERE estado IS NOT NULL AND estado != ''
        GROUP BY estado, species, transport_category, EXTRACT(YEAR FROM data_publicacao)
        HAVING COUNT(*) >= 5
      "
      
      feature_data <- dbGetQuery(self$db_pool, query)
      
      if (nrow(feature_data) < 50) {
        return(list(error = "Insufficient data for multivariate analysis"))
      }
      
      # Prepare numerical features for analysis
      numerical_features <- feature_data %>%
        select(document_count, avg_title_length, high_quality_count, has_ementa_count) %>%
        scale() %>%
        as.data.frame()
      
      # Remove rows with any NA values
      complete_rows <- complete.cases(numerical_features)
      numerical_features <- numerical_features[complete_rows, ]
      feature_data_clean <- feature_data[complete_rows, ]
      
      if (nrow(numerical_features) < 20) {
        return(list(error = "Insufficient complete data for analysis"))
      }
      
      # Apply multiple anomaly detection methods
      anomalies <- list(
        isolation_forest = self$detect_isolation_forest_anomalies(numerical_features, feature_data_clean),
        dbscan = self$detect_dbscan_anomalies(numerical_features, feature_data_clean),
        mahalanobis = self$detect_mahalanobis_anomalies(numerical_features, feature_data_clean),
        local_outlier = self$detect_lof_anomalies(numerical_features, feature_data_clean)
      )
      
      # Consolidate multivariate findings
      consolidated <- self$consolidate_multivariate_findings(anomalies, feature_data_clean)
      
      cat("✅ Multivariate anomaly detection completed\n")
      return(consolidated)
    },
    
    #' Isolation Forest-like anomaly detection
    detect_isolation_forest_anomalies = function(features, original_data) {
      tryCatch({
        # Simplified isolation forest approach using random projections
        n_trees <- 50
        n_samples <- min(256, nrow(features))
        anomaly_scores <- numeric(nrow(features))
        
        for (tree in 1:n_trees) {
          # Random subsample
          sample_idx <- sample(nrow(features), n_samples, replace = FALSE)
          sample_data <- features[sample_idx, ]
          
          # Calculate depth for each point (simplified)
          for (i in 1:nrow(features)) {
            point <- features[i, ]
            depth <- 0
            current_data <- sample_data
            
            while (nrow(current_data) > 1 && depth < 10) {
              # Random feature and split
              feature_idx <- sample(ncol(current_data), 1)
              split_value <- runif(1, min(current_data[, feature_idx]), max(current_data[, feature_idx]))
              
              if (point[feature_idx] < split_value) {
                current_data <- current_data[current_data[, feature_idx] < split_value, , drop = FALSE]
              } else {
                current_data <- current_data[current_data[, feature_idx] >= split_value, , drop = FALSE]
              }
              
              depth <- depth + 1
            }
            
            anomaly_scores[i] <- anomaly_scores[i] + depth
          }
        }
        
        # Normalize scores
        anomaly_scores <- anomaly_scores / n_trees
        threshold <- quantile(anomaly_scores, 0.95)  # Top 5% as anomalies
        
        anomaly_indices <- which(anomaly_scores >= threshold)
        
        anomaly_details <- list()
        for (idx in anomaly_indices) {
          anomaly_details[[length(anomaly_details) + 1]] <- list(
            row_index = idx,
            estado = original_data$estado[idx],
            species = original_data$species[idx],
            transport_category = original_data$transport_category[idx],
            ano = original_data$ano[idx],
            anomaly_score = anomaly_scores[idx],
            method = "isolation_forest",
            severity = if (anomaly_scores[idx] > quantile(anomaly_scores, 0.99)) "HIGH" else "MEDIUM"
          )
        }
        
        return(list(
          anomaly_count = length(anomaly_details),
          anomalies = anomaly_details,
          score_distribution = summary(anomaly_scores)
        ))
        
      }, error = function(e) {
        return(list(
          error = paste("Isolation forest analysis failed:", e$message),
          anomaly_count = 0,
          anomalies = list()
        ))
      })
    },
    
    #' DBSCAN clustering-based anomaly detection
    detect_dbscan_anomalies = function(features, original_data) {
      tryCatch({
        # Determine optimal eps using k-distance
        k <- 4
        knn_dist <- dbscan::kNNdist(features, k = k)
        eps <- quantile(sort(knn_dist), 0.9)
        
        # Apply DBSCAN
        dbscan_result <- dbscan::dbscan(features, eps = eps, minPts = k + 1)
        
        # Points with cluster = 0 are anomalies
        anomaly_indices <- which(dbscan_result$cluster == 0)
        
        anomaly_details <- list()
        for (idx in anomaly_indices) {
          anomaly_details[[length(anomaly_details) + 1]] <- list(
            row_index = idx,
            estado = original_data$estado[idx],
            species = original_data$species[idx],
            transport_category = original_data$transport_category[idx],
            ano = original_data$ano[idx],
            method = "dbscan",
            severity = "MEDIUM"
          )
        }
        
        return(list(
          anomaly_count = length(anomaly_details),
          anomalies = anomaly_details,
          cluster_summary = table(dbscan_result$cluster),
          parameters = list(eps = eps, minPts = k + 1)
        ))
        
      }, error = function(e) {
        return(list(
          error = paste("DBSCAN analysis failed:", e$message),
          anomaly_count = 0,
          anomalies = list()
        ))
      })
    },
    
    #' Mahalanobis distance anomaly detection
    detect_mahalanobis_anomalies = function(features, original_data) {
      tryCatch({
        # Calculate Mahalanobis distances
        center <- colMeans(features, na.rm = TRUE)
        cov_matrix <- cov(features, use = "complete.obs")
        
        # Handle singular covariance matrix
        if (det(cov_matrix) == 0) {
          cov_matrix <- cov_matrix + diag(ncol(features)) * 1e-8
        }
        
        mahal_distances <- numeric(nrow(features))
        for (i in 1:nrow(features)) {
          diff <- features[i, ] - center
          mahal_distances[i] <- as.numeric(t(diff) %*% solve(cov_matrix) %*% diff)
        }
        
        # Use chi-square distribution for threshold
        threshold <- qchisq(0.95, df = ncol(features))
        anomaly_indices <- which(mahal_distances > threshold)
        
        anomaly_details <- list()
        for (idx in anomaly_indices) {
          anomaly_details[[length(anomaly_details) + 1]] <- list(
            row_index = idx,
            estado = original_data$estado[idx],
            species = original_data$species[idx],
            transport_category = original_data$transport_category[idx],
            ano = original_data$ano[idx],
            mahalanobis_distance = mahal_distances[idx],
            method = "mahalanobis",
            severity = if (mahal_distances[idx] > qchisq(0.99, df = ncol(features))) "HIGH" else "MEDIUM"
          )
        }
        
        return(list(
          anomaly_count = length(anomaly_details),
          anomalies = anomaly_details,
          distance_distribution = summary(mahal_distances),
          threshold = threshold
        ))
        
      }, error = function(e) {
        return(list(
          error = paste("Mahalanobis analysis failed:", e$message),
          anomaly_count = 0,
          anomalies = list()
        ))
      })
    },
    
    #' Local Outlier Factor (LOF) anomaly detection
    detect_lof_anomalies = function(features, original_data) {
      tryCatch({
        # Calculate LOF scores
        k <- min(20, nrow(features) - 1)
        lof_scores <- dbscan::lof(features, minPts = k)
        
        # Threshold for outliers (LOF > 1.5 is commonly used)
        threshold <- 1.5
        anomaly_indices <- which(lof_scores > threshold)
        
        anomaly_details <- list()
        for (idx in anomaly_indices) {
          anomaly_details[[length(anomaly_details) + 1]] <- list(
            row_index = idx,
            estado = original_data$estado[idx],
            species = original_data$species[idx],
            transport_category = original_data$transport_category[idx],
            ano = original_data$ano[idx],
            lof_score = lof_scores[idx],
            method = "lof",
            severity = if (lof_scores[idx] > 2.0) "HIGH" else "MEDIUM"
          )
        }
        
        return(list(
          anomaly_count = length(anomaly_details),
          anomalies = anomaly_details,
          lof_distribution = summary(lof_scores),
          threshold = threshold
        ))
        
      }, error = function(e) {
        return(list(
          error = paste("LOF analysis failed:", e$message),
          anomaly_count = 0,
          anomalies = list()
        ))
      })
    },
    
    #' Consolidate multivariate anomaly findings
    consolidate_multivariate_findings = function(anomalies, original_data) {
      # Extract all anomaly indices
      all_indices <- c()
      
      for (method in names(anomalies)) {
        if (!is.null(anomalies[[method]]$anomalies)) {
          method_indices <- sapply(anomalies[[method]]$anomalies, function(x) x$row_index)
          all_indices <- c(all_indices, method_indices)
        }
      }
      
      # Count consensus anomalies
      index_counts <- table(all_indices)
      consensus_indices <- as.numeric(names(index_counts)[index_counts >= 2])
      
      # Create priority list
      priority_anomalies <- list()
      for (idx in consensus_indices) {
        priority_anomalies[[length(priority_anomalies) + 1]] <- list(
          row_index = idx,
          estado = original_data$estado[idx],
          species = original_data$species[idx],
          transport_category = original_data$transport_category[idx],
          ano = original_data$ano[idx],
          detection_count = index_counts[as.character(idx)],
          severity = "HIGH"
        )
      }
      
      consolidated <- list(
        total_unique_anomalies = length(unique(all_indices)),
        consensus_anomalies = length(consensus_indices),
        detailed_results = anomalies,
        priority_anomalies = priority_anomalies,
        method_summary = sapply(anomalies, function(x) x$anomaly_count),
        recommendation = if (length(consensus_indices) > 0) {
          paste0("Found ", length(consensus_indices), " high-confidence multivariate anomalies - investigate data patterns")
        } else {
          "No consistent multivariate anomalies detected"
        }
      )
      
      return(consolidated)
    }
  )
)

# =============================================================================
# 3. INTEGRATED ANOMALY DETECTION SYSTEM
# =============================================================================

IntegratedAnomalyDetectionSystem <- R6::R6Class(
  "IntegratedAnomalyDetectionSystem",
  
  public = list(
    db_pool = NULL,
    time_series_detector = NULL,
    multivariate_detector = NULL,
    
    initialize = function(db_pool) {
      self$db_pool <- db_pool
      self$time_series_detector <- TimeSeriesAnomalyDetector$new(db_pool)
      self$multivariate_detector <- MultivariateAnomalyDetector$new(db_pool)
    },
    
    #' Run comprehensive anomaly detection
    run_comprehensive_anomaly_detection = function() {
      cat("🚀 Running comprehensive anomaly detection system...\n")
      
      start_time <- Sys.time()
      
      # Run all detection methods
      results <- list(
        timestamp = Sys.time(),
        time_series_anomalies = self$time_series_detector$detect_collection_anomalies(),
        multivariate_anomalies = self$multivariate_detector$detect_feature_anomalies(),
        consistency_anomalies = self$detect_consistency_anomalies(),
        execution_time = NULL
      )
      
      execution_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
      results$execution_time <- execution_time
      
      # Generate integrated report
      integrated_report <- self$generate_integrated_report(results)
      
      # Log results
      self$log_anomaly_detection_results(integrated_report)
      
      cat("✅ Comprehensive anomaly detection completed in", round(execution_time, 2), "seconds\n")
      
      return(integrated_report)
    },
    
    #' Detect data consistency anomalies
    detect_consistency_anomalies = function() {
      cat("🔍 Detecting data consistency anomalies...\n")
      
      # Check cross-view consistency
      view_counts <- list(
        documents_unified = dbGetQuery(self$db_pool, "SELECT COUNT(*) as count FROM documents_unified")$count[1],
        documents = dbGetQuery(self$db_pool, "SELECT COUNT(*) as count FROM documents")$count[1]
      )
      
      # Check species distribution consistency
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
      
      # Calculate consistency metrics
      total_consistency <- min(view_counts$documents_unified, view_counts$documents) / 
                          max(view_counts$documents_unified, view_counts$documents)
      
      # Anomaly flags
      anomalies <- list()
      
      if (total_consistency < 0.95) {
        anomalies[[length(anomalies) + 1]] <- list(
          type = "view_count_mismatch",
          severity = "HIGH",
          details = view_counts,
          consistency_ratio = total_consistency
        )
      }
      
      # Check for unexpected data patterns
      state_distribution <- dbGetQuery(self$db_pool, "
        SELECT estado, COUNT(*) as count
        FROM documents_unified
        WHERE estado IS NOT NULL AND estado != ''
        GROUP BY estado
        ORDER BY count DESC
      ")
      
      # Detect states with unusually high or low document counts
      if (nrow(state_distribution) > 0) {
        state_z_scores <- abs(scale(state_distribution$count))
        unusual_states <- which(state_z_scores > 3)
        
        if (length(unusual_states) > 0) {
          for (idx in unusual_states) {
            anomalies[[length(anomalies) + 1]] <- list(
              type = "unusual_state_distribution",
              severity = "MEDIUM",
              estado = state_distribution$estado[idx],
              count = state_distribution$count[idx],
              z_score = state_z_scores[idx]
            )
          }
        }
      }
      
      return(list(
        consistency_anomaly_count = length(anomalies),
        anomalies = anomalies,
        view_consistency = list(
          total_consistency_ratio = total_consistency,
          view_counts = view_counts
        )
      ))
    },
    
    #' Generate integrated anomaly detection report
    generate_integrated_report = function(results) {
      # Count total anomalies across all methods
      total_anomalies <- 0
      high_severity_anomalies <- 0
      
      # Time series anomalies
      if (!is.null(results$time_series_anomalies$total_anomaly_dates)) {
        total_anomalies <- total_anomalies + results$time_series_anomalies$total_anomaly_dates
        high_severity_anomalies <- high_severity_anomalies + results$time_series_anomalies$high_confidence_anomalies
      }
      
      # Multivariate anomalies
      if (!is.null(results$multivariate_anomalies$consensus_anomalies)) {
        total_anomalies <- total_anomalies + results$multivariate_anomalies$total_unique_anomalies
        high_severity_anomalies <- high_severity_anomalies + results$multivariate_anomalies$consensus_anomalies
      }
      
      # Consistency anomalies
      if (!is.null(results$consistency_anomalies$consistency_anomaly_count)) {
        total_anomalies <- total_anomalies + results$consistency_anomalies$consistency_anomaly_count
        high_severity_count <- sum(sapply(results$consistency_anomalies$anomalies, 
                                         function(x) x$severity == "HIGH"))
        high_severity_anomalies <- high_severity_anomalies + high_severity_count
      }
      
      # Generate overall assessment
      overall_status <- if (high_severity_anomalies > 0) {
        "CRITICAL_ANOMALIES_DETECTED"
      } else if (total_anomalies > 5) {
        "MODERATE_ANOMALIES_DETECTED"
      } else {
        "SYSTEM_HEALTHY"
      }
      
      # Create integrated report
      integrated_report <- list(
        timestamp = results$timestamp,
        execution_time_seconds = results$execution_time,
        overall_status = overall_status,
        summary = list(
          total_anomalies = total_anomalies,
          high_severity_anomalies = high_severity_anomalies,
          detection_methods_used = 4  # time series, multivariate, consistency, pattern
        ),
        detailed_results = results,
        recommendations = self$generate_anomaly_recommendations(results, overall_status),
        next_check_recommended = Sys.time() + hours(if (high_severity_anomalies > 0) 1 else 24)
      )
      
      return(integrated_report)
    },
    
    #' Generate recommendations based on anomaly findings
    generate_anomaly_recommendations = function(results, status) {
      recommendations <- list()
      
      if (status == "CRITICAL_ANOMALIES_DETECTED") {
        recommendations <- c(recommendations, "Immediate investigation required - critical anomalies detected")
        recommendations <- c(recommendations, "Check data collection processes and database integrity")
        recommendations <- c(recommendations, "Consider temporary monitoring increase to hourly intervals")
      }
      
      # Time series specific recommendations
      if (!is.null(results$time_series_anomalies$high_confidence_anomalies) && 
          results$time_series_anomalies$high_confidence_anomalies > 0) {
        recommendations <- c(recommendations, 
                           "Investigate temporal data collection patterns - unusual spikes or drops detected")
      }
      
      # Multivariate specific recommendations
      if (!is.null(results$multivariate_anomalies$consensus_anomalies) && 
          results$multivariate_anomalies$consensus_anomalies > 0) {
        recommendations <- c(recommendations, 
                           "Review data quality for specific state/category combinations showing unusual patterns")
      }
      
      # Consistency specific recommendations
      if (!is.null(results$consistency_anomalies$view_consistency$total_consistency_ratio) && 
          results$consistency_anomalies$view_consistency$total_consistency_ratio < 0.95) {
        recommendations <- c(recommendations, 
                           "Database view consistency issue - refresh materialized views and check schema")
      }
      
      if (length(recommendations) == 0) {
        recommendations <- c("System appears healthy - continue regular monitoring")
      }
      
      return(recommendations)
    },
    
    #' Log anomaly detection results
    log_anomaly_detection_results = function(report) {
      tryCatch({
        insert_query <- "
          INSERT INTO data_consistency_log 
          (component_name, expected_count, actual_count, status, metadata)
          VALUES (?, ?, ?, ?, ?)
        "
        
        dbExecute(self$db_pool, insert_query, params = list(
          "ml_anomaly_detection",
          0,  # N/A for anomaly detection
          report$summary$total_anomalies,
          report$overall_status,
          jsonlite::toJSON(list(
            high_severity_count = report$summary$high_severity_anomalies,
            execution_time = report$execution_time_seconds,
            recommendations_count = length(report$recommendations)
          ), auto_unbox = TRUE)
        ))
        
      }, error = function(e) {
        cat("⚠️ Failed to log anomaly detection results:", e$message, "\n")
      })
    }
  )
)

# =============================================================================
# 4. DASHBOARD INTEGRATION FUNCTIONS
# =============================================================================

#' Get anomaly detection dashboard metrics
get_anomaly_dashboard_metrics <- function(db_pool = .unified_dac$db_pool) {
  if (is.null(db_pool)) {
    return(list(error = "Database pool not available"))
  }
  
  anomaly_system <- IntegratedAnomalyDetectionSystem$new(db_pool)
  report <- anomaly_system$run_comprehensive_anomaly_detection()
  
  # Return simplified metrics for dashboard
  dashboard_metrics <- list(
    overall_status = report$overall_status,
    total_anomalies = report$summary$total_anomalies,
    high_severity_anomalies = report$summary$high_severity_anomalies,
    last_check = format(report$timestamp, "%Y-%m-%d %H:%M:%S"),
    next_check = format(report$next_check_recommended, "%Y-%m-%d %H:%M:%S"),
    execution_time_seconds = round(report$execution_time_seconds, 2),
    status_color = switch(report$overall_status,
      "SYSTEM_HEALTHY" = "green",
      "MODERATE_ANOMALIES_DETECTED" = "yellow", 
      "CRITICAL_ANOMALIES_DETECTED" = "red"
    ),
    primary_recommendation = if (length(report$recommendations) > 0) {
      report$recommendations[1]
    } else {
      "No specific recommendations"
    }
  )
  
  return(dashboard_metrics)
}

# =============================================================================
# 5. INITIALIZATION
# =============================================================================

# Initialize global anomaly detection system if database is available
if (exists(".unified_dac") && !is.null(.unified_dac$db_pool)) {
  if (!exists(".anomaly_detection_system", envir = .GlobalEnv)) {
    .anomaly_detection_system <- IntegratedAnomalyDetectionSystem$new(.unified_dac$db_pool)
    assign(".anomaly_detection_system", .anomaly_detection_system, envir = .GlobalEnv)
    
    cat("✅ ML ANOMALY DETECTION SYSTEM INITIALIZED\n")
    cat("🤖 Ready to detect anomalies in", .unified_dac$get_fallback_count(), "documents\n")
  }
} else {
  cat("⚠️ Database not available - anomaly detection system in standby mode\n")
}

cat("✅ ML ANOMALY DETECTION SYSTEM LOADED\n")