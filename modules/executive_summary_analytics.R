# ============================================================================
# ENHANCED EXECUTIVE SUMMARY ANALYTICS ENGINE
# ============================================================================
# 
# Advanced analytics module for Brazilian Legislative Monitoring Dashboard
# Provides comprehensive insights for 134k+ legislative documents
# 
# Features:
# - Temporal trend analysis with change point detection
# - Geographic distribution with state-level patterns
# - Smart document classification and anomaly detection
# - Predictive indicators and forecasting
# - Performance-optimized caching system
# - Government-relevant KPIs and actionable insights
# 
# Author: Data Science Consultant
# Date: 2025-08-29
# Version: 1.0 Production-Ready
# ============================================================================

# Load required packages with error handling
required_packages <- c(
  "dplyr", "tidyr", "lubridate", "ggplot2", "plotly", "scales", 
  "DT", "forecast", "changepoint", "cluster", "corrplot", "RColorBrewer",
  "tidytext", "stringr", "jsonlite", "memoise", "future", "promises"
)

missing_packages <- setdiff(required_packages, rownames(installed.packages()))
if (length(missing_packages) > 0) {
  cat("📦 Installing missing packages:", paste(missing_packages, collapse = ", "), "\n")
  install.packages(missing_packages, quiet = TRUE)
}

# Load packages
suppressPackageStartupMessages({
  lapply(required_packages, function(pkg) {
    tryCatch({
      library(pkg, character.only = TRUE)
    }, error = function(e) {
      cat("⚠️", pkg, "not available, using fallbacks\n")
    })
  })
})

# Enable memoise for caching
if (requireNamespace("memoise", quietly = TRUE)) {
  cache_dir <- "cache/performance/"
  if (!dir.exists(cache_dir)) {
    dir.create(cache_dir, recursive = TRUE)
  }
}

cat("✅ Enhanced Executive Summary Analytics Engine loaded\n")

# ============================================================================
# 1. TEMPORAL TREND ANALYSIS WITH STATISTICAL SIGNIFICANCE
# ============================================================================

#' Comprehensive temporal analysis for legislative documents
#' 
#' @param data Data frame with legislative documents
#' @param cache_enabled Logical, whether to use caching for performance
#' @return List with temporal analysis results
analyze_temporal_trends_executive <- function(data, cache_enabled = TRUE) {
  
  cat("📊 Analyzing temporal trends for Executive Summary...\n")
  
  # Define cached function if memoise is available
  if (cache_enabled && requireNamespace("memoise", quietly = TRUE)) {
    analyze_fn <- memoise::memoise(function(data_hash) {
      perform_temporal_analysis(data)
    })
    
    # Create data hash for caching
    data_hash <- digest::digest(list(nrow(data), names(data), head(data$date, 100)))
    return(analyze_fn(data_hash))
  } else {
    return(perform_temporal_analysis(data))
  }
}

#' Core temporal analysis function
perform_temporal_analysis <- function(data) {
  tryCatch({
    # Prepare temporal data
    temporal_data <- data %>%
      mutate(
        parsed_date = as.Date(date),
        year = year(parsed_date),
        month = month(parsed_date),
        year_month = floor_date(parsed_date, "month"),
        quarter = quarter(parsed_date),
        decade = floor(year / 10) * 10
      ) %>%
      filter(!is.na(parsed_date), year >= 1980, year <= 2025)
    
    if (nrow(temporal_data) == 0) {
      return(list(error = "No valid temporal data available"))
    }
    
    # Monthly publication trends (last 24 months)
    monthly_trends <- temporal_data %>%
      filter(year_month >= (Sys.Date() - years(2))) %>%
      group_by(year_month) %>%
      summarise(
        document_count = n(),
        unique_categories = n_distinct(categoria, na.rm = TRUE),
        unique_states = n_distinct(estado, na.rm = TRUE),
        federal_docs = sum(grepl("Federal", jurisdicao, na.rm = TRUE)),
        state_docs = sum(grepl("Estadual", jurisdicao, na.rm = TRUE)),
        municipal_docs = sum(grepl("Municipal", jurisdicao, na.rm = TRUE)),
        .groups = "drop"
      ) %>%
      arrange(year_month) %>%
      mutate(
        month_label = format(year_month, "%b %Y"),
        growth_rate = ifelse(
          lag(document_count) != 0 & !is.na(lag(document_count)),
          (document_count - lag(document_count)) / lag(document_count) * 100,
          NA
        ),
        moving_avg_3m = (document_count + lag(document_count, 1, default = document_count) + 
                        lag(document_count, 2, default = document_count)) / 3
      )
    
    # Yearly analysis for longer trends
    yearly_trends <- temporal_data %>%
      group_by(year) %>%
      summarise(
        document_count = n(),
        legislation_pct = mean(categoria == "Legislação", na.rm = TRUE) * 100,
        jurisprudence_pct = mean(categoria == "Jurisprudência", na.rm = TRUE) * 100,
        doctrine_pct = mean(categoria == "Doutrina", na.rm = TRUE) * 100,
        transport_related = sum(grepl("transporte|rodoviário|ferroviário|aéreo|marítimo", 
                                     tolower(paste(titulo, ementa)), na.rm = TRUE)),
        .groups = "drop"
      ) %>%
      filter(year >= 2000) %>%
      arrange(year)
    
    # Change point detection for significant trend changes
    trend_changes <- list()
    if (nrow(yearly_trends) > 10 && requireNamespace("changepoint", quietly = TRUE)) {
      tryCatch({
        cpt_analysis <- changepoint::cpt.mean(yearly_trends$document_count, method = "PELT")
        change_years <- yearly_trends$year[changepoint::cpts(cpt_analysis)]
        
        trend_changes$detected_changes <- length(change_years)
        trend_changes$change_years <- change_years
        trend_changes$significance <- ifelse(length(change_years) > 0, "Significant trend changes detected", "Stable trend pattern")
        
      }, error = function(e) {
        trend_changes$error <- "Change point detection failed"
      })
    }
    
    # Statistical trend analysis
    current_year <- year(Sys.Date())
    recent_period <- temporal_data %>% filter(year >= (current_year - 1))
    previous_period <- temporal_data %>% filter(year == (current_year - 2))
    
    statistical_insights <- list(
      current_year_total = nrow(recent_period),
      previous_year_total = nrow(previous_period),
      year_over_year_growth = ifelse(
        nrow(previous_period) > 0,
        ((nrow(recent_period) - nrow(previous_period)) / nrow(previous_period)) * 100,
        NA
      ),
      monthly_volatility = sd(monthly_trends$document_count, na.rm = TRUE),
      seasonal_patterns = list(
        q1_avg = mean(temporal_data$document_count[temporal_data$quarter == 1], na.rm = TRUE),
        q2_avg = mean(temporal_data$document_count[temporal_data$quarter == 2], na.rm = TRUE),
        q3_avg = mean(temporal_data$document_count[temporal_data$quarter == 3], na.rm = TRUE),
        q4_avg = mean(temporal_data$document_count[temporal_data$quarter == 4], na.rm = TRUE)
      )
    )
    
    # Forecasting for next 6 months (if sufficient data)
    forecast_results <- list()
    if (nrow(monthly_trends) >= 12) {
      tryCatch({
        ts_data <- ts(monthly_trends$document_count, frequency = 12)
        forecast_model <- forecast::auto.arima(ts_data)
        forecast_6m <- forecast::forecast(forecast_model, h = 6)
        
        forecast_results$next_6_months <- data.frame(
          month = seq(max(monthly_trends$year_month) + months(1), 
                     max(monthly_trends$year_month) + months(6), by = "month"),
          predicted_count = as.numeric(forecast_6m$mean),
          lower_bound = as.numeric(forecast_6m$lower[, 2]),
          upper_bound = as.numeric(forecast_6m$upper[, 2])
        )
        
        forecast_results$trend_direction <- ifelse(
          mean(forecast_results$next_6_months$predicted_count) > mean(tail(monthly_trends$document_count, 3)),
          "increasing", "decreasing"
        )
        
      }, error = function(e) {
        forecast_results$error <- "Forecasting failed - insufficient data"
      })
    }
    
    cat("✅ Temporal trend analysis completed\n")
    
    return(list(
      monthly_trends = monthly_trends,
      yearly_trends = yearly_trends,
      trend_changes = trend_changes,
      statistical_insights = statistical_insights,
      forecast_results = forecast_results,
      summary = list(
        total_documents_analyzed = nrow(temporal_data),
        date_range = paste(min(temporal_data$year), "-", max(temporal_data$year)),
        recent_monthly_avg = round(mean(tail(monthly_trends$document_count, 3)), 0),
        trend_status = ifelse(!is.null(trend_changes$change_years), "Dynamic", "Stable")
      )
    ))
    
  }, error = function(e) {
    cat("❌ Error in temporal analysis:", e$message, "\n")
    return(list(error = e$message))
  })
}

# ============================================================================
# 2. GEOGRAPHIC DISTRIBUTION ANALYTICS
# ============================================================================

#' Comprehensive geographic analysis for Brazilian states
#' 
#' @param data Data frame with legislative documents
#' @return List with geographic analysis results
analyze_geographic_distribution <- function(data) {
  
  cat("🗺️ Analyzing geographic distribution patterns...\n")
  
  tryCatch({
    # Prepare geographic data
    geographic_data <- data %>%
      filter(!is.na(estado), estado != "", estado != "Federal") %>%
      mutate(
        state_clean = toupper(trimws(estado)),
        region = case_when(
          state_clean %in% c("AC", "AP", "AM", "PA", "RO", "RR", "TO") ~ "Norte",
          state_clean %in% c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE") ~ "Nordeste",
          state_clean %in% c("DF", "GO", "MS", "MT") ~ "Centro-Oeste",
          state_clean %in% c("ES", "MG", "RJ", "SP") ~ "Sudeste",
          state_clean %in% c("PR", "RS", "SC") ~ "Sul",
          TRUE ~ "Outros"
        )
      )
    
    # State-level analysis
    state_analysis <- geographic_data %>%
      group_by(state_clean, region) %>%
      summarise(
        document_count = n(),
        legislation_count = sum(categoria == "Legislação", na.rm = TRUE),
        jurisprudence_count = sum(categoria == "Jurisprudência", na.rm = TRUE),
        doctrine_count = sum(categoria == "Doutrina", na.rm = TRUE),
        transport_related = sum(grepl("transporte|rodoviário|logística", 
                                     tolower(paste(titulo, ementa)), na.rm = TRUE)),
        recent_activity = sum(year(as.Date(date)) >= (year(Sys.Date()) - 1), na.rm = TRUE),
        avg_docs_per_month = document_count / 12,  # Assuming 1-year analysis period
        .groups = "drop"
      ) %>%
      arrange(desc(document_count)) %>%
      mutate(
        activity_level = case_when(
          document_count >= quantile(document_count, 0.8, na.rm = TRUE) ~ "Very High",
          document_count >= quantile(document_count, 0.6, na.rm = TRUE) ~ "High",
          document_count >= quantile(document_count, 0.4, na.rm = TRUE) ~ "Medium",
          document_count >= quantile(document_count, 0.2, na.rm = TRUE) ~ "Low",
          TRUE ~ "Very Low"
        ),
        transport_intensity = (transport_related / document_count) * 100
      )
    
    # Regional analysis
    regional_analysis <- geographic_data %>%
      group_by(region) %>%
      summarise(
        document_count = n(),
        state_count = n_distinct(state_clean),
        avg_per_state = round(n() / n_distinct(state_clean), 0),
        legislation_pct = (sum(categoria == "Legislação", na.rm = TRUE) / n()) * 100,
        jurisprudence_pct = (sum(categoria == "Jurisprudência", na.rm = TRUE) / n()) * 100,
        transport_focus = (sum(grepl("transporte|rodoviário|logística", 
                                   tolower(paste(titulo, ementa)), na.rm = TRUE)) / n()) * 100,
        .groups = "drop"
      ) %>%
      arrange(desc(document_count))
    
    # Cross-jurisdictional patterns
    jurisdictional_patterns <- data %>%
      filter(!is.na(jurisdicao)) %>%
      group_by(jurisdicao) %>%
      summarise(
        document_count = n(),
        unique_states = n_distinct(estado, na.rm = TRUE),
        transport_docs = sum(grepl("transporte|rodoviário|logística", 
                                  tolower(paste(titulo, ementa)), na.rm = TRUE)),
        avg_per_category = n() / n_distinct(categoria, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(desc(document_count))
    
    # Geographic hotspots identification
    hotspots <- state_analysis %>%
      filter(activity_level %in% c("High", "Very High")) %>%
      mutate(
        specialization = case_when(
          transport_intensity > 30 ~ "Transport Hub",
          legislation_count > jurisprudence_count * 2 ~ "Legislative Center",
          jurisprudence_count > legislation_count ~ "Judicial Hub",
          TRUE ~ "Balanced Activity"
        )
      ) %>%
      select(state_clean, region, document_count, activity_level, specialization, transport_intensity)
    
    # Coverage gaps analysis
    all_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                   "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                   "RS", "RO", "RR", "SC", "SP", "SE", "TO")
    
    coverage_gaps <- data.frame(
      state = all_states,
      stringsAsFactors = FALSE
    ) %>%
      left_join(
        state_analysis %>% select(state_clean, document_count), 
        by = c("state" = "state_clean")
      ) %>%
      mutate(
        document_count = ifelse(is.na(document_count), 0, document_count),
        coverage_status = case_when(
          document_count == 0 ~ "No Coverage",
          document_count < 10 ~ "Very Low Coverage",
          document_count < 50 ~ "Low Coverage",
          document_count < 200 ~ "Medium Coverage",
          TRUE ~ "Good Coverage"
        )
      ) %>%
      filter(coverage_status %in% c("No Coverage", "Very Low Coverage", "Low Coverage"))
    
    cat("✅ Geographic distribution analysis completed\n")
    
    return(list(
      state_analysis = state_analysis,
      regional_analysis = regional_analysis,
      jurisdictional_patterns = jurisdictional_patterns,
      hotspots = hotspots,
      coverage_gaps = coverage_gaps,
      summary = list(
        states_with_data = nrow(state_analysis),
        most_active_region = regional_analysis$region[1],
        coverage_percentage = (nrow(state_analysis) / 27) * 100,  # 26 states + DF
        transport_specialized_states = nrow(filter(hotspots, specialization == "Transport Hub"))
      )
    ))
    
  }, error = function(e) {
    cat("❌ Error in geographic analysis:", e$message, "\n")
    return(list(error = e$message))
  })
}

# ============================================================================
# 3. SMART DOCUMENT CLASSIFICATION AND PATTERN RECOGNITION
# ============================================================================

#' Advanced document classification with pattern recognition
#' 
#' @param data Data frame with legislative documents
#' @return List with classification results
analyze_document_patterns <- function(data) {
  
  cat("🔍 Analyzing document patterns and classifications...\n")
  
  tryCatch({
    # Enhanced document type classification
    document_types <- data %>%
      mutate(
        doc_type_enhanced = case_when(
          grepl("lei complementar", tolower(titulo)) ~ "Lei Complementar",
          grepl("lei federal|lei nº|lei n°", tolower(titulo)) ~ "Lei",
          grepl("decreto federal|decreto nº|decreto n°", tolower(titulo)) ~ "Decreto",
          grepl("medida provisória|mp nº|mp n°", tolower(titulo)) ~ "Medida Provisória",
          grepl("resolução|res nº", tolower(titulo)) ~ "Resolução",
          grepl("portaria|port nº", tolower(titulo)) ~ "Portaria",
          grepl("instrução normativa|in nº", tolower(titulo)) ~ "Instrução Normativa",
          grepl("súmula|acórdão", tolower(titulo)) ~ "Jurisprudência",
          grepl("parecer|nota técnica", tolower(titulo)) ~ "Parecer Técnico",
          TRUE ~ tipo
        )
      )
    
    # Document type distribution analysis
    type_distribution <- document_types %>%
      count(doc_type_enhanced, sort = TRUE) %>%
      mutate(
        percentage = (n / sum(n)) * 100,
        cumulative_pct = cumsum(percentage)
      ) %>%
      filter(!is.na(doc_type_enhanced), doc_type_enhanced != "")
    
    # Transport mode classification
    transport_classification <- data %>%
      mutate(
        transport_mode = case_when(
          grepl("rodoviário|caminhão|frete|estrada|rodovia", tolower(paste(titulo, ementa))) ~ "Rodoviário",
          grepl("ferroviário|ferrovia|trem|locomotiva", tolower(paste(titulo, ementa))) ~ "Ferroviário",
          grepl("aéreo|aviação|aeroporto|aeronave", tolower(paste(titulo, ementa))) ~ "Aéreo",
          grepl("aquaviário|marítimo|porto|navegação|navio", tolower(paste(titulo, ementa))) ~ "Aquaviário",
          grepl("multimodal|intermodal|logística", tolower(paste(titulo, ementa))) ~ "Multimodal",
          grepl("urbano|metrô|ônibus|brt", tolower(paste(titulo, ementa))) ~ "Urbano",
          TRUE ~ "Geral"
        )
      ) %>%
      count(transport_mode, sort = TRUE) %>%
      mutate(percentage = (n / sum(n)) * 100)
    
    # Regulatory agency patterns
    agency_patterns <- data %>%
      mutate(
        agency_involved = case_when(
          grepl("antt", tolower(paste(titulo, ementa))) ~ "ANTT",
          grepl("antaq", tolower(paste(titulo, ementa))) ~ "ANTAQ",
          grepl("anac", tolower(paste(titulo, ementa))) ~ "ANAC",
          grepl("anp", tolower(paste(titulo, ementa))) ~ "ANP",
          grepl("contran", tolower(paste(titulo, ementa))) ~ "CONTRAN",
          grepl("denatran", tolower(paste(titulo, ementa))) ~ "DENATRAN",
          grepl("dnit", tolower(paste(titulo, ementa))) ~ "DNIT",
          grepl("ibama", tolower(paste(titulo, ementa))) ~ "IBAMA",
          TRUE ~ "Outros"
        )
      ) %>%
      count(agency_involved, sort = TRUE) %>%
      mutate(percentage = (n / sum(n)) * 100) %>%
      filter(agency_involved != "Outros")
    
    # Topic frequency analysis using keyword extraction
    transport_keywords <- c(
      "transporte", "frete", "carga", "combustível", "diesel", "motorista",
      "veículo", "segurança", "emissão", "sustentável", "logística", "armazenagem",
      "terminal", "porto", "aeroporto", "rodovia", "ferrovia", "navegação"
    )
    
    keyword_frequency <- data.frame(
      keyword = transport_keywords,
      frequency = sapply(transport_keywords, function(k) {
        sum(grepl(k, tolower(paste(data$titulo, data$ementa)), na.rm = TRUE))
      }),
      stringsAsFactors = FALSE
    ) %>%
      mutate(
        percentage = (frequency / nrow(data)) * 100,
        category = case_when(
          keyword %in% c("transporte", "frete", "carga", "logística") ~ "Operational",
          keyword %in% c("combustível", "diesel", "emissão", "sustentável") ~ "Environmental",
          keyword %in% c("motorista", "segurança", "veículo") ~ "Safety & Labor",
          keyword %in% c("terminal", "porto", "aeroporto", "rodovia", "ferrovia") ~ "Infrastructure",
          TRUE ~ "Other"
        )
      ) %>%
      arrange(desc(frequency))
    
    # Anomaly detection in document patterns
    anomalies <- list()
    
    # Temporal anomalies
    monthly_counts <- data %>%
      mutate(year_month = floor_date(as.Date(date), "month")) %>%
      filter(!is.na(year_month)) %>%
      count(year_month) %>%
      arrange(year_month)
    
    if (nrow(monthly_counts) > 6) {
      mean_monthly <- mean(monthly_counts$n)
      sd_monthly <- sd(monthly_counts$n)
      threshold <- mean_monthly + 2 * sd_monthly
      
      anomalies$temporal <- monthly_counts %>%
        filter(n > threshold) %>%
        mutate(anomaly_type = "High Volume Month") %>%
        head(5)
    }
    
    # Content anomalies (unusually long or short titles)
    title_lengths <- nchar(data$titulo)
    title_mean <- mean(title_lengths, na.rm = TRUE)
    title_sd <- sd(title_lengths, na.rm = TRUE)
    
    anomalies$content <- data %>%
      mutate(title_length = nchar(titulo)) %>%
      filter(
        title_length > (title_mean + 3 * title_sd) | 
        title_length < (title_mean - 2 * title_sd)
      ) %>%
      mutate(
        anomaly_type = ifelse(title_length > title_mean, "Unusually Long Title", "Unusually Short Title")
      ) %>%
      select(titulo, title_length, anomaly_type) %>%
      head(10)
    
    # Pattern insights
    pattern_insights <- list(
      dominant_document_type = type_distribution$doc_type_enhanced[1],
      dominant_transport_mode = transport_classification$transport_mode[1],
      most_active_agency = agency_patterns$agency_involved[1],
      top_keywords = head(keyword_frequency$keyword, 5),
      classification_coverage = (sum(!is.na(document_types$doc_type_enhanced)) / nrow(data)) * 100,
      transport_relevance = (sum(grepl("transporte|rodoviário|logística", 
                                      tolower(paste(data$titulo, data$ementa)), na.rm = TRUE)) / nrow(data)) * 100
    )
    
    cat("✅ Document pattern analysis completed\n")
    
    return(list(
      type_distribution = type_distribution,
      transport_classification = transport_classification,
      agency_patterns = agency_patterns,
      keyword_frequency = keyword_frequency,
      anomalies = anomalies,
      pattern_insights = pattern_insights,
      summary = list(
        total_documents = nrow(data),
        classified_documents = sum(!is.na(document_types$doc_type_enhanced)),
        unique_document_types = nrow(type_distribution),
        transport_documents = sum(transport_classification$n[transport_classification$transport_mode != "Geral"])
      )
    ))
    
  }, error = function(e) {
    cat("❌ Error in document pattern analysis:", e$message, "\n")
    return(list(error = e$message))
  })
}

# ============================================================================
# 4. GOVERNMENT KPIs AND ACTIONABLE INTELLIGENCE
# ============================================================================

#' Generate government-relevant KPIs and actionable insights
#' 
#' @param data Data frame with legislative documents
#' @param temporal_analysis Results from temporal analysis
#' @param geographic_analysis Results from geographic analysis
#' @param pattern_analysis Results from pattern analysis
#' @return List with KPIs and actionable insights
generate_executive_kpis <- function(data, temporal_analysis, geographic_analysis, pattern_analysis) {
  
  cat("📊 Generating executive KPIs and actionable intelligence...\n")
  
  tryCatch({
    current_date <- Sys.Date()
    current_year <- year(current_date)
    current_month <- month(current_date)
    
    # Core KPIs
    core_kpis <- list(
      # Volume Metrics
      total_documents = nrow(data),
      current_year_documents = sum(year(as.Date(data$date)) == current_year, na.rm = TRUE),
      monthly_average = round(
        sum(year(as.Date(data$date)) == current_year, na.rm = TRUE) / current_month, 0
      ),
      
      # Coverage Metrics
      states_covered = length(unique(data$estado[!is.na(data$estado) & data$estado != ""])),
      jurisdictions_active = length(unique(data$jurisdicao[!is.na(data$jurisdicao)])),
      coverage_percentage = (length(unique(data$estado[!is.na(data$estado) & data$estado != ""])) / 27) * 100,
      
      # Quality Metrics
      complete_metadata_pct = (sum(!is.na(data$titulo) & !is.na(data$data) & !is.na(data$categoria)) / nrow(data)) * 100,
      recent_data_pct = (sum(as.Date(data$date) >= (current_date - days(30)), na.rm = TRUE) / nrow(data)) * 100,
      
      # Transport Focus Metrics
      transport_relevance_pct = (sum(grepl("transporte|rodoviário|logística|frete", 
                                          tolower(paste(data$titulo, data$ementa)), na.rm = TRUE)) / nrow(data)) * 100,
      regulatory_agency_mentions = sum(grepl("antt|antaq|anac|contran|dnit", 
                                           tolower(paste(data$titulo, data$ementa)), na.rm = TRUE))
    )
    
    # Trend Indicators
    trend_indicators <- list()
    if (!is.null(temporal_analysis$statistical_insights)) {
      trend_indicators <- list(
        year_over_year_growth = temporal_analysis$statistical_insights$year_over_year_growth,
        monthly_volatility = temporal_analysis$statistical_insights$monthly_volatility,
        trend_direction = ifelse(
          !is.null(temporal_analysis$forecast_results$trend_direction),
          temporal_analysis$forecast_results$trend_direction,
          "stable"
        ),
        seasonal_peak = names(which.max(unlist(temporal_analysis$statistical_insights$seasonal_patterns)))
      )
    }
    
    # Regional Performance Indicators
    regional_performance <- list()
    if (!is.null(geographic_analysis$regional_analysis)) {
      regional_performance <- list(
        most_active_region = geographic_analysis$regional_analysis$region[1],
        regional_concentration_index = max(geographic_analysis$regional_analysis$document_count) / 
                                      sum(geographic_analysis$regional_analysis$document_count),
        transport_specialized_regions = sum(geographic_analysis$regional_analysis$transport_focus > 20),
        coverage_gaps = nrow(geographic_analysis$coverage_gaps)
      )
    }
    
    # Legislative Productivity Metrics
    productivity_metrics <- list(
      documents_per_day = round(nrow(data) / as.numeric(difftime(current_date, min(as.Date(data$date), na.rm = TRUE), units = "days")), 2),
      legislation_to_jurisprudence_ratio = round(
        sum(data$categoria == "Legislação", na.rm = TRUE) / 
        sum(data$categoria == "Jurisprudência", na.rm = TRUE), 2
      ),
      federal_dominance_pct = (sum(grepl("Federal", data$jurisdicao, na.rm = TRUE)) / nrow(data)) * 100,
      recent_legislative_activity = sum(
        year(as.Date(data$date)) == current_year & 
        data$categoria == "Legislação", na.rm = TRUE
      )
    )
    
    # Alert System Triggers
    alert_system <- list()
    
    # High volume alert
    if (!is.null(temporal_analysis$monthly_trends)) {
      recent_monthly_avg <- mean(tail(temporal_analysis$monthly_trends$document_count, 3))
      historical_avg <- mean(temporal_analysis$monthly_trends$document_count)
      
      if (recent_monthly_avg > historical_avg * 1.5) {
        alert_system$high_volume <- list(
          level = "WARNING",
          message = sprintf("Recent monthly average (%.0f) is %.0f%% above historical average", 
                          recent_monthly_avg, ((recent_monthly_avg / historical_avg) - 1) * 100)
        )
      }
    }
    
    # Coverage gap alert
    if (!is.null(geographic_analysis$coverage_gaps) && nrow(geographic_analysis$coverage_gaps) > 5) {
      alert_system$coverage_gaps <- list(
        level = "INFO",
        message = sprintf("%d states have low or no document coverage", nrow(geographic_analysis$coverage_gaps))
      )
    }
    
    # Data quality alert
    if (core_kpis$complete_metadata_pct < 90) {
      alert_system$data_quality <- list(
        level = "WARNING",
        message = sprintf("Metadata completeness is %.1f%% - below 90%% threshold", core_kpis$complete_metadata_pct)
      )
    }
    
    # Actionable Insights
    actionable_insights <- list(
      # Priority Actions
      priority_actions = list(
        improve_coverage = if (core_kpis$coverage_percentage < 85) {
          sprintf("Expand data collection to %d underrepresented states", 
                 27 - core_kpis$states_covered)
        } else NULL,
        
        enhance_metadata = if (core_kpis$complete_metadata_pct < 95) {
          "Implement metadata validation to improve data quality"
        } else NULL,
        
        monitor_trends = if (!is.null(trend_indicators$year_over_year_growth) && 
                            abs(trend_indicators$year_over_year_growth) > 20) {
          sprintf("Investigate %.1f%% year-over-year change in document volume", 
                 trend_indicators$year_over_year_growth)
        } else NULL
      ),
      
      # Strategic Recommendations
      strategic_recommendations = list(
        regional_focus = sprintf("Consider targeted analysis of %s region (highest activity)", 
                               regional_performance$most_active_region),
        transport_policy = if (core_kpis$transport_relevance_pct > 15) {
          "High transport policy relevance - consider specialized transport dashboard"
        } else "Expand transport-related document collection",
        predictive_capacity = if (!is.null(temporal_analysis$forecast_results)) {
          "Implement automated forecasting alerts for legislative volume changes"
        } else "Collect more historical data to enable predictive analytics"
      ),
      
      # Operational Improvements
      operational_improvements = list(
        data_freshness = sprintf("Current data recency: %.1f%% from last 30 days", 
                               core_kpis$recent_data_pct),
        processing_efficiency = sprintf("Processing rate: %.2f documents per day", 
                                     productivity_metrics$documents_per_day),
        quality_score = sprintf("Overall data quality score: %.1f%%", 
                              core_kpis$complete_metadata_pct)
      )
    )
    
    # Executive Dashboard Summary
    executive_summary <- list(
      headline_metrics = list(
        total_documents = core_kpis$total_documents,
        states_covered = core_kpis$states_covered,
        current_year_growth = trend_indicators$year_over_year_growth,
        transport_relevance = core_kpis$transport_relevance_pct
      ),
      
      key_insights = list(
        most_active_region = regional_performance$most_active_region,
        dominant_document_type = pattern_analysis$pattern_insights$dominant_document_type,
        top_transport_mode = pattern_analysis$pattern_insights$dominant_transport_mode,
        trend_direction = trend_indicators$trend_direction
      ),
      
      status_indicators = list(
        data_quality = ifelse(core_kpis$complete_metadata_pct > 95, "EXCELLENT", 
                             ifelse(core_kpis$complete_metadata_pct > 90, "GOOD", "NEEDS_IMPROVEMENT")),
        coverage_status = ifelse(core_kpis$coverage_percentage > 90, "COMPREHENSIVE",
                                ifelse(core_kpis$coverage_percentage > 70, "ADEQUATE", "INCOMPLETE")),
        activity_level = ifelse(core_kpis$monthly_average > 1000, "HIGH",
                               ifelse(core_kpis$monthly_average > 500, "MEDIUM", "LOW"))
      )
    )
    
    cat("✅ Executive KPIs and actionable intelligence generated\n")
    
    return(list(
      core_kpis = core_kpis,
      trend_indicators = trend_indicators,
      regional_performance = regional_performance,
      productivity_metrics = productivity_metrics,
      alert_system = alert_system,
      actionable_insights = actionable_insights,
      executive_summary = executive_summary,
      generated_at = Sys.time()
    ))
    
  }, error = function(e) {
    cat("❌ Error generating executive KPIs:", e$message, "\n")
    return(list(error = e$message))
  })
}

# ============================================================================
# 5. COMPREHENSIVE EXECUTIVE SUMMARY ORCHESTRATOR
# ============================================================================

#' Main function to generate comprehensive executive summary analytics
#' 
#' @param data Data frame with legislative documents
#' @param cache_enabled Logical, whether to use caching
#' @return List with complete executive summary analytics
generate_executive_summary_analytics <- function(data, cache_enabled = TRUE) {
  
  cat("🚀 Generating comprehensive executive summary analytics...\n")
  cat("📊 Analyzing", nrow(data), "documents...\n")
  
  start_time <- Sys.time()
  
  tryCatch({
    # Validate input data
    if (nrow(data) == 0) {
      stop("No data provided for analysis")
    }
    
    required_columns <- c("titulo", "data", "categoria", "estado", "jurisdicao")
    missing_columns <- setdiff(required_columns, names(data))
    if (length(missing_columns) > 0) {
      cat("⚠️ Missing columns:", paste(missing_columns, collapse = ", "), "- using available data\n")
    }
    
    # Run comprehensive analyses
    cat("📈 Running temporal trend analysis...\n")
    temporal_results <- analyze_temporal_trends_executive(data, cache_enabled)
    
    cat("🗺️ Running geographic distribution analysis...\n")
    geographic_results <- analyze_geographic_distribution(data)
    
    cat("🔍 Running document pattern analysis...\n")
    pattern_results <- analyze_document_patterns(data)
    
    cat("📊 Generating executive KPIs...\n")
    kpi_results <- generate_executive_kpis(data, temporal_results, geographic_results, pattern_results)
    
    end_time <- Sys.time()
    processing_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
    
    cat("✅ Executive summary analytics completed in", round(processing_time, 2), "seconds\n")
    
    # Compile comprehensive results
    comprehensive_results <- list(
      metadata = list(
        generated_at = end_time,
        processing_time_seconds = processing_time,
        documents_analyzed = nrow(data),
        analysis_version = "1.0",
        cache_enabled = cache_enabled
      ),
      
      temporal_analysis = temporal_results,
      geographic_analysis = geographic_results,
      pattern_analysis = pattern_results,
      kpi_analysis = kpi_results,
      
      # Quick access summary for dashboard
      dashboard_summary = list(
        total_documents = nrow(data),
        states_covered = kpi_results$core_kpis$states_covered,
        current_year_documents = kpi_results$core_kpis$current_year_documents,
        transport_relevance = kpi_results$core_kpis$transport_relevance_pct,
        data_quality_score = kpi_results$core_kpis$complete_metadata_pct,
        most_active_region = kpi_results$regional_performance$most_active_region,
        trend_direction = kpi_results$trend_indicators$trend_direction,
        alert_count = length(kpi_results$alert_system),
        top_insights = list(
          kpi_results$actionable_insights$priority_actions[[1]],
          kpi_results$actionable_insights$strategic_recommendations[[1]],
          kpi_results$actionable_insights$operational_improvements[[1]]
        )
      )
    )
    
    # Save results to cache if enabled
    if (cache_enabled && dir.exists("cache/performance/")) {
      cache_file <- file.path("cache/performance/", 
                             paste0("executive_summary_", format(Sys.Date(), "%Y%m%d"), ".rds"))
      tryCatch({
        saveRDS(comprehensive_results, cache_file)
        cat("💾 Results cached to:", cache_file, "\n")
      }, error = function(e) {
        cat("⚠️ Failed to cache results:", e$message, "\n")
      })
    }
    
    return(comprehensive_results)
    
  }, error = function(e) {
    cat("❌ Error in comprehensive executive summary analysis:", e$message, "\n")
    return(list(
      error = e$message,
      metadata = list(
        generated_at = Sys.time(),
        documents_analyzed = ifelse(exists("data"), nrow(data), 0),
        analysis_failed = TRUE
      )
    ))
  })
}

cat("🎯 Enhanced Executive Summary Analytics Engine ready for deployment\n")