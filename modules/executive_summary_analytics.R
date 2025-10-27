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

# Never install packages at runtime in production
if (identical(tolower(Sys.getenv("RAILWAY_ENVIRONMENT")), "production")) {
  missing_packages <- setdiff(required_packages, rownames(installed.packages()))
  if (length(missing_packages) > 0) {
    message("[exec_summary_analytics] Runtime install disabled in production. Missing: ",
            paste(missing_packages, collapse = ", "))
  }
} else if (isTRUE(as.logical(Sys.getenv("ALLOW_RUNTIME_INSTALL", "FALSE")))) {
  missing_packages <- setdiff(required_packages, rownames(installed.packages()))
  if (length(missing_packages) > 0) {
    cat("📦 Missing packages:", paste(missing_packages, collapse = ", "), "\n")
    message("[startup] Runtime install skipped; all packages must be baked into the image")
  }
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
    
    if (isTRUE(is.null(temporal_data)) || !is.data.frame(temporal_data) || nrow(temporal_data) == 0) {
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
        federal_docs = sum(safe_grepl("Federal", jurisdicao), na.rm = TRUE),
        state_docs = sum(safe_grepl("Estadual", jurisdicao), na.rm = TRUE),
        municipal_docs = sum(safe_grepl("Municipal", jurisdicao), na.rm = TRUE),
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
        moving_avg_3m = (document_count + lag(document_count, 1, default = NA_real_) + 
                        lag(document_count, 2, default = NA_real_)) / 3,
        quarter_label = quarter(year_month)
      )
    
    # Yearly analysis for longer trends
    yearly_trends <- temporal_data %>%
      group_by(year) %>%
      summarise(
        document_count = n(),
        legislation_pct = mean(categoria == "Legislação", na.rm = TRUE) * 100,
        jurisprudence_pct = mean(categoria == "Jurisprudência", na.rm = TRUE) * 100,
        doctrine_pct = mean(categoria == "Doutrina", na.rm = TRUE) * 100,
        transport_related = sum(safe_grepl("transporte|rodoviário|ferroviário|aéreo|marítimo", paste(titulo, ementa)), na.rm = TRUE),
        .groups = "drop"
      ) %>%
      filter(year >= 2000) %>%
      arrange(year)
    
    # Change point detection for significant trend changes
    trend_changes <- list()
    if (!isTRUE(is.null(yearly_trends)) && is.data.frame(yearly_trends) && nrow(yearly_trends) > 10 && requireNamespace("changepoint", quietly = TRUE)) {
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
      year_over_year_growth = if (nrow(previous_period) > 0) {
        ((nrow(recent_period) - nrow(previous_period)) / nrow(previous_period)) * 100
      } else {
        NA_real_
      },
      monthly_volatility = sd(monthly_trends$document_count, na.rm = TRUE),
      seasonal_patterns = list(
        q1_avg = if (any(monthly_trends$quarter_label == 1, na.rm = TRUE)) mean(monthly_trends$document_count[monthly_trends$quarter_label == 1], na.rm = TRUE) else NA_real_,
        q2_avg = if (any(monthly_trends$quarter_label == 2, na.rm = TRUE)) mean(monthly_trends$document_count[monthly_trends$quarter_label == 2], na.rm = TRUE) else NA_real_,
        q3_avg = if (any(monthly_trends$quarter_label == 3, na.rm = TRUE)) mean(monthly_trends$document_count[monthly_trends$quarter_label == 3], na.rm = TRUE) else NA_real_,
        q4_avg = if (any(monthly_trends$quarter_label == 4, na.rm = TRUE)) mean(monthly_trends$document_count[monthly_trends$quarter_label == 4], na.rm = TRUE) else NA_real_
      )
    )
    
    # Forecasting for next 6 months (if sufficient data)
    forecast_results <- list()
    if (!isTRUE(is.null(monthly_trends)) && is.data.frame(monthly_trends) && nrow(monthly_trends) >= 12) {
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
        
        forecast_results$trend_direction <- if (isTRUE(length(forecast_results$next_6_months$predicted_count) > 0) && nrow(monthly_trends) >= 3) {
          if (mean(forecast_results$next_6_months$predicted_count) > mean(tail(monthly_trends$document_count, 3))) {
            "increasing"
          } else {
            "decreasing"
          }
        } else {
          "stable"
        }
        
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
        trend_status = if (!isTRUE(is.null(trend_changes$change_years)) && length(trend_changes$change_years) > 0) "Dynamic" else "Stable"
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
        transport_related = sum(safe_grepl("transporte|rodoviário|logística", paste(titulo, ementa)), na.rm = TRUE),
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
        transport_focus = (sum(safe_grepl("transporte|rodoviário|logística", paste(titulo, ementa)), na.rm = TRUE) / n()) * 100,
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
        transport_docs = sum(safe_grepl("transporte|rodoviário|logística", paste(titulo, ementa)), na.rm = TRUE),
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
        most_active_region = scalar_chr(regional_analysis$region, "N/A"),
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
          safe_grepl("lei complementar", titulo) ~ "Lei Complementar",
          safe_grepl("lei federal|lei nº|lei n°", titulo) ~ "Lei",
          safe_grepl("decreto federal|decreto nº|decreto n°", titulo) ~ "Decreto",
          safe_grepl("medida provisória|mp nº|mp n°", titulo) ~ "Medida Provisória",
          safe_grepl("resolução|res nº", titulo) ~ "Resolução",
          safe_grepl("portaria|port nº", titulo) ~ "Portaria",
          safe_grepl("instrução normativa|in nº", titulo) ~ "Instrução Normativa",
          safe_grepl("súmula|acórdão", titulo) ~ "Jurisprudência",
          safe_grepl("parecer|nota técnica", titulo) ~ "Parecer Técnico",
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
          safe_grepl("rodoviário|caminhão|frete|estrada|rodovia", paste(titulo, ementa)) ~ "Rodoviário",
          safe_grepl("ferroviário|ferrovia|trem|locomotiva", paste(titulo, ementa)) ~ "Ferroviário",
          safe_grepl("aéreo|aviação|aeroporto|aeronave", paste(titulo, ementa)) ~ "Aéreo",
          safe_grepl("aquaviário|marítimo|porto|navegação|navio", paste(titulo, ementa)) ~ "Aquaviário",
          safe_grepl("multimodal|intermodal|logística", paste(titulo, ementa)) ~ "Multimodal",
          safe_grepl("urbano|metrô|ônibus|brt", paste(titulo, ementa)) ~ "Urbano",
          TRUE ~ "Geral"
        )
      ) %>%
      count(transport_mode, sort = TRUE) %>%
      mutate(percentage = (n / sum(n)) * 100)
    
    # Regulatory agency patterns
    agency_patterns <- data %>%
      mutate(
        agency_involved = case_when(
          safe_grepl("antt", paste(titulo, ementa)) ~ "ANTT",
          safe_grepl("antaq", paste(titulo, ementa)) ~ "ANTAQ",
          safe_grepl("anac", paste(titulo, ementa)) ~ "ANAC",
          safe_grepl("anp", paste(titulo, ementa)) ~ "ANP",
          safe_grepl("contran", paste(titulo, ementa)) ~ "CONTRAN",
          safe_grepl("denatran", paste(titulo, ementa)) ~ "DENATRAN",
          safe_grepl("dnit", paste(titulo, ementa)) ~ "DNIT",
          safe_grepl("ibama", paste(titulo, ementa)) ~ "IBAMA",
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
        text_combined <- paste(data$titulo, data$ementa, sep = " ")
        sum(safe_grepl(k, text_combined), na.rm = TRUE)
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

    if (!isTRUE(is.null(monthly_counts)) && is.data.frame(monthly_counts) && nrow(monthly_counts) > 6) {
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
      dominant_document_type = scalar_chr(type_distribution$doc_type_enhanced, "N/A"),
      dominant_transport_mode = scalar_chr(transport_classification$transport_mode, "N/A"),
      most_active_agency = scalar_chr(agency_patterns$agency_involved, "N/A"),
      top_keywords = head(keyword_frequency$keyword, 5),
      classification_coverage = (sum(!is.na(document_types$doc_type_enhanced)) / nrow(data)) * 100,
      transport_relevance = (sum(safe_grepl("transporte|rodoviário|logística", paste(data$titulo, data$ementa)), na.rm = TRUE) / nrow(data)) * 100
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
      transport_relevance_pct = (sum(safe_grepl("transporte|rodoviário|logística|frete", paste(data$titulo, data$ementa)), na.rm = TRUE) / nrow(data)) * 100,
      regulatory_agency_mentions = sum(safe_grepl("antt|antaq|anac|contran|dnit", paste(data$titulo, data$ementa)), na.rm = TRUE)
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
        most_active_region = scalar_chr(geographic_analysis$regional_analysis$region, "N/A"),
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
      federal_dominance_pct = (sum(safe_grepl("Federal", data$jurisdicao), na.rm = TRUE) / nrow(data)) * 100,
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
    if (!isTRUE(is.null(geographic_analysis$coverage_gaps)) && nrow(geographic_analysis$coverage_gaps) > 5) {
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
        
        monitor_trends = if (!isTRUE(is.null(trend_indicators$year_over_year_growth)) && 
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
    if (isTRUE(is.null(data)) || !is.data.frame(data) || nrow(data) == 0) {
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
          scalar_chr(kpi_results$actionable_insights$priority_actions, "N/A"),
          scalar_chr(kpi_results$actionable_insights$strategic_recommendations, "N/A"),
          scalar_chr(kpi_results$actionable_insights$operational_improvements, "N/A")
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
