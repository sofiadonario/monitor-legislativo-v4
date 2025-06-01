# ============================================================================
# ADVANCED ANALYTICS ENGINE - BRAZILIAN LEGISLATIVE MONITORING SYSTEM
# ============================================================================
# 
# Production-ready analytics functions for 134K+ Brazilian legislative documents
# Temporal coverage: 1820-2025 | Railway-optimized | LGPD Compliant
# 
# Author: Data Science Consultant
# Date: 2025-08-19
# Version: 4.0 Production
# ============================================================================

# Load required packages with error handling
required_packages <- c(
  "dplyr", "tidyr", "lubridate", "stringr", "plotly", "ggplot2", 
  "scales", "RColorBrewer", "corrplot", "cluster", "randomForest",
  "forecast", "changepoint", "tm", "tidytext", "networkD3", "igraph"
)

missing_packages <- c()
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("⚠️ Installing missing packages:", paste(missing_packages, collapse = ", "), "\n")
  tryCatch({
    install.packages(missing_packages, quiet = TRUE)
  }, error = function(e) {
    cat("❌ Package installation failed. Some features may be limited.\n")
  })
}

# Load libraries with error handling
for (pkg in required_packages) {
  tryCatch({
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }, error = function(e) {
    cat("⚠️", pkg, "not available, using fallbacks\n")
  })
}

cat("✅ Advanced Analytics Engine initialized\n")

# ============================================================================
# 1. TEMPORAL TREND ANALYSIS (1820-2025)
# ============================================================================

#' Advanced temporal trend analysis for Brazilian legislative documents
#' 
#' @param data Data frame with documents containing date columns
#' @param date_column Character string, name of the date column
#' @param period_type Character: "yearly", "monthly", "decade", "presidential_term"
#' @param smoothing Logical, whether to apply smoothing
#' @return List with trend analysis results
analyze_temporal_trends <- function(data, date_column = "date", period_type = "yearly", smoothing = TRUE) {
  
  cat("📊 Analyzing temporal trends...\n")
  
  tryCatch({
    # Validate inputs
    if (!date_column %in% names(data)) {
      stop("Date column not found in data")
    }
    
    # Prepare temporal data
    data <- data %>%
      mutate(
        parsed_date = as.Date(get(date_column)),
        year = year(parsed_date),
        decade = floor(year(parsed_date) / 10) * 10,
        month = month(parsed_date),
        month_year = floor_date(parsed_date, "month")
      ) %>%
      filter(!is.na(parsed_date), year >= 1820, year <= 2025)
    
    if (nrow(data) == 0) {
      warning("No valid dates found in data")
      return(list(
        error = "No valid temporal data",
        message = "Unable to perform temporal analysis"
      ))
    }
    
    # Generate period-specific aggregations
    temporal_summary <- switch(period_type,
      "yearly" = data %>%
        group_by(year) %>%
        summarise(
          document_count = n(),
          categories = n_distinct(category, na.rm = TRUE),
          states = n_distinct(state, na.rm = TRUE),
          avg_title_length = mean(nchar(title), na.rm = TRUE),
          .groups = "drop"
        ) %>%
        arrange(year),
      
      "monthly" = data %>%
        group_by(month_year) %>%
        summarise(
          document_count = n(),
          categories = n_distinct(category, na.rm = TRUE),
          states = n_distinct(state, na.rm = TRUE),
          .groups = "drop"
        ) %>%
        arrange(month_year),
      
      "decade" = data %>%
        group_by(decade) %>%
        summarise(
          document_count = n(),
          categories = n_distinct(category, na.rm = TRUE),
          states = n_distinct(state, na.rm = TRUE),
          major_categories = list(names(sort(table(category), decreasing = TRUE))[1:3]),
          .groups = "drop"
        ) %>%
        arrange(decade),
      
      "presidential_term" = {
        # Brazilian presidential terms since 1985
        presidential_periods <- data.frame(
          start_year = c(1985, 1990, 1995, 1999, 2003, 2011, 2016, 2019, 2023),
          end_year = c(1990, 1995, 1999, 2003, 2011, 2016, 2019, 2023, 2027),
          president = c("Sarney", "Collor/Franco", "FHC I", "FHC II", "Lula", "Dilma", "Temer", "Bolsonaro", "Lula III"),
          era = c("Redemocratização", "Estabilização", "Consolidação", "Consolidação", "Crescimento", "Crise", "Transição", "Polarização", "Reconstrução")
        )
        
        data_with_periods <- data %>%
          mutate(
            presidential_period = sapply(year, function(y) {
              idx <- which(y >= presidential_periods$start_year & y < presidential_periods$end_year)
              if (length(idx) > 0) presidential_periods$president[idx[1]] else "Período Anterior"
            })
          )
        
        data_with_periods %>%
          group_by(presidential_period) %>%
          summarise(
            document_count = n(),
            categories = n_distinct(category, na.rm = TRUE),
            states = n_distinct(state, na.rm = TRUE),
            year_range = paste(min(year), "-", max(year)),
            .groups = "drop"
          )
      }
    )
    
    # Calculate trend metrics
    trend_metrics <- list()
    
    if (period_type %in% c("yearly", "monthly")) {
      # Time series analysis for continuous periods
      ts_data <- temporal_summary$document_count
      
      # Growth rate calculation
      if (length(ts_data) > 1) {
        growth_rates <- diff(ts_data) / ts_data[-length(ts_data)] * 100
        trend_metrics$avg_growth_rate <- mean(growth_rates, na.rm = TRUE)
        trend_metrics$volatility <- sd(growth_rates, na.rm = TRUE)
      }
      
      # Trend detection using changepoints
      if (requireNamespace("changepoint", quietly = TRUE) && length(ts_data) > 10) {
        tryCatch({
          cpt_results <- changepoint::cpt.mean(ts_data, method = "PELT")
          trend_metrics$changepoints <- changepoint::cpts(cpt_results)
          trend_metrics$trend_periods <- length(trend_metrics$changepoints) + 1
        }, error = function(e) {
          trend_metrics$changepoints <- NULL
        })
      }
      
      # Seasonal decomposition for monthly data
      if (period_type == "monthly" && length(ts_data) > 24) {
        tryCatch({
          ts_object <- ts(ts_data, frequency = 12)
          decomp <- forecast::stl(ts_object, s.window = "periodic")
          trend_metrics$seasonal_strength <- max(decomp$time.series[, "seasonal"]) - min(decomp$time.series[, "seasonal"])
          trend_metrics$trend_direction <- ifelse(tail(decomp$time.series[, "trend"], 1) > head(decomp$time.series[, "trend"], 1), "increasing", "decreasing")
        }, error = function(e) {
          trend_metrics$seasonal_strength <- NULL
        })
      }
    }
    
    # Legislative productivity analysis
    productivity_metrics <- list(
      peak_period = temporal_summary[which.max(temporal_summary$document_count), ],
      low_period = temporal_summary[which.min(temporal_summary$document_count), ],
      total_documents = sum(temporal_summary$document_count),
      active_periods = sum(temporal_summary$document_count > 0),
      coverage_percentage = (sum(temporal_summary$document_count > 0) / nrow(temporal_summary)) * 100
    )
    
    # Historical context analysis
    historical_context <- list()
    
    if (period_type == "decade") {
      historical_context$major_legislative_eras <- temporal_summary %>%
        mutate(
          era_label = case_when(
            decade < 1890 ~ "Império",
            decade < 1930 ~ "República Velha",
            decade < 1946 ~ "Era Vargas",
            decade < 1964 ~ "República Populista",
            decade < 1985 ~ "Regime Militar",
            decade >= 1985 ~ "Nova República"
          )
        ) %>%
        group_by(era_label) %>%
        summarise(
          total_documents = sum(document_count),
          decades_covered = n(),
          avg_per_decade = mean(document_count),
          .groups = "drop"
        )
    }
    
    cat("✅ Temporal trend analysis completed\n")
    
    return(list(
      temporal_summary = temporal_summary,
      trend_metrics = trend_metrics,
      productivity_metrics = productivity_metrics,
      historical_context = historical_context,
      period_type = period_type,
      data_quality = list(
        total_records = nrow(data),
        date_coverage = paste(min(data$year, na.rm = TRUE), "-", max(data$year, na.rm = TRUE)),
        missing_dates = sum(is.na(data$parsed_date))
      )
    ))
    
  }, error = function(e) {
    cat("❌ Error in temporal trend analysis:", e$message, "\n")
    return(list(
      error = e$message,
      message = "Temporal analysis failed"
    ))
  })
}

# ============================================================================
# 2. SMART DOCUMENT CATEGORIZATION & CROSS-REFERENCE DETECTION
# ============================================================================

#' Advanced document categorization using Brazilian legal taxonomy
#' 
#' @param data Data frame with documents
#' @param title_column Character string, name of title column
#' @param content_column Character string, name of content/summary column
#' @param method Character: "ml", "rule_based", "hybrid"
#' @return List with categorization results
categorize_documents_advanced <- function(data, title_column = "title", 
                                        content_column = "summary", method = "hybrid") {
  
  cat("🏷️ Advanced document categorization starting...\n")
  
  tryCatch({
    # Validate inputs
    if (!title_column %in% names(data)) {
      stop("Title column not found in data")
    }
    
    # Brazilian legal document classification system
    legal_categories <- list(
      "Constituição" = c("constituição", "emenda constitucional", "ato das disposições"),
      "Lei Complementar" = c("lei complementar", "lc nº", "lc n°"),
      "Lei Ordinária" = c("lei federal", "lei estadual", "lei municipal", "lei nº", "lei n°"),
      "Medida Provisória" = c("medida provisória", "mp nº", "mp n°"),
      "Decreto" = c("decreto federal", "decreto estadual", "decreto municipal", "decreto nº", "decreto n°"),
      "Decreto-Lei" = c("decreto-lei", "dl nº", "dl n°"),
      "Resolução" = c("resolução", "res nº", "res n°"),
      "Portaria" = c("portaria", "port nº", "port n°"),
      "Instrução Normativa" = c("instrução normativa", "in nº", "in n°"),
      "Circular" = c("circular", "circ nº", "circ n°"),
      "Ordem de Serviço" = c("ordem de serviço", "os nº", "os n°"),
      "Parecer" = c("parecer", "par nº", "par n°"),
      "Nota Técnica" = c("nota técnica", "nt nº", "nt n°")
    )
    
    # Transportation-specific subcategories
    transport_categories <- list(
      "Transporte Rodoviário" = c("rodoviário", "caminhão", "caminhões", "carreta", "bitrem", "rodotrem", "frete", "antt"),
      "Transporte Marítimo" = c("marítimo", "navegação", "porto", "embarcação", "navio", "antaq"),
      "Transporte Aéreo" = c("aéreo", "aviação", "aeroporto", "aeronave", "anac"),
      "Transporte Ferroviário" = c("ferroviário", "ferrovia", "trem", "locomotiva"),
      "Logística" = c("logística", "armazenagem", "distribuição", "centro de distribuição"),
      "Combustíveis" = c("combustível", "diesel", "gasolina", "etanol", "biodiesel", "anp"),
      "Segurança Viária" = c("segurança viária", "trânsito", "contran", "denatran"),
      "Meio Ambiente" = c("emissões", "poluição", "sustentável", "carbono", "proconve"),
      "Trabalhista" = c("motorista", "trabalhador", "jornada", "descanso", "clt")
    )
    
    # Regulatory agencies
    regulatory_agencies <- list(
      "ANTT" = c("antt", "agência nacional de transportes terrestres"),
      "ANTAQ" = c("antaq", "agência nacional de transportes aquaviários"),
      "ANAC" = c("anac", "agência nacional de aviação civil"),
      "ANP" = c("anp", "agência nacional do petróleo"),
      "CONTRAN" = c("contran", "conselho nacional de trânsito"),
      "DENATRAN" = c("denatran", "departamento nacional de trânsito"),
      "DNIT" = c("dnit", "departamento nacional de infraestrutura"),
      "IBAMA" = c("ibama", "instituto brasileiro do meio ambiente"),
      "INMETRO" = c("inmetro", "instituto nacional de metrologia")
    )
    
    # Initialize categorization results
    categorization_results <- data %>%
      mutate(
        text_for_analysis = paste(tolower(get(title_column)), 
                                tolower(ifelse(content_column %in% names(data), get(content_column), "")), 
                                sep = " "),
        legal_type = NA_character_,
        transport_category = NA_character_,
        regulatory_agency = NA_character_,
        confidence_score = 0,
        keywords_found = NA_character_
      )
    
    # Rule-based classification
    if (method %in% c("rule_based", "hybrid")) {
      
      for (i in seq_len(nrow(categorization_results))) {
        text <- categorization_results$text_for_analysis[i]
        keywords_found <- c()
        max_confidence <- 0
        
        # Legal type classification
        for (legal_type in names(legal_categories)) {
          keywords <- legal_categories[[legal_type]]
          matches <- sum(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))
          
          if (matches > 0) {
            confidence <- matches / length(keywords)
            if (confidence > max_confidence) {
              categorization_results$legal_type[i] <- legal_type
              max_confidence <- confidence
            }
            keywords_found <- c(keywords_found, keywords[sapply(keywords, function(k) grepl(k, text, fixed = TRUE))])
          }
        }
        
        # Transport category classification
        transport_confidence <- 0
        for (transport_cat in names(transport_categories)) {
          keywords <- transport_categories[[transport_cat]]
          matches <- sum(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))
          
          if (matches > 0) {
            confidence <- matches / length(keywords)
            if (confidence > transport_confidence) {
              categorization_results$transport_category[i] <- transport_cat
              transport_confidence <- confidence
            }
            keywords_found <- c(keywords_found, keywords[sapply(keywords, function(k) grepl(k, text, fixed = TRUE))])
          }
        }
        
        # Regulatory agency detection
        for (agency in names(regulatory_agencies)) {
          keywords <- regulatory_agencies[[agency]]
          matches <- sum(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))
          
          if (matches > 0) {
            categorization_results$regulatory_agency[i] <- agency
            keywords_found <- c(keywords_found, keywords[sapply(keywords, function(k) grepl(k, text, fixed = TRUE))])
          }
        }
        
        categorization_results$confidence_score[i] <- max(max_confidence, transport_confidence)
        categorization_results$keywords_found[i] <- paste(unique(keywords_found), collapse = "; ")
      }
    }
    
    # ML-based enhancement (if hybrid method)
    if (method %in% c("ml", "hybrid") && requireNamespace("randomForest", quietly = TRUE)) {
      
      tryCatch({
        # Prepare features for ML
        ml_features <- categorization_results %>%
          mutate(
            title_length = nchar(get(title_column)),
            has_numbers = grepl("\\d", get(title_column)),
            has_year = grepl("20\\d{2}|19\\d{2}", get(title_column)),
            word_count = lengths(strsplit(text_for_analysis, "\\s+")),
            capital_ratio = nchar(gsub("[^A-Z]", "", get(title_column))) / nchar(get(title_column))
          ) %>%
          select(title_length, has_numbers, has_year, word_count, capital_ratio) %>%
          mutate_if(is.logical, as.numeric)
        
        # Simple ML enhancement based on existing categorizations
        if (sum(!is.na(categorization_results$legal_type)) > 10) {
          
          # Create training data for legal type
          training_data <- cbind(ml_features, legal_type = categorization_results$legal_type) %>%
            filter(!is.na(legal_type))
          
          if (nrow(training_data) > 5) {
            # Train random forest for confidence enhancement
            rf_model <- randomForest::randomForest(
              legal_type ~ ., 
              data = training_data,
              ntree = 50,
              nodesize = 2
            )
            
            # Predict for all documents
            ml_predictions <- predict(rf_model, ml_features, type = "prob")
            
            # Enhance confidence scores
            categorization_results$ml_confidence <- apply(ml_predictions, 1, max)
            categorization_results$confidence_score <- pmax(
              categorization_results$confidence_score, 
              categorization_results$ml_confidence * 0.7  # Weight ML predictions lower
            )
          }
        }
        
      }, error = function(e) {
        cat("⚠️ ML enhancement failed, using rule-based only\n")
      })
    }
    
    # Cross-reference detection
    cross_references <- detect_cross_references(data, title_column, content_column)
    
    # Generate categorization summary
    categorization_summary <- list(
      total_documents = nrow(categorization_results),
      categorized_documents = sum(!is.na(categorization_results$legal_type)),
      coverage_percentage = (sum(!is.na(categorization_results$legal_type)) / nrow(categorization_results)) * 100,
      
      legal_type_distribution = categorization_results %>%
        filter(!is.na(legal_type)) %>%
        count(legal_type, sort = TRUE),
      
      transport_category_distribution = categorization_results %>%
        filter(!is.na(transport_category)) %>%
        count(transport_category, sort = TRUE),
      
      regulatory_agency_distribution = categorization_results %>%
        filter(!is.na(regulatory_agency)) %>%
        count(regulatory_agency, sort = TRUE),
      
      confidence_stats = list(
        mean_confidence = mean(categorization_results$confidence_score, na.rm = TRUE),
        high_confidence_docs = sum(categorization_results$confidence_score > 0.7, na.rm = TRUE),
        low_confidence_docs = sum(categorization_results$confidence_score < 0.3 & categorization_results$confidence_score > 0, na.rm = TRUE)
      )
    )
    
    cat("✅ Document categorization completed\n")
    
    return(list(
      categorized_data = categorization_results %>% select(-text_for_analysis),
      categorization_summary = categorization_summary,
      cross_references = cross_references,
      method_used = method
    ))
    
  }, error = function(e) {
    cat("❌ Error in document categorization:", e$message, "\n")
    return(list(
      error = e$message,
      message = "Document categorization failed"
    ))
  })
}

#' Detect cross-references between documents
detect_cross_references <- function(data, title_column = "title", content_column = "summary") {
  
  tryCatch({
    cat("🔗 Detecting cross-references...\n")
    
    # Pattern for Brazilian legal citations
    citation_patterns <- c(
      "Lei\\s+n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}",  # Lei nº 1234/2020
      "Decreto\\s+n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}",  # Decreto nº 5678/2021
      "MP\\s+n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}",  # MP nº 910/2019
      "LC\\s+n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}",  # LC nº 123/2018
      "Art\\.?\\s+\\d+[ºo°]?",  # Art. 5º
      "Inciso\\s+[IVX]+",  # Inciso III
      "§\\s*\\d+[ºo°]?",  # § 2º
      "CF[,/]\\d{2,4}",  # CF/88
      "CTN",  # Código Tributário Nacional
      "CLT",  # Consolidação das Leis do Trabalho
      "CTB"   # Código de Trânsito Brasileiro
    )
    
    # Extract citations from each document
    document_citations <- data %>%
      mutate(
        combined_text = paste(get(title_column), 
                            ifelse(content_column %in% names(data), get(content_column), ""), 
                            sep = " "),
        document_id = row_number()
      ) %>%
      rowwise() %>%
      mutate(
        citations = list({
          text <- combined_text
          found_citations <- c()
          
          for (pattern in citation_patterns) {
            matches <- stringr::str_extract_all(text, pattern, simplify = FALSE)[[1]]
            if (length(matches) > 0) {
              found_citations <- c(found_citations, matches)
            }
          }
          
          unique(found_citations)
        })
      ) %>%
      ungroup()
    
    # Create citation network
    citation_network <- document_citations %>%
      filter(lengths(citations) > 0) %>%
      unnest(citations) %>%
      group_by(citations) %>%
      summarise(
        citing_documents = list(document_id),
        frequency = n(),
        .groups = "drop"
      ) %>%
      filter(frequency > 1)  # Only keep citations that appear in multiple documents
    
    # Cross-reference statistics
    cross_ref_stats <- list(
      total_documents_with_citations = sum(lengths(document_citations$citations) > 0),
      total_unique_citations = nrow(citation_network),
      most_cited = if (nrow(citation_network) > 0) {
        citation_network %>% arrange(desc(frequency)) %>% head(10)
      } else {
        data.frame()
      },
      citation_coverage = (sum(lengths(document_citations$citations) > 0) / nrow(data)) * 100
    )
    
    cat("✅ Cross-reference detection completed\n")
    
    return(list(
      document_citations = document_citations %>% select(document_id, citations),
      citation_network = citation_network,
      cross_ref_stats = cross_ref_stats
    ))
    
  }, error = function(e) {
    cat("❌ Error in cross-reference detection:", e$message, "\n")
    return(list(
      error = e$message,
      message = "Cross-reference detection failed"
    ))
  })
}

# ============================================================================
# 3. BRAZILIAN LEGAL CONTEXT ANALYTICS
# ============================================================================

#' Analyze Brazilian legal context with transport focus
#' 
#' @param data Data frame with documents
#' @param focus Character: "transport", "environmental", "economic", "all"
#' @return List with legal context analysis results
analyze_brazilian_legal_context <- function(data, focus = "transport") {
  
  cat("🇧🇷 Analyzing Brazilian legal context...\n")
  
  tryCatch({
    # Brazilian federal system hierarchy
    authority_hierarchy <- list(
      "Federal" = c("união", "federal", "presidente", "congresso nacional", "supremo tribunal", "stf", "stj"),
      "Estadual" = c("estado", "estadual", "governador", "assembleia legislativa", "tribunal de justiça"),
      "Municipal" = c("município", "municipal", "prefeito", "câmara municipal", "prefeitura"),
      "Distrital" = c("distrito federal", "df", "governador do df")
    )
    
    # Transportation regulatory framework
    transport_framework <- list(
      "Marco Regulatório" = c("lei 10.233/2001", "lei federal 10233", "marco regulatório dos transportes"),
      "Agências Reguladoras" = c("antt", "antaq", "anac", "agência nacional"),
      "Código de Trânsito" = c("ctb", "lei 9.503/97", "código de trânsito brasileiro"),
      "Lei do Motorista" = c("lei 13.103/2015", "lei do motorista", "jornada de trabalho"),
      "Lei de Licitações" = c("lei 14.133/2021", "lei 8.666/93", "licitação", "contrato administrativo"),
      "Marco da Cabotagem" = c("br do mar", "cabotagem", "navegação de cabotagem"),
      "Ferrogrão" = c("ferrogrão", "fico", "ferrovia de integração"),
      "Novo Marco Ferroviário" = c("novo marco ferroviário", "lei 14.273/2021")
    )
    
    # Environmental legislation
    environmental_framework <- list(
      "PROCONVE" = c("proconve", "programa de controle de emissões", "l6"),
      "Política Nacional de Biocombustíveis" = c("renovabio", "lei 13.576/2017", "biocombustível"),
      "Marco do Saneamento" = c("lei 14.026/2020", "novo marco do saneamento"),
      "Código Florestal" = c("lei 12.651/2012", "código florestal", "reserva legal")
    )
    
    # Analyze authority distribution
    authority_analysis <- data %>%
      mutate(
        text_analysis = tolower(paste(title, ifelse("summary" %in% names(data), summary, ""), sep = " ")),
        authority_level = NA_character_
      )
    
    for (i in seq_len(nrow(authority_analysis))) {
      text <- authority_analysis$text_analysis[i]
      
      for (level in names(authority_hierarchy)) {
        keywords <- authority_hierarchy[[level]]
        if (any(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))) {
          authority_analysis$authority_level[i] <- level
          break
        }
      }
    }
    
    # Framework classification
    framework_classification <- data %>%
      mutate(
        text_analysis = tolower(paste(title, ifelse("summary" %in% names(data), summary, ""), sep = " ")),
        transport_framework = NA_character_,
        environmental_framework = NA_character_
      )
    
    # Transport framework detection
    for (i in seq_len(nrow(framework_classification))) {
      text <- framework_classification$text_analysis[i]
      
      for (framework in names(transport_framework)) {
        keywords <- transport_framework[[framework]]
        if (any(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))) {
          framework_classification$transport_framework[i] <- framework
          break
        }
      }
      
      # Environmental framework detection
      for (framework in names(environmental_framework)) {
        keywords <- environmental_framework[[framework]]
        if (any(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))) {
          framework_classification$environmental_framework[i] <- framework
          break
        }
      }
    }
    
    # Federal system analysis
    federal_system_analysis <- list(
      authority_distribution = authority_analysis %>%
        filter(!is.na(authority_level)) %>%
        count(authority_level, sort = TRUE) %>%
        mutate(percentage = (n / sum(n)) * 100),
      
      federal_dominance = authority_analysis %>%
        filter(!is.na(authority_level)) %>%
        summarise(
          federal_percentage = (sum(authority_level == "Federal") / n()) * 100,
          state_percentage = (sum(authority_level == "Estadual") / n()) * 100,
          municipal_percentage = (sum(authority_level == "Municipal") / n()) * 100
        ),
      
      competence_conflicts = authority_analysis %>%
        filter(grepl("competência|conflito|federativo", text_analysis)) %>%
        nrow()
    )
    
    # Transport regulatory analysis
    if (focus %in% c("transport", "all")) {
      transport_analysis <- list(
        framework_coverage = framework_classification %>%
          filter(!is.na(transport_framework)) %>%
          count(transport_framework, sort = TRUE),
        
        regulatory_agencies = data %>%
          mutate(
            text_analysis = tolower(paste(title, ifelse("summary" %in% names(data), summary, ""), sep = " "))
          ) %>%
          summarise(
            antt_mentions = sum(grepl("antt", text_analysis)),
            antaq_mentions = sum(grepl("antaq", text_analysis)),
            anac_mentions = sum(grepl("anac", text_analysis)),
            anp_mentions = sum(grepl("anp", text_analysis)),
            contran_mentions = sum(grepl("contran", text_analysis))
          ),
        
        modal_focus = data %>%
          mutate(
            text_analysis = tolower(paste(title, ifelse("summary" %in% names(data), summary, ""), sep = " "))
          ) %>%
          summarise(
            rodoviario = sum(grepl("rodoviário|caminhão|frete", text_analysis)),
            ferroviario = sum(grepl("ferroviário|ferrovia|trem", text_analysis)),
            aquaviario = sum(grepl("aquaviário|porto|navegação", text_analysis)),
            aereo = sum(grepl("aéreo|aviação|aeroporto", text_analysis))
          ) %>%
          pivot_longer(everything(), names_to = "modal", values_to = "mentions")
      )
    } else {
      transport_analysis <- list()
    }
    
    # Constitutional principles analysis
    constitutional_analysis <- list(
      constitutional_mentions = data %>%
        mutate(
          text_analysis = tolower(paste(title, ifelse("summary" %in% names(data), summary, ""), sep = " "))
        ) %>%
        summarise(
          cf88_mentions = sum(grepl("constituição|constitucional|cf", text_analysis)),
          due_process = sum(grepl("devido processo|ampla defesa|contraditório", text_analysis)),
          proportionality = sum(grepl("proporcionalidade|razoabilidade", text_analysis)),
          efficiency = sum(grepl("eficiência|economicidade", text_analysis))
        ),
      
      fundamental_rights = data %>%
        filter(grepl("direito fundamental|direitos humanos|dignidade humana", 
                    tolower(paste(title, ifelse("summary" %in% names(data), summary, ""), sep = " ")))) %>%
        nrow()
    )
    
    # Temporal evolution of legal frameworks
    temporal_framework_evolution <- data %>%
      mutate(
        year = year(as.Date(date)),
        has_transport_framework = !is.na(framework_classification$transport_framework),
        has_environmental_framework = !is.na(framework_classification$environmental_framework)
      ) %>%
      filter(!is.na(year), year >= 1988) %>%  # Post-constitutional period
      group_by(year) %>%
      summarise(
        total_docs = n(),
        transport_framework_docs = sum(has_transport_framework, na.rm = TRUE),
        environmental_framework_docs = sum(has_environmental_framework, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      mutate(
        transport_percentage = (transport_framework_docs / total_docs) * 100,
        environmental_percentage = (environmental_framework_docs / total_docs) * 100
      )
    
    cat("✅ Brazilian legal context analysis completed\n")
    
    return(list(
      federal_system_analysis = federal_system_analysis,
      transport_analysis = transport_analysis,
      constitutional_analysis = constitutional_analysis,
      temporal_framework_evolution = temporal_framework_evolution,
      framework_classification = framework_classification %>% 
        select(-text_analysis),
      focus_area = focus
    ))
    
  }, error = function(e) {
    cat("❌ Error in Brazilian legal context analysis:", e$message, "\n")
    return(list(
      error = e$message,
      message = "Legal context analysis failed"
    ))
  })
}

cat("✅ Advanced Analytics Engine fully loaded\n")