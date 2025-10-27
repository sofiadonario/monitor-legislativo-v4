# ============================================================================
# PERFORMANCE & REGULATORY IMPACT ANALYTICS
# ============================================================================
# 
# Legislative productivity metrics, policy influence tracking, and regulatory
# impact assessment tools optimized for Railway deployment
# 
# Author: Data Science Consultant  
# Date: 2025-08-19
# Version: 4.0 Production
# ============================================================================

# Load required packages with error handling
required_packages <- c(
  "dplyr", "tidyr", "lubridate", "stringr", "ggplot2", "plotly",
  "networkD3", "igraph", "forecast", "cluster", "corrplot", "scales"
)

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("⚠️ Package", pkg, "not available, some features may be limited\n")
  } else {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }
}

cat("✅ Performance & Impact Analytics Module initialized\n")

# ============================================================================
# 4. LEGISLATIVE PRODUCTIVITY METRICS
# ============================================================================

#' Comprehensive legislative productivity analysis
#' 
#' @param data Data frame with legislative documents
#' @param time_period Character: "monthly", "quarterly", "yearly", "presidential_term"
#' @param authority_level Character: "federal", "state", "municipal", "all"
#' @return List with productivity metrics and analysis
analyze_legislative_productivity <- function(data, time_period = "yearly", authority_level = "all") {
  
  cat("📊 Analyzing legislative productivity...\n")
  
  tryCatch({
    # Validate and prepare data
    data <- data %>%
      mutate(
        date_parsed = as.Date(date),
        year = year(date_parsed),
        quarter = quarter(date_parsed),
        month = month(date_parsed),
        month_year = floor_date(date_parsed, "month")
      ) %>%
      filter(!is.na(date_parsed), year >= 1988, year <= 2025)  # Focus on current constitutional period
    
    if (nrow(data) == 0) {
      warning("No valid data for productivity analysis")
      return(list(error = "No valid data"))
    }
    
    # Authority level filtering
    if (authority_level != "all") {
      authority_keywords <- list(
        "federal" = c("federal", "união", "congresso nacional", "senado", "câmara dos deputados"),
        "state" = c("estadual", "estado", "assembleia legislativa", "governo estadual"),
        "municipal" = c("municipal", "município", "câmara municipal", "prefeitura")
      )
      
      if (authority_level %in% names(authority_keywords)) {
        keywords <- authority_keywords[[authority_level]]
        data <- data %>%
          mutate(
            text_for_filter = tolower(paste(title, ifelse("summary" %in% names(data), summary, ""), sep = " "))
          ) %>%
          filter(any(sapply(keywords, function(k) grepl(k, text_for_filter)))) %>%
          select(-text_for_filter)
      }
    }
    
    # Time-based aggregation
    productivity_summary <- switch(time_period,
      "monthly" = data %>%
        group_by(year, month) %>%
        summarise(
          period_label = paste(year, sprintf("%02d", month), sep = "-"),
          document_count = n(),
          unique_categories = n_distinct(category, na.rm = TRUE),
          unique_states = n_distinct(state, na.rm = TRUE),
          avg_title_length = mean(nchar(title), na.rm = TRUE),
          .groups = "drop"
        ) %>%
        arrange(year, month),
      
      "quarterly" = data %>%
        group_by(year, quarter) %>%
        summarise(
          period_label = paste(year, "Q", quarter, sep = ""),
          document_count = n(),
          unique_categories = n_distinct(category, na.rm = TRUE),
          unique_states = n_distinct(state, na.rm = TRUE),
          avg_title_length = mean(nchar(title), na.rm = TRUE),
          .groups = "drop"
        ) %>%
        arrange(year, quarter),
      
      "yearly" = data %>%
        group_by(year) %>%
        summarise(
          period_label = as.character(year),
          document_count = n(),
          unique_categories = n_distinct(category, na.rm = TRUE),
          unique_states = n_distinct(state, na.rm = TRUE),
          avg_title_length = mean(nchar(title), na.rm = TRUE),
          major_categories = list(names(sort(table(category), decreasing = TRUE))[1:min(3, length(unique(category)))]),
          .groups = "drop"
        ) %>%
        arrange(year),
      
      "presidential_term" = {
        # Brazilian presidential terms since 1988
        presidential_terms <- data.frame(
          start_year = c(1985, 1990, 1995, 1999, 2003, 2011, 2016, 2019, 2023),
          end_year = c(1990, 1995, 1999, 2003, 2011, 2016, 2019, 2023, 2027),
          president = c("Sarney", "Collor/Franco", "FHC I", "FHC II", "Lula I-II", "Dilma", "Temer", "Bolsonaro", "Lula III"),
          political_context = c("Redemocratização", "Estabilização", "Consolidação", "Consolidação", "Crescimento", "Crise Política", "Transição", "Polarização", "Reconstrução")
        )
        
        data_with_terms <- data %>%
          mutate(
            presidential_term = sapply(year, function(y) {
              idx <- which(y >= presidential_terms$start_year & y < presidential_terms$end_year)
              if (length(idx) > 0) presidential_terms$president[idx[1]] else "Período Anterior"
            }),
            political_context = sapply(year, function(y) {
              idx <- which(y >= presidential_terms$start_year & y < presidential_terms$end_year)
              if (length(idx) > 0) presidential_terms$political_context[idx[1]] else "Período Anterior"
            })
          )
        
        data_with_terms %>%
          group_by(presidential_term, political_context) %>%
          summarise(
            period_label = first(presidential_term),
            document_count = n(),
            unique_categories = n_distinct(category, na.rm = TRUE),
            unique_states = n_distinct(state, na.rm = TRUE),
            years_covered = n_distinct(year),
            avg_per_year = n() / n_distinct(year),
            year_range = paste(min(year), "-", max(year)),
            .groups = "drop"
          )
      }
    )
    
    # Calculate productivity metrics
    productivity_metrics <- list()
    
    if (nrow(productivity_summary) > 1) {
      productivity_metrics$growth_analysis <- list(
        total_growth = ((tail(productivity_summary$document_count, 1) - head(productivity_summary$document_count, 1)) / 
                       head(productivity_summary$document_count, 1)) * 100,
        avg_growth_rate = mean(diff(productivity_summary$document_count) / 
                              productivity_summary$document_count[-length(productivity_summary$document_count)] * 100, na.rm = TRUE),
        volatility = sd(productivity_summary$document_count, na.rm = TRUE),
        coefficient_of_variation = sd(productivity_summary$document_count, na.rm = TRUE) / 
                                  mean(productivity_summary$document_count, na.rm = TRUE)
      )
      
      # Productivity peaks and troughs
      productivity_metrics$peak_analysis <- list(
        highest_productivity = productivity_summary[which.max(productivity_summary$document_count), ],
        lowest_productivity = productivity_summary[which.min(productivity_summary$document_count), ],
        above_average_periods = sum(productivity_summary$document_count > mean(productivity_summary$document_count)),
        productivity_trend = ifelse(
          tail(productivity_summary$document_count, 1) > head(productivity_summary$document_count, 1),
          "increasing", "decreasing"
        )
      )
      
      # Seasonal patterns (for monthly/quarterly data)
      if (time_period %in% c("monthly", "quarterly")) {
        if (time_period == "monthly" && nrow(productivity_summary) >= 12) {
          monthly_avg <- data %>%
            group_by(month) %>%
            summarise(avg_documents = n() / n_distinct(year), .groups = "drop")
          
          productivity_metrics$seasonal_patterns <- list(
            peak_month = monthly_avg$month[which.max(monthly_avg$avg_documents)],
            low_month = monthly_avg$month[which.min(monthly_avg$avg_documents)],
            seasonal_variation = (max(monthly_avg$avg_documents) - min(monthly_avg$avg_documents)) / 
                               mean(monthly_avg$avg_documents) * 100,
            monthly_averages = monthly_avg
          )
        }
        
        if (time_period == "quarterly" && nrow(productivity_summary) >= 4) {
          quarterly_avg <- data %>%
            group_by(quarter) %>%
            summarise(avg_documents = n() / n_distinct(year), .groups = "drop")
          
          productivity_metrics$seasonal_patterns <- list(
            peak_quarter = quarterly_avg$quarter[which.max(quarterly_avg$avg_documents)],
            low_quarter = quarterly_avg$quarter[which.min(quarterly_avg$avg_documents)],
            seasonal_variation = (max(quarterly_avg$avg_documents) - min(quarterly_avg$avg_documents)) / 
                               mean(quarterly_avg$avg_documents) * 100,
            quarterly_averages = quarterly_avg
          )
        }
      }
    }
    
    # Category-based productivity analysis
    category_productivity <- data %>%
      group_by(category) %>%
      summarise(
        total_documents = n(),
        years_active = n_distinct(year),
        avg_per_year = n() / n_distinct(year),
        first_appearance = min(year, na.rm = TRUE),
        last_appearance = max(year, na.rm = TRUE),
        states_covered = n_distinct(state, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(desc(total_documents))
    
    # Legislative efficiency metrics
    efficiency_metrics <- list(
      documents_per_category = mean(category_productivity$total_documents),
      category_coverage = nrow(category_productivity),
      geographic_coverage = n_distinct(data$state, na.rm = TRUE),
      temporal_coverage = max(data$year, na.rm = TRUE) - min(data$year, na.rm = TRUE),
      average_annual_output = nrow(data) / (max(data$year, na.rm = TRUE) - min(data$year, na.rm = TRUE) + 1),
      consistency_score = 1 - (sd(productivity_summary$document_count, na.rm = TRUE) / 
                              mean(productivity_summary$document_count, na.rm = TRUE))
    )
    
    cat("✅ Legislative productivity analysis completed\n")
    
    return(list(
      productivity_summary = productivity_summary,
      productivity_metrics = productivity_metrics,
      category_productivity = category_productivity,
      efficiency_metrics = efficiency_metrics,
      time_period = time_period,
      authority_level = authority_level,
      analysis_period = paste(min(data$year, na.rm = TRUE), "-", max(data$year, na.rm = TRUE)),
      total_documents_analyzed = nrow(data)
    ))
    
  }, error = function(e) {
    cat("❌ Error in legislative productivity analysis:", e$message, "\n")
    return(list(error = e$message, message = "Productivity analysis failed"))
  })
}

# ============================================================================
# 5. POLICY INFLUENCE TRACKING
# ============================================================================

#' Track policy influence and document interconnections
#' 
#' @param data Data frame with legislative documents
#' @param influence_type Character: "citation", "temporal", "thematic", "authority"
#' @return List with policy influence analysis results
track_policy_influence <- function(data, influence_type = "citation") {
  
  cat("🎯 Tracking policy influence...\n")
  
  tryCatch({
    # Validate data
    if (nrow(data) == 0) {
      warning("No data for policy influence tracking")
      return(list(error = "No data available"))
    }
    
    # Prepare text for analysis
    data <- data %>%
      mutate(
        combined_text = tolower(paste(title, ifelse("summary" %in% names(data), summary, ""), sep = " ")),
        document_id = row_number(),
        date_parsed = as.Date(date),
        year = year(date_parsed)
      ) %>%
      filter(!is.na(date_parsed))
    
    influence_results <- list()
    
    # Citation-based influence tracking
    if (influence_type %in% c("citation", "all")) {
      cat("🔗 Analyzing citation influence...\n")
      
      # Extract legal citations
      citation_patterns <- c(
        "Lei\\s+(?:Federal\\s+)?n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}",
        "Decreto\\s+(?:Federal\\s+)?n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}",
        "Medida\\s+Provisória\\s+n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}",
        "Lei\\s+Complementar\\s+n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}",
        "Resolução\\s+n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}",
        "Portaria\\s+n[ºo°]?\\.?\\s*\\d+[,/]\\d{4}"
      )
      
      # Create citation network
      citation_data <- data %>%
        rowwise() %>%
        mutate(
          extracted_citations = list({
            text <- combined_text
            all_citations <- c()
            
            for (pattern in citation_patterns) {
              matches <- stringr::str_extract_all(text, pattern, simplify = FALSE)[[1]]
              if (length(matches) > 0) {
                all_citations <- c(all_citations, matches)
              }
            }
            
            unique(tolower(all_citations))
          }),
          citation_count = length(extracted_citations)
        ) %>%
        ungroup()
      
      # Citation influence metrics
      citation_network <- citation_data %>%
        filter(citation_count > 0) %>%
        unnest(extracted_citations) %>%
        group_by(extracted_citations) %>%
        summarise(
          citing_documents = n(),
          document_ids = list(document_id),
          years_cited = list(year),
          influence_span = max(year) - min(year),
          .groups = "drop"
        ) %>%
        arrange(desc(citing_documents)) %>%
        mutate(
          influence_score = citing_documents * log(influence_span + 1),  # Weight by temporal span
          influence_rank = row_number()
        )
      
      # Most influential legal documents
      influential_documents <- citation_network %>%
        head(20) %>%
        mutate(
          citation_type = case_when(
            grepl("lei\\s+federal", extracted_citations) ~ "Lei Federal",
            grepl("decreto", extracted_citations) ~ "Decreto",
            grepl("medida\\s+provisória", extracted_citations) ~ "Medida Provisória",
            grepl("lei\\s+complementar", extracted_citations) ~ "Lei Complementar",
            grepl("resolução", extracted_citations) ~ "Resolução",
            grepl("portaria", extracted_citations) ~ "Portaria",
            TRUE ~ "Outros"
          )
        )
      
      influence_results$citation_influence <- list(
        citation_network = citation_network,
        influential_documents = influential_documents,
        citation_stats = list(
          total_citations = nrow(citation_network),
          avg_citations_per_doc = mean(citation_data$citation_count),
          documents_with_citations = sum(citation_data$citation_count > 0),
          citation_coverage = (sum(citation_data$citation_count > 0) / nrow(data)) * 100
        )
      )
    }
    
    # Temporal influence tracking
    if (influence_type %in% c("temporal", "all")) {
      cat("⏰ Analyzing temporal influence...\n")
      
      # Identify document clusters by time and topic
      temporal_clusters <- data %>%
        arrange(date_parsed) %>%
        mutate(
          time_window = floor_date(date_parsed, "quarter"),  # Group by quarter
          lag_time = as.numeric(date_parsed - lag(date_parsed)),
          is_cluster_start = is.na(lag_time) | lag_time > 90  # 3+ months gap
        ) %>%
        group_by(time_window) %>%
        summarise(
          cluster_size = n(),
          dominant_category = names(sort(table(category), decreasing = TRUE))[1],
          states_involved = n_distinct(state, na.rm = TRUE),
          temporal_density = n() / as.numeric(max(date_parsed) - min(date_parsed) + 1),
          .groups = "drop"
        ) %>%
        filter(cluster_size > 1) %>%
        arrange(desc(cluster_size))
      
      # Policy momentum analysis
      policy_momentum <- data %>%
        arrange(date_parsed) %>%
        mutate(
          rolling_30d = zoo::rollsum(rep(1, nrow(.)), k = min(30, nrow(.)), fill = NA, align = "right"),
          rolling_90d = zoo::rollsum(rep(1, nrow(.)), k = min(90, nrow(.)), fill = NA, align = "right"),
          momentum_score = rolling_30d + (rolling_90d * 0.5)
        ) %>%
        filter(!is.na(momentum_score))
      
      influence_results$temporal_influence <- list(
        temporal_clusters = temporal_clusters,
        momentum_periods = policy_momentum %>%
          arrange(desc(momentum_score)) %>%
          head(10),
        temporal_stats = list(
          avg_cluster_size = mean(temporal_clusters$cluster_size),
          max_momentum = max(policy_momentum$momentum_score, na.rm = TRUE),
          active_quarters = nrow(temporal_clusters)
        )
      )
    }
    
    # Thematic influence tracking
    if (influence_type %in% c("thematic", "all")) {
      cat("🎨 Analyzing thematic influence...\n")
      
      # Extract key terms and themes
      theme_keywords <- list(
        "Sustentabilidade" = c("sustentável", "sustentabilidade", "meio ambiente", "emissões", "carbono", "verde"),
        "Digitalização" = c("digital", "tecnologia", "eletrônico", "online", "sistema", "plataforma"),
        "Segurança" = c("segurança", "seguro", "proteção", "prevenção", "acidente", "risco"),
        "Competitividade" = c("competitivo", "competitividade", "concorrência", "mercado", "eficiência"),
        "Infraestrutura" = c("infraestrutura", "obra", "construção", "rodovia", "porto", "aeroporto"),
        "Trabalho" = c("trabalho", "trabalhador", "emprego", "jornada", "direitos", "social"),
        "Regulamentação" = c("regulamentação", "norma", "padrão", "fiscalização", "controle", "licença"),
        "Economia" = c("econômico", "economia", "financeiro", "custo", "preço", "investimento")
      )
      
      # Thematic analysis
      thematic_analysis <- data %>%
        rowwise() %>%
        mutate(
          themes = list({
            text <- combined_text
            identified_themes <- c()
            
            for (theme in names(theme_keywords)) {
              keywords <- theme_keywords[[theme]]
              if (any(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))) {
                identified_themes <- c(identified_themes, theme)
              }
            }
            
            identified_themes
          }),
          theme_count = length(themes)
        ) %>%
        ungroup()
      
      # Theme influence over time
      theme_evolution <- thematic_analysis %>%
        filter(theme_count > 0) %>%
        unnest(themes) %>%
        group_by(year, themes) %>%
        summarise(document_count = n(), .groups = "drop") %>%
        group_by(themes) %>%
        summarise(
          total_documents = sum(document_count),
          years_active = n_distinct(year),
          first_appearance = min(year),
          recent_activity = sum(document_count[year >= (max(year) - 5)]),
          growth_trend = ifelse(
            sum(document_count[year >= (max(year) - 2)]) > sum(document_count[year < (max(year) - 2)]),
            "growing", "declining"
          ),
          .groups = "drop"
        ) %>%
        arrange(desc(total_documents))
      
      influence_results$thematic_influence <- list(
        theme_evolution = theme_evolution,
        thematic_analysis = thematic_analysis %>% select(-combined_text),
        theme_stats = list(
          most_common_theme = theme_evolution$themes[1],
          emerging_themes = theme_evolution %>% filter(growth_trend == "growing") %>% pull(themes),
          declining_themes = theme_evolution %>% filter(growth_trend == "declining") %>% pull(themes)
        )
      )
    }
    
    # Authority-based influence tracking
    if (influence_type %in% c("authority", "all")) {
      cat("🏛️ Analyzing authority influence...\n")
      
      # Authority classification
      authority_keywords <- list(
        "Executivo Federal" = c("presidente", "ministério", "ministro", "secretaria federal"),
        "Legislativo Federal" = c("congresso", "senado", "câmara dos deputados", "lei federal"),
        "Judiciário Federal" = c("stf", "stj", "supremo", "superior tribunal"),
        "Agências Reguladoras" = c("antt", "antaq", "anac", "anp", "anvisa", "anatel"),
        "Executivo Estadual" = c("governador", "secretaria estadual", "governo estadual"),
        "Legislativo Estadual" = c("assembleia legislativa", "deputado estadual"),
        "Executivo Municipal" = c("prefeito", "prefeitura", "secretaria municipal"),
        "Legislativo Municipal" = c("câmara municipal", "vereador")
      )
      
      # Classify documents by authority
      authority_classification <- data %>%
        rowwise() %>%
        mutate(
          authority_type = {
            text <- combined_text
            detected_authorities <- c()
            
            for (auth_type in names(authority_keywords)) {
              keywords <- authority_keywords[[auth_type]]
              if (any(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))) {
                detected_authorities <- c(detected_authorities, auth_type)
              }
            }
            
            if (length(detected_authorities) > 0) detected_authorities[1] else "Não Identificado"
          }
        ) %>%
        ungroup()
      
      # Authority influence metrics
      authority_influence <- authority_classification %>%
        group_by(authority_type) %>%
        summarise(
          total_documents = n(),
          years_active = n_distinct(year),
          states_covered = n_distinct(state, na.rm = TRUE),
          categories_covered = n_distinct(category, na.rm = TRUE),
          avg_per_year = n() / n_distinct(year),
          influence_score = n() * log(n_distinct(year) + 1) * log(n_distinct(state, na.rm = TRUE) + 1),
          .groups = "drop"
        ) %>%
        arrange(desc(influence_score))
      
      influence_results$authority_influence <- list(
        authority_classification = authority_classification %>% select(-combined_text),
        authority_influence = authority_influence,
        authority_stats = list(
          most_influential_authority = authority_influence$authority_type[1],
          federal_vs_local = list(
            federal = sum(authority_influence$total_documents[grepl("Federal", authority_influence$authority_type)]),
            state = sum(authority_influence$total_documents[grepl("Estadual", authority_influence$authority_type)]),
            municipal = sum(authority_influence$total_documents[grepl("Municipal", authority_influence$authority_type)])
          )
        )
      )
    }
    
    cat("✅ Policy influence tracking completed\n")
    
    return(influence_results)
    
  }, error = function(e) {
    cat("❌ Error in policy influence tracking:", e$message, "\n")
    return(list(error = e$message, message = "Policy influence tracking failed"))
  })
}

# ============================================================================
# 6. REGULATORY IMPACT ASSESSMENT
# ============================================================================

#' Comprehensive regulatory impact assessment
#' 
#' @param data Data frame with legislative documents  
#' @param assessment_type Character: "economic", "social", "environmental", "comprehensive"
#' @param railway_optimized Logical: whether to use Railway-optimized processing
#' @return List with regulatory impact assessment results
assess_regulatory_impact <- function(data, assessment_type = "comprehensive", railway_optimized = TRUE) {
  
  cat("⚖️ Conducting regulatory impact assessment...\n")
  
  tryCatch({
    # Validate data
    if (nrow(data) == 0) {
      warning("No data for regulatory impact assessment")
      return(list(error = "No data available"))
    }
    
    # Prepare data with Railway optimization
    if (railway_optimized) {
      # Sample large datasets for Railway memory efficiency
      if (nrow(data) > 10000) {
        cat("🔧 Railway optimization: Sampling large dataset for performance\n")
        data <- data %>% sample_n(min(10000, nrow(data)))
      }
    }
    
    # Prepare text and temporal data
    data <- data %>%
      mutate(
        combined_text = tolower(paste(title, ifelse("summary" %in% names(data), summary, ""), sep = " ")),
        date_parsed = as.Date(date),
        year = year(date_parsed),
        document_id = row_number()
      ) %>%
      filter(!is.na(date_parsed))
    
    impact_results <- list()
    
    # Economic impact indicators
    if (assessment_type %in% c("economic", "comprehensive")) {
      cat("💰 Analyzing economic impact...\n")
      
      economic_keywords <- list(
        "Custos" = c("custo", "preço", "tarifa", "taxa", "valor", "orçamento", "despesa"),
        "Investimento" = c("investimento", "financiamento", "capital", "recurso", "fundo"),
        "Competitividade" = c("competitivo", "concorrência", "mercado", "eficiência", "produtividade"),
        "Emprego" = c("emprego", "trabalho", "contratação", "demissão", "desemprego"),
        "Crescimento" = c("crescimento", "desenvolvimento", "expansão", "pib", "economia"),
        "Inovação" = c("inovação", "tecnologia", "pesquisa", "desenvolvimento", "modernização"),
        "Comércio" = c("comércio", "exportação", "importação", "balança", "negócio"),
        "Inflação" = c("inflação", "deflação", "índice", "preços", "monetário")
      )
      
      economic_impact <- data %>%
        rowwise() %>%
        mutate(
          economic_indicators = list({
            text <- combined_text
            indicators <- c()
            
            for (indicator in names(economic_keywords)) {
              keywords <- economic_keywords[[indicator]]
              if (any(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))) {
                indicators <- c(indicators, indicator)
              }
            }
            
            indicators
          }),
          economic_impact_score = length(economic_indicators)
        ) %>%
        ungroup()
      
      # Economic impact analysis
      economic_analysis <- economic_impact %>%
        filter(economic_impact_score > 0) %>%
        unnest(economic_indicators) %>%
        group_by(economic_indicators) %>%
        summarise(
          affected_documents = n(),
          years_span = max(year) - min(year) + 1,
          states_affected = n_distinct(state, na.rm = TRUE),
          impact_intensity = n() / n_distinct(year),
          .groups = "drop"
        ) %>%
        arrange(desc(affected_documents))
      
      # Economic impact over time
      economic_temporal <- economic_impact %>%
        filter(economic_impact_score > 0) %>%
        group_by(year) %>%
        summarise(
          documents_with_economic_impact = n(),
          avg_impact_score = mean(economic_impact_score),
          total_documents = n(),
          .groups = "drop"
        ) %>%
        mutate(
          economic_intensity = documents_with_economic_impact / total_documents * 100
        )
      
      impact_results$economic_impact <- list(
        economic_analysis = economic_analysis,
        economic_temporal = economic_temporal,
        high_impact_documents = economic_impact %>%
          filter(economic_impact_score >= 3) %>%
          arrange(desc(economic_impact_score)) %>%
          head(20) %>%
          select(title, economic_impact_score, year, state),
        economic_stats = list(
          total_documents_with_economic_impact = sum(economic_impact$economic_impact_score > 0),
          avg_economic_impact_score = mean(economic_impact$economic_impact_score),
          most_affected_indicator = economic_analysis$economic_indicators[1],
          economic_coverage = (sum(economic_impact$economic_impact_score > 0) / nrow(data)) * 100
        )
      )
    }
    
    # Social impact indicators
    if (assessment_type %in% c("social", "comprehensive")) {
      cat("👥 Analyzing social impact...\n")
      
      social_keywords <- list(
        "Direitos Trabalhistas" = c("trabalhador", "direitos", "jornada", "salário", "benefício", "clt"),
        "Saúde e Segurança" = c("saúde", "segurança", "acidente", "doença", "prevenção", "proteção"),
        "Educação" = c("educação", "treinamento", "capacitação", "qualificação", "formação"),
        "Inclusão Social" = c("inclusão", "acessibilidade", "deficiente", "idoso", "mulher", "diversidade"),
        "Qualidade de Vida" = c("qualidade de vida", "bem-estar", "moradia", "transporte público"),
        "Participação Cidadã" = c("participação", "consulta pública", "audiência", "transparência"),
        "Proteção ao Consumidor" = c("consumidor", "direito do consumidor", "proteção", "defesa"),
        "Meio Ambiente Social" = c("comunidade", "impacto social", "reassentamento", "compensação")
      )
      
      social_impact <- data %>%
        rowwise() %>%
        mutate(
          social_indicators = list({
            text <- combined_text
            indicators <- c()
            
            for (indicator in names(social_keywords)) {
              keywords <- social_keywords[[indicator]]
              if (any(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))) {
                indicators <- c(indicators, indicator)
              }
            }
            
            indicators
          }),
          social_impact_score = length(social_indicators)
        ) %>%
        ungroup()
      
      # Social impact analysis
      social_analysis <- social_impact %>%
        filter(social_impact_score > 0) %>%
        unnest(social_indicators) %>%
        group_by(social_indicators) %>%
        summarise(
          affected_documents = n(),
          states_affected = n_distinct(state, na.rm = TRUE),
          temporal_span = max(year) - min(year) + 1,
          .groups = "drop"
        ) %>%
        arrange(desc(affected_documents))
      
      impact_results$social_impact <- list(
        social_analysis = social_analysis,
        high_impact_documents = social_impact %>%
          filter(social_impact_score >= 2) %>%
          arrange(desc(social_impact_score)) %>%
          head(15) %>%
          select(title, social_impact_score, year, state),
        social_stats = list(
          documents_with_social_impact = sum(social_impact$social_impact_score > 0),
          most_affected_social_area = if(nrow(social_analysis) > 0) social_analysis$social_indicators[1] else "None",
          social_coverage = (sum(social_impact$social_impact_score > 0) / nrow(data)) * 100
        )
      )
    }
    
    # Environmental impact indicators
    if (assessment_type %in% c("environmental", "comprehensive")) {
      cat("🌱 Analyzing environmental impact...\n")
      
      environmental_keywords <- list(
        "Emissões" = c("emissões", "poluição", "co2", "carbono", "gases", "atmosfera"),
        "Qualidade do Ar" = c("ar", "atmosférica", "particulado", "ozônio", "fumaça"),
        "Recursos Naturais" = c("recursos naturais", "água", "solo", "floresta", "biodiversidade"),
        "Sustentabilidade" = c("sustentável", "sustentabilidade", "verde", "renovável", "limpo"),
        "Licenciamento" = c("licenciamento ambiental", "eia", "rima", "impacto ambiental"),
        "Resíduos" = c("resíduos", "lixo", "reciclagem", "descarte", "tratamento"),
        "Energia" = c("energia", "combustível", "biocombustível", "eficiência energética"),
        "Mudanças Climáticas" = c("clima", "climático", "aquecimento", "mudanças climáticas")
      )
      
      environmental_impact <- data %>%
        rowwise() %>%
        mutate(
          environmental_indicators = list({
            text <- combined_text
            indicators <- c()
            
            for (indicator in names(environmental_keywords)) {
              keywords <- environmental_keywords[[indicator]]
              if (any(sapply(keywords, function(k) grepl(k, text, fixed = TRUE)))) {
                indicators <- c(indicators, indicator)
              }
            }
            
            indicators
          }),
          environmental_impact_score = length(environmental_indicators)
        ) %>%
        ungroup()
      
      # Environmental impact analysis
      environmental_analysis <- environmental_impact %>%
        filter(environmental_impact_score > 0) %>%
        unnest(environmental_indicators) %>%
        group_by(environmental_indicators) %>%
        summarise(
          affected_documents = n(),
          temporal_span = max(year) - min(year) + 1,
          states_affected = n_distinct(state, na.rm = TRUE),
          .groups = "drop"
        ) %>%
        arrange(desc(affected_documents))
      
      impact_results$environmental_impact <- list(
        environmental_analysis = environmental_analysis,
        high_impact_documents = environmental_impact %>%
          filter(environmental_impact_score >= 2) %>%
          arrange(desc(environmental_impact_score)) %>%
          head(15) %>%
          select(title, environmental_impact_score, year, state),
        environmental_stats = list(
          documents_with_environmental_impact = sum(environmental_impact$environmental_impact_score > 0),
          most_critical_environmental_area = if(nrow(environmental_analysis) > 0) environmental_analysis$environmental_indicators[1] else "None",
          environmental_coverage = (sum(environmental_impact$environmental_impact_score > 0) / nrow(data)) * 100
        )
      )
    }
    
    # Comprehensive impact synthesis
    if (assessment_type == "comprehensive") {
      comprehensive_impact <- data %>%
        left_join(
          if("economic_impact" %in% names(impact_results)) {
            impact_results$economic_impact$economic_analysis %>% 
              select(document_id = row_number(), economic_impact_score) 
          } else { 
            data.frame(document_id = 1:nrow(data), economic_impact_score = 0) 
          },
          by = "document_id"
        ) %>%
        left_join(
          if("social_impact" %in% names(impact_results)) {
            impact_results$social_impact$social_analysis %>% 
              select(document_id = row_number(), social_impact_score)
          } else { 
            data.frame(document_id = 1:nrow(data), social_impact_score = 0) 
          },
          by = "document_id"
        ) %>%
        left_join(
          if("environmental_impact" %in% names(impact_results)) {
            impact_results$environmental_impact$environmental_analysis %>% 
              select(document_id = row_number(), environmental_impact_score)
          } else { 
            data.frame(document_id = 1:nrow(data), environmental_impact_score = 0) 
          },
          by = "document_id"
        ) %>%
        mutate(
          total_impact_score = (economic_impact_score %||% 0) + (social_impact_score %||% 0) + (environmental_impact_score %||% 0),
          impact_category = case_when(
            total_impact_score >= 6 ~ "Alto Impacto",
            total_impact_score >= 3 ~ "Médio Impacto", 
            total_impact_score >= 1 ~ "Baixo Impacto",
            TRUE ~ "Sem Impacto Identificado"
          )
        )
      
      impact_results$comprehensive_synthesis <- list(
        impact_distribution = comprehensive_impact %>%
          count(impact_category) %>%
          mutate(percentage = (n / sum(n)) * 100),
        high_impact_documents = comprehensive_impact %>%
          filter(total_impact_score >= 4) %>%
          arrange(desc(total_impact_score)) %>%
          head(25) %>%
          select(title, total_impact_score, economic_impact_score, social_impact_score, environmental_impact_score, year, state),
        impact_by_year = comprehensive_impact %>%
          group_by(year) %>%
          summarise(
            avg_total_impact = mean(total_impact_score),
            high_impact_docs = sum(total_impact_score >= 4),
            .groups = "drop"
          )
      )
    }
    
    # Assessment metadata
    assessment_metadata <- list(
      assessment_type = assessment_type,
      railway_optimized = railway_optimized,
      documents_analyzed = nrow(data),
      analysis_date = Sys.time(),
      temporal_coverage = paste(min(data$year, na.rm = TRUE), "-", max(data$year, na.rm = TRUE)),
      geographic_coverage = n_distinct(data$state, na.rm = TRUE)
    )
    
    impact_results$assessment_metadata <- assessment_metadata
    
    cat("✅ Regulatory impact assessment completed\n")
    
    return(impact_results)
    
  }, error = function(e) {
    cat("❌ Error in regulatory impact assessment:", e$message, "\n")
    return(list(error = e$message, message = "Regulatory impact assessment failed"))
  })
}

# Helper function for null coalescing
`%||%` <- function(x, y) if (isTRUE(is.null(x)) || isTRUE(length(x) == 0) || isTRUE(is.na(x))) y else x

cat("✅ Performance & Impact Analytics Module fully loaded\n")