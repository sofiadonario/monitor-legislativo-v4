# Sentiment and Modality Analysis Module for Brazilian Legislative Documents
# MackMonitor v4 - Regulatory Tone and Policy Strictness Analysis
# Author: Analytics Module
# Date: 2025-01-25

library(sentimentr)
library(tidytext)
library(syuzhet)
library(dplyr)
library(stringr)
library(purrr)
library(ggplot2)
library(lubridate)

# ============================================================================
# 1. CONFIGURATION AND DICTIONARIES
# ============================================================================

# Portuguese sentiment lexicons
load_portuguese_lexicons <- function() {
  lexicons <- list()
  
  # OpLexicon - Portuguese sentiment lexicon
  if (file.exists("lexicons/oplexicon_v3.0.txt")) {
    oplexicon <- read.table("lexicons/oplexicon_v3.0.txt", 
                           header = FALSE, 
                           sep = ",",
                           stringsAsFactors = FALSE,
                           col.names = c("word", "type", "polarity", "annotation"))
    lexicons$oplexicon <- oplexicon %>%
      select(word, polarity) %>%
      mutate(polarity = as.numeric(polarity))
  }
  
  # SentiLex-PT
  if (file.exists("lexicons/SentiLex-PT02.txt")) {
    # Custom parser for SentiLex format
    sentilex <- read.csv("lexicons/SentiLex-PT02.txt", 
                        header = FALSE, 
                        sep = ";",
                        stringsAsFactors = FALSE)
    # Parse polarity from format
    lexicons$sentilex <- sentilex  # Would need proper parsing
  }
  
  # Fallback: basic Portuguese sentiment words
  lexicons$basic <- data.frame(
    word = c(
      # Positive
      "bom", "melhor", "ótimo", "excelente", "positivo", "benefício",
      "progresso", "avanço", "sucesso", "eficiente", "eficaz", "qualidade",
      "inovação", "desenvolvimento", "crescimento", "proteção", "segurança",
      "transparência", "sustentável", "inclusão",
      # Negative
      "ruim", "pior", "péssimo", "negativo", "problema", "dificuldade",
      "atraso", "fracasso", "ineficiente", "ineficaz", "corrupção",
      "violação", "ilegal", "irregular", "prejuízo", "dano", "risco",
      "ameaça", "crise", "deficiência"
    ),
    polarity = c(rep(1, 20), rep(-1, 20))
  )
  
  return(lexicons)
}

# Legal and regulatory modality dictionaries
create_modality_dictionaries <- function() {
  dict <- list()
  
  # Obligation/Requirement verbs (deontic modality)
  dict$obligation <- c(
    "deverá", "devem", "deve", "deverão",
    "obrigatório", "obrigatória", "obrigatoriamente",
    "necessário", "necessária", "necessariamente",
    "imprescindível", "mandatório", "compulsório",
    "exigido", "exige", "requer", "requerido",
    "incumbe", "compete", "cumprir", "observar"
  )
  
  # Permission verbs (permissive modality)
  dict$permission <- c(
    "poderá", "podem", "pode", "poderão",
    "permitido", "permitida", "autorizado", "autorizada",
    "facultado", "facultativo", "opcional",
    "livre", "possível", "admitido", "admissível",
    "lícito", "legítimo"
  )
  
  # Prohibition verbs (prohibitive modality)
  dict$prohibition <- c(
    "proibido", "proibida", "vedado", "vedada",
    "não poderá", "não pode", "não podem",
    "impedido", "impedida", "ilícito", "ilegal",
    "irregular", "inadmissível", "inaceitável"
  )
  
  # Recommendation verbs (advisory modality)
  dict$recommendation <- c(
    "recomenda", "recomendado", "aconselhável",
    "sugere", "sugerido", "conveniente",
    "preferível", "desejável", "apropriado"
  )
  
  # Regulatory strictness indicators
  dict$strict <- c(
    "rigoroso", "rigorosa", "estrito", "estrita",
    "severo", "severa", "rígido", "rígida",
    "inflexível", "taxativo", "peremptório",
    "sob pena", "penalidade", "sanção", "multa",
    "punição", "infração", "autuação", "embargo"
  )
  
  dict$flexible <- c(
    "flexível", "adaptável", "ajustável",
    "exceção", "ressalva", "salvo", "exceto",
    "caso a caso", "critério", "discricionário",
    "alternativo", "opcional", "facultativo"
  )
  
  # Policy action verbs
  dict$action_verbs <- c(
    # Implementation
    "implementar", "executar", "realizar", "efetuar",
    "estabelecer", "instituir", "criar", "constituir",
    # Regulation
    "regular", "regulamentar", "normatizar", "disciplinar",
    "fiscalizar", "supervisionar", "controlar", "monitorar",
    # Modification
    "alterar", "modificar", "revogar", "substituir",
    "atualizar", "revisar", "adequar", "ajustar",
    # Authorization
    "autorizar", "aprovar", "homologar", "validar",
    "conceder", "outorgar", "deferir", "permitir"
  )
  
  return(dict)
}

# ============================================================================
# 2. SENTIMENT ANALYSIS FUNCTIONS
# ============================================================================

#' Analyze sentiment using multiple methods
#' @param texts Character vector of texts
#' @param method Sentiment method to use
#' @param lexicon Sentiment lexicon
#' @return Data frame with sentiment scores
analyze_sentiment_multi <- function(texts, 
                                   method = "sentimentr",
                                   lexicon = NULL) {
  
  results <- data.frame(
    text_id = 1:length(texts),
    text_length = str_count(texts, "\\w+")
  )
  
  # Method 1: sentimentr (sentence-level)
  if (method %in% c("sentimentr", "all")) {
    sent_scores <- sentiment(texts)
    
    results$sentiment_mean <- sent_scores %>%
      group_by(element_id) %>%
      summarise(sentiment = mean(sentiment, na.rm = TRUE)) %>%
      pull(sentiment)
    
    results$sentiment_sd <- sent_scores %>%
      group_by(element_id) %>%
      summarise(sd = sd(sentiment, na.rm = TRUE)) %>%
      pull(sd)
  }
  
  # Method 2: Lexicon-based
  if (method %in% c("lexicon", "all") && !is.null(lexicon)) {
    lex_scores <- map_dbl(texts, function(text) {
      words <- str_split(tolower(text), "\\s+")[[1]]
      matches <- lexicon$word %in% words
      if (sum(matches) > 0) {
        return(mean(lexicon$polarity[matches]))
      } else {
        return(0)
      }
    })
    results$lexicon_sentiment <- lex_scores
  }
  
  # Method 3: Syuzhet (emotion detection)
  if (method %in% c("syuzhet", "all")) {
    emotions <- get_nrc_sentiment(texts, language = "portuguese")
    results <- cbind(results, emotions)
  }
  
  # Calculate overall sentiment category
  if ("sentiment_mean" %in% names(results)) {
    results$sentiment_category <- cut(
      results$sentiment_mean,
      breaks = c(-Inf, -0.1, 0.1, Inf),
      labels = c("Negative", "Neutral", "Positive")
    )
  }
  
  return(results)
}

#' Analyze sentiment by document sections
#' @param text Full document text
#' @param section_markers Regex patterns for sections
#' @return Section-level sentiment scores
analyze_sentiment_by_section <- function(text, 
                                       section_markers = NULL) {
  
  if (is.null(section_markers)) {
    # Default legal document sections
    section_markers <- c(
      preambulo = "^(o|a)\\s+(presidente|governador|prefeito)",
      considerandos = "considerando",
      dispositivos = "(art(igo)?\\s*\\d+|capítulo|seção)",
      disposicoes_finais = "disposições\\s+(finais|gerais)",
      vigencia = "esta\\s+lei\\s+entra\\s+em\\s+vigor"
    )
  }
  
  # Split text into sections
  sections <- list()
  remaining_text <- text
  
  for (section_name in names(section_markers)) {
    pattern <- section_markers[section_name]
    if (grepl(pattern, remaining_text, ignore.case = TRUE)) {
      # Extract section
      match_pos <- regexpr(pattern, remaining_text, ignore.case = TRUE)
      section_start <- match_pos[1]
      
      # Find next section or end
      other_patterns <- section_markers[names(section_markers) != section_name]
      next_positions <- map_int(other_patterns, function(p) {
        pos <- regexpr(p, substr(remaining_text, section_start, nchar(remaining_text)), 
                      ignore.case = TRUE)[1]
        ifelse(pos > 0, pos + section_start - 1, nchar(remaining_text))
      })
      
      section_end <- min(next_positions)
      sections[[section_name]] <- substr(remaining_text, section_start, section_end)
    }
  }
  
  # Analyze each section
  section_sentiments <- map_dfr(names(sections), function(section_name) {
    sentiment_scores <- sentiment(sections[[section_name]])
    
    data.frame(
      section = section_name,
      sentiment_mean = mean(sentiment_scores$sentiment, na.rm = TRUE),
      sentiment_sd = sd(sentiment_scores$sentiment, na.rm = TRUE),
      n_sentences = nrow(sentiment_scores)
    )
  })
  
  return(section_sentiments)
}

# ============================================================================
# 3. MODALITY ANALYSIS FUNCTIONS
# ============================================================================

#' Analyze legal modality in texts
#' @param texts Character vector of texts
#' @param dictionaries Modality dictionaries
#' @return Data frame with modality scores
analyze_modality <- function(texts, 
                           dictionaries = create_modality_dictionaries()) {
  
  results <- data.frame(
    text_id = 1:length(texts),
    text_length = str_count(texts, "\\w+")
  )
  
  # Count modality markers
  for (modality in names(dictionaries)) {
    pattern <- paste0("\\b(", paste(dictionaries[[modality]], collapse = "|"), ")\\b")
    results[[paste0(modality, "_count")]] <- str_count(tolower(texts), pattern)
    results[[paste0(modality, "_density")]] <- results[[paste0(modality, "_count")]] / 
                                               results$text_length * 1000
  }
  
  # Calculate regulatory strictness index
  results$strictness_index <- (results$obligation_density + 
                              results$prohibition_density + 
                              results$strict_density) -
                             (results$permission_density + 
                              results$flexible_density)
  
  # Classify regulatory approach
  results$regulatory_style <- case_when(
    results$strictness_index > 10 ~ "Highly Prescriptive",
    results$strictness_index > 5 ~ "Prescriptive",
    results$strictness_index > -5 ~ "Balanced",
    results$strictness_index > -10 ~ "Flexible",
    TRUE ~ "Highly Flexible"
  )
  
  # Dominant modality
  modality_cols <- grep("_density$", names(results), value = TRUE)
  modality_cols <- modality_cols[!grepl("(strict|flexible)", modality_cols)]
  
  results$dominant_modality <- apply(results[modality_cols], 1, function(x) {
    if (all(x == 0)) return("None")
    names(x)[which.max(x)]
  })
  
  results$dominant_modality <- gsub("_density", "", results$dominant_modality)
  
  return(results)
}

#' Extract policy action patterns
#' @param texts Character vector of texts
#' @param action_dict Action verb dictionary
#' @return Data frame with action patterns
extract_policy_actions <- function(texts, 
                                 action_dict = create_modality_dictionaries()$action_verbs) {
  
  # Create pattern for action verbs
  action_pattern <- paste0("(", paste(action_dict, collapse = "|"), ")")
  
  # Extract sentences with action verbs
  action_sentences <- map(texts, function(text) {
    sentences <- unlist(str_split(text, "[.!?]+"))
    action_sents <- sentences[grepl(action_pattern, sentences, ignore.case = TRUE)]
    
    if (length(action_sents) > 0) {
      # Extract verb and object
      map_dfr(action_sents, function(sent) {
        verb_match <- str_extract(tolower(sent), action_pattern)
        
        # Try to extract object (simplified)
        after_verb <- str_split(sent, verb_match, n = 2)[[1]][2]
        object <- str_extract(after_verb, "\\w+\\s+\\w+")
        
        data.frame(
          sentence = sent,
          action_verb = verb_match,
          object = object,
          stringsAsFactors = FALSE
        )
      })
    } else {
      NULL
    }
  })
  
  # Combine results
  all_actions <- bind_rows(action_sentences, .id = "text_id")
  
  # Summarize action patterns
  action_summary <- all_actions %>%
    group_by(action_verb) %>%
    summarise(
      frequency = n(),
      example_objects = paste(unique(na.omit(object))[1:3], collapse = "; ")
    ) %>%
    arrange(desc(frequency))
  
  return(list(
    actions = all_actions,
    summary = action_summary
  ))
}

# ============================================================================
# 4. TEMPORAL ANALYSIS
# ============================================================================

#' Analyze sentiment and modality over time
#' @param documents Data frame with texts and dates
#' @param time_unit Time aggregation unit
#' @return Time series of sentiment/modality
analyze_temporal_patterns <- function(documents, 
                                    time_unit = "year") {
  
  # Add time period
  documents$period <- floor_date(documents$data_publicacao, time_unit)
  
  # Analyze sentiment for each document
  sentiment_results <- analyze_sentiment_multi(documents$conteudo)
  modality_results <- analyze_modality(documents$conteudo)
  
  # Combine with document metadata
  combined <- cbind(
    documents[, c("id", "period", "tipo", "authority_level")],
    sentiment_results,
    modality_results[, -c(1:2)]  # Remove duplicate columns
  )
  
  # Aggregate by time period
  temporal_summary <- combined %>%
    group_by(period) %>%
    summarise(
      n_documents = n(),
      # Sentiment
      avg_sentiment = mean(sentiment_mean, na.rm = TRUE),
      sentiment_volatility = sd(sentiment_mean, na.rm = TRUE),
      pct_positive = mean(sentiment_category == "Positive", na.rm = TRUE),
      pct_negative = mean(sentiment_category == "Negative", na.rm = TRUE),
      # Modality
      avg_strictness = mean(strictness_index, na.rm = TRUE),
      pct_prescriptive = mean(regulatory_style %in% 
                             c("Prescriptive", "Highly Prescriptive"), na.rm = TRUE),
      # Dominant patterns
      most_common_modality = names(sort(table(dominant_modality), 
                                       decreasing = TRUE))[1]
    )
  
  # Calculate trends
  temporal_summary <- temporal_summary %>%
    arrange(period) %>%
    mutate(
      sentiment_trend = c(NA, diff(avg_sentiment)),
      strictness_trend = c(NA, diff(avg_strictness))
    )
  
  return(temporal_summary)
}

# ============================================================================
# 5. DOMAIN-SPECIFIC ANALYSIS
# ============================================================================

#' Analyze regulatory impact language
#' @param texts Character vector of regulatory texts
#' @return Impact analysis results
analyze_regulatory_impact <- function(texts) {
  
  # Impact-related keywords
  impact_dict <- list(
    economic = c("econômico", "custo", "investimento", "orçamento", "receita",
                "despesa", "fiscal", "tributário", "financeiro"),
    social = c("social", "população", "cidadão", "comunidade", "público",
               "sociedade", "beneficiário", "vulnerável", "inclusão"),
    environmental = c("ambiental", "sustentável", "preservação", "conservação",
                     "poluição", "emissão", "resíduo", "recurso natural"),
    administrative = c("administrativo", "burocrático", "procedimento", "prazo",
                      "documentação", "processo", "tramitação", "simplificação")
  )
  
  results <- data.frame(text_id = 1:length(texts))
  
  # Count impact mentions
  for (impact_type in names(impact_dict)) {
    pattern <- paste0("\\b(", paste(impact_dict[[impact_type]], collapse = "|"), ")\\b")
    results[[paste0(impact_type, "_mentions")]] <- str_count(tolower(texts), pattern)
  }
  
  # Identify primary impact focus
  impact_cols <- paste0(names(impact_dict), "_mentions")
  results$primary_impact <- apply(results[impact_cols], 1, function(x) {
    if (all(x == 0)) return("None")
    names(impact_dict)[which.max(x)]
  })
  
  # Extract quantitative commitments
  results$has_metrics <- str_detect(texts, "\\d+\\s*(por cento|%|reais|R\\$|dias|meses|anos)")
  results$has_deadlines <- str_detect(texts, "(prazo|até|dentro de|no máximo)\\s*\\d+\\s*(dias|meses|anos)")
  
  return(results)
}

# ============================================================================
# 6. VISUALIZATION FUNCTIONS
# ============================================================================

#' Create sentiment distribution plot
#' @param sentiment_data Sentiment analysis results
#' @return ggplot object
plot_sentiment_distribution <- function(sentiment_data) {
  p <- ggplot(sentiment_data, aes(x = sentiment_mean, fill = sentiment_category)) +
    geom_histogram(bins = 30, alpha = 0.7) +
    geom_vline(xintercept = 0, linetype = "dashed", color = "gray40") +
    scale_fill_manual(values = c("Negative" = "#e74c3c", 
                                "Neutral" = "#95a5a6", 
                                "Positive" = "#27ae60")) +
    theme_minimal() +
    labs(
      title = "Distribution of Document Sentiment",
      x = "Sentiment Score",
      y = "Number of Documents",
      fill = "Sentiment"
    )
  
  return(p)
}

#' Create modality profile radar chart
#' @param modality_data Modality analysis results
#' @return ggplot object
plot_modality_profile <- function(modality_data) {
  library(ggradar)
  
  # Prepare data for radar chart
  modality_cols <- c("obligation_density", "permission_density", 
                    "prohibition_density", "recommendation_density")
  
  radar_data <- modality_data %>%
    select(all_of(modality_cols)) %>%
    summarise_all(mean, na.rm = TRUE) %>%
    mutate(group = "Average") %>%
    select(group, everything())
  
  # Normalize to 0-1 scale
  radar_data[, -1] <- scale(radar_data[, -1], 
                           center = FALSE, 
                           scale = apply(radar_data[, -1], 2, max, na.rm = TRUE))
  
  p <- ggradar(radar_data,
               grid.min = 0,
               grid.max = 1,
               group.line.width = 1,
               group.point.size = 3,
               legend.position = "bottom") +
    labs(title = "Regulatory Modality Profile")
  
  return(p)
}

#' Create temporal trends plot
#' @param temporal_data Temporal analysis results
#' @param metric Which metric to plot
#' @return ggplot object
plot_temporal_trends <- function(temporal_data, 
                               metric = c("sentiment", "strictness")) {
  
  metric <- match.arg(metric)
  
  if (metric == "sentiment") {
    p <- ggplot(temporal_data, aes(x = period)) +
      geom_line(aes(y = avg_sentiment), color = "steelblue", size = 1.2) +
      geom_ribbon(aes(ymin = avg_sentiment - sentiment_volatility,
                     ymax = avg_sentiment + sentiment_volatility),
                 alpha = 0.2, fill = "steelblue") +
      geom_hline(yintercept = 0, linetype = "dashed", color = "gray40") +
      theme_minimal() +
      labs(
        title = "Sentiment Trends in Legislative Documents",
        x = "Time Period",
        y = "Average Sentiment Score"
      )
  } else {
    p <- ggplot(temporal_data, aes(x = period)) +
      geom_line(aes(y = avg_strictness), color = "darkred", size = 1.2) +
      geom_area(aes(y = pct_prescriptive * 10), alpha = 0.3, fill = "darkred") +
      theme_minimal() +
      labs(
        title = "Regulatory Strictness Over Time",
        x = "Time Period",
        y = "Strictness Index"
      ) +
      scale_y_continuous(
        sec.axis = sec_axis(~./10, name = "% Prescriptive Documents")
      )
  }
  
  return(p)
}

# ============================================================================
# 7. MAIN ANALYSIS PIPELINE
# ============================================================================

#' Complete sentiment and modality analysis pipeline
#' @param documents Data frame with document texts
#' @param config Analysis configuration
#' @return List with analysis results
run_sentiment_modality_pipeline <- function(documents, config = NULL) {
  
  cat("\n=== SENTIMENT AND MODALITY ANALYSIS PIPELINE ===\n")
  
  results <- list()
  
  # 1. Load resources
  cat("\n1. Loading lexicons and dictionaries...\n")
  lexicons <- load_portuguese_lexicons()
  dictionaries <- create_modality_dictionaries()
  
  # 2. Document-level analysis
  cat("\n2. Analyzing document sentiment...\n")
  results$sentiment <- analyze_sentiment_multi(
    documents$conteudo,
    method = "all",
    lexicon = lexicons$basic
  )
  
  cat("\n3. Analyzing regulatory modality...\n")
  results$modality <- analyze_modality(documents$conteudo, dictionaries)
  
  # 4. Section-level analysis (sample)
  cat("\n4. Analyzing sentiment by sections (sample)...\n")
  sample_docs <- sample(which(nchar(documents$conteudo) > 1000), 
                       min(100, sum(nchar(documents$conteudo) > 1000)))
  
  results$section_sentiment <- map_dfr(sample_docs, function(i) {
    section_analysis <- analyze_sentiment_by_section(documents$conteudo[i])
    section_analysis$doc_id <- documents$id[i]
    section_analysis
  })
  
  # 5. Policy action extraction
  cat("\n5. Extracting policy actions...\n")
  results$policy_actions <- extract_policy_actions(documents$conteudo, 
                                                  dictionaries$action_verbs)
  
  # 6. Impact analysis
  cat("\n6. Analyzing regulatory impact language...\n")
  results$impact <- analyze_regulatory_impact(documents$conteudo)
  
  # 7. Temporal patterns
  cat("\n7. Analyzing temporal patterns...\n")
  results$temporal <- analyze_temporal_patterns(documents)
  
  # 8. Generate visualizations
  cat("\n8. Creating visualizations...\n")
  results$plots <- list(
    sentiment_dist = plot_sentiment_distribution(results$sentiment),
    modality_profile = plot_modality_profile(results$modality),
    sentiment_trends = plot_temporal_trends(results$temporal, "sentiment"),
    strictness_trends = plot_temporal_trends(results$temporal, "strictness")
  )
  
  # 9. Summary statistics
  results$summary <- list(
    sentiment = list(
      mean_sentiment = mean(results$sentiment$sentiment_mean, na.rm = TRUE),
      sentiment_distribution = table(results$sentiment$sentiment_category),
      most_positive_docs = documents$id[order(results$sentiment$sentiment_mean, 
                                             decreasing = TRUE)[1:5]],
      most_negative_docs = documents$id[order(results$sentiment$sentiment_mean)[1:5]]
    ),
    modality = list(
      regulatory_styles = table(results$modality$regulatory_style),
      avg_strictness = mean(results$modality$strictness_index, na.rm = TRUE),
      dominant_modalities = table(results$modality$dominant_modality)
    ),
    actions = list(
      total_actions = nrow(results$policy_actions$actions),
      top_action_verbs = head(results$policy_actions$summary, 10)
    ),
    impact = list(
      impact_focus = table(results$impact$primary_impact),
      pct_with_metrics = mean(results$impact$has_metrics, na.rm = TRUE),
      pct_with_deadlines = mean(results$impact$has_deadlines, na.rm = TRUE)
    )
  )
  
  cat("\nSentiment and modality analysis complete!\n")
  
  return(results)
}

# ============================================================================
# 8. EXPORT FUNCTIONS
# ============================================================================

#' Save sentiment and modality results
#' @param results Analysis results
#' @param output_dir Output directory
save_sentiment_modality_results <- function(results, 
                                          output_dir = "sentiment_modality_output") {
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Save data tables
  write.csv(results$sentiment, 
            file.path(output_dir, "sentiment_analysis.csv"), 
            row.names = FALSE)
  
  write.csv(results$modality, 
            file.path(output_dir, "modality_analysis.csv"), 
            row.names = FALSE)
  
  write.csv(results$temporal, 
            file.path(output_dir, "temporal_patterns.csv"), 
            row.names = FALSE)
  
  write.csv(results$policy_actions$summary, 
            file.path(output_dir, "policy_actions_summary.csv"), 
            row.names = FALSE)
  
  # Save plots
  for (plot_name in names(results$plots)) {
    ggsave(
      file.path(output_dir, paste0(plot_name, ".png")),
      results$plots[[plot_name]],
      width = 10,
      height = 8
    )
  }
  
  # Save summary report
  saveRDS(results$summary, file.path(output_dir, "analysis_summary.rds"))
  
  # Create summary report
  sink(file.path(output_dir, "summary_report.txt"))
  cat("SENTIMENT AND MODALITY ANALYSIS SUMMARY\n")
  cat("=======================================\n\n")
  
  cat("SENTIMENT ANALYSIS:\n")
  cat(sprintf("Average sentiment: %.3f\n", results$summary$sentiment$mean_sentiment))
  print(results$summary$sentiment$sentiment_distribution)
  
  cat("\n\nREGULATORY MODALITY:\n")
  cat(sprintf("Average strictness index: %.2f\n", results$summary$modality$avg_strictness))
  print(results$summary$modality$regulatory_styles)
  
  cat("\n\nPOLICY ACTIONS:\n")
  cat(sprintf("Total action statements: %d\n", results$summary$actions$total_actions))
  cat("\nTop action verbs:\n")
  print(results$summary$actions$top_action_verbs)
  
  cat("\n\nREGULATORY IMPACT:\n")
  print(results$summary$impact$impact_focus)
  cat(sprintf("\nDocuments with metrics: %.1f%%\n", 
              results$summary$impact$pct_with_metrics * 100))
  cat(sprintf("Documents with deadlines: %.1f%%\n", 
              results$summary$impact$pct_with_deadlines * 100))
  
  sink()
  
  cat(sprintf("\nResults saved to %s/\n", output_dir))
}