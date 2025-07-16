# ============================================================================
# ANALYTICS ABRANGENTES PARA DATASET LEXML - TRANSPORTE DE CARGA
# Autor: Manus AI
# Data: 2025-07-12
# Descrição: Conjunto completo de análises para o dataset LexML corrigido
# ============================================================================

# Carregamento de Pacotes ====================================================
library(tidyverse)      # Manipulação de dados
library(lubridate)      # Manipulação de datas
library(tm)             # Text mining
library(tidytext)       # Text mining tidy
library(wordcloud)      # Nuvens de palavras
library(igraph)         # Análise de redes
library(networkD3)      # Visualização de redes interativas
library(plotly)         # Gráficos interativos
library(forecast)       # Séries temporais
library(tseries)        # Testes de séries temporais
library(changepoint)    # Detecção de mudanças
library(topicmodels)    # Modelagem de tópicos
library(quanteda)       # Análise quantitativa de texto
library(ggraph)         # Visualização de grafos
library(visNetwork)     # Redes interativas
library(DT)             # Tabelas interativas
library(leaflet)        # Mapas interativos
library(sf)             # Dados espaciais
library(corrplot)       # Matriz de correlação
library(cluster)        # Análise de clusters
library(factoextra)     # Visualização de clusters
library(survival)       # Análise de sobrevivência
library(randomForest)   # Machine learning
library(caret)          # Machine learning
library(xgboost)        # Gradient boosting
library(shiny)          # Aplicações web
library(shinydashboard) # Dashboards
library(flexdashboard)  # Dashboards flexíveis

# Configurações Globais ======================================================
options(scipen = 999)  # Evitar notação científica
Sys.setlocale("LC_TIME", "pt_BR.UTF-8")  # Configurar locale para português

# Função para carregar dados =================================================
load_lexml_data <- function(file_path) {
  data <- read_csv(file_path, locale = locale(encoding = "UTF-8"))
  
  # Limpeza e preparação dos dados
  data <- data %>%
    mutate(
      enacting_date = as.Date(enacting_date),
      year = year(enacting_date),
      month = month(enacting_date),
      decade = floor(year / 10) * 10,
      document_type_clean = case_when(
        urn_type == "legislation" ~ "Legislação",
        urn_type == "jurisprudence" ~ "Jurisprudência",
        urn_type == "doctrine" ~ "Doutrina",
        TRUE ~ "Outros"
      ),
      authority_clean = case_when(
        str_detect(tolower(authority), "federal") ~ "Federal",
        str_detect(tolower(authority), "estadual") ~ "Estadual",
        str_detect(tolower(authority), "municipal") ~ "Municipal",
        str_detect(tolower(authority), "distrital") ~ "Distrital",
        TRUE ~ authority
      )
    ) %>%
    filter(!is.na(enacting_date), year >= 1950, year <= 2025)
  
  return(data)
}

# 1. ANÁLISE TEMPORAL AVANÇADA ===============================================

# 1.1 Análise de Tendências Temporais
temporal_analysis <- function(data) {
  
  # Série temporal por ano
  yearly_counts <- data %>%
    count(year, document_type_clean) %>%
    complete(year = 1950:2025, document_type_clean, fill = list(n = 0))
  
  # Gráfico de tendências por tipo
  p1 <- ggplot(yearly_counts, aes(x = year, y = n, color = document_type_clean)) +
    geom_line(size = 1.2) +
    geom_smooth(method = "loess", se = TRUE, alpha = 0.3) +
    scale_x_continuous(breaks = seq(1950, 2025, 10)) +
    labs(
      title = "Evolução Temporal da Produção Normativa - Transporte de Carga",
      subtitle = "Análise de tendências por tipo de documento (1950-2025)",
      x = "Ano",
      y = "Número de Documentos",
      color = "Tipo de Documento"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(size = 14, face = "bold"),
      legend.position = "bottom"
    )
  
  # Análise de sazonalidade mensal
  monthly_analysis <- data %>%
    count(month, document_type_clean) %>%
    mutate(month_name = month.name[month])
  
  p2 <- ggplot(monthly_analysis, aes(x = month, y = n, fill = document_type_clean)) +
    geom_col(position = "dodge") +
    scale_x_continuous(breaks = 1:12, labels = month.abb) +
    labs(
      title = "Sazonalidade da Produção Normativa",
      subtitle = "Distribuição mensal por tipo de documento",
      x = "Mês",
      y = "Número de Documentos",
      fill = "Tipo de Documento"
    ) +
    theme_minimal()
  
  # Detecção de pontos de mudança
  ts_data <- yearly_counts %>%
    filter(document_type_clean == "Legislação") %>%
    arrange(year) %>%
    pull(n)
  
  cpt_analysis <- cpt.mean(ts_data, method = "PELT")
  change_points <- cpts(cpt_analysis)
  change_years <- yearly_counts$year[change_points]
  
  # Análise de ciclos políticos (mandatos presidenciais)
  presidential_terms <- data.frame(
    start = c(1995, 2003, 2011, 2016, 2019, 2023),
    end = c(2002, 2010, 2016, 2018, 2022, 2026),
    president = c("FHC", "Lula", "Dilma", "Temer", "Bolsonaro", "Lula III")
  )
  
  political_analysis <- data %>%
    mutate(
      presidential_term = case_when(
        year >= 1995 & year <= 2002 ~ "FHC (1995-2002)",
        year >= 2003 & year <= 2010 ~ "Lula (2003-2010)",
        year >= 2011 & year <= 2016 ~ "Dilma (2011-2016)",
        year >= 2016 & year <= 2018 ~ "Temer (2016-2018)",
        year >= 2019 & year <= 2022 ~ "Bolsonaro (2019-2022)",
        year >= 2023 ~ "Lula III (2023-)",
        TRUE ~ "Outros"
      )
    ) %>%
    filter(presidential_term != "Outros") %>%
    count(presidential_term, document_type_clean)
  
  p3 <- ggplot(political_analysis, aes(x = presidential_term, y = n, fill = document_type_clean)) +
    geom_col(position = "dodge") +
    coord_flip() +
    labs(
      title = "Produção Normativa por Mandato Presidencial",
      subtitle = "Análise de ciclos políticos no transporte de carga",
      x = "Mandato Presidencial",
      y = "Número de Documentos",
      fill = "Tipo de Documento"
    ) +
    theme_minimal()
  
  return(list(
    trends = p1,
    seasonality = p2,
    political_cycles = p3,
    change_points = change_years,
    yearly_data = yearly_counts
  ))
}

# 1.2 Previsão de Séries Temporais
forecast_analysis <- function(data) {
  
  # Preparar série temporal
  ts_data <- data %>%
    filter(document_type_clean == "Legislação") %>%
    count(year) %>%
    complete(year = 1950:2025, fill = list(n = 0)) %>%
    arrange(year)
  
  # Criar objeto ts
  ts_obj <- ts(ts_data$n, start = 1950, frequency = 1)
  
  # Modelos de previsão
  models <- list(
    arima = auto.arima(ts_obj),
    ets = ets(ts_obj),
    naive = naive(ts_obj),
    seasonal_naive = snaive(ts_obj)
  )
  
  # Previsões para 5 anos
  forecasts <- map(models, ~ forecast(.x, h = 5))
  
  # Visualização das previsões
  forecast_df <- map_dfr(forecasts, ~ {
    data.frame(
      year = 2026:2030,
      forecast = as.numeric(.x$mean),
      lower = as.numeric(.x$lower[,2]),
      upper = as.numeric(.x$upper[,2])
    )
  }, .id = "model")
  
  p_forecast <- ggplot() +
    geom_line(data = ts_data, aes(x = year, y = n), color = "black", size = 1) +
    geom_line(data = forecast_df, aes(x = year, y = forecast, color = model), size = 1) +
    geom_ribbon(data = forecast_df, aes(x = year, ymin = lower, ymax = upper, fill = model), alpha = 0.3) +
    labs(
      title = "Previsão da Produção Legislativa - Transporte de Carga",
      subtitle = "Modelos de previsão para 2026-2030",
      x = "Ano",
      y = "Número de Documentos",
      color = "Modelo",
      fill = "Modelo"
    ) +
    theme_minimal()
  
  return(list(
    models = models,
    forecasts = forecasts,
    plot = p_forecast,
    accuracy = map_dfr(models, accuracy, .id = "model")
  ))
}

# 2. ANÁLISE DE TEXTO E MINERAÇÃO ============================================

# 2.1 Análise de Frequência de Termos
text_analysis <- function(data) {
  
  # Preparar corpus
  corpus_data <- data %>%
    select(urn, document_summary, document_description, document_type_clean) %>%
    filter(!is.na(document_summary), document_summary != "")
  
  # Tokenização e limpeza
  tokens <- corpus_data %>%
    unnest_tokens(word, document_summary) %>%
    anti_join(stop_words, by = "word") %>%
    filter(
      !str_detect(word, "^\\d+$"),  # Remove números
      str_length(word) > 2,         # Remove palavras muito curtas
      !word %in% c("art", "lei", "decreto", "urn", "lex", "br")  # Remove termos técnicos
    )
  
  # Frequência de termos
  word_freq <- tokens %>%
    count(word, sort = TRUE) %>%
    top_n(50)
  
  # Nuvem de palavras
  wordcloud_plot <- function() {
    wordcloud(
      words = word_freq$word,
      freq = word_freq$n,
      min.freq = 5,
      max.words = 100,
      random.order = FALSE,
      rot.per = 0.35,
      colors = brewer.pal(8, "Dark2")
    )
  }
  
  # TF-IDF por tipo de documento
  tfidf_analysis <- tokens %>%
    count(document_type_clean, word) %>%
    bind_tf_idf(word, document_type_clean, n) %>%
    group_by(document_type_clean) %>%
    top_n(15, tf_idf) %>%
    ungroup()
  
  p_tfidf <- ggplot(tfidf_analysis, aes(x = reorder(word, tf_idf), y = tf_idf, fill = document_type_clean)) +
    geom_col(show.legend = FALSE) +
    facet_wrap(~document_type_clean, scales = "free") +
    coord_flip() +
    labs(
      title = "Termos Mais Distintivos por Tipo de Documento",
      subtitle = "Análise TF-IDF dos termos mais característicos",
      x = "Termo",
      y = "TF-IDF"
    ) +
    theme_minimal()
  
  return(list(
    word_freq = word_freq,
    wordcloud = wordcloud_plot,
    tfidf = p_tfidf,
    tokens = tokens
  ))
}

# 2.2 Modelagem de Tópicos
topic_modeling <- function(data, k = 8) {
  
  # Preparar dados para LDA
  corpus_data <- data %>%
    select(urn, document_summary) %>%
    filter(!is.na(document_summary), document_summary != "")
  
  # Criar corpus quanteda
  corpus <- corpus(corpus_data, text_field = "document_summary")
  
  # Tokenização e limpeza
  tokens <- tokens(corpus, remove_punct = TRUE, remove_numbers = TRUE) %>%
    tokens_tolower() %>%
    tokens_remove(stopwords("portuguese")) %>%
    tokens_remove(c("art", "lei", "decreto", "urn", "lex", "br", "federal"))
  
  # Criar DFM
  dfm <- dfm(tokens) %>%
    dfm_trim(min_termfreq = 5, min_docfreq = 2)
  
  # Modelo LDA
  lda_model <- LDA(dfm, k = k, control = list(seed = 123))
  
  # Extrair tópicos
  topics <- tidy(lda_model, matrix = "beta") %>%
    group_by(topic) %>%
    top_n(10, beta) %>%
    ungroup() %>%
    arrange(topic, -beta)
  
  # Visualização dos tópicos
  p_topics <- topics %>%
    mutate(term = reorder_within(term, beta, topic)) %>%
    ggplot(aes(term, beta, fill = factor(topic))) +
    geom_col(show.legend = FALSE) +
    facet_wrap(~ topic, scales = "free") +
    coord_flip() +
    scale_x_reordered() +
    labs(
      title = "Principais Tópicos na Regulamentação de Transporte de Carga",
      subtitle = paste("Modelagem LDA com", k, "tópicos"),
      x = "Termo",
      y = "Probabilidade (Beta)"
    ) +
    theme_minimal()
  
  # Distribuição de tópicos por documento
  doc_topics <- tidy(lda_model, matrix = "gamma")
  
  return(list(
    model = lda_model,
    topics = topics,
    plot = p_topics,
    doc_topics = doc_topics
  ))
}

# 2.3 Análise de Sentimento
sentiment_analysis <- function(data) {
  
  # Carregar léxico de sentimentos em português
  # Nota: Seria necessário um léxico específico para português
  # Aqui usamos uma abordagem simplificada
  
  positive_words <- c("melhoria", "desenvolvimento", "crescimento", "eficiência", 
                     "modernização", "inovação", "sustentável", "segurança")
  negative_words <- c("problema", "dificuldade", "restrição", "limitação", 
                     "proibição", "multa", "penalidade", "infração")
  
  # Análise de sentimento
  sentiment_data <- data %>%
    select(urn, document_summary, year, document_type_clean) %>%
    filter(!is.na(document_summary)) %>%
    mutate(
      text_lower = tolower(document_summary),
      positive_count = str_count(text_lower, paste(positive_words, collapse = "|")),
      negative_count = str_count(text_lower, paste(negative_words, collapse = "|")),
      sentiment_score = positive_count - negative_count,
      sentiment_category = case_when(
        sentiment_score > 0 ~ "Positivo",
        sentiment_score < 0 ~ "Negativo",
        TRUE ~ "Neutro"
      )
    )
  
  # Evolução do sentimento ao longo do tempo
  sentiment_temporal <- sentiment_data %>%
    group_by(year, sentiment_category) %>%
    summarise(count = n(), .groups = "drop") %>%
    group_by(year) %>%
    mutate(proportion = count / sum(count))
  
  p_sentiment <- ggplot(sentiment_temporal, aes(x = year, y = proportion, fill = sentiment_category)) +
    geom_area(position = "stack") +
    scale_fill_manual(values = c("Negativo" = "#d62728", "Neutro" = "#7f7f7f", "Positivo" = "#2ca02c")) +
    labs(
      title = "Evolução do Sentimento na Regulamentação de Transporte",
      subtitle = "Proporção de documentos por categoria de sentimento",
      x = "Ano",
      y = "Proporção",
      fill = "Sentimento"
    ) +
    theme_minimal()
  
  return(list(
    data = sentiment_data,
    temporal = p_sentiment,
    summary = sentiment_data %>% count(sentiment_category)
  ))
}

# 3. ANÁLISE DE REDES E RELACIONAMENTOS ======================================

# 3.1 Rede de Citações
citation_network <- function(data) {
  
  # Extrair citações de outros documentos
  citations <- data %>%
    select(urn, document_summary) %>%
    filter(!is.na(document_summary)) %>%
    mutate(
      # Extrair referências a leis, decretos, etc.
      citations = str_extract_all(document_summary, 
                                 "(?i)(lei|decreto|medida provisória|resolução)\\s+n[ºo°]?\\s*\\d+")
    ) %>%
    unnest(citations) %>%
    filter(!is.na(citations)) %>%
    mutate(citations = str_to_lower(str_trim(citations)))
  
  # Criar rede de citações
  citation_edges <- citations %>%
    count(urn, citations, name = "weight") %>%
    filter(weight > 0)
  
  # Criar grafo
  if(nrow(citation_edges) > 0) {
    g <- graph_from_data_frame(citation_edges, directed = TRUE)
    
    # Métricas de rede
    metrics <- data.frame(
      node = V(g)$name,
      degree = degree(g),
      betweenness = betweenness(g),
      closeness = closeness(g),
      pagerank = page_rank(g)$vector
    )
    
    # Visualização da rede
    p_network <- ggraph(g, layout = "fr") +
      geom_edge_link(aes(alpha = weight), arrow = arrow(length = unit(2, "mm"))) +
      geom_node_point(aes(size = degree), color = "steelblue") +
      geom_node_text(aes(label = ifelse(degree > quantile(degree, 0.9), name, "")), 
                     repel = TRUE, size = 3) +
      theme_graph() +
      labs(
        title = "Rede de Citações na Regulamentação de Transporte",
        subtitle = "Conexões entre documentos normativos"
      )
    
    return(list(
      graph = g,
      metrics = metrics,
      plot = p_network,
      edges = citation_edges
    ))
  } else {
    return(list(message = "Não foram encontradas citações suficientes para análise de rede"))
  }
}

# 3.2 Rede de Autoridades
authority_network <- function(data) {
  
  # Criar rede de colaboração entre autoridades
  authority_cooccurrence <- data %>%
    filter(!is.na(authority_clean)) %>%
    count(authority_clean, document_type_clean) %>%
    spread(document_type_clean, n, fill = 0)
  
  # Calcular similaridade entre autoridades
  authority_matrix <- authority_cooccurrence %>%
    column_to_rownames("authority_clean") %>%
    as.matrix()
  
  # Criar rede baseada em similaridade
  similarity_matrix <- cor(t(authority_matrix), use = "complete.obs")
  similarity_matrix[is.na(similarity_matrix)] <- 0
  
  # Converter para grafo
  g_auth <- graph_from_adjacency_matrix(similarity_matrix, 
                                       mode = "undirected", 
                                       weighted = TRUE, 
                                       diag = FALSE)
  
  # Filtrar arestas fracas
  g_auth <- delete_edges(g_auth, E(g_auth)[weight < 0.3])
  
  # Visualização
  p_auth_network <- ggraph(g_auth, layout = "stress") +
    geom_edge_link(aes(alpha = weight, width = weight)) +
    geom_node_point(size = 5, color = "orange") +
    geom_node_text(aes(label = name), repel = TRUE) +
    theme_graph() +
    labs(
      title = "Rede de Similaridade entre Autoridades",
      subtitle = "Baseada na produção normativa por tipo de documento"
    )
  
  return(list(
    graph = g_auth,
    plot = p_auth_network,
    similarity_matrix = similarity_matrix
  ))
}

# 4. ANÁLISE GEOESPACIAL =====================================================

# 4.1 Distribuição Geográfica
geographic_analysis <- function(data) {
  
  # Análise por estado (extrair de URNs quando possível)
  state_analysis <- data %>%
    filter(!is.na(state), state != "") %>%
    count(state, document_type_clean) %>%
    group_by(state) %>%
    mutate(total = sum(n), proportion = n / total) %>%
    ungroup()
  
  # Visualização por estado
  p_states <- ggplot(state_analysis, aes(x = reorder(state, total), y = n, fill = document_type_clean)) +
    geom_col() +
    coord_flip() +
    labs(
      title = "Distribuição da Produção Normativa por Estado",
      subtitle = "Regulamentação de transporte de carga",
      x = "Estado",
      y = "Número de Documentos",
      fill = "Tipo de Documento"
    ) +
    theme_minimal()
  
  # Análise de federalismo regulatório
  federalism_analysis <- data %>%
    count(authority_clean, document_type_clean) %>%
    group_by(authority_clean) %>%
    mutate(total = sum(n), proportion = n / total) %>%
    ungroup()
  
  p_federalism <- ggplot(federalism_analysis, aes(x = authority_clean, y = n, fill = document_type_clean)) +
    geom_col(position = "dodge") +
    labs(
      title = "Federalismo Regulatório no Transporte de Carga",
      subtitle = "Distribuição da produção normativa por esfera de governo",
      x = "Esfera de Governo",
      y = "Número de Documentos",
      fill = "Tipo de Documento"
    ) +
    theme_minimal()
  
  return(list(
    states = p_states,
    federalism = p_federalism,
    state_data = state_analysis,
    federalism_data = federalism_analysis
  ))
}

# 5. ANÁLISE PREDITIVA E MACHINE LEARNING ===================================

# 5.1 Classificação de Documentos
document_classification <- function(data) {
  
  # Preparar dados para classificação
  ml_data <- data %>%
    select(urn, document_summary, document_type_clean, authority_clean, year) %>%
    filter(!is.na(document_summary), document_summary != "", 
           !is.na(document_type_clean)) %>%
    mutate(
      text_length = str_length(document_summary),
      word_count = str_count(document_summary, "\\\\w+"),
      has_numbers = str_detect(document_summary, "\\\\d+"),
      has_dates = str_detect(document_summary, "\\\\d{4}"),
      decade = floor(year / 10) * 10
    )
  
  # Criar features de texto (TF-IDF)
  corpus <- Corpus(VectorSource(ml_data$document_summary))
  corpus <- tm_map(corpus, content_transformer(tolower))
  corpus <- tm_map(corpus, removePunctuation)
  corpus <- tm_map(corpus, removeNumbers)
  corpus <- tm_map(corpus, removeWords, stopwords("portuguese"))
  corpus <- tm_map(corpus, stripWhitespace)
  
  dtm <- DocumentTermMatrix(corpus)
  dtm_tfidf <- weightTfIdf(dtm)
  
  # Converter para matriz esparsa
  tfidf_matrix <- as.matrix(dtm_tfidf)
  
  # Selecionar top features
  top_terms <- findFreqTerms(dtm, lowfreq = 5)
  tfidf_features <- tfidf_matrix[, colnames(tfidf_matrix) %in% top_terms[1:100]]
  
  # Combinar features
  features <- cbind(
    ml_data[, c("text_length", "word_count", "has_numbers", "has_dates", "decade")],
    tfidf_features
  )
  
  # Preparar target
  target <- factor(ml_data$document_type_clean)
  
  # Dividir em treino e teste
  set.seed(123)
  train_idx <- createDataPartition(target, p = 0.8, list = FALSE)
  
  X_train <- features[train_idx, ]
  X_test <- features[-train_idx, ]
  y_train <- target[train_idx]
  y_test <- target[-train_idx]
  
  # Treinar modelo Random Forest
  rf_model <- randomForest(X_train, y_train, ntree = 100, importance = TRUE)
  
  # Predições
  rf_pred <- predict(rf_model, X_test)
  
  # Matriz de confusão
  confusion_matrix <- confusionMatrix(rf_pred, y_test)
  
  # Importância das features
  importance_df <- importance(rf_model) %>%
    as.data.frame() %>%
    rownames_to_column("feature") %>%
    arrange(desc(MeanDecreaseGini))
  
  p_importance <- ggplot(importance_df[1:20, ], aes(x = reorder(feature, MeanDecreaseGini), y = MeanDecreaseGini)) +
    geom_col(fill = "steelblue") +
    coord_flip() +
    labs(
      title = "Importância das Features para Classificação",
      subtitle = "Top 20 features mais importantes (Random Forest)",
      x = "Feature",
      y = "Mean Decrease Gini"
    ) +
    theme_minimal()
  
  return(list(
    model = rf_model,
    predictions = rf_pred,
    confusion_matrix = confusion_matrix,
    importance = importance_df,
    importance_plot = p_importance,
    accuracy = confusion_matrix$overall["Accuracy"]
  ))
}

# 5.2 Detecção de Anomalias
anomaly_detection <- function(data) {
  
  # Análise de anomalias temporais
  monthly_counts <- data %>%
    mutate(year_month = floor_date(enacting_date, "month")) %>%
    count(year_month) %>%
    complete(year_month = seq(min(year_month, na.rm = TRUE), 
                             max(year_month, na.rm = TRUE), 
                             by = "month"), 
             fill = list(n = 0))
  
  # Detectar outliers usando IQR
  Q1 <- quantile(monthly_counts$n, 0.25, na.rm = TRUE)
  Q3 <- quantile(monthly_counts$n, 0.75, na.rm = TRUE)
  IQR <- Q3 - Q1
  
  monthly_counts <- monthly_counts %>%
    mutate(
      is_outlier = n < (Q1 - 1.5 * IQR) | n > (Q3 + 1.5 * IQR),
      outlier_type = case_when(
        n > (Q3 + 1.5 * IQR) ~ "Alto",
        n < (Q1 - 1.5 * IQR) ~ "Baixo",
        TRUE ~ "Normal"
      )
    )
  
  # Visualização de anomalias
  p_anomalies <- ggplot(monthly_counts, aes(x = year_month, y = n)) +
    geom_line(color = "gray70") +
    geom_point(aes(color = outlier_type), size = 2) +
    scale_color_manual(values = c("Alto" = "red", "Baixo" = "blue", "Normal" = "gray70")) +
    labs(
      title = "Detecção de Anomalias na Produção Normativa",
      subtitle = "Análise mensal com identificação de outliers",
      x = "Data",
      y = "Número de Documentos",
      color = "Tipo de Anomalia"
    ) +
    theme_minimal()
  
  # Anomalias identificadas
  anomalies <- monthly_counts %>%
    filter(is_outlier) %>%
    arrange(desc(abs(n - median(monthly_counts$n, na.rm = TRUE))))
  
  return(list(
    plot = p_anomalies,
    anomalies = anomalies,
    monthly_data = monthly_counts
  ))
}

# 6. DASHBOARD INTERATIVO ====================================================

# 6.1 Função para criar dashboard Shiny
create_dashboard <- function() {
  
  ui <- dashboardPage(
    dashboardHeader(title = "Monitor Legislativo - Transporte de Carga"),
    
    dashboardSidebar(
      sidebarMenu(
        menuItem("Visão Geral", tabName = "overview", icon = icon("dashboard")),
        menuItem("Análise Temporal", tabName = "temporal", icon = icon("chart-line")),
        menuItem("Análise de Texto", tabName = "text", icon = icon("file-text")),
        menuItem("Redes", tabName = "networks", icon = icon("project-diagram")),
        menuItem("Geográfico", tabName = "geographic", icon = icon("map")),
        menuItem("Predições", tabName = "predictions", icon = icon("crystal-ball"))
      )
    ),
    
    dashboardBody(
      tabItems(
        # Visão Geral
        tabItem(tabName = "overview",
          fluidRow(
            valueBoxOutput("total_docs"),
            valueBoxOutput("date_range"),
            valueBoxOutput("doc_types")
          ),
          fluidRow(
            box(
              title = "Distribuição por Tipo de Documento",
              status = "primary",
              solidHeader = TRUE,
              plotlyOutput("type_distribution")
            ),
            box(
              title = "Evolução Temporal",
              status = "primary", 
              solidHeader = TRUE,
              plotlyOutput("temporal_overview")
            )
          )
        ),
        
        # Análise Temporal
        tabItem(tabName = "temporal",
          fluidRow(
            box(
              title = "Controles",
              status = "primary",
              solidHeader = TRUE,
              width = 3,
              selectInput("doc_type_filter", "Tipo de Documento:",
                         choices = c("Todos", "Legislação", "Jurisprudência", "Doutrina")),
              dateRangeInput("date_range_filter", "Período:",
                           start = "1950-01-01", end = "2025-12-31")
            ),
            box(
              title = "Tendências Temporais",
              status = "primary",
              solidHeader = TRUE,
              width = 9,
              plotlyOutput("temporal_trends")
            )
          ),
          fluidRow(
            box(
              title = "Análise de Sazonalidade",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              plotlyOutput("seasonality_plot")
            ),
            box(
              title = "Ciclos Políticos",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              plotlyOutput("political_cycles")
            )
          )
        ),
        
        # Análise de Texto
        tabItem(tabName = "text",
          fluidRow(
            box(
              title = "Nuvem de Palavras",
              status = "success",
              solidHeader = TRUE,
              width = 6,
              plotOutput("wordcloud")
            ),
            box(
              title = "Termos Mais Frequentes",
              status = "success",
              solidHeader = TRUE,
              width = 6,
              plotlyOutput("word_frequency")
            )
          ),
          fluidRow(
            box(
              title = "Análise TF-IDF",
              status = "warning",
              solidHeader = TRUE,
              width = 12,
              plotlyOutput("tfidf_analysis")
            )
          )
        ),
        
        # Redes
        tabItem(tabName = "networks",
          fluidRow(
            box(
              title = "Rede de Citações",
              status = "danger",
              solidHeader = TRUE,
              width = 6,
              visNetworkOutput("citation_network")
            ),
            box(
              title = "Rede de Autoridades",
              status = "danger",
              solidHeader = TRUE,
              width = 6,
              visNetworkOutput("authority_network")
            )
          )
        ),
        
        # Geográfico
        tabItem(tabName = "geographic",
          fluidRow(
            box(
              title = "Distribuição por Estado",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              plotlyOutput("state_distribution")
            ),
            box(
              title = "Federalismo Regulatório",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              plotlyOutput("federalism_analysis")
            )
          )
        ),
        
        # Predições
        tabItem(tabName = "predictions",
          fluidRow(
            box(
              title = "Previsões de Produção Normativa",
              status = "primary",
              solidHeader = TRUE,
              width = 8,
              plotlyOutput("forecast_plot")
            ),
            box(
              title = "Métricas do Modelo",
              status = "primary",
              solidHeader = TRUE,
              width = 4,
              tableOutput("model_metrics")
            )
          ),
          fluidRow(
            box(
              title = "Detecção de Anomalias",
              status = "warning",
              solidHeader = TRUE,
              width = 12,
              plotlyOutput("anomaly_plot")
            )
          )
        )
      )
    )
  )
  
  server <- function(input, output, session) {
    # Carregar dados (seria substituído por dados reais)
    # data <- load_lexml_data("path/to/data.csv")
    
    # Implementar lógica do servidor aqui
    # output$total_docs <- renderValueBox({ ... })
    # output$temporal_trends <- renderPlotly({ ... })
    # etc.
  }
  
  return(list(ui = ui, server = server))
}

# 7. RELATÓRIO AUTOMATIZADO ==================================================

# 7.1 Função para gerar relatório completo
generate_report <- function(data, output_file = "relatorio_lexml.html") {
  
  # Executar todas as análises
  temporal_results <- temporal_analysis(data)
  forecast_results <- forecast_analysis(data)
  text_results <- text_analysis(data)
  topic_results <- topic_modeling(data)
  sentiment_results <- sentiment_analysis(data)
  citation_results <- citation_network(data)
  authority_results <- authority_network(data)
  geographic_results <- geographic_analysis(data)
  ml_results <- document_classification(data)
  anomaly_results <- anomaly_detection(data)
  
  # Criar relatório R Markdown
  rmd_content <- '
---
title: "Relatório de Análise Legislativa - Transporte de Carga"
author: "Monitor Legislativo"
date: "`r Sys.Date()`"
output: 
  html_document:
    toc: true
    toc_float: true
    theme: flatly
---

```{r setup, include=FALSE}
knitr::opts_chunk$set(echo = FALSE, warning = FALSE, message = FALSE)
```

# Resumo Executivo

Este relatório apresenta uma análise abrangente da produção normativa relacionada ao transporte de carga no Brasil, baseada em dados do LexML.

## Principais Achados

- **Total de documentos analisados**: `r nrow(data)`
- **Período coberto**: `r min(data$year, na.rm = TRUE)` - `r max(data$year, na.rm = TRUE)`
- **Tipos de documento**: `r paste(unique(data$document_type_clean), collapse = ", ")`

# Análise Temporal

```{r temporal}
temporal_results$trends
```

# Análise de Texto

```{r text}
text_results$tfidf
```

# Análise de Redes

```{r networks}
if("plot" %in% names(citation_results)) {
  citation_results$plot
}
```

# Análise Geográfica

```{r geographic}
geographic_results$federalism
```

# Previsões

```{r forecast}
forecast_results$plot
```

# Conclusões e Recomendações

[Conclusões baseadas nos resultados das análises]
'
  
  # Salvar e renderizar
  writeLines(rmd_content, "temp_report.Rmd")
  rmarkdown::render("temp_report.Rmd", output_file = output_file)
  file.remove("temp_report.Rmd")
  
  return(output_file)
}

# 8. FUNÇÃO PRINCIPAL ========================================================

# 8.1 Executar todas as análises
run_complete_analysis <- function(data_file) {
  
  # Carregar dados
  cat("Carregando dados...\\n")
  data <- load_lexml_data(data_file)
  
  # Executar análises
  cat("Executando análise temporal...\\n")
  temporal_results <- temporal_analysis(data)
  
  cat("Executando previsões...\\n")
  forecast_results <- forecast_analysis(data)
  
  cat("Executando análise de texto...\\n")
  text_results <- text_analysis(data)
  
  cat("Executando modelagem de tópicos...\\n")
  topic_results <- topic_modeling(data)
  
  cat("Executando análise de sentimento...\\n")
  sentiment_results <- sentiment_analysis(data)
  
  cat("Executando análise de redes...\\n")
  citation_results <- citation_network(data)
  authority_results <- authority_network(data)
  
  cat("Executando análise geográfica...\\n")
  geographic_results <- geographic_analysis(data)
  
  cat("Executando machine learning...\\n")
  ml_results <- document_classification(data)
  
  cat("Executando detecção de anomalias...\\n")
  anomaly_results <- anomaly_detection(data)
  
  # Compilar resultados
  results <- list(
    data = data,
    temporal = temporal_results,
    forecast = forecast_results,
    text = text_results,
    topics = topic_results,
    sentiment = sentiment_results,
    citations = citation_results,
    authorities = authority_results,
    geographic = geographic_results,
    ml = ml_results,
    anomalies = anomaly_results
  )
  
  cat("Análise completa finalizada!\\n")
  return(results)
}

# Exemplo de uso:
# results <- run_complete_analysis("lexml_corrected_data.csv")
# generate_report(results$data)
# dashboard <- create_dashboard()
# shinyApp(dashboard$ui, dashboard$server)

