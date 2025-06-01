# ============================================================================
# ANALYTICS ABRANGENTES PARA DATASET LEXML - TRANSPORTE DE CARGA
# Implementação do Sistema R Analytics baseado na documentação
# Autor: Sistema LexML
# Data: 2025-01-14
# Descrição: Conjunto completo de análises para o dataset LexML
# ============================================================================

# Carregamento de Pacotes ====================================================
suppressMessages({
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
  library(corrplot)       # Matriz de correlação
  library(cluster)        # Análise de clusters
  library(factoextra)     # Visualização de clusters
  library(randomForest)   # Machine learning
  library(caret)          # Machine learning
  library(shiny)          # Aplicações web
  library(shinydashboard) # Dashboards
  library(flexdashboard)  # Dashboards flexíveis
  library(jsonlite)       # Manipulação JSON
  library(RColorBrewer)   # Paletas de cores
  library(scales)         # Formatação de escalas
  library(stringr)        # Manipulação de strings
  library(readr)          # Leitura de arquivos
})

# Configurações Globais ======================================================
options(scipen = 999)  # Evitar notação científica
Sys.setlocale("LC_TIME", "C")  # Configurar locale para inglês (mais compatível)

# Classe Principal do Sistema de Analytics ===================================
LexMLAnalytics <- R6::R6Class(
  "LexMLAnalytics",
  
  public = list(
    data = NULL,
    processed_data = NULL,
    results = list(),
    
    initialize = function() {
      cat("🚀 Iniciando Sistema de Analytics LexML\n")
      cat("📊 Versão: 3.0 Final\n")
      cat("📅 Data:", Sys.Date(), "\n")
      cat("=" %+% strrep("=", 60) %+% "\n")
    },
    
    # Função para carregar dados
    load_data = function(file_path) {
      cat("📂 Carregando dados de:", file_path, "\n")
      
      tryCatch({
        # Detectar formato do arquivo
        if (str_detect(file_path, "\\.csv$")) {
          self$data <- read_csv(file_path, locale = locale(encoding = "UTF-8"))
        } else if (str_detect(file_path, "\\.json$")) {
          self$data <- fromJSON(file_path)
        } else {
          stop("Formato de arquivo não suportado. Use .csv ou .json")
        }
        
        # Processar dados
        self$processed_data <- self$process_data(self$data)
        
        cat("✅ Dados carregados com sucesso!\n")
        cat("📊 Total de registros:", nrow(self$processed_data), "\n")
        
        return(invisible(self))
        
      }, error = function(e) {
        cat("❌ Erro ao carregar dados:", e$message, "\n")
        return(invisible(self))
      })
    },
    
    # Função para processar dados
    process_data = function(data) {
      cat("🔧 Processando dados...\n")
      
      # Limpeza e preparação dos dados
      processed <- data %>%
        mutate(
          # Converter datas
          enacting_date = as.Date(enacting_date, format = "%Y-%m-%d"),
          date_searched = as.Date(date_searched, format = "%Y-%m-%d"),
          
          # Extrair informações temporais
          year = year(enacting_date),
          month = month(enacting_date),
          decade = floor(year / 10) * 10,
          
          # Limpar tipos de documento
          document_type_clean = case_when(
            urn_type == "legislation" ~ "Legislação",
            urn_type == "jurisprudence" ~ "Jurisprudência",
            urn_type == "doctrine" ~ "Doutrina",
            TRUE ~ "Outros"
          ),
          
          # Limpar autoridades
          authority_clean = case_when(
            str_detect(tolower(court_class), "federal") ~ "Federal",
            str_detect(tolower(court_class), "estadual") ~ "Estadual",
            str_detect(tolower(court_class), "municipal") ~ "Municipal",
            str_detect(tolower(court_class), "distrital") ~ "Distrital",
            TRUE ~ "Outros"
          ),
          
          # Calcular relevância de transporte
          transport_relevance = self$calculate_transport_relevance(title, document_summary)
        ) %>%
        # Filtrar dados válidos
        filter(
          !is.na(enacting_date),
          year >= 1950,
          year <= 2025,
          !is.na(document_type_clean)
        )
      
      return(processed)
    },
    
    # Função para calcular relevância de transporte
    calculate_transport_relevance = function(title, summary) {
      transport_keywords <- c(
        "transporte", "carga", "caminhão", "veículo", "frete", "logística",
        "rodoviário", "modal", "combustível", "diesel", "motorista", "embarcador"
      )
      
      text <- paste(tolower(title), tolower(summary))
      matches <- sum(str_detect(text, transport_keywords))
      
      return(pmin(matches / length(transport_keywords), 1.0))
    },
    
    # 1. ANÁLISE TEMPORAL AVANÇADA
    temporal_analysis = function() {
      cat("📈 Executando análise temporal...\n")
      
      if (is.null(self$processed_data)) {
        cat("❌ Dados não carregados. Execute load_data() primeiro.\n")
        return(invisible(self))
      }
      
      # Série temporal por ano
      yearly_counts <- self$processed_data %>%
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
      monthly_analysis <- self$processed_data %>%
        filter(!is.na(month)) %>%
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
      
      # Análise de ciclos políticos
      political_analysis <- self$processed_data %>%
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
      
      # Armazenar resultados
      self$results$temporal <- list(
        trends = p1,
        seasonality = p2,
        political_cycles = p3,
        yearly_data = yearly_counts,
        monthly_data = monthly_analysis,
        political_data = political_analysis
      )
      
      cat("✅ Análise temporal concluída!\n")
      return(invisible(self))
    },
    
    # 2. ANÁLISE DE TEXTO E MINERAÇÃO
    text_analysis = function() {
      cat("📝 Executando análise de texto...\n")
      
      if (is.null(self$processed_data)) {
        cat("❌ Dados não carregados. Execute load_data() primeiro.\n")
        return(invisible(self))
      }
      
      # Preparar corpus
      corpus_data <- self$processed_data %>%
        select(urn, document_summary, document_type_clean) %>%
        filter(!is.na(document_summary), document_summary != "")
      
      # Tokenização e limpeza
      stop_words_pt <- c(
        "a", "o", "e", "de", "da", "do", "em", "para", "com", "por", "que", "se",
        "na", "no", "um", "uma", "os", "as", "dos", "das", "ao", "à", "pelo",
        "pela", "este", "esta", "esse", "essa", "aquele", "aquela", "seu", "sua",
        "art", "lei", "decreto", "urn", "lex", "br", "federal", "estadual"
      )
      
      tokens <- corpus_data %>%
        mutate(text = tolower(document_summary)) %>%
        unnest_tokens(word, text) %>%
        filter(
          !word %in% stop_words_pt,
          !str_detect(word, "^\\d+$"),
          str_length(word) > 2
        )
      
      # Frequência de termos
      word_freq <- tokens %>%
        count(word, sort = TRUE) %>%
        top_n(50, n)
      
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
      
      # Armazenar resultados
      self$results$text <- list(
        word_freq = word_freq,
        tfidf = p_tfidf,
        tokens = tokens
      )
      
      cat("✅ Análise de texto concluída!\n")
      return(invisible(self))
    },
    
    # 3. ANÁLISE GEOGRÁFICA
    geographic_analysis = function() {
      cat("🗺️ Executando análise geográfica...\n")
      
      if (is.null(self$processed_data)) {
        cat("❌ Dados não carregados. Execute load_data() primeiro.\n")
        return(invisible(self))
      }
      
      # Análise por estado
      state_analysis <- self$processed_data %>%
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
      federalism_analysis <- self$processed_data %>%
        filter(!is.na(authority_clean), authority_clean != "Outros") %>%
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
      
      # Armazenar resultados
      self$results$geographic <- list(
        states = p_states,
        federalism = p_federalism,
        state_data = state_analysis,
        federalism_data = federalism_analysis
      )
      
      cat("✅ Análise geográfica concluída!\n")
      return(invisible(self))
    },
    
    # 4. ANÁLISE DE RELEVÂNCIA
    relevance_analysis = function() {
      cat("🎯 Executando análise de relevância...\n")
      
      if (is.null(self$processed_data)) {
        cat("❌ Dados não carregados. Execute load_data() primeiro.\n")
        return(invisible(self))
      }
      
      # Distribuição de relevância de transporte
      relevance_dist <- self$processed_data %>%
        mutate(
          relevance_category = case_when(
            transport_relevance >= 0.7 ~ "Alta",
            transport_relevance >= 0.4 ~ "Média",
            transport_relevance >= 0.1 ~ "Baixa",
            TRUE ~ "Mínima"
          )
        ) %>%
        count(relevance_category, document_type_clean)
      
      p_relevance <- ggplot(relevance_dist, aes(x = relevance_category, y = n, fill = document_type_clean)) +
        geom_col(position = "dodge") +
        labs(
          title = "Distribuição de Relevância para Transporte de Carga",
          subtitle = "Análise da relevância temática dos documentos",
          x = "Categoria de Relevância",
          y = "Número de Documentos",
          fill = "Tipo de Documento"
        ) +
        theme_minimal()
      
      # Top documentos mais relevantes
      top_relevant <- self$processed_data %>%
        filter(transport_relevance > 0.5) %>%
        select(title, urn, transport_relevance, document_type_clean, year) %>%
        arrange(desc(transport_relevance)) %>%
        head(20)
      
      # Armazenar resultados
      self$results$relevance <- list(
        distribution = p_relevance,
        top_documents = top_relevant,
        relevance_data = relevance_dist
      )
      
      cat("✅ Análise de relevância concluída!\n")
      return(invisible(self))
    },
    
    # 5. ANÁLISE DE TERMOS DE BUSCA
    search_terms_analysis = function() {
      cat("🔍 Executando análise de termos de busca...\n")
      
      if (is.null(self$processed_data)) {
        cat("❌ Dados não carregados. Execute load_data() primeiro.\n")
        return(invisible(self))
      }
      
      # Análise por termo de busca
      search_analysis <- self$processed_data %>%
        filter(!is.na(search_term), search_term != "") %>%
        count(search_term, document_type_clean) %>%
        group_by(search_term) %>%
        mutate(total = sum(n)) %>%
        ungroup() %>%
        arrange(desc(total))
      
      # Top 15 termos mais produtivos
      top_terms <- search_analysis %>%
        group_by(search_term) %>%
        summarise(total = sum(n), .groups = "drop") %>%
        arrange(desc(total)) %>%
        head(15)
      
      p_search_terms <- ggplot(top_terms, aes(x = reorder(search_term, total), y = total)) +
        geom_col(fill = "steelblue") +
        coord_flip() +
        labs(
          title = "Termos de Busca Mais Produtivos",
          subtitle = "Top 15 termos que retornaram mais documentos",
          x = "Termo de Busca",
          y = "Número de Documentos"
        ) +
        theme_minimal()
      
      # Armazenar resultados
      self$results$search_terms <- list(
        productivity = p_search_terms,
        top_terms = top_terms,
        search_data = search_analysis
      )
      
      cat("✅ Análise de termos de busca concluída!\n")
      return(invisible(self))
    },
    
    # 6. DASHBOARD INTERATIVO
    create_dashboard = function() {
      cat("📊 Criando dashboard interativo...\n")
      
      # Interface do dashboard
      ui <- dashboardPage(
        dashboardHeader(title = "Monitor Legislativo - Transporte de Carga"),
        
        dashboardSidebar(
          sidebarMenu(
            menuItem("Visão Geral", tabName = "overview", icon = icon("dashboard")),
            menuItem("Análise Temporal", tabName = "temporal", icon = icon("chart-line")),
            menuItem("Análise de Texto", tabName = "text", icon = icon("file-text")),
            menuItem("Análise Geográfica", tabName = "geographic", icon = icon("map")),
            menuItem("Relevância", tabName = "relevance", icon = icon("bullseye")),
            menuItem("Termos de Busca", tabName = "search", icon = icon("search"))
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
                  title = "Tendências Temporais",
                  status = "primary",
                  solidHeader = TRUE,
                  width = 12,
                  plotlyOutput("temporal_trends")
                )
              ),
              fluidRow(
                box(
                  title = "Sazonalidade",
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
                  title = "Análise TF-IDF",
                  status = "success",
                  solidHeader = TRUE,
                  width = 12,
                  plotlyOutput("tfidf_analysis")
                )
              ),
              fluidRow(
                box(
                  title = "Termos Mais Frequentes",
                  status = "success",
                  solidHeader = TRUE,
                  width = 12,
                  DT::dataTableOutput("word_frequency")
                )
              )
            ),
            
            # Análise Geográfica
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
            
            # Análise de Relevância
            tabItem(tabName = "relevance",
              fluidRow(
                box(
                  title = "Distribuição de Relevância",
                  status = "warning",
                  solidHeader = TRUE,
                  width = 8,
                  plotlyOutput("relevance_distribution")
                ),
                box(
                  title = "Top Documentos",
                  status = "warning",
                  solidHeader = TRUE,
                  width = 4,
                  DT::dataTableOutput("top_relevant_docs")
                )
              )
            ),
            
            # Análise de Termos de Busca
            tabItem(tabName = "search",
              fluidRow(
                box(
                  title = "Produtividade dos Termos",
                  status = "danger",
                  solidHeader = TRUE,
                  width = 12,
                  plotlyOutput("search_productivity")
                )
              )
            )
          )
        )
      )
      
      # Servidor do dashboard
      server <- function(input, output, session) {
        # Value boxes
        output$total_docs <- renderValueBox({
          valueBox(
            value = nrow(self$processed_data),
            subtitle = "Total de Documentos",
            icon = icon("file"),
            color = "blue"
          )
        })
        
        output$date_range <- renderValueBox({
          min_year <- min(self$processed_data$year, na.rm = TRUE)
          max_year <- max(self$processed_data$year, na.rm = TRUE)
          valueBox(
            value = paste(min_year, "-", max_year),
            subtitle = "Período Analisado",
            icon = icon("calendar"),
            color = "green"
          )
        })
        
        output$doc_types <- renderValueBox({
          n_types <- length(unique(self$processed_data$document_type_clean))
          valueBox(
            value = n_types,
            subtitle = "Tipos de Documento",
            icon = icon("tags"),
            color = "yellow"
          )
        })
        
        # Gráficos
        output$temporal_trends <- renderPlotly({
          if (!is.null(self$results$temporal)) {
            ggplotly(self$results$temporal$trends)
          }
        })
        
        output$seasonality_plot <- renderPlotly({
          if (!is.null(self$results$temporal)) {
            ggplotly(self$results$temporal$seasonality)
          }
        })
        
        output$political_cycles <- renderPlotly({
          if (!is.null(self$results$temporal)) {
            ggplotly(self$results$temporal$political_cycles)
          }
        })
        
        output$tfidf_analysis <- renderPlotly({
          if (!is.null(self$results$text)) {
            ggplotly(self$results$text$tfidf)
          }
        })
        
        output$state_distribution <- renderPlotly({
          if (!is.null(self$results$geographic)) {
            ggplotly(self$results$geographic$states)
          }
        })
        
        output$federalism_analysis <- renderPlotly({
          if (!is.null(self$results$geographic)) {
            ggplotly(self$results$geographic$federalism)
          }
        })
        
        output$relevance_distribution <- renderPlotly({
          if (!is.null(self$results$relevance)) {
            ggplotly(self$results$relevance$distribution)
          }
        })
        
        output$search_productivity <- renderPlotly({
          if (!is.null(self$results$search_terms)) {
            ggplotly(self$results$search_terms$productivity)
          }
        })
        
        # Tabelas
        output$word_frequency <- DT::renderDataTable({
          if (!is.null(self$results$text)) {
            DT::datatable(
              self$results$text$word_freq,
              options = list(pageLength = 15)
            )
          }
        })
        
        output$top_relevant_docs <- DT::renderDataTable({
          if (!is.null(self$results$relevance)) {
            DT::datatable(
              self$results$relevance$top_documents,
              options = list(pageLength = 10)
            )
          }
        })
      }
      
      # Retornar aplicação Shiny
      return(shinyApp(ui = ui, server = server))
    },
    
    # 7. EXECUTAR ANÁLISE COMPLETA
    run_complete_analysis = function() {
      cat("🚀 Executando análise completa...\n")
      cat("=" %+% strrep("=", 50) %+% "\n")
      
      # Verificar se dados foram carregados
      if (is.null(self$processed_data)) {
        cat("❌ Dados não carregados. Execute load_data() primeiro.\n")
        return(invisible(self))
      }
      
      # Executar todas as análises
      tryCatch({
        self$temporal_analysis()
        self$text_analysis()
        self$geographic_analysis()
        self$relevance_analysis()
        self$search_terms_analysis()
        
        cat("🎉 Análise completa concluída com sucesso!\n")
        cat("📊 Resultados disponíveis em $results\n")
        cat("🖥️ Execute create_dashboard() para visualizar os resultados\n")
        
      }, error = function(e) {
        cat("❌ Erro durante a análise:", e$message, "\n")
      })
      
      return(invisible(self))
    },
    
    # 8. GERAR RELATÓRIO
    generate_report = function(output_file = NULL) {
      if (is.null(output_file)) {
        output_file <- paste0("lexml_analytics_report_", Sys.Date(), ".html")
      }
      
      cat("📄 Gerando relatório:", output_file, "\n")
      
      # Criar relatório R Markdown
      rmd_content <- '
---
title: "Relatório de Análise Legislativa - Transporte de Carga"
author: "Monitor Legislativo LexML"
date: "`r Sys.Date()`"
output: 
  html_document:
    toc: true
    toc_float: true
    theme: flatly
    code_folding: hide
---

```{r setup, include=FALSE}
knitr::opts_chunk$set(echo = FALSE, warning = FALSE, message = FALSE)
```

# Resumo Executivo

Este relatório apresenta uma análise abrangente da produção normativa relacionada ao transporte de carga no Brasil, baseada em dados do LexML.

## Principais Achados

- **Total de documentos analisados**: `r nrow(analytics$processed_data)`
- **Período coberto**: `r min(analytics$processed_data$year, na.rm = TRUE)` - `r max(analytics$processed_data$year, na.rm = TRUE)`
- **Tipos de documento**: `r paste(unique(analytics$processed_data$document_type_clean), collapse = ", ")`

# Análise Temporal

```{r temporal}
if (!is.null(analytics$results$temporal)) {
  analytics$results$temporal$trends
}
```

# Análise de Texto

```{r text}
if (!is.null(analytics$results$text)) {
  analytics$results$text$tfidf
}
```

# Análise Geográfica

```{r geographic}
if (!is.null(analytics$results$geographic)) {
  analytics$results$geographic$federalism
}
```

# Análise de Relevância

```{r relevance}
if (!is.null(analytics$results$relevance)) {
  analytics$results$relevance$distribution
}
```

# Conclusões e Recomendações

- A produção normativa apresenta variações significativas ao longo do tempo
- Diferentes tipos de documento mostram padrões distintos de publicação
- A relevância temática varia consideravelmente entre os documentos
- Existe uma distribuição desigual entre diferentes esferas de governo

---

*Relatório gerado automaticamente pelo Sistema de Analytics LexML*
'
      
      # Salvar e renderizar
      temp_file <- tempfile(fileext = ".Rmd")
      writeLines(rmd_content, temp_file)
      
      tryCatch({
        # Fazer analytics disponível para o relatório
        analytics <- self
        
        rmarkdown::render(
          temp_file,
          output_file = output_file,
          envir = new.env()
        )
        
        cat("✅ Relatório gerado com sucesso!\n")
        
      }, error = function(e) {
        cat("❌ Erro ao gerar relatório:", e$message, "\n")
      })
      
      return(invisible(self))
    },
    
    # 9. SALVAR RESULTADOS
    save_results = function(output_dir = "results") {
      cat("💾 Salvando resultados em:", output_dir, "\n")
      
      # Criar diretório se não existir
      if (!dir.exists(output_dir)) {
        dir.create(output_dir, recursive = TRUE)
      }
      
      # Salvar cada tipo de resultado
      for (analysis_type in names(self$results)) {
        type_dir <- file.path(output_dir, analysis_type)
        if (!dir.exists(type_dir)) {
          dir.create(type_dir, recursive = TRUE)
        }
        
        # Salvar gráficos
        for (plot_name in names(self$results[[analysis_type]])) {
          if (inherits(self$results[[analysis_type]][[plot_name]], "ggplot")) {
            ggsave(
              file.path(type_dir, paste0(plot_name, ".png")),
              self$results[[analysis_type]][[plot_name]],
              width = 12, height = 8
            )
          }
        }
      }
      
      # Salvar dados processados
      write_csv(self$processed_data, file.path(output_dir, "processed_data.csv"))
      
      cat("✅ Resultados salvos com sucesso!\n")
      return(invisible(self))
    }
  )
)

# Função de conveniência para criar nova instância
create_lexml_analytics <- function() {
  return(LexMLAnalytics$new())
}

# Exemplo de uso
if (FALSE) {
  # Criar instância do sistema
  analytics <- create_lexml_analytics()
  
  # Carregar dados
  analytics$load_data("lexml_results.csv")
  
  # Executar análise completa
  analytics$run_complete_analysis()
  
  # Criar dashboard
  app <- analytics$create_dashboard()
  shiny::runApp(app)
  
  # Gerar relatório
  analytics$generate_report()
  
  # Salvar resultados
  analytics$save_results()
}

# Mensagem de carregamento
cat("🚀 Sistema de Analytics LexML carregado com sucesso!\n")
cat("📊 Use create_lexml_analytics() para criar uma nova instância\n")
cat("📖 Consulte a documentação para instruções de uso\n")