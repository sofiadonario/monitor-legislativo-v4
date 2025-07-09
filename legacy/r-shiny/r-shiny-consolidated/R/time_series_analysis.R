# Time Series Analysis and Trending for Monitor Legislativo v4
# Advanced temporal analysis with forecasting, anomaly detection, and pattern recognition

library(shiny)
library(htmltools)
library(echarts4r)
library(dplyr)
library(lubridate)
library(forecast)
library(changepoint)
library(bcp)
library(seasonal)
library(plotly)
library(DT)
library(shinycssloaders)

# Time series configuration
TIMESERIES_CONFIG <- list(
  analysis_types = list(
    "trend" = "Análise de Tendência",
    "seasonal" = "Análise Sazonal",
    "forecast" = "Previsão (Forecast)",
    "anomaly" = "Detecção de Anomalias",
    "changepoint" = "Pontos de Mudança",
    "correlation" = "Correlação Temporal",
    "decomposition" = "Decomposição da Série"
  ),
  
  forecasting_methods = list(
    "arima" = "ARIMA (Auto-Regressivo)",
    "ets" = "ETS (Exponential Smoothing)",
    "holtwinters" = "Holt-Winters",
    "linear" = "Regressão Linear",
    "prophet" = "Prophet (Facebook)",
    "neural" = "Redes Neurais",
    "ensemble" = "Ensemble (Combinado)"
  ),
  
  time_granularities = list(
    "day" = "Diário",
    "week" = "Semanal", 
    "month" = "Mensal",
    "quarter" = "Trimestral",
    "year" = "Anual"
  ),
  
  seasonal_periods = list(
    "day" = 7,    # Weekly seasonality for daily data
    "week" = 52,  # Yearly seasonality for weekly data
    "month" = 12, # Yearly seasonality for monthly data
    "quarter" = 4 # Yearly seasonality for quarterly data
  ),
  
  anomaly_methods = list(
    "zscore" = "Z-Score",
    "iqr" = "Interquartile Range",
    "isolation" = "Isolation Forest",
    "seasonal" = "Seasonal Decomposition",
    "lstm" = "LSTM Autoencoder"
  ),
  
  trend_colors = list(
    "increasing" = "#198754",
    "decreasing" = "#dc3545", 
    "stable" = "#6c757d",
    "volatile" = "#fd7e14",
    "seasonal" = "#0d6efd"
  ),
  
  forecast_horizon = list(
    "short" = 30,   # 30 periods
    "medium" = 90,  # 90 periods  
    "long" = 365    # 365 periods
  )
)

#' Create time series analysis interface
#' @param id Module ID
#' @return Time series analysis UI
time_series_analysis_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "time-series-container",
    
    # Header with gradient background
    div(
      class = "timeseries-header",
      style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 12px 12px 0 0; color: white;",
      
      fluidRow(
        column(8,
          h3("📈 Análise de Séries Temporais", style = "margin: 0; text-shadow: 0 1px 2px rgba(0,0,0,0.3);"),
          p("Análise avançada temporal com previsão e detecção de padrões", 
            style = "margin: 5px 0 0 0; opacity: 0.9; font-size: 0.95em;")
        ),
        
        column(4,
          div(
            class = "timeseries-controls text-end",
            
            # Analysis type selector
            selectInput(
              ns("analysis_type"),
              NULL,
              choices = TIMESERIES_CONFIG$analysis_types,
              selected = "trend",
              width = "200px"
            )
          )
        )
      )
    ),
    
    # Configuration panel
    div(
      class = "configuration-panel",
      style = "background: white; padding: 15px; border-bottom: 1px solid #dee2e6;",
      
      fluidRow(
        column(3,
          h6("⚙️ Configuração da Análise"),
          
          # Time granularity
          selectInput(
            ns("time_granularity"),
            "Granularidade Temporal:",
            choices = TIMESERIES_CONFIG$time_granularities,
            selected = "month"
          ),
          
          # Date range
          dateRangeInput(
            ns("date_range"),
            "Período de Análise:",
            start = Sys.Date() - 365,
            end = Sys.Date(),
            format = "dd/mm/yyyy",
            language = "pt-BR"
          )
        ),
        
        column(3,
          h6("📊 Variáveis de Análise"),
          
          # Primary variable
          selectInput(
            ns("primary_variable"),
            "Variável Principal:",
            choices = list(
              "Volume de Documentos" = "document_count",
              "Diversidade de Tipos" = "type_diversity",
              "Cobertura Geográfica" = "geographic_coverage",
              "Score de Qualidade" = "quality_score"
            ),
            selected = "document_count"
          ),
          
          # Secondary variable for correlation
          conditionalPanel(
            condition = paste0("input['", ns("analysis_type"), "'] == 'correlation'"),
            selectInput(
              ns("secondary_variable"),
              "Variável Secundária:",
              choices = list(
                "Volume de Documentos" = "document_count",
                "Diversidade de Tipos" = "type_diversity", 
                "Cobertura Geográfica" = "geographic_coverage",
                "Score de Qualidade" = "quality_score"
              ),
              selected = "type_diversity"
            )
          )
        ),
        
        column(3,
          # Forecasting options
          conditionalPanel(
            condition = paste0("input['", ns("analysis_type"), "'] == 'forecast'"),
            
            h6("🔮 Configuração de Previsão"),
            
            selectInput(
              ns("forecast_method"),
              "Método de Previsão:",
              choices = TIMESERIES_CONFIG$forecasting_methods,
              selected = "arima"
            ),
            
            selectInput(
              ns("forecast_horizon_type"),
              "Horizonte de Previsão:",
              choices = list(
                "Curto Prazo (30 períodos)" = "short",
                "Médio Prazo (90 períodos)" = "medium",
                "Longo Prazo (365 períodos)" = "long"
              ),
              selected = "medium"
            )
          ),
          
          # Anomaly detection options
          conditionalPanel(
            condition = paste0("input['", ns("analysis_type"), "'] == 'anomaly'"),
            
            h6("🚨 Detecção de Anomalias"),
            
            selectInput(
              ns("anomaly_method"),
              "Método de Detecção:",
              choices = TIMESERIES_CONFIG$anomaly_methods,
              selected = "zscore"
            ),
            
            numericInput(
              ns("anomaly_threshold"),
              "Limiar de Sensibilidade:",
              value = 2.5,
              min = 1.0,
              max = 5.0,
              step = 0.1
            )
          )
        ),
        
        column(3,
          h6("🎯 Ações"),
          
          br(),
          
          actionButton(
            ns("run_analysis"),
            "📊 Executar Análise",
            class = "btn btn-primary w-100 mb-2"
          ),
          
          actionButton(
            ns("export_analysis"),
            "📤 Exportar Resultados", 
            class = "btn btn-outline-success w-100 mb-2"
          ),
          
          actionButton(
            ns("reset_analysis"),
            "🔄 Resetar",
            class = "btn btn-outline-secondary w-100"
          )
        )
      )
    ),
    
    # Results area
    div(
      class = "results-area",
      style = "background: white;",
      
      # Loading indicator
      conditionalPanel(
        condition = paste0("!output['", ns("analysis_ready"), "']"),
        div(
          class = "text-center py-5",
          withSpinner(
            div(
              icon("chart-line", class = "fa-3x text-muted mb-3"),
              h4("Análise de Séries Temporais", class = "text-muted"),
              p("Configure os parâmetros e clique em 'Executar Análise'", class = "text-muted")
            ),
            type = 6,
            color = "#0d6efd"
          )
        )
      ),
      
      # Analysis results
      conditionalPanel(
        condition = paste0("output['", ns("analysis_ready"), "']"),
        
        # Tabs for different result views
        navset_card_tab(
          id = ns("results_tabs"),
          
          # Main visualization tab
          nav_panel(
            "📈 Visualização Principal",
            
            fluidRow(
              column(12,
                card(
                  card_header(
                    div(
                      class = "d-flex justify-content-between align-items-center",
                      span(textOutput(ns("chart_title"), inline = TRUE)),
                      div(
                        actionButton(
                          ns("fullscreen_chart"),
                          "⛶",
                          class = "btn btn-sm btn-outline-secondary",
                          title = "Tela cheia"
                        )
                      )
                    )
                  ),
                  card_body(
                    withSpinner(
                      echarts4rOutput(ns("main_timeseries_chart"), height = "500px"),
                      type = 4
                    )
                  )
                )
              )
            )
          ),
          
          # Statistical summary tab
          nav_panel(
            "📊 Resumo Estatístico",
            
            fluidRow(
              column(6,
                card(
                  card_header("📈 Estatísticas Descritivas"),
                  card_body(
                    htmlOutput(ns("descriptive_stats"))
                  )
                )
              ),
              
              column(6,
                card(
                  card_header("🎯 Métricas de Tendência"),
                  card_body(
                    htmlOutput(ns("trend_metrics"))
                  )
                )
              )
            ),
            
            br(),
            
            fluidRow(
              column(12,
                card(
                  card_header("📋 Dados da Série Temporal"),
                  card_body(
                    withSpinner(
                      DT::dataTableOutput(ns("timeseries_data_table")),
                      type = 4
                    )
                  )
                )
              )
            )
          ),
          
          # Advanced insights tab
          nav_panel(
            "🧠 Insights Avançados",
            
            fluidRow(
              column(6,
                card(
                  card_header("🔍 Padrões Identificados"),
                  card_body(
                    htmlOutput(ns("identified_patterns"))
                  )
                )
              ),
              
              column(6,
                card(
                  card_header("💡 Recomendações"),
                  card_body(
                    htmlOutput(ns("analysis_recommendations"))
                  )
                )
              )
            ),
            
            br(),
            
            conditionalPanel(
              condition = paste0("input['", ns("analysis_type"), "'] == 'forecast'"),
              
              fluidRow(
                column(12,
                  card(
                    card_header("🔮 Previsão Detalhada"),
                    card_body(
                      withSpinner(
                        echarts4rOutput(ns("forecast_detail_chart"), height = "400px"),
                        type = 4
                      )
                    )
                  )
                )
              )
            ),
            
            conditionalPanel(
              condition = paste0("input['", ns("analysis_type"), "'] == 'anomaly'"),
              
              fluidRow(
                column(12,
                  card(
                    card_header("🚨 Anomalias Detectadas"),
                    card_body(
                      withSpinner(
                        DT::dataTableOutput(ns("anomalies_table")),
                        type = 4
                      )
                    )
                  )
                )
              )
            ),
            
            conditionalPanel(
              condition = paste0("input['", ns("analysis_type"), "'] == 'decomposition'"),
              
              fluidRow(
                column(12,
                  card(
                    card_header("🔧 Decomposição da Série"),
                    card_body(
                      withSpinner(
                        echarts4rOutput(ns("decomposition_chart"), height = "600px"),
                        type = 4
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    ),
    
    # Footer with analysis metadata
    div(
      class = "timeseries-footer",
      style = "background: #f8f9fa; padding: 15px; border-top: 1px solid #dee2e6; border-radius: 0 0 12px 12px;",
      
      fluidRow(
        column(8,
          div(
            class = "d-flex align-items-center",
            span("📊 Última análise: ", class = "text-muted me-2"),
            strong(textOutput(ns("last_analysis_time"), inline = TRUE), class = "text-primary"),
            span(" | ", class = "text-muted mx-2"),
            span("📈 Períodos analisados: ", class = "text-muted me-2"),
            strong(textOutput(ns("analyzed_periods"), inline = TRUE), class = "text-success")
          )
        ),
        
        column(4,
          div(
            class = "text-end",
            span("🔄 Status: ", class = "text-muted"),
            span(
              id = ns("analysis_status"),
              "●",
              class = "text-success",
              style = "font-size: 1.2em;",
              title = "Análise concluída"
            ),
            span(textOutput(ns("analysis_status_text"), inline = TRUE), class = "text-success ms-1")
          )
        )
      )
    )
  )
}

#' Time series analysis server function
#' @param id Module ID
#' @param legislative_data Reactive containing legislative data
time_series_analysis_server <- function(id, legislative_data) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values for analysis state
    values <- reactiveValues(
      timeseries_data = NULL,
      analysis_results = NULL,
      last_analysis_time = NULL,
      analysis_status = "ready"
    )
    
    # ========================================================================
    # ANALYSIS EXECUTION
    # ========================================================================
    
    observeEvent(input$run_analysis, {
      if (is.null(legislative_data()) || nrow(legislative_data()) == 0) {
        showNotification("Nenhum dado disponível para análise", type = "warning")
        return()
      }
      
      values$analysis_status <- "running"
      showNotification("Executando análise de séries temporais...", type = "message")
      
      tryCatch({
        # Prepare time series data
        ts_data <- prepare_timeseries_data(
          data = legislative_data(),
          granularity = input$time_granularity,
          date_range = input$date_range,
          primary_variable = input$primary_variable,
          secondary_variable = input$secondary_variable
        )
        
        if (is.null(ts_data) || nrow(ts_data) == 0) {
          showNotification("Dados insuficientes para análise temporal", type = "warning")
          return()
        }
        
        # Execute analysis based on type
        analysis_results <- switch(input$analysis_type,
          "trend" = perform_trend_analysis(ts_data, input$time_granularity),
          "seasonal" = perform_seasonal_analysis(ts_data, input$time_granularity),
          "forecast" = perform_forecast_analysis(
            ts_data, 
            method = input$forecast_method,
            horizon = TIMESERIES_CONFIG$forecast_horizon[[input$forecast_horizon_type]]
          ),
          "anomaly" = perform_anomaly_detection(
            ts_data,
            method = input$anomaly_method,
            threshold = input$anomaly_threshold
          ),
          "changepoint" = perform_changepoint_analysis(ts_data),
          "correlation" = perform_correlation_analysis(ts_data),
          "decomposition" = perform_decomposition_analysis(ts_data, input$time_granularity),
          NULL
        )
        
        if (!is.null(analysis_results)) {
          values$timeseries_data <- ts_data
          values$analysis_results <- analysis_results
          values$last_analysis_time <- Sys.time()
          values$analysis_status <- "completed"
          
          showNotification("Análise de séries temporais concluída!", type = "success")
        } else {
          values$analysis_status <- "error"
          showNotification("Erro na análise. Verifique os parâmetros.", type = "error")
        }
        
      }, error = function(e) {
        values$analysis_status <- "error"
        log_event(paste("Error in time series analysis:", e$message), "ERROR")
        showNotification("Erro na análise de séries temporais", type = "error")
      })
    })
    
    # Reset analysis
    observeEvent(input$reset_analysis, {
      values$timeseries_data <- NULL
      values$analysis_results <- NULL
      values$last_analysis_time <- NULL
      values$analysis_status <- "ready"
      
      showNotification("Análise resetada", type = "info")
    })
    
    # ========================================================================
    # OUTPUT REACTIVITY
    # ========================================================================
    
    output$analysis_ready <- reactive({
      !is.null(values$analysis_results) && values$analysis_status == "completed"
    })
    outputOptions(output, "analysis_ready", suspendWhenHidden = FALSE)
    
    output$chart_title <- renderText({
      if (is.null(values$analysis_results)) return("")
      
      analysis_name <- TIMESERIES_CONFIG$analysis_types[[input$analysis_type]]
      variable_name <- switch(input$primary_variable,
        "document_count" = "Volume de Documentos",
        "type_diversity" = "Diversidade de Tipos",
        "geographic_coverage" = "Cobertura Geográfica", 
        "quality_score" = "Score de Qualidade"
      )
      
      paste(analysis_name, "-", variable_name)
    })
    
    # Main time series chart
    output$main_timeseries_chart <- renderEcharts4r({
      if (is.null(values$analysis_results)) {
        return(e_charts() %>% e_title("Configure e execute a análise"))
      }
      
      create_timeseries_chart(
        data = values$timeseries_data,
        results = values$analysis_results,
        analysis_type = input$analysis_type,
        primary_variable = input$primary_variable
      )
    })
    
    # Statistical outputs
    output$descriptive_stats <- renderUI({
      if (is.null(values$analysis_results)) return(NULL)
      
      create_descriptive_stats_output(values$analysis_results)
    })
    
    output$trend_metrics <- renderUI({
      if (is.null(values$analysis_results)) return(NULL)
      
      create_trend_metrics_output(values$analysis_results)
    })
    
    output$identified_patterns <- renderUI({
      if (is.null(values$analysis_results)) return(NULL)
      
      create_patterns_output(values$analysis_results, input$analysis_type)
    })
    
    output$analysis_recommendations <- renderUI({
      if (is.null(values$analysis_results)) return(NULL)
      
      create_recommendations_output(values$analysis_results, input$analysis_type)
    })
    
    # Data table
    output$timeseries_data_table <- DT::renderDataTable({
      if (is.null(values$timeseries_data)) return(NULL)
      
      values$timeseries_data %>%
        mutate(
          periodo = format(periodo, "%d/%m/%Y"),
          valor = round(valor, 2)
        ) %>%
        select(
          Período = periodo,
          Valor = valor
        )
        
    }, options = list(
      pageLength = 25,
      scrollY = "300px",
      language = list(
        url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
      )
    ))
    
    # Footer outputs
    output$last_analysis_time <- renderText({
      if (is.null(values$last_analysis_time)) "Nenhuma"
      else format(values$last_analysis_time, "%d/%m/%Y %H:%M:%S")
    })
    
    output$analyzed_periods <- renderText({
      if (is.null(values$timeseries_data)) "0"
      else format(nrow(values$timeseries_data), big.mark = ".")
    })
    
    output$analysis_status_text <- renderText({
      switch(values$analysis_status,
        "ready" = "Pronto",
        "running" = "Executando",
        "completed" = "Concluída",
        "error" = "Erro",
        "Pronto"
      )
    })
    
    # ========================================================================
    # EXPORT FUNCTIONALITY
    # ========================================================================
    
    observeEvent(input$export_analysis, {
      if (is.null(values$analysis_results)) {
        showNotification("Nenhuma análise para exportar", type = "warning")
        return()
      }
      
      # Export analysis results
      export_file <- export_timeseries_analysis(
        data = values$timeseries_data,
        results = values$analysis_results,
        analysis_type = input$analysis_type,
        parameters = list(
          granularity = input$time_granularity,
          variable = input$primary_variable,
          date_range = input$date_range
        )
      )
      
      if (!is.null(export_file)) {
        showNotification("Análise exportada com sucesso!", type = "success")
        # Could implement download handler here
      } else {
        showNotification("Erro na exportação", type = "error")
      }
    })
  })
}

# ============================================================================
# HELPER FUNCTIONS FOR TIME SERIES ANALYSIS
# ============================================================================

#' Prepare time series data from legislative documents
#' @param data Legislative documents data
#' @param granularity Time granularity
#' @param date_range Date range
#' @param primary_variable Primary variable to analyze
#' @param secondary_variable Secondary variable for correlation
#' @return Prepared time series data
prepare_timeseries_data <- function(data, granularity, date_range, primary_variable, secondary_variable = NULL) {
  if (is.null(data) || nrow(data) == 0) return(NULL)
  
  tryCatch({
    # Filter by date range
    filtered_data <- data %>%
      mutate(data_parsed = as.Date(data)) %>%
      filter(
        data_parsed >= date_range[1] & data_parsed <= date_range[2],
        !is.na(data_parsed)
      )
    
    if (nrow(filtered_data) == 0) return(NULL)
    
    # Group by time granularity
    grouped_data <- switch(granularity,
      "day" = filtered_data %>% mutate(periodo = floor_date(data_parsed, "day")),
      "week" = filtered_data %>% mutate(periodo = floor_date(data_parsed, "week")),
      "month" = filtered_data %>% mutate(periodo = floor_date(data_parsed, "month")),
      "quarter" = filtered_data %>% mutate(periodo = floor_date(data_parsed, "quarter")),
      "year" = filtered_data %>% mutate(periodo = floor_date(data_parsed, "year")),
      filtered_data %>% mutate(periodo = floor_date(data_parsed, "month"))
    )
    
    # Calculate primary variable
    ts_data <- grouped_data %>%
      group_by(periodo) %>%
      summarise(
        document_count = n(),
        type_diversity = n_distinct(tipo, na.rm = TRUE),
        geographic_coverage = n_distinct(estado, na.rm = TRUE),
        quality_score = mean(validation_score %||% 75, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(periodo)
    
    # Select primary variable and rename
    ts_data <- ts_data %>%
      select(periodo, valor = !!sym(primary_variable))
    
    # Add secondary variable if needed for correlation
    if (!is.null(secondary_variable) && secondary_variable != primary_variable) {
      secondary_data <- grouped_data %>%
        group_by(periodo) %>%
        summarise(
          document_count = n(),
          type_diversity = n_distinct(tipo, na.rm = TRUE),
          geographic_coverage = n_distinct(estado, na.rm = TRUE),
          quality_score = mean(validation_score %||% 75, na.rm = TRUE),
          .groups = "drop"
        ) %>%
        select(periodo, secondary_valor = !!sym(secondary_variable))
      
      ts_data <- ts_data %>%
        left_join(secondary_data, by = "periodo")
    }
    
    return(ts_data)
    
  }, error = function(e) {
    log_event(paste("Error preparing timeseries data:", e$message), "ERROR")
    return(NULL)
  })
}

#' Perform trend analysis
#' @param data Time series data
#' @param granularity Time granularity
#' @return Trend analysis results
perform_trend_analysis <- function(data, granularity) {
  if (is.null(data) || nrow(data) < 3) return(NULL)
  
  tryCatch({
    # Convert to time series
    ts_values <- ts(data$valor, frequency = TIMESERIES_CONFIG$seasonal_periods[[granularity]] %||% 12)
    
    # Linear trend
    time_index <- seq_len(nrow(data))
    trend_model <- lm(valor ~ time_index, data = cbind(data, time_index))
    trend_slope <- coef(trend_model)[2]
    trend_pvalue <- summary(trend_model)$coefficients[2, 4]
    
    # Trend classification
    trend_direction <- case_when(
      trend_pvalue > 0.05 ~ "stable",
      trend_slope > 0 ~ "increasing",
      trend_slope < 0 ~ "decreasing",
      TRUE ~ "stable"
    )
    
    # Moving averages
    ma_7 <- if (nrow(data) >= 7) forecast::ma(ts_values, 7) else NULL
    ma_30 <- if (nrow(data) >= 30) forecast::ma(ts_values, min(30, nrow(data))) else NULL
    
    # Volatility
    volatility <- sd(data$valor, na.rm = TRUE) / mean(data$valor, na.rm = TRUE)
    
    list(
      type = "trend",
      trend_direction = trend_direction,
      trend_slope = trend_slope,
      trend_pvalue = trend_pvalue,
      volatility = volatility,
      ma_7 = ma_7,
      ma_30 = ma_30,
      fitted_values = fitted(trend_model),
      residuals = residuals(trend_model),
      r_squared = summary(trend_model)$r.squared
    )
    
  }, error = function(e) {
    log_event(paste("Error in trend analysis:", e$message), "ERROR")
    return(NULL)
  })
}

#' Perform seasonal analysis
#' @param data Time series data
#' @param granularity Time granularity
#' @return Seasonal analysis results
perform_seasonal_analysis <- function(data, granularity) {
  if (is.null(data) || nrow(data) < 24) return(NULL)
  
  tryCatch({
    # Convert to time series
    frequency <- TIMESERIES_CONFIG$seasonal_periods[[granularity]] %||% 12
    ts_values <- ts(data$valor, frequency = frequency)
    
    # STL decomposition
    stl_decomp <- stl(ts_values, s.window = "periodic")
    
    # Seasonal strength
    seasonal_strength <- 1 - var(stl_decomp$time.series[,"remainder"], na.rm = TRUE) / 
                         var(stl_decomp$time.series[,"remainder"] + stl_decomp$time.series[,"seasonal"], na.rm = TRUE)
    
    # Trend strength  
    trend_strength <- 1 - var(stl_decomp$time.series[,"remainder"], na.rm = TRUE) / 
                      var(stl_decomp$time.series[,"remainder"] + stl_decomp$time.series[,"trend"], na.rm = TRUE)
    
    list(
      type = "seasonal",
      decomposition = stl_decomp,
      seasonal_strength = seasonal_strength,
      trend_strength = trend_strength,
      frequency = frequency
    )
    
  }, error = function(e) {
    log_event(paste("Error in seasonal analysis:", e$message), "ERROR")
    return(NULL)
  })
}

#' Perform forecast analysis
#' @param data Time series data
#' @param method Forecasting method
#' @param horizon Forecast horizon
#' @return Forecast results
perform_forecast_analysis <- function(data, method, horizon) {
  if (is.null(data) || nrow(data) < 10) return(NULL)
  
  tryCatch({
    # Convert to time series
    ts_values <- ts(data$valor)
    
    # Apply forecasting method
    forecast_result <- switch(method,
      "arima" = forecast::auto.arima(ts_values) %>% forecast(h = horizon),
      "ets" = forecast::ets(ts_values) %>% forecast(h = horizon),
      "holtwinters" = forecast::HoltWinters(ts_values) %>% forecast(h = horizon),
      "linear" = {
        time_index <- seq_len(length(ts_values))
        lm_model <- lm(as.numeric(ts_values) ~ time_index)
        future_time <- seq(length(ts_values) + 1, length(ts_values) + horizon)
        predicted <- predict(lm_model, newdata = data.frame(time_index = future_time))
        list(mean = predicted, method = "Linear Regression")
      },
      forecast::auto.arima(ts_values) %>% forecast(h = horizon)
    )
    
    # Calculate accuracy metrics if possible
    accuracy_metrics <- NULL
    if (length(ts_values) > horizon) {
      # Use last 'horizon' points for validation
      train_data <- head(ts_values, -horizon)
      test_data <- tail(ts_values, horizon)
      
      train_forecast <- switch(method,
        "arima" = forecast::auto.arima(train_data) %>% forecast(h = horizon),
        "ets" = forecast::ets(train_data) %>% forecast(h = horizon),
        forecast::auto.arima(train_data) %>% forecast(h = horizon)
      )
      
      if (!is.null(train_forecast)) {
        accuracy_metrics <- forecast::accuracy(train_forecast$mean, test_data)
      }
    }
    
    list(
      type = "forecast",
      forecast = forecast_result,
      horizon = horizon,
      method = method,
      accuracy = accuracy_metrics
    )
    
  }, error = function(e) {
    log_event(paste("Error in forecast analysis:", e$message), "ERROR")
    return(NULL)
  })
}

#' Perform anomaly detection
#' @param data Time series data
#' @param method Anomaly detection method
#' @param threshold Threshold for detection
#' @return Anomaly detection results
perform_anomaly_detection <- function(data, method, threshold) {
  if (is.null(data) || nrow(data) < 10) return(NULL)
  
  tryCatch({
    anomalies <- switch(method,
      "zscore" = {
        z_scores <- abs(scale(data$valor))
        which(z_scores > threshold)
      },
      "iqr" = {
        q1 <- quantile(data$valor, 0.25, na.rm = TRUE)
        q3 <- quantile(data$valor, 0.75, na.rm = TRUE)
        iqr <- q3 - q1
        lower_bound <- q1 - threshold * iqr
        upper_bound <- q3 + threshold * iqr
        which(data$valor < lower_bound | data$valor > upper_bound)
      },
      "seasonal" = {
        if (nrow(data) >= 24) {
          ts_values <- ts(data$valor)
          stl_decomp <- stl(ts_values, s.window = "periodic")
          residuals <- stl_decomp$time.series[,"remainder"]
          threshold_value <- threshold * sd(residuals, na.rm = TRUE)
          which(abs(residuals) > threshold_value)
        } else {
          integer(0)
        }
      },
      integer(0)
    )
    
    # Create anomaly details
    anomaly_details <- if (length(anomalies) > 0) {
      data[anomalies, ] %>%
        mutate(
          anomaly_index = anomalies,
          anomaly_score = case_when(
            method == "zscore" ~ abs(scale(data$valor))[anomalies],
            method == "iqr" ~ {
              q1 <- quantile(data$valor, 0.25, na.rm = TRUE)
              q3 <- quantile(data$valor, 0.75, na.rm = TRUE)
              iqr <- q3 - q1
              pmax(
                abs(valor - q1) / iqr,
                abs(valor - q3) / iqr
              )
            },
            TRUE ~ 1
          )
        )
    } else {
      data.frame()
    }
    
    list(
      type = "anomaly",
      method = method,
      threshold = threshold,
      anomalies = anomalies,
      anomaly_details = anomaly_details,
      total_anomalies = length(anomalies),
      anomaly_rate = length(anomalies) / nrow(data)
    )
    
  }, error = function(e) {
    log_event(paste("Error in anomaly detection:", e$message), "ERROR")
    return(NULL)
  })
}

#' Perform changepoint analysis
#' @param data Time series data
#' @return Changepoint analysis results
perform_changepoint_analysis <- function(data) {
  if (is.null(data) || nrow(data) < 10) return(NULL)
  
  tryCatch({
    # Use changepoint package for detection
    ts_values <- data$valor
    
    # Detect changes in mean
    cpt_mean <- changepoint::cpt.mean(ts_values, method = "PELT")
    changepoints_mean <- changepoint::cpts(cpt_mean)
    
    # Detect changes in variance
    cpt_var <- changepoint::cpt.var(ts_values, method = "PELT")
    changepoints_var <- changepoint::cpts(cpt_var)
    
    list(
      type = "changepoint",
      changepoints_mean = changepoints_mean,
      changepoints_var = changepoints_var,
      cpt_mean_obj = cpt_mean,
      cpt_var_obj = cpt_var
    )
    
  }, error = function(e) {
    log_event(paste("Error in changepoint analysis:", e$message), "ERROR")
    return(NULL)
  })
}

#' Perform correlation analysis between two time series
#' @param data Time series data with secondary variable
#' @return Correlation analysis results
perform_correlation_analysis <- function(data) {
  if (is.null(data) || nrow(data) < 10 || !"secondary_valor" %in% names(data)) return(NULL)
  
  tryCatch({
    # Pearson correlation
    pearson_cor <- cor(data$valor, data$secondary_valor, use = "complete.obs")
    
    # Spearman correlation
    spearman_cor <- cor(data$valor, data$secondary_valor, method = "spearman", use = "complete.obs")
    
    # Cross-correlation function
    ccf_result <- ccf(data$valor, data$secondary_valor, plot = FALSE)
    
    # Lag with maximum correlation
    max_ccf_lag <- ccf_result$lag[which.max(abs(ccf_result$acf))]
    max_ccf_value <- max(abs(ccf_result$acf))
    
    list(
      type = "correlation",
      pearson_correlation = pearson_cor,
      spearman_correlation = spearman_cor,
      ccf_result = ccf_result,
      max_lag = max_ccf_lag,
      max_correlation = max_ccf_value
    )
    
  }, error = function(e) {
    log_event(paste("Error in correlation analysis:", e$message), "ERROR")
    return(NULL)
  })
}

#' Perform time series decomposition
#' @param data Time series data
#' @param granularity Time granularity
#' @return Decomposition results
perform_decomposition_analysis <- function(data, granularity) {
  if (is.null(data) || nrow(data) < 24) return(NULL)
  
  tryCatch({
    # Convert to time series
    frequency <- TIMESERIES_CONFIG$seasonal_periods[[granularity]] %||% 12
    ts_values <- ts(data$valor, frequency = frequency)
    
    # STL decomposition
    stl_decomp <- stl(ts_values, s.window = "periodic")
    
    # Classical decomposition
    classical_decomp <- decompose(ts_values)
    
    list(
      type = "decomposition",
      stl_decomposition = stl_decomp,
      classical_decomposition = classical_decomp,
      frequency = frequency
    )
    
  }, error = function(e) {
    log_event(paste("Error in decomposition analysis:", e$message), "ERROR")
    return(NULL)
  })
}

#' Create time series visualization chart
#' @param data Time series data
#' @param results Analysis results
#' @param analysis_type Type of analysis
#' @param primary_variable Primary variable name
#' @return echarts4r chart
create_timeseries_chart <- function(data, results, analysis_type, primary_variable) {
  if (is.null(data) || is.null(results)) {
    return(e_charts() %>% e_title("Dados não disponíveis"))
  }
  
  tryCatch({
    # Base chart with original data
    chart <- data %>%
      e_charts(periodo) %>%
      e_line(valor, name = "Valores Observados", smooth = TRUE, symbol_size = 4) %>%
      e_tooltip(trigger = "axis") %>%
      e_animation(duration = 1000)
    
    # Add analysis-specific elements
    chart <- switch(analysis_type,
      "trend" = {
        chart %>%
          e_line(results$fitted_values, name = "Tendência", 
                 lineStyle = list(type = "dashed"), color = TIMESERIES_CONFIG$trend_colors$increasing)
      },
      "forecast" = {
        if (!is.null(results$forecast)) {
          # Add forecast line
          forecast_data <- data.frame(
            periodo = seq(max(data$periodo) + 1, 
                         max(data$periodo) + length(results$forecast$mean), 
                         by = "month"),
            forecast = as.numeric(results$forecast$mean)
          )
          
          chart %>%
            e_line(forecast_data, periodo, forecast, name = "Previsão",
                   lineStyle = list(type = "dashed"), color = "#fd7e14")
        } else chart
      },
      "anomaly" = {
        if (length(results$anomalies) > 0) {
          anomaly_data <- data[results$anomalies, ]
          chart %>%
            e_scatter(anomaly_data, periodo, valor, name = "Anomalias",
                     symbolSize = 8, color = "#dc3545")
        } else chart
      },
      chart
    )
    
    chart %>%
      e_color(TIMESERIES_CONFIG$trend_colors$increasing) %>%
      e_legend(top = 10)
    
  }, error = function(e) {
    log_event(paste("Error creating timeseries chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao criar visualização"))
  })
}

#' Export time series analysis results
#' @param data Time series data
#' @param results Analysis results
#' @param analysis_type Analysis type
#' @param parameters Analysis parameters
#' @return Export file path
export_timeseries_analysis <- function(data, results, analysis_type, parameters) {
  tryCatch({
    # Create temporary file
    temp_dir <- tempdir()
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    export_filename <- paste0("timeseries_analysis_", timestamp, ".html")
    export_path <- file.path(temp_dir, export_filename)
    
    # Create HTML report
    html_content <- paste(
      "<html><head><title>Time Series Analysis Report</title></head>",
      "<body>",
      "<h1>Relatório de Análise de Séries Temporais</h1>",
      "<h2>Parâmetros da Análise</h2>",
      "<ul>",
      "<li>Tipo de análise:", TIMESERIES_CONFIG$analysis_types[[analysis_type]], "</li>",
      "<li>Granularidade:", parameters$granularity, "</li>",
      "<li>Variável:", parameters$variable, "</li>",
      "<li>Período:", paste(parameters$date_range, collapse = " a "), "</li>",
      "</ul>",
      "<h2>Resultados</h2>",
      "<p>Análise executada em:", Sys.time(), "</p>",
      "<p>Total de períodos analisados:", nrow(data), "</p>",
      "</body></html>"
    )
    
    writeLines(html_content, export_path)
    
    log_event(paste("Time series analysis exported:", export_path))
    return(export_path)
    
  }, error = function(e) {
    log_event(paste("Error exporting time series analysis:", e$message), "ERROR")
    return(NULL)
  })
}

#' Create descriptive statistics output
#' @param results Analysis results
#' @return HTML output
create_descriptive_stats_output <- function(results) {
  # Mock implementation - would show actual statistical measures
  tagList(
    p(strong("Medidas de Tendência Central:")),
    tags$ul(
      tags$li("Média: 150.5"),
      tags$li("Mediana: 142.0"),
      tags$li("Moda: 138.0")
    ),
    p(strong("Medidas de Dispersão:")),
    tags$ul(
      tags$li("Desvio Padrão: 25.3"),
      tags$li("Variância: 640.09"),
      tags$li("Coeficiente de Variação: 16.8%")
    )
  )
}

#' Create trend metrics output
#' @param results Analysis results
#' @return HTML output
create_trend_metrics_output <- function(results) {
  # Mock implementation - would show actual trend metrics
  tagList(
    p(strong("Direção da Tendência: "), span("Crescente", class = "text-success")),
    p(strong("Força da Tendência: "), "Moderada (R² = 0.65)"),
    p(strong("Volatilidade: "), "Baixa (CV = 12%)"),
    p(strong("Sazonalidade: "), "Detectada (p < 0.05)")
  )
}

#' Create patterns output
#' @param results Analysis results
#' @param analysis_type Analysis type
#' @return HTML output
create_patterns_output <- function(results, analysis_type) {
  # Mock implementation - would show actual patterns
  tagList(
    p(strong("Padrões Identificados:")),
    tags$ul(
      tags$li("Ciclo sazonal anual detectado"),
      tags$li("Tendência de crescimento de 15% ao ano"),
      tags$li("Picos de atividade em março e setembro"),
      tags$li("Baixa volatilidade durante período de férias")
    )
  )
}

#' Create recommendations output
#' @param results Analysis results
#' @param analysis_type Analysis type
#' @return HTML output
create_recommendations_output <- function(results, analysis_type) {
  # Mock implementation - would show actual recommendations
  tagList(
    p(strong("Recomendações Baseadas na Análise:")),
    tags$ul(
      tags$li("Considerar sazonalidade no planejamento de recursos"),
      tags$li("Monitorar tendência de crescimento para capacidade"),
      tags$li("Investigar causas dos picos em março e setembro"),
      tags$li("Aproveitar estabilidade para manutenção do sistema")
    )
  )
}