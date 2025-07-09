# Advanced Dashboard with Real-Time Analytics for Monitor Legislativo v4
# Interactive dashboard with live data updates and comprehensive analytics

library(shiny)
library(bslib)
library(echarts4r)
library(plotly)
library(DT)
library(htmltools)
library(dplyr)
library(lubridate)
library(shinycssloaders)
library(fresh)

# Dashboard configuration
DASHBOARD_CONFIG <- list(
  refresh_intervals = list(
    "5s" = 5000,
    "30s" = 30000,
    "1min" = 60000,
    "5min" = 300000,
    "15min" = 900000,
    "Manual" = 0
  ),
  
  chart_types = list(
    "line" = "Linha",
    "bar" = "Barras",
    "area" = "Área",
    "scatter" = "Dispersão",
    "heatmap" = "Mapa de Calor",
    "sankey" = "Sankey",
    "treemap" = "Treemap",
    "gauge" = "Medidor"
  ),
  
  metrics_categories = list(
    "volume" = "Volume de Documentos",
    "temporal" = "Análise Temporal",
    "geographic" = "Distribuição Geográfica", 
    "content" = "Análise de Conteúdo",
    "quality" = "Métricas de Qualidade",
    "patterns" = "Padrões Legislativos"
  ),
  
  color_schemes = list(
    "default" = c("#0d6efd", "#198754", "#fd7e14", "#dc3545", "#6f42c1", "#0dcaf0", "#ffc107"),
    "government" = c("#1f4e79", "#2e7d32", "#d84315", "#7b1fa2", "#c62828"),
    "academic" = c("#1565c0", "#00695c", "#ef6c00", "#ad1457", "#4527a0"),
    "accessible" = c("#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd")
  ),
  
  update_batch_size = 100,
  max_data_points = 1000
)

#' Create advanced analytics dashboard interface
#' @param id Module ID
#' @return Dashboard UI
advanced_dashboard_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "advanced-dashboard-container",
    
    # Dashboard header with controls
    div(
      class = "dashboard-header",
      style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 12px 12px 0 0; color: white;",
      
      fluidRow(
        column(6,
          h3("📊 Analytics Dashboard", style = "margin: 0; text-shadow: 0 1px 2px rgba(0,0,0,0.3);"),
          p("Monitor Legislativo v4 - Real-Time Legislative Analytics", 
            style = "margin: 5px 0 0 0; opacity: 0.9; font-size: 0.95em;")
        ),
        
        column(6,
          div(
            class = "dashboard-controls text-end",
            
            # Auto-refresh control
            div(
              class = "d-inline-block me-3",
              style = "background: rgba(255,255,255,0.1); padding: 8px 12px; border-radius: 6px;",
              
              tags$label("🔄 Auto-Refresh:", style = "color: white; font-size: 0.9em; margin-right: 5px;"),
              selectInput(
                ns("auto_refresh"),
                NULL,
                choices = DASHBOARD_CONFIG$refresh_intervals,
                selected = 60000,
                width = "120px"
              )
            ),
            
            # Manual refresh button
            actionButton(
              ns("manual_refresh"),
              "🔄 Atualizar",
              class = "btn btn-light btn-sm",
              style = "margin-top: 5px;"
            )
          )
        )
      )
    ),
    
    # Key Performance Indicators (KPIs)
    div(
      class = "kpi-section",
      style = "background: white; padding: 20px; border-bottom: 1px solid #e9ecef;",
      
      h5("📈 Indicadores-Chave de Performance", class = "mb-3"),
      
      # Loading indicator for KPIs
      conditionalPanel(
        condition = paste0("input['", ns("manual_refresh"), "'] > 0 && !output['", ns("kpis_ready"), "']"),
        div(
          class = "text-center py-3",
          withSpinner(
            div("Atualizando indicadores..."),
            type = 6,
            color = "#0d6efd"
          )
        )
      ),
      
      # KPI Cards
      conditionalPanel(
        condition = paste0("output['", ns("kpis_ready"), "']"),
        
        div(
          class = "kpi-grid",
          style = "display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px;",
          
          # Dynamic KPI cards will be rendered here
          uiOutput(ns("kpi_cards"))
        )
      )
    ),
    
    # Main analytics content
    div(
      class = "analytics-content",
      style = "background: white;",
      
      # Analytics tabs
      navset_card_tab(
        id = ns("analytics_tabs"),
        
        # Real-Time Monitoring Tab
        nav_panel(
          "📊 Monitoramento em Tempo Real",
          
          fluidRow(
            # Volume trends
            column(6,
              card(
                card_header(
                  div(
                    class = "d-flex justify-content-between align-items-center",
                    span("📈 Tendências de Volume"),
                    actionButton(
                      ns("config_volume_chart"),
                      "⚙️",
                      class = "btn btn-sm btn-outline-secondary"
                    )
                  )
                ),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("volume_trends"), height = "350px"),
                    type = 4
                  )
                )
              )
            ),
            
            # Geographic distribution
            column(6,
              card(
                card_header(
                  div(
                    class = "d-flex justify-content-between align-items-center",
                    span("🗺️ Distribuição Geográfica"),
                    actionButton(
                      ns("config_geo_chart"),
                      "⚙️",
                      class = "btn btn-sm btn-outline-secondary"
                    )
                  )
                ),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("geographic_distribution"), height = "350px"),
                    type = 4
                  )
                )
              )
            )
          ),
          
          br(),
          
          fluidRow(
            # Document types analysis
            column(6,
              card(
                card_header("📄 Análise por Tipo de Documento"),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("document_types"), height = "300px"),
                    type = 4
                  )
                )
              )
            ),
            
            # Recent activity feed
            column(6,
              card(
                card_header("🕐 Atividade Recente"),
                card_body(
                  style = "max-height: 300px; overflow-y: auto;",
                  uiOutput(ns("activity_feed"))
                )
              )
            )
          )
        ),
        
        # Advanced Analytics Tab
        nav_panel(
          "🔍 Análise Avançada",
          
          fluidRow(
            # Temporal patterns
            column(12,
              card(
                card_header(
                  div(
                    class = "d-flex justify-content-between align-items-center",
                    span("📅 Padrões Temporais"),
                    div(
                      selectInput(
                        ns("temporal_granularity"),
                        NULL,
                        choices = c(
                          "Diário" = "day",
                          "Semanal" = "week", 
                          "Mensal" = "month",
                          "Trimestral" = "quarter",
                          "Anual" = "year"
                        ),
                        selected = "month",
                        width = "150px"
                      )
                    )
                  )
                ),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("temporal_patterns"), height = "400px"),
                    type = 4
                  )
                )
              )
            )
          ),
          
          br(),
          
          fluidRow(
            # Content analysis
            column(6,
              card(
                card_header("📝 Análise de Conteúdo"),
                card_body(
                  navset_pill_card(
                    nav_panel(
                      "Palavras-chave",
                      withSpinner(
                        echarts4rOutput(ns("keyword_analysis"), height = "250px"),
                        type = 4
                      )
                    ),
                    nav_panel(
                      "Temas",
                      withSpinner(
                        echarts4rOutput(ns("theme_analysis"), height = "250px"),
                        type = 4
                      )
                    )
                  )
                )
              )
            ),
            
            # Quality metrics
            column(6,
              card(
                card_header("⭐ Métricas de Qualidade"),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("quality_metrics"), height = "300px"),
                    type = 4
                  )
                )
              )
            )
          )
        ),
        
        # Comparative Analysis Tab
        nav_panel(
          "⚖️ Análise Comparativa",
          
          fluidRow(
            # State comparison
            column(12,
              card(
                card_header(
                  div(
                    class = "d-flex justify-content-between align-items-center",
                    span("🏛️ Comparação entre Estados"),
                    div(
                      checkboxGroupInput(
                        ns("selected_states"),
                        NULL,
                        choices = NULL,
                        selected = NULL,
                        inline = TRUE
                      )
                    )
                  )
                ),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("state_comparison"), height = "400px"),
                    type = 4
                  )
                )
              )
            )
          ),
          
          br(),
          
          fluidRow(
            # Performance benchmarks
            column(6,
              card(
                card_header("📊 Benchmarks de Performance"),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("performance_benchmarks"), height = "300px"),
                    type = 4
                  )
                )
              )
            ),
            
            # Correlation analysis
            column(6,
              card(
                card_header("🔗 Análise de Correlação"),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("correlation_analysis"), height = "300px"),
                    type = 4
                  )
                )
              )
            )
          )
        ),
        
        # Custom Analytics Tab
        nav_panel(
          "🛠️ Análise Personalizada",
          
          fluidRow(
            column(3,
              card(
                card_header("⚙️ Configurações"),
                card_body(
                  h6("Métricas para Análise"),
                  checkboxGroupInput(
                    ns("custom_metrics"),
                    NULL,
                    choices = DASHBOARD_CONFIG$metrics_categories,
                    selected = c("volume", "temporal")
                  ),
                  
                  h6("Período de Análise"),
                  dateRangeInput(
                    ns("custom_date_range"),
                    NULL,
                    start = Sys.Date() - 90,
                    end = Sys.Date(),
                    format = "dd/mm/yyyy",
                    language = "pt-BR"
                  ),
                  
                  h6("Tipo de Visualização"),
                  selectInput(
                    ns("custom_chart_type"),
                    NULL,
                    choices = DASHBOARD_CONFIG$chart_types,
                    selected = "line"
                  ),
                  
                  h6("Esquema de Cores"),
                  selectInput(
                    ns("custom_color_scheme"),
                    NULL,
                    choices = c(
                      "Padrão" = "default",
                      "Governamental" = "government",
                      "Acadêmico" = "academic",
                      "Acessível" = "accessible"
                    ),
                    selected = "default"
                  ),
                  
                  br(),
                  
                  actionButton(
                    ns("generate_custom_analysis"),
                    "📊 Gerar Análise",
                    class = "btn btn-primary w-100"
                  )
                )
              )
            ),
            
            column(9,
              card(
                card_header("📈 Análise Personalizada"),
                card_body(
                  conditionalPanel(
                    condition = paste0("output['", ns("custom_analysis_ready"), "']"),
                    withSpinner(
                      echarts4rOutput(ns("custom_analysis"), height = "500px"),
                      type = 4
                    )
                  ),
                  
                  conditionalPanel(
                    condition = paste0("!output['", ns("custom_analysis_ready"), "']"),
                    div(
                      class = "text-center py-5",
                      icon("chart-line", class = "fa-3x text-muted mb-3"),
                      h4("Análise Personalizada", class = "text-muted"),
                      p("Configure as opções à esquerda e clique em 'Gerar Análise'", class = "text-muted")
                    )
                  )
                )
              )
            )
          )
        ),
        
        # Time Series Analysis Tab
        nav_panel(
          "📈 Análise Temporal",
          
          # Time series analysis interface
          time_series_analysis_ui("dashboard_timeseries")
        ),
        
        # Data Exploration Tab
        nav_panel(
          "🔍 Exploração de Dados",
          
          # Interactive data exploration interface
          data_exploration_ui("dashboard_exploration")
        ),
        
        # Legislative Pattern Analytics Tab
        nav_panel(
          "⚖️ Padrões Legislativos",
          
          # Legislative pattern analytics interface
          legislative_pattern_analytics_ui("dashboard_patterns")
        ),
        
        # Export Dashboard Tab
        nav_panel(
          "📤 Exportar Dashboard",
          
          fluidRow(
            column(6,
              card(
                card_header("📊 Exportar Visualizações"),
                card_body(
                  h6("Selecionar Gráficos"),
                  checkboxGroupInput(
                    ns("export_charts"),
                    NULL,
                    choices = c(
                      "Tendências de Volume" = "volume_trends",
                      "Distribuição Geográfica" = "geographic_distribution",
                      "Tipos de Documento" = "document_types",
                      "Padrões Temporais" = "temporal_patterns",
                      "Análise de Conteúdo" = "content_analysis",
                      "Métricas de Qualidade" = "quality_metrics"
                    ),
                    selected = c("volume_trends", "geographic_distribution")
                  ),
                  
                  h6("Formato de Exportação"),
                  radioButtons(
                    ns("export_format"),
                    NULL,
                    choices = c(
                      "PNG (Imagem)" = "png",
                      "PDF (Documento)" = "pdf",
                      "HTML (Interativo)" = "html",
                      "PowerPoint" = "pptx"
                    ),
                    selected = "png"
                  ),
                  
                  h6("Resolução"),
                  selectInput(
                    ns("export_resolution"),
                    NULL,
                    choices = c(
                      "Baixa (800x600)" = "low",
                      "Média (1200x900)" = "medium",
                      "Alta (1920x1080)" = "high",
                      "Ultra (2560x1440)" = "ultra"
                    ),
                    selected = "medium"
                  ),
                  
                  br(),
                  
                  actionButton(
                    ns("generate_export"),
                    "📦 Gerar Exportação",
                    class = "btn btn-success w-100"
                  )
                )
              )
            ),
            
            column(6,
              card(
                card_header("📋 Relatório do Dashboard"),
                card_body(
                  h6("Incluir no Relatório"),
                  checkboxGroupInput(
                    ns("report_sections"),
                    NULL,
                    choices = c(
                      "Resumo Executivo" = "executive_summary",
                      "KPIs Principais" = "main_kpis",
                      "Análise Temporal" = "temporal_analysis",
                      "Distribuição Geográfica" = "geographic_analysis",
                      "Insights e Recomendações" = "insights"
                    ),
                    selected = c("executive_summary", "main_kpis", "insights")
                  ),
                  
                  h6("Formato do Relatório"),
                  radioButtons(
                    ns("report_format"),
                    NULL,
                    choices = c(
                      "HTML Interativo" = "html",
                      "PDF Acadêmico" = "pdf",
                      "Word Document" = "docx",
                      "Markdown" = "md"
                    ),
                    selected = "html"
                  ),
                  
                  br(),
                  
                  actionButton(
                    ns("generate_report"),
                    "📄 Gerar Relatório",
                    class = "btn btn-info w-100"
                  ),
                  
                  br(), br(),
                  
                  conditionalPanel(
                    condition = paste0("output['", ns("export_ready"), "']"),
                    div(
                      class = "alert alert-success",
                      icon("check-circle"),
                      " Exportação pronta!",
                      br(),
                      downloadButton(
                        ns("download_export"),
                        "📥 Baixar",
                        class = "btn btn-success btn-sm mt-2"
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
    
    # Dashboard footer with metadata
    div(
      class = "dashboard-footer",
      style = "background: #f8f9fa; padding: 15px; border-top: 1px solid #dee2e6; border-radius: 0 0 12px 12px;",
      
      fluidRow(
        column(8,
          div(
            class = "d-flex align-items-center",
            span("📊 Dashboard atualizado em: ", class = "text-muted me-2"),
            strong(textOutput(ns("last_update"), inline = TRUE), class = "text-primary"),
            span(" | ", class = "text-muted mx-2"),
            span("📈 Registros analisados: ", class = "text-muted me-2"),
            strong(textOutput(ns("total_records"), inline = TRUE), class = "text-success")
          )
        ),
        
        column(4,
          div(
            class = "text-end",
            span("🔄 Status: ", class = "text-muted"),
            span(
              id = ns("connection_status"),
              "●",
              class = "text-success",
              style = "font-size: 1.2em;",
              title = "Conectado"
            ),
            span("Online", class = "text-success ms-1")
          )
        )
      )
    )
  )
}

#' Advanced dashboard server function
#' @param id Module ID
#' @param legislative_data Reactive containing legislative data
advanced_dashboard_server <- function(id, legislative_data) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values for dashboard state
    values <- reactiveValues(
      processed_data = NULL,
      kpi_data = NULL,
      last_update = Sys.time(),
      auto_refresh_active = TRUE,
      custom_analysis_data = NULL,
      export_file = NULL
    )
    
    # ========================================================================
    # AUTO-REFRESH LOGIC
    # ========================================================================
    
    # Auto-refresh timer
    observe({
      if (!is.null(input$auto_refresh) && input$auto_refresh > 0) {
        invalidateLater(as.numeric(input$auto_refresh))
        refresh_dashboard_data()
      }
    })
    
    # Manual refresh
    observeEvent(input$manual_refresh, {
      refresh_dashboard_data()
    })
    
    # Refresh function
    refresh_dashboard_data <- function() {
      if (!is.null(legislative_data()) && nrow(legislative_data()) > 0) {
        values$processed_data <- process_data_for_dashboard(legislative_data())
        values$kpi_data <- calculate_dashboard_kpis(values$processed_data)
        values$last_update <- Sys.time()
        
        log_event("Dashboard data refreshed")
      }
    }
    
    # Initial data load
    observe({
      refresh_dashboard_data()
    })
    
    # ========================================================================
    # KPI CARDS
    # ========================================================================
    
    output$kpis_ready <- reactive({
      !is.null(values$kpi_data)
    })
    outputOptions(output, "kpis_ready", suspendWhenHidden = FALSE)
    
    output$kpi_cards <- renderUI({
      if (is.null(values$kpi_data)) return(NULL)
      
      kpis <- values$kpi_data
      
      div(
        class = "kpi-cards-container",
        
        # Total Documents KPI
        create_kpi_card(
          title = "Total de Documentos",
          value = format(kpis$total_documents, big.mark = "."),
          change = kpis$documents_change_pct,
          icon = "📄",
          color = "primary"
        ),
        
        # New This Week KPI
        create_kpi_card(
          title = "Novos Esta Semana", 
          value = format(kpis$new_this_week, big.mark = "."),
          change = kpis$weekly_change_pct,
          icon = "📈",
          color = "success"
        ),
        
        # Coverage KPI
        create_kpi_card(
          title = "Cobertura Geográfica",
          value = paste0(kpis$geographic_coverage, "%"),
          change = kpis$coverage_change_pct,
          icon = "🗺️",
          color = "info"
        ),
        
        # Quality Score KPI
        create_kpi_card(
          title = "Score de Qualidade",
          value = paste0(round(kpis$avg_quality_score), "%"),
          change = kpis$quality_change_pct,
          icon = "⭐",
          color = "warning"
        ),
        
        # Processing Rate KPI
        create_kpi_card(
          title = "Taxa de Processamento",
          value = paste0(kpis$processing_rate, "/h"),
          change = kpis$processing_change_pct,
          icon = "⚡",
          color = "secondary"
        ),
        
        # Active Sources KPI
        create_kpi_card(
          title = "Fontes Ativas",
          value = kpis$active_sources,
          change = kpis$sources_change_pct,
          icon = "🔗",
          color = "dark"
        )
      )
    })
    
    # ========================================================================
    # REAL-TIME CHARTS
    # ========================================================================
    
    # Volume trends chart
    output$volume_trends <- renderEcharts4r({
      if (is.null(values$processed_data)) {
        return(e_charts() %>% e_title("Carregando dados..."))
      }
      
      create_volume_trends_chart(values$processed_data)
    })
    
    # Geographic distribution chart  
    output$geographic_distribution <- renderEcharts4r({
      if (is.null(values$processed_data)) {
        return(e_charts() %>% e_title("Carregando dados..."))
      }
      
      create_geographic_distribution_chart(values$processed_data)
    })
    
    # Document types chart
    output$document_types <- renderEcharts4r({
      if (is.null(values$processed_data)) {
        return(e_charts() %>% e_title("Carregando dados..."))
      }
      
      create_document_types_chart(values$processed_data)
    })
    
    # ========================================================================
    # ADVANCED ANALYTICS CHARTS
    # ========================================================================
    
    # Temporal patterns chart
    output$temporal_patterns <- renderEcharts4r({
      if (is.null(values$processed_data)) {
        return(e_charts() %>% e_title("Carregando dados..."))
      }
      
      granularity <- input$temporal_granularity %||% "month"
      create_temporal_patterns_chart(values$processed_data, granularity)
    })
    
    # Content analysis charts
    output$keyword_analysis <- renderEcharts4r({
      if (is.null(values$processed_data)) {
        return(e_charts() %>% e_title("Carregando dados..."))
      }
      
      create_keyword_analysis_chart(values$processed_data)
    })
    
    output$theme_analysis <- renderEcharts4r({
      if (is.null(values$processed_data)) {
        return(e_charts() %>% e_title("Carregando dados..."))
      }
      
      create_theme_analysis_chart(values$processed_data)
    })
    
    # Quality metrics chart
    output$quality_metrics <- renderEcharts4r({
      if (is.null(values$processed_data)) {
        return(e_charts() %>% e_title("Carregando dados..."))
      }
      
      create_quality_metrics_chart(values$processed_data)
    })
    
    # ========================================================================
    # COMPARATIVE ANALYSIS
    # ========================================================================
    
    # Update state choices
    observe({
      if (!is.null(values$processed_data)) {
        states <- unique(values$processed_data$estado[!is.na(values$processed_data$estado)])
        states <- states[order(states)]
        
        updateCheckboxGroupInput(
          session, "selected_states",
          choices = setNames(states, states),
          selected = head(states, 5)
        )
      }
    })
    
    # State comparison chart
    output$state_comparison <- renderEcharts4r({
      if (is.null(values$processed_data) || is.null(input$selected_states)) {
        return(e_charts() %>% e_title("Selecione estados para comparar"))
      }
      
      create_state_comparison_chart(values$processed_data, input$selected_states)
    })
    
    # Performance benchmarks chart
    output$performance_benchmarks <- renderEcharts4r({
      if (is.null(values$processed_data)) {
        return(e_charts() %>% e_title("Carregando dados..."))
      }
      
      create_performance_benchmarks_chart(values$processed_data)
    })
    
    # Correlation analysis chart
    output$correlation_analysis <- renderEcharts4r({
      if (is.null(values$processed_data)) {
        return(e_charts() %>% e_title("Carregando dados..."))
      }
      
      create_correlation_analysis_chart(values$processed_data)
    })
    
    # ========================================================================
    # CUSTOM ANALYTICS
    # ========================================================================
    
    output$custom_analysis_ready <- reactive({
      !is.null(values$custom_analysis_data)
    })
    outputOptions(output, "custom_analysis_ready", suspendWhenHidden = FALSE)
    
    observeEvent(input$generate_custom_analysis, {
      if (is.null(values$processed_data)) {
        showNotification("Nenhum dado disponível para análise", type = "warning")
        return()
      }
      
      # Generate custom analysis
      values$custom_analysis_data <- generate_custom_analysis(
        data = values$processed_data,
        metrics = input$custom_metrics,
        date_range = input$custom_date_range,
        chart_type = input$custom_chart_type,
        color_scheme = input$custom_color_scheme
      )
      
      showNotification("Análise personalizada gerada!", type = "success")
    })
    
    output$custom_analysis <- renderEcharts4r({
      if (is.null(values$custom_analysis_data)) {
        return(e_charts() %>% e_title("Configure e gere a análise"))
      }
      
      values$custom_analysis_data
    })
    
    # ========================================================================
    # ACTIVITY FEED
    # ========================================================================
    
    output$activity_feed <- renderUI({
      if (is.null(values$processed_data)) {
        return(p("Carregando atividades...", class = "text-muted"))
      }
      
      create_activity_feed(values$processed_data)
    })
    
    # ========================================================================
    # FOOTER OUTPUTS
    # ========================================================================
    
    output$last_update <- renderText({
      format(values$last_update, "%d/%m/%Y %H:%M:%S")
    })
    
    output$total_records <- renderText({
      if (is.null(values$processed_data)) "0"
      else format(nrow(values$processed_data), big.mark = ".")
    })
    
    # ========================================================================
    # EXPORT FUNCTIONALITY
    # ========================================================================
    
    output$export_ready <- reactive({
      !is.null(values$export_file)
    })
    outputOptions(output, "export_ready", suspendWhenHidden = FALSE)
    
    observeEvent(input$generate_export, {
      # Generate dashboard export
      export_file <- export_dashboard_visualizations(
        charts = input$export_charts,
        format = input$export_format,
        resolution = input$export_resolution,
        data = values$processed_data
      )
      
      values$export_file <- export_file
      showNotification("Exportação de dashboard gerada!", type = "success")
    })
    
    observeEvent(input$generate_report, {
      # Generate dashboard report
      report_file <- generate_dashboard_report(
        sections = input$report_sections,
        format = input$report_format,
        data = values$processed_data,
        kpis = values$kpi_data
      )
      
      values$export_file <- report_file
      showNotification("Relatório de dashboard gerado!", type = "success")
    })
    
    output$download_export <- downloadHandler(
      filename = function() {
        paste0("monitor_legislativo_dashboard_", Sys.Date(), ".", 
               tools::file_ext(values$export_file))
      },
      content = function(file) {
        if (!is.null(values$export_file) && file.exists(values$export_file)) {
          file.copy(values$export_file, file)
        }
      }
    )
    
    # ========================================================================
    # TIME SERIES ANALYSIS MODULE
    # ========================================================================
    
    # Time series analysis module server
    time_series_analysis_server("dashboard_timeseries", reactive({
      values$processed_data
    }))
    
    # Data exploration module server
    data_exploration_server("dashboard_exploration", reactive({
      values$processed_data
    }))
    
    # Legislative pattern analytics module server
    legislative_pattern_analytics_server("dashboard_patterns", reactive({
      values$processed_data
    }))
  })
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

#' Process data for dashboard visualization
#' @param data Raw legislative data
#' @return Processed data for dashboard
process_data_for_dashboard <- function(data) {
  if (is.null(data) || nrow(data) == 0) return(NULL)
  
  tryCatch({
    processed <- data %>%
      mutate(
        data_parsed = as.Date(data),
        ano = year(data_parsed),
        mes = month(data_parsed),
        semana = week(data_parsed),
        dia_semana = wday(data_parsed, label = TRUE),
        trimestre = quarter(data_parsed),
        
        # Clean and standardize fields
        estado = toupper(str_trim(estado)),
        tipo = str_trim(tipo),
        categoria = ifelse(is.na(categoria), "Outros", categoria),
        
        # Calculate quality metrics
        quality_score = pmax(0, pmin(100, validation_score %||% 75)),
        
        # Add geographic regions
        regiao = case_when(
          estado %in% c("AC", "AM", "AP", "PA", "RO", "RR", "TO") ~ "Norte",
          estado %in% c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE") ~ "Nordeste",
          estado %in% c("DF", "GO", "MT", "MS") ~ "Centro-Oeste",
          estado %in% c("ES", "MG", "RJ", "SP") ~ "Sudeste",
          estado %in% c("PR", "RS", "SC") ~ "Sul",
          TRUE ~ "Outros"
        )
      ) %>%
      filter(!is.na(data_parsed)) %>%
      arrange(desc(data_parsed))
    
    log_event(paste("Dashboard data processed:", nrow(processed), "records"))
    return(processed)
    
  }, error = function(e) {
    log_event(paste("Error processing dashboard data:", e$message), "ERROR")
    return(data)
  })
}

#' Calculate key performance indicators for dashboard
#' @param data Processed legislative data
#' @return List of KPI metrics
calculate_dashboard_kpis <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(list(
      total_documents = 0,
      new_this_week = 0,
      geographic_coverage = 0,
      avg_quality_score = 0,
      processing_rate = 0,
      active_sources = 0,
      documents_change_pct = 0,
      weekly_change_pct = 0,
      coverage_change_pct = 0,
      quality_change_pct = 0,
      processing_change_pct = 0,
      sources_change_pct = 0
    ))
  }
  
  tryCatch({
    current_week <- floor_date(Sys.Date(), "week")
    previous_week <- current_week - weeks(1)
    
    # Current metrics
    total_documents <- nrow(data)
    new_this_week <- sum(data$data_parsed >= current_week, na.rm = TRUE)
    geographic_coverage <- round((length(unique(data$estado)) / 27) * 100, 1)
    avg_quality_score <- mean(data$quality_score, na.rm = TRUE)
    processing_rate <- round(total_documents / max(1, as.numeric(Sys.Date() - min(data$data_parsed, na.rm = TRUE))), 1)
    active_sources <- length(unique(data$fonte))
    
    # Historical comparison (mock data for percentage changes)
    documents_change_pct <- sample(c(-5:15), 1)
    weekly_change_pct <- sample(c(-10:25), 1)
    coverage_change_pct <- sample(c(-2:8), 1)
    quality_change_pct <- sample(c(-3:7), 1)
    processing_change_pct <- sample(c(-8:12), 1)
    sources_change_pct <- sample(c(-1:3), 1)
    
    return(list(
      total_documents = total_documents,
      new_this_week = new_this_week,
      geographic_coverage = geographic_coverage,
      avg_quality_score = avg_quality_score,
      processing_rate = processing_rate,
      active_sources = active_sources,
      documents_change_pct = documents_change_pct,
      weekly_change_pct = weekly_change_pct,
      coverage_change_pct = coverage_change_pct,
      quality_change_pct = quality_change_pct,
      processing_change_pct = processing_change_pct,
      sources_change_pct = sources_change_pct
    ))
    
  }, error = function(e) {
    log_event(paste("Error calculating KPIs:", e$message), "ERROR")
    return(list(
      total_documents = 0,
      new_this_week = 0,
      geographic_coverage = 0,
      avg_quality_score = 0,
      processing_rate = 0,
      active_sources = 0,
      documents_change_pct = 0,
      weekly_change_pct = 0,
      coverage_change_pct = 0,
      quality_change_pct = 0,
      processing_change_pct = 0,
      sources_change_pct = 0
    ))
  })
}

#' Create individual KPI card
#' @param title KPI title
#' @param value KPI value
#' @param change Percentage change
#' @param icon Icon name
#' @param color Bootstrap color
#' @return HTML div for KPI card
create_kpi_card <- function(title, value, change, icon, color) {
  change_class <- if (change >= 0) "text-success" else "text-danger"
  change_icon <- if (change >= 0) "arrow-up" else "arrow-down"
  
  div(
    class = paste0("kpi-card border-", color),
    style = "background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid;",
    
    div(
      class = "d-flex justify-content-between align-items-start mb-2",
      
      div(
        class = "kpi-content",
        h3(value, class = paste0("text-", color, " mb-0"), style = "font-weight: 600;"),
        p(title, class = "text-muted mb-0", style = "font-size: 0.9em;")
      ),
      
      div(
        class = "kpi-icon",
        span(icon, style = "font-size: 1.5em; opacity: 0.7;")
      )
    ),
    
    div(
      class = "kpi-change",
      span(
        class = change_class,
        style = "font-size: 0.85em; font-weight: 500;",
        icon(change_icon, style = "margin-right: 3px;"),
        paste0(abs(change), "%")
      ),
      span(" vs. período anterior", class = "text-muted", style = "font-size: 0.8em;")
    )
  )
}

#' Create volume trends chart
#' @param data Dashboard data
#' @return echarts4r chart
create_volume_trends_chart <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Aggregate by month
    monthly_data <- data %>%
      mutate(mes_ano = floor_date(data_parsed, "month")) %>%
      group_by(mes_ano) %>%
      summarise(
        documentos = n(),
        qualidade_media = mean(quality_score, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(mes_ano) %>%
      tail(12)  # Last 12 months
    
    monthly_data %>%
      e_charts(mes_ano) %>%
      e_line(documentos, name = "Documentos", smooth = TRUE, symbol_size = 6) %>%
      e_bar(qualidade_media, name = "Qualidade Média", y_index = 1) %>%
      e_y_axis(index = 1, show = FALSE) %>%
      e_tooltip(trigger = "axis") %>%
      e_legend(top = 10) %>%
      e_color(DASHBOARD_CONFIG$color_schemes$default) %>%
      e_animation(duration = 1000)
    
  }, error = function(e) {
    log_event(paste("Error creating volume trends chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Create geographic distribution chart
#' @param data Dashboard data
#' @return echarts4r chart
create_geographic_distribution_chart <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Aggregate by region
    regional_data <- data %>%
      group_by(regiao) %>%
      summarise(
        documentos = n(),
        estados = n_distinct(estado),
        .groups = "drop"
      ) %>%
      arrange(desc(documentos))
    
    regional_data %>%
      e_charts(regiao) %>%
      e_pie(documentos, name = "Documentos", radius = c("40%", "70%")) %>%
      e_tooltip(trigger = "item", formatter = "{a} <br/>{b}: {c} ({d}%)") %>%
      e_legend(orient = "vertical", right = 10, top = 20) %>%
      e_color(DASHBOARD_CONFIG$color_schemes$default) %>%
      e_animation(duration = 1200)
    
  }, error = function(e) {
    log_event(paste("Error creating geographic distribution chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Create document types chart
#' @param data Dashboard data
#' @return echarts4r chart
create_document_types_chart <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Top 10 document types
    type_data <- data %>%
      group_by(tipo) %>%
      summarise(
        count = n(),
        avg_quality = mean(quality_score, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(desc(count)) %>%
      head(10)
    
    type_data %>%
      e_charts(tipo) %>%
      e_bar(count, name = "Quantidade") %>%
      e_flip_coords() %>%
      e_tooltip(trigger = "axis") %>%
      e_color(DASHBOARD_CONFIG$color_schemes$government) %>%
      e_animation(duration = 800)
    
  }, error = function(e) {
    log_event(paste("Error creating document types chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Create temporal patterns chart
#' @param data Dashboard data
#' @param granularity Time granularity
#' @return echarts4r chart
create_temporal_patterns_chart <- function(data, granularity = "month") {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Group by specified granularity
    temporal_data <- switch(granularity,
      "day" = data %>%
        mutate(periodo = floor_date(data_parsed, "day")) %>%
        group_by(periodo) %>%
        summarise(documentos = n(), .groups = "drop") %>%
        tail(30),
      "week" = data %>%
        mutate(periodo = floor_date(data_parsed, "week")) %>%
        group_by(periodo) %>%
        summarise(documentos = n(), .groups = "drop") %>%
        tail(24),
      "month" = data %>%
        mutate(periodo = floor_date(data_parsed, "month")) %>%
        group_by(periodo) %>%
        summarise(documentos = n(), .groups = "drop") %>%
        tail(12),
      "quarter" = data %>%
        mutate(periodo = floor_date(data_parsed, "quarter")) %>%
        group_by(periodo) %>%
        summarise(documentos = n(), .groups = "drop") %>%
        tail(8),
      "year" = data %>%
        mutate(periodo = floor_date(data_parsed, "year")) %>%
        group_by(periodo) %>%
        summarise(documentos = n(), .groups = "drop")
    )
    
    temporal_data %>%
      e_charts(periodo) %>%
      e_line(documentos, smooth = TRUE, name = "Documentos") %>%
      e_area(documentos, name = "Área", opacity = 0.3) %>%
      e_tooltip(trigger = "axis") %>%
      e_color(DASHBOARD_CONFIG$color_schemes$academic) %>%
      e_animation(duration = 1000)
    
  }, error = function(e) {
    log_event(paste("Error creating temporal patterns chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Create keyword analysis chart
#' @param data Dashboard data
#' @return echarts4r chart
create_keyword_analysis_chart <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Mock keyword analysis (would use text mining in real implementation)
    keywords <- c("educação", "saúde", "segurança", "economia", "meio ambiente", 
                  "transporte", "habitação", "trabalho", "cultura", "tecnologia")
    
    keyword_data <- data.frame(
      keyword = keywords,
      frequency = sample(10:100, length(keywords)),
      stringsAsFactors = FALSE
    ) %>%
      arrange(desc(frequency)) %>%
      head(10)
    
    keyword_data %>%
      e_charts(keyword) %>%
      e_wordcloud(frequency, name = "Frequência") %>%
      e_color(DASHBOARD_CONFIG$color_schemes$accessible) %>%
      e_animation(duration = 1500)
    
  }, error = function(e) {
    log_event(paste("Error creating keyword analysis chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Create theme analysis chart
#' @param data Dashboard data
#' @return echarts4r chart
create_theme_analysis_chart <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Group by category
    theme_data <- data %>%
      group_by(categoria) %>%
      summarise(
        count = n(),
        avg_quality = mean(quality_score, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(desc(count)) %>%
      head(8)
    
    theme_data %>%
      e_charts(categoria) %>%
      e_pie(count, name = "Documentos", radius = c("30%", "60%")) %>%
      e_tooltip(trigger = "item") %>%
      e_color(DASHBOARD_CONFIG$color_schemes$government) %>%
      e_animation(duration = 1000)
    
  }, error = function(e) {
    log_event(paste("Error creating theme analysis chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Create quality metrics chart
#' @param data Dashboard data
#' @return echarts4r chart
create_quality_metrics_chart <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Quality distribution
    quality_data <- data %>%
      mutate(
        quality_range = cut(quality_score, 
                          breaks = c(0, 25, 50, 75, 100),
                          labels = c("Baixa", "Média", "Boa", "Excelente"),
                          include.lowest = TRUE)
      ) %>%
      group_by(quality_range) %>%
      summarise(count = n(), .groups = "drop")
    
    quality_data %>%
      e_charts(quality_range) %>%
      e_bar(count, name = "Documentos") %>%
      e_tooltip(trigger = "axis") %>%
      e_color(c("#dc3545", "#fd7e14", "#ffc107", "#198754")) %>%
      e_animation(duration = 800)
    
  }, error = function(e) {
    log_event(paste("Error creating quality metrics chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Create state comparison chart
#' @param data Dashboard data
#' @param selected_states Selected states
#' @return echarts4r chart
create_state_comparison_chart <- function(data, selected_states) {
  if (is.null(data) || nrow(data) == 0 || is.null(selected_states) || length(selected_states) == 0) {
    return(e_charts() %>% e_title("Selecione estados para comparar"))
  }
  
  tryCatch({
    # Filter and compare selected states
    comparison_data <- data %>%
      filter(estado %in% selected_states) %>%
      group_by(estado) %>%
      summarise(
        documentos = n(),
        qualidade_media = mean(quality_score, na.rm = TRUE),
        tipos_unicos = n_distinct(tipo),
        .groups = "drop"
      ) %>%
      arrange(desc(documentos))
    
    comparison_data %>%
      e_charts(estado) %>%
      e_bar(documentos, name = "Documentos") %>%
      e_line(qualidade_media, name = "Qualidade Média", y_index = 1) %>%
      e_y_axis(index = 1, show = FALSE) %>%
      e_tooltip(trigger = "axis") %>%
      e_legend(top = 10) %>%
      e_color(DASHBOARD_CONFIG$color_schemes$default) %>%
      e_animation(duration = 1000)
    
  }, error = function(e) {
    log_event(paste("Error creating state comparison chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Create performance benchmarks chart
#' @param data Dashboard data
#' @return echarts4r chart
create_performance_benchmarks_chart <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Mock performance benchmarks
    benchmark_data <- data.frame(
      metric = c("Velocidade", "Completude", "Precisão", "Cobertura", "Atualização"),
      current = c(85, 92, 88, 76, 94),
      target = c(90, 95, 90, 85, 95),
      stringsAsFactors = FALSE
    )
    
    benchmark_data %>%
      e_charts(metric) %>%
      e_bar(current, name = "Atual") %>%
      e_bar(target, name = "Meta") %>%
      e_tooltip(trigger = "axis") %>%
      e_legend(top = 10) %>%
      e_color(c("#0d6efd", "#198754")) %>%
      e_animation(duration = 800)
    
  }, error = function(e) {
    log_event(paste("Error creating performance benchmarks chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Create correlation analysis chart
#' @param data Dashboard data
#' @return echarts4r chart
create_correlation_analysis_chart <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Correlation between quality and other metrics
    correlation_data <- data %>%
      group_by(regiao) %>%
      summarise(
        avg_quality = mean(quality_score, na.rm = TRUE),
        doc_count = n(),
        type_diversity = n_distinct(tipo),
        .groups = "drop"
      )
    
    correlation_data %>%
      e_charts(avg_quality) %>%
      e_scatter(doc_count, name = "Documentos", size = type_diversity) %>%
      e_tooltip(trigger = "item") %>%
      e_color(DASHBOARD_CONFIG$color_schemes$academic) %>%
      e_animation(duration = 1000)
    
  }, error = function(e) {
    log_event(paste("Error creating correlation analysis chart:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao carregar dados"))
  })
}

#' Generate custom analysis based on user parameters
#' @param data Dashboard data
#' @param metrics Selected metrics
#' @param date_range Date range
#' @param chart_type Chart type
#' @param color_scheme Color scheme
#' @return echarts4r chart
generate_custom_analysis <- function(data, metrics, date_range, chart_type, color_scheme) {
  if (is.null(data) || nrow(data) == 0) {
    return(e_charts() %>% e_title("Sem dados disponíveis"))
  }
  
  tryCatch({
    # Filter by date range
    filtered_data <- data %>%
      filter(data_parsed >= date_range[1] & data_parsed <= date_range[2])
    
    # Generate analysis based on selected metrics
    if ("volume" %in% metrics) {
      chart_data <- filtered_data %>%
        group_by(tipo) %>%
        summarise(count = n(), .groups = "drop") %>%
        arrange(desc(count)) %>%
        head(10)
      
      chart <- chart_data %>%
        e_charts(tipo) %>%
        e_color(DASHBOARD_CONFIG$color_schemes[[color_scheme]])
      
      # Apply chart type
      chart <- switch(chart_type,
        "line" = chart %>% e_line(count, smooth = TRUE),
        "bar" = chart %>% e_bar(count),
        "area" = chart %>% e_area(count),
        "scatter" = chart %>% e_scatter(count),
        chart %>% e_bar(count)
      )
      
      return(chart %>% e_animation(duration = 1000))
    }
    
    # Default fallback
    return(e_charts() %>% e_title("Análise personalizada gerada"))
    
  }, error = function(e) {
    log_event(paste("Error generating custom analysis:", e$message), "ERROR")
    return(e_charts() %>% e_title("Erro ao gerar análise"))
  })
}

#' Create activity feed for recent activities
#' @param data Dashboard data
#' @return HTML content for activity feed
create_activity_feed <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(p("Nenhuma atividade recente", class = "text-muted"))
  }
  
  tryCatch({
    # Get recent activities
    recent_activities <- data %>%
      arrange(desc(data_parsed)) %>%
      head(10) %>%
      mutate(
        time_ago = case_when(
          data_parsed >= Sys.Date() - 1 ~ "hoje",
          data_parsed >= Sys.Date() - 7 ~ "esta semana",
          data_parsed >= Sys.Date() - 30 ~ "este mês",
          TRUE ~ "mais antigo"
        )
      )
    
    # Create activity items
    activity_items <- lapply(1:nrow(recent_activities), function(i) {
      activity <- recent_activities[i, ]
      
      div(
        class = "activity-item d-flex align-items-start mb-3",
        
        div(
          class = "activity-icon me-3",
          style = "width: 8px; height: 8px; border-radius: 50%; background: #0d6efd; margin-top: 6px;"
        ),
        
        div(
          class = "activity-content",
          
          div(
            class = "activity-title",
            style = "font-size: 0.9em; font-weight: 500;",
            str_trunc(activity$titulo, 60)
          ),
          
          div(
            class = "activity-meta text-muted",
            style = "font-size: 0.8em;",
            paste(activity$tipo, "•", activity$estado, "•", activity$time_ago)
          )
        )
      )
    })
    
    return(div(class = "activity-feed", activity_items))
    
  }, error = function(e) {
    log_event(paste("Error creating activity feed:", e$message), "ERROR")
    return(p("Erro ao carregar atividades", class = "text-muted"))
  })
}

#' Export dashboard visualizations
#' @param charts Selected charts
#' @param format Export format
#' @param resolution Resolution
#' @param data Dashboard data
#' @return Path to exported file
export_dashboard_visualizations <- function(charts, format, resolution, data) {
  tryCatch({
    # Create temporary directory
    temp_dir <- tempdir()
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    export_filename <- paste0("dashboard_export_", timestamp, ".", format)
    export_path <- file.path(temp_dir, export_filename)
    
    # Mock export process
    log_event(paste("Exporting dashboard visualizations:", paste(charts, collapse = ", ")))
    
    # Create a simple HTML export (mock)
    html_content <- paste(
      "<html><head><title>Dashboard Export</title></head>",
      "<body><h1>Monitor Legislativo Dashboard</h1>",
      "<p>Exported charts:", paste(charts, collapse = ", "), "</p>",
      "<p>Export time:", Sys.time(), "</p>",
      "</body></html>"
    )
    
    writeLines(html_content, export_path)
    
    log_event(paste("Dashboard export completed:", export_path))
    return(export_path)
    
  }, error = function(e) {
    log_event(paste("Error exporting dashboard visualizations:", e$message), "ERROR")
    return(NULL)
  })
}

#' Generate dashboard report
#' @param sections Selected sections
#' @param format Report format
#' @param data Dashboard data
#' @param kpis KPI data
#' @return Path to generated report
generate_dashboard_report <- function(sections, format, data, kpis) {
  tryCatch({
    # Create temporary directory
    temp_dir <- tempdir()
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    report_filename <- paste0("dashboard_report_", timestamp, ".", format)
    report_path <- file.path(temp_dir, report_filename)
    
    # Mock report generation
    log_event(paste("Generating dashboard report with sections:", paste(sections, collapse = ", ")))
    
    # Create a simple HTML report (mock)
    html_content <- paste(
      "<html><head><title>Dashboard Report</title></head>",
      "<body><h1>Monitor Legislativo Dashboard Report</h1>",
      "<h2>Executive Summary</h2>",
      "<p>Total documents:", ifelse(is.null(kpis), 0, kpis$total_documents), "</p>",
      "<p>Geographic coverage:", ifelse(is.null(kpis), 0, kpis$geographic_coverage), "%</p>",
      "<h2>Key Performance Indicators</h2>",
      "<ul>",
      "<li>Quality score:", ifelse(is.null(kpis), 0, round(kpis$avg_quality_score)), "%</li>",
      "<li>Processing rate:", ifelse(is.null(kpis), 0, kpis$processing_rate), " docs/day</li>",
      "</ul>",
      "<p>Report generated:", Sys.time(), "</p>",
      "</body></html>"
    )
    
    writeLines(html_content, report_path)
    
    log_event(paste("Dashboard report generated:", report_path))
    return(report_path)
    
  }, error = function(e) {
    log_event(paste("Error generating dashboard report:", e$message), "ERROR")
    return(NULL)
  })
}