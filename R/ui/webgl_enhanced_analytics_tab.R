# ==============================================================================
# WEBGL-ENHANCED ANALYTICS TAB UI - MONITOR LEGISLATIVO V4
# ==============================================================================
# 
# High-performance analytics dashboard with WebGL acceleration
# Supports 300k+ data points at 60fps with real-time performance monitoring
# Automatic renderer selection and quality adaptation
# 
# Features:
# - WebGL-accelerated plotly visualizations for large datasets
# - Real-time performance monitoring and adaptive quality
# - Browser capability detection and automatic fallbacks
# - Accessibility compliance maintained with screen reader support
# - Portuguese localization with WCAG 2.1 AA compliance
# ==============================================================================

cat("🚀 Loading WebGL-Enhanced Analytics Tab UI\n")

# Load WebGL framework
source("R/visualization/webgl_framework.R", local = TRUE)
source("R/visualization/brazilian_geo_integration.R", local = TRUE)

# Enhanced Analytics Tab with WebGL Integration
tagList(
  # Performance monitoring header
  fluidRow(
    column(12,
      div(
        class = "webgl-performance-header",
        style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;",
        fluidRow(
          column(8,
            h2("📈 Analytics Avançados WebGL", style = "margin: 0; color: white;"),
            p("Análise de alto desempenho com aceleração WebGL para grandes volumes de dados", 
              style = "color: rgba(255,255,255,0.9); margin: 5px 0 0 0; font-size: 14px;")
          ),
          column(4,
            div(
              id = "webgl_performance_indicator",
              style = "text-align: right; padding-top: 5px;",
              div(
                id = "performance_status",
                class = "performance-badge",
                style = "display: inline-block; background: rgba(255,255,255,0.2); padding: 8px 12px; border-radius: 20px; font-size: 12px;",
                span(id = "performance_text", "Inicializando..."),
                span(id = "performance_icon", style = "margin-left: 5px;", icon("spinner", class = "fa-spin"))
              )
            )
          )
        )
      )
    )
  ),
  
  # Enhanced Analytics Control Panel
  fluidRow(
    column(4,
      wellPanel(
        style = "border-left: 4px solid #667eea;",
        h4("⚙️ Configurações de Análise", style = "color: #2c3e50; margin-top: 0;"),
        
        # Analysis type with WebGL indicators
        div(
          selectInput(
            inputId = "analytics_type",
            label = "Tipo de Análise:",
            choices = list(
              "📊 Tendências Temporais (WebGL)" = "temporal",
              "💭 Análise de Sentimento" = "sentiment", 
              "🏷️ Temas Emergentes" = "topics",
              "🕸️ Análise de Rede (WebGL)" = "network",
              "🗺️ Comparação Regional (WebGL)" = "regional"
            ),
            selected = "temporal"
          ),
          div(
            id = "webgl_indicator",
            style = "margin-top: -10px; margin-bottom: 15px; font-size: 11px; color: #27ae60;",
            span(id = "webgl_status_text", icon("rocket"), " WebGL Ativo")
          )
        ),
        
        # Date range with performance estimation
        div(
          dateRangeInput(
            inputId = "analytics_date_range",
            label = "Período de Análise:",
            start = Sys.Date() - 365,
            end = Sys.Date(),
            format = "dd/mm/yyyy",
            language = "pt-BR"
          ),
          div(
            id = "data_size_estimate",
            style = "margin-top: -10px; margin-bottom: 15px; font-size: 11px; color: #7f8c8d;",
            span("Estimativa: ", span(id = "estimated_points", "~50.000"), " pontos de dados")
          )
        ),
        
        # Granularity with performance impact
        selectInput(
          inputId = "analytics_granularity",
          label = "Granularidade:",
          choices = list(
            "📅 Diária (Alta Resolução)" = "daily",
            "📆 Semanal (Balanceado)" = "weekly", 
            "🗓️ Mensal (Otimizado)" = "monthly",
            "📊 Trimestral (Rápido)" = "quarterly",
            "📈 Anual (Ultra-Rápido)" = "yearly"
          ),
          selected = "monthly"
        ),
        
        # Enhanced filters with geographic integration
        checkboxGroupInput(
          inputId = "analytics_filters",
          label = "Filtros Geográficos:",
          choices = list(
            "🏛️ Federal" = "federal",
            "🏢 Estadual" = "state", 
            "🏘️ Municipal" = "municipal",
            "🗺️ Regional (IBGE)" = "regional"
          ),
          selected = c("federal", "state")
        ),
        
        # Performance optimization controls
        div(
          style = "border-top: 1px solid #ecf0f1; padding-top: 15px; margin-top: 15px;",
          h5("🎯 Otimização de Performance", style = "color: #2c3e50; margin-bottom: 10px;"),
          
          sliderInput(
            inputId = "performance_quality",
            label = "Qualidade vs Velocidade:",
            min = 1,
            max = 3,
            value = 2,
            step = 1,
            ticks = FALSE,
            post = c("1" = "🚀 Velocidade", "2" = "⚖️ Balanceado", "3" = "🎨 Qualidade")
          ),
          
          checkboxInput(
            inputId = "auto_adapt_quality",
            label = "Adaptação Automática de Qualidade",
            value = TRUE
          ),
          
          checkboxInput(
            inputId = "enable_webgl_fallback",
            label = "Fallback Automático SVG",
            value = TRUE
          )
        ),
        
        # Execute button with loading state
        div(
          style = "margin-top: 20px;",
          actionButton(
            inputId = "analytics_run",
            label = "🚀 Executar Análise WebGL",
            icon = icon("play"),
            class = "btn-primary btn-block btn-lg",
            style = "border-radius: 25px; font-weight: bold;"
          ),
          
          div(
            id = "analysis_progress",
            style = "margin-top: 10px; display: none;",
            div(
              class = "progress progress-striped active",
              div(
                id = "progress_bar",
                class = "progress-bar progress-bar-info",
                style = "width: 0%",
                span(id = "progress_text", "Preparando dados...")
              )
            )
          )
        )
      )
    ),
    
    column(8,
      # Performance monitoring dashboard
      div(
        id = "performance_dashboard",
        style = "margin-bottom: 20px;",
        fluidRow(
          column(3,
            div(
              class = "performance-metric-card",
              style = "background: #f8f9ff; border-left: 4px solid #667eea; padding: 15px; border-radius: 5px;",
              h6("Tempo de Renderização", style = "margin: 0; color: #666; font-size: 11px; text-transform: uppercase;"),
              h3(id = "render_time_display", "0ms", style = "margin: 5px 0; color: #2c3e50;"),
              small(id = "render_time_target", "Meta: <2000ms", style = "color: #27ae60;")
            )
          ),
          column(3,
            div(
              class = "performance-metric-card", 
              style = "background: #f0fff4; border-left: 4px solid #27ae60; padding: 15px; border-radius: 5px;",
              h6("Taxa de Quadros", style = "margin: 0; color: #666; font-size: 11px; text-transform: uppercase;"),
              h3(id = "fps_display", "60fps", style = "margin: 5px 0; color: #2c3e50;"),
              small(id = "fps_target", "Meta: 60fps", style = "color: #27ae60;")
            )
          ),
          column(3,
            div(
              class = "performance-metric-card",
              style = "background: #fffbf0; border-left: 4px solid #f39c12; padding: 15px; border-radius: 5px;",
              h6("Pontos de Dados", style = "margin: 0; color: #666; font-size: 11px; text-transform: uppercase;"),
              h3(id = "data_points_display", "0", style = "margin: 5px 0; color: #2c3e50;"),
              small(id = "data_points_target", "Suporte: 300k+", style = "color: #f39c12;")
            )
          ),
          column(3,
            div(
              class = "performance-metric-card",
              style = "background: #fff0f5; border-left: 4px solid #e74c3c; padding: 15px; border-radius: 5px;",
              h6("Score de Performance", style = "margin: 0; color: #666; font-size: 11px; text-transform: uppercase;"),
              h3(id = "performance_score_display", "100", style = "margin: 5px 0; color: #2c3e50;"),
              small(id = "performance_score_desc", "Excelente", style = "color: #27ae60;")
            )
          )
        )
      ),
      
      # Main Visualization Area with Enhanced WebGL Charts
      tabsetPanel(
        type = "pills",
        id = "analytics_visualization_tabs",
        
        # Temporal Analysis with WebGL
        tabPanel(
          title = span(icon("chart-line"), "Análise Temporal"),
          value = "temporal_tab",
          br(),
          conditionalPanel(
            condition = "input.analytics_type == 'temporal'",
            div(
              class = "webgl-visualization-container",
              style = "background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
              div(
                class = "visualization-header",
                style = "display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;",
                h4("📈 Tendências Temporais WebGL", style = "margin: 0; color: #2c3e50;"),
                div(
                  class = "visualization-controls",
                  actionButton("temporal_fullscreen", "", icon = icon("expand"), class = "btn-sm btn-outline-secondary", title = "Tela Cheia"),
                  actionButton("temporal_download", "", icon = icon("download"), class = "btn-sm btn-outline-primary", title = "Baixar", style = "margin-left: 5px;"),
                  actionButton("temporal_settings", "", icon = icon("cog"), class = "btn-sm btn-outline-info", title = "Configurações", style = "margin-left: 5px;")
                )
              ),
              
              # WebGL chart with loading overlay
              div(
                style = "position: relative;",
                plotlyOutput("analytics_temporal_chart_webgl", height = "500px"),
                div(
                  id = "temporal_loading_overlay",
                  class = "loading-overlay",
                  style = "display: none; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,255,255,0.9); z-index: 1000; border-radius: 8px;",
                  div(
                    class = "loading-content",
                    style = "position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;",
                    div(
                      style = "display: inline-block; border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite;"
                    ),
                    p("Processando dados com WebGL...", style = "margin-top: 15px; color: #666; font-weight: bold;")
                  )
                )
              ),
              
              # Chart information and controls
              div(
                style = "margin-top: 15px; padding-top: 15px; border-top: 1px solid #ecf0f1;",
                fluidRow(
                  column(6,
                    div(
                      class = "chart-info",
                      h6("📊 Informações do Gráfico", style = "color: #666; margin-bottom: 8px;"),
                      div(id = "temporal_chart_info", style = "font-size: 13px; color: #666;",
                        p("Renderer: WebGL | Pontos: 0 | Tempo: 0ms", style = "margin: 2px 0;"),
                        p("Qualidade: Alta | FPS: 60", style = "margin: 2px 0;")
                      )
                    )
                  ),
                  column(6,
                    div(
                      class = "chart-controls",
                      style = "text-align: right;",
                      h6("🎛️ Controles Avançados", style = "color: #666; margin-bottom: 8px;"),
                      div(
                        class = "btn-group btn-group-sm",
                        actionButton("temporal_zoom_reset", "Reset Zoom", class = "btn-outline-secondary"),
                        actionButton("temporal_animation_toggle", "Animação", class = "btn-outline-info"),
                        actionButton("temporal_webgl_toggle", "WebGL", class = "btn-outline-success")
                      )
                    )
                  )
                )
              )
            )
          )
        ),
        
        # Regional Analysis with Geographic WebGL
        tabPanel(
          title = span(icon("map"), "Análise Regional"),
          value = "regional_tab",
          br(),
          conditionalPanel(
            condition = "input.analytics_type == 'regional'",
            div(
              class = "webgl-visualization-container",
              style = "background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
              div(
                class = "visualization-header",
                style = "display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;",
                h4("🗺️ Comparação Regional WebGL", style = "margin: 0; color: #2c3e50;"),
                div(
                  class = "geographic-controls",
                  selectInput("regional_map_type", NULL, 
                            choices = list("Coroplético" = "choropleth", "Pontos" = "scatter", "Densidade" = "heatmap"),
                            selected = "choropleth", width = "120px")
                )
              ),
              
              # WebGL geographic visualization
              div(
                style = "position: relative;",
                leafletOutput("analytics_regional_map_webgl", height = "500px"),
                div(
                  id = "regional_loading_overlay", 
                  class = "loading-overlay",
                  style = "display: none; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,255,255,0.9); z-index: 1000; border-radius: 8px;",
                  div(
                    class = "loading-content",
                    style = "position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;",
                    div(
                      style = "display: inline-block; border: 3px solid #f3f3f3; border-top: 3px solid #27ae60; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite;"
                    ),
                    p("Carregando dados geográficos...", style = "margin-top: 15px; color: #666; font-weight: bold;")
                  )
                )
              ),
              
              # Geographic statistics
              div(
                style = "margin-top: 15px;",
                fluidRow(
                  column(4,
                    div(
                      class = "geo-stats-card",
                      style = "background: #f8f9ff; border-radius: 5px; padding: 15px; text-align: center;",
                      h5("📍 Estados Cobertos", style = "margin: 0 0 8px 0; color: #2c3e50;"),
                      h3(id = "covered_states_count", "0/27", style = "margin: 0; color: #667eea;"),
                      small("Estados com dados", style = "color: #666;")
                    )
                  ),
                  column(4,
                    div(
                      class = "geo-stats-card",
                      style = "background: #f0fff4; border-radius: 5px; padding: 15px; text-align: center;",
                      h5("🏘️ Municípios", style = "margin: 0 0 8px 0; color: #2c3e50;"),
                      h3(id = "covered_municipalities_count", "0", style = "margin: 0; color: #27ae60;"),
                      small("Municípios identificados", style = "color: #666;")
                    )
                  ),
                  column(4,
                    div(
                      class = "geo-stats-card",
                      style = "background: #fffbf0; border-radius: 5px; padding: 15px; text-align: center;",
                      h5("🎯 Precisão", style = "margin: 0 0 8px 0; color: #2c3e50;"),
                      h3(id = "geocoding_accuracy", "0%", style = "margin: 0; color: #f39c12;"),
                      small("Confiança geográfica", style = "color: #666;")
                    )
                  )
                )
              )
            )
          )
        ),
        
        # Network Analysis with WebGL
        tabPanel(
          title = span(icon("project-diagram"), "Análise de Rede"),
          value = "network_tab", 
          br(),
          conditionalPanel(
            condition = "input.analytics_type == 'network'",
            div(
              class = "webgl-visualization-container",
              style = "background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
              h4("🕸️ Análise de Rede de Documentos WebGL", style = "margin: 0 0 15px 0; color: #2c3e50;"),
              
              # 3D Network visualization with WebGL
              div(
                style = "position: relative;",
                plotlyOutput("analytics_network_chart_webgl", height = "600px"),
                div(
                  id = "network_controls",
                  class = "network-controls",
                  style = "position: absolute; top: 10px; right: 10px; background: rgba(255,255,255,0.9); padding: 10px; border-radius: 5px;",
                  div(
                    class = "btn-group-vertical btn-group-sm",
                    actionButton("network_3d_toggle", "3D", class = "btn-outline-primary"),
                    actionButton("network_cluster_toggle", "Clusters", class = "btn-outline-info"),
                    actionButton("network_labels_toggle", "Labels", class = "btn-outline-secondary")
                  )
                )
              ),
              
              # Network statistics
              div(
                style = "margin-top: 15px;",
                uiOutput("network_statistics")
              )
            )
          )
        ),
        
        # Sentiment Analysis
        tabPanel(
          title = span(icon("heart"), "Sentimento"),
          value = "sentiment_tab",
          br(),
          conditionalPanel(
            condition = "input.analytics_type == 'sentiment'",
            div(
              class = "webgl-visualization-container",
              style = "background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
              h4("💭 Análise de Sentimento Regulatório", style = "margin: 0 0 15px 0; color: #2c3e50;"),
              plotlyOutput("analytics_sentiment_chart", height = "400px")
            )
          )
        ),
        
        # Topic Modeling
        tabPanel(
          title = span(icon("tags"), "Tópicos"),
          value = "topics_tab",
          br(),
          conditionalPanel(
            condition = "input.analytics_type == 'topics'",
            div(
              class = "webgl-visualization-container",
              style = "background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
              h4("🏷️ Modelagem de Tópicos", style = "margin: 0 0 15px 0; color: #2c3e50;"),
              plotlyOutput("analytics_topics_chart", height = "400px")
            )
          )
        )
      )
    )
  ),
  
  # Enhanced Results and Export Section
  fluidRow(
    column(6,
      div(
        class = "results-panel",
        style = "background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
        h4("🔍 Insights da Análise", style = "color: #2c3e50; margin-bottom: 15px;"),
        div(
          id = "analytics_insights_webgl",
          style = "min-height: 200px;",
          uiOutput("analytics_insights"),
          div(
            id = "insights_loading",
            style = "display: none; text-align: center; padding: 50px;",
            icon("spinner", class = "fa-spin fa-2x", style = "color: #667eea;"),
            p("Gerando insights automatizados...", style = "margin-top: 15px; color: #666;")
          )
        )
      )
    ),
    
    column(6,
      div(
        class = "export-panel",
        style = "background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
        h4("💾 Exportação e Performance", style = "color: #2c3e50; margin-bottom: 15px;"),
        
        # Export options
        fluidRow(
          column(6,
            div(
              h5("Exportar Visualizações", style = "color: #666; margin-bottom: 10px;"),
              downloadButton("analytics_download_chart", "📊 Gráfico WebGL", 
                           icon = icon("chart-line"), class = "btn-info btn-sm btn-block", 
                           style = "margin-bottom: 8px;"),
              downloadButton("analytics_download_data", "📋 Dados CSV",
                           icon = icon("database"), class = "btn-success btn-sm btn-block",
                           style = "margin-bottom: 8px;"),
              downloadButton("analytics_download_report", "📄 Relatório PDF",
                           icon = icon("file-pdf"), class = "btn-primary btn-sm btn-block")
            )
          ),
          column(6,
            div(
              h5("Performance Report", style = "color: #666; margin-bottom: 10px;"),
              div(
                id = "performance_summary",
                style = "background: #f8f9fa; padding: 12px; border-radius: 5px; font-size: 12px;",
                p(id = "perf_summary_renderer", "Renderer: WebGL", style = "margin: 2px 0;"),
                p(id = "perf_summary_time", "Tempo Médio: 0ms", style = "margin: 2px 0;"),
                p(id = "perf_summary_quality", "Qualidade: Alta", style = "margin: 2px 0;"),
                p(id = "perf_summary_fallbacks", "Fallbacks: 0", style = "margin: 2px 0;")
              ),
              actionButton("run_performance_benchmark", "🏃 Benchmark", 
                         class = "btn-warning btn-sm btn-block", style = "margin-top: 8px;")
            )
          )
        )
      )
    )
  ),
  
  # Detailed Results Table with Enhanced Features
  fluidRow(
    column(12,
      div(
        class = "results-table-panel",
        style = "background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-top: 20px;",
        h4("📋 Resultados Detalhados", style = "color: #2c3e50; margin-bottom: 15px;"),
        
        # Table controls
        div(
          style = "margin-bottom: 15px;",
          fluidRow(
            column(6,
              div(
                class = "table-controls-left",
                checkboxInput("show_geographic_columns", "Colunas Geográficas", value = TRUE),
                checkboxInput("show_performance_columns", "Métricas de Performance", value = FALSE)
              )
            ),
            column(6,
              div(
                class = "table-controls-right",
                style = "text-align: right;",
                selectInput("table_page_size", "Linhas:", 
                          choices = list("25" = 25, "50" = 50, "100" = 100, "500" = 500),
                          selected = 50, width = "100px")
              )
            )
          )
        ),
        
        # Enhanced DataTable with performance indicators
        div(
          style = "position: relative;",
          DT::dataTableOutput("analytics_detailed_results_webgl"),
          div(
            id = "table_loading_overlay",
            class = "loading-overlay", 
            style = "display: none; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,255,255,0.9); z-index: 1000;",
            div(
              class = "loading-content",
              style = "position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;",
              icon("spinner", class = "fa-spin fa-2x", style = "color: #667eea;"),
              p("Carregando dados...", style = "margin-top: 15px; color: #666; font-weight: bold;")
            )
          )
        )
      )
    )
  ),
  
  # JavaScript for WebGL integration and performance monitoring
  tags$script(HTML("
    // WebGL Performance Monitoring
    const WebGLPerformance = {
      startTime: null,
      frameCount: 0,
      lastFpsTime: Date.now(),
      
      startMeasurement() {
        this.startTime = performance.now();
      },
      
      endMeasurement() {
        const endTime = performance.now();
        const renderTime = Math.round(endTime - this.startTime);
        this.updatePerformanceUI(renderTime);
        return renderTime;
      },
      
      updatePerformanceUI(renderTime) {
        document.getElementById('render_time_display').textContent = renderTime + 'ms';
        
        // Update performance status
        const status = document.getElementById('performance_status');
        const statusText = document.getElementById('performance_text');
        const statusIcon = document.getElementById('performance_icon');
        
        if (renderTime < 2000) {
          status.style.background = 'rgba(39, 174, 96, 0.2)';
          statusText.textContent = 'Excelente';
          statusIcon.innerHTML = '<i class=\"fa fa-check\"></i>';
        } else if (renderTime < 5000) {
          status.style.background = 'rgba(243, 156, 18, 0.2)';
          statusText.textContent = 'Bom';
          statusIcon.innerHTML = '<i class=\"fa fa-clock\"></i>';
        } else {
          status.style.background = 'rgba(231, 76, 60, 0.2)';
          statusText.textContent = 'Lento';
          statusIcon.innerHTML = '<i class=\"fa fa-exclamation-triangle\"></i>';
        }
      },
      
      updateDataPoints(count) {
        document.getElementById('data_points_display').textContent = count.toLocaleString('pt-BR');
      },
      
      updatePerformanceScore(score) {
        document.getElementById('performance_score_display').textContent = score;
        const desc = document.getElementById('performance_score_desc');
        
        if (score >= 80) {
          desc.textContent = 'Excelente';
          desc.style.color = '#27ae60';
        } else if (score >= 60) {
          desc.textContent = 'Bom';
          desc.style.color = '#f39c12';
        } else {
          desc.textContent = 'Precisa Melhorar';
          desc.style.color = '#e74c3c';
        }
      }
    };
    
    // CSS Animation for loading spinners
    const style = document.createElement('style');
    style.textContent = `
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      .loading-overlay {
        backdrop-filter: blur(2px);
      }
      .performance-metric-card {
        transition: transform 0.2s ease, box-shadow 0.2s ease;
      }
      .performance-metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 15px rgba(0,0,0,0.15);
      }
      .webgl-visualization-container {
        transition: box-shadow 0.3s ease;
      }
      .webgl-visualization-container:hover {
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
      }
    `;
    document.head.appendChild(style);
    
    // Initialize performance monitoring
    $(document).ready(function() {
      console.log('WebGL Analytics Tab initialized');
      WebGLPerformance.updatePerformanceScore(100);
    });
  ")),
  
  # CSS for enhanced styling
  tags$style(HTML("
    .webgl-performance-header {
      position: relative;
      overflow: hidden;
    }
    .webgl-performance-header::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: url('data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1000 100\"><polygon fill=\"rgba(255,255,255,0.1)\" points=\"0,0 1000,0 1000,60 0,100\"/></svg>');
      pointer-events: none;
    }
    .performance-badge {
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255,255,255,0.2);
    }
    .btn-group .btn {
      margin: 0 2px;
    }
    .nav-pills .nav-link {
      border-radius: 20px;
      margin: 0 5px;
    }
    .nav-pills .nav-link.active {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
  "))
)