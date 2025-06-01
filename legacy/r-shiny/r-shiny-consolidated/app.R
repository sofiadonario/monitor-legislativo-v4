# Monitor Legislativo v4 - R Architecture Consolidation
# Modern R Shiny Application with bslib, echarts4r, and leaflet
# Academic Research Platform for Brazilian Legislative Data

# Load libraries
library(shiny)
library(bslib)
library(echarts4r)
library(leaflet)
library(tmap)
library(DT)
library(dplyr)
library(config)
library(httr)
library(jsonlite)
library(sf)
library(promises)
library(future)

# Set up future for async operations
plan(multisession)

# Load configuration
config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
app_config <- config::get(config = config_env)

# Source modules
source("R/database.R")
source("R/api_client.R")
source("R/geographic.R")
source("R/visualization.R")
source("R/utils.R")

# Source Week 2 enhanced modules
source("R/ui_components.R")
source("R/geobr_integration.R")
source("R/data_processing.R")
source("R/performance.R")

# Source Week 3 LexML and search engine modules
source("R/lexml_integration.R")
source("R/vocabulary_processing.R")
source("R/search_engine.R")
source("R/document_pipeline.R")

# Source Week 4 geographic analysis and mapping modules
source("R/spatial_analysis.R")
source("R/interactive_mapping.R")
source("R/map_search.R")

# Source Week 5 document analysis and academic tools modules
source("R/document_viewer.R")
source("R/document_comparison.R")
source("R/citation_generator.R")
source("R/export_system.R")

# Source Week 6 advanced dashboard and analytics modules
source("R/advanced_dashboard.R")
source("R/time_series_analysis.R")
source("R/data_exploration.R")
source("R/legislative_pattern_analytics.R")

# Source Week 7 authentication and user management modules
source("R/auth_system.R")
source("R/user_management.R")
source("R/security_system.R")

# Source Week 8 performance optimization and monitoring modules
source("R/redis_cache.R")
source("R/performance_optimization.R")
source("R/application_monitoring.R")
source("R/analytics_reporting.R")

# Source Week 9 API integration and external services modules
source("R/restRserve_api.R")
source("R/external_integrations.R")
source("R/batch_operations.R")
source("R/data_pipeline.R")

# Source Week 10 AI integration and advanced analytics modules
source("R/ai_integration.R")
source("R/knowledge_graph.R")
source("R/semantic_search.R")
source("R/recommendation_engine.R")

# Source Week 11 production deployment and monitoring modules
source("R/prometheus_exporter.R")

# Initialize application
cat("🚀 Starting Monitor Legislativo v4 - R Architecture\n")

# Initialize Week 8 performance and monitoring systems
redis_init_result <- initialize_redis_cache(warm_on_startup = TRUE)
perf_init_result <- initialize_performance_optimization()
monitoring_init_result <- initialize_monitoring()
analytics_init_result <- initialize_analytics()

cat("📊 Performance systems initialized:\n")
cat(paste("  Redis Cache:", if(redis_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  Performance Optimization:", if(perf_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  Application Monitoring:", if(monitoring_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  Analytics & Reporting:", if(analytics_init_result$status == "success") "✅" else "❌", "\n"))

# Initialize Week 9 API and integration systems
api_init_result <- initialize_api_system(start_server = FALSE)  # Don't auto-start server
external_init_result <- initialize_external_integrations()
batch_init_result <- initialize_batch_operations()
pipeline_init_result <- initialize_data_pipeline()

cat("🔗 API & Integration systems initialized:\n")
cat(paste("  RestRserve API:", if(api_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  External Integrations:", if(external_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  Batch Operations:", if(batch_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  Data Pipeline:", if(pipeline_init_result$status == "success") "✅" else "❌", "\n"))

# Initialize Week 10 AI and advanced analytics systems
ai_init_result <- initialize_ai_integration()
kg_init_result <- initialize_knowledge_graph()
semantic_init_result <- initialize_semantic_search()
recommendation_init_result <- initialize_recommendation_engine()

cat("🤖 AI & Advanced Analytics systems initialized:\n")
cat(paste("  AI Integration:", if(ai_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  Knowledge Graph:", if(kg_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  Semantic Search:", if(semantic_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  Recommendation Engine:", if(recommendation_init_result$status == "success") "✅" else "❌", "\n"))

# Initialize Week 11 production deployment and monitoring systems
prometheus_init_result <- initialize_prometheus_exporter()
if (Sys.getenv("R_CONFIG_ACTIVE", "default") == "production") {
  start_metrics_server()
}

cat("🚀 Production & Monitoring systems initialized:\n")
cat(paste("  Prometheus Exporter:", if(prometheus_init_result$status == "success") "✅" else "❌", "\n"))
cat(paste("  Metrics Server:", if(Sys.getenv("R_CONFIG_ACTIVE") == "production") "✅ (Started)" else "🔄 (Development Mode)", "\n"))

# Initialize enhanced geographic data and performance monitoring  
geographic_data <- load_enhanced_ibge_data(year = 2020, level = "state", simplified = TRUE)
warm_cache()  # Pre-warm cache for better performance

# Initialize spatial analysis system
if (!is.null(geographic_data)) {
  log_event(paste("Enhanced IBGE data loaded:", nrow(geographic_data), "states with spatial analysis"))
} else {
  log_event("Using fallback geographic data", "WARN")
  geographic_data <- create_fallback_spatial_data("state")
}

# ============================================================================
# USER INTERFACE
# ============================================================================

ui <- page_navbar(
  title = app_config$app$title,
  id = "main_nav",
  theme = bs_theme(
    version = 5,
    bootswatch = "flatly",
    primary = app_config$ui$primary_color,
    secondary = app_config$ui$secondary_color,
    success = app_config$ui$success_color,
    warning = app_config$ui$warning_color,
    danger = app_config$ui$danger_color,
    info = app_config$ui$info_color,
    base_font = font_google("Inter"),
    heading_font = font_google("Inter", wght = "600")
  ),
  
  # Custom CSS for modern glassmorphism design and security JavaScript
  tags$head(
    tags$style(HTML("
      .navbar-brand {
        font-weight: 600;
        font-size: 1.25rem;
      }
      
      .card {
        background: rgba(255, 255, 255, 0.9);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        border-radius: 12px;
      }
      
      .value-box {
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0));
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.18);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        transition: transform 0.3s ease;
      }
      
      .value-box:hover {
        transform: translateY(-2px);
      }
      
      .search-panel {
        background: rgba(248, 249, 250, 0.8);
        backdrop-filter: blur(10px);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 2rem;
      }
      
      .leaflet-container {
        border-radius: 12px;
      }
      
      .nav-tabs .nav-link.active {
        background: rgba(255, 255, 255, 0.9);
        backdrop-filter: blur(10px);
      }
      
      .user-profile-container {
        background: rgba(255, 255, 255, 0.95);
        border-radius: 12px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
      }
      
      .auth-button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border: none;
        border-radius: 8px;
        color: white;
        padding: 8px 16px;
        transition: all 0.3s ease;
      }
      
      .auth-button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
      }
    ")),
    
    # Include security JavaScript
    tags$script(HTML(get_security_js()))
  ),
  
  # Search and Dashboard Tab
  nav_panel(
    title = "🔍 Busca e Análise",
    icon = icon("search"),
    layout_columns(
      col_widths = c(4, 8),
      
      # Enhanced Search Panel with new UI components
      search_interface_ui("main_search"),
      
      # Results Panel
      card(
        card_header("📊 Resultados da Busca"),
        card_body(
          # Enhanced summary cards with animations
          layout_columns(
            col_widths = c(3, 3, 3, 3),
            enhanced_value_box(
              title = "Total de Documentos",
              value = textOutput("total_documents"),
              icon = "file-text",
              color = "primary"
            ),
            enhanced_value_box(
              title = "Estados Cobertos",
              value = textOutput("total_states"),
              icon = "map",
              color = "success"
            ),
            enhanced_value_box(
              title = "Tipos de Documento",
              value = textOutput("total_types"),
              icon = "tags",
              color = "info"
            ),
            enhanced_value_box(
              title = "Mais Recente",
              value = textOutput("latest_date"),
              icon = "calendar",
              color = "warning"
            )
          ),
          
          # Data visualization tabs
          navset_card_tab(
            id = "results_tabs",
            
            nav_panel(
              "📋 Tabela",
              enhanced_data_table("results", options = list(
                pageLength = 25,
                scrollX = TRUE,
                dom = 'Bfrtip',
                buttons = list('copy', 'csv', 'excel', 'pdf')
              ))
            ),
            
            nav_panel(
              "📊 Gráficos",
              layout_columns(
                col_widths = c(6, 6),
                enhanced_chart_ui("type_chart", "Distribuição por Tipo de Documento"),
                enhanced_chart_ui("temporal_chart", "Evolução Temporal da Legislação")
              )
            )
          )
        )
      )
    )
  ),
  
  # Geographic Analysis Tab
  nav_panel(
    title = "🗺️ Análise Geográfica",
    icon = icon("map"),
    layout_columns(
      col_widths = c(8, 4),
      
      # Enhanced Map Panel
      enhanced_map_ui("brazil_map", height = "600px"),
      
      # Map Controls and Info
      layout_columns(
        col_widths = 12,
        
        card(
          card_header("🎛️ Controles do Mapa"),
          card_body(
            radioButtons(
              "map_color_by",
              "Colorir por:",
              choices = list(
                "Número de documentos" = "count",
                "Densidade (docs/km²)" = "density",
                "Data mais recente" = "latest"
              ),
              selected = "count"
            ),
            
            checkboxInput("show_municipalities", "Mostrar municípios", FALSE),
            checkboxInput("show_clusters", "Agrupar documentos", TRUE),
            
            br(),
            
            action_button(
              "btn_refresh_map",
              "🔄 Atualizar Mapa",
              class = "btn-success w-100"
            )
          )
        ),
        
        card(
          card_header("📊 Estatísticas Geográficas"),
          card_body(
            htmlOutput("geographic_stats")
          )
        ),
        
        card(
          card_header("📍 Localização Selecionada"),
          card_body(
            htmlOutput("selected_location_info")
          )
        )
      )
    )
  ),
  
  # Document Analysis Tab
  nav_panel(
    title = "📄 Análise de Documentos",
    icon = icon("file-alt"),
    
    # Enhanced document analysis with tabs
    navset_card_tab(
      id = "document_analysis_tabs",
      
      # Document Viewer Tab
      nav_panel(
        "📖 Visualização de Documentos",
        layout_columns(
          col_widths = c(12),
          
          conditionalPanel(
            condition = "output.has_selected_document",
            
            # Enhanced document viewer
            document_viewer_ui("main_document_viewer")
          ),
          
          conditionalPanel(
            condition = "!output.has_selected_document",
            div(
              class = "text-center py-5",
              icon("file-alt", class = "fa-3x text-muted"),
              h4("Selecione um documento", class = "text-muted mt-3"),
              p("Clique em um documento na tabela de resultados para visualizar detalhes", class = "text-muted")
            )
          )
        )
      ),
      
      # Document Comparison Tab
      nav_panel(
        "📊 Comparação de Documentos",
        layout_columns(
          col_widths = c(12),
          
          # Document comparison interface
          document_comparison_ui("main_document_comparison")
        )
      ),
      
      # Legacy Document Details Tab (for backward compatibility)
      nav_panel(
        "📋 Detalhes Tradicionais",
        layout_columns(
          col_widths = c(12),
          
          conditionalPanel(
            condition = "output.has_selected_document",
            
            layout_columns(
              col_widths = c(6, 6),
              
              # Document details
              card(
                card_header("📋 Detalhes do Documento"),
                card_body(
                  htmlOutput("document_details")
                )
              ),
              
              # Document analysis
              card(
                card_header("🤖 Análise AI"),
                card_body(
                  htmlOutput("document_analysis")
                )
              )
            ),
            
            # Document content viewer
            card(
              card_header("📖 Conteúdo do Documento"),
              card_body(
                htmlOutput("document_content")
              )
            )
          ),
          
          conditionalPanel(
            condition = "!output.has_selected_document",
            div(
              class = "text-center py-5",
              icon("file-alt", class = "fa-3x text-muted"),
              h4("Selecione um documento", class = "text-muted mt-3"),
              p("Clique em um documento na tabela de resultados para visualizar detalhes", class = "text-muted")
            )
          )
        )
      )
    )
  ),
  
  # Analytics Dashboard Tab (Week 6)
  nav_panel(
    title = "📊 Analytics Dashboard",
    icon = icon("chart-line"),
    
    # Advanced dashboard interface
    advanced_dashboard_ui("main_analytics_dashboard")
  ),
  
  # Export and Citations Tab
  nav_panel(
    title = "📤 Exportar & Citar",
    icon = icon("download"),
    
    # Enhanced export with tabs
    navset_card_tab(
      id = "export_tabs",
      
      # Data Export Tab
      nav_panel(
        "📊 Exportação de Dados",
        layout_columns(
          col_widths = c(8, 4),
          
          card(
            card_header("📤 Exportar Dados de Pesquisa"),
            card_body(
              # Export template selection
              h5("Tipo de Relatório"),
              selectInput(
                "export_template",
                NULL,
                choices = list(
                  "📊 Dataset para Pesquisa" = "research_dataset",
                  "📋 Relatório Acadêmico Completo" = "academic_report",
                  "📈 Resumo Executivo dos Dados" = "data_summary",
                  "📊 Análise Estatística Detalhada" = "statistical_analysis",
                  "🗺️ Relatório de Análise Geográfica" = "geographic_analysis",
                  "📅 Análise Temporal Legislativa" = "temporal_analysis",
                  "⚖️ Estudo Comparativo" = "comparative_study"
                ),
                selected = "research_dataset"
              ),
              
              # Format selection
              h5("Formato de Exportação"),
              radioButtons(
                "export_format",
                NULL,
                choices = list(
                  "📊 CSV - Dados tabulares" = "csv",
                  "📋 Excel - Planilha completa" = "xlsx",
                  "📄 HTML - Relatório web" = "html",
                  "📋 JSON - Dados estruturados" = "json",
                  "📦 ZIP - Pacote completo" = "zip",
                  "🔧 R Data (RDS)" = "rds",
                  "📄 XML - Dados estruturados" = "xml"
                ),
                selected = "csv"
              ),
              
              # Quality level
              h5("Nível de Qualidade"),
              radioButtons(
                "export_quality",
                NULL,
                choices = list(
                  "📝 Rascunho (Visualização)" = "draft",
                  "📋 Padrão (Publicação)" = "standard",
                  "🎓 Publicação (Revisão por Pares)" = "publication",
                  "🗃️ Arquivo (Preservação)" = "archive"
                ),
                selected = "standard"
              ),
              
              # Enhanced options
              h5("Opções de Exportação"),
              checkboxGroupInput(
                "export_options",
                NULL,
                choices = list(
                  "Incluir metadados completos" = "include_metadata",
                  "Incluir análise estatística" = "include_stats",
                  "Incluir visualizações" = "include_charts",
                  "Incluir citações acadêmicas" = "include_citations"
                ),
                selected = c("include_metadata", "include_stats")
              ),
              
              numericInput(
                "export_limit",
                "Máximo de registros:",
                value = 1000,
                min = 1,
                max = 5000,
                step = 100
              ),
              
              br(),
              
              action_button(
                "btn_export",
                "📦 Gerar Exportação",
                class = "btn-success btn-lg w-100"
              ),
              
              br(), br(),
              
              conditionalPanel(
                condition = "output.export_ready",
                div(
                  class = "alert alert-success",
                  icon("check-circle"),
                  " Exportação concluída!",
                  br(),
                  downloadButton(
                    "download_export",
                    "📥 Baixar Arquivo",
                    class = "btn-success btn-sm mt-2"
                  )
                )
              )
            )
          ),
          
          card(
            card_header("📋 Citação da Plataforma"),
            card_body(
              h6("Como citar esta pesquisa:"),
              wellPanel(
                style = "background: rgba(248, 249, 250, 0.8); border-radius: 8px;",
                tags$small(
                  em(paste0(
                    "Monitor Legislativo v4. Dados legislativos brasileiros. ",
                    "Consultado em ", format(Sys.Date(), "%d de %B de %Y"), ". ",
                    "Plataforma acadêmica de pesquisa."
                  ))
                )
              ),
              
              h6("Fontes de Dados:"),
              tags$ul(
                tags$li("Câmara dos Deputados"),
                tags$li("Senado Federal"),
                tags$li("LexML Brasil"),
                tags$li("Assembleias Legislativas"),
                tags$li("IBGE - Dados Geográficos")
              )
            )
          )
        )
      ),
      
      # Academic Citations Tab
      nav_panel(
        "🎓 Citações Acadêmicas",
        layout_columns(
          col_widths = c(12),
          
          # Citation generator interface
          citation_generator_ui("main_citation_generator")
        )
      )
    )
  ),
  
  # User Management Tab (Week 7)
  nav_panel(
    title = "👤 Usuário",
    icon = icon("user"),
    
    # User profile and management interface
    user_profile_ui("main_user_profile")
  ),
  
  # API & Integrations Tab (Week 9)
  nav_panel(
    title = "🔗 API & Integrações",
    icon = icon("plug"),
    
    layout_columns(
      col_widths = c(6, 6),
      
      # External Services Status
      card(
        card_header("🌐 Status dos Serviços Externos"),
        card_body(
          htmlOutput("external_services_status"),
          br(),
          action_button(
            "btn_test_integrations",
            "🔍 Testar Integrações",
            class = "btn-primary btn-sm w-100"
          )
        )
      ),
      
      # Data Pipeline Status  
      card(
        card_header("📊 Pipeline de Dados"),
        card_body(
          htmlOutput("data_pipeline_status"),
          br(),
          action_button(
            "btn_run_pipeline",
            "🚀 Executar Pipeline",
            class = "btn-success btn-sm w-100"
          )
        )
      )
    ),
    
    layout_columns(
      col_widths = c(4, 4, 4),
      
      # Batch Operations
      card(
        card_header("📦 Operações em Lote"),
        card_body(
          htmlOutput("batch_operations_status"),
          br(),
          action_button(
            "btn_view_batches",
            "📋 Ver Operações",
            class = "btn-info btn-sm w-100"
          )
        )
      ),
      
      # API Statistics
      card(
        card_header("📈 Estatísticas da API"),
        card_body(
          htmlOutput("api_statistics"),
          br(),
          action_button(
            "btn_start_api_server",
            "🚀 Iniciar Servidor API",
            class = "btn-warning btn-sm w-100"
          )
        )
      ),
      
      # Integration Metrics
      card(
        card_header("📊 Métricas de Integração"),
        card_body(
          htmlOutput("integration_metrics")
        )
      )
    )
  ),
  
  # Performance Monitoring Tab (Week 8)
  nav_panel(
    title = "📊 Performance",
    icon = icon("tachometer-alt"),
    
    layout_columns(
      col_widths = c(4, 4, 4),
      
      # System Health Card
      card(
        card_header("🏥 System Health"),
        card_body(
          htmlOutput("system_health_status"),
          br(),
          action_button(
            "btn_run_health_check",
            "🔍 Run Health Check",
            class = "btn-primary btn-sm w-100"
          )
        )
      ),
      
      # Performance Metrics Card
      card(
        card_header("⚡ Performance Metrics"),
        card_body(
          htmlOutput("performance_metrics_summary"),
          br(),
          action_button(
            "btn_optimize_performance",
            "🚀 Optimize Performance",
            class = "btn-success btn-sm w-100"
          )
        )
      ),
      
      # Analytics Summary Card
      card(
        card_header("📈 Analytics Summary"),
        card_body(
          htmlOutput("analytics_summary"),
          br(),
          action_button(
            "btn_generate_report",
            "📋 Generate Report",
            class = "btn-info btn-sm w-100"
          )
        )
      )
    ),
    
    layout_columns(
      col_widths = c(6, 6),
      
      # Cache Performance
      card(
        card_header("💾 Cache Performance"),
        card_body(
          htmlOutput("cache_performance_stats")
        )
      ),
      
      # Recent Alerts
      card(
        card_header("🚨 Recent Alerts"),
        card_body(
          htmlOutput("recent_alerts_display")
        )
      )
    )
  ),
  
  # Settings Tab
  nav_panel(
    title = "⚙️ Configurações",
    icon = icon("cog"),
    layout_columns(
      col_widths = c(6, 6),
      
      card(
        card_header("⚙️ Configurações da Aplicação"),
        card_body(
          h6("APIs de Dados"),
          checkboxGroupInput(
            "enabled_apis",
            NULL,
            choices = list(
              "Backend Principal" = "backend",
              "Câmara dos Deputados" = "camara",
              "Senado Federal" = "senado",
              "LexML Brasil" = "lexml"
            ),
            selected = c("backend", "lexml")
          ),
          
          h6("Performance"),
          numericInput(
            "max_results",
            "Máximo de resultados:",
            value = app_config$performance$max_results_default,
            min = 100,
            max = 5000,
            step = 100
          ),
          
          numericInput(
            "cache_duration",
            "Duração do cache (minutos):",
            value = app_config$cache$ttl_default / 60,
            min = 5,
            max = 1440
          ),
          
          br(),
          
          action_button(
            "btn_clear_cache",
            "🗑️ Limpar Cache",
            class = "btn-warning"
          )
        )
      ),
      
      card(
        card_header("📊 Status do Sistema"),
        card_body(
          h6("APIs Status"),
          verbatimTextOutput("api_status"),
          
          h6("Estatísticas de Uso"),
          verbatimTextOutput("system_stats"),
          
          h6("Informações da Aplicação"),
          p(paste("Versão:", app_config$app$version)),
          p(paste("Configuração:", config_env)),
          p(paste("Inicializado:", format(Sys.time(), "%d/%m/%Y %H:%M")))
        )
      )
    )
  ),
  
  # AI & Advanced Analytics Tab (Week 10)
  nav_panel(
    title = "🤖 IA & Analytics",
    icon = icon("brain"),
    
    navset_card_tab(
      id = "ai_analytics_tabs",
      
      # AI Integration Tab
      nav_panel(
        "🧠 Integração com IA",
        layout_columns(
          col_widths = c(6, 6),
          
          # AI Services Status
          card(
            card_header("🔧 Status dos Serviços de IA"),
            card_body(
              htmlOutput("ai_services_status"),
              br(),
              action_button(
                "btn_test_ai_services",
                "🧪 Testar Serviços",
                class = "btn-primary btn-sm w-100"
              )
            )
          ),
          
          # Document Summarization
          card(
            card_header("📝 Resumo de Documentos"),
            card_body(
              p("Gere resumos automáticos usando IA"),
              selectInput(
                "ai_summary_type",
                "Tipo de resumo:",
                choices = list(
                  "Executivo" = "executive",
                  "Técnico" = "technical", 
                  "Jurídico" = "legal"
                ),
                selected = "executive"
              ),
              numericInput(
                "ai_summary_length",
                "Comprimento máximo:",
                value = 300,
                min = 100,
                max = 1000,
                step = 50
              ),
              action_button(
                "btn_generate_summary",
                "📄 Gerar Resumo",
                class = "btn-success btn-sm w-100"
              ),
              br(), br(),
              htmlOutput("ai_summary_result")
            )
          )
        ),
        
        layout_columns(
          col_widths = c(12),
          
          # Document Classification
          card(
            card_header("🏷️ Classificação de Documentos"),
            card_body(
              p("Classifique documentos automaticamente usando IA"),
              htmlOutput("ai_classification_results"),
              br(),
              action_button(
                "btn_classify_documents",
                "🔄 Classificar Documentos",
                class = "btn-info btn-sm"
              )
            )
          )
        )
      ),
      
      # Semantic Search Tab
      nav_panel(
        "🔍 Busca Semântica",
        layout_columns(
          col_widths = c(8, 4),
          
          # Semantic Search Interface
          card(
            card_header("🔍 Busca Semântica Avançada"),
            card_body(
              p("Busque documentos usando significado e contexto, não apenas palavras-chave"),
              textAreaInput(
                "semantic_query",
                "Consulta semântica:",
                placeholder = "Ex: documentos sobre transparência na administração pública que tratam de acesso à informação...",
                rows = 3,
                width = "100%"
              ),
              
              sliderInput(
                "semantic_similarity_threshold",
                "Limite de similaridade:",
                min = 0.5,
                max = 1.0,
                value = 0.7,
                step = 0.05
              ),
              
              numericInput(
                "semantic_max_results",
                "Máximo de resultados:",
                value = 20,
                min = 5,
                max = 100,
                step = 5
              ),
              
              action_button(
                "btn_semantic_search",
                "🔍 Buscar Semanticamente",
                class = "btn-primary btn-lg w-100"
              ),
              
              br(), br(),
              
              # Search Results
              htmlOutput("semantic_search_results")
            )
          ),
          
          # Semantic Search Stats
          card(
            card_header("📊 Estatísticas da Busca Semântica"),
            card_body(
              htmlOutput("semantic_search_stats")
            )
          )
        )
      ),
      
      # Knowledge Graph Tab
      nav_panel(
        "🕸️ Grafo de Conhecimento",
        layout_columns(
          col_widths = c(12),
          
          # Knowledge Graph Visualization
          card(
            card_header("🗺️ Visualização do Grafo de Conhecimento"),
            card_body(
              p("Explore relações entre entidades no corpus legislativo"),
              
              # Graph Controls
              layout_columns(
                col_widths = c(3, 3, 3, 3),
                
                selectInput(
                  "kg_entity_type",
                  "Tipo de entidade:",
                  choices = list(
                    "Todas" = "",
                    "Lei" = "LEI",
                    "Decreto" = "DECRETO", 
                    "Órgão" = "ORGAO",
                    "Pessoa" = "PESSOA",
                    "Conceito Jurídico" = "CONCEITO_JURIDICO"
                  ),
                  selected = ""
                ),
                
                selectInput(
                  "kg_relationship_type",
                  "Tipo de relação:",
                  choices = list(
                    "Todas" = "",
                    "Regulamenta" = "REGULAMENTA",
                    "Revoga" = "REVOGA",
                    "Altera" = "ALTERA",
                    "Cita" = "CITA"
                  ),
                  selected = ""
                ),
                
                sliderInput(
                  "kg_confidence_threshold",
                  "Confiança mínima:",
                  min = 0.1,
                  max = 1.0,
                  value = 0.5,
                  step = 0.1
                ),
                
                action_button(
                  "btn_update_knowledge_graph",
                  "🔄 Atualizar Grafo",
                  class = "btn-primary btn-sm w-100"
                )
              ),
              
              br(),
              
              # Graph Visualization
              htmlOutput("knowledge_graph_viz"),
              
              br(),
              
              # Graph Statistics
              htmlOutput("knowledge_graph_stats")
            )
          )
        )
      ),
      
      # Recommendations Tab
      nav_panel(
        "💡 Recomendações",
        layout_columns(
          col_widths = c(8, 4),
          
          # Recommendations Display
          card(
            card_header("💡 Documentos Recomendados"),
            card_body(
              p("Descubra documentos relevantes com base em suas interações"),
              
              # Recommendation Controls
              checkboxInput(
                "exclude_seen_docs",
                "Excluir documentos já visualizados",
                value = TRUE
              ),
              
              numericInput(
                "max_recommendations",
                "Número de recomendações:",
                value = 10,
                min = 5,
                max = 50,
                step = 5
              ),
              
              action_button(
                "btn_generate_recommendations",
                "✨ Gerar Recomendações",
                class = "btn-success btn-lg w-100"
              ),
              
              br(), br(),
              
              # Recommendations List
              htmlOutput("recommendations_list")
            )
          ),
          
          # Recommendation Statistics
          card(
            card_header("📈 Estatísticas de Recomendação"),
            card_body(
              htmlOutput("recommendation_stats")
            )
          )
        )
      ),
      
      # AI Analytics Summary Tab
      nav_panel(
        "📊 Resumo de Analytics",
        layout_columns(
          col_widths = c(4, 4, 4),
          
          # AI Integration Summary
          card(
            card_header("🧠 Resumo da Integração com IA"),
            card_body(
              htmlOutput("ai_integration_summary")
            )
          ),
          
          # Knowledge Graph Summary
          card(
            card_header("🕸️ Resumo do Grafo de Conhecimento"),
            card_body(
              htmlOutput("knowledge_graph_summary")
            )
          ),
          
          # Semantic Search Summary
          card(
            card_header("🔍 Resumo da Busca Semântica"),
            card_body(
              htmlOutput("semantic_search_summary")
            )
          )
        )
      )
    )
  )
)

# ============================================================================
# SERVER LOGIC
# ============================================================================

server <- function(input, output, session) {
  
  # Initialize security system
  initialize_security(session)
  
  # Reactive values
  values <- reactiveValues(
    search_results = NULL,
    selected_document = NULL,
    export_file = NULL,
    map_data = NULL,
    user_data = NULL,
    auth_status = FALSE
  )
  
  # ========================================================================
  # SEARCH FUNCTIONALITY
  # ========================================================================
  
  # Enhanced search with LexML integration and vocabulary processing
  observeEvent(input$`main_search-btn_search`, {
    
    # Record performance metric and track usage
    search_start_time <- Sys.time()
    track_usage_event("search_query", list(
      query = input$`main_search-search_query`,
      has_filters = !is.null(input$`main_search-document_types`) || !is.null(input$`main_search-states_filter`)
    ))
    
    create_toast("Iniciando busca avançada...", "info")
    
    # Use enhanced search engine with LexML and vocabulary expansion
    enhanced_search(
      query = input$`main_search-search_query`,
      filters = list(
        date_from = input$`main_search-date_range`[1],
        date_to = input$`main_search-date_range`[2],
        types = input$`main_search-document_types`,
        states = input$`main_search-states_filter`,
        limit = input$max_results %||% 1000
      ),
      sources = c("lexml", "api"),
      options = list(
        enable_vocabulary_expansion = TRUE,
        enable_result_ranking = TRUE,
        max_results_per_source = 500
      )
    ) %...>% {
      # Process results through document pipeline
      processed_results <- process_document_pipeline(., options = list(
        enable_classification = TRUE,
        enable_quality_scoring = TRUE,
        min_document_quality = 60
      ))
      
      if (!is.null(processed_results) && nrow(processed_results) > 0) {
        values$search_results <- processed_results
        
        search_time <- as.numeric(Sys.time() - search_start_time, units = "secs") * 1000
        record_metric("search_time", search_time, "performance")
        
        # Get vocabulary analysis
        vocab_analysis <- analyze_vocabulary_coverage(input$`main_search-search_query`)
        
        create_toast(
          paste("Busca LexML concluída!", nrow(processed_results), "documentos processados",
                "- Cobertura vocabular:", paste0(vocab_analysis$coverage_percentage, "%")),
          "success"
        )
      } else {
        create_toast("Nenhum documento encontrado", "warning")
        values$search_results <- create_empty_search_result()
      }
    } %...!% {
      create_toast("Erro na busca LexML. Usando dados de fallback...", "error")
      values$search_results <- create_fallback_lexml_data(input$`main_search-search_query`)
    }
  })
  
  # Clear filters with enhanced UI
  observeEvent(input$`main_search-btn_clear_filters`, {
    updateTextInput(session, "main_search-search_query", value = "")
    updateDateRangeInput(session, "main_search-date_range", 
                        start = Sys.Date() - 365, end = Sys.Date())
    updateCheckboxGroupInput(session, "main_search-document_types", selected = NULL)
    updateSelectizeInput(session, "main_search-states_filter", selected = NULL)
    
    values$search_results <- NULL
    values$selected_document <- NULL
    
    create_toast("Filtros limpos", "info")
  })
  
  # ========================================================================
  # OUTPUTS - SUMMARY BOXES
  # ========================================================================
  
  output$total_documents <- renderText({
    if (is.null(values$search_results)) "0" 
    else format(nrow(values$search_results), big.mark = ".")
  })
  
  output$total_states <- renderText({
    if (is.null(values$search_results)) "0"
    else length(unique(values$search_results$estado[!is.na(values$search_results$estado)]))
  })
  
  output$total_types <- renderText({
    if (is.null(values$search_results)) "0"
    else length(unique(values$search_results$tipo[!is.na(values$search_results$tipo)]))
  })
  
  output$latest_date <- renderText({
    if (is.null(values$search_results)) "N/A"
    else {
      latest <- max(as.Date(values$search_results$data), na.rm = TRUE)
      format(latest, "%d/%m/%Y")
    }
  })
  
  # ========================================================================
  # OUTPUTS - ENHANCED DATA TABLE
  # ========================================================================
  
  output$`results-table` <- DT::renderDataTable({
    
    if (is.null(values$search_results)) {
      return(data.frame(
        Mensagem = "Execute uma busca para visualizar resultados"
      ))
    }
    
    # Prepare display data with enhanced processing
    display_data <- values$search_results %>%
      select(
        Título = titulo,
        Tipo = tipo,
        Número = numero,
        Data = data,
        Estado = estado,
        Qualidade = validation_score,
        Categoria = categoria,
        Fonte = fonte
      ) %>%
      mutate(
        Data = format(as.Date(Data), "%d/%m/%Y"),
        Título = stringr::str_trunc(Título, 80),
        Qualidade = paste0(round(Qualidade), "%")
      ) %>%
      arrange(desc(as.Date(Data, format = "%d/%m/%Y")))
    
    display_data
    
  }, options = list(
    pageLength = 25,
    scrollX = TRUE,
    scrollY = "400px",
    dom = 'Bfrtip',
    buttons = list(
      list(extend = 'copy', text = 'Copiar'),
      list(extend = 'csv', text = 'CSV'),
      list(extend = 'excel', text = 'Excel'),
      list(extend = 'pdf', text = 'PDF')
    ),
    language = list(
      url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
    ),
    selection = 'single'
  ), selection = 'single')
  
  # Row count for enhanced table
  output$`results-row_count` <- renderText({
    if (is.null(values$search_results)) "0 documentos"
    else paste(nrow(values$search_results), "documentos")
  })
  
  # Handle row selection for document details
  observeEvent(input$`results-table_rows_selected`, {
    if (length(input$`results-table_rows_selected`) > 0 && !is.null(values$search_results)) {
      selected_row <- input$`results-table_rows_selected`[1]
      values$selected_document <- values$search_results[selected_row, ]
    }
  })
  
  # ========================================================================
  # OUTPUTS - CHARTS
  # ========================================================================
  
  # Enhanced charts with new UI components
  output$`type_chart-chart` <- renderEcharts4r({
    
    if (is.null(values$search_results)) {
      return(e_charts() %>% e_title("Sem dados para exibir"))
    }
    
    type_data <- values$search_results %>%
      count(tipo, sort = TRUE) %>%
      slice_head(n = 10)
    
    type_data %>%
      e_charts(tipo) %>%
      e_bar(n, name = "Documentos") %>%
      e_color(c("#0d6efd", "#198754", "#fd7e14", "#dc3545", "#6f42c1")) %>%
      e_title("Distribuição por Tipo de Documento") %>%
      e_tooltip(trigger = "axis") %>%
      e_legend(show = FALSE) %>%
      e_flip_coords() %>%
      e_animation(duration = 1000)
  })
  
  output$`temporal_chart-chart` <- renderEcharts4r({
    
    if (is.null(values$search_results)) {
      return(e_charts() %>% e_title("Sem dados para exibir"))
    }
    
    temporal_data <- values$search_results %>%
      mutate(ano = lubridate::year(as.Date(data))) %>%
      count(ano, sort = FALSE) %>%
      filter(!is.na(ano))
    
    temporal_data %>%
      e_charts(ano) %>%
      e_line(n, smooth = TRUE, name = "Documentos", symbol_size = 6) %>%
      e_area(n, name = "Área", opacity = 0.3) %>%
      e_color("#0d6efd") %>%
      e_title("Evolução Temporal da Legislação") %>%
      e_tooltip(trigger = "axis") %>%
      e_legend(show = FALSE) %>%
      e_animation(duration = 1500)
  })
  
  # ========================================================================
  # OUTPUTS - MAP
  # ========================================================================
  
  # Enhanced interactive map with spatial analysis
  output$`brazil_map-map` <- renderLeaflet({
    
    # Create enhanced interactive map with clustering and spatial analysis
    enhanced_map <- create_enhanced_interactive_map(
      legislative_data = values$search_results,
      geo_data = geographic_data,
      map_style = input$`brazil_map-map_style` %||% "default",
      color_variable = input$`brazil_map-color_variable` %||% "count",
      enable_clustering = input$`brazil_map-show_clusters` %||% TRUE
    )
    
    # Initialize map search functionality
    if (!is.null(enhanced_map)) {
      enhanced_map <- initialize_map_search(enhanced_map, enable_drawing = TRUE)
    }
    
    enhanced_map %||% leaflet() %>% 
      setView(lng = -47.8825, lat = -15.7942, zoom = 4) %>%
      addProviderTiles(providers$CartoDB.Positron)
  })
  
  # Update map when data or settings change
  observeEvent(list(values$search_results, input$`brazil_map-color_variable`, input$`brazil_map-show_clusters`), {
    if (!is.null(values$search_results) && !is.null(geographic_data)) {
      
      # Update map with enhanced interactive features
      leafletProxy("brazil_map-map") %>%
        update_interactive_map(
          legislative_data = values$search_results,
          geo_data = geographic_data,
          color_variable = input$`brazil_map-color_variable` %||% "count",
          enable_clustering = input$`brazil_map-show_clusters` %||% TRUE
        )
    }
  })
  
  # Enhanced geographic statistics with spatial analysis
  output$geographic_stats <- renderUI({
    if (is.null(values$search_results)) {
      return(p("Nenhum dado para análise geográfica"))
    }
    
    # Perform spatial clustering analysis
    clustered_docs <- spatial_cluster_documents(values$search_results, geographic_data)
    
    # Calculate comprehensive spatial statistics  
    spatial_stats <- calculate_spatial_statistics(clustered_docs, geographic_data)
    
    tagList(
      p(strong("🗺️ Cobertura Nacional:")),
      p(paste(spatial_stats$covered_states, "estados cobertos (", spatial_stats$geographic_coverage, "%)")),
      
      p(strong("📍 Análise Espacial:")),
      p(paste("Total de documentos:", spatial_stats$total_documents)),
      
      if (!is.null(clustered_docs) && "spatial_cluster" %in% names(clustered_docs)) {
        tagList(
          p(strong("🔗 Clusters Espaciais:")),
          p(paste("Encontrados", length(unique(clustered_docs$spatial_cluster)), "grupos espaciais")),
          
          p(strong("📊 Densidade Regional:")),
          if (nrow(spatial_stats$regional_aggregation) > 0) {
            div(
              lapply(1:min(3, nrow(spatial_stats$regional_aggregation)), function(i) {
                region <- spatial_stats$regional_aggregation[i, ]
                p(paste("•", region$region_code, ":", region$total_documents, "documentos"))
              })
            )
          } else p("Dados regionais não disponíveis")
        )
      } else {
        p("Análise de clusters em andamento...")
      }
    )
  })
  
  # ========================================================================
  # DOCUMENT ANALYSIS
  # ========================================================================
  
  output$has_selected_document <- reactive({
    !is.null(values$selected_document)
  })
  outputOptions(output, "has_selected_document", suspendWhenHidden = FALSE)
  
  output$document_details <- renderUI({
    if (is.null(values$selected_document)) return(NULL)
    
    doc <- values$selected_document
    
    tagList(
      h5(doc$titulo),
      p(strong("Tipo: "), doc$tipo),
      p(strong("Número: "), doc$numero),
      p(strong("Data: "), format(as.Date(doc$data), "%d de %B de %Y")),
      p(strong("Estado: "), doc$estado),
      p(strong("Fonte: "), doc$fonte),
      if (!is.null(doc$autor)) p(strong("Autor: "), doc$autor),
      if (!is.null(doc$ementa)) {
        tagList(
          strong("Ementa:"),
          p(doc$ementa, style = "text-align: justify;")
        )
      }
    )
  })
  
  # ========================================================================
  # ENHANCED DOCUMENT MODULES (Week 5)
  # ========================================================================
  
  # Document viewer module
  document_viewer_server("main_document_viewer", reactive({
    if (!is.null(values$selected_document)) {
      # Convert single document to data frame format expected by viewer
      data.frame(values$selected_document, stringsAsFactors = FALSE)
    } else {
      NULL
    }
  }))
  
  # Document comparison module
  document_comparison_server("main_document_comparison", reactive({
    values$search_results
  }))
  
  # Citation generator module
  citation_generator_server("main_citation_generator", reactive({
    values$search_results
  }))
  
  # Advanced analytics dashboard module (Week 6)
  advanced_dashboard_server("main_analytics_dashboard", reactive({
    values$search_results
  }))
  
  # ========================================================================
  # USER MANAGEMENT AND AUTHENTICATION (Week 7)
  # ========================================================================
  
  # User profile management module
  user_profile_server("main_user_profile", reactive({
    values$user_data
  }))
  
  # ========================================================================
  # PERFORMANCE MONITORING AND ANALYTICS (Week 8)
  # ========================================================================
  
  # System health status
  output$system_health_status <- renderUI({
    if (exists("monitoring_state") && !is.null(monitoring_state$health_status)) {
      health_data <- monitoring_state$health_status
      
      status_color <- switch(health_data$overall_status,
        "healthy" = "success",
        "degraded" = "warning", 
        "unhealthy" = "danger",
        "secondary"
      )
      
      tagList(
        div(
          class = paste("alert alert-", status_color),
          h6(paste("System Status:", toupper(health_data$overall_status))),
          p(paste("Components:", health_data$healthy_components, "/", health_data$total_components, "healthy")),
          if (!is.null(health_data$duration_ms)) {
            p(paste("Last check:", round(health_data$duration_ms), "ms"))
          }
        )
      )
    } else {
      div(
        class = "alert alert-secondary",
        h6("Health Status: Unknown"),
        p("No health check data available")
      )
    }
  })
  
  # Performance metrics summary
  output$performance_metrics_summary <- renderUI({
    if (exists("get_performance_stats")) {
      perf_stats <- get_performance_stats()
      memory_usage <- perf_stats$memory$used_mb %||% 0
      
      tagList(
        div(
          class = "metric-row",
          p(strong("Memory Usage:"), paste(round(memory_usage), "MB")),
          if (!is.null(perf_stats$query_performance)) {
            p(strong("Avg Query Time:"), paste(perf_stats$query_performance$avg_time_ms, "ms"))
          },
          p(strong("Cache Hit Rate:"), paste(perf_stats$query_cache$hit_rate %||% 0, "%")),
          p(strong("Cache Size:"), paste(perf_stats$query_cache$size %||% 0, "entries"))
        )
      )
    } else {
      p("Performance metrics not available")
    }
  })
  
  # Analytics summary
  output$analytics_summary <- renderUI({
    if (exists("get_analytics_dashboard_data")) {
      analytics_data <- get_analytics_dashboard_data()
      
      tagList(
        div(
          class = "metric-row",
          p(strong("Events Today:"), analytics_data$usage_summary$total_events_today %||% 0),
          p(strong("Events This Week:"), analytics_data$usage_summary$total_events_week %||% 0),
          p(strong("Cost Today:"), paste("$", sprintf("%.4f", analytics_data$cost_summary$total_cost_today %||% 0))),
          p(strong("Budget Used:"), paste(round(analytics_data$cost_summary$budget_utilization %||% 0, 1), "%"))
        )
      )
    } else {
      p("Analytics data not available")
    }
  })
  
  # Cache performance stats
  output$cache_performance_stats <- renderUI({
    if (exists("get_cache_statistics")) {
      cache_stats <- get_cache_statistics()
      
      if (cache_stats$status == "redis_unavailable") {
        div(
          class = "alert alert-warning",
          "Redis cache not available"
        )
      } else {
        tagList(
          h6("Redis Performance"),
          p(paste("Memory Used:", cache_stats$redis_memory_used %||% "Unknown")),
          p(paste("Connected Clients:", cache_stats$redis_connected_clients %||% "Unknown")),
          
          if (!is.null(cache_stats$search_results)) {
            tagList(
              h6("Search Cache"),
              p(paste("Hit Rate:", cache_stats$search_results$hit_rate, "%")),
              p(paste("Total Requests:", cache_stats$search_results$total_requests))
            )
          }
        )
      }
    } else {
      p("Cache statistics not available")
    }
  })
  
  # Recent alerts display
  output$recent_alerts_display <- renderUI({
    if (exists("monitoring_state") && !is.null(monitoring_state$alerts)) {
      recent_alerts <- head(monitoring_state$alerts, 5)
      
      if (length(recent_alerts) == 0) {
        div(
          class = "alert alert-success",
          "No recent alerts"
        )
      } else {
        tagList(
          lapply(recent_alerts, function(alert) {
            alert_class <- switch(alert$severity,
              "critical" = "danger",
              "warning" = "warning",
              "info" = "info",
              "secondary"
            )
            
            div(
              class = paste("alert alert-", alert_class, "alert-sm"),
              style = "margin-bottom: 5px;",
              strong(paste("[", toupper(alert$severity), "]")),
              " ", alert$message,
              br(),
              tags$small(format(alert$timestamp, "%H:%M:%S"))
            )
          })
        )
      }
    } else {
      div(
        class = "alert alert-secondary",
        "No alerts available"
      )
    }
  })
  
  # Performance monitoring actions
  observeEvent(input$btn_run_health_check, {
    if (exists("perform_health_checks")) {
      showNotification("Running health checks...", type = "message")
      
      future({
        perform_health_checks()
      }) %...>% {
        showNotification("Health check completed", type = "success")
      } %...!% {
        showNotification("Health check failed", type = "error")
      }
    } else {
      showNotification("Health check system not available", type = "error")
    }
  })
  
  observeEvent(input$btn_optimize_performance, {
    if (exists("optimize_memory_usage")) {
      showNotification("Optimizing performance...", type = "message")
      
      future({
        optimize_memory_usage(aggressive = TRUE)
      }) %...>% {
        showNotification("Performance optimization completed", type = "success")
      } %...!% {
        showNotification("Performance optimization failed", type = "error")
      }
    } else {
      showNotification("Performance optimization not available", type = "error")
    }
  })
  
  observeEvent(input$btn_generate_report, {
    if (exists("generate_usage_report")) {
      showNotification("Generating analytics report...", type = "message")
      
      future({
        generate_usage_report("daily", "html")
      }) %...>% {
        showNotification("Analytics report generated", type = "success")
      } %...!% {
        showNotification("Report generation failed", type = "error")
      }
    } else {
      showNotification("Analytics reporting not available", type = "error")
    }
  })
  
  # ========================================================================
  # API & INTEGRATIONS (Week 9)
  # ========================================================================
  
  # External services status
  output$external_services_status <- renderUI({
    if (exists("get_integration_statistics")) {
      integration_stats <- get_integration_statistics()
      
      tagList(
        div(
          class = "metric-row",
          p(strong("Total Requests:"), integration_stats$total_requests %||% 0),
          p(strong("Success Rate:"), paste0(round((integration_stats$success_rate %||% 0) * 100, 1), "%")),
          p(strong("Services Healthy:"), paste(integration_stats$services_healthy %||% 0, "/", integration_stats$total_services %||% 0)),
          p(strong("Last Health Check:"), 
            if (!is.null(integration_stats$last_health_check)) {
              format(integration_stats$last_health_check, "%H:%M:%S")
            } else {
              "Never"
            }
          )
        )
      )
    } else {
      p("Integration statistics not available")
    }
  })
  
  # Data pipeline status
  output$data_pipeline_status <- renderUI({
    if (exists("get_pipeline_statistics")) {
      pipeline_stats <- get_pipeline_statistics()
      
      tagList(
        div(
          class = "metric-row",
          p(strong("Active Pipelines:"), pipeline_stats$active_pipelines %||% 0),
          p(strong("Completed Runs:"), pipeline_stats$completed_pipelines %||% 0),
          p(strong("Recent Runs (24h):"), pipeline_stats$recent_runs_24h %||% 0),
          p(strong("Avg Duration:"), paste(round(pipeline_stats$avg_duration_seconds %||% 0, 1), "sec")),
          p(strong("Success Rate:"), paste0(pipeline_stats$success_rate %||% 0, "%"))
        )
      )
    } else {
      p("Pipeline statistics not available")
    }
  })
  
  # Batch operations status
  output$batch_operations_status <- renderUI({
    if (exists("get_batch_statistics")) {
      batch_stats <- get_batch_statistics()
      
      tagList(
        div(
          class = "metric-row",
          p(strong("Active Batches:"), batch_stats$active_batches %||% 0),
          p(strong("Completed Batches:"), batch_stats$completed_batches %||% 0),
          p(strong("Scheduled Jobs:"), batch_stats$scheduled_jobs %||% 0),
          p(strong("Avg Throughput:"), paste(batch_stats$avg_throughput_docs_per_sec %||% 0, "docs/sec")),
          p(strong("Success Rate:"), paste0(round((batch_stats$success_rate %||% 0) * 100, 1), "%"))
        )
      )
    } else {
      p("Batch statistics not available")
    }
  })
  
  # API statistics
  output$api_statistics <- renderUI({
    if (exists("api_state") && !is.null(api_state$app)) {
      tagList(
        div(
          class = "metric-row",
          p(strong("API Status:"), "Initialized"),
          p(strong("Active Connections:"), api_state$active_connections %||% 0),
          p(strong("Total Requests:"), length(api_state$request_counts %||% list())),
          p(strong("Performance Metrics:"), length(api_state$performance_metrics %||% list()))
        )
      )
    } else {
      div(
        class = "alert alert-warning",
        "API not initialized"
      )
    }
  })
  
  # Integration metrics
  output$integration_metrics <- renderUI({
    if (exists("external_state") && !is.null(external_state$service_health)) {
      healthy_services <- sum(sapply(external_state$service_health, function(x) x$status == "healthy"))
      total_services <- length(external_state$service_health)
      
      tagList(
        div(
          class = "metric-row",
          p(strong("Government APIs:"), 
            sum(sapply(names(EXTERNAL_CONFIG$government_apis), function(x) EXTERNAL_CONFIG$government_apis[[x]]$enabled))),
          p(strong("Regulatory Agencies:"), 
            sum(sapply(names(EXTERNAL_CONFIG$regulatory_agencies), function(x) EXTERNAL_CONFIG$regulatory_agencies[[x]]$enabled))),
          p(strong("Health Status:"), paste(healthy_services, "/", total_services)),
          p(strong("Cache Enabled:"), if(EXTERNAL_CONFIG$caching$cache_responses) "Yes" else "No")
        )
      )
    } else {
      p("Integration metrics not available")
    }
  })
  
  # API and integration actions
  observeEvent(input$btn_test_integrations, {
    if (exists("check_all_services_health")) {
      showNotification("Testing external integrations...", type = "message")
      
      future({
        check_all_services_health()
      }) %...>% {
        showNotification("Integration health check completed", type = "success")
      } %...!% {
        showNotification("Integration health check failed", type = "error")
      }
    } else {
      showNotification("Integration system not available", type = "error")
    }
  })
  
  observeEvent(input$btn_run_pipeline, {
    if (exists("execute_data_pipeline")) {
      showNotification("Starting data pipeline execution...", type = "message")
      
      future({
        execute_data_pipeline()
      }) %...>% {
        if (.$status == "completed") {
          showNotification(paste("Pipeline completed:", .$total_documents, "documents processed"), type = "success")
        } else {
          showNotification(paste("Pipeline failed:", .$error), type = "error")
        }
      } %...!% {
        showNotification("Pipeline execution failed", type = "error")
      }
    } else {
      showNotification("Data pipeline not available", type = "error")
    }
  })
  
  observeEvent(input$btn_start_api_server, {
    if (exists("start_api_server") && exists("api_state") && !is.null(api_state$app)) {
      showNotification("Starting API server...", type = "message")
      
      tryCatch({
        start_api_server(background = TRUE)
        showNotification("API server started successfully", type = "success")
      }, error = function(e) {
        showNotification(paste("Failed to start API server:", e$message), type = "error")
      })
    } else {
      showNotification("API system not available", type = "error")
    }
  })
  
  observeEvent(input$btn_view_batches, {
    showNotification("Batch operations viewer would open here", type = "message")
  })
  
  # ========================================================================
  # EXPORT FUNCTIONALITY
  # ========================================================================
  
  output$export_ready <- reactive({
    !is.null(values$export_file)
  })
  outputOptions(output, "export_ready", suspendWhenHidden = FALSE)
  
  observeEvent(input$btn_export, {
    if (is.null(values$search_results)) {
      showNotification("Nenhum dado para exportar", type = "error")
      return()
    }
    
    showNotification("Gerando exportação avançada...", type = "message")
    
    future({
      # Use enhanced export system
      export_legislative_data(
        data = values$search_results,
        format = input$export_format,
        template = input$export_template %||% "research_dataset",
        options = list(
          include_metadata = "include_metadata" %in% input$export_options,
          include_stats = "include_stats" %in% input$export_options,
          include_charts = "include_charts" %in% input$export_options,
          include_citations = "include_citations" %in% input$export_options,
          limit = input$export_limit,
          states = input$`main_search-states_filter`,
          types = input$`main_search-document_types`,
          date_from = input$`main_search-date_range`[1],
          date_to = input$`main_search-date_range`[2]
        ),
        quality = input$export_quality %||% "standard"
      )
    }) %...>% {
      values$export_file <- .
      showNotification("Exportação avançada concluída!", type = "success")
    } %...!% {
      showNotification("Erro na exportação. Tente novamente.", type = "error")
    }
  })
  
  output$download_export <- downloadHandler(
    filename = function() {
      template_name <- gsub("[^a-zA-Z0-9]", "_", input$export_template %||% "export")
      paste0("monitor_legislativo_", template_name, "_", Sys.Date(), ".", input$export_format)
    },
    content = function(file) {
      if (!is.null(values$export_file) && file.exists(values$export_file)) {
        file.copy(values$export_file, file)
      }
    }
  )
  
  # ========================================================================
  # SYSTEM STATUS
  # ========================================================================
  
  output$api_status <- renderText({
    status <- check_apis_status()
    paste(names(status), ":", sapply(status, function(x) x$status), collapse = "\n")
  })
  
  output$system_stats <- renderText({
    
    # Get performance statistics
    perf_stats <- get_performance_stats()
    memory_stats <- get_memory_usage()
    
    paste(
      "Uptime:", perf_stats$uptime_hours, "horas",
      "\nMemória usada:", memory_stats$used_mb, "MB",
      "\nRequisições totais:", perf_stats$total_requests,
      "\nResultados em cache:", ifelse(is.null(values$search_results), 0, nrow(values$search_results)),
      if (!is.null(perf_stats$search_performance)) {
        paste("\nTempo médio busca:", perf_stats$search_performance$average_time_ms, "ms")
      } else ""
    )
  })
  
  # Clear cache with performance monitoring
  observeEvent(input$btn_clear_cache, {
    
    # Use performance module for cleanup
    cleanup_result <- cleanup_memory(aggressive = TRUE)
    
    values$search_results <- NULL
    values$selected_document <- NULL
    values$export_file <- NULL
    
    create_toast(
      paste("Cache limpo:", round(cleanup_result$memory_freed_mb, 1), "MB liberados"),
      "success"
    )
  })
  
  # ========================================================================
  # AI & ADVANCED ANALYTICS HANDLERS (Week 10)
  # ========================================================================
  
  # AI Services Status
  output$ai_services_status <- renderUI({
    ai_stats <- get_ai_statistics()
    
    div(
      h6("Status dos Provedores de IA"),
      if (ai_stats$total_requests > 0) {
        tagList(
          p(paste("Total de requisições:", ai_stats$total_requests)),
          p(paste("Cache hit ratio:", round(ai_stats$cache_hit_ratio * 100, 1), "%")),
          p(paste("Features ativas:", ai_stats$enabled_features))
        )
      } else {
        p("Nenhuma atividade de IA registrada", class = "text-muted")
      },
      
      h6("Circuit Breakers"),
      if (!is.null(ai_stats$circuit_breaker_status)) {
        lapply(names(ai_stats$circuit_breaker_status), function(provider) {
          status <- ai_stats$circuit_breaker_status[[provider]]
          icon_class <- switch(status,
            "closed" = "text-success",
            "open" = "text-danger", 
            "half-open" = "text-warning",
            "text-muted"
          )
          p(icon("circle", class = icon_class), " ", provider, ": ", status)
        })
      } else {
        p("Circuit breakers não disponíveis", class = "text-muted")
      }
    )
  })
  
  # Test AI Services
  observeEvent(input$btn_test_ai_services, {
    create_toast("Testando serviços de IA...", "info")
    
    # Test basic AI functionality
    test_text <- "Lei Federal sobre transparência na administração pública"
    
    # Test summarization
    summary_result <- summarize_document(test_text, "executive", 100)
    
    if (!is.null(summary_result$summary)) {
      create_toast("Serviços de IA funcionando corretamente", "success")
    } else {
      create_toast("Erro nos serviços de IA", "error")
    }
  })
  
  # Generate Document Summary
  observeEvent(input$btn_generate_summary, {
    if (is.null(values$selected_document)) {
      create_toast("Selecione um documento primeiro", "warning")
      return()
    }
    
    create_toast("Gerando resumo com IA...", "info")
    
    doc_content <- values$selected_document$content %||% values$selected_document$texto
    
    if (is.null(doc_content) || doc_content == "") {
      create_toast("Documento não possui conteúdo para resumir", "warning")
      return()
    }
    
    summary_result <- summarize_document(
      doc_content,
      input$ai_summary_type,
      input$ai_summary_length
    )
    
    if (!is.null(summary_result$summary)) {
      output$ai_summary_result <- renderUI({
        div(
          class = "alert alert-success",
          h6("Resumo Gerado"),
          p(summary_result$summary),
          hr(),
          tags$small(
            paste("Tamanho original:", summary_result$original_length, "caracteres"),
            br(),
            paste("Tamanho do resumo:", summary_result$summary_length, "caracteres"),
            br(), 
            paste("Taxa de compressão:", summary_result$compression_ratio),
            br(),
            paste("Provedor:", summary_result$provider)
          )
        )
      })
      
      create_toast("Resumo gerado com sucesso", "success")
    } else {
      create_toast(paste("Erro ao gerar resumo:", summary_result$message), "error")
    }
  })
  
  # Semantic Search
  observeEvent(input$btn_semantic_search, {
    if (is.null(input$semantic_query) || input$semantic_query == "") {
      create_toast("Digite uma consulta para busca semântica", "warning")
      return()
    }
    
    create_toast("Executando busca semântica...", "info")
    
    semantic_results <- semantic_search_query(
      query = input$semantic_query,
      options = list(
        similarity_threshold = input$semantic_similarity_threshold,
        max_results = input$semantic_max_results
      )
    )
    
    if (semantic_results$total_results > 0) {
      output$semantic_search_results <- renderUI({
        result_cards <- lapply(semantic_results$results, function(result) {
          div(
            class = "card mb-2",
            div(
              class = "card-body",
              h6(class = "card-title", result$title),
              p(class = "card-text", result$snippet),
              div(
                class = "d-flex justify-content-between",
                tags$small(
                  span(class = "badge bg-primary", paste("Similaridade:", round(result$similarity_score, 3))),
                  " ",
                  span(class = "badge bg-secondary", result$type),
                  " ",
                  span(class = "badge bg-info", result$estado)
                ),
                tags$small(class = "text-muted", result$data)
              )
            )
          )
        })
        
        div(
          h6(paste("Encontrados", semantic_results$total_results, "documentos relevantes")),
          result_cards
        )
      })
      
      create_toast(paste("Busca semântica concluída:", semantic_results$total_results, "resultados"), "success")
    } else {
      output$semantic_search_results <- renderUI({
        div(
          class = "alert alert-info",
          "Nenhum documento encontrado com a similaridade especificada"
        )
      })
      create_toast("Nenhum resultado encontrado", "info")
    }
  })
  
  # Generate Recommendations
  observeEvent(input$btn_generate_recommendations, {
    create_toast("Gerando recomendações...", "info")
    
    # Use a dummy user ID for demo purposes
    user_id <- session$token %||% "demo_user"
    
    recommendations <- generate_recommendations(
      user_id = user_id,
      exclude_seen = input$exclude_seen_docs,
      max_results = input$max_recommendations
    )
    
    if (length(recommendations) > 0) {
      output$recommendations_list <- renderUI({
        rec_cards <- lapply(recommendations, function(rec) {
          div(
            class = "card mb-2",
            div(
              class = "card-body",
              h6(class = "card-title", rec$title %||% "Documento"),
              p(class = "card-text", rec$snippet %||% "Sem descrição disponível"),
              div(
                class = "d-flex justify-content-between",
                tags$small(
                  span(class = "badge bg-success", paste("Score:", round(rec$final_score, 3))),
                  " ",
                  span(class = "badge bg-secondary", rec$type %||% "Documento")
                ),
                tags$small(class = "text-muted", rec$explanation %||% "")
              )
            )
          )
        })
        
        div(
          h6(paste("Geradas", length(recommendations), "recomendações")),
          rec_cards
        )
      })
      
      create_toast(paste("Recomendações geradas:", length(recommendations)), "success")
    } else {
      output$recommendations_list <- renderUI({
        div(
          class = "alert alert-info",
          "Nenhuma recomendação disponível no momento"
        )
      })
      create_toast("Nenhuma recomendação gerada", "info")
    }
  })
  
  # Update Knowledge Graph
  observeEvent(input$btn_update_knowledge_graph, {
    create_toast("Atualizando grafo de conhecimento...", "info")
    
    kg_data <- query_knowledge_graph(
      entity_type = if(input$kg_entity_type != "") input$kg_entity_type else NULL,
      relationship_type = if(input$kg_relationship_type != "") input$kg_relationship_type else NULL,
      min_confidence = input$kg_confidence_threshold
    )
    
    if (nrow(kg_data$nodes) > 0) {
      # Create knowledge graph visualization
      kg_viz <- create_graph_visualization(kg_data)
      
      output$knowledge_graph_viz <- renderUI({
        if (!is.null(kg_viz)) {
          kg_viz
        } else {
          div(
            class = "alert alert-info text-center",
            icon("network-wired", class = "fa-3x text-muted mb-3"),
            h5("Grafo de Conhecimento"),
            p("Visualização do grafo será exibida aqui")
          )
        }
      })
      
      output$knowledge_graph_stats <- renderUI({
        div(
          h6("Estatísticas do Grafo"),
          p(paste("Entidades:", nrow(kg_data$nodes))),
          p(paste("Relações:", nrow(kg_data$edges))),
          p(paste("Densidade:", round(nrow(kg_data$edges) / (nrow(kg_data$nodes) * (nrow(kg_data$nodes) - 1)), 4)))
        )
      })
      
      create_toast("Grafo de conhecimento atualizado", "success")
    } else {
      output$knowledge_graph_viz <- renderUI({
        div(
          class = "alert alert-info",
          "Nenhuma entidade encontrada com os filtros especificados"
        )
      })
      create_toast("Nenhuma entidade encontrada", "info")
    }
  })
  
  # AI Analytics Summaries
  output$ai_integration_summary <- renderUI({
    ai_stats <- get_ai_statistics()
    
    div(
      valueBox(
        value = ai_stats$total_requests,
        subtitle = "Requisições de IA",
        icon = icon("brain"),
        color = "primary"
      ),
      br(),
      valueBox(
        value = paste0(round(ai_stats$cache_hit_ratio * 100, 1), "%"),
        subtitle = "Taxa de Cache Hit",
        icon = icon("memory"),
        color = "success"
      )
    )
  })
  
  output$knowledge_graph_summary <- renderUI({
    kg_stats <- get_knowledge_graph_statistics()
    
    div(
      valueBox(
        value = kg_stats$nodes,
        subtitle = "Entidades",
        icon = icon("sitemap"),
        color = "info"
      ),
      br(),
      valueBox(
        value = kg_stats$edges,
        subtitle = "Relações",
        icon = icon("link"),
        color = "warning"
      )
    )
  })
  
  output$semantic_search_summary <- renderUI({
    semantic_stats <- get_semantic_search_statistics()
    
    div(
      valueBox(
        value = semantic_stats$indexed_documents,
        subtitle = "Documentos Indexados",
        icon = icon("search"),
        color = "secondary"
      ),
      br(),
      valueBox(
        value = semantic_stats$indexed_chunks,
        subtitle = "Chunks Indexados",
        icon = icon("puzzle-piece"),
        color = "dark"
      )
    )
  })
  
  output$semantic_search_stats <- renderUI({
    semantic_stats <- get_semantic_search_statistics()
    
    div(
      h6("Estatísticas da Busca Semântica"),
      p(paste("Documentos indexados:", semantic_stats$indexed_documents)),
      p(paste("Chunks indexados:", semantic_stats$indexed_chunks)),
      p(paste("Dimensão dos embeddings:", semantic_stats$embedding_dimension)),
      p(paste("Limite de similaridade:", semantic_stats$similarity_threshold)),
      p(paste("Última atualização:", format(semantic_stats$last_index_update %||% Sys.time(), "%d/%m/%Y %H:%M")))
    )
  })
  
  output$recommendation_stats <- renderUI({
    rec_stats <- get_recommendation_statistics()
    
    div(
      h6("Estatísticas de Recomendação"),
      p(paste("Usuários totais:", rec_stats$total_users)),
      p(paste("Interações totais:", rec_stats$total_interactions)),
      p(paste("Documentos populares:", rec_stats$popular_documents)),
      p(paste("Algoritmos ativos:", rec_stats$algorithms_enabled)),
      p(paste("Última atualização:", format(rec_stats$last_updated, "%d/%m/%Y %H:%M")))
    )
  })
  
  # ========================================================================
  # SESSION MANAGEMENT
  # ========================================================================
  
  # Cleanup on session end
  session$onSessionEnded(function() {
    cat("🛑 Sessão encerrada\n")
  })
}

# ============================================================================
# RUN APPLICATION
# ============================================================================

# Configure application options
options(
  shiny.port = app_config$app$port,
  shiny.host = app_config$app$host,
  shiny.autoreload = config_env == "development"
)

# Run the application
shinyApp(ui = ui, server = server)