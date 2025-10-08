# System Monitoring Tab UI
# Monitor Legislativo v4 - System Health and Performance Monitoring
# ==================================================================

fluidRow(
  column(12,
    h2("⚙️ Monitoramento do Sistema"),
    p("Monitoramento em tempo real da saúde do sistema, performance e métricas operacionais.", 
      style = "color: #7f8c8d; margin-bottom: 30px;")
  )
),

# System Status Overview - DISABLED (all outputs orphaned, no server code)
# TEMPORARILY DISABLED - Testing crash fix
# fluidRow(
#   column(3,
#     valueBoxOutput("monitoring_system_status", width = 12)
#   ),
#   column(3,
#     valueBoxOutput("monitoring_database_status", width = 12)
#   ),
#   column(3,
#     valueBoxOutput("monitoring_active_users", width = 12)
#   ),
#   column(3,
#     valueBoxOutput("monitoring_response_time", width = 12)
#   )
# ),

fluidRow(
  column(12,
    div(
      class = "alert alert-info",
      style = "margin: 20px;",
      icon("info-circle"),
      strong(" Sistema de Monitoramento em Desenvolvimento"),
      p("As métricas de monitoramento do sistema serão implementadas em breve.", style = "margin-top: 10px;")
    )
  )
),

# Performance Metrics - DISABLED (orphaned plotly outputs)
# TEMPORARILY DISABLED - Testing crash fix
# fluidRow(
#   column(6,
#     box(
#       title = "Performance do Sistema",
#       status = "primary",
#       solidHeader = TRUE,
#       width = 12,
#       plotlyOutput("monitoring_performance_chart", height = "300px")
#     )
#   ),
#   column(6,
#     box(
#       title = "Uso de Recursos",
#       status = "info",
#       solidHeader = TRUE,
#       width = 12,
#       plotlyOutput("monitoring_resources_chart", height = "300px")
#     )
#   )
# ),

# Database and Cache Monitoring - DISABLED (orphaned uiOutputs)
# TEMPORARILY DISABLED - Testing crash fix
# fluidRow(
#   column(6,
#     box(
#       title = "Monitoramento da Base de Dados",
#       status = "success",
#       solidHeader = TRUE,
#       width = 12,
#       uiOutput("monitoring_database_info"),
#       br(),
#       actionButton(
#         inputId = "monitoring_refresh_db",
#         label = "Atualizar Status",
#         icon = icon("refresh"),
#         class = "btn-info"
#       )
#     )
#   ),
#   column(6,
#     box(
#       title = "Cache e Performance",
#       status = "warning",
#       solidHeader = TRUE,
#       width = 12,
#       uiOutput("monitoring_cache_info"),
#       br(),
#       actionButton(
#         inputId = "monitoring_clear_cache",
#         label = "Limpar Cache",
#         icon = icon("broom"),
#         class = "btn-warning"
#       )
#     )
#   )
# ),

# System Logs and Alerts - DISABLED (orphaned outputs)
# TEMPORARILY DISABLED - Testing crash fix
# fluidRow(
#   column(12,
#     box(
#       title = "Logs do Sistema e Alertas",
#       status = "danger",
#       solidHeader = TRUE,
#       width = 12,
#       tabsetPanel(
#         type = "tabs",
#         tabPanel(
#           title = "Logs Recentes",
#           br(),
#           DT::dataTableOutput("monitoring_recent_logs")
#         ),
#         tabPanel(
#           title = "Alertas",
#           br(),
#           uiOutput("monitoring_alerts")
#         ),
#         tabPanel(
#           title = "Métricas Detalhadas",
#           br(),
#           verbatimTextOutput("monitoring_detailed_metrics")
#         )
#       )
#     )
#   )
# )