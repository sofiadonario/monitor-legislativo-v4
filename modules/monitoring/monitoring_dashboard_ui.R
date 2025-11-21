# =============================================================================
# Monitoring Dashboard UI
# =============================================================================
# Monitor Legislativo v4 - Phase 5 Task 5.4
#
# Visual dashboard for monitoring application health, performance metrics,
# database status, and system resources in real-time.
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# =============================================================================

#' Monitoring Dashboard UI
#'
#' Creates the UI for the monitoring dashboard with real-time metrics
#'
#' @param id Module ID
#' @return Shiny UI
#' @export
monitoringDashboardUI <- function(id) {
  ns <- NS(id)

  tagList(
    # Custom CSS for monitoring dashboard
    tags$head(
      tags$style(HTML("
        .metric-card {
          background: white;
          border-radius: 8px;
          padding: 20px;
          margin: 10px 0;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .metric-value {
          font-size: 2.5em;
          font-weight: bold;
          margin: 10px 0;
        }

        .metric-label {
          font-size: 0.9em;
          color: #666;
          text-transform: uppercase;
        }

        .status-healthy {
          color: #28a745;
        }

        .status-degraded {
          color: #ffc107;
        }

        .status-unhealthy {
          color: #dc3545;
        }

        .alert-item {
          padding: 10px;
          margin: 5px 0;
          border-left: 4px solid;
          background: #f8f9fa;
        }

        .alert-critical {
          border-left-color: #dc3545;
        }

        .alert-warning {
          border-left-color: #ffc107;
        }

        .alert-info {
          border-left-color: #17a2b8;
        }

        .refresh-indicator {
          font-size: 0.8em;
          color: #999;
          margin-left: 10px;
        }

        .chart-container {
          height: 300px;
          margin: 20px 0;
        }

        .log-viewer {
          background: #1e1e1e;
          color: #d4d4d4;
          padding: 15px;
          border-radius: 4px;
          font-family: 'Courier New', monospace;
          font-size: 12px;
          max-height: 400px;
          overflow-y: auto;
        }

        .log-error {
          color: #f48771;
        }

        .log-warning {
          color: #dcdcaa;
        }

        .log-info {
          color: #4ec9b0;
        }
      "))
    ),

    fluidPage(
      # Page header
      fluidRow(
        column(
          12,
          h2(
            icon("chart-line"),
            " Painel de Monitoramento",
            tags$span(
              id = ns("last_refresh"),
              class = "refresh-indicator",
              "Carregando..."
            )
          ),
          hr()
        )
      ),

      # Auto-refresh controls
      fluidRow(
        column(
          12,
          wellPanel(
            style = "background: #f8f9fa;",
            fluidRow(
              column(
                3,
                checkboxInput(
                  ns("auto_refresh"),
                  "Atualização Automática",
                  value = TRUE
                )
              ),
              column(
                3,
                sliderInput(
                  ns("refresh_interval"),
                  "Intervalo (segundos):",
                  min = 5,
                  max = 60,
                  value = 10,
                  step = 5
                )
              ),
              column(
                3,
                actionButton(
                  ns("refresh_now"),
                  "Atualizar Agora",
                  icon = icon("sync-alt"),
                  class = "btn-primary"
                )
              ),
              column(
                3,
                downloadButton(
                  ns("export_metrics"),
                  "Exportar Métricas",
                  class = "btn-secondary"
                )
              )
            )
          )
        )
      ),

      # Overall health status
      fluidRow(
        column(
          12,
          div(
            class = "metric-card",
            h3(icon("heartbeat"), " Status Geral do Sistema"),
            uiOutput(ns("overall_health"))
          )
        )
      ),

      # Key metrics
      fluidRow(
        column(
          3,
          div(
            class = "metric-card",
            div(class = "metric-label", "Tempo Ativo"),
            div(class = "metric-value", textOutput(ns("uptime")))
          )
        ),
        column(
          3,
          div(
            class = "metric-card",
            div(class = "metric-label", "Requisições Totais"),
            div(class = "metric-value", textOutput(ns("total_requests")))
          )
        ),
        column(
          3,
          div(
            class = "metric-card",
            div(class = "metric-label", "Taxa de Erro"),
            div(class = "metric-value", textOutput(ns("error_rate")))
          )
        ),
        column(
          3,
          div(
            class = "metric-card",
            div(class = "metric-label", "Tempo Resposta Médio"),
            div(class = "metric-value", textOutput(ns("avg_response_time")))
          )
        )
      ),

      # Detailed health checks
      fluidRow(
        column(
          6,
          div(
            class = "metric-card",
            h4(icon("database"), " Status do Banco de Dados"),
            uiOutput(ns("database_health"))
          )
        ),
        column(
          6,
          div(
            class = "metric-card",
            h4(icon("memory"), " Uso de Memória"),
            uiOutput(ns("memory_health"))
          )
        )
      ),

      # Performance charts
      fluidRow(
        column(
          6,
          div(
            class = "metric-card",
            h4(icon("chart-area"), " Requisições por Minuto"),
            div(class = "chart-container", plotly::plotlyOutput(ns("requests_chart")))
          )
        ),
        column(
          6,
          div(
            class = "metric-card",
            h4(icon("clock"), " Tempo de Resposta"),
            div(class = "chart-container", plotly::plotlyOutput(ns("response_time_chart")))
          )
        )
      ),

      # Active alerts
      fluidRow(
        column(
          12,
          div(
            class = "metric-card",
            h4(icon("exclamation-triangle"), " Alertas Ativos"),
            uiOutput(ns("active_alerts"))
          )
        )
      ),

      # Database connection pool
      fluidRow(
        column(
          6,
          div(
            class = "metric-card",
            h4(icon("network-wired"), " Pool de Conexões"),
            uiOutput(ns("connection_pool"))
          )
        ),
        column(
          6,
          div(
            class = "metric-card",
            h4(icon("server"), " Cache de Queries"),
            uiOutput(ns("query_cache_stats"))
          )
        )
      ),

      # Recent logs
      fluidRow(
        column(
          12,
          div(
            class = "metric-card",
            h4(icon("file-alt"), " Logs Recentes"),
            div(
              class = "log-viewer",
              uiOutput(ns("recent_logs"))
            )
          )
        )
      ),

      # Prometheus metrics
      fluidRow(
        column(
          12,
          div(
            class = "metric-card",
            h4(icon("chart-bar"), " Métricas Prometheus"),
            verbatimTextOutput(ns("prometheus_metrics"))
          )
        )
      )
    )
  )
}

cat("✅ Monitoring Dashboard UI loaded\n")
