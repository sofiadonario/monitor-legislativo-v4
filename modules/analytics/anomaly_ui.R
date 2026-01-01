# ==============================================================================
# ANOMALY DETECTION UI MODULE
# ==============================================================================
# Shiny UI components for anomaly detection dashboard.
#
# Features:
# - Multiple anomaly type selection
# - Sensitivity controls
# - Detection method selector
# - Interactive visualizations (plotly)
# - Data table displays (DT)
# - Export functionality
#
# Author: Monitor Legislativo v4 - Data Science Team
# Date: 2025-11-13
# ==============================================================================

library(shiny)
library(bslib)
library(plotly)
library(DT)

# shinyWidgets is optional
SHINYWIDGETS_AVAILABLE <- requireNamespace("shinyWidgets", quietly = TRUE)
if (SHINYWIDGETS_AVAILABLE) {
  library(shinyWidgets)
}

# Helper for optional pickerInput - falls back to selectInput if shinyWidgets not available
safe_pickerInput <- function(inputId, label, choices, selected = NULL, multiple = FALSE, options = list(), ...) {
  if (SHINYWIDGETS_AVAILABLE) {
    shinyWidgets::pickerInput(
      inputId = inputId,
      label = label,
      choices = choices,
      selected = selected,
      multiple = multiple,
      options = options,
      ...
    )
  } else {
    selectInput(
      inputId = inputId,
      label = label,
      choices = choices,
      selected = selected,
      multiple = multiple
    )
  }
}

#' Anomaly Detection UI Module
#'
#' Creates the UI for the anomaly detection dashboard.
#'
#' @param id Character string. Module namespace ID.
#'
#' @return UI elements for anomaly detection module.
#'
#' @import shiny
#' @import shinyWidgets
#' @import bslib
#'
#' @export
anomalyUI <- function(id) {
  ns <- NS(id)

  tagList(
    # Custom CSS for styling
    tags$head(
      tags$style(HTML("
        .anomaly-card {
          border-left: 4px solid #3498db;
          transition: all 0.3s ease;
        }
        .anomaly-card:hover {
          box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .severity-high {
          border-left-color: #e74c3c !important;
          background-color: #fff5f5;
        }
        .severity-medium {
          border-left-color: #f39c12 !important;
          background-color: #fffbf0;
        }
        .severity-low {
          border-left-color: #f1c40f !important;
          background-color: #fffef0;
        }
        .stat-box {
          text-align: center;
          padding: 15px;
          border-radius: 8px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          margin-bottom: 10px;
        }
        .stat-value {
          font-size: 2em;
          font-weight: bold;
          margin: 0;
        }
        .stat-label {
          font-size: 0.9em;
          opacity: 0.9;
          margin-top: 5px;
        }
        .control-panel {
          background-color: #f8f9fa;
          padding: 20px;
          border-radius: 8px;
          margin-bottom: 20px;
        }
        .anomaly-explanation {
          background-color: #e8f4f8;
          padding: 10px;
          border-radius: 5px;
          margin-top: 10px;
          font-size: 0.9em;
        }
      "))
    ),

    # Page Title
    div(
      class = "page-header",
      h2(
        icon("exclamation-triangle"),
        "Detecção de Anomalias",
        style = "color: #2c3e50; margin-bottom: 5px;"
      ),
      p(
        "Sistema avançado para identificação de padrões anômalos em dados legislativos",
        style = "color: #7f8c8d; margin-bottom: 20px;"
      )
    ),

    # Quick Stats Row
    fluidRow(
      column(3,
        div(class = "stat-box",
          p(class = "stat-value", textOutput(ns("stat_total_anomalies"))),
          p(class = "stat-label", "Total de Anomalias")
        )
      ),
      column(3,
        div(class = "stat-box", style = "background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);",
          p(class = "stat-value", textOutput(ns("stat_high_severity"))),
          p(class = "stat-label", "Alta Gravidade")
        )
      ),
      column(3,
        div(class = "stat-box", style = "background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);",
          p(class = "stat-value", textOutput(ns("stat_anomaly_rate"))),
          p(class = "stat-label", "Taxa de Anomalias")
        )
      ),
      column(3,
        div(class = "stat-box", style = "background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);",
          p(class = "stat-value", textOutput(ns("stat_last_updated"))),
          p(class = "stat-label", "Última Atualização")
        )
      )
    ),

    # Control Panel
    div(
      class = "control-panel",
      fluidRow(
        column(4,
          safe_pickerInput(
            inputId = ns("anomaly_type"),
            label = tags$b("Tipo de Anomalia"),
            choices = list(
              "Volume" = "volume",
              "Texto" = "text",
              "Temporal" = "temporal",
              "Jurisdicional" = "jurisdictional",
              "Multivariada" = "multivariate"
            ),
            selected = "volume",
            multiple = FALSE,
            options = list(
              `style` = "btn-primary",
              `live-search` = TRUE
            )
          )
        ),
        column(4,
          selectInput(
            inputId = ns("detection_method"),
            label = tags$b("Método de Detecção"),
            choices = list(
              "IQR (Interquartile Range)" = "iqr",
              "Z-Score" = "zscore",
              "Poisson" = "poisson",
              "Ensemble (Todos)" = "all",
              "STL Decomposition" = "stl",
              "ARIMA" = "arima",
              "Isolation Forest" = "isolation_forest"
            ),
            selected = "iqr"
          )
        ),
        column(4,
          sliderInput(
            inputId = ns("sensitivity"),
            label = tags$b("Sensibilidade"),
            min = 1,
            max = 5,
            value = 1.5,
            step = 0.1,
            post = "×"
          )
        )
      ),
      fluidRow(
        column(4,
          selectInput(
            inputId = ns("time_granularity"),
            label = tags$b("Granularidade Temporal"),
            choices = list(
              "Diária" = "day",
              "Semanal" = "week",
              "Mensal" = "month",
              "Anual" = "year"
            ),
            selected = "month"
          )
        ),
        column(4,
          dateRangeInput(
            inputId = ns("date_range"),
            label = tags$b("Período de Análise"),
            start = Sys.Date() - 365,
            end = Sys.Date(),
            format = "dd/mm/yyyy",
            language = "pt-BR",
            separator = "até"
          )
        ),
        column(4,
          selectInput(
            inputId = ns("severity_filter"),
            label = tags$b("Filtrar por Gravidade"),
            choices = list(
              "Todas" = "all",
              "Alta" = "high",
              "Média" = "medium",
              "Baixa" = "low"
            ),
            selected = "all",
            multiple = TRUE
          )
        )
      ),
      fluidRow(
        column(12,
          div(
            style = "text-align: center; margin-top: 10px;",
            actionButton(
              inputId = ns("run_detection"),
              label = "Executar Detecção",
              icon = icon("play"),
              class = "btn-primary btn-lg",
              style = "margin-right: 10px;"
            ),
            actionButton(
              inputId = ns("reset_filters"),
              label = "Limpar Filtros",
              icon = icon("undo"),
              class = "btn-secondary"
            ),
            downloadButton(
              outputId = ns("download_report"),
              label = "Exportar Relatório",
              class = "btn-success",
              style = "margin-left: 10px;"
            )
          )
        )
      )
    ),

    # Main Content Tabs
    tabsetPanel(
      id = ns("main_tabs"),
      type = "pills",

      # Overview Tab
      tabPanel(
        title = tagList(icon("chart-line"), "Visão Geral"),
        value = "overview",
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Distribuição de Anomalias ao Longo do Tempo"),
              card_body(
                plotlyOutput(ns("timeline_plot"), height = "400px")
              )
            )
          )
        ),
        br(),
        fluidRow(
          column(6,
            card(
              card_header("Anomalias por Gravidade"),
              card_body(
                plotlyOutput(ns("severity_distribution"), height = "300px")
              )
            )
          ),
          column(6,
            card(
              card_header("Top 10 Anomalias"),
              card_body(
                plotlyOutput(ns("top_anomalies_chart"), height = "300px")
              )
            )
          )
        )
      ),

      # Volume Anomalies Tab
      tabPanel(
        title = tagList(icon("chart-bar"), "Anomalias de Volume"),
        value = "volume",
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Detecção de Anomalias de Volume"),
              card_body(
                plotlyOutput(ns("volume_anomaly_plot"), height = "400px")
              )
            )
          )
        ),
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Tabela de Anomalias de Volume"),
              card_body(
                DTOutput(ns("volume_anomaly_table"))
              )
            )
          )
        )
      ),

      # Text Anomalies Tab
      tabPanel(
        title = tagList(icon("file-alt"), "Anomalias de Texto"),
        value = "text",
        br(),
        fluidRow(
          column(6,
            card(
              card_header("Distribuição de Comprimento de Texto"),
              card_body(
                plotlyOutput(ns("text_length_dist"), height = "300px")
              )
            )
          ),
          column(6,
            card(
              card_header("Diversidade Lexical"),
              card_body(
                plotlyOutput(ns("lexical_diversity_plot"), height = "300px")
              )
            )
          )
        ),
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Documentos com Anomalias Textuais"),
              card_body(
                DTOutput(ns("text_anomaly_table"))
              )
            )
          )
        )
      ),

      # Temporal Anomalies Tab
      tabPanel(
        title = tagList(icon("clock"), "Anomalias Temporais"),
        value = "temporal",
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Decomposição Temporal (STL)"),
              card_body(
                plotlyOutput(ns("stl_decomposition"), height = "500px")
              )
            )
          )
        ),
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Pontos de Mudança Detectados"),
              card_body(
                plotlyOutput(ns("changepoint_plot"), height = "350px")
              )
            )
          )
        ),
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Tabela de Anomalias Temporais"),
              card_body(
                DTOutput(ns("temporal_anomaly_table"))
              )
            )
          )
        )
      ),

      # Jurisdictional Anomalies Tab
      tabPanel(
        title = tagList(icon("map-marked-alt"), "Anomalias Jurisdicionais"),
        value = "jurisdictional",
        br(),
        fluidRow(
          column(6,
            card(
              card_header("Estados com Anomalias"),
              card_body(
                plotlyOutput(ns("state_anomalies_map"), height = "400px")
              )
            )
          ),
          column(6,
            card(
              card_header("Métricas por Jurisdição"),
              card_body(
                plotlyOutput(ns("jurisdiction_metrics"), height = "400px")
              )
            )
          )
        ),
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Ranking de Jurisdições Anômalas"),
              card_body(
                DTOutput(ns("jurisdiction_anomaly_table"))
              )
            )
          )
        )
      ),

      # Detailed Analysis Tab
      tabPanel(
        title = tagList(icon("microscope"), "Análise Detalhada"),
        value = "detailed",
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Seleção de Anomalia para Análise"),
              card_body(
                fluidRow(
                  column(6,
                    uiOutput(ns("anomaly_selector"))
                  ),
                  column(6,
                    div(
                      style = "padding: 10px; background-color: #f8f9fa; border-radius: 5px;",
                      h5("Informações da Anomalia", style = "margin-top: 0;"),
                      textOutput(ns("anomaly_score_display")),
                      br(),
                      textOutput(ns("anomaly_severity_display")),
                      br(),
                      div(
                        class = "anomaly-explanation",
                        textOutput(ns("anomaly_explanation"))
                      )
                    )
                  )
                )
              )
            )
          )
        ),
        br(),
        fluidRow(
          column(6,
            card(
              card_header("Contexto Histórico"),
              card_body(
                plotlyOutput(ns("historical_context_plot"), height = "300px")
              )
            )
          ),
          column(6,
            card(
              card_header("Características da Anomalia"),
              card_body(
                plotlyOutput(ns("anomaly_features_radar"), height = "300px")
              )
            )
          )
        ),
        br(),
        fluidRow(
          column(12,
            card(
              card_header("Anomalias Similares"),
              card_body(
                DTOutput(ns("similar_anomalies_table"))
              )
            )
          )
        )
      ),

      # Settings & Help Tab
      tabPanel(
        title = tagList(icon("cog"), "Configurações"),
        value = "settings",
        br(),
        fluidRow(
          column(6,
            card(
              card_header("Configurações de Detecção"),
              card_body(
                checkboxGroupInput(
                  inputId = ns("enabled_methods"),
                  label = "Métodos Habilitados",
                  choices = list(
                    "Volume" = "volume",
                    "Texto" = "text",
                    "Temporal" = "temporal",
                    "Jurisdicional" = "jurisdictional"
                  ),
                  selected = c("volume", "text", "temporal", "jurisdictional")
                ),
                hr(),
                sliderInput(
                  inputId = ns("min_anomaly_score"),
                  label = "Pontuação Mínima para Exibição",
                  min = 0,
                  max = 100,
                  value = 40,
                  post = " pts"
                ),
                hr(),
                numericInput(
                  inputId = ns("max_results"),
                  label = "Máximo de Resultados",
                  value = 100,
                  min = 10,
                  max = 1000,
                  step = 10
                )
              )
            )
          ),
          column(6,
            card(
              card_header("Ajuda e Documentação"),
              card_body(
                h5("Métodos de Detecção"),
                tags$ul(
                  tags$li(tags$b("IQR:"), "Detecta valores além de Q1 - 1.5×IQR ou Q3 + 1.5×IQR"),
                  tags$li(tags$b("Z-Score:"), "Identifica valores com |Z| > 3 (ou sensibilidade configurada)"),
                  tags$li(tags$b("Poisson:"), "Compara com distribuição de Poisson esperada"),
                  tags$li(tags$b("STL:"), "Decomposição sazonal para detectar anomalias temporais"),
                  tags$li(tags$b("Isolation Forest:"), "Algoritmo de ML para anomalias multivariadas")
                ),
                hr(),
                h5("Interpretação de Gravidade"),
                tags$ul(
                  tags$li(tags$span("Alta:", style = "color: #e74c3c; font-weight: bold;"), " Pontuação ≥ 80"),
                  tags$li(tags$span("Média:", style = "color: #f39c12; font-weight: bold;"), " Pontuação 60-79"),
                  tags$li(tags$span("Baixa:", style = "color: #f1c40f; font-weight: bold;"), " Pontuação 40-59")
                ),
                hr(),
                actionButton(
                  inputId = ns("show_help"),
                  label = "Documentação Completa",
                  icon = icon("book"),
                  class = "btn-info btn-sm"
                )
              )
            )
          )
        )
      )
    ),

    # Footer
    br(),
    hr(),
    div(
      style = "text-align: center; color: #7f8c8d; font-size: 0.9em;",
      p("Sistema de Detecção de Anomalias - Monitor Legislativo v4"),
      p("Desenvolvido com R, Shiny, e métodos estatísticos avançados")
    )
  )
}

# ==============================================================================
# END OF FILE
# ==============================================================================
