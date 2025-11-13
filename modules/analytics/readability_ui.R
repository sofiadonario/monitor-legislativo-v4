# ==============================================================================
# READABILITY DASHBOARD UI MODULE
# ==============================================================================
# Interactive analytics dashboard for legislative document readability analysis
#
# Features:
# - Comprehensive filter panel (year, document type, level, branch, court)
# - Real-time statistics (Flesch-Kincaid, FOG, SMOG, document count)
# - Interactive visualizations (distributions, comparisons, trends)
# - Downloadable data tables with CSV export
# - WCAG 2.1 AA compliant design
#
# Author: Monitor Legislativo v4
# Date: 2025-11-12
# Language: Portuguese (PT-BR)
# ==============================================================================

#' Readability Dashboard UI Module
#'
#' Creates the user interface for the Readability Analytics dashboard.
#'
#' @param id Character string. Module namespace ID.
#' @return Shiny UI tagList with complete dashboard interface.
#'
#' @import shiny
#' @import bslib
#' @import plotly
#' @import DT
#'
#' @export
readabilityUI <- function(id) {
  ns <- NS(id)

  tagList(
    # Custom CSS for enhanced readability dashboard
    tags$head(
      tags$style(HTML("
        .readability-value-box {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 20px;
          border-radius: 8px;
          text-align: center;
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
          margin-bottom: 15px;
          transition: transform 0.2s ease;
        }

        .readability-value-box:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }

        .readability-value-box.flesch {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .readability-value-box.fog {
          background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .readability-value-box.smog {
          background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }

        .readability-value-box.count {
          background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }

        .readability-value-box h2 {
          font-size: 42px;
          font-weight: 700;
          margin: 10px 0;
        }

        .readability-value-box p {
          font-size: 14px;
          margin: 5px 0;
          opacity: 0.9;
        }

        .readability-value-box small {
          font-size: 11px;
          opacity: 0.7;
        }

        .readability-filter-panel {
          background-color: #f8f9fa;
          padding: 20px;
          border-radius: 8px;
          margin-bottom: 20px;
        }

        .readability-viz-card {
          background: white;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          margin-bottom: 20px;
        }

        .readability-viz-card h4 {
          color: #2c3e50;
          font-weight: 600;
          margin-bottom: 15px;
          border-bottom: 2px solid #667eea;
          padding-bottom: 10px;
        }

        .readability-tooltip {
          cursor: help;
          text-decoration: underline dotted;
          color: #667eea;
        }

        .readability-legend {
          background-color: #f0f4f8;
          padding: 15px;
          border-left: 4px solid #667eea;
          border-radius: 4px;
          margin-bottom: 20px;
        }

        .readability-legend h5 {
          color: #2c3e50;
          font-weight: 600;
          margin-top: 0;
        }

        .readability-legend ul {
          margin: 10px 0;
          padding-left: 20px;
        }

        .readability-legend li {
          margin: 5px 0;
          color: #4a5568;
        }
      "))
    ),

    # Dashboard Header
    fluidRow(
      column(12,
        div(
          style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                   color: white; padding: 30px; border-radius: 8px;
                   margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);",
          h2(icon("book-reader"), " Análise de Legibilidade",
             style = "margin: 0; font-weight: 700;"),
          p("Avaliação da complexidade e acessibilidade de documentos legislativos brasileiros",
            style = "margin: 10px 0 0 0; font-size: 16px; opacity: 0.95;")
        )
      )
    ),

    # Main Layout: Sidebar + Content
    fluidRow(
      # LEFT SIDEBAR: Filters
      column(3,
        div(class = "readability-filter-panel",
          h4(icon("filter"), " Filtros de Pesquisa",
             style = "color: #2c3e50; font-weight: 600; margin-top: 0;"),

          # Year Selector
          selectInput(
            ns("filter_ano"),
            label = tags$span(
              "Ano",
              tags$span(
                icon("info-circle"),
                class = "readability-tooltip",
                title = "Filtre documentos por ano de publicação"
              )
            ),
            choices = NULL,  # Populated dynamically by server
            selected = NULL,
            multiple = TRUE
          ),

          # Document Type Selector
          selectInput(
            ns("filter_tipo"),
            label = tags$span(
              "Tipo de Documento",
              tags$span(
                icon("info-circle"),
                class = "readability-tooltip",
                title = "Selecione tipos específicos de documentos legislativos"
              )
            ),
            choices = NULL,  # Populated dynamically
            selected = NULL,
            multiple = TRUE
          ),

          # Administrative Level Selector
          selectInput(
            ns("filter_nivel"),
            label = tags$span(
              "Nível Administrativo",
              tags$span(
                icon("info-circle"),
                class = "readability-tooltip",
                title = "Federal, Estadual ou Municipal"
              )
            ),
            choices = c("Todos" = "all",
                       "Federal" = "federal",
                       "Estadual" = "estadual",
                       "Municipal" = "municipal"),
            selected = "all"
          ),

          # Power Branch Selector
          selectInput(
            ns("filter_poder"),
            label = tags$span(
              "Poder",
              tags$span(
                icon("info-circle"),
                class = "readability-tooltip",
                title = "Executivo, Legislativo ou Judiciário"
              )
            ),
            choices = NULL,  # Populated dynamically
            selected = NULL,
            multiple = TRUE
          ),

          # Court Type Selector (for Judicial branch)
          conditionalPanel(
            condition = sprintf("input['%s'].includes('judiciario')", ns("filter_poder")),
            selectInput(
              ns("filter_corte"),
              label = tags$span(
                "Tipo de Corte",
                tags$span(
                  icon("info-circle"),
                  class = "readability-tooltip",
                  title = "Tribunais e cortes judiciais específicas"
                )
              ),
              choices = NULL,  # Populated dynamically
              selected = NULL,
              multiple = TRUE
            )
          ),

          hr(style = "margin: 20px 0;"),

          # Action Buttons
          div(style = "text-align: center;",
            actionButton(
              ns("apply_filters"),
              "Aplicar Filtros",
              icon = icon("search"),
              class = "btn-primary btn-block",
              style = "margin-bottom: 10px; font-weight: 600;"
            ),
            actionButton(
              ns("reset_filters"),
              "Limpar Tudo",
              icon = icon("times"),
              class = "btn-secondary btn-block",
              style = "font-weight: 600;"
            )
          ),

          hr(style = "margin: 20px 0;"),

          # Filter Status Indicator
          uiOutput(ns("filter_status"))
        )
      ),

      # RIGHT CONTENT: Visualizations and Statistics
      column(9,

        # KEY STATISTICS ROW
        fluidRow(
          column(3,
            div(class = "readability-value-box flesch",
              icon("book-open", style = "font-size: 24px; opacity: 0.8;"),
              h2(textOutput(ns("stat_flesch"), inline = TRUE)),
              p("Flesch-Kincaid"),
              tags$small(
                tags$span(
                  icon("info-circle"),
                  class = "readability-tooltip",
                  title = "Pontuação de 0-100. Valores maiores = textos mais fáceis de ler.
                           60+ = acessível, 30-60 = médio, <30 = difícil"
                ),
                " Média"
              )
            )
          ),
          column(3,
            div(class = "readability-value-box fog",
              icon("graduation-cap", style = "font-size: 24px; opacity: 0.8;"),
              h2(textOutput(ns("stat_fog"), inline = TRUE)),
              p("Índice FOG"),
              tags$small(
                tags$span(
                  icon("info-circle"),
                  class = "readability-tooltip",
                  title = "Anos de educação necessários para compreender o texto.
                           Valores menores indicam maior acessibilidade. 7-8 = ideal"
                ),
                " Anos"
              )
            )
          ),
          column(3,
            div(class = "readability-value-box smog",
              icon("user-graduate", style = "font-size: 24px; opacity: 0.8;"),
              h2(textOutput(ns("stat_smog"), inline = TRUE)),
              p("Índice SMOG"),
              tags$small(
                tags$span(
                  icon("info-circle"),
                  class = "readability-tooltip",
                  title = "Grau de escolaridade necessário. Similar ao FOG,
                           mas mais preciso para textos complexos"
                ),
                " Grau"
              )
            )
          ),
          column(3,
            div(class = "readability-value-box count",
              icon("file-alt", style = "font-size: 24px; opacity: 0.8;"),
              h2(textOutput(ns("stat_count"), inline = TRUE)),
              p("Documentos"),
              tags$small(
                tags$span(
                  icon("info-circle"),
                  class = "readability-tooltip",
                  title = "Total de documentos analisados com métricas de legibilidade"
                ),
                " Analisados"
              )
            )
          )
        ),

        # READABILITY INTERPRETATION LEGEND
        fluidRow(
          column(12,
            div(class = "readability-legend",
              h5(icon("lightbulb"), " Guia de Interpretação"),
              tags$ul(
                tags$li(tags$strong("Flesch-Kincaid 90-100:"), " Muito fácil (5ª série)"),
                tags$li(tags$strong("Flesch-Kincaid 60-70:"), " Padrão (8ª-9ª série)"),
                tags$li(tags$strong("Flesch-Kincaid 0-30:"), " Muito difícil (universitário)"),
                tags$li(tags$strong("FOG/SMOG < 10:"), " Acessível ao público geral"),
                tags$li(tags$strong("FOG/SMOG > 15:"), " Requer formação técnica/superior")
              )
            )
          )
        ),

        # VISUALIZATION 1: Distribution Histogram
        fluidRow(
          column(12,
            div(class = "readability-viz-card",
              h4(icon("chart-bar"), " Distribuição de Legibilidade por Tipo de Documento"),
              plotlyOutput(ns("plot_distribution"), height = "400px") %>%
                shinycssloaders::withSpinner(type = 6, color = "#667eea")
            )
          )
        ),

        # VISUALIZATION 2: Box Plot Comparison
        fluidRow(
          column(12,
            div(class = "readability-viz-card",
              h4(icon("layer-group"), " Comparação por Nível Administrativo"),
              plotlyOutput(ns("plot_boxplot"), height = "400px") %>%
                shinycssloaders::withSpinner(type = 6, color = "#764ba2")
            )
          )
        ),

        # VISUALIZATION 3: Time Series Trend
        fluidRow(
          column(12,
            div(class = "readability-viz-card",
              h4(icon("chart-line"), " Evolução Temporal da Legibilidade"),
              plotlyOutput(ns("plot_timeseries"), height = "400px") %>%
                shinycssloaders::withSpinner(type = 6, color = "#f093fb")
            )
          )
        ),

        # VISUALIZATION 4: Scatter Plot (Length vs Readability)
        fluidRow(
          column(12,
            div(class = "readability-viz-card",
              h4(icon("project-diagram"), " Comprimento do Documento vs. Legibilidade"),
              plotlyOutput(ns("plot_scatter"), height = "400px") %>%
                shinycssloaders::withSpinner(type = 6, color = "#4facfe")
            )
          )
        ),

        # DATA TABLE: Top/Bottom Documents
        fluidRow(
          column(12,
            div(class = "readability-viz-card",
              h4(icon("table"), " Documentos Mais e Menos Legíveis"),
              p("Explore os 20 documentos com maior e menor pontuação Flesch-Kincaid",
                style = "color: #718096; font-size: 14px; margin-bottom: 15px;"),

              # Toggle between Most/Least readable
              radioButtons(
                ns("table_mode"),
                label = "Visualizar:",
                choices = c("Mais Legíveis (Maior Pontuação)" = "top",
                           "Menos Legíveis (Menor Pontuação)" = "bottom"),
                selected = "top",
                inline = TRUE
              ),

              # Download Button
              downloadButton(
                ns("download_data"),
                "Baixar Dados (CSV)",
                class = "btn-success btn-sm",
                style = "margin-bottom: 15px;"
              ),

              # Data Table
              DT::dataTableOutput(ns("table_documents")) %>%
                shinycssloaders::withSpinner(type = 6, color = "#43e97b")
            )
          )
        )
      )
    )
  )
}

# ==============================================================================
# HELPER FUNCTION: Create Tooltip with Info Icon
# ==============================================================================

#' Create an informative tooltip for UI elements
#'
#' @param label Character. Label text
#' @param tooltip Character. Tooltip message
#' @return HTML span with label and tooltip icon
create_tooltip_label <- function(label, tooltip) {
  tags$span(
    label,
    tags$span(
      icon("info-circle"),
      class = "readability-tooltip",
      title = tooltip,
      style = "margin-left: 5px; cursor: help;"
    )
  )
}
