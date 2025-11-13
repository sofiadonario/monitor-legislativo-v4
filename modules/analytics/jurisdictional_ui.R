# ==============================================================================
# MULTI-JURISDICTIONAL COMPARISON UI MODULE
# ==============================================================================
# Interactive Shiny UI for comparing legislative patterns across Brazilian
# jurisdictions (Federal, State, Municipal) and between individual states.
#
# Features:
# - Dynamic filters: year range, state selection, metric type
# - Three comparison modes: All Jurisdictions, State-to-State, Cross-Level
# - Interactive visualizations: bar charts, line charts, heatmaps, dendrograms, radar charts
# - CSV export functionality
# - WCAG 2.1 AA compliant design
#
# Author: Monitor Legislativo v4 - Data Science Team
# Date: 2025-11-13
# Language: Portuguese (PT-BR)
# ==============================================================================

#' Multi-Jurisdictional Comparison UI Module
#'
#' Creates the user interface for jurisdictional comparison analytics.
#'
#' @param id Character string. Module namespace ID.
#' @return Shiny UI tagList with complete dashboard interface.
#'
#' @import shiny
#' @import plotly
#' @import DT
#'
#' @export
jurisdictionalUI <- function(id) {
  ns <- NS(id)

  tagList(
    # Custom CSS for enhanced jurisdictional dashboard
    tags$head(
      tags$style(HTML("
        .jurisdictional-header {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 25px;
          border-radius: 8px;
          margin-bottom: 20px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .jurisdictional-header h2 {
          margin: 0 0 10px 0;
          font-weight: 700;
        }

        .jurisdictional-header p {
          margin: 0;
          opacity: 0.95;
          font-size: 15px;
        }

        .jurisdictional-stat-box {
          background: white;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          margin-bottom: 15px;
          border-left: 4px solid #667eea;
          transition: transform 0.2s ease;
        }

        .jurisdictional-stat-box:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }

        .jurisdictional-stat-box h3 {
          font-size: 32px;
          margin: 5px 0;
          color: #667eea;
          font-weight: 700;
        }

        .jurisdictional-stat-box p {
          margin: 0;
          color: #666;
          font-size: 14px;
        }

        .filter-panel {
          background: #f8f9fa;
          padding: 20px;
          border-radius: 8px;
          margin-bottom: 20px;
        }

        .comparison-mode-selector {
          display: flex;
          gap: 10px;
          margin-bottom: 20px;
          flex-wrap: wrap;
        }

        .comparison-mode-btn {
          flex: 1;
          min-width: 200px;
          padding: 15px;
          border: 2px solid #667eea;
          border-radius: 8px;
          background: white;
          cursor: pointer;
          transition: all 0.3s ease;
          text-align: center;
        }

        .comparison-mode-btn:hover {
          background: #667eea;
          color: white;
          transform: translateY(-2px);
        }

        .comparison-mode-btn.active {
          background: #667eea;
          color: white;
          font-weight: 600;
        }

        .viz-container {
          background: white;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          margin-bottom: 20px;
        }

        .viz-container h4 {
          margin-top: 0;
          color: #333;
          font-weight: 600;
          border-bottom: 2px solid #667eea;
          padding-bottom: 10px;
        }

        .state-selector-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
          gap: 8px;
          margin: 15px 0;
        }

        .state-checkbox {
          display: flex;
          align-items: center;
          padding: 8px;
          background: #f8f9fa;
          border-radius: 4px;
          font-size: 14px;
        }

        .export-buttons {
          display: flex;
          gap: 10px;
          flex-wrap: wrap;
          margin-top: 15px;
        }

        .info-box {
          background: #e3f2fd;
          border-left: 4px solid #2196f3;
          padding: 15px;
          border-radius: 4px;
          margin: 15px 0;
        }

        .info-box p {
          margin: 0;
          color: #1565c0;
        }
      "))
    ),

    # Header Section
    div(
      class = "jurisdictional-header",
      h2(icon("balance-scale"), " Comparação Multi-Jurisdicional"),
      p("Análise comparativa de padrões legislativos entre níveis jurisdicionais e estados brasileiros")
    ),

    # Quick Stats Row
    fluidRow(
      column(3,
        div(
          class = "jurisdictional-stat-box",
          h3(textOutput(ns("stat_total_jurisdictions"), inline = TRUE)),
          p(icon("landmark"), " Níveis Jurisdicionais")
        )
      ),
      column(3,
        div(
          class = "jurisdictional-stat-box",
          h3(textOutput(ns("stat_total_states"), inline = TRUE)),
          p(icon("map"), " Estados Analisados")
        )
      ),
      column(3,
        div(
          class = "jurisdictional-stat-box",
          h3(textOutput(ns("stat_total_documents"), inline = TRUE)),
          p(icon("file-alt"), " Total de Documentos")
        )
      ),
      column(3,
        div(
          class = "jurisdictional-stat-box",
          h3(textOutput(ns("stat_date_range"), inline = TRUE)),
          p(icon("calendar"), " Período Analisado")
        )
      )
    ),

    # Comparison Mode Selector
    div(
      class = "filter-panel",
      h4(icon("sliders-h"), " Modo de Comparação"),
      radioButtons(
        ns("comparison_mode"),
        label = NULL,
        choices = c(
          "Todos os Níveis Jurisdicionais" = "all_jurisdictions",
          "Comparação Estado a Estado" = "state_to_state",
          "Análise Cross-Level (por Tema)" = "cross_level"
        ),
        selected = "all_jurisdictions",
        inline = FALSE
      )
    ),

    # Conditional Filter Panels
    conditionalPanel(
      condition = sprintf("input['%s'] == 'state_to_state'", ns("comparison_mode")),
      div(
        class = "filter-panel",
        h4(icon("map-marked-alt"), " Seleção de Estados"),
        fluidRow(
          column(12,
            div(
              style = "margin-bottom: 10px;",
              actionButton(ns("select_all_states"), "Selecionar Todos", class = "btn-sm btn-primary"),
              actionButton(ns("clear_all_states"), "Limpar Seleção", class = "btn-sm btn-secondary", style = "margin-left: 10px;"),
              actionButton(ns("select_sudeste"), "Sudeste", class = "btn-sm btn-info", style = "margin-left: 10px;"),
              actionButton(ns("select_sul"), "Sul", class = "btn-sm btn-info", style = "margin-left: 10px;"),
              actionButton(ns("select_nordeste"), "Nordeste", class = "btn-sm btn-info", style = "margin-left: 10px;")
            )
          )
        ),
        checkboxGroupInput(
          ns("selected_states"),
          label = NULL,
          choices = c(
            "Acre (AC)" = "AC", "Alagoas (AL)" = "AL", "Amapá (AP)" = "AP",
            "Amazonas (AM)" = "AM", "Bahia (BA)" = "BA", "Ceará (CE)" = "CE",
            "Distrito Federal (DF)" = "DF", "Espírito Santo (ES)" = "ES",
            "Goiás (GO)" = "GO", "Maranhão (MA)" = "MA", "Mato Grosso (MT)" = "MT",
            "Mato Grosso do Sul (MS)" = "MS", "Minas Gerais (MG)" = "MG",
            "Pará (PA)" = "PA", "Paraíba (PB)" = "PB", "Paraná (PR)" = "PR",
            "Pernambuco (PE)" = "PE", "Piauí (PI)" = "PI", "Rio de Janeiro (RJ)" = "RJ",
            "Rio Grande do Norte (RN)" = "RN", "Rio Grande do Sul (RS)" = "RS",
            "Rondônia (RO)" = "RO", "Roraima (RR)" = "RR", "Santa Catarina (SC)" = "SC",
            "São Paulo (SP)" = "SP", "Sergipe (SE)" = "SE", "Tocantins (TO)" = "TO"
          ),
          selected = c("SP", "RJ", "MG"),  # Default: Top 3 states
          inline = TRUE
        )
      )
    ),

    conditionalPanel(
      condition = sprintf("input['%s'] == 'cross_level'", ns("comparison_mode")),
      div(
        class = "filter-panel",
        h4(icon("search"), " Análise por Tema/Palavras-chave"),
        textInput(
          ns("topic_keywords"),
          "Palavras-chave (separadas por vírgula):",
          value = "tributário, imposto, ICMS",
          placeholder = "Ex: saúde, educação, meio ambiente"
        ),
        div(
          class = "info-box",
          p(icon("info-circle"), " A análise buscará estas palavras-chave nos títulos e textos dos documentos para comparar como diferentes níveis jurisdicionais abordam o tema.")
        )
      )
    ),

    # Common Filters
    div(
      class = "filter-panel",
      h4(icon("filter"), " Filtros Gerais"),
      fluidRow(
        column(4,
          sliderInput(
            ns("year_range"),
            "Período de Análise:",
            min = 2000,
            max = 2025,
            value = c(2015, 2025),
            step = 1,
            sep = "",
            ticks = FALSE
          )
        ),
        column(4,
          selectInput(
            ns("metric_type"),
            "Métrica Principal:",
            choices = c(
              "Volume de Documentos" = "count",
              "Diversidade de Tipos" = "diversity",
              "Comprimento Médio" = "avg_length",
              "Complexidade" = "complexity"
            ),
            selected = "count"
          )
        ),
        column(4,
          div(
            style = "margin-top: 25px;",
            actionButton(
              ns("apply_filters"),
              "Aplicar Filtros",
              icon = icon("check"),
              class = "btn-primary"
            ),
            actionButton(
              ns("reset_filters"),
              "Resetar",
              icon = icon("undo"),
              class = "btn-secondary",
              style = "margin-left: 10px;"
            )
          )
        )
      )
    ),

    # Visualization Panels
    tabsetPanel(
      id = ns("viz_tabs"),
      type = "tabs",

      # Tab 1: Overview Charts
      tabPanel(
        "Visão Geral",
        icon = icon("chart-bar"),
        br(),
        fluidRow(
          column(6,
            div(
              class = "viz-container",
              h4(icon("chart-column"), " Volume por Jurisdição"),
              plotlyOutput(ns("bar_chart_volume"), height = "400px")
            )
          ),
          column(6,
            div(
              class = "viz-container",
              h4(icon("chart-pie"), " Distribuição Percentual"),
              plotlyOutput(ns("pie_chart_distribution"), height = "400px")
            )
          )
        ),
        fluidRow(
          column(12,
            div(
              class = "viz-container",
              h4(icon("chart-line"), " Evolução Temporal"),
              plotlyOutput(ns("line_chart_temporal"), height = "450px")
            )
          )
        )
      ),

      # Tab 2: Detailed Comparison
      tabPanel(
        "Comparação Detalhada",
        icon = icon("table"),
        br(),
        div(
          class = "viz-container",
          h4(icon("table"), " Métricas Comparativas"),
          div(
            class = "export-buttons",
            downloadButton(ns("download_comparison_csv"), "Exportar CSV", class = "btn-success btn-sm"),
            downloadButton(ns("download_comparison_excel"), "Exportar Excel", class = "btn-success btn-sm")
          ),
          br(),
          DT::dataTableOutput(ns("comparison_table"))
        )
      ),

      # Tab 3: Heatmap Analysis
      tabPanel(
        "Mapa de Calor",
        icon = icon("fire"),
        br(),
        div(
          class = "viz-container",
          h4(icon("th"), " Estado × Tipo de Documento"),
          plotlyOutput(ns("heatmap_state_type"), height = "600px")
        )
      ),

      # Tab 4: State Clustering
      tabPanel(
        "Agrupamento de Estados",
        icon = icon("project-diagram"),
        br(),
        fluidRow(
          column(8,
            div(
              class = "viz-container",
              h4(icon("sitemap"), " Dendrograma de Clustering"),
              plotOutput(ns("dendrogram_states"), height = "600px")
            )
          ),
          column(4,
            div(
              class = "viz-container",
              h4(icon("info-circle"), " Informações do Clustering"),
              uiOutput(ns("clustering_info")),
              br(),
              h5("Grupos Identificados:"),
              DT::dataTableOutput(ns("cluster_assignments_table"))
            )
          )
        )
      ),

      # Tab 5: Radar Chart
      tabPanel(
        "Análise Multidimensional",
        icon = icon("chart-area"),
        br(),
        div(
          class = "viz-container",
          h4(icon("radar"), " Gráfico Radar - Comparação Multi-Métrica"),
          plotlyOutput(ns("radar_chart_multimetric"), height = "600px")
        ),
        div(
          class = "info-box",
          p(icon("lightbulb"), " O gráfico radar permite visualizar múltiplas dimensões simultaneamente: volume, diversidade, complexidade e tendências temporais.")
        )
      )
    ),

    # Footer with Data Info
    hr(),
    div(
      style = "text-align: center; color: #666; padding: 15px;",
      p(
        icon("database"), " Dados do Monitor Legislativo v4 | ",
        icon("file-alt"), textOutput(ns("footer_doc_count"), inline = TRUE), " documentos | ",
        icon("calendar"), " Atualizado em 21/10/2025"
      )
    )
  )
}
