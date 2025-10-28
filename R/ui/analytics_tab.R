# v61: Migrated from shinydashboard box() to bslib card()
# Advanced Analytics Tab UI
# Monitor Legislativo v4 - Analytics Dashboard Interface
# ======================================================

div(
  layout_columns(
    col_widths = 12,
    column(12,
      h2("📈 Analytics Avançados"),
      p("Análise avançada de tendências legislativas, padrões temporais e insights estratégicos.",
        style = "color: #7f8c8d; margin-bottom: 30px;")
    )
  ),

  # Analytics Control Panel
  layout_columns(
    col_widths = c(4, 8),
    column(4,
      wellPanel(
        h4("Configurações de Análise"),

        selectInput(
          inputId = "analytics_type",
          label = "Tipo de Análise:",
          choices = list(
            "Tendências Temporais" = "temporal",
            "Análise de Sentimento" = "sentiment",
            "Temas Emergentes" = "topics",
            "Análise de Rede" = "network",
            "Comparação Regional" = "regional"
          ),
          selected = "temporal"
        ),

        dateRangeInput(
          inputId = "analytics_date_range",
          label = "Período de Análise:",
          start = Sys.Date() - 365,
          end = Sys.Date(),
          format = "dd/mm/yyyy",
          language = "pt-BR"
        ),

        selectInput(
          inputId = "analytics_granularity",
          label = "Granularidade:",
          choices = list(
            "Mensal" = "monthly",
            "Trimestral" = "quarterly",
            "Anual" = "yearly"
          ),
          selected = "monthly"
        ),

        checkboxGroupInput(
          inputId = "analytics_filters",
          label = "Filtros:",
          choices = list(
            "Federal" = "federal",
            "Estadual" = "state",
            "Municipal" = "municipal"
          ),
          selected = c("federal", "state")
        ),

        actionButton(
          inputId = "analytics_run",
          label = "Executar Análise",
          icon = icon("play"),
          class = "btn-primary btn-block"
        )
      )
    ),

    column(8,
      # Main Analytics Display
      conditionalPanel(
        condition = "input.analytics_type == 'temporal'",
        card(
          card_header("Análise de Tendências Temporais"),
          plotlyOutput("analytics_temporal_chart", height = "400px")
        )
      ),

      conditionalPanel(
        condition = "input.analytics_type == 'sentiment'",
        card(
          card_header("Análise de Sentimento Regulatório"),
          plotlyOutput("analytics_sentiment_chart", height = "400px")
        )
      ),

      conditionalPanel(
        condition = "input.analytics_type == 'topics'",
        card(
          card_header("Modelagem de Tópicos"),
          plotlyOutput("analytics_topics_chart", height = "400px")
        )
      ),

      conditionalPanel(
        condition = "input.analytics_type == 'network'",
        card(
          card_header("Análise de Rede de Documentos"),
          plotlyOutput("analytics_network_chart", height = "400px")
        )
      ),

      conditionalPanel(
        condition = "input.analytics_type == 'regional'",
        card(
          card_header("Comparação Regional"),
          plotlyOutput("analytics_regional_chart", height = "400px")
        )
      )
    )
  ),

  # Analytics Results Summary
  layout_columns(
    col_widths = 12,
    card(
      card_header("Insights da Análise"),
      uiOutput("analytics_insights"),
      card_footer("Insights gerados automaticamente baseados na análise atual")
    )
  ),

  # Detailed Results and Export
  layout_columns(
    col_widths = c(6, 6),
    card(
      card_header("Resultados Detalhados"),
      DT::dataTableOutput("analytics_detailed_results")
    ),
    card(
      card_header("Opções de Exportação"),
      fluidRow(
        column(6,
          downloadButton(
            outputId = "analytics_download_chart",
            label = "Baixar Gráfico",
            icon = icon("chart-line"),
            class = "btn-info btn-block"
          )
        ),
        column(6,
          downloadButton(
            outputId = "analytics_download_data",
            label = "Baixar Dados",
            icon = icon("database"),
            class = "btn-success btn-block"
          )
        )
      ),
      br(),
      fluidRow(
        column(12,
          downloadButton(
            outputId = "analytics_download_report",
            label = "Gerar Relatório Completo",
            icon = icon("file-pdf"),
            class = "btn-primary btn-block"
          )
        )
      )
    )
  )
)
