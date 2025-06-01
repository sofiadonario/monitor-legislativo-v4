# Advanced Analytics Tab UI
# Monitor Legislativo v4 - Analytics Dashboard Interface
# ======================================================

fluidRow(
  column(12,
    h2("📈 Analytics Avançados"),
    p("Análise avançada de tendências legislativas, padrões temporais e insights estratégicos.", 
      style = "color: #7f8c8d; margin-bottom: 30px;")
  )
),

# Analytics Control Panel
fluidRow(
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
      box(
        title = "Análise de Tendências Temporais",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        plotlyOutput("analytics_temporal_chart", height = "400px")
      )
    ),
    
    conditionalPanel(
      condition = "input.analytics_type == 'sentiment'",
      box(
        title = "Análise de Sentimento Regulatório",
        status = "info",
        solidHeader = TRUE,
        width = 12,
        plotlyOutput("analytics_sentiment_chart", height = "400px")
      )
    ),
    
    conditionalPanel(
      condition = "input.analytics_type == 'topics'",
      box(
        title = "Modelagem de Tópicos",
        status = "success",
        solidHeader = TRUE,
        width = 12,
        plotlyOutput("analytics_topics_chart", height = "400px")
      )
    ),
    
    conditionalPanel(
      condition = "input.analytics_type == 'network'",
      box(
        title = "Análise de Rede de Documentos",
        status = "warning",
        solidHeader = TRUE,
        width = 12,
        plotlyOutput("analytics_network_chart", height = "400px")
      )
    ),
    
    conditionalPanel(
      condition = "input.analytics_type == 'regional'",
      box(
        title = "Comparação Regional",
        status = "danger",
        solidHeader = TRUE,
        width = 12,
        plotlyOutput("analytics_regional_chart", height = "400px")
      )
    )
  )
),

# Analytics Results Summary
fluidRow(
  column(12,
    box(
      title = "Insights da Análise",
      status = "primary",
      solidHeader = TRUE,
      width = 12,
      uiOutput("analytics_insights"),
      footer = "Insights gerados automaticamente baseados na análise atual"
    )
  )
),

# Detailed Results and Export
fluidRow(
  column(6,
    box(
      title = "Resultados Detalhados",
      status = "info",
      solidHeader = TRUE,
      width = 12,
      DT::dataTableOutput("analytics_detailed_results")
    )
  ),
  column(6,
    box(
      title = "Opções de Exportação",
      status = "success",
      solidHeader = TRUE,
      width = 12,
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