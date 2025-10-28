# v61: Migrated from shinydashboard box() to bslib card()
# Advanced NLP/Text Mining Tab UI
# Monitor Legislativo v4 - NLP Dashboard Interface
# ================================================

div(
  layout_columns(
    col_widths = 12,
    div(
      h2("🧠 Análise de Texto e Processamento de Linguagem Natural"),
      p("Ferramentas avançadas de análise textual para documentos legislativos brasileiros.",
        style = "color: #7f8c8d; margin-bottom: 30px;")
    )
  ),

  # NLP Analysis Controls
  layout_columns(
    col_widths = c(4, 8),
    wellPanel(
      h4("Configurações de Análise"),

      selectInput(
        inputId = "nlp_analysis_type",
        label = "Tipo de Análise:",
        choices = list(
          "Análise de Sentimento" = "sentiment",
          "Extração de Entidades" = "entities",
          "Modelagem de Tópicos" = "topics",
          "Similaridade de Documentos" = "similarity",
          "Análise KWIC" = "kwic"
        ),
        selected = "sentiment"
      ),

      textAreaInput(
        inputId = "nlp_text_input",
        label = "Texto para Análise:",
        placeholder = "Cole o texto do documento ou deixe em branco para usar documentos selecionados...",
        rows = 4
      ),

      checkboxGroupInput(
        inputId = "nlp_options",
        label = "Opções de Processamento:",
        choices = list(
          "Remover stopwords" = "remove_stopwords",
          "Normalização" = "normalize",
          "Stemming/Lemmatização" = "stemming",
          "Reconhecimento de entidades" = "ner"
        ),
        selected = c("remove_stopwords", "normalize")
      ),

      actionButton(
        inputId = "nlp_analyze",
        label = "Analisar",
        icon = icon("brain"),
        class = "btn-primary btn-block"
      )
    ),

    tabsetPanel(
      type = "tabs",

      tabPanel(
        title = "Resultados",
        br(),
        uiOutput("nlp_results_overview"),
        br(),
        conditionalPanel(
          condition = "input.nlp_analysis_type == 'sentiment'",
          uiOutput("nlp_sentiment_results")
        ),
        conditionalPanel(
          condition = "input.nlp_analysis_type == 'entities'",
          uiOutput("nlp_entities_results")
        ),
        conditionalPanel(
          condition = "input.nlp_analysis_type == 'topics'",
          uiOutput("nlp_topics_results")
        ),
        conditionalPanel(
          condition = "input.nlp_analysis_type == 'similarity'",
          uiOutput("nlp_similarity_results")
        ),
        conditionalPanel(
          condition = "input.nlp_analysis_type == 'kwic'",
          uiOutput("nlp_kwic_results")
        )
      ),

      tabPanel(
        title = "Visualizações",
        br(),
        plotlyOutput("nlp_visualization_chart", height = "500px")
      ),

      tabPanel(
        title = "Dados Detalhados",
        br(),
        DT::dataTableOutput("nlp_detailed_results")
      ),

      tabPanel(
        title = "Exportar",
        br(),
        wellPanel(
          h4("Opções de Exportação"),
          fluidRow(
            column(6,
              downloadButton(
                outputId = "nlp_download_results",
                label = "Baixar Resultados",
                icon = icon("download"),
                class = "btn-info btn-block"
              )
            ),
            column(6,
              downloadButton(
                outputId = "nlp_download_visualization",
                label = "Baixar Visualização",
                icon = icon("chart-bar"),
                class = "btn-success btn-block"
              )
            )
          )
        )
      )
    )
  )
)
