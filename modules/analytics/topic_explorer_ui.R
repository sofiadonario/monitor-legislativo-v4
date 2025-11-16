# =============================================================================
# Sprint 3: Topic Explorer UI (STM)
# =============================================================================
# Description: Shiny UI module for exploring Structural Topic Model results
# Version: 1.0
# Date: January 2025
# =============================================================================

#' Topic Explorer UI Module
#'
#' UI for exploring STM topics, prevalence, and covariate effects
#'
#' @param id Character, module ID
#'
#' @return Shiny UI
#' @export
topic_explorer_ui <- function(id) {
  ns <- NS(id)

  tagList(
    fluidRow(
      column(12,
        h3(icon("lightbulb"), " Explorador de Topics (STM)"),
        p("Explore os tópicos latentes descobertos no corpus legislativo usando Structural Topic Modeling."),
        p(class = "text-muted",
          "O STM identifica automaticamente temas na legislação e modela como variam por jurisdição, poder, e tempo.")
      )
    ),

    hr(),

    # Model Selection
    fluidRow(
      column(12,
        wellPanel(
          h4(icon("cog"), " Seleção do Modelo"),

          fluidRow(
            column(6,
              selectInput(
                ns("model_select"),
                "Modelo STM:",
                choices = c("Carregando..." = ""),
                selected = NULL
              )
            ),

            column(6,
              uiOutput(ns("model_info_ui"))
            )
          )
        )
      )
    ),

    # Topic Overview
    fluidRow(
      column(12,
        h4(icon("chart-pie"), " Visão Geral dos Tópicos"),

        fluidRow(
          column(4,
            valueBoxOutput(ns("total_topics_box"), width = NULL)
          ),

          column(4,
            valueBoxOutput(ns("total_documents_box"), width = NULL)
          ),

          column(4,
            valueBoxOutput(ns("vocab_size_box"), width = NULL)
          )
        )
      )
    ),

    hr(),

    # Topic Browser
    fluidRow(
      column(12,
        wellPanel(
          h4(icon("list"), " Navegador de Tópicos"),

          fluidRow(
            column(4,
              selectInput(
                ns("topic_select"),
                "Selecionar Tópico:",
                choices = NULL
              ),

              sliderInput(
                ns("top_words_n"),
                "Palavras a Mostrar:",
                min = 5,
                max = 20,
                value = 10,
                step = 1
              ),

              selectInput(
                ns("word_type"),
                "Tipo de Palavras:",
                choices = c(
                  "Probabilidade" = "prob",
                  "FREX" = "frex",
                  "Lift" = "lift",
                  "Score" = "score"
                ),
                selected = "frex"
              )
            ),

            column(8,
              h5("Palavras Principais do Tópico:"),
              uiOutput(ns("topic_words_ui")),

              hr(),

              h5("Proporção Esperada:"),
              uiOutput(ns("topic_proportion_ui"))
            )
          )
        )
      )
    ),

    # Visualizations
    fluidRow(
      column(12,
        tabsetPanel(
          id = ns("viz_tabs"),

          # Topic Prevalence
          tabPanel(
            "Prevalência",
            icon = icon("chart-bar"),
            br(),
            plotly::plotlyOutput(ns("prevalence_plot"), height = "500px"),
            hr(),
            p(class = "text-muted",
              "Proporção esperada de cada tópico no corpus. Tópicos maiores são mais prevalentes.")
          ),

          # Topic Correlations
          tabPanel(
            "Correlações",
            icon = icon("project-diagram"),
            br(),
            visNetwork::visNetworkOutput(ns("correlation_network"), height = "600px"),
            hr(),
            p(class = "text-muted",
              "Rede mostrando correlações entre tópicos. Tópicos conectados tendem a aparecer juntos.")
          ),

          # Word Clouds
          tabPanel(
            "Nuvens de Palavras",
            icon = icon("cloud"),
            br(),
            fluidRow(
              column(4,
                selectInput(
                  ns("wordcloud_topic"),
                  "Tópico:",
                  choices = NULL
                )
              ),
              column(4,
                sliderInput(
                  ns("wordcloud_words"),
                  "Máx. Palavras:",
                  min = 20,
                  max = 100,
                  value = 50
                )
              ),
              column(4,
                br(),
                actionButton(
                  ns("generate_wordcloud"),
                  "Gerar Nuvem",
                  icon = icon("sync"),
                  class = "btn-primary"
                )
              )
            ),
            hr(),
            plotOutput(ns("wordcloud_plot"), height = "500px")
          ),

          # Covariate Effects
          tabPanel(
            "Efeitos de Covariáveis",
            icon = icon("sliders-h"),
            br(),

            fluidRow(
              column(4,
                selectInput(
                  ns("covariate_select"),
                  "Covariável:",
                  choices = c(
                    "Nível Jurisdicional" = "nivel",
                    "Poder" = "poder",
                    "Ano" = "ano"
                  ),
                  selected = "nivel"
                )
              ),

              column(4,
                conditionalPanel(
                  condition = sprintf("input['%s'] == 'nivel'", ns("covariate_select")),
                  ns = ns,
                  selectInput(
                    ns("nivel_value1"),
                    "Comparar:",
                    choices = c("Federal", "Estadual", "Municipal"),
                    selected = "Federal"
                  ),
                  selectInput(
                    ns("nivel_value2"),
                    "Com:",
                    choices = c("Federal", "Estadual", "Municipal"),
                    selected = "Estadual"
                  )
                )
              ),

              column(4,
                sliderInput(
                  ns("topics_to_show"),
                  "Tópicos a Mostrar:",
                  min = 3,
                  max = 20,
                  value = 9,
                  step = 1
                )
              )
            ),

            hr(),
            plotly::plotlyOutput(ns("effects_plot"), height = "600px"),

            hr(),
            p(class = "text-muted",
              "Diferença na prevalência dos tópicos entre categorias. Barras positivas indicam maior prevalência na primeira categoria.")
          ),

          # Representative Documents
          tabPanel(
            "Documentos Representativos",
            icon = icon("file-alt"),
            br(),

            fluidRow(
              column(6,
                selectInput(
                  ns("repr_topic_select"),
                  "Tópico:",
                  choices = NULL
                )
              ),

              column(6,
                sliderInput(
                  ns("repr_docs_n"),
                  "Número de Documentos:",
                  min = 3,
                  max = 10,
                  value = 5
                )
              )
            ),

            hr(),
            DT::dataTableOutput(ns("representative_docs_table"))
          ),

          # Document Search by Topic
          tabPanel(
            "Buscar por Tópico",
            icon = icon("search"),
            br(),

            fluidRow(
              column(4,
                selectInput(
                  ns("search_topic"),
                  "Tópico:",
                  choices = NULL
                )
              ),

              column(4,
                sliderInput(
                  ns("min_topic_proportion"),
                  "Proporção Mínima:",
                  min = 0,
                  max = 1,
                  value = 0.3,
                  step = 0.05
                )
              ),

              column(4,
                br(),
                actionButton(
                  ns("search_by_topic_btn"),
                  "Buscar Documentos",
                  icon = icon("search"),
                  class = "btn-primary"
                )
              )
            ),

            hr(),
            DT::dataTableOutput(ns("topic_search_results"))
          ),

          # Time Trends
          tabPanel(
            "Tendências Temporais",
            icon = icon("chart-line"),
            br(),

            fluidRow(
              column(6,
                selectInput(
                  ns("trend_topic_select"),
                  "Tópico:",
                  choices = NULL,
                  multiple = TRUE
                )
              ),

              column(6,
                selectInput(
                  ns("trend_nivel"),
                  "Filtrar por Nível:",
                  choices = c("Todos" = "all", "Federal" = "Federal",
                             "Estadual" = "Estadual", "Municipal" = "Municipal"),
                  selected = "all"
                )
              )
            ),

            hr(),
            plotly::plotlyOutput(ns("time_trend_plot"), height = "500px"),

            hr(),
            p(class = "text-muted",
              "Como a prevalência dos tópicos mudou ao longo do tempo. Útil para identificar tendências legislativas.")
          )
        )
      )
    )
  )
}

#' Value Box Output (Shiny Dashboard Style)
#'
#' Render value box in UI
valueBoxOutput <- function(outputId, width = 4) {
  div(
    class = paste0("col-sm-", width),
    uiOutput(outputId)
  )
}
