# =============================================================================
# Sprint 3: Semantic Search UI (Word2Vec/GloVe)
# =============================================================================
# Description: Shiny UI module for semantic similarity search using word embeddings
# Version: 1.0
# Date: January 2025
# =============================================================================

# Helper for optional visNetwork output
safe_visNetworkOutput <- function(...) {
  if (requireNamespace("visNetwork", quietly = TRUE)) {
    visNetwork::visNetworkOutput(...)
  } else {
    shiny::div(class = "alert alert-warning", "Network visualization requires visNetwork package")
  }
}

#' Semantic Search UI Module
#'
#' UI for semantic similarity search using Word2Vec or GloVe embeddings
#'
#' @param id Character, module ID
#'
#' @return Shiny UI
#' @export
semantic_search_ui <- function(id) {
  ns <- NS(id)

  tagList(
    fluidRow(
      column(12,
        h3(icon("search"), " Busca Semântica por Similaridade"),
        p("Encontre documentos semanticamente similares usando embeddings Word2Vec."),
        p(class = "text-muted",
          "Esta ferramenta usa representações vetoriais de 300 dimensões para encontrar leis com significado semelhante, mesmo sem palavras-chave idênticas.")
      )
    ),

    hr(),

    # Search Input Section
    fluidRow(
      column(12,
        wellPanel(
          h4(icon("database"), " Selecionar Documento de Referência"),

          fluidRow(
            column(6,
              selectInput(
                ns("search_method"),
                "Método de Busca:",
                choices = c(
                  "Buscar por ID do Documento" = "id",
                  "Buscar por Texto" = "text",
                  "Buscar por Palavra-Chave" = "keyword"
                ),
                selected = "id"
              )
            ),

            column(6,
              selectInput(
                ns("embedding_type"),
                "Tipo de Embedding:",
                choices = c(
                  "Word2Vec" = "word2vec",
                  "GloVe" = "glove"
                ),
                selected = "word2vec"
              )
            )
          ),

          # Conditional inputs based on search method
          conditionalPanel(
            condition = sprintf("input['%s'] == 'id'", ns("search_method")),
            ns = ns,
            numericInput(
              ns("document_id"),
              "ID do Documento:",
              value = 1,
              min = 1,
              step = 1
            )
          ),

          conditionalPanel(
            condition = sprintf("input['%s'] == 'text'", ns("search_method")),
            ns = ns,
            textAreaInput(
              ns("query_text"),
              "Texto da Consulta:",
              placeholder = "Digite ou cole o texto de uma lei, decreto, ou portaria...",
              rows = 4
            )
          ),

          conditionalPanel(
            condition = sprintf("input['%s'] == 'keyword'", ns("search_method")),
            ns = ns,
            textInput(
              ns("query_keyword"),
              "Palavra-Chave:",
              placeholder = "Ex: transporte, educação, saúde..."
            )
          ),

          fluidRow(
            column(6,
              sliderInput(
                ns("top_n"),
                "Número de Resultados:",
                min = 5,
                max = 50,
                value = 10,
                step = 5
              )
            ),

            column(6,
              sliderInput(
                ns("min_similarity"),
                "Similaridade Mínima:",
                min = 0,
                max = 1,
                value = 0.5,
                step = 0.05
              )
            )
          ),

          actionButton(
            ns("search_btn"),
            "Buscar Documentos Similares",
            icon = icon("search"),
            class = "btn-primary btn-lg btn-block"
          )
        )
      )
    ),

    # Results Section
    fluidRow(
      column(12,
        uiOutput(ns("search_results_ui"))
      )
    ),

    # Filters
    fluidRow(
      column(12,
        wellPanel(
          h4(icon("filter"), " Filtros de Resultados"),

          fluidRow(
            column(4,
              selectInput(
                ns("filter_nivel"),
                "Nível Jurisdicional:",
                choices = c("Todos" = "all", "Federal" = "Federal",
                           "Estadual" = "Estadual", "Municipal" = "Municipal"),
                selected = "all"
              )
            ),

            column(4,
              selectInput(
                ns("filter_tipo"),
                "Tipo de Documento:",
                choices = c("Todos" = "all"),  # Will be populated dynamically
                selected = "all"
              )
            ),

            column(4,
              sliderInput(
                ns("filter_year"),
                "Ano de Publicação:",
                min = 1988,
                max = as.integer(format(Sys.Date(), "%Y")),
                value = c(2000, as.integer(format(Sys.Date(), "%Y"))),
                sep = ""
              )
            )
          )
        )
      )
    ),

    # Visualization Section
    fluidRow(
      column(12,
        tabsetPanel(
          id = ns("results_tabs"),

          # Table View
          tabPanel(
            "Tabela",
            icon = icon("table"),
            br(),
            DT::dataTableOutput(ns("results_table"))
          ),

          # Similarity Distribution
          tabPanel(
            "Distribuição",
            icon = icon("chart-bar"),
            br(),
            plotly::plotlyOutput(ns("similarity_dist"), height = "400px")
          ),

          # 2D Embedding Visualization
          tabPanel(
            "Visualização 2D",
            icon = icon("project-diagram"),
            br(),
            p("Visualização UMAP/t-SNE dos embeddings (em desenvolvimento)"),
            plotly::plotlyOutput(ns("embedding_viz"), height = "600px")
          ),

          # Network Graph
          tabPanel(
            "Rede",
            icon = icon("share-alt"),
            br(),
            p("Rede de similaridade (em desenvolvimento)"),
            safe_visNetworkOutput(ns("similarity_network"), height = "600px")
          )
        )
      )
    )
  )
}
