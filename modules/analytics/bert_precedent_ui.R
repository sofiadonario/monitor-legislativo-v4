# =============================================================================
# Sprint 3: BERT Precedent Search UI
# =============================================================================
# Description: Shiny UI module for BERT-based legal precedent retrieval
# Version: 1.0
# Date: January 2025
# =============================================================================

#' BERT Precedent Search UI Module
#'
#' UI for finding legal precedents using Portuguese BERT embeddings
#'
#' @param id Character, module ID
#'
#' @return Shiny UI
#' @export
bert_precedent_ui <- function(id) {
  ns <- NS(id)

  tagList(
    fluidRow(
      column(12,
        h3(icon("gavel"), " Busca de Precedentes Jurídicos (BERT)"),
        p("Encontre precedentes jurídicos similares usando embeddings BERT contextualizados."),
        p(class = "text-muted",
          "Esta ferramenta utiliza o modelo Portuguese BERT (neuralmind) com 768 dimensões para capturar o significado jurídico completo dos documentos, incluindo contexto e estrutura legal.")
      )
    ),

    hr(),

    # Search Configuration
    fluidRow(
      column(12,
        wellPanel(
          h4(icon("cog"), " Configuração da Busca"),

          fluidRow(
            column(6,
              selectInput(
                ns("search_mode"),
                "Modo de Busca:",
                choices = c(
                  "Buscar por ID do Documento" = "id",
                  "Buscar por Texto Jurídico" = "text",
                  "Comparar Dois Documentos" = "compare"
                ),
                selected = "id"
              )
            ),

            column(6,
              selectInput(
                ns("search_scope"),
                "Escopo da Busca:",
                choices = c(
                  "Todo o Corpus" = "all",
                  "Mesmo Nível Jurisdicional" = "same_nivel",
                  "Mesmo Tipo de Documento" = "same_tipo"
                ),
                selected = "all"
              )
            )
          ),

          # Search by ID
          conditionalPanel(
            condition = sprintf("input['%s'] == 'id'", ns("search_mode")),
            ns = ns,
            fluidRow(
              column(12,
                numericInput(
                  ns("reference_doc_id"),
                  "ID do Documento de Referência:",
                  value = 1,
                  min = 1,
                  step = 1
                ),
                actionButton(
                  ns("load_reference_btn"),
                  "Carregar Documento",
                  icon = icon("download"),
                  class = "btn-info"
                )
              )
            ),

            hr(),

            uiOutput(ns("reference_doc_preview"))
          ),

          # Search by Text
          conditionalPanel(
            condition = sprintf("input['%s'] == 'text'", ns("search_mode")),
            ns = ns,
            fluidRow(
              column(12,
                textAreaInput(
                  ns("query_text_bert"),
                  "Texto Jurídico para Análise:",
                  placeholder = "Cole aqui o texto de uma lei, decreto, ou trecho jurídico relevante...\n\nExemplo: 'Art. 1º Esta lei estabelece normas gerais sobre o transporte público urbano...'",
                  rows = 6
                ),
                p(class = "text-muted",
                  "Mínimo 100 caracteres para análise contextual adequada.")
              )
            )
          ),

          # Compare Mode
          conditionalPanel(
            condition = sprintf("input['%s'] == 'compare'", ns("search_mode")),
            ns = ns,
            fluidRow(
              column(6,
                numericInput(
                  ns("compare_doc1_id"),
                  "Documento 1 (ID):",
                  value = 1,
                  min = 1,
                  step = 1
                )
              ),
              column(6,
                numericInput(
                  ns("compare_doc2_id"),
                  "Documento 2 (ID):",
                  value = 2,
                  min = 1,
                  step = 1
                )
              )
            )
          ),

          hr(),

          # Search Parameters
          fluidRow(
            column(4,
              sliderInput(
                ns("bert_top_n"),
                "Número de Precedentes:",
                min = 5,
                max = 100,
                value = 20,
                step = 5
              )
            ),

            column(4,
              sliderInput(
                ns("bert_min_similarity"),
                "Similaridade Mínima:",
                min = 0.5,
                max = 1.0,
                value = 0.7,
                step = 0.05
              )
            ),

            column(4,
              selectInput(
                ns("similarity_metric"),
                "Métrica de Similaridade:",
                choices = c(
                  "Cosseno" = "cosine",
                  "Euclidiana" = "euclidean",
                  "Produto Interno" = "dot"
                ),
                selected = "cosine"
              )
            )
          ),

          actionButton(
            ns("search_precedents_btn"),
            "Buscar Precedentes",
            icon = icon("search"),
            class = "btn-primary btn-lg btn-block"
          )
        )
      )
    ),

    # Results Summary
    fluidRow(
      column(12,
        uiOutput(ns("results_summary_ui"))
      )
    ),

    # Advanced Filters
    fluidRow(
      column(12,
        wellPanel(
          h4(icon("filter"), " Filtros Avançados"),

          fluidRow(
            column(3,
              selectInput(
                ns("filter_nivel_bert"),
                "Nível Jurisdicional:",
                choices = c("Todos" = "all", "Federal" = "Federal",
                           "Estadual" = "Estadual", "Municipal" = "Municipal"),
                selected = "all"
              )
            ),

            column(3,
              selectInput(
                ns("filter_poder_bert"),
                "Poder:",
                choices = c("Todos" = "all", "Executivo" = "Executivo",
                           "Legislativo" = "Legislativo", "Judiciário" = "Judiciário"),
                selected = "all"
              )
            ),

            column(3,
              selectInput(
                ns("filter_tipo_bert"),
                "Tipo de Documento:",
                choices = c("Todos" = "all"),  # Populated dynamically
                selected = "all"
              )
            ),

            column(3,
              sliderInput(
                ns("filter_year_bert"),
                "Ano:",
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

    # Visualization Tabs
    fluidRow(
      column(12,
        tabsetPanel(
          id = ns("bert_tabs"),

          # Results Table
          tabPanel(
            "Precedentes Encontrados",
            icon = icon("list"),
            br(),
            DT::dataTableOutput(ns("precedents_table"))
          ),

          # Similarity Analysis
          tabPanel(
            "Análise de Similaridade",
            icon = icon("chart-bar"),
            br(),

            fluidRow(
              column(6,
                h5("Distribuição de Scores"),
                plotly::plotlyOutput(ns("similarity_distribution"), height = "350px")
              ),

              column(6,
                h5("Similaridade por Jurisdição"),
                plotly::plotlyOutput(ns("similarity_by_nivel"), height = "350px")
              )
            ),

            hr(),

            fluidRow(
              column(12,
                h5("Similaridade ao Longo do Tempo"),
                plotly::plotlyOutput(ns("similarity_timeline"), height = "350px")
              )
            )
          ),

          # Document Comparison
          tabPanel(
            "Comparação Detalhada",
            icon = icon("columns"),
            br(),

            fluidRow(
              column(6,
                numericInput(
                  ns("compare_select_id"),
                  "Selecione Documento para Comparar (ID):",
                  value = NULL,
                  min = 1,
                  step = 1
                )
              ),

              column(6,
                br(),
                actionButton(
                  ns("compare_docs_btn"),
                  "Comparar com Documento de Referência",
                  icon = icon("exchange-alt"),
                  class = "btn-info"
                )
              )
            ),

            hr(),

            uiOutput(ns("comparison_output"))
          ),

          # Cluster Analysis
          tabPanel(
            "Agrupamento Temático",
            icon = icon("project-diagram"),
            br(),

            p("Análise de agrupamento dos precedentes encontrados usando BERT embeddings."),

            fluidRow(
              column(4,
                sliderInput(
                  ns("n_clusters"),
                  "Número de Grupos:",
                  min = 2,
                  max = 10,
                  value = 5,
                  step = 1
                )
              ),

              column(4,
                selectInput(
                  ns("cluster_method"),
                  "Método de Agrupamento:",
                  choices = c(
                    "K-Means" = "kmeans",
                    "Hierárquico" = "hierarchical",
                    "DBSCAN" = "dbscan"
                  ),
                  selected = "kmeans"
                )
              ),

              column(4,
                br(),
                actionButton(
                  ns("run_clustering_btn"),
                  "Executar Agrupamento",
                  icon = icon("play"),
                  class = "btn-success"
                )
              )
            ),

            hr(),

            plotly::plotlyOutput(ns("cluster_plot"), height = "600px")
          ),

          # Embedding Visualization
          tabPanel(
            "Espaço de Embeddings",
            icon = icon("cube"),
            br(),

            p("Visualização 2D do espaço semântico BERT usando UMAP."),
            p(class = "text-muted",
              "Documentos próximos no espaço têm significados jurídicos similares."),

            fluidRow(
              column(4,
                selectInput(
                  ns("reduction_method"),
                  "Método de Redução:",
                  choices = c(
                    "UMAP" = "umap",
                    "t-SNE" = "tsne",
                    "PCA" = "pca"
                  ),
                  selected = "umap"
                )
              ),

              column(4,
                selectInput(
                  ns("color_by"),
                  "Colorir Por:",
                  choices = c(
                    "Similaridade" = "similarity",
                    "Nível" = "nivel",
                    "Tipo" = "tipo",
                    "Ano" = "ano"
                  ),
                  selected = "similarity"
                )
              ),

              column(4,
                br(),
                actionButton(
                  ns("compute_viz_btn"),
                  "Gerar Visualização",
                  icon = icon("magic"),
                  class = "btn-primary"
                )
              )
            ),

            hr(),

            plotly::plotlyOutput(ns("embedding_space_plot"), height = "700px")
          ),

          # Export Results
          tabPanel(
            "Exportar Resultados",
            icon = icon("download"),
            br(),

            h4("Exportar Precedentes Encontrados"),

            fluidRow(
              column(6,
                selectInput(
                  ns("export_format"),
                  "Formato de Exportação:",
                  choices = c(
                    "CSV" = "csv",
                    "Excel (XLSX)" = "xlsx",
                    "JSON" = "json",
                    "Relatório PDF" = "pdf"
                  ),
                  selected = "csv"
                )
              ),

              column(6,
                checkboxGroupInput(
                  ns("export_columns"),
                  "Colunas para Incluir:",
                  choices = c(
                    "ID" = "id",
                    "Título" = "titulo",
                    "Ementa" = "ementa",
                    "Score de Similaridade" = "similarity",
                    "Nível" = "nivel",
                    "Tipo" = "tipo",
                    "Data" = "data"
                  ),
                  selected = c("id", "titulo", "similarity", "nivel", "tipo", "data")
                )
              )
            ),

            hr(),

            downloadButton(
              ns("download_precedents"),
              "Download Resultados",
              class = "btn-success btn-lg"
            ),

            hr(),

            h5("Estatísticas da Busca"),
            verbatimTextOutput(ns("search_stats"))
          )
        )
      )
    )
  )
}
