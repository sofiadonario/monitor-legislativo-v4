#' Amendment Pattern Analysis UI Module
#'
#' Shiny module UI for amendment pattern analysis and visualization
#'
#' @author Monitor Legislativo Analytics Team
#' @date 2025-01-13

library(shiny)
library(plotly)
library(DT)

# Optional packages - make visNetwork and shinydashboard optional
if (requireNamespace("shinydashboard", quietly = TRUE)) {
  library(shinydashboard)
} else {
  # Fallback box function when shinydashboard not available
  box <- function(..., title = NULL, status = NULL, solidHeader = FALSE,
                  width = 12, collapsible = FALSE, collapsed = FALSE) {
    content <- list(...)
    title_elem <- if (!is.null(title)) shiny::h4(title) else NULL
    shiny::wellPanel(title_elem, content)
  }
}

# Helper for optional visNetwork output
safe_visNetworkOutput <- function(...) {
  if (requireNamespace("visNetwork", quietly = TRUE)) {
    visNetwork::visNetworkOutput(...)
  } else {
    shiny::div(class = "alert alert-warning", "Network visualization requires visNetwork package")
  }
}

#' Amendment Analysis UI
#'
#' @param id Module namespace ID
#' @return Shiny UI elements
#' @export
amendment_ui <- function(id) {
  ns <- NS(id)

  tagList(
    fluidRow(
      # Header
      box(
        title = div(
          icon("gavel"),
          "Análise de Padrões de Emendas Legislativas"
        ),
        status = "primary",
        solidHeader = TRUE,
        width = 12,

        p("Sistema abrangente para rastreamento de modificações legislativas ao longo do tempo,
          identificação de hotspots de emendas e detecção de cascatas de alterações."),

        fluidRow(
          valueBoxOutput(ns("total_amendments_box"), width = 3),
          valueBoxOutput(ns("hotspots_box"), width = 3),
          valueBoxOutput(ns("cascades_box"), width = 3),
          valueBoxOutput(ns("velocity_box"), width = 3)
        )
      )
    ),

    fluidRow(
      # Controls Panel
      box(
        title = div(icon("sliders-h"), "Controles de Análise"),
        status = "info",
        solidHeader = TRUE,
        width = 3,
        collapsible = TRUE,

        h5(strong("Modo de Análise")),
        selectInput(
          ns("analysis_mode"),
          "Selecione o modo:",
          choices = list(
            "Visão Geral" = "overview",
            "Timeline de Documento" = "timeline",
            "Hotspots de Emendas" = "hotspots",
            "Cascatas de Alterações" = "cascades",
            "Velocidade de Mudança" = "velocity",
            "Padrões Inter-jurisdicionais" = "cross_jurisdiction"
          ),
          selected = "overview"
        ),

        hr(),

        h5(strong("Filtros")),

        sliderInput(
          ns("year_range"),
          "Período de Análise:",
          min = 1820,
          max = as.integer(format(Sys.Date(), "%Y")),
          value = c(2000, as.integer(format(Sys.Date(), "%Y"))),
          step = 1,
          sep = ""
        ),

        selectInput(
          ns("jurisdiction_filter"),
          "Nível Jurisdicional:",
          choices = list(
            "Todos" = "all",
            "Federal" = "Federal",
            "Estadual" = "Estadual",
            "Municipal" = "Municipal"
          ),
          selected = "all"
        ),

        selectInput(
          ns("amendment_type"),
          "Tipo de Emenda:",
          choices = list(
            "Todas" = "all",
            "Modificação" = "modification",
            "Revogação" = "revocation",
            "Adição" = "addition",
            "Substituição" = "substitution"
          ),
          selected = "all"
        ),

        # Timeline-specific controls
        conditionalPanel(
          condition = sprintf("input['%s'] == 'timeline'", ns("analysis_mode")),
          hr(),
          h5(strong("Documento Focal")),
          numericInput(
            ns("focal_doc_id"),
            "ID do Documento:",
            value = NULL,
            min = 1
          ),
          textInput(
            ns("focal_doc_urn"),
            "ou URN:",
            value = "",
            placeholder = "urn:lex:br:federal:lei:..."
          ),
          sliderInput(
            ns("max_depth"),
            "Profundidade Máxima:",
            min = 1,
            max = 20,
            value = 10,
            step = 1
          )
        ),

        # Hotspot-specific controls
        conditionalPanel(
          condition = sprintf("input['%s'] == 'hotspots'", ns("analysis_mode")),
          hr(),
          h5(strong("Configurações de Hotspot")),
          numericInput(
            ns("min_amendments"),
            "Mínimo de Emendas:",
            value = 3,
            min = 1,
            max = 50,
            step = 1
          ),
          numericInput(
            ns("top_n_hotspots"),
            "Top N Hotspots:",
            value = 20,
            min = 5,
            max = 100,
            step = 5
          )
        ),

        # Cascade-specific controls
        conditionalPanel(
          condition = sprintf("input['%s'] == 'cascades'", ns("analysis_mode")),
          hr(),
          h5(strong("Configurações de Cascata")),
          numericInput(
            ns("min_chain_length"),
            "Comprimento Mínimo:",
            value = 3,
            min = 2,
            max = 10,
            step = 1
          )
        ),

        # Velocity-specific controls
        conditionalPanel(
          condition = sprintf("input['%s'] == 'velocity'", ns("analysis_mode")),
          hr(),
          h5(strong("Configurações de Velocidade")),
          numericInput(
            ns("window_years"),
            "Janela Temporal (anos):",
            value = 3,
            min = 1,
            max = 10,
            step = 1
          ),
          checkboxInput(
            ns("by_jurisdiction"),
            "Por Jurisdição",
            value = FALSE
          )
        ),

        hr(),

        actionButton(
          ns("run_analysis"),
          label = div(icon("play"), "Executar Análise"),
          class = "btn-primary btn-block",
          style = "margin-bottom: 10px;"
        ),

        actionButton(
          ns("refresh_data"),
          label = div(icon("sync"), "Atualizar Dados"),
          class = "btn-info btn-block",
          style = "margin-bottom: 10px;"
        ),

        downloadButton(
          ns("download_results"),
          label = "Exportar Resultados",
          class = "btn-success btn-block"
        )
      ),

      # Results Panel
      box(
        title = div(icon("chart-line"), "Resultados da Análise"),
        status = "success",
        solidHeader = TRUE,
        width = 9,

        tabsetPanel(
          id = ns("results_tabs"),

          # Overview Tab
          tabPanel(
            "Visão Geral",
            value = "overview_tab",
            br(),

            fluidRow(
              column(6,
                h4(icon("info-circle"), "Resumo Estatístico"),
                uiOutput(ns("overview_stats"))
              ),
              column(6,
                h4(icon("chart-pie"), "Distribuição de Emendas"),
                plotlyOutput(ns("amendment_distribution"), height = "300px")
              )
            ),

            hr(),

            h4(icon("table"), "Emendas Recentes"),
            DT::dataTableOutput(ns("recent_amendments_table"))
          ),

          # Timeline Tab
          tabPanel(
            "Timeline",
            value = "timeline_tab",
            br(),

            fluidRow(
              column(12,
                uiOutput(ns("focal_doc_info"))
              )
            ),

            fluidRow(
              column(6,
                h4(icon("project-diagram"), "Rede de Emendas"),
                safe_visNetworkOutput(ns("timeline_network"), height = "500px")
              ),
              column(6,
                h4(icon("chart-line"), "Timeline Temporal"),
                plotlyOutput(ns("timeline_plot"), height = "500px")
              )
            ),

            hr(),

            h4(icon("list"), "Histórico Completo"),
            DT::dataTableOutput(ns("timeline_table"))
          ),

          # Hotspots Tab
          tabPanel(
            "Hotspots",
            value = "hotspots_tab",
            br(),

            fluidRow(
              column(8,
                h4(icon("fire"), "Leis Mais Emendadas"),
                plotlyOutput(ns("hotspots_chart"), height = "500px")
              ),
              column(4,
                h4(icon("trophy"), "Top Hotspots"),
                uiOutput(ns("hotspots_summary"))
              )
            ),

            hr(),

            fluidRow(
              column(12,
                h4(icon("map"), "Heatmap de Frequência"),
                plotlyOutput(ns("hotspots_heatmap"), height = "400px")
              )
            ),

            hr(),

            h4(icon("table"), "Tabela Detalhada"),
            DT::dataTableOutput(ns("hotspots_table"))
          ),

          # Cascades Tab
          tabPanel(
            "Cascatas",
            value = "cascades_tab",
            br(),

            fluidRow(
              column(6,
                h4(icon("sitemap"), "Visualização de Cascatas"),
                safe_visNetworkOutput(ns("cascade_network"), height = "500px")
              ),
              column(6,
                h4(icon("chart-bar"), "Distribuição de Complexidade"),
                plotlyOutput(ns("cascade_distribution"), height = "500px")
              )
            ),

            hr(),

            h4(icon("list-ol"), "Cadeias de Emendas"),
            DT::dataTableOutput(ns("cascades_table"))
          ),

          # Velocity Tab
          tabPanel(
            "Velocidade",
            value = "velocity_tab",
            br(),

            fluidRow(
              column(12,
                h4(icon("tachometer-alt"), "Velocidade de Emendas ao Longo do Tempo"),
                plotlyOutput(ns("velocity_plot"), height = "400px")
              )
            ),

            hr(),

            fluidRow(
              column(6,
                h4(icon("chart-area"), "Aceleração"),
                plotlyOutput(ns("acceleration_plot"), height = "300px")
              ),
              column(6,
                h4(icon("info-circle"), "Métricas de Tendência"),
                uiOutput(ns("velocity_stats"))
              )
            ),

            hr(),

            h4(icon("table"), "Dados de Velocidade"),
            DT::dataTableOutput(ns("velocity_table"))
          ),

          # Cross-Jurisdiction Tab
          tabPanel(
            "Inter-jurisdicional",
            value = "cross_jurisdiction_tab",
            br(),

            fluidRow(
              column(6,
                h4(icon("exchange-alt"), "Fluxos Entre Níveis"),
                plotlyOutput(ns("jurisdiction_sankey"), height = "500px")
              ),
              column(6,
                h4(icon("clock"), "Velocidade de Difusão"),
                plotlyOutput(ns("diffusion_speed"), height = "500px")
              )
            ),

            hr(),

            fluidRow(
              column(12,
                h4(icon("network-wired"), "Padrões de Fluxo"),
                plotlyOutput(ns("jurisdiction_flow_chart"), height = "400px")
              )
            ),

            hr(),

            h4(icon("table"), "Tabela de Padrões"),
            DT::dataTableOutput(ns("cross_jurisdiction_table"))
          ),

          # Statistics Tab
          tabPanel(
            "Estatísticas",
            value = "statistics_tab",
            br(),

            fluidRow(
              column(3,
                valueBoxOutput(ns("stat_total_docs"), width = NULL)
              ),
              column(3,
                valueBoxOutput(ns("stat_amendment_rate"), width = NULL)
              ),
              column(3,
                valueBoxOutput(ns("stat_avg_velocity"), width = NULL)
              ),
              column(3,
                valueBoxOutput(ns("stat_complexity"), width = NULL)
              )
            ),

            hr(),

            fluidRow(
              column(6,
                h4(icon("chart-line"), "Tendência Histórica"),
                plotlyOutput(ns("historical_trend"), height = "350px")
              ),
              column(6,
                h4(icon("chart-pie"), "Por Tipo de Emenda"),
                plotlyOutput(ns("type_distribution"), height = "350px")
              )
            ),

            hr(),

            fluidRow(
              column(6,
                h4(icon("map-marked-alt"), "Por Jurisdição"),
                plotlyOutput(ns("jurisdiction_distribution"), height = "350px")
              ),
              column(6,
                h4(icon("calendar"), "Sazonalidade"),
                plotlyOutput(ns("seasonality_plot"), height = "350px")
              )
            )
          )
        )
      )
    ),

    # Documentation Box
    fluidRow(
      box(
        title = div(icon("book"), "Documentação e Ajuda"),
        status = "warning",
        solidHeader = TRUE,
        width = 12,
        collapsible = TRUE,
        collapsed = TRUE,

        h4("Como Usar Este Módulo"),

        tags$ul(
          tags$li(
            tags$strong("Visão Geral:"),
            " Estatísticas gerais sobre emendas legislativas no período selecionado."
          ),
          tags$li(
            tags$strong("Timeline:"),
            " Rastreie o histórico completo de emendas para um documento específico.
            Insira o ID do documento ou URN para iniciar."
          ),
          tags$li(
            tags$strong("Hotspots:"),
            " Identifique as leis mais frequentemente emendadas.
            Ajuste o número mínimo de emendas para refinar os resultados."
          ),
          tags$li(
            tags$strong("Cascatas:"),
            " Detecte cadeias de emendas onde A emenda B, B emenda C, etc.
            Útil para entender a propagação de mudanças legislativas."
          ),
          tags$li(
            tags$strong("Velocidade:"),
            " Analise a taxa de mudança legislativa ao longo do tempo.
            Identifique períodos de alta e baixa atividade de emendas."
          ),
          tags$li(
            tags$strong("Inter-jurisdicional:"),
            " Explore como emendas fluem entre níveis Federal, Estadual e Municipal."
          )
        ),

        hr(),

        h4("Termos-Chave"),

        tags$dl(
          tags$dt("Emenda/Alteração:"),
          tags$dd("Modificação de um texto legal existente usando termos como 'altera', 'modifica'."),

          tags$dt("Revogação:"),
          tags$dd("Cancelamento ou anulação de uma lei usando termos como 'revoga'."),

          tags$dt("Hotspot:"),
          tags$dd("Lei que recebe um número significativo de emendas ao longo do tempo."),

          tags$dt("Cascata:"),
          tags$dd("Cadeia de emendas sequenciais onde cada emenda modifica uma lei já emendada."),

          tags$dt("Velocidade:"),
          tags$dd("Taxa de mudança legislativa medida por emendas por ano."),

          tags$dt("Aceleração:"),
          tags$dd("Mudança na velocidade de emendas ao longo do tempo.")
        ),

        hr(),

        h4("Detecção de Padrões"),

        p("O sistema identifica automaticamente emendas usando palavras-chave em português:"),

        tags$ul(
          tags$li(tags$strong("Modificação:"), " altera, modifica, altera dispositivos"),
          tags$li(tags$strong("Revogação:"), " revoga, cancela, anula"),
          tags$li(tags$strong("Adição:"), " acrescenta, inclui, adiciona, insere"),
          tags$li(tags$strong("Substituição:"), " substitui, troca, muda"),
          tags$li(tags$strong("Referências:"), " Lei nº, Decreto nº, art., §, inciso")
        )
      )
    )
  )
}

cat("✅ Amendment Analysis UI Module loaded successfully\n")
