# ==============================================================================
# MONITOR LEGISLATIVO V4 - OPTIMIZED UI
# ==============================================================================
# Clean, modular UI structure
# ==============================================================================

ui <- dashboardPage(
  skin = "blue",

  # HEADER
  # ======
  dashboardHeader(
    title = "Monitor Legislativo v4",
    titleWidth = 300
  ),

  # SIDEBAR
  # =======
  dashboardSidebar(
    width = 250,
    sidebarMenu(
      id = "main_menu",
      menuItem("📊 Painel Executivo", tabName = "dashboard", icon = icon("chart-line")),
      menuItem("🔍 Busca", tabName = "search", icon = icon("search")),
      menuItem("🗺️ Mapa Geográfico", tabName = "maps", icon = icon("map")),
      menuItem("📈 Analytics", tabName = "analytics", icon = icon("chart-area"))
    )
  ),

  # BODY
  # ====
  dashboardBody(
    # Custom CSS for Brazilian theme
    tags$head(
      tags$style(HTML("
        .main-header .logo { background-color: #2c3e50 !important; }
        .main-header .navbar { background-color: #2c3e50 !important; }
        .skin-blue .main-sidebar { background-color: #34495e; }
        .content-wrapper { background-color: #f8f9fa; }
        .small-box { border-radius: 8px; margin-bottom: 15px; }
        .box { border-radius: 5px; }
      "))
    ),

    tabItems(

      # ================================================================
      # EXECUTIVE DASHBOARD TAB
      # ================================================================
      tabItem(
        tabName = "dashboard",

        # Header
        fluidRow(
          column(
            12,
            h2("📊 Painel Executivo", style = "margin-bottom: 20px;"),
            p("Visão geral do sistema de monitoramento legislativo brasileiro",
              style = "color: #7f8c8d; margin-bottom: 30px;")
          )
        ),

        # KPI Value Boxes
        fluidRow(
          column(4, uiOutput("total_docs_box")),
          column(4, uiOutput("states_box")),
          column(4, uiOutput("municipalities_box"))
        ),

        # Charts Row
        fluidRow(
          box(
            title = "Distribuição por Estado",
            status = "primary",
            solidHeader = TRUE,
            width = 6,
            plotlyOutput("state_chart", height = 400)
          ),
          box(
            title = "Distribuição por Categoria",
            status = "info",
            solidHeader = TRUE,
            width = 6,
            plotlyOutput("category_chart", height = 400)
          )
        ),

        # Info Box
        fluidRow(
          box(
            title = "Status do Sistema",
            status = "success",
            solidHeader = TRUE,
            width = 12,
            div(
              style = "padding: 10px;",
              icon("check-circle", class = "fa-2x", style = "color: #27ae60; margin-right: 15px;"),
              strong("Sistema operacional"),
              br(),
              "Dados atualizados em tempo real | Cache ativo | Workers assíncronos disponíveis"
            )
          )
        )
      ),

      # ================================================================
      # SEARCH TAB
      # ================================================================
      tabItem(
        tabName = "search",

        fluidRow(
          column(
            12,
            h2("🔍 Busca Avançada", style = "margin-bottom: 20px;"),
            p("Interface de busca com filtros especializados",
              style = "color: #7f8c8d; margin-bottom: 30px;")
          )
        ),

        # Search Controls
        fluidRow(
          box(
            title = "Filtros de Busca",
            status = "primary",
            solidHeader = TRUE,
            width = 12,

            fluidRow(
              column(
                6,
                textInput(
                  "search_text",
                  "Termo de busca:",
                  placeholder = "Digite palavras-chave..."
                )
              ),
              column(
                3,
                selectInput(
                  "filter_state",
                  "Estado:",
                  choices = c("Todos" = "all", "SP", "RJ", "MG", "RS", "PR", "BA"),
                  selected = "all"
                )
              ),
              column(
                3,
                br(),
                actionButton(
                  "search_btn",
                  "Buscar",
                  icon = icon("search"),
                  class = "btn-primary btn-block",
                  style = "margin-top: 0px;"
                )
              )
            )
          )
        ),

        # Results Table
        fluidRow(
          box(
            title = "Resultados",
            status = "info",
            solidHeader = TRUE,
            width = 12,
            DTOutput("search_results_table")
          )
        )
      ),

      # ================================================================
      # MAPS TAB
      # ================================================================
      tabItem(
        tabName = "maps",

        fluidRow(
          column(
            12,
            h2("🗺️ Visualização Geográfica", style = "margin-bottom: 20px;"),
            p("Distribuição espacial de documentos legislativos no Brasil",
              style = "color: #7f8c8d; margin-bottom: 30px;")
          )
        ),

        fluidRow(
          box(
            title = "Mapa do Brasil",
            status = "primary",
            solidHeader = TRUE,
            width = 12,

            # Controls
            div(
              style = "margin-bottom: 15px;",
              actionButton(
                "load_map_btn",
                "Carregar Mapa Coroplético",
                icon = icon("globe"),
                class = "btn-primary"
              ),
              tags$small(
                " (Clique para carregar distribuição de documentos por estado)",
                style = "color: #7f8c8d; margin-left: 10px;"
              )
            ),

            # Map container
            leafletOutput("brazil_map", height = 600)
          )
        )
      ),

      # ================================================================
      # ANALYTICS TAB
      # ================================================================
      tabItem(
        tabName = "analytics",

        fluidRow(
          column(
            12,
            h2("📈 Analytics Avançados", style = "margin-bottom: 20px;"),
            p("Análises temporais, tendências e padrões legislativos",
              style = "color: #7f8c8d; margin-bottom: 30px;")
          )
        ),

        fluidRow(
          box(
            title = "Análise de Padrões",
            status = "warning",
            solidHeader = TRUE,
            width = 12,

            p("Execute análises complexas que processam milhares de documentos:"),

            actionButton(
              "run_analysis_btn",
              "Executar Análise (Async)",
              icon = icon("cogs"),
              class = "btn-warning"
            ),

            br(), br(),

            div(
              style = "padding: 20px; background: #f8f9fa; border-radius: 5px; min-height: 100px;",
              textOutput("heavy_analysis")
            ),

            br(),

            div(
              class = "alert alert-info",
              icon("info-circle"),
              strong(" Nota: "),
              "Esta operação roda em background e não bloqueia a interface."
            )
          )
        )
      )
    )
  )
)
