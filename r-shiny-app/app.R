# Legislative Monitor R Shiny Application
# REAL Brazilian Legislative Data from Government APIs
# Academic Research Tool

# --- DEBUG TRACING FOR WRITEIMPL WARNING ---
message(">>>> APP.R DEBUG TRACING ENABLED <<<<")

# Wrap cat() to trace multi-element vectors
old_cat <- base::cat
cat <- function(..., file = "", sep = " ", fill = FALSE, labels = NULL, append = FALSE) {
  args <- list(...)
  if (length(args) > 0 && is.character(args[[1]]) && length(args[[1]]) > 1) {
    message("=== CAT MULTI-ELEMENT DETECTED ===")
    message(paste("Length:", length(args[[1]])))
    message(paste("Content preview:", paste(head(args[[1]], 3), collapse = " | ")))
    message("Call stack:")
    print(sys.calls())
    message("=== END CAT TRACE ===")
  }
  old_cat(..., file = file, sep = sep, fill = fill, labels = labels, append = append)
}

# Wrap writeLines() to trace multi-element vectors
old_writeLines <- base::writeLines
writeLines <- function(text, con = stdout(), sep = "\n", useBytes = FALSE) {
  if (is.character(text) && length(text) > 1) {
    message("=== WRITELINES MULTI-ELEMENT DETECTED ===")
    message(paste("Length:", length(text)))
    message(paste("Content preview:", paste(head(text, 3), collapse = " | ")))
    message("Call stack:")
    print(sys.calls())
    message("=== END WRITELINES TRACE ===")
  }
  old_writeLines(text, con = con, sep = sep, useBytes = useBytes)
}
# --- END DEBUG TRACING ---

# Add health check handler with writeImpl fix
message(">>>> Setting up health check handler <<<<")

# Fix for writeImpl issue - ensure single element character vectors
options(shiny.http.response.filter = function(req, res) {
  if (!is.null(req$PATH_INFO) && req$PATH_INFO == "/health") {
    message("=== HEALTH CHECK REQUEST RECEIVED ===")
    
    # Method 1: Try using shiny's built-in response
    res$status <- 200L
    res$headers[["Content-Type"]] <- "text/plain"
    res$headers[["Access-Control-Allow-Origin"]] <- "https://sofiadonario.github.io"
    res$headers[["Access-Control-Allow-Methods"]] <- "GET, OPTIONS"
    res$headers[["Access-Control-Allow-Headers"]] <- "Content-Type"
    res$body <- as.character("OK")
    
    message(paste("Response body class:", class(res$body)))
    message(paste("Response body length:", length(res$body)))
    message(paste("Response body content:", res$body))
    
    return(res)
  }
  return(res)
})

# Register /health handler with CORS support
registerHttpHandler("/health", function(req) {
  # Pre-flight
  if (identical(req$REQUEST_METHOD, "OPTIONS")) {
    return(list(
      status = 204L,
      headers = list(
        "Access-Control-Allow-Origin" = "https://sofiadonario.github.io",
        "Access-Control-Allow-Methods" = "GET, OPTIONS",
        "Access-Control-Allow-Headers" = "Content-Type"
      ),
      body = ""
    ))
  }
  # Normal GET
  list(
    status = 200L,
    headers = list(
      "Content-Type" = "text/plain",
      "Access-Control-Allow-Origin" = "https://sofiadonario.github.io"
    ),
    body = "OK"
  )
})

# Load environment and required packages
source(".Rprofile")

# Load all modules
source("R/auth.R")
source("R/api_client.R")
source("R/data_processor.R")
source("R/map_generator.R")
source("R/export_utils.R")
source("R/database.R")
source("R/urn_parser_integration.R")

# Initialize application
flog.info("Starting Legislative Monitor R Application")

# Initialize database
init_success <- init_database()
if (!init_success) {
  flog.error("Failed to initialize database")
}

# Load geographic data at startup
geography_data <- load_brazil_geography()

# Load parsed URN data at startup
urn_data <- load_parsed_urn_data()
flog.info("Loaded %d parsed URN records at startup", nrow(urn_data))

# =============================================================================
# USER INTERFACE
# =============================================================================

# Create main UI function that requires authentication
create_main_ui <- function() {
  tryCatch({
    dashboardPage(
      
      # Header
      dashboardHeader(
        title = "Monitor Legislativo Acadêmico",
        titleWidth = 300,
        
        # User info and logout in header
        tags$li(class = "dropdown",
                style = "padding: 15px 10px; margin-right: 10px;",
                tags$span(style = "color: white;",
                         icon("user"), " Usuário conectado | "),
                actionLink("logout_link", 
                          tags$span(style = "color: white;", 
                                   icon("sign-out"), " Sair"))
        )
      ),
  
  # Sidebar
  dashboardSidebar(
    width = 300,
    
    sidebarMenu(
      menuItem("🗺️ Mapa Interativo", tabName = "map", icon = icon("map")),
      menuItem("📊 Dados e Análise", tabName = "data", icon = icon("table")),
      menuItem("🔍 Análise de URN", tabName = "urn_analysis", icon = icon("search")),
      menuItem("📋 Exportar", tabName = "export", icon = icon("download")),
      menuItem("⚙️ Configurações", tabName = "settings", icon = icon("cog")),
      menuItem("ℹ️ Sobre", tabName = "about", icon = icon("info"))
    ),
    
    # Search and Filter Panel
    h4("🔍 Busca e Filtros"),
    
    # Text search
    textInput(
      "search_text",
      "Buscar documentos:",
      placeholder = "Digite palavras-chave..."
    ),
    
    # Date range
    dateRangeInput(
      "date_range",
      "Período:",
      start = Sys.Date() - 365,  # Last year
      end = Sys.Date(),
      format = "dd/mm/yyyy"
    ),
    
    # Document types
    checkboxGroupInput(
      "document_types",
      "Tipos de documento:",
      choices = list(
        "Leis" = "lei",
        "Decretos" = "decreto", 
        "Portarias" = "portaria",
        "Resoluções" = "resolucao",
        "Medidas Provisórias" = "medida_provisoria"
      ),
      selected = c("lei", "decreto")
    ),
    
    # States selection
    selectInput(
      "states_filter",
      "Estados:",
      choices = c("Todos" = "all", 
                 "Acre" = "AC", "Alagoas" = "AL", "Amapá" = "AP", "Amazonas" = "AM",
                 "Bahia" = "BA", "Ceará" = "CE", "Distrito Federal" = "DF", 
                 "Espírito Santo" = "ES", "Goiás" = "GO", "Maranhão" = "MA",
                 "Mato Grosso" = "MT", "Mato Grosso do Sul" = "MS", 
                 "Minas Gerais" = "MG", "Pará" = "PA", "Paraíba" = "PB",
                 "Paraná" = "PR", "Pernambuco" = "PE", "Piauí" = "PI",
                 "Rio de Janeiro" = "RJ", "Rio Grande do Norte" = "RN",
                 "Rio Grande do Sul" = "RS", "Rondônia" = "RO", "Roraima" = "RR",
                 "Santa Catarina" = "SC", "São Paulo" = "SP", "Sergipe" = "SE",
                 "Tocantins" = "TO"),
      selected = "all",
      multiple = TRUE
    ),
    
    # Action buttons
    br(),
    actionButton("btn_search", "🔍 Buscar", class = "btn-primary", width = "100%"),
    br(), br(),
    actionButton("btn_clear", "🗑️ Limpar Filtros", class = "btn-warning", width = "100%"),
    
    # API Status
    br(),
    h5("📡 Status das APIs"),
    verbatimTextOutput("api_status", placeholder = TRUE)
  ),
  
  # Main content
  dashboardBody(
    
    # Custom CSS
    tags$head(
      tags$link(rel = "stylesheet", type = "text/css", href = "custom.css"),
      HTML('<meta http-equiv="Content-Security-Policy" content="frame-ancestors \'self\' https://sofiadonario.github.io;">')
    ),
    
    tabItems(
      
      # MAP TAB
      tabItem(
        tabName = "map",
        
        fluidRow(
          # Map controls
          box(
            title = "🗺️ Mapa Legislativo do Brasil", 
            status = "primary", 
            solidHeader = TRUE,
            width = 9,
            height = "80vh",
            
            leafletOutput("brazil_map", height = "70vh")
          ),
          
          # Map info panel
          box(
            title = "📊 Informações",
            status = "info",
            solidHeader = TRUE,
            width = 3,
            height = "80vh",
            
            valueBoxOutput("total_docs", width = 12),
            valueBoxOutput("states_count", width = 12),
            valueBoxOutput("latest_doc", width = 12),
            
            br(),
            h5("🎛️ Controles do Mapa"),
            radioButtons(
              "map_color_by",
              "Colorir por:",
              choices = list(
                "Número de documentos" = "count",
                "Densidade (docs/km²)" = "density",
                "Data mais recente" = "latest"
              ),
              selected = "count"
            ),
            
            checkboxInput("show_municipalities", "Mostrar municípios", FALSE),
            checkboxInput("show_recent_docs", "Mostrar docs recentes", TRUE),
            
            br(),
            actionButton("btn_refresh_map", "🔄 Atualizar Mapa", class = "btn-success")
          )
        ),
        
        # Selected location info
        fluidRow(
          conditionalPanel(
            condition = "output.selected_location",
            box(
              title = "📍 Localização Selecionada",
              status = "success",
              solidHeader = TRUE,
              width = 12,
              collapsible = TRUE,
              
              htmlOutput("location_details")
            )
          )
        )
      ),
      
      # URN ANALYSIS TAB  
      tabItem(
        tabName = "urn_analysis",
        
        fluidRow(
          box(
            title = "📈 Resumo da Análise de URN",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            
            fluidRow(
              valueBoxOutput("urn_total_docs", width = 3),
              valueBoxOutput("urn_legislation_count", width = 3),
              valueBoxOutput("urn_jurisprudence_count", width = 3),
              valueBoxOutput("urn_coverage_rate", width = 3)
            )
          )
        ),
        
        fluidRow(
          box(
            title = "🔍 Filtros de URN",
            status = "info",
            solidHeader = TRUE,
            width = 3,
            
            radioButtons(
              "urn_filter_type",
              "Tipo de Documento:",
              choices = list(
                "Todos" = "all",
                "Legislação" = "legislation",
                "Jurisprudência" = "jurisprudence"
              ),
              selected = "all"
            ),
            
            hr(),
            
            conditionalPanel(
              condition = "input.urn_filter_type == 'legislation' || input.urn_filter_type == 'all'",
              h5("📋 Filtros de Legislação"),
              selectInput(
                "urn_state_filter",
                "Estado:",
                choices = NULL,  # Will be populated by server
                multiple = TRUE
              ),
              selectInput(
                "urn_municipality_filter", 
                "Município:",
                choices = NULL,  # Will be populated by server
                multiple = TRUE
              )
            ),
            
            conditionalPanel(
              condition = "input.urn_filter_type == 'jurisprudence' || input.urn_filter_type == 'all'",
              h5("⚖️ Filtros de Jurisprudência"),
              selectInput(
                "urn_justice_filter",
                "Tipo de Justiça:",
                choices = NULL,  # Will be populated by server
                multiple = TRUE
              ),
              selectInput(
                "urn_region_filter",
                "Região Judicial:", 
                choices = NULL,  # Will be populated by server
                multiple = TRUE
              )
            ),
            
            br(),
            actionButton("btn_apply_urn_filters", "🔍 Aplicar Filtros", 
                        class = "btn-primary", width = "100%"),
            br(), br(),
            actionButton("btn_clear_urn_filters", "🗑️ Limpar Filtros", 
                        class = "btn-warning", width = "100%")
          ),
          
          box(
            title = "📊 Distribuição por Tipo",
            status = "success",
            solidHeader = TRUE,
            width = 4,
            
            plotOutput("urn_type_plot", height = "300px")
          ),
          
          box(
            title = "📅 Distribuição Temporal",
            status = "warning", 
            solidHeader = TRUE,
            width = 5,
            
            plotOutput("urn_temporal_plot", height = "300px")
          )
        ),
        
        fluidRow(
          box(
            title = "🗺️ Análise Geográfica (Legislação)",
            status = "primary",
            solidHeader = TRUE,
            width = 6,
            
            plotOutput("urn_state_plot", height = "400px")
          ),
          
          box(
            title = "⚖️ Análise Judicial (Jurisprudência)",
            status = "danger",
            solidHeader = TRUE,
            width = 6,
            
            plotOutput("urn_justice_plot", height = "400px") 
          )
        ),
        
        fluidRow(
          box(
            title = "📋 Dados Detalhados de URN",
            status = "info",
            solidHeader = TRUE,
            width = 12,
            
            DT::dataTableOutput("urn_details_table"),
            
            br(),
            
            fluidRow(
              column(6, 
                     h5("📊 Estatísticas:"),
                     verbatimTextOutput("urn_filtered_stats")
              ),
              column(6,
                     div(style = "text-align: right;",
                         br(),
                         downloadButton("download_urn_analysis", "📥 Baixar Análise URN", 
                                      class = "btn-success")
                     )
              )
            )
          )
        )
      ),
      
      # DATA TAB
      tabItem(
        tabName = "data",
        
        fluidRow(
          box(
            title = "📊 Resultados da Busca",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            
            # Data table
            DT::dataTableOutput("results_table"),
            
            br(),
            
            # Pagination and summary
            fluidRow(
              column(6, textOutput("results_summary")),
              column(6, 
                     div(style = "text-align: right;",
                         downloadButton("download_results", "📥 Baixar Resultados", 
                                      class = "btn-success")
                     )
              )
            )
          )
        ),
        
        # Document details modal trigger
        fluidRow(
          box(
            title = "📋 Análise dos Dados",
            status = "info", 
            solidHeader = TRUE,
            width = 6,
            
            h5("Distribuição por Tipo"),
            plotOutput("type_distribution", height = "300px")
          ),
          
          box(
            title = "📅 Distribuição Temporal", 
            status = "warning",
            solidHeader = TRUE,
            width = 6,
            
            h5("Documentos por Ano"),
            plotOutput("temporal_distribution", height = "300px")
          )
        )
      ),
      
      # EXPORT TAB
      tabItem(
        tabName = "export",
        
        fluidRow(
          box(
            title = "📤 Exportar Dados",
            status = "primary",
            solidHeader = TRUE,
            width = 8,
            
            h4("Selecione o formato de exportação:"),
            
            radioButtons(
              "export_format",
              "Formato:",
              choices = list(
                "📊 CSV - Dados tabulares" = "csv",
                "📋 Excel - Planilha completa" = "xlsx", 
                "🔖 XML - Dados estruturados" = "xml",
                "📄 HTML - Relatório formatado" = "html",
                "📰 PDF - Relatório acadêmico" = "pdf"
              ),
              selected = "csv"
            ),
            
            h4("Opções de exportação:"),
            
            checkboxInput("export_include_metadata", "Incluir metadados e citações", TRUE),
            checkboxInput("export_include_summary", "Incluir resumo estatístico", TRUE),
            checkboxInput("export_include_maps", "Incluir visualizações (HTML/PDF)", FALSE),
            
            br(),
            
            # Export controls
            fluidRow(
              column(6,
                     numericInput("export_limit", "Máximo de registros:", 
                                value = 1000, min = 1, max = 10000, step = 100)
              ),
              column(6,
                     selectInput("export_sort", "Ordenar por:",
                               choices = list(
                                 "Data (mais recente)" = "data_desc",
                                 "Data (mais antigo)" = "data_asc", 
                                 "Título (A-Z)" = "titulo_asc",
                                 "Estado" = "estado"
                               ),
                               selected = "data_desc")
              )
            ),
            
            br(),
            
            actionButton("btn_export", "📦 Gerar Exportação", 
                        class = "btn-success btn-lg", width = "100%"),
            
            br(), br(),
            
            # Export status
            conditionalPanel(
              condition = "output.export_status",
              div(id = "export_status_div",
                  htmlOutput("export_status")
              )
            )
          ),
          
          box(
            title = "📋 Citação Acadêmica",
            status = "info",
            solidHeader = TRUE,
            width = 4,
            
            h5("Como citar esta pesquisa:"),
            
            wellPanel(
              style = "background-color: #f8f9fa;",
              p(strong("Citação sugerida:")),
              p(em("Monitor Legislativo Acadêmico. Dados legislativos georeferenciados do Brasil. 
                   Consultado em ", format(Sys.Date(), "%d de %B de %Y"), ". 
                   Disponível em: [URL da aplicação].")),
              
              br(),
              
              p(strong("Fontes de dados:")),
              tags$ul(
                tags$li("Câmara dos Deputados - dadosabertos.camara.leg.br"),
                tags$li("Senado Federal - legis.senado.leg.br"),
                tags$li("LexML Brasil - lexml.gov.br"),
                tags$li("Assembleias Legislativas Estaduais"),
                tags$li("Câmaras Municipais")
              )
            ),
            
            h5("📊 Estatísticas da Base de Dados"),
            verbatimTextOutput("database_stats")
          )
        ),
        
        # Export history
        fluidRow(
          box(
            title = "📚 Histórico de Exportações",
            status = "warning",
            solidHeader = TRUE,
            width = 12,
            collapsible = TRUE,
            collapsed = TRUE,
            
            DT::dataTableOutput("export_history_table")
          )
        )
      ),
      
      # SETTINGS TAB
      tabItem(
        tabName = "settings",
        
        fluidRow(
          box(
            title = "⚙️ Configurações da Aplicação",
            status = "primary",
            solidHeader = TRUE,
            width = 6,
            
            h4("📡 APIs de Dados"),
            
            checkboxGroupInput(
              "enabled_apis",
              "APIs ativas:",
              choices = list(
                "Câmara dos Deputados" = "camara",
                "Senado Federal" = "senado",
                "LexML Brasil" = "lexml",
                "Assembleias Estaduais" = "states"
              ),
              selected = c("camara", "senado", "lexml")
            ),
            
            h4("🗄️ Cache e Performance"),
            
            numericInput("cache_duration", "Duração do cache (horas):", 
                        value = 24, min = 1, max = 168),
            
            numericInput("max_results", "Máximo de resultados por consulta:",
                        value = 1000, min = 100, max = 5000, step = 100),
            
            br(),
            
            actionButton("btn_clear_cache", "🗑️ Limpar Cache", class = "btn-warning"),
            br(), br(),
            actionButton("btn_backup_db", "💾 Backup do Banco", class = "btn-info")
          ),
          
          box(
            title = "📊 Monitoramento do Sistema",
            status = "info",
            solidHeader = TRUE,
            width = 6,
            
            h4("📈 Estatísticas de Uso"),
            
            valueBoxOutput("system_uptime", width = 12),
            valueBoxOutput("total_queries", width = 12),
            valueBoxOutput("cache_hit_rate", width = 12),
            
            h4("💾 Uso de Memória"),
            verbatimTextOutput("memory_usage"),
            
            h4("🌐 Status das APIs"),
            verbatimTextOutput("detailed_api_status")
          )
        ),
        
        # Logs panel
        fluidRow(
          box(
            title = "📝 Logs da Aplicação",
            status = "warning",
            solidHeader = TRUE,
            width = 12,
            collapsible = TRUE,
            collapsed = TRUE,
            
            verbatimTextOutput("app_logs")
          )
        )
      ),
      
      # ABOUT TAB
      tabItem(
        tabName = "about",
        
        fluidRow(
          box(
            title = "ℹ️ Sobre o Monitor Legislativo Acadêmico",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            
            h3("🎯 Objetivo"),
            p("Esta aplicação foi desenvolvida para pesquisadores acadêmicos que necessitam de 
              acesso estruturado e visualização de dados legislativos brasileiros de fontes oficiais."),
            
            h3("📊 Fontes de Dados"),
            p("Todos os dados são obtidos diretamente de APIs oficiais do governo brasileiro:"),
            
            tags$ul(
              tags$li(strong("Federal:"), "Câmara dos Deputados, Senado Federal, LexML Brasil"),
              tags$li(strong("Estadual:"), "Assembleias Legislativas dos 27 estados"),
              tags$li(strong("Municipal:"), "Câmaras Municipais das principais cidades")
            ),
            
            h3("🛠️ Tecnologia"),
            p("Aplicação desenvolvida em R com as seguintes tecnologias:"),
            
            fluidRow(
              column(6,
                     tags$ul(
                       tags$li("R Shiny - Interface web"),
                       tags$li("Leaflet - Mapas interativos"),
                       tags$li("geobr - Dados geográficos IBGE"),
                       tags$li("DT - Tabelas de dados")
                     )
              ),
              column(6,
                     tags$ul(
                       tags$li("SQLite - Banco de dados local"),
                       tags$li("httr - Comunicação com APIs"),
                       tags$li("dplyr - Processamento de dados"),
                       tags$li("ggplot2 - Visualizações")
                     )
              )
            ),
            
            h3("💰 Custo de Infraestrutura"),
            
            wellPanel(
              style = "background-color: #d4edda; border-color: #c3e6cb;",
              h4("✅ Objetivo alcançado: < $30/mês"),
              
              tags$ul(
                tags$li("Hospedagem: Gratuita (Shinyapps.io free tier)"),
                tags$li("APIs: Gratuitas (governo brasileiro)"),
                tags$li("Dados geográficos: Gratuitos (IBGE via geobr)"),
                tags$li("Storage: SQLite local (sem custos)")
              ),
              
              p(strong("Total estimado: $0-15/mês"), 
                "(apenas se precisar de tier pago do Shinyapps.io para mais usuários)")
            ),
            
            h3("📄 Licença e Uso Acadêmico"),
            p("Esta aplicação é disponibilizada gratuitamente para uso acadêmico e de pesquisa. 
              Todos os dados utilizados são de domínio público e obtidos de fontes oficiais."),
            
            h3("📞 Suporte"),
            p("Para questões técnicas ou sugestões de melhoria, abra uma issue no repositório do projeto."),
            
            br(),
            
            div(style = "text-align: center; padding: 20px; background-color: #f8f9fa; border-radius: 5px;",
                h4("🚀 Versão 1.0.0"),
                p("Desenvolvido como ferramenta acadêmica para pesquisa em legislação brasileira"),
                p(em("Última atualização: ", format(Sys.Date(), "%d de %B de %Y")))
            )
          )
        )
      )
    )
  )
  )
  }, error = function(e) {
    # Return simple UI if main UI fails
    fluidPage(
      h2("⚠️ Dashboard Loading Error"),
      p("There was an error loading the main dashboard."),
      p("Error:", e$message),
      br(),
      actionButton("logout_link", "Back to Login", class = "btn-warning")
    )
  })
}

# Main UI with authentication wrapper
ui <- fluidPage(
  tags$head(
    # This is a meta tag fallback, but the primary fix is in the server function.
    HTML('<meta http-equiv="Content-Security-Policy" content="frame-ancestors \'self\' https://sofiadonario.github.io;">')
  ),
  uiOutput("ui")
)

# =============================================================================
# SERVER LOGIC
# =============================================================================

server <- function(input, output, session) {
  
  # DEFINITIVE CORS FIX: Set headers on all responses. This must be the first observer.
  observe({
    add_headers <- function(res) {
      res$headers$`Access-Control-Allow-Origin` <- "*"
      res
    }
    session$registerDataObj(name = "cors-headers", data = list(), filter = add_headers)
  })

  # Add CORS headers for React integration
  session$allowReconnect("force")
  
  # Set CORS headers for all responses
  observe({
    session$sendCustomMessage(type = 'set-headers', message = list(
      "Access-Control-Allow-Origin" = "*",
      "Access-Control-Allow-Methods" = "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers" = "Content-Type, Authorization, X-Requested-With"
    ))
  })
  
  # Initialize authentication state
  if (is.null(session$userData$authenticated)) {
    session$userData$authenticated <- FALSE
  }
  
  # Create reactive authentication state
  auth_state <- reactive({
    # This will react to changes in session$userData$authenticated
    session$userData$authenticated
  })
  
  # Handle authentication and UI switching
  observe({
    auth_state()  # Make sure this reactive runs
    
    flog.info("UI Observer triggered - Auth state: %s", auth_state())
    
    if (!is_authenticated(session)) {
      flog.info("User not authenticated - showing login UI")
      # Show login UI
      output$ui <- renderUI({
        create_login_ui()
      })
      
      # Handle login
      handle_login(input, output, session)
      
    } else {
      flog.info("User authenticated - attempting to load main UI")
      # Show main application UI
      output$ui <- renderUI({
        tryCatch({
          result <- create_main_ui()
          flog.info("Main UI created successfully")
          result
        }, error = function(e) {
          flog.error("Error creating main UI: %s", e$message)
          fluidPage(
            h2("⚠️ Dashboard Error"),
            p("Error loading dashboard:", e$message),
            actionButton("logout_link", "Back to Login")
          )
        })
      })
    }
  })
  
  # Handle logout
  observeEvent(input$logout_link, {
    logout_user(session)
  })
  
  # Reactive values (available to all parts of the app)
  values <- reactiveValues(
    current_data = NULL,
    selected_state = NULL,
    search_filters = list(),
    export_progress = NULL
  )
  
  # Main data search function (only works if authenticated)
  search_legislative_data <- reactive({
    req(is_authenticated(session))
    
    # ==========================================================================
    # DATA LOADING AND PROCESSING
    # ==========================================================================
    
    # Trigger search when button is clicked or filters change
    input$btn_search
    
    isolate({
      flog.info("Starting legislative data search")
      
      # Build filters
      filters <- list()
      
      # Text search
      if (!is.null(input$search_text) && nchar(input$search_text) > 0) {
        filters$search_text <- input$search_text
      }
      
      # Date range
      if (!is.null(input$date_range)) {
        filters$date_from <- input$date_range[1]
        filters$date_to <- input$date_range[2]
      }
      
      # Document types
      if (!is.null(input$document_types) && length(input$document_types) > 0) {
        filters$tipo <- input$document_types
      }
      
      # States
      if (!is.null(input$states_filter) && !"all" %in% input$states_filter) {
        filters$estado <- input$states_filter
      }
      
      values$search_filters <- filters
      
      # Try to load from database first
      db_data <- load_legislative_data(filters, limit = input$max_results %||% 1000)
      
      if (!is.null(db_data) && nrow(db_data) > 0) {
        flog.info("Loaded %d records from database", nrow(db_data))
        values$current_data <- db_data
        return(db_data)
      }
      
      # If no data in database, fetch from APIs
      withProgress(message = "Coletando dados das APIs governamentais...", value = 0, {
        
        incProgress(0.2, detail = "Câmara dos Deputados...")
        
        # Fetch fresh data from APIs
        fresh_data <- fetch_all_legislative_data(
          date_from = filters$date_from,
          date_to = filters$date_to,
          states = if (!"all" %in% input$states_filter) input$states_filter else NULL,
          query = filters$search_text,
          max_results = input$max_results %||% 1000
        )
        
        incProgress(0.6, detail = "Processando dados...")
        
        if (!is.null(fresh_data)) {
          # Standardize and validate data
          processed_data <- standardize_legislative_data(fresh_data)
          processed_data <- validate_legislative_data(processed_data)
          processed_data <- remove_duplicates(processed_data)
          processed_data <- enrich_geographic_data(processed_data)
          
          incProgress(0.8, detail = "Salvando no banco...")
          
          # Save to database
          save_legislative_data(processed_data, overwrite = TRUE)
          
          incProgress(1.0, detail = "Concluído!")
          
          values$current_data <- processed_data
          return(processed_data)
        } else {
          showNotification("Nenhum dado encontrado nas APIs", type = "warning")
          return(NULL)
        }
      })
    })
  })
  
  # ==========================================================================
  # MAP OUTPUTS
  # ==========================================================================
  
  # Main Brazil map
  output$brazil_map <- renderLeaflet({
    req(is_authenticated(session))
    
    data <- search_legislative_data()
    
    if (is.null(data) || nrow(data) == 0) {
      # Show empty map with message
      leaflet() %>%
        addProviderTiles(providers$CartoDB.Positron) %>%
        setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
        addPopups(lng = -47.9292, lat = -15.7801, 
                 popup = "Nenhum dado encontrado. Tente ajustar os filtros de busca.")
    } else {
      create_legislative_map(
        legislative_data = data,
        geography_data = geography_data,
        focus_state = values$selected_state,
        color_by = input$map_color_by %||% "count"
      )
    }
  })
  
  # Map state selection
  observeEvent(input$brazil_map_shape_click, {
    req(is_authenticated(session))
    click <- input$brazil_map_shape_click
    if (!is.null(click$id)) {
      values$selected_state <- click$id
      
      # Show state details
      output$selected_location <- reactive({
        !is.null(values$selected_state)
      })
      outputOptions(output, "selected_location", suspendWhenHidden = FALSE)
    }
  })
  
  # Location details
  output$location_details <- renderUI({
    
    if (is.null(values$selected_state) || is.null(values$current_data)) {
      return(NULL)
    }
    
    state_data <- values$current_data %>%
      filter(estado == values$selected_state)
    
    if (nrow(state_data) == 0) {
      return(p("Nenhum documento encontrado para este estado."))
    }
    
    # State summary
    total_docs <- nrow(state_data)
    latest_doc <- state_data %>% arrange(desc(data)) %>% slice(1)
    types_count <- length(unique(state_data$tipo))
    
    tagList(
      fluidRow(
        column(3, valueBox(total_docs, "Documentos", icon = icon("file"), color = "blue", width = NULL)),
        column(3, valueBox(types_count, "Tipos", icon = icon("tags"), color = "green", width = NULL)),
        column(3, valueBox(format(as.Date(latest_doc$data), "%m/%Y"), "Mais Recente", icon = icon("calendar"), color = "orange", width = NULL)),
        column(3, actionButton("btn_focus_state", "Ver Detalhes", class = "btn-primary"))
      ),
      
      hr(),
      
      h5("Documentos Recentes:"),
      
      DT::renderDataTable({
        state_data %>%
          select(Título = titulo, Tipo = tipo, Data = data, Autor = autor) %>%
          arrange(desc(Data)) %>%
          slice_head(n = 10)
      }, options = list(pageLength = 5, scrollX = TRUE))
    )
  })
  
  # Map value boxes
  output$total_docs <- renderValueBox({
    req(is_authenticated(session))
    count <- if (!is.null(values$current_data)) nrow(values$current_data) else 0
    valueBox(count, "Total de Documentos", icon = icon("file-text"), color = "blue")
  })
  
  output$states_count <- renderValueBox({
    req(is_authenticated(session))
    count <- if (!is.null(values$current_data)) {
      length(unique(values$current_data$estado[!is.na(values$current_data$estado)]))
    } else 0
    valueBox(count, "Estados com Dados", icon = icon("map"), color = "green")
  })
  
  output$latest_doc <- renderValueBox({
    req(is_authenticated(session))
    date <- if (!is.null(values$current_data)) {
      format(max(as.Date(values$current_data$data), na.rm = TRUE), "%d/%m/%Y")
    } else "N/A"
    valueBox(date, "Documento Mais Recente", icon = icon("clock"), color = "orange")
  })
  
  # ==========================================================================
  # DATA TAB OUTPUTS
  # ==========================================================================
  
  # Results table
  output$results_table <- DT::renderDataTable({
    req(is_authenticated(session))
    
    data <- values$current_data
    
    if (is.null(data) || nrow(data) == 0) {
      return(data.frame(Mensagem = "Nenhum resultado encontrado. Clique em 'Buscar' para carregar dados."))
    }
    
    # Prepare display data
    display_data <- data %>%
      select(
        Título = titulo,
        Tipo = tipo,
        Número = numero,
        Data = data,
        Estado = estado,
        Autor = autor,
        Fonte = fonte_original
      ) %>%
      mutate(
        Data = format(as.Date(Data), "%d/%m/%Y"),
        Título = str_trunc(Título, 80)
      ) %>%
      arrange(desc(as.Date(Data, format = "%d/%m/%Y")))
    
    display_data
    
  }, options = list(
    pageLength = 25,
    scrollX = TRUE,
    language = list(
      url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
    )
  ))
  
  # Results summary
  output$results_summary <- renderText({
    
    count <- if (!is.null(values$current_data)) nrow(values$current_data) else 0
    paste("Exibindo", count, "documentos legislativos")
  })
  
  # Analysis plots
  output$type_distribution <- renderPlot({
    
    data <- values$current_data
    
    if (is.null(data) || nrow(data) == 0) {
      return(ggplot() + 
             annotate("text", x = 0.5, y = 0.5, label = "Sem dados para exibir") +
             theme_void())
    }
    
    type_counts <- data %>%
      count(tipo, sort = TRUE) %>%
      mutate(tipo = str_to_title(tipo))
    
    ggplot(type_counts, aes(x = reorder(tipo, n), y = n, fill = tipo)) +
      geom_col() +
      coord_flip() +
      labs(title = "Distribuição por Tipo de Documento",
           x = "Tipo de Documento", 
           y = "Quantidade") +
      theme_minimal() +
      theme(legend.position = "none") +
      scale_fill_viridis_d()
  })
  
  output$temporal_distribution <- renderPlot({
    
    data <- values$current_data
    
    if (is.null(data) || nrow(data) == 0) {
      return(ggplot() + 
             annotate("text", x = 0.5, y = 0.5, label = "Sem dados para exibir") +
             theme_void())
    }
    
    yearly_counts <- data %>%
      count(ano, sort = TRUE) %>%
      filter(!is.na(ano))
    
    ggplot(yearly_counts, aes(x = ano, y = n)) +
      geom_line(color = "steelblue", size = 1.2) +
      geom_point(color = "steelblue", size = 2) +
      labs(title = "Documentos por Ano",
           x = "Ano", 
           y = "Quantidade de Documentos") +
      theme_minimal() +
      scale_x_continuous(breaks = scales::pretty_breaks(n = 8))
  })
  
  # ==========================================================================
  # URN ANALYSIS TAB OUTPUTS
  # ==========================================================================
  
  # URN data filtering
  urn_filtered_data <- reactive({
    
    data <- urn_data
    
    # Apply URN type filter
    if (!is.null(input$urn_filter_type) && input$urn_filter_type != "all") {
      data <- data %>% filter(urn_type == input$urn_filter_type)
    }
    
    # Apply state filter for legislation
    if (!is.null(input$urn_state_filter) && length(input$urn_state_filter) > 0) {
      data <- data %>% filter(state %in% input$urn_state_filter | is.na(state))
    }
    
    # Apply municipality filter for legislation  
    if (!is.null(input$urn_municipality_filter) && length(input$urn_municipality_filter) > 0) {
      data <- data %>% filter(municipality %in% input$urn_municipality_filter | is.na(municipality))
    }
    
    # Apply justice filter for jurisprudence
    if (!is.null(input$urn_justice_filter) && length(input$urn_justice_filter) > 0) {
      data <- data %>% filter(justice %in% input$urn_justice_filter | is.na(justice))
    }
    
    # Apply region filter for jurisprudence
    if (!is.null(input$urn_region_filter) && length(input$urn_region_filter) > 0) {
      data <- data %>% filter(region %in% input$urn_region_filter | is.na(region))
    }
    
    return(data)
  })
  
  # Update filter choices based on available data
  observe({
    
    # Update state choices for legislation
    states <- urn_data %>% 
      filter(urn_type == "legislation", !is.na(state)) %>% 
      distinct(state) %>% 
      arrange(state) %>% 
      pull(state)
    
    updateSelectInput(session, "urn_state_filter", 
                     choices = setNames(states, states))
    
    # Update municipality choices based on selected states
    municipalities <- urn_data %>%
      filter(urn_type == "legislation", !is.na(municipality)) %>%
      distinct(municipality) %>%
      arrange(municipality) %>%
      pull(municipality)
    
    updateSelectInput(session, "urn_municipality_filter",
                     choices = setNames(municipalities, municipalities))
    
    # Update justice type choices for jurisprudence
    justice_types <- urn_data %>%
      filter(urn_type == "jurisprudence", !is.na(justice)) %>%
      distinct(justice) %>%
      arrange(justice) %>%
      pull(justice)
    
    updateSelectInput(session, "urn_justice_filter",
                     choices = setNames(justice_types, justice_types))
    
    # Update region choices for jurisprudence
    regions <- urn_data %>%
      filter(urn_type == "jurisprudence", !is.na(region)) %>%
      distinct(region) %>%
      arrange(region) %>%
      pull(region)
    
    updateSelectInput(session, "urn_region_filter",
                     choices = setNames(regions, regions))
  })
  
  # URN summary value boxes
  output$urn_total_docs <- renderValueBox({
    data <- urn_filtered_data()
    count <- nrow(data)
    valueBox(count, "Total de Documentos", icon = icon("file-text"), color = "blue")
  })
  
  output$urn_legislation_count <- renderValueBox({
    data <- urn_filtered_data()
    count <- sum(data$urn_type == "legislation", na.rm = TRUE)
    valueBox(count, "Legislação", icon = icon("gavel"), color = "green")
  })
  
  output$urn_jurisprudence_count <- renderValueBox({
    data <- urn_filtered_data()
    count <- sum(data$urn_type == "jurisprudence", na.rm = TRUE)
    valueBox(count, "Jurisprudência", icon = icon("balance-scale"), color = "red")
  })
  
  output$urn_coverage_rate <- renderValueBox({
    data <- urn_filtered_data()
    total <- nrow(data)
    parsed <- sum(!is.na(data$urn_type) & data$urn_type != "unknown", na.rm = TRUE)
    rate <- if (total > 0) round(parsed / total * 100, 1) else 0
    valueBox(paste0(rate, "%"), "Taxa de Parsing", icon = icon("chart-line"), color = "yellow")
  })
  
  # URN analysis plots
  output$urn_type_plot <- renderPlot({
    data <- urn_filtered_data()
    plot_urn_type_distribution(data)
  })
  
  output$urn_temporal_plot <- renderPlot({
    data <- urn_filtered_data()
    plot_temporal_distribution(data)
  })
  
  output$urn_state_plot <- renderPlot({
    data <- urn_filtered_data()
    plot_state_distribution(data)
  })
  
  output$urn_justice_plot <- renderPlot({
    data <- urn_filtered_data()
    plot_justice_distribution(data)
  })
  
  # URN details table
  output$urn_details_table <- DT::renderDataTable({
    data <- urn_filtered_data()
    create_urn_datatable(data, input$urn_filter_type %||% "all")
  })
  
  # URN filtered statistics
  output$urn_filtered_stats <- renderText({
    data <- urn_filtered_data()
    summary_stats <- generate_urn_summary(data)
    
    paste(
      "Documentos filtrados:", summary_stats$total_documents,
      "\nLegislação:", paste0(summary_stats$legislation_count, " (", summary_stats$legislation_percentage, "%)"),
      "\nJurisprudência:", paste0(summary_stats$jurisprudence_count, " (", summary_stats$jurisprudence_percentage, "%)"),
      "\nEstados únicos:", summary_stats$unique_states,
      "\nMunicípios únicos:", summary_stats$unique_municipalities,
      "\nPeríodo:", summary_stats$date_range,
      "\nTipos principais:", paste(summary_stats$top_document_types, collapse = ", ")
    )
  })
  
  # URN filter actions
  observeEvent(input$btn_apply_urn_filters, {
    # Trigger reactive update (filters are already applied via reactive)
    showNotification("Filtros aplicados aos dados de URN", type = "message")
  })
  
  observeEvent(input$btn_clear_urn_filters, {
    updateRadioButtons(session, "urn_filter_type", selected = "all")
    updateSelectInput(session, "urn_state_filter", selected = character(0))
    updateSelectInput(session, "urn_municipality_filter", selected = character(0))
    updateSelectInput(session, "urn_justice_filter", selected = character(0))
    updateSelectInput(session, "urn_region_filter", selected = character(0))
    
    showNotification("Filtros de URN limpos", type = "message")
  })
  
  # URN data download
  output$download_urn_analysis <- downloadHandler(
    filename = function() {
      paste0("urn_analysis_", format(Sys.Date(), "%Y%m%d"), ".csv")
    },
    content = function(file) {
      data <- urn_filtered_data()
      write.csv(data, file, row.names = FALSE)
    }
  )
  
  # ==========================================================================
  # EXPORT FUNCTIONALITY
  # ==========================================================================
  
  # Export button handler
  observeEvent(input$btn_export, {
    req(is_authenticated(session))
    
    if (is.null(values$current_data) || nrow(values$current_data) == 0) {
      showNotification("Nenhum dado para exportar. Execute uma busca primeiro.", type = "error")
      return()
    }
    
    withProgress(message = "Gerando exportação...", value = 0, {
      
      export_data <- values$current_data
      
      # Apply export limit
      if (!is.null(input$export_limit) && input$export_limit < nrow(export_data)) {
        export_data <- export_data %>% slice_head(n = input$export_limit)
      }
      
      # Apply sorting
      if (!is.null(input$export_sort)) {
        export_data <- switch(input$export_sort,
          "data_desc" = arrange(export_data, desc(data)),
          "data_asc" = arrange(export_data, data),
          "titulo_asc" = arrange(export_data, titulo),
          "estado" = arrange(export_data, estado, data),
          export_data
        )
      }
      
      incProgress(0.3, detail = "Preparando dados...")
      
      # Generate export based on format
      result_file <- switch(input$export_format,
        "csv" = export_to_csv(export_data, include_metadata = input$export_include_metadata),
        "xlsx" = export_to_excel(export_data, include_summary = input$export_include_summary),
        "xml" = export_to_xml(export_data, include_metadata = input$export_include_metadata),
        "html" = export_to_html(export_data, include_maps = input$export_include_maps),
        "pdf" = export_to_pdf(export_data)
      )
      
      incProgress(1.0, detail = "Concluído!")
      
      if (!is.null(result_file)) {
        output$export_status <- renderUI({
          div(class = "alert alert-success",
              icon("check-circle"), " Exportação concluída com sucesso!",
              br(),
              strong("Arquivo: "), result_file,
              br(),
              downloadLink("download_export_file", "📥 Baixar arquivo", class = "btn btn-success btn-sm")
          )
        })
        
        # Make file available for download
        output$download_export_file <- downloadHandler(
          filename = basename(result_file),
          content = function(file) {
            file.copy(result_file, file)
          }
        )
        
      } else {
        output$export_status <- renderUI({
          div(class = "alert alert-danger",
              icon("exclamation-triangle"), " Erro na exportação. Tente novamente.")
        })
      }
    })
  })
  
  # Database statistics
  output$database_stats <- renderText({
    
    stats <- get_database_stats()
    
    if (is.null(stats)) {
      return("Estatísticas não disponíveis")
    }
    
    paste(
      "Total de documentos:", stats$total_documents,
      "\nEstados únicos:", stats$unique_states,
      "\nEntradas em cache:", stats$cache_entries,
      "\nDocumento mais antigo:", stats$oldest_document,
      "\nDocumento mais recente:", stats$newest_document,
      "\nÚltima atualização:", format(as.POSIXct(stats$last_update), "%d/%m/%Y %H:%M")
    )
  })
  
  # ==========================================================================
  # SETTINGS AND SYSTEM
  # ==========================================================================
  
  # API Status
  output$api_status <- renderText({
    
    status <- check_api_status()
    
    if (is.null(status)) {
      return("Status não disponível")
    }
    
    status_text <- ""
    for (api in names(status)) {
      icon_char <- if (status[[api]]$status == "Online") "✅" else "❌"
      status_text <- paste0(status_text, icon_char, " ", api, "\n")
    }
    
    return(status_text)
  })
  
  # Clear filters
  observeEvent(input$btn_clear, {
    req(is_authenticated(session))
    updateTextInput(session, "search_text", value = "")
    updateDateRangeInput(session, "date_range", start = Sys.Date() - 365, end = Sys.Date())
    updateCheckboxGroupInput(session, "document_types", selected = c("lei", "decreto"))
    updateSelectInput(session, "states_filter", selected = "all")
    
    values$current_data <- NULL
    values$selected_state <- NULL
    
    showNotification("Filtros limpos", type = "message")
  })
  
  # Clear cache
  observeEvent(input$btn_clear_cache, {
    cleaned <- clean_cache()
    showNotification(paste("Cache limpo:", cleaned, "entradas removidas"), type = "success")
  })
  
  # System monitoring
  output$memory_usage <- renderText({
    mem_info <- gc()
    paste("Usado:", round(sum(mem_info[,2]), 1), "MB")
  })
  
  # Close database connection when session ends
  session$onSessionEnded(function() {
    close_database()
    flog.info("Session ended, database connection closed")
  })
  
  # ==============================================================================
  # CRITICAL FIX: Add response headers to allow embedding
  # ==============================================================================
  observe({
    shiny::addCustomMessageHandler("http-headers", function(message) {
      session$sendCustomMessage("http-headers", NULL)
    })
    
    session$onFlushed(function() {
      if (!session$clientData$headersSent) {
        session$sendCustomMessage("http-headers", list(
          "Content-Security-Policy" = "frame-ancestors 'self' https://sofiadonario.github.io",
          "X-Frame-Options" = "ALLOW-FROM https://sofiadonario.github.io"
        ))
      }
    }, once = TRUE)
  })
}

# =============================================================================
# RUN APPLICATION
# =============================================================================

# Add custom HTTP handlers for API endpoints
addResourcePath("health", tempdir())

# Health endpoint handler
health_handler <- function(req) {
  # Set CORS headers
  headers <- list(
    "Access-Control-Allow-Origin" = "*",
    "Access-Control-Allow-Methods" = "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers" = "Content-Type, Authorization, X-Requested-With",
    "Content-Type" = "application/json"
  )
  
  # Handle OPTIONS preflight request
  if (req$REQUEST_METHOD == "OPTIONS") {
    return(list(
      status = 200L,
      headers = headers,
      body = ""
    ))
  }
  
  # Health check response
  response_body <- jsonlite::toJSON(list(
    status = "healthy",
    timestamp = Sys.time(),
    version = "1.0.0"
  ), auto_unbox = TRUE)
  
  return(list(
    status = 200L,
    headers = headers,
    body = response_body
  ))
}

# Configure Shiny with CORS support
options(shiny.port = 3838)
options(shiny.host = "0.0.0.0")

# Enable CORS in httpuv
options(shiny.cors = TRUE)

# Add custom filter for CORS headers
addResourcePath("api", tempdir())

# Create the Shiny app object with CORS support
runApp(
  list(ui = ui, server = server),
  host = "0.0.0.0",
  port = 3838,
  options = list(
    # Enable CORS
    "shiny.cors" = TRUE,
    # Add CORS headers
    "shiny.sanitize.errors" = FALSE
  )
)