# Legislative Monitor R Shiny Application
# REAL Brazilian Legislative Data from Government APIs
# Academic Research Tool

# Load environment and required packages
source(".Rprofile")

# Load all modules
source("R/auth.R")
source("R/api_client.R")
source("R/data_processor.R")
source("R/map_generator.R")
source("R/export_utils.R")
source("R/database.R")

# Initialize application
flog.info("Starting Legislative Monitor R Application")

# Initialize database
init_success <- init_database()
if (!init_success) {
  flog.error("Failed to initialize database")
}

# Load geographic data at startup
geography_data <- load_brazil_geography()

# =============================================================================
# USER INTERFACE
# =============================================================================

# Create main UI function that requires authentication
create_main_ui <- function() {
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
      format = "dd/mm/yyyy",
      language = "pt-BR"
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
      tags$link(rel = "stylesheet", type = "text/css", href = "custom.css")
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
}

# Main UI with authentication wrapper
ui <- fluidPage(
  uiOutput("ui")
)

# =============================================================================
# SERVER LOGIC
# =============================================================================

server <- function(input, output, session) {
  
  # Initialize authentication state
  if (is.null(session$userData$authenticated)) {
    session$userData$authenticated <- FALSE
  }
  
  # Handle authentication and UI switching
  observe({
    if (!is_authenticated(session)) {
      # Show login UI
      output$ui <- renderUI({
        create_login_ui()
      })
      
      # Handle login
      handle_login(input, output, session)
      
    } else {
      # Show main application UI
      output$ui <- renderUI({
        create_main_ui()
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
}

# =============================================================================
# RUN APPLICATION
# =============================================================================

# Create the Shiny app object
shinyApp(ui = ui, server = server)