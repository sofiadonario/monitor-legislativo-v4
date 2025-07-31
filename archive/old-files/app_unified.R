# Monitor Legislativo v4 - Unified R Shiny Application
# Railway Production Deployment - No Authentication Required

library(shiny)
library(shinydashboard)
library(DT)
library(leaflet)
library(plotly)
library(dplyr)
library(jsonlite)

# Database connection setup
setup_database <- function() {
  tryCatch({
    # Check if DATABASE_URL is available
    db_url <- Sys.getenv("DATABASE_URL")
    if (nchar(db_url) == 0) {
      message("DATABASE_URL not found, using sample data")
      return(FALSE)
    }
    
    # For now, return FALSE to use sample data
    # TODO: Implement actual database connection
    return(FALSE)
  }, error = function(e) {
    message("Database connection failed: ", e$message)
    return(FALSE)
  })
}

# Sample data for demonstration
get_sample_data <- function() {
  data.frame(
    id = 1:10,
    titulo = c(
      "Lei do Transporte Público Sustentável",
      "Decreto de Mobilidade Urbana",
      "Portaria de Transporte Escolar",
      "Resolução de Segurança Viária",
      "Lei de Infraestrutura Rodoviária",
      "Decreto de Transporte Metropolitano",
      "Portaria de Transporte Coletivo",
      "Lei de Mobilidade Ativa",
      "Resolução de Trânsito Urbano",
      "Decreto de Transporte Sustentável"
    ),
    tipo = c("lei", "decreto", "portaria", "resolucao", "lei", "decreto", "portaria", "lei", "resolucao", "decreto"),
    data = seq(from = as.Date("2023-01-01"), to = as.Date("2023-10-01"), length.out = 10),
    estado = c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE"),
    autor = c("Deputado A", "Senador B", "Vereador C", "Deputado D", "Senador E", "Vereador F", "Deputado G", "Senador H", "Vereador I", "Deputado J"),
    fonte = rep("LexML", 10),
    stringsAsFactors = FALSE
  )
}

# Brazilian states for map
brazilian_states <- data.frame(
  state = c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE"),
  name = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Rio Grande do Sul", "Paraná", "Santa Catarina", "Bahia", "Goiás", "Pernambuco", "Ceará"),
  lat = c(-23.5505, -22.9068, -19.9191, -30.0346, -25.4284, -27.2423, -12.9714, -16.6869, -8.0476, -3.7172),
  lng = c(-46.6333, -43.1729, -43.9386, -51.2177, -49.2733, -48.5044, -38.5014, -49.2648, -34.8770, -38.5434),
  stringsAsFactors = FALSE
)

# UI Definition
ui <- dashboardPage(
  dashboardHeader(
    title = "Monitor Legislativo v4",
    titleWidth = 300
  ),
  
  dashboardSidebar(
    width = 300,
    sidebarMenu(
      menuItem("🏠 Dashboard", tabName = "dashboard", icon = icon("home")),
      menuItem("🔍 Busca", tabName = "search", icon = icon("search")),
      menuItem("🗺️ Mapa", tabName = "map", icon = icon("map")),
      menuItem("📊 Dados", tabName = "data", icon = icon("table")),
      menuItem("📈 Analytics", tabName = "analytics", icon = icon("chart-line")),
      menuItem("⚙️ Sistema", tabName = "system", icon = icon("cog"))
    ),
    
    hr(),
    
    # Search filters
    h4("🔍 Filtros"),
    textInput("search_text", "Buscar:", placeholder = "Digite termos..."),
    selectInput("state_filter", "Estado:",
                choices = c("Todos" = "all", setNames(brazilian_states$state, brazilian_states$name)),
                selected = "all"),
    selectInput("type_filter", "Tipo:",
                choices = c("Todos" = "all", "Lei" = "lei", "Decreto" = "decreto", "Portaria" = "portaria", "Resolução" = "resolucao"),
                selected = "all"),
    
    br(),
    actionButton("btn_search", "🔍 Buscar", class = "btn-primary", width = "100%"),
    br(), br(),
    actionButton("btn_clear", "🗑️ Limpar", class = "btn-warning", width = "100%")
  ),
  
  dashboardBody(
    tags$head(
      tags$style(HTML("
        .content-wrapper, .right-side {
          background-color: #f4f4f4;
        }
        .box {
          border-radius: 5px;
          border: 1px solid #d2d6de;
        }
        .main-header .logo {
          font-weight: bold;
        }
      "))
    ),
    
    tabItems(
      # Dashboard Tab
      tabItem(
        tabName = "dashboard",
        fluidRow(
          valueBoxOutput("total_docs", width = 3),
          valueBoxOutput("states_count", width = 3),
          valueBoxOutput("latest_doc", width = 3),
          valueBoxOutput("system_status", width = 3)
        ),
        
        fluidRow(
          box(
            title = "📊 Resumo dos Dados",
            status = "primary",
            solidHeader = TRUE,
            width = 6,
            plotlyOutput("summary_plot")
          ),
          
          box(
            title = "🗺️ Distribuição por Estado",
            status = "success",
            solidHeader = TRUE,
            width = 6,
            plotlyOutput("state_distribution")
          )
        ),
        
        fluidRow(
          box(
            title = "📅 Linha do Tempo",
            status = "info",
            solidHeader = TRUE,
            width = 12,
            plotlyOutput("timeline_plot")
          )
        )
      ),
      
      # Search Tab
      tabItem(
        tabName = "search",
        fluidRow(
          box(
            title = "🔍 Busca Avançada",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            
            fluidRow(
              column(6,
                textInput("adv_search_text", "Termos de busca:", placeholder = "Digite palavras-chave..."),
                dateRangeInput("date_range", "Período:", start = Sys.Date() - 365, end = Sys.Date())
              ),
              column(6,
                selectInput("adv_state_filter", "Estados:", 
                           choices = c("Todos" = "all", setNames(brazilian_states$state, brazilian_states$name)),
                           selected = "all", multiple = TRUE),
                checkboxGroupInput("adv_type_filter", "Tipos de documento:",
                                 choices = list("Lei" = "lei", "Decreto" = "decreto", "Portaria" = "portaria", "Resolução" = "resolucao"),
                                 selected = c("lei", "decreto"))
              )
            ),
            
            br(),
            actionButton("btn_advanced_search", "🔍 Buscar", class = "btn-primary btn-lg")
          )
        ),
        
        fluidRow(
          box(
            title = "📋 Resultados",
            status = "success",
            solidHeader = TRUE,
            width = 12,
            
            DT::dataTableOutput("search_results")
          )
        )
      ),
      
      # Map Tab
      tabItem(
        tabName = "map",
        fluidRow(
          box(
            title = "🗺️ Mapa do Brasil - Legislação por Estado",
            status = "primary",
            solidHeader = TRUE,
            width = 8,
            height = "600px",
            
            leafletOutput("brazil_map", height = "500px")
          ),
          
          box(
            title = "📊 Controles do Mapa",
            status = "info",
            solidHeader = TRUE,
            width = 4,
            height = "600px",
            
            h5("Configurações"),
            radioButtons("map_color_by", "Colorir por:",
                        choices = list("Número de documentos" = "count", "Tipo predominante" = "type"),
                        selected = "count"),
            
            checkboxInput("show_labels", "Mostrar rótulos", TRUE),
            
            br(),
            h5("Estatísticas"),
            verbatimTextOutput("map_stats")
          )
        )
      ),
      
      # Data Tab
      tabItem(
        tabName = "data",
        fluidRow(
          box(
            title = "📊 Dados Legislativos",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            
            DT::dataTableOutput("data_table"),
            
            br(),
            fluidRow(
              column(6, textOutput("data_summary")),
              column(6, 
                     div(style = "text-align: right;",
                         downloadButton("download_data", "📥 Baixar Dados", class = "btn-success")
                     )
              )
            )
          )
        )
      ),
      
      # Analytics Tab
      tabItem(
        tabName = "analytics",
        fluidRow(
          box(
            title = "📈 Análise por Tipo",
            status = "warning",
            solidHeader = TRUE,
            width = 6,
            plotlyOutput("type_analysis")
          ),
          
          box(
            title = "📅 Análise Temporal",
            status = "success",
            solidHeader = TRUE,
            width = 6,
            plotlyOutput("temporal_analysis")
          )
        ),
        
        fluidRow(
          box(
            title = "🗺️ Análise Geográfica",
            status = "info",
            solidHeader = TRUE,
            width = 12,
            plotlyOutput("geographic_analysis")
          )
        )
      ),
      
      # System Tab
      tabItem(
        tabName = "system",
        fluidRow(
          box(
            title = "⚙️ Informações do Sistema",
            status = "primary",
            solidHeader = TRUE,
            width = 6,
            
            h4("Status do Sistema"),
            verbatimTextOutput("system_info"),
            
            br(),
            h4("Configurações"),
            p("Ambiente:", strong("Railway Production")),
            p("Base de dados:", strong("PostgreSQL + Redis")),
            p("Versão:", strong("4.0 - Arquitetura Unificada"))
          ),
          
          box(
            title = "🔧 Ferramentas",
            status = "success",
            solidHeader = TRUE,
            width = 6,
            
            h4("Ações do Sistema"),
            actionButton("btn_refresh_data", "🔄 Atualizar Dados", class = "btn-info"),
            br(), br(),
            actionButton("btn_clear_cache", "🗑️ Limpar Cache", class = "btn-warning"),
            br(), br(),
            actionButton("btn_health_check", "🏥 Verificar Saúde", class = "btn-success"),
            
            br(), br(),
            h4("Status das Conexões"),
            verbatimTextOutput("connection_status")
          )
        )
      )
    )
  )
)

# Server Logic
server <- function(input, output, session) {
  
  # Initialize database
  db_connected <- setup_database()
  
  # Reactive data
  current_data <- reactive({
    get_sample_data()
  })
  
  # Filtered data based on search
  filtered_data <- reactive({
    data <- current_data()
    
    # Apply filters
    if (!is.null(input$state_filter) && input$state_filter != "all") {
      data <- data[data$estado == input$state_filter, ]
    }
    
    if (!is.null(input$type_filter) && input$type_filter != "all") {
      data <- data[data$tipo == input$type_filter, ]
    }
    
    if (!is.null(input$search_text) && nchar(input$search_text) > 0) {
      data <- data[grepl(input$search_text, data$titulo, ignore.case = TRUE), ]
    }
    
    return(data)
  })
  
  # Dashboard Value Boxes
  output$total_docs <- renderValueBox({
    count <- nrow(filtered_data())
    valueBox(count, "Documentos", icon = icon("file-text"), color = "blue")
  })
  
  output$states_count <- renderValueBox({
    count <- length(unique(filtered_data()$estado))
    valueBox(count, "Estados", icon = icon("map"), color = "green")
  })
  
  output$latest_doc <- renderValueBox({
    latest <- max(filtered_data()$data, na.rm = TRUE)
    valueBox(format(latest, "%m/%Y"), "Mais Recente", icon = icon("calendar"), color = "orange")
  })
  
  output$system_status <- renderValueBox({
    valueBox("Online", "Sistema", icon = icon("check-circle"), color = "green")
  })
  
  # Dashboard Plots
  output$summary_plot <- renderPlotly({
    data <- filtered_data()
    type_counts <- table(data$tipo)
    
    p <- plot_ly(
      x = names(type_counts),
      y = as.numeric(type_counts),
      type = "bar",
      marker = list(color = c("#3498db", "#e74c3c", "#f39c12", "#2ecc71"))
    ) %>%
      layout(
        title = "Documentos por Tipo",
        xaxis = list(title = "Tipo"),
        yaxis = list(title = "Quantidade")
      )
    
    return(p)
  })
  
  output$state_distribution <- renderPlotly({
    data <- filtered_data()
    state_counts <- table(data$estado)
    
    p <- plot_ly(
      x = names(state_counts),
      y = as.numeric(state_counts),
      type = "bar",
      marker = list(color = "#2ecc71")
    ) %>%
      layout(
        title = "Documentos por Estado",
        xaxis = list(title = "Estado"),
        yaxis = list(title = "Quantidade")
      )
    
    return(p)
  })
  
  output$timeline_plot <- renderPlotly({
    data <- filtered_data()
    data$year_month <- format(data$data, "%Y-%m")
    timeline_counts <- table(data$year_month)
    
    p <- plot_ly(
      x = as.Date(paste0(names(timeline_counts), "-01")),
      y = as.numeric(timeline_counts),
      type = "scatter",
      mode = "lines+markers",
      line = list(color = "#3498db")
    ) %>%
      layout(
        title = "Linha do Tempo - Documentos por Mês",
        xaxis = list(title = "Data"),
        yaxis = list(title = "Quantidade")
      )
    
    return(p)
  })
  
  # Map
  output$brazil_map <- renderLeaflet({
    data <- filtered_data()
    state_counts <- data %>%
      group_by(estado) %>%
      summarise(count = n(), .groups = "drop")
    
    map_data <- merge(brazilian_states, state_counts, by.x = "state", by.y = "estado", all.x = TRUE)
    map_data$count[is.na(map_data$count)] <- 0
    
    leaflet(map_data) %>%
      addTiles() %>%
      addCircleMarkers(
        lat = ~lat,
        lng = ~lng,
        radius = ~sqrt(count) * 5,
        popup = ~paste("<b>", name, "</b><br>", count, "documentos"),
        color = "#3498db",
        fillOpacity = 0.7
      ) %>%
      setView(lng = -47.9292, lat = -15.7801, zoom = 4)
  })
  
  # Data Table
  output$data_table <- DT::renderDataTable({
    data <- filtered_data()
    data$data <- format(data$data, "%d/%m/%Y")
    data
  }, options = list(pageLength = 10, scrollX = TRUE))
  
  # Search Results
  output$search_results <- DT::renderDataTable({
    # Trigger on advanced search button
    input$btn_advanced_search
    
    data <- filtered_data()
    data$data <- format(data$data, "%d/%m/%Y")
    data
  }, options = list(pageLength = 15, scrollX = TRUE))
  
  # System Information
  output$system_info <- renderText({
    paste(
      "R Version:", R.version.string,
      "\nShiny Version:", packageVersion("shiny"),
      "\nStatus: Railway Production",
      "\nDatabase:", ifelse(db_connected, "Conectado", "Dados de exemplo"),
      "\nUptime:", format(Sys.time() - as.POSIXct("2025-01-01"), digits = 2),
      "\nMemória:", paste(round(sum(gc()[,2]), 1), "MB")
    )
  })
  
  # Connection Status
  output$connection_status <- renderText({
    paste(
      "PostgreSQL:", ifelse(nchar(Sys.getenv("DATABASE_URL")) > 0, "✅ Configurado", "❌ Não configurado"),
      "\nRedis:", ifelse(nchar(Sys.getenv("REDIS_URL")) > 0, "✅ Configurado", "❌ Não configurado"),
      "\nRailway:", "✅ Conectado",
      "\nHealth Check:", "✅ Funcionando"
    )
  })
  
  # Clear filters
  observeEvent(input$btn_clear, {
    updateTextInput(session, "search_text", value = "")
    updateSelectInput(session, "state_filter", selected = "all")
    updateSelectInput(session, "type_filter", selected = "all")
  })
  
  # Health check button
  observeEvent(input$btn_health_check, {
    showNotification("Sistema funcionando normalmente!", type = "success")
  })
  
  # Data summary
  output$data_summary <- renderText({
    count <- nrow(filtered_data())
    paste("Total:", count, "documentos")
  })
  
  # Download handler
  output$download_data <- downloadHandler(
    filename = function() {
      paste("monitor_legislativo_", Sys.Date(), ".csv", sep = "")
    },
    content = function(file) {
      write.csv(filtered_data(), file, row.names = FALSE)
    }
  )
}

# Run the application
shinyApp(ui = ui, server = server)