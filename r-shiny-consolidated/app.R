# Monitor Legislativo v4 - R Architecture Consolidation
# Modern R Shiny Application with bslib, echarts4r, and leaflet
# Academic Research Platform for Brazilian Legislative Data

# Load libraries
library(shiny)
library(bslib)
library(echarts4r)
library(leaflet)
library(tmap)
library(DT)
library(dplyr)
library(config)
library(httr)
library(jsonlite)
library(sf)
library(promises)
library(future)

# Set up future for async operations
plan(multisession)

# Load configuration
config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
app_config <- config::get(config = config_env)

# Source modules
source("R/database.R")
source("R/api_client.R")
source("R/geographic.R")
source("R/visualization.R")
source("R/ui_components.R")
source("R/utils.R")

# Initialize application
cat("🚀 Starting Monitor Legislativo v4 - R Architecture\n")

# ============================================================================
# USER INTERFACE
# ============================================================================

ui <- page_navbar(
  title = app_config$app$title,
  id = "main_nav",
  theme = bs_theme(
    version = 5,
    bootswatch = "flatly",
    primary = app_config$ui$primary_color,
    secondary = app_config$ui$secondary_color,
    success = app_config$ui$success_color,
    warning = app_config$ui$warning_color,
    danger = app_config$ui$danger_color,
    info = app_config$ui$info_color,
    base_font = font_google("Inter"),
    heading_font = font_google("Inter", wght = "600")
  ),
  
  # Custom CSS for modern glassmorphism design
  tags$head(
    tags$style(HTML("
      .navbar-brand {
        font-weight: 600;
        font-size: 1.25rem;
      }
      
      .card {
        background: rgba(255, 255, 255, 0.9);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        border-radius: 12px;
      }
      
      .value-box {
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0));
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.18);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        transition: transform 0.3s ease;
      }
      
      .value-box:hover {
        transform: translateY(-2px);
      }
      
      .search-panel {
        background: rgba(248, 249, 250, 0.8);
        backdrop-filter: blur(10px);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 2rem;
      }
      
      .leaflet-container {
        border-radius: 12px;
      }
      
      .nav-tabs .nav-link.active {
        background: rgba(255, 255, 255, 0.9);
        backdrop-filter: blur(10px);
      }
    "))
  ),
  
  # Search and Dashboard Tab
  nav_panel(
    title = "🔍 Busca e Análise",
    icon = icon("search"),
    layout_columns(
      col_widths = c(4, 8),
      
      # Search Panel
      card(
        class = "search-panel",
        card_header(
          class = "d-flex justify-content-between align-items-center",
          tags$h5("🔍 Filtros de Busca", class = "mb-0"),
          action_button(
            "btn_clear_filters",
            "Limpar",
            class = "btn-outline-secondary btn-sm"
          )
        ),
        card_body(
          textInput(
            "search_query",
            "Buscar documentos:",
            placeholder = "Ex: transporte público, mobilidade urbana...",
            value = ""
          ),
          
          dateRangeInput(
            "date_range",
            "Período:",
            start = Sys.Date() - 365,
            end = Sys.Date(),
            format = "dd/mm/yyyy",
            language = "pt-BR"
          ),
          
          selectInput(
            "document_types",
            "Tipos de documento:",
            choices = list(
              "Todos" = "all",
              "Leis" = "lei",
              "Decretos" = "decreto",
              "Portarias" = "portaria",
              "Resoluções" = "resolucao"
            ),
            selected = "all",
            multiple = TRUE
          ),
          
          selectInput(
            "states_filter",
            "Estados:",
            choices = get_brazilian_states(),
            selected = NULL,
            multiple = TRUE
          ),
          
          br(),
          
          action_button(
            "btn_search",
            "🔍 Buscar",
            class = "btn-primary w-100",
            style = "border-radius: 8px; font-weight: 500;"
          )
        )
      ),
      
      # Results Panel
      card(
        card_header("📊 Resultados da Busca"),
        card_body(
          # Summary cards
          layout_columns(
            col_widths = c(3, 3, 3, 3),
            value_box(
              title = "Total de Documentos",
              value = textOutput("total_documents"),
              showcase = icon("file-text"),
              theme = value_box_theme(bg = app_config$ui$primary_color)
            ),
            value_box(
              title = "Estados",
              value = textOutput("total_states"),
              showcase = icon("map"),
              theme = value_box_theme(bg = app_config$ui$success_color)
            ),
            value_box(
              title = "Tipos",
              value = textOutput("total_types"),
              showcase = icon("tags"),
              theme = value_box_theme(bg = app_config$ui$info_color)
            ),
            value_box(
              title = "Mais Recente",
              value = textOutput("latest_date"),
              showcase = icon("calendar"),
              theme = value_box_theme(bg = app_config$ui$warning_color)
            )
          ),
          
          # Data visualization tabs
          navset_card_tab(
            id = "results_tabs",
            
            nav_panel(
              "📋 Tabela",
              div(
                style = "margin-top: 1rem;",
                DT::dataTableOutput("results_table")
              )
            ),
            
            nav_panel(
              "📊 Gráficos",
              layout_columns(
                col_widths = c(6, 6),
                card(
                  card_header("Distribuição por Tipo"),
                  card_body(echarts4rOutput("type_chart"))
                ),
                card(
                  card_header("Distribuição Temporal"),
                  card_body(echarts4rOutput("temporal_chart"))
                )
              )
            )
          )
        )
      )
    )
  ),
  
  # Geographic Analysis Tab
  nav_panel(
    title = "🗺️ Análise Geográfica",
    icon = icon("map"),
    layout_columns(
      col_widths = c(8, 4),
      
      # Map Panel
      card(
        full_screen = TRUE,
        card_header("🗺️ Mapa Legislativo do Brasil"),
        card_body(
          padding = 0,
          leafletOutput("brazil_map", height = "600px")
        )
      ),
      
      # Map Controls and Info
      layout_columns(
        col_widths = 12,
        
        card(
          card_header("🎛️ Controles do Mapa"),
          card_body(
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
            checkboxInput("show_clusters", "Agrupar documentos", TRUE),
            
            br(),
            
            action_button(
              "btn_refresh_map",
              "🔄 Atualizar Mapa",
              class = "btn-success w-100"
            )
          )
        ),
        
        card(
          card_header("📊 Estatísticas Geográficas"),
          card_body(
            htmlOutput("geographic_stats")
          )
        ),
        
        card(
          card_header("📍 Localização Selecionada"),
          card_body(
            htmlOutput("selected_location_info")
          )
        )
      )
    )
  ),
  
  # Document Analysis Tab
  nav_panel(
    title = "📄 Análise de Documentos",
    icon = icon("file-alt"),
    layout_columns(
      col_widths = c(12),
      
      card(
        card_header("🔍 Análise Detalhada de Documentos"),
        card_body(
          conditionalPanel(
            condition = "output.has_selected_document",
            
            layout_columns(
              col_widths = c(6, 6),
              
              # Document details
              card(
                card_header("📋 Detalhes do Documento"),
                card_body(
                  htmlOutput("document_details")
                )
              ),
              
              # Document analysis
              card(
                card_header("🤖 Análise AI"),
                card_body(
                  htmlOutput("document_analysis")
                )
              )
            ),
            
            # Document content viewer
            card(
              card_header("📖 Conteúdo do Documento"),
              card_body(
                htmlOutput("document_content")
              )
            )
          ),
          
          conditionalPanel(
            condition = "!output.has_selected_document",
            div(
              class = "text-center py-5",
              icon("file-alt", class = "fa-3x text-muted"),
              h4("Selecione um documento", class = "text-muted mt-3"),
              p("Clique em um documento na tabela de resultados para visualizar detalhes", class = "text-muted")
            )
          )
        )
      )
    )
  ),
  
  # Export Tab
  nav_panel(
    title = "📤 Exportar",
    icon = icon("download"),
    layout_columns(
      col_widths = c(8, 4),
      
      card(
        card_header("📤 Exportar Dados de Pesquisa"),
        card_body(
          h5("Formato de Exportação"),
          radioButtons(
            "export_format",
            NULL,
            choices = list(
              "📊 CSV - Dados tabulares" = "csv",
              "📋 Excel - Planilha completa" = "xlsx",
              "📄 PDF - Relatório acadêmico" = "pdf",
              "🌐 HTML - Relatório web" = "html",
              "📋 JSON - Dados estruturados" = "json"
            ),
            selected = "csv"
          ),
          
          h5("Opções de Exportação"),
          checkboxGroupInput(
            "export_options",
            NULL,
            choices = list(
              "Incluir metadados completos" = "metadata",
              "Incluir análise estatística" = "stats",
              "Incluir visualizações" = "charts",
              "Incluir citações acadêmicas" = "citations"
            ),
            selected = c("metadata", "stats")
          ),
          
          numericInput(
            "export_limit",
            "Máximo de registros:",
            value = 1000,
            min = 1,
            max = 5000,
            step = 100
          ),
          
          br(),
          
          action_button(
            "btn_export",
            "📦 Gerar Exportação",
            class = "btn-success btn-lg w-100"
          ),
          
          br(), br(),
          
          conditionalPanel(
            condition = "output.export_ready",
            div(
              class = "alert alert-success",
              icon("check-circle"),
              " Exportação concluída!",
              br(),
              downloadButton(
                "download_export",
                "📥 Baixar Arquivo",
                class = "btn-success btn-sm mt-2"
              )
            )
          )
        )
      ),
      
      card(
        card_header("📋 Citação Acadêmica"),
        card_body(
          h6("Como citar esta pesquisa:"),
          wellPanel(
            style = "background: rgba(248, 249, 250, 0.8); border-radius: 8px;",
            tags$small(
              em(paste0(
                "Monitor Legislativo v4. Dados legislativos brasileiros. ",
                "Consultado em ", format(Sys.Date(), "%d de %B de %Y"), ". ",
                "Plataforma acadêmica de pesquisa."
              ))
            )
          ),
          
          h6("Fontes de Dados:"),
          tags$ul(
            tags$li("Câmara dos Deputados"),
            tags$li("Senado Federal"),
            tags$li("LexML Brasil"),
            tags$li("Assembleias Legislativas"),
            tags$li("IBGE - Dados Geográficos")
          )
        )
      )
    )
  ),
  
  # Settings Tab
  nav_panel(
    title = "⚙️ Configurações",
    icon = icon("cog"),
    layout_columns(
      col_widths = c(6, 6),
      
      card(
        card_header("⚙️ Configurações da Aplicação"),
        card_body(
          h6("APIs de Dados"),
          checkboxGroupInput(
            "enabled_apis",
            NULL,
            choices = list(
              "Backend Principal" = "backend",
              "Câmara dos Deputados" = "camara",
              "Senado Federal" = "senado",
              "LexML Brasil" = "lexml"
            ),
            selected = c("backend", "lexml")
          ),
          
          h6("Performance"),
          numericInput(
            "max_results",
            "Máximo de resultados:",
            value = app_config$performance$max_results_default,
            min = 100,
            max = 5000,
            step = 100
          ),
          
          numericInput(
            "cache_duration",
            "Duração do cache (minutos):",
            value = app_config$cache$ttl_default / 60,
            min = 5,
            max = 1440
          ),
          
          br(),
          
          action_button(
            "btn_clear_cache",
            "🗑️ Limpar Cache",
            class = "btn-warning"
          )
        )
      ),
      
      card(
        card_header("📊 Status do Sistema"),
        card_body(
          h6("APIs Status"),
          verbatimTextOutput("api_status"),
          
          h6("Estatísticas de Uso"),
          verbatimTextOutput("system_stats"),
          
          h6("Informações da Aplicação"),
          p(paste("Versão:", app_config$app$version)),
          p(paste("Configuração:", config_env)),
          p(paste("Inicializado:", format(Sys.time(), "%d/%m/%Y %H:%M")))
        )
      )
    )
  )
)

# ============================================================================
# SERVER LOGIC
# ============================================================================

server <- function(input, output, session) {
  
  # Reactive values
  values <- reactiveValues(
    search_results = NULL,
    selected_document = NULL,
    export_file = NULL,
    map_data = NULL
  )
  
  # ========================================================================
  # SEARCH FUNCTIONALITY
  # ========================================================================
  
  # Search button click
  observeEvent(input$btn_search, {
    
    # Show loading
    showNotification("Buscando dados...", type = "message", duration = 2)
    
    # Perform search asynchronously
    future({
      search_legislative_data(
        query = input$search_query,
        date_from = input$date_range[1],
        date_to = input$date_range[2],
        types = if("all" %in% input$document_types) NULL else input$document_types,
        states = input$states_filter,
        limit = input$max_results
      )
    }) %...>% {
      values$search_results <- .
      showNotification("Busca concluída!", type = "success", duration = 3)
    } %...!% {
      showNotification("Erro na busca", type = "error", duration = 5)
    }
  })
  
  # Clear filters
  observeEvent(input$btn_clear_filters, {
    updateTextInput(session, "search_query", value = "")
    updateDateRangeInput(session, "date_range", 
                        start = Sys.Date() - 365, end = Sys.Date())
    updateSelectInput(session, "document_types", selected = "all")
    updateSelectInput(session, "states_filter", selected = NULL)
    
    values$search_results <- NULL
    values$selected_document <- NULL
    
    showNotification("Filtros limpos", type = "message")
  })
  
  # ========================================================================
  # OUTPUTS - SUMMARY BOXES
  # ========================================================================
  
  output$total_documents <- renderText({
    if (is.null(values$search_results)) "0" 
    else format(nrow(values$search_results), big.mark = ".")
  })
  
  output$total_states <- renderText({
    if (is.null(values$search_results)) "0"
    else length(unique(values$search_results$estado[!is.na(values$search_results$estado)]))
  })
  
  output$total_types <- renderText({
    if (is.null(values$search_results)) "0"
    else length(unique(values$search_results$tipo[!is.na(values$search_results$tipo)]))
  })
  
  output$latest_date <- renderText({
    if (is.null(values$search_results)) "N/A"
    else {
      latest <- max(as.Date(values$search_results$data), na.rm = TRUE)
      format(latest, "%d/%m/%Y")
    }
  })
  
  # ========================================================================
  # OUTPUTS - DATA TABLE
  # ========================================================================
  
  output$results_table <- DT::renderDataTable({
    
    if (is.null(values$search_results)) {
      return(data.frame(
        Mensagem = "Execute uma busca para visualizar resultados"
      ))
    }
    
    # Prepare display data
    display_data <- values$search_results %>%
      select(
        Título = titulo,
        Tipo = tipo,
        Número = numero,
        Data = data,
        Estado = estado,
        Fonte = fonte
      ) %>%
      mutate(
        Data = format(as.Date(Data), "%d/%m/%Y"),
        Título = stringr::str_trunc(Título, 80)
      ) %>%
      arrange(desc(as.Date(Data, format = "%d/%m/%Y")))
    
    display_data
    
  }, options = list(
    pageLength = app_config$performance$pagination_size,
    scrollX = TRUE,
    language = list(
      url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
    ),
    selection = 'single'
  ), selection = 'single')
  
  # Handle row selection for document details
  observeEvent(input$results_table_rows_selected, {
    if (length(input$results_table_rows_selected) > 0 && !is.null(values$search_results)) {
      selected_row <- input$results_table_rows_selected[1]
      values$selected_document <- values$search_results[selected_row, ]
    }
  })
  
  # ========================================================================
  # OUTPUTS - CHARTS
  # ========================================================================
  
  output$type_chart <- renderEcharts4r({
    
    if (is.null(values$search_results)) {
      return(e_charts() %>% e_title("Sem dados para exibir"))
    }
    
    type_data <- values$search_results %>%
      count(tipo, sort = TRUE) %>%
      slice_head(n = 10)
    
    type_data %>%
      e_charts(tipo) %>%
      e_bar(n, name = "Documentos") %>%
      e_color(app_config$ui$chart_palette) %>%
      e_title("Distribuição por Tipo") %>%
      e_tooltip(trigger = "axis") %>%
      e_legend(show = FALSE) %>%
      e_flip_coords()
  })
  
  output$temporal_chart <- renderEcharts4r({
    
    if (is.null(values$search_results)) {
      return(e_charts() %>% e_title("Sem dados para exibir"))
    }
    
    temporal_data <- values$search_results %>%
      mutate(ano = lubridate::year(as.Date(data))) %>%
      count(ano, sort = FALSE) %>%
      filter(!is.na(ano))
    
    temporal_data %>%
      e_charts(ano) %>%
      e_line(n, smooth = TRUE, name = "Documentos") %>%
      e_color(app_config$ui$primary_color) %>%
      e_title("Distribuição Temporal") %>%
      e_tooltip(trigger = "axis") %>%
      e_legend(show = FALSE)
  })
  
  # ========================================================================
  # OUTPUTS - MAP
  # ========================================================================
  
  output$brazil_map <- renderLeaflet({
    
    # Create base map
    map <- leaflet() %>%
      setView(lng = app_config$geography$default_center$lng,
              lat = app_config$geography$default_center$lat,
              zoom = app_config$geography$default_zoom) %>%
      addProviderTiles(providers[[app_config$ui$map$default_tiles]])
    
    # Add data if available
    if (!is.null(values$search_results)) {
      map <- add_legislative_data_to_map(map, values$search_results, input$map_color_by)
    }
    
    map
  })
  
  # Update map when data or settings change
  observeEvent(list(values$search_results, input$map_color_by, input$show_clusters), {
    if (!is.null(values$search_results)) {
      leafletProxy("brazil_map") %>%
        clearMarkers() %>%
        clearMarkerClusters() %>%
        add_legislative_data_to_map(values$search_results, input$map_color_by)
    }
  })
  
  # ========================================================================
  # DOCUMENT ANALYSIS
  # ========================================================================
  
  output$has_selected_document <- reactive({
    !is.null(values$selected_document)
  })
  outputOptions(output, "has_selected_document", suspendWhenHidden = FALSE)
  
  output$document_details <- renderUI({
    if (is.null(values$selected_document)) return(NULL)
    
    doc <- values$selected_document
    
    tagList(
      h5(doc$titulo),
      p(strong("Tipo: "), doc$tipo),
      p(strong("Número: "), doc$numero),
      p(strong("Data: "), format(as.Date(doc$data), "%d de %B de %Y")),
      p(strong("Estado: "), doc$estado),
      p(strong("Fonte: "), doc$fonte),
      if (!is.null(doc$autor)) p(strong("Autor: "), doc$autor),
      if (!is.null(doc$ementa)) {
        tagList(
          strong("Ementa:"),
          p(doc$ementa, style = "text-align: justify;")
        )
      }
    )
  })
  
  # ========================================================================
  # EXPORT FUNCTIONALITY
  # ========================================================================
  
  output$export_ready <- reactive({
    !is.null(values$export_file)
  })
  outputOptions(output, "export_ready", suspendWhenHidden = FALSE)
  
  observeEvent(input$btn_export, {
    if (is.null(values$search_results)) {
      showNotification("Nenhum dado para exportar", type = "error")
      return()
    }
    
    showNotification("Gerando exportação...", type = "message")
    
    future({
      export_legislative_data(
        data = values$search_results,
        format = input$export_format,
        options = input$export_options,
        limit = input$export_limit
      )
    }) %...>% {
      values$export_file <- .
      showNotification("Exportação concluída!", type = "success")
    }
  })
  
  output$download_export <- downloadHandler(
    filename = function() {
      paste0("monitor_legislativo_", Sys.Date(), ".", input$export_format)
    },
    content = function(file) {
      file.copy(values$export_file, file)
    }
  )
  
  # ========================================================================
  # SYSTEM STATUS
  # ========================================================================
  
  output$api_status <- renderText({
    status <- check_apis_status()
    paste(names(status), ":", sapply(status, function(x) x$status), collapse = "\n")
  })
  
  output$system_stats <- renderText({
    paste(
      "Memória usada:", format(object.size(values), units = "MB"),
      "\nSessão iniciada:", format(Sys.time(), "%H:%M:%S"),
      "\nResultados em cache:", ifelse(is.null(values$search_results), 0, nrow(values$search_results))
    )
  })
  
  # Clear cache
  observeEvent(input$btn_clear_cache, {
    values$search_results <- NULL
    values$selected_document <- NULL
    values$export_file <- NULL
    gc()
    showNotification("Cache limpo", type = "success")
  })
  
  # ========================================================================
  # SESSION MANAGEMENT
  # ========================================================================
  
  # Cleanup on session end
  session$onSessionEnded(function() {
    cat("🛑 Sessão encerrada\n")
  })
}

# ============================================================================
# RUN APPLICATION
# ============================================================================

# Configure application options
options(
  shiny.port = app_config$app$port,
  shiny.host = app_config$app$host,
  shiny.autoreload = config_env == "development"
)

# Run the application
shinyApp(ui = ui, server = server)