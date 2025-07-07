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
source("R/utils.R")

# Source Week 2 enhanced modules
source("R/ui_components.R")
source("R/geobr_integration.R")
source("R/data_processing.R")
source("R/performance.R")

# Source Week 3 LexML and search engine modules
source("R/lexml_integration.R")
source("R/vocabulary_processing.R")
source("R/search_engine.R")
source("R/document_pipeline.R")

# Initialize application
cat("🚀 Starting Monitor Legislativo v4 - R Architecture\n")

# Initialize geographic data and performance monitoring
geographic_data <- initialize_geographic_data(load_municipalities = FALSE)
warm_cache()  # Pre-warm cache for better performance

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
      
      # Enhanced Search Panel with new UI components
      search_interface_ui("main_search"),
      
      # Results Panel
      card(
        card_header("📊 Resultados da Busca"),
        card_body(
          # Enhanced summary cards with animations
          layout_columns(
            col_widths = c(3, 3, 3, 3),
            enhanced_value_box(
              title = "Total de Documentos",
              value = textOutput("total_documents"),
              icon = "file-text",
              color = "primary"
            ),
            enhanced_value_box(
              title = "Estados Cobertos",
              value = textOutput("total_states"),
              icon = "map",
              color = "success"
            ),
            enhanced_value_box(
              title = "Tipos de Documento",
              value = textOutput("total_types"),
              icon = "tags",
              color = "info"
            ),
            enhanced_value_box(
              title = "Mais Recente",
              value = textOutput("latest_date"),
              icon = "calendar",
              color = "warning"
            )
          ),
          
          # Data visualization tabs
          navset_card_tab(
            id = "results_tabs",
            
            nav_panel(
              "📋 Tabela",
              enhanced_data_table("results", options = list(
                pageLength = 25,
                scrollX = TRUE,
                dom = 'Bfrtip',
                buttons = list('copy', 'csv', 'excel', 'pdf')
              ))
            ),
            
            nav_panel(
              "📊 Gráficos",
              layout_columns(
                col_widths = c(6, 6),
                enhanced_chart_ui("type_chart", "Distribuição por Tipo de Documento"),
                enhanced_chart_ui("temporal_chart", "Evolução Temporal da Legislação")
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
      
      # Enhanced Map Panel
      enhanced_map_ui("brazil_map", height = "600px"),
      
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
  
  # Enhanced search with LexML integration and vocabulary processing
  observeEvent(input$`main_search-btn_search`, {
    
    # Record performance metric
    search_start_time <- Sys.time()
    
    create_toast("Iniciando busca avançada...", "info")
    
    # Use enhanced search engine with LexML and vocabulary expansion
    enhanced_search(
      query = input$`main_search-search_query`,
      filters = list(
        date_from = input$`main_search-date_range`[1],
        date_to = input$`main_search-date_range`[2],
        types = input$`main_search-document_types`,
        states = input$`main_search-states_filter`,
        limit = input$max_results %||% 1000
      ),
      sources = c("lexml", "api"),
      options = list(
        enable_vocabulary_expansion = TRUE,
        enable_result_ranking = TRUE,
        max_results_per_source = 500
      )
    ) %...>% {
      # Process results through document pipeline
      processed_results <- process_document_pipeline(., options = list(
        enable_classification = TRUE,
        enable_quality_scoring = TRUE,
        min_document_quality = 60
      ))
      
      if (!is.null(processed_results) && nrow(processed_results) > 0) {
        values$search_results <- processed_results
        
        search_time <- as.numeric(Sys.time() - search_start_time, units = "secs") * 1000
        record_metric("search_time", search_time, "performance")
        
        # Get vocabulary analysis
        vocab_analysis <- analyze_vocabulary_coverage(input$`main_search-search_query`)
        
        create_toast(
          paste("Busca LexML concluída!", nrow(processed_results), "documentos processados",
                "- Cobertura vocabular:", paste0(vocab_analysis$coverage_percentage, "%")),
          "success"
        )
      } else {
        create_toast("Nenhum documento encontrado", "warning")
        values$search_results <- create_empty_search_result()
      }
    } %...!% {
      create_toast("Erro na busca LexML. Usando dados de fallback...", "error")
      values$search_results <- create_fallback_lexml_data(input$`main_search-search_query`)
    }
  })
  
  # Clear filters with enhanced UI
  observeEvent(input$`main_search-btn_clear_filters`, {
    updateTextInput(session, "main_search-search_query", value = "")
    updateDateRangeInput(session, "main_search-date_range", 
                        start = Sys.Date() - 365, end = Sys.Date())
    updateCheckboxGroupInput(session, "main_search-document_types", selected = NULL)
    updateSelectizeInput(session, "main_search-states_filter", selected = NULL)
    
    values$search_results <- NULL
    values$selected_document <- NULL
    
    create_toast("Filtros limpos", "info")
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
  # OUTPUTS - ENHANCED DATA TABLE
  # ========================================================================
  
  output$`results-table` <- DT::renderDataTable({
    
    if (is.null(values$search_results)) {
      return(data.frame(
        Mensagem = "Execute uma busca para visualizar resultados"
      ))
    }
    
    # Prepare display data with enhanced processing
    display_data <- values$search_results %>%
      select(
        Título = titulo,
        Tipo = tipo,
        Número = numero,
        Data = data,
        Estado = estado,
        Qualidade = validation_score,
        Categoria = categoria,
        Fonte = fonte
      ) %>%
      mutate(
        Data = format(as.Date(Data), "%d/%m/%Y"),
        Título = stringr::str_trunc(Título, 80),
        Qualidade = paste0(round(Qualidade), "%")
      ) %>%
      arrange(desc(as.Date(Data, format = "%d/%m/%Y")))
    
    display_data
    
  }, options = list(
    pageLength = 25,
    scrollX = TRUE,
    scrollY = "400px",
    dom = 'Bfrtip',
    buttons = list(
      list(extend = 'copy', text = 'Copiar'),
      list(extend = 'csv', text = 'CSV'),
      list(extend = 'excel', text = 'Excel'),
      list(extend = 'pdf', text = 'PDF')
    ),
    language = list(
      url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
    ),
    selection = 'single'
  ), selection = 'single')
  
  # Row count for enhanced table
  output$`results-row_count` <- renderText({
    if (is.null(values$search_results)) "0 documentos"
    else paste(nrow(values$search_results), "documentos")
  })
  
  # Handle row selection for document details
  observeEvent(input$`results-table_rows_selected`, {
    if (length(input$`results-table_rows_selected`) > 0 && !is.null(values$search_results)) {
      selected_row <- input$`results-table_rows_selected`[1]
      values$selected_document <- values$search_results[selected_row, ]
    }
  })
  
  # ========================================================================
  # OUTPUTS - CHARTS
  # ========================================================================
  
  # Enhanced charts with new UI components
  output$`type_chart-chart` <- renderEcharts4r({
    
    if (is.null(values$search_results)) {
      return(e_charts() %>% e_title("Sem dados para exibir"))
    }
    
    type_data <- values$search_results %>%
      count(tipo, sort = TRUE) %>%
      slice_head(n = 10)
    
    type_data %>%
      e_charts(tipo) %>%
      e_bar(n, name = "Documentos") %>%
      e_color(c("#0d6efd", "#198754", "#fd7e14", "#dc3545", "#6f42c1")) %>%
      e_title("Distribuição por Tipo de Documento") %>%
      e_tooltip(trigger = "axis") %>%
      e_legend(show = FALSE) %>%
      e_flip_coords() %>%
      e_animation(duration = 1000)
  })
  
  output$`temporal_chart-chart` <- renderEcharts4r({
    
    if (is.null(values$search_results)) {
      return(e_charts() %>% e_title("Sem dados para exibir"))
    }
    
    temporal_data <- values$search_results %>%
      mutate(ano = lubridate::year(as.Date(data))) %>%
      count(ano, sort = FALSE) %>%
      filter(!is.na(ano))
    
    temporal_data %>%
      e_charts(ano) %>%
      e_line(n, smooth = TRUE, name = "Documentos", symbol_size = 6) %>%
      e_area(n, name = "Área", opacity = 0.3) %>%
      e_color("#0d6efd") %>%
      e_title("Evolução Temporal da Legislação") %>%
      e_tooltip(trigger = "axis") %>%
      e_legend(show = FALSE) %>%
      e_animation(duration = 1500)
  })
  
  # ========================================================================
  # OUTPUTS - MAP
  # ========================================================================
  
  # Enhanced map with geobr integration
  output$`brazil_map-map` <- renderLeaflet({
    
    # Create base map with geobr data
    if (geographic_data$geobr_available && !is.null(geographic_data$states)) {
      map <- create_choropleth_with_data(
        geographic_data = geographic_data$states,
        legislative_data = values$search_results %||% data.frame(),
        join_by = "state_code",
        value_column = "count"
      )
    } else {
      # Fallback to basic map
      map <- leaflet() %>%
        setView(lng = -47.8825, lat = -15.7942, zoom = 4) %>%
        addProviderTiles(providers$CartoDB.Positron)
    }
    
    map %||% leaflet() %>% 
      setView(lng = -47.8825, lat = -15.7942, zoom = 4) %>%
      addProviderTiles(providers$CartoDB.Positron)
  })
  
  # Update map when data or settings change
  observeEvent(list(values$search_results, input$`brazil_map-color_variable`), {
    if (!is.null(values$search_results) && geographic_data$geobr_available) {
      
      # Update map with new choropleth
      new_map <- create_choropleth_with_data(
        geographic_data = geographic_data$states,
        legislative_data = values$search_results,
        join_by = "state_code",
        value_column = input$`brazil_map-color_variable` %||% "count"
      )
      
      if (!is.null(new_map)) {
        output$`brazil_map-map` <- renderLeaflet(new_map)
      }
    }
  })
  
  # Geographic statistics
  output$geographic_stats <- renderUI({
    if (is.null(values$search_results)) {
      return(p("Nenhum dado para análise geográfica"))
    }
    
    stats <- calculate_geographic_stats(values$search_results, "state")
    
    tagList(
      p(strong("Cobertura Nacional:")),
      p(paste(stats$total_locations, "estados cobertos (", stats$coverage_percentage, "%)")),
      p(strong("Documentos com localização:")),
      p(paste(stats$documents_with_location, "de", nrow(values$search_results))),
      if (nchar(stats$top_locations) > 0) {
        tagList(
          p(strong("Estados com mais documentos:")),
          p(stats$top_locations)
        )
      }
    )
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
    
    # Get performance statistics
    perf_stats <- get_performance_stats()
    memory_stats <- get_memory_usage()
    
    paste(
      "Uptime:", perf_stats$uptime_hours, "horas",
      "\nMemória usada:", memory_stats$used_mb, "MB",
      "\nRequisições totais:", perf_stats$total_requests,
      "\nResultados em cache:", ifelse(is.null(values$search_results), 0, nrow(values$search_results)),
      if (!is.null(perf_stats$search_performance)) {
        paste("\nTempo médio busca:", perf_stats$search_performance$average_time_ms, "ms")
      } else ""
    )
  })
  
  # Clear cache with performance monitoring
  observeEvent(input$btn_clear_cache, {
    
    # Use performance module for cleanup
    cleanup_result <- cleanup_memory(aggressive = TRUE)
    
    values$search_results <- NULL
    values$selected_document <- NULL
    values$export_file <- NULL
    
    create_toast(
      paste("Cache limpo:", round(cleanup_result$memory_freed_mb, 1), "MB liberados"),
      "success"
    )
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