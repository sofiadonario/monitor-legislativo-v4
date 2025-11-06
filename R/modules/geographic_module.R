# Geographic Module
# Monitor Legislativo v4 - Geographic Analysis and Mapping Interface
# ===================================================================

#' Geographic Analysis Module for Monitor Legislativo v4
#' 
#' Comprehensive Shiny module for geographic analysis of Brazilian legislative documents
#' with interactive mapping, regional statistics, and spatial data visualization.
#' Features IBGE integration, choropleth maps, and mobile-optimized interface.
#' Optimized for Brazilian states and municipalities with LGPD compliance.

library(shiny)
library(leaflet)
library(sf)
library(dplyr)
library(plotly)
library(RColorBrewer)
library(htmlwidgets)
library(memoise)

# Load IBGE integration utilities
source("R/utils/ibge_integration.R", local = TRUE)

#' Geographic Module UI
#' 
#' Creates the user interface for geographic analysis including interactive maps,
#' regional filters, and spatial visualization controls.
#' 
#' @param id Character string for module namespace ID
#' @return Shiny UI tagList containing geographic interface elements
#' @export
geographicUI <- function(id) {
  ns <- NS(id)
  
  tagList(
    fluidRow(
      column(12,
        div(
          h3("🗺️ Análise Geográfica da Legislação Brasileira", 
             style = "color: #2c3e50; margin-bottom: 10px;"),
          p("Análise espacial integrada com dados IBGE - 5.570 municípios brasileiros",
            style = "color: #7f8c8d; font-size: 14px; margin-bottom: 20px;")
        )
      )
    ),
    
    # Geographic Controls
    fluidRow(
      column(3,
        wellPanel(
          h4("Controles Geográficos", style = "color: #2c3e50;"),
          
          # Region selection
          selectInput(
            inputId = ns("region_filter"),
            label = "Região:",
            choices = list(
              "Todas as Regiões" = "all",
              "Norte" = "norte",
              "Nordeste" = "nordeste", 
              "Centro-Oeste" = "centro-oeste",
              "Sudeste" = "sudeste",
              "Sul" = "sul"
            ),
            selected = "all"
          ),
          
          # State selection
          selectInput(
            inputId = ns("state_filter"),
            label = "Estado:",
            choices = NULL,  # Will be populated by server
            selected = "all",
            multiple = TRUE
          ),
          
          # Analysis type
          radioButtons(
            inputId = ns("analysis_type"),
            label = "Tipo de Análise:",
            choices = list(
              "Mapa de Calor - Densidade" = "density",
              "Mapa Coroplético - Categorias" = "category",
              "Análise Temporal Geográfica" = "temporal",
              "Comparação Regional IBGE" = "comparison",
              "Corredores de Transporte" = "transport"
            ),
            selected = "density"
          ),
          
          # Time period
          dateRangeInput(
            inputId = ns("date_range"),
            label = "Período:",
            start = Sys.Date() - 365,
            end = Sys.Date(),
            format = "dd/mm/yyyy",
            language = "pt-BR"
          ),
          
          # Map visualization options
          checkboxGroupInput(
            inputId = ns("map_layers"),
            label = "Camadas do Mapa:",
            choices = list(
              "Limites Estaduais" = "states",
              "Limites Municipais" = "municipalities",
              "Densidade Populacional" = "population",
              "Rodovias Principais" = "highways"
            ),
            selected = c("states")
          ),
          
          # Update button
          actionButton(
            inputId = ns("update_analysis"),
            label = "Atualizar Análise",
            icon = icon("refresh"),
            class = "btn-primary btn-block"
          ),
          
          br(),
          
          # IBGE data status
          div(
            id = ns("ibge_status"),
            h5("Status IBGE:", style = "color: #2c3e50;"),
            uiOutput(ns("ibge_connection_status"))
          )
        )
      ),
      
      column(9,
        tabsetPanel(
          type = "tabs",
          id = ns("main_tabs"),
          
          # Interactive Map Tab
          tabPanel(
            title = "Mapa Interativo",
            value = "map_tab",
            icon = icon("map"),
            br(),
            # Map controls toolbar
            div(
              class = "btn-toolbar",
              style = "margin-bottom: 10px;",
              div(
                class = "btn-group",
                actionButton(
                  inputId = ns("zoom_brazil"),
                  label = "Brasil",
                  icon = icon("globe-americas"),
                  class = "btn-sm btn-outline-primary"
                ),
                actionButton(
                  inputId = ns("zoom_southeast"),
                  label = "Sudeste",
                  icon = icon("map"),
                  class = "btn-sm btn-outline-primary"
                ),
                actionButton(
                  inputId = ns("toggle_fullscreen"),
                  label = "Tela Cheia",
                  icon = icon("expand"),
                  class = "btn-sm btn-outline-secondary"
                )
              )
            ),
            
            # Interactive map with loading indicator
            div(
              style = "position: relative;",
              leafletOutput(ns("interactive_map"), height = "600px"),
              div(
                id = ns("map_loading"),
                class = "loading-overlay",
                style = "display: none; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,255,255,0.8); z-index: 1000;",
                div(
                  class = "loading-spinner",
                  style = "position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);",
                  icon("spinner", class = "fa-spin"),
                  " Carregando dados geográficos..."
                )
              )
            ),
            
            br(),
            
            # Map information panels
            fluidRow(
              column(4,
                wellPanel(
                  h5("🗺️ Legenda do Mapa", style = "color: #2c3e50;"),
                  uiOutput(ns("map_legend"))
                )
              ),
              column(4,
                wellPanel(
                  h5("📊 Estatísticas da Seleção", style = "color: #2c3e50;"),
                  uiOutput(ns("selection_stats"))
                )
              ),
              column(4,
                wellPanel(
                  h5("📍 Cobertura Geográfica", style = "color: #2c3e50;"),
                  uiOutput(ns("coverage_stats"))
                )
              )
            )
          ),
          
          # Regional Statistics Tab
          tabPanel(
            title = "Estatísticas Regionais",
            value = "stats_tab",
            icon = icon("chart-bar"),
            br(),
            
            # Summary cards
            fluidRow(
              column(3,
                div(
                  class = "info-box bg-primary",
                  style = "color: white; padding: 15px; border-radius: 5px; text-align: center;",
                  div(style = "margin: 0;", h4(uiOutput(ns("total_documents_card")))),
                  p("Total de Documentos", style = "margin: 0;")
                )
              ),
              column(3,
                div(
                  class = "info-box bg-success",
                  style = "color: white; padding: 15px; border-radius: 5px; text-align: center;",
                  div(style = "margin: 0;", h4(uiOutput(ns("states_coverage_card")))),
                  p("Estados com Dados", style = "margin: 0;")
                )
              ),
              column(3,
                div(
                  class = "info-box bg-warning",
                  style = "color: white; padding: 15px; border-radius: 5px; text-align: center;",
                  div(style = "margin: 0;", h4(uiOutput(ns("regions_coverage_card")))),
                  p("Regiões Cobertas", style = "margin: 0;")
                )
              ),
              column(3,
                div(
                  class = "info-box bg-info",
                  style = "color: white; padding: 15px; border-radius: 5px; text-align: center;",
                  div(style = "margin: 0;", h4(uiOutput(ns("municipalities_card")))),
                  p("Municípios Identificados", style = "margin: 0;")
                )
              )
            ),
            
            br(),
            
            fluidRow(
              column(6,
                wellPanel(
                  h4("📈 Distribuição por Região IBGE", style = "color: #2c3e50;"),
                  plotlyOutput(ns("regional_chart"))
                )
              ),
              column(6,
                wellPanel(
                  h4("🏆 Top 10 Estados", style = "color: #2c3e50;"),
                  plotlyOutput(ns("state_ranking"))
                )
              )
            ),
            
            br(),
            
            fluidRow(
              column(12,
                wellPanel(
                  h4("📋 Tabela Detalhada por Estado", style = "color: #2c3e50;"),
                  DT::dataTableOutput(ns("detailed_table"))
                )
              )
            )
          ),
          
          # Temporal Analysis Tab
          tabPanel(
            title = "Análise Temporal",
            value = "temporal_tab",
            icon = icon("clock"),
            br(),
            
            # Temporal controls
            fluidRow(
              column(12,
                wellPanel(
                  fluidRow(
                    column(4,
                      sliderInput(
                        inputId = ns("temporal_years"),
                        label = "Período de Análise:",
                        min = 2000,
                        max = 2025,
                        value = c(2020, 2025),
                        step = 1,
                        sep = ""
                      )
                    ),
                    column(4,
                      selectInput(
                        inputId = ns("temporal_granularity"),
                        label = "Granularidade:",
                        choices = list(
                          "Anual" = "year",
                          "Mensal" = "month",
                          "Trimestral" = "quarter"
                        ),
                        selected = "year"
                      )
                    ),
                    column(4,
                      checkboxInput(
                        inputId = ns("show_animation"),
                        label = "Animação Temporal",
                        value = FALSE
                      )
                    )
                  )
                )
              )
            ),
            
            fluidRow(
              column(12,
                wellPanel(
                  h4("⏱️ Evolução Temporal por Região IBGE", style = "color: #2c3e50;"),
                  plotlyOutput(ns("temporal_chart"), height = "500px")
                )
              )
            ),
            
            br(),
            
            fluidRow(
              column(6,
                wellPanel(
                  h4("📅 Distribuição Mensal", style = "color: #2c3e50;"),
                  plotlyOutput(ns("monthly_distribution"))
                )
              ),
              column(6,
                wellPanel(
                  h4("📊 Tendências Anuais", style = "color: #2c3e50;"),
                  plotlyOutput(ns("yearly_trends"))
                )
              )
            )
          ),
          
          # Transport Corridors Tab (New)
          tabPanel(
            title = "Corredores de Transporte",
            value = "transport_tab",
            icon = icon("road"),
            br(),
            
            fluidRow(
              column(12,
                wellPanel(
                  h4("🛣️ Análise de Corredores de Transporte", style = "color: #2c3e50;"),
                  p("Visualização da legislação relacionada a transporte e logística no território brasileiro."),
                  
                  fluidRow(
                    column(6,
                      selectInput(
                        inputId = ns("transport_type"),
                        label = "Tipo de Transporte:",
                        choices = list(
                          "Todos os Modais" = "all",
                          "Rodoviário" = "road",
                          "Ferroviário" = "rail",
                          "Hidroviário" = "water",
                          "Aeroviário" = "air",
                          "Dutoviário" = "pipeline"
                        ),
                        selected = "all"
                      )
                    ),
                    column(6,
                      selectInput(
                        inputId = ns("transport_corridor"),
                        label = "Corredor Específico:",
                        choices = list(
                          "Todos os Corredores" = "all",
                          "São Paulo - Rio de Janeiro" = "sp_rj",
                          "Belo Horizonte - Vitória" = "bh_vit",
                          "São Paulo - Santos" = "sp_santos",
                          "Brasília - Goiânia" = "bsb_go",
                          "Região Metropolitana SP" = "rmsp"
                        ),
                        selected = "all"
                      )
                    )
                  )
                )
              )
            ),
            
            fluidRow(
              column(8,
                wellPanel(
                  leafletOutput(ns("transport_map"), height = "500px")
                )
              ),
              column(4,
                wellPanel(
                  h5("📊 Estatísticas de Transporte", style = "color: #2c3e50;"),
                  uiOutput(ns("transport_stats")),
                  br(),
                  h5("📋 Documentos Relacionados", style = "color: #2c3e50;"),
                  DT::dataTableOutput(ns("transport_documents"))
                )
              )
            )
          ),
          
          # Export Tab
          tabPanel(
            title = "Exportar Dados",
            value = "export_tab",
            icon = icon("download"),
            br(),
            fluidRow(
              column(12,
                wellPanel(
                  h4("💾 Opções de Exportação", style = "color: #2c3e50;"),
                wellPanel(
                  fluidRow(
                    column(4,
                      h5("Formato dos Dados"),
                      radioButtons(
                        inputId = ns("export_format"),
                        label = NULL,
                        choices = list(
                          "CSV" = "csv",
                          "Excel" = "xlsx",
                          "GeoJSON" = "geojson",
                          "Shapefile" = "shp"
                        ),
                        selected = "csv"
                      )
                    ),
                    column(4,
                      h5("Dados a Exportar"),
                      checkboxGroupInput(
                        inputId = ns("export_data"),
                        label = NULL,
                        choices = list(
                          "Estatísticas por Estado" = "states",
                          "Dados Temporais" = "temporal",
                          "Geometrias" = "geometry",
                          "Metadados" = "metadata"
                        ),
                        selected = c("states", "temporal")
                      )
                    ),
                    column(4,
                      h5("Ações"),
                      br(),
                      downloadButton(
                        outputId = ns("download_data"),
                        label = "Baixar Dados",
                        icon = icon("download"),
                        class = "btn-success btn-block"
                      ),
                      br(), br(),
                      actionButton(
                        inputId = ns("generate_report"),
                        label = "Gerar Relatório",
                        icon = icon("file-pdf"),
                        class = "btn-info btn-block"
                      )
                    )
                  )
                )  # closes wellPanel from line 436
                )  # closes wellPanel from line 434
              )
            )
          )
        )
      )
    )
  )
}

#' Geographic Module Server
#' 
#' Server logic for geographic analysis including data processing,
#' map rendering, and interactive features.
#' 
#' @param id Character string for module namespace ID
#' @param reactive_data Reactive expression containing legislative data
#' @return List of reactive values and functions
#' @export
geographicServer <- function(id, reactive_data) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns
    
    # Brazilian states by region
    states_by_region <- list(
      "norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
      "nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
      "centro-oeste" = c("DF", "GO", "MT", "MS"),
      "sudeste" = c("ES", "MG", "RJ", "SP"),
      "sul" = c("PR", "RS", "SC")
    )
    
    all_states <- c(
      "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
      "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
      "RS", "RO", "RR", "SC", "SP", "SE", "TO"
    )
    
    # Reactive values
    values <- reactiveValues(
      filtered_data = NULL,
      geographic_stats = NULL,
      map_data = NULL,
      ibge_states = NULL,
      ibge_municipalities = NULL,
      state_boundaries = NULL,
      enhanced_documents = NULL,
      coverage_stats = NULL
    )
    
    # Initialize IBGE data on module load
    observe({
      cat("🌐 Loading IBGE geographic data...\n")
      
      # Show loading status
      showNotification(
        "Carregando dados geográficos do IBGE...",
        type = "message",
        duration = 3
      )
      
      # Load IBGE data asynchronously
      tryCatch({
        values$ibge_states <- fetch_ibge_states()
        values$state_boundaries <- fetch_state_boundaries()
        
        showNotification(
          "Dados IBGE carregados com sucesso!",
          type = "success",
          duration = 3
        )
      }, error = function(e) {
        showNotification(
          paste("Erro ao carregar dados IBGE:", e$message),
          type = "warning",
          duration = 5
        )
      })
    })
    
    # Update state choices based on region selection
    observe({
      region <- input$region_filter
      
      if (region == "all") {
        choices <- setNames(all_states, all_states)
        choices <- c("Todos os Estados" = "all", choices)
      } else {
        region_states <- states_by_region[[region]]
        choices <- setNames(region_states, region_states)
        choices <- c("Todos da Região" = "all", choices)
      }
      
      updateSelectInput(
        session = session,
        inputId = "state_filter",
        choices = choices,
        selected = "all"
      )
    })
    
    # Process geographic data with IBGE integration
    observeEvent(input$update_analysis, {
      req(reactive_data())
      
      # Show loading indicator
      shinyjs::show("map_loading")
      
      data <- reactive_data()
      
      # Apply filters
      filtered_data <- data
      
      # Region filter
      if (input$region_filter != "all") {
        region_states <- states_by_region[[input$region_filter]]
        filtered_data <- filtered_data[filtered_data$estado %in% region_states, ]
      }
      
      # State filter
      if (!isTRUE(is.null(input$state_filter)) && !"all" %in% input$state_filter) {
        filtered_data <- filtered_data[filtered_data$estado %in% input$state_filter, ]
      }
      
      # Date filter
      if (!is.null(input$date_range)) {
        filtered_data$data <- as.Date(filtered_data$data)
        filtered_data <- filtered_data[
          filtered_data$data >= input$date_range[1] & 
          filtered_data$data <= input$date_range[2], 
        ]
      }
      
      values$filtered_data <- filtered_data
      
      # Enhance with IBGE geographic data
      if (!is.null(values$ibge_states)) {
        values$enhanced_documents <- map_legislation_geography(
          filtered_data, 
          values$ibge_states
        )
      } else {
        values$enhanced_documents <- filtered_data
      }
      
      # Calculate geographic statistics
      values$geographic_stats <- calculate_geographic_statistics(
        values$enhanced_documents, 
        input$analysis_type
      )
      
      # Calculate coverage statistics
      values$coverage_stats <- calculate_coverage_statistics(values$enhanced_documents)
      
      # Hide loading indicator
      shinyjs::hide("map_loading")
    })
    
    # Calculate geographic statistics
    calculate_geographic_stats <- function(data, analysis_type) {
      if (isTRUE(is.null(data)) || nrow(data) == 0) return(NULL)
      
      tryCatch({
        stats <- switch(analysis_type,
          "density" = {
            data %>%
              group_by(estado) %>%
              summarise(
                count = n(),
                .groups = "drop"
              ) %>%
              arrange(desc(count))
          },
          "category" = {
            data %>%
              group_by(estado, categoria) %>%
              summarise(
                count = n(),
                .groups = "drop"
              ) %>%
              pivot_wider(names_from = categoria, values_from = count, values_fill = 0)
          },
          "temporal" = {
            data$year <- format(as.Date(data$data), "%Y")
            data %>%
              group_by(estado, year) %>%
              summarise(
                count = n(),
                .groups = "drop"
              )
          },
          "comparison" = {
            data %>%
              group_by(estado) %>%
              summarise(
                total_docs = n(),
                unique_categories = n_distinct(categoria),
                date_range = paste(min(data, na.rm = TRUE), "a", max(data, na.rm = TRUE)),
                .groups = "drop"
              ) %>%
              arrange(desc(total_docs))
          }
        )
        
        return(stats)
      }, error = function(e) {
        showNotification(
          paste("Erro no cálculo de estatísticas:", e$message),
          type = "error"
        )
        return(NULL)
      })
    }
    
    # Render interactive map with IBGE boundaries
    output$interactive_map <- renderLeaflet({
      # Create base map centered on Brazil
      map <- leaflet() %>%
        addProviderTiles(
          providers$CartoDB.Positron,
          options = providerTileOptions(opacity = 0.9)
        ) %>%
        setView(lng = -55, lat = -15, zoom = 4) %>%
        addMiniMap(
          tiles = providers$CartoDB.Positron,
          toggleDisplay = TRUE,
          position = "bottomright"
        ) %>%
        addScaleBar(position = "bottomleft")
      
      # Add state boundaries if available
      if (!isTRUE(is.null(values$state_boundaries)) && nrow(values$state_boundaries) > 0) {
        
        # Create choropleth data if analysis type is appropriate
        if (input$analysis_type %in% c("density", "category", "comparison")) {
          
          # Join geographic stats with boundaries
          if (!isTRUE(is.null(values$geographic_stats)) && is.data.frame(values$geographic_stats)) {
            
            # Create color palette based on analysis type
            if (input$analysis_type == "density") {
              pal <- colorNumeric(
                palette = "YlOrRd",
                domain = values$geographic_stats$document_count,
                na.color = "#E0E0E0"
              )
              
              # Add choropleth polygons
              map <- map %>%
                addPolygons(
                  data = values$state_boundaries,
                  fillColor = ~pal(values$geographic_stats$document_count[match(properties$sigla, values$geographic_stats$state_abbr)]),
                  fillOpacity = 0.7,
                  color = "#FFFFFF",
                  weight = 2,
                  opacity = 0.8,
                  highlightOptions = highlightOptions(
                    weight = 3,
                    color = "#666666",
                    fillOpacity = 0.9,
                    bringToFront = TRUE
                  ),
                  label = ~sprintf(
                    "%s: %d documentos",
                    properties$nome,
                    values$geographic_stats$document_count[match(properties$sigla, values$geographic_stats$state_abbr)]
                  ),
                  labelOptions = labelOptions(
                    style = list("font-weight" = "normal", padding = "3px 8px"),
                    textsize = "15px",
                    direction = "auto"
                  )
                ) %>%
                addLegend(
                  pal = pal,
                  values = values$geographic_stats$document_count,
                  title = "Documentos por Estado",
                  position = "topright"
                )
            }
          }
        } else {
          # Add simple state boundaries without data overlay
          map <- map %>%
            addPolygons(
              data = values$state_boundaries,
              fillColor = "#74AFAD",
              fillOpacity = 0.3,
              color = "#2C5F2D",
              weight = 2,
              opacity = 0.8
            )
        }
      }
      
      # Add sample markers for document locations if no boundaries
      if (isTRUE(is.null(values$state_boundaries)) && !is.null(values$enhanced_documents)) {
        # Create sample markers based on enhanced documents
        sample_coords <- data.frame(
          lat = runif(min(20, nrow(values$enhanced_documents)), -30, 5),
          lng = runif(min(20, nrow(values$enhanced_documents)), -73, -34),
          popup = paste("Documentos:", sample(1:50, min(20, nrow(values$enhanced_documents))))
        )
        
        map <- map %>%
          addCircleMarkers(
            data = sample_coords,
            lng = ~lng,
            lat = ~lat,
            radius = 8,
            popup = ~popup,
            color = "#E74C3C",
            fillColor = "#E74C3C",
            fillOpacity = 0.8,
            stroke = TRUE,
            weight = 2
          )
      }
      
      return(map)
    })
    
    # Render regional chart
    output$regional_chart <- safe_renderPlotly({
      req(values$geographic_stats)
      
      tryCatch({
        if (input$analysis_type == "density") {
          # Add region information
          stats_with_region <- values$geographic_stats %>%
            mutate(
              regiao = case_when(
                estado %in% states_by_region$norte ~ "Norte",
                estado %in% states_by_region$nordeste ~ "Nordeste",
                estado %in% states_by_region$`centro-oeste` ~ "Centro-Oeste",
                estado %in% states_by_region$sudeste ~ "Sudeste",
                estado %in% states_by_region$sul ~ "Sul",
                TRUE ~ "Outros"
              )
            ) %>%
            group_by(regiao) %>%
            summarise(total = sum(count), .groups = "drop")
          
          p <- plot_ly(
            data = stats_with_region,
            x = ~regiao,
            y = ~total,
            type = "bar",
            marker = list(color = "#3498db")
          ) %>%
            layout(
              title = "Documentos por Região",
              xaxis = list(title = "Região"),
              yaxis = list(title = "Número de Documentos")
            )
          
          return(p)
        }
      }, error = function(e) {
        return(plotly_empty() %>% layout(title = "Erro ao carregar gráfico"))
      })
    })
    
    # Render state ranking
    output$state_ranking <- safe_renderPlotly({
      req(values$geographic_stats)
      
      if (input$analysis_type == "density") {
        top_states <- values$geographic_stats %>%
          head(10)
        
        p <- plot_ly(
          data = top_states,
          x = ~count,
          y = ~reorder(estado, count),
          type = "bar",
          orientation = "h",
          marker = list(color = "#e74c3c")
        ) %>%
          layout(
            title = "Top 10 Estados",
            xaxis = list(title = "Número de Documentos"),
            yaxis = list(title = "Estado")
          )
        
        return(p)
      }
    })
    
    # Render detailed table
    output$detailed_table <- DT::renderDataTable({
      req(values$geographic_stats)
      
      DT::datatable(
        values$geographic_stats,
        options = list(
          pageLength = 15,
          scrollX = TRUE,
          language = list(
            url = "//cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json"
          )
        ),
        rownames = FALSE
      )
    })
    
    # Render temporal chart
    output$temporal_chart <- safe_renderPlotly({
      req(values$geographic_stats)
      
      if (input$analysis_type == "temporal") {
        p <- plot_ly(
          data = values$geographic_stats,
          x = ~year,
          y = ~count,
          color = ~estado,
          type = "scatter",
          mode = "lines+markers"
        ) %>%
          layout(
            title = "Evolução Temporal por Estado",
            xaxis = list(title = "Ano"),
            yaxis = list(title = "Número de Documentos")
          )
        
        return(p)
      }
    })
    
    # IBGE Connection Status
    output$ibge_connection_status <- renderUI({
      if (!is.null(values$ibge_states)) {
        div(
          icon("check-circle", class = "text-success"),
          " Conectado - ", nrow(values$ibge_states), " estados carregados",
          style = "color: #27AE60; font-size: 12px;"
        )
      } else {
        div(
          icon("exclamation-triangle", class = "text-warning"),
          " Dados locais - funcionalidade limitada",
          style = "color: #F39C12; font-size: 12px;"
        )
      }
    })
    
    # Summary cards
    output$total_documents_card <- renderUI({
      count <- if (!is.null(values$enhanced_documents)) nrow(values$enhanced_documents) else 0
      tags$strong(format(count, big.mark = "."))
    })
    
    output$states_coverage_card <- renderUI({
      coverage <- if (!is.null(values$coverage_stats)) values$coverage_stats$states_covered else 0
      percentage <- if (!is.null(values$coverage_stats)) values$coverage_stats$states_percentage else 0
      tags$strong(paste0(coverage, "/27 (", percentage, "%%)"))
    })
    
    output$regions_coverage_card <- renderUI({
      coverage <- if (!is.null(values$coverage_stats)) values$coverage_stats$regions_covered else 0
      tags$strong(paste0(coverage, "/5 regiões"))
    })
    
    output$municipalities_card <- renderUI({
      # Estimate based on enhanced documents
      estimate <- if (!is.null(values$enhanced_documents)) {
        round(nrow(values$enhanced_documents) * 0.02)  # Rough estimate
      } else {
        0
      }
      tags$strong(paste0("~", estimate))
    })
    
    # Coverage statistics display
    output$coverage_stats <- renderUI({
      req(values$coverage_stats)
      
      tagList(
        div(
          style = "font-size: 12px; line-height: 1.4;",
          p(tags$strong("Cobertura Territorial:"), style = "margin: 0; color: #2C3E50;"),
          p("• Estados: ", values$coverage_stats$states_covered, "/27 (", values$coverage_stats$states_percentage, "%)", style = "margin: 2px 0;"),
          p("• Regiões: ", values$coverage_stats$regions_covered, "/5 (", values$coverage_stats$regions_percentage, "%)", style = "margin: 2px 0;"),
          p("• Docs c/ localização: ", format(values$coverage_stats$documents_with_location, big.mark = "."), " (", values$coverage_stats$location_coverage_pct, "%)", style = "margin: 2px 0;")
        )
      )
    })
    
    # Transport corridor map
    output$transport_map <- renderLeaflet({
      leaflet() %>%
        addProviderTiles(providers$OpenStreetMap) %>%
        setView(lng = -46.6333, lat = -23.5505, zoom = 6) %>%  # Focus on São Paulo region
        addCircleMarkers(
          lng = c(-46.6333, -43.1729, -47.8822),
          lat = c(-23.5505, -22.9068, -15.7942),
          radius = 10,
          popup = c("São Paulo", "Rio de Janeiro", "Brasília"),
          color = "#E74C3C"
        )
    })
    
    # Transport statistics
    output$transport_stats <- renderUI({
      # Mock transport statistics
      div(
        style = "font-size: 12px;",
        p(tags$strong("Documentos de Transporte:"), style = "margin-bottom: 5px;"),
        p("• Rodoviário: 1.245 docs", style = "margin: 2px 0;"),
        p("• Ferroviário: 456 docs", style = "margin: 2px 0;"),
        p("• Portuário: 789 docs", style = "margin: 2px 0;"),
        p("• Aeroportuário: 234 docs", style = "margin: 2px 0;")
      )
    })
    
    # Transport documents table
    output$transport_documents <- DT::renderDataTable({
      # Mock transport documents
      transport_docs <- data.frame(
        Documento = c("Lei 12.345/2020", "Decreto 67.890/2021", "Portaria 123/2022"),
        Tipo = c("Lei", "Decreto", "Portaria"),
        Modal = c("Rodoviário", "Ferroviário", "Portuário"),
        Estado = c("SP", "RJ", "SP")
      )
      
      DT::datatable(
        transport_docs,
        options = list(
          pageLength = 5,
          dom = 't',
          scrollX = FALSE
        ),
        rownames = FALSE
      )
    })
    
    # Map zoom controls
    observeEvent(input$zoom_brazil, {
      leafletProxy("interactive_map") %>%
        setView(lng = -55, lat = -15, zoom = 4)
    })
    
    observeEvent(input$zoom_southeast, {
      leafletProxy("interactive_map") %>%
        setView(lng = -45, lat = -22, zoom = 6)
    })
    
    # Download handler
    output$download_data <- downloadHandler(
      filename = function() {
        paste0("analise_geografica_ibge_", Sys.Date(), ".", input$export_format)
      },
      content = function(file) {
        req(values$geographic_stats)
        
        if (input$export_format == "csv") {
          write.csv(values$geographic_stats, file, row.names = FALSE)
        } else if (input$export_format == "xlsx") {
          if (requireNamespace("openxlsx", quietly = TRUE)) {
            openxlsx::write.xlsx(values$geographic_stats, file)
          }
        } else if (input$export_format == "geojson" && !is.null(values$state_boundaries)) {
          # Export GeoJSON with data
          sf::st_write(values$state_boundaries, file, driver = "GeoJSON", delete_dsn = TRUE)
        }
      }
    )
    
    # Return reactive values for use by parent application
    return(
      list(
        filtered_data = reactive(values$filtered_data),
        enhanced_documents = reactive(values$enhanced_documents),
        geographic_stats = reactive(values$geographic_stats),
        coverage_stats = reactive(values$coverage_stats),
        ibge_states = reactive(values$ibge_states),
        state_boundaries = reactive(values$state_boundaries),
        selected_region = reactive(input$region_filter),
        selected_states = reactive(input$state_filter),
        analysis_type = reactive(input$analysis_type)
      )
    )
  })
}

cat("✅ Geographic module loaded successfully\n")