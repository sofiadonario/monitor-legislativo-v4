# DASHBOARD INTEGRATION - PHASE 1
# Brazilian Legislative Monitoring System - Polygon Processing
# ============================================================================
# 
# Integration layer for polygon processing system with existing dashboard tabs
# Seamless municipality-level analysis integration
# 
# Features:
# - Enhanced geographic tab with municipality visualization
# - Municipality-level filtering for all tabs
# - Progressive enhancement of existing state-level features
# - Backward compatibility with state-level analysis
# - Performance-optimized for Railway deployment

library(shiny)
library(shinydashboard)
library(dplyr)
library(plotly)
library(DT)
library(leaflet)

# Load polygon processing modules
tryCatch({
  source("modules/polygon_processing/polygon_core.R", local = TRUE)
  source("modules/polygon_processing/performance_optimizer.R", local = TRUE)
  source("modules/polygon_processing/spatial_database.R", local = TRUE)
  cat("✅ Polygon processing modules loaded\n")
}, error = function(e) {
  cat("⚠️ Error loading polygon modules:", e$message, "\n")
  cat("   Continuing with state-level functionality only\n")
})

# ============================================================================
# ENHANCED GEOGRAPHIC UI COMPONENTS
# ============================================================================

#' Create municipality-enabled geographic filter UI
#' @param ns Namespace function for module
#' @return Shiny UI elements for municipality filtering
municipality_filter_ui <- function(ns) {
  tagList(
    fluidRow(
      column(4,
        selectInput(ns("region_filter"), 
                   "Região:",
                   choices = c("Todas" = "all", 
                              "Norte" = "norte",
                              "Nordeste" = "nordeste", 
                              "Centro-Oeste" = "centro_oeste",
                              "Sudeste" = "sudeste",
                              "Sul" = "sul"),
                   selected = "all")
      ),
      column(4,
        conditionalPanel(
          condition = "input.region_filter != 'all'",
          ns = ns,
          selectInput(ns("state_filter"),
                     "Estado:",
                     choices = c("Todos" = "all"),
                     selected = "all")
        )
      ),
      column(4,
        conditionalPanel(
          condition = "input.state_filter != 'all'",
          ns = ns,
          selectInput(ns("municipality_filter"),
                     "Município:",
                     choices = c("Todos" = "all"),
                     selected = "all",
                     multiple = TRUE)
        )
      )
    ),
    
    # Resolution control for polygon display
    fluidRow(
      column(6,
        selectInput(ns("map_resolution"),
                   "Resolução do Mapa:",
                   choices = c("Alta (zoom)" = "high",
                              "Média (estado)" = "medium", 
                              "Baixa (país)" = "low"),
                   selected = "medium")
      ),
      column(6,
        checkboxInput(ns("enable_municipalities"),
                     "Mostrar Municípios",
                     value = FALSE)
      )
    ),
    
    # Performance indicators
    conditionalPanel(
      condition = "input.enable_municipalities == true",
      ns = ns,
      div(class = "performance-indicators",
        fluidRow(
          column(4,
            valueBoxOutput(ns("memory_usage"), width = NULL)
          ),
          column(4,
            valueBoxOutput(ns("query_time"), width = NULL)
          ),
          column(4,
            valueBoxOutput(ns("municipalities_loaded"), width = NULL)
          )
        )
      )
    )
  )
}

#' Create enhanced geographic visualization output
#' @param ns Namespace function for module
#' @return Shiny UI elements for geographic visualization
enhanced_geographic_output_ui <- function(ns) {
  tagList(
    # Tab navigation for different views
    tabsetPanel(
      id = ns("geo_tabs"),
      
      # Choropleth map tab
      tabPanel("Mapa Coroplético",
        value = "choropleth",
        fluidRow(
          column(12,
            plotlyOutput(ns("municipality_choropleth"), height = "600px")
          )
        ),
        fluidRow(
          column(12,
            div(class = "map-legend",
              p("Clique nos estados ou municípios para mais detalhes. Use os controles acima para ajustar a resolução.")
            )
          )
        )
      ),
      
      # Interactive leaflet map tab
      tabPanel("Mapa Interativo",
        value = "leaflet",
        fluidRow(
          column(12,
            leafletOutput(ns("municipality_leaflet"), height = "600px")
          )
        )
      ),
      
      # Statistical summary tab
      tabPanel("Resumo Estatístico",
        value = "stats",
        fluidRow(
          column(6,
            DT::dataTableOutput(ns("municipality_stats"))
          ),
          column(6,
            plotlyOutput(ns("municipality_distribution"), height = "400px")
          )
        )
      )
    )
  )
}

# ============================================================================
# SERVER-SIDE INTEGRATION LOGIC
# ============================================================================

#' Server logic for municipality-enhanced geographic module
#' @param input Shiny input object
#' @param output Shiny output object  
#' @param session Shiny session object
#' @param pool Database connection pool
#' @param document_data Reactive containing document data
#' @return List of reactive values and functions
enhanced_geographic_server <- function(input, output, session, pool, document_data) {
  
  # Initialize performance monitoring
  performance_monitor <- create_memory_pressure_monitor()
  query_cache <- create_polygon_cache(ttl_seconds = 1800, max_entries = 50)
  
  # Reactive values for polygon processing
  values <- reactiveValues(
    current_municipalities = NULL,
    spatial_index = NULL,
    last_query_time = 0,
    memory_usage = 0,
    municipalities_count = 0
  )
  
  # ============================================================================
  # REACTIVE DATA LOADING
  # ============================================================================
  
  # Load municipalities based on filter selection
  municipalities_data <- reactive({
    req(input$region_filter)
    
    memory_monitor <- create_memory_monitor("load_municipalities_reactive")
    on.exit(memory_monitor(), add = TRUE)
    
    # Check if municipalities are enabled
    if (!input$enable_municipalities) {
      return(NULL)
    }
    
    tryCatch({
      start_time <- Sys.time()
      
      # Determine which states/municipalities to load
      if (input$region_filter == "all") {
        state_codes <- unlist(IBGE_REGIONS, use.names = FALSE)
      } else {
        state_codes <- IBGE_REGIONS[[input$region_filter]]
      }
      
      # Filter by specific state if selected
      if (!isTRUE(is.null(input$state_filter)) && input$state_filter != "all") {
        state_codes <- input$state_filter
      }
      
      # Load municipalities with caching
      cache_key <- paste(c(sort(state_codes), input$map_resolution), collapse = "_")
      cached_data <- query_cache$get(cache_key)
      
      if (!is.null(cached_data)) {
        cat("⚡ Using cached municipality data\n")
        municipalities <- cached_data
      } else {
        municipalities <- load_ibge_municipalities(
          state_codes = state_codes,
          resolution = input$map_resolution,
          use_cache = TRUE
        )
        
        # Cache the result
        query_cache$set(cache_key, municipalities)
      }
      
      # Create spatial index for fast queries
      if (!isTRUE(is.null(municipalities)) && nrow(municipalities) > 0) {
        values$spatial_index <- create_spatial_index(municipalities)
        values$municipalities_count <- nrow(municipalities)
      }
      
      # Update performance metrics
      end_time <- Sys.time()
      values$last_query_time <- as.numeric(end_time - start_time, units = "secs") * 1000
      values$memory_usage <- query_cache$size_mb()
      
      return(municipalities)
      
    }, error = function(e) {
      cat("❌ Error loading municipalities:", e$message, "\n")
      showNotification("Erro ao carregar dados de municípios. Usando dados de estado.", 
                      type = "warning", duration = 5)
      return(NULL)
    })
  })
  
  # Enhanced document data with municipality information
  enhanced_document_data <- reactive({
    documents <- document_data()
    municipalities <- municipalities_data()
    
    if (isTRUE(is.null(documents)) || nrow(documents) == 0) {
      return(documents)
    }
    
    if (isTRUE(is.null(municipalities)) || !input$enable_municipalities) {
      # Return documents with state-level information only
      return(documents %>%
        mutate(
          administrative_level = "state",
          municipality_code = paste0(estado, "000"),
          municipality_name = paste("Estado", estado)
        ))
    }
    
    tryCatch({
      # Perform spatial join for documents with coordinates
      documents_with_coords <- documents %>%
        filter(!is.na(lat), !is.na(lng))
      
      if (nrow(documents_with_coords) > 0) {
        # Use hierarchical spatial join
        enhanced_docs <- hierarchical_spatial_join(
          documents_with_coords,
          level = "municipal",
          fallback_level = "state"
        )
        
        # Add documents without coordinates
        docs_without_coords <- documents %>%
          filter(is.na(lat) | is.na(lng)) %>%
          mutate(
            administrative_level = "state",
            municipality_code = paste0(estado, "000"),
            municipality_name = paste("Estado", estado)
          )
        
        result <- bind_rows(enhanced_docs, docs_without_coords)
      } else {
        # No coordinates available, use state-level
        result <- documents %>%
          mutate(
            administrative_level = "state",
            municipality_code = paste0(estado, "000"), 
            municipality_name = paste("Estado", estado)
          )
      }
      
      return(result)
      
    }, error = function(e) {
      cat("❌ Error enhancing document data:", e$message, "\n")
      # Fallback to original data
      return(documents %>%
        mutate(
          administrative_level = "state",
          municipality_code = NA,
          municipality_name = NA
        ))
    })
  })
  
  # ============================================================================
  # UI UPDATES
  # ============================================================================
  
  # Update state choices based on region selection
  observe({
    req(input$region_filter)
    
    if (input$region_filter == "all") {
      choices <- c("Todos" = "all")
    } else {
      region_states <- IBGE_REGIONS[[input$region_filter]]
      choices <- c("Todos" = "all", setNames(region_states, region_states))
    }
    
    updateSelectInput(session, "state_filter", choices = choices)
  })
  
  # Update municipality choices based on state selection
  observe({
    req(input$state_filter)
    
    if (input$state_filter == "all" || !input$enable_municipalities) {
      choices <- c("Todos" = "all")
    } else {
      municipalities <- municipalities_data()
      if (!is.null(municipalities)) {
        state_municipalities <- municipalities %>%
          filter(state_code == input$state_filter) %>%
          arrange(municipality_name)
        
        choices <- c("Todos" = "all", 
                    setNames(state_municipalities$municipality_code, 
                            state_municipalities$municipality_name))
      } else {
        choices <- c("Todos" = "all")
      }
    }
    
    updateSelectInput(session, "municipality_filter", choices = choices)
  })
  
  # ============================================================================
  # OUTPUT RENDERING
  # ============================================================================
  
  # Performance indicators
  output$memory_usage <- renderValueBox({
    safe_valueBox(
      value = paste0(round(values$memory_usage, 1), " MB"),
      subtitle = "Uso de Memória",
      icon = icon("memory"),
      color = if (values$memory_usage > 150) "red" else if (values$memory_usage > 100) "yellow" else "green"
    )
  })
  
  output$query_time <- renderValueBox({
    safe_valueBox(
      value = paste0(round(values$last_query_time, 0), " ms"),
      subtitle = "Tempo de Consulta", 
      icon = icon("clock"),
      color = if (values$last_query_time > 2000) "red" else if (values$last_query_time > 1000) "yellow" else "green"
    )
  })
  
  output$municipalities_loaded <- renderValueBox({
    safe_valueBox(
      value = format(values$municipalities_count, big.mark = ","),
      subtitle = "Municípios Carregados",
      icon = icon("map-marker-alt"),
      color = "blue"
    )
  })
  
  # Enhanced choropleth map
  output$municipality_choropleth <- renderPlotly({
    documents <- enhanced_document_data()
    municipalities <- municipalities_data()
    
    if (isTRUE(is.null(documents)) || nrow(documents) == 0) {
      return(plot_ly() %>%
        add_text(x = 0.5, y = 0.5, text = "Nenhum documento encontrado") %>%
        layout(xaxis = list(visible = FALSE), yaxis = list(visible = FALSE)))
    }
    
    tryCatch({
      if (input$enable_municipalities && !is.null(municipalities)) {
        # Municipality-level visualization
        municipality_stats <- documents %>%
          filter(!is.na(municipality_code)) %>%
          group_by(municipality_code, municipality_name, state_code) %>%
          summarise(
            doc_count = n(),
            latest_date = max(data_documento, na.rm = TRUE),
            .groups = "drop"
          )
        
        # Join with municipality coordinates
        municipality_stats <- municipality_stats %>%
          left_join(municipalities %>% 
                   sf::st_drop_geometry() %>%
                   select(municipality_code, latitude, longitude), 
                   by = "municipality_code") %>%
          filter(!is.na(latitude), !is.na(longitude))
        
        if (nrow(municipality_stats) > 0) {
          p <- create_municipality_choropleth(municipality_stats, input$map_resolution)
        } else {
          # Fallback to state level
          p <- create_state_level_fallback(documents)
        }
      } else {
        # State-level visualization (existing functionality)
        p <- create_state_level_choropleth(documents)
      }
      
      return(p)
      
    }, error = function(e) {
      cat("❌ Error creating choropleth:", e$message, "\n")
      return(plot_ly() %>%
        add_text(x = 0.5, y = 0.5, text = "Erro ao gerar visualização") %>%
        layout(xaxis = list(visible = FALSE), yaxis = list(visible = FALSE)))
    })
  })
  
  # Interactive leaflet map
  output$municipality_leaflet <- renderLeaflet({
    documents <- enhanced_document_data()
    municipalities <- municipalities_data()
    
    if (isTRUE(is.null(documents)) || nrow(documents) == 0) {
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -55, lat = -15, zoom = 4))
    }
    
    tryCatch({
      # Create base map
      map <- leaflet() %>%
        addTiles() %>%
        setView(lng = -55, lat = -15, zoom = 4)
      
      if (input$enable_municipalities && !is.null(municipalities)) {
        # Add municipality polygons
        map <- map %>%
          addPolygons(
            data = municipalities,
            fillColor = ~colorQuantile("YlOrRd", values = sample(1:100, nrow(municipalities)))(sample(1:100, nrow(municipalities))),
            fillOpacity = 0.7,
            color = "white",
            weight = 1,
            popup = ~paste0("<b>", municipality_name, "</b><br>",
                          "Estado: ", state_code, "<br>",
                          "Área: ", round(area_km2, 1), " km²")
          )
      }
      
      # Add document points
      docs_with_coords <- documents %>%
        filter(!is.na(lat), !is.na(lng))
      
      if (nrow(docs_with_coords) > 0) {
        map <- map %>%
          addCircleMarkers(
            data = docs_with_coords,
            lng = ~lng,
            lat = ~lat,
            radius = 5,
            popup = ~paste0("<b>", titulo, "</b><br>",
                           "Data: ", format(data_documento, "%d/%m/%Y"), "<br>",
                           "Tipo: ", tipo),
            color = "blue",
            fillOpacity = 0.7
          )
      }
      
      return(map)
      
    }, error = function(e) {
      cat("❌ Error creating leaflet map:", e$message, "\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -55, lat = -15, zoom = 4))
    })
  })
  
  # Municipality statistics table
  output$municipality_stats <- DT::renderDataTable({
    documents <- enhanced_document_data()
    
    if (isTRUE(is.null(documents)) || isTRUE(nrow(documents) == 0) || !input$enable_municipalities) {
      return(data.frame(
        Mensagem = "Habilite 'Mostrar Municípios' para ver estatísticas detalhadas"
      ))
    }
    
    stats <- documents %>%
      filter(!is.na(municipality_code)) %>%
      group_by(municipality_name, state_code) %>%
      summarise(
        `Documentos` = n(),
        `Última Atualização` = format(max(data_documento, na.rm = TRUE), "%d/%m/%Y"),
        `Tipos Únicos` = n_distinct(tipo, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(desc(`Documentos`))
    
    DT::datatable(
      stats,
      options = list(
        pageLength = 15,
        scrollX = TRUE,
        dom = 'frtip'
      ),
      rownames = FALSE
    )
  })
  
  # Municipality distribution chart
  output$municipality_distribution <- renderPlotly({
    documents <- enhanced_document_data()
    
    if (isTRUE(is.null(documents)) || isTRUE(nrow(documents) == 0) || !input$enable_municipalities) {
      return(plot_ly() %>%
        add_text(x = 0.5, y = 0.5, text = "Habilite municípios para ver distribuição") %>%
        layout(xaxis = list(visible = FALSE), yaxis = list(visible = FALSE)))
    }
    
    distribution_data <- documents %>%
      filter(!is.na(municipality_code)) %>%
      group_by(state_code) %>%
      summarise(
        municipalities = n_distinct(municipality_code),
        documents = n(),
        .groups = "drop"
      ) %>%
      arrange(desc(documents))
    
    plot_ly(
      data = distribution_data,
      x = ~reorder(state_code, documents),
      y = ~documents,
      type = "bar",
      text = ~paste0(state_code, "<br>", documents, " docs<br>", municipalities, " municípios"),
      hoverinfo = "text"
    ) %>%
      layout(
        title = "Distribuição por Estado",
        xaxis = list(title = "Estado"),
        yaxis = list(title = "Número de Documentos"),
        margin = list(b = 50)
      )
  })
  
  # ============================================================================
  # RETURN REACTIVE FUNCTIONS
  # ============================================================================
  
  return(list(
    enhanced_document_data = enhanced_document_data,
    municipalities_data = municipalities_data,
    memory_monitor = performance_monitor,
    query_cache = query_cache
  ))
}

# ============================================================================
# HELPER VISUALIZATION FUNCTIONS
# ============================================================================

#' Create municipality-level choropleth map
#' @param municipality_stats Data frame with municipality statistics
#' @param resolution Map resolution level
#' @return Plotly object
create_municipality_choropleth <- function(municipality_stats, resolution = "medium") {
  if (nrow(municipality_stats) == 0) {
    return(plot_ly() %>%
      add_text(x = 0.5, y = 0.5, text = "Nenhum município com dados") %>%
      layout(xaxis = list(visible = FALSE), yaxis = list(visible = FALSE)))
  }
  
  plot_ly(
    data = municipality_stats,
    type = "scattergeo",
    mode = "markers",
    lon = ~longitude,
    lat = ~latitude,
    text = ~municipality_name,
    marker = list(
      size = ~sqrt(doc_count) * 3,
      color = ~doc_count,
      colorscale = "Viridis",
      colorbar = list(title = "Documentos"),
      line = list(color = "white", width = 1),
      sizemode = "diameter"
    ),
    hovertext = ~paste0(
      "<b>", municipality_name, "</b><br>",
      "Estado: ", state_code, "<br>",
      "Documentos: ", format(doc_count, big.mark = ","), "<br>",
      "Última atualização: ", format(latest_date, "%d/%m/%Y")
    ),
    hoverinfo = "text"
  ) %>%
  layout(
    geo = list(
      scope = "south america",
      showland = TRUE,
      landcolor = toRGB("gray95"),
      projection = list(type = "mercator"),
      center = list(lon = -55, lat = -15),
      lonaxis = list(range = c(-75, -35)),
      lataxis = list(range = c(-35, 5))
    ),
    title = "Distribuição Municipal de Documentos Legislativos",
    margin = list(l = 0, r = 0, t = 40, b = 0)
  )
}

#' Create state-level choropleth (fallback)
#' @param documents Document data frame
#' @return Plotly object
create_state_level_choropleth <- function(documents) {
  # Use existing state-level functionality
  state_stats <- documents %>%
    filter(!is.na(estado)) %>%
    group_by(estado) %>%
    summarise(
      doc_count = n(),
      latest_date = max(data_documento, na.rm = TRUE),
      .groups = "drop"
    )
  
  # Join with state coordinates
  if (exists("BRAZIL_STATE_COORDS")) {
    state_stats <- state_stats %>%
      left_join(BRAZIL_STATE_COORDS, by = c("estado" = "state_code")) %>%
      filter(!is.na(lat), !is.na(lng))
    
    create_webgl_choropleth(state_stats, use_webgl = TRUE)
  } else {
    plot_ly() %>%
      add_text(x = 0.5, y = 0.5, text = "Dados de coordenadas não disponíveis") %>%
      layout(xaxis = list(visible = FALSE), yaxis = list(visible = FALSE))
  }
}

# ============================================================================
# MODULE EXPORTS
# ============================================================================

dashboard_integration_exports <- list(
  # UI components
  municipality_filter_ui = municipality_filter_ui,
  enhanced_geographic_output_ui = enhanced_geographic_output_ui,
  
  # Server logic
  enhanced_geographic_server = enhanced_geographic_server,
  
  # Helper functions
  create_municipality_choropleth = create_municipality_choropleth,
  create_state_level_choropleth = create_state_level_choropleth
)

cat("✅ Dashboard Integration Module loaded successfully\n")
cat("   Municipality filtering: ENABLED\n")
cat("   Enhanced geographic visualization: ENABLED\n")
cat("   Progressive enhancement: ENABLED\n")
cat("   Backward compatibility: ENABLED\n")