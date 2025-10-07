# Transport Corridor Analysis Module
# ===================================
# Specialized geospatial analysis for Brazilian transport policy monitoring
# Focus on highways, railways, ports, and multimodal corridors

library(sf)
library(leaflet)
library(data.table)

# BRAZILIAN TRANSPORT INFRASTRUCTURE DATA
# ========================================

# Major Brazilian highways
brazil_highways <- list(
  BR116 = list(
    name = "BR-116 (Rodovia Presidente Dutra)",
    description = "Brazil's longest highway - 4,385 km",
    states = c("RS", "SC", "PR", "SP", "RJ", "MG", "BA", "PE", "PB", "CE", "RN"),
    key_cities = c("Porto Alegre", "Curitiba", "São Paulo", "Rio de Janeiro", "Belo Horizonte", "Salvador", "Fortaleza"),
    coordinates = list(
      c(-51.2177, -30.0346), # Porto Alegre
      c(-49.2654, -25.4284), # Curitiba
      c(-46.6333, -23.5505), # São Paulo
      c(-43.1729, -22.9068), # Rio de Janeiro
      c(-43.9345, -19.9167), # Belo Horizonte
      c(-38.5014, -12.9714), # Salvador
      c(-38.5247, -3.7319)   # Fortaleza
    )
  ),
  
  BR101 = list(
    name = "BR-101 (Translitorânea)",
    description = "Coastal highway - 4,551 km",
    states = c("RS", "SC", "PR", "SP", "RJ", "ES", "BA", "SE", "AL", "PE", "PB", "RN"),
    key_cities = c("São José do Norte", "Florianópolis", "Santos", "Rio de Janeiro", "Vitória", "Salvador", "Aracaju", "Maceió", "Recife", "João Pessoa", "Natal"),
    coordinates = list(
      c(-52.0333, -32.0167), # São José do Norte
      c(-48.5494, -27.5954), # Florianópolis
      c(-46.3344, -23.9681), # Santos
      c(-43.1729, -22.9068), # Rio de Janeiro
      c(-40.2958, -20.3155), # Vitória
      c(-38.5014, -12.9714), # Salvador
      c(-37.0731, -10.9472), # Aracaju
      c(-35.7353, -9.6658),  # Maceió
      c(-34.8811, -8.0476),  # Recife
      c(-34.8633, -7.1195),  # João Pessoa
      c(-35.2094, -5.7945)   # Natal
    )
  ),
  
  BR364 = list(
    name = "BR-364",
    description = "Integration highway - 4,141 km",
    states = c("SP", "MG", "GO", "MT", "RO", "AC"),
    key_cities = c("Limeira", "Uberlândia", "Goiânia", "Cuiabá", "Porto Velho", "Rio Branco"),
    coordinates = list(
      c(-47.4017, -22.5647), # Limeira
      c(-48.2772, -18.9186), # Uberlândia
      c(-49.2643, -16.6864), # Goiânia
      c(-56.0974, -15.5954), # Cuiabá
      c(-63.9039, -8.7619),  # Porto Velho
      c(-67.8099, -9.9747)   # Rio Branco
    )
  ),
  
  BR163 = list(
    name = "BR-163 (Cuiabá-Santarém)",
    description = "Agricultural corridor - 3,579 km",
    states = c("RS", "SC", "PR", "MS", "MT", "PA"),
    key_cities = c("Tenente Portela", "Cascavel", "Campo Grande", "Cuiabá", "Sinop", "Santarém"),
    coordinates = list(
      c(-53.7581, -27.3714), # Tenente Portela
      c(-53.4552, -24.9555), # Cascavel
      c(-54.6464, -20.4486), # Campo Grande
      c(-56.0974, -15.5954), # Cuiabá
      c(-55.5016, -11.8639), # Sinop
      c(-54.7083, -2.4406)   # Santarém
    )
  )
)

# Major Brazilian ports
brazil_ports <- list(
  santos = list(name = "Porto de Santos", lat = -23.9681, lng = -46.3344, state = "SP", type = "major"),
  paranagua = list(name = "Porto de Paranaguá", lat = -25.5205, lng = -48.5097, state = "PR", type = "major"),
  riogrande = list(name = "Porto do Rio Grande", lat = -32.0349, lng = -52.0986, state = "RS", type = "major"),
  itajai = list(name = "Porto de Itajaí", lat = -26.9078, lng = -48.6619, state = "SC", type = "major"),
  suape = list(name = "Porto de Suape", lat = -8.3933, lng = -34.9722, state = "PE", type = "major"),
  vitoria = list(name = "Porto de Vitória", lat = -20.3155, lng = -40.2958, state = "ES", type = "major"),
  rio = list(name = "Porto do Rio de Janeiro", lat = -22.8961, lng = -43.1242, state = "RJ", type = "major"),
  salvador = list(name = "Porto de Salvador", lat = -12.9714, lng = -38.5014, state = "BA", type = "major")
)

# Railway networks
brazil_railways <- list(
  norte_sul = list(
    name = "Ferrovia Norte-Sul",
    operator = "RUMO/VLI",
    length_km = 3100,
    states = c("MA", "TO", "GO", "MG", "SP"),
    key_points = list(
      c(-44.3028, -2.5297),  # São Luís
      c(-48.3575, -10.1833), # Palmas
      c(-50.1436, -16.4692), # Anápolis
      c(-49.9456, -21.7619), # Estrela d'Oeste
      c(-47.8847, -22.0153)  # Rio Grande (SP)
    )
  ),
  
  transnordestina = list(
    name = "Ferrovia Transnordestina",
    operator = "CSN",
    length_km = 1753,
    states = c("PI", "CE", "PE"),
    key_points = list(
      c(-42.8019, -5.0892),  # Eliseu Martins
      c(-38.5247, -3.7319),  # Fortaleza (Pecém)
      c(-39.2578, -7.2306),  # Salgueiro
      c(-34.8811, -8.0476)   # Recife (Suape)
    )
  ),
  
  fico = list(
    name = "Ferrovia de Integração Centro-Oeste (FICO)",
    operator = "Planned",
    length_km = 1638,
    states = c("MT", "GO", "TO", "BA"),
    key_points = list(
      c(-55.7250, -15.0000), # Lucas do Rio Verde
      c(-52.2544, -14.2350), # Água Boa
      c(-49.0697, -12.9704), # Campinorte
      c(-46.8754, -12.1464)  # Ilhéus
    )
  )
)

# TRANSPORT CORRIDOR UI
# =====================
transportCorridorUI <- function(id) {
  ns <- NS(id)
  
  tagList(
    fluidRow(
      box(
        title = "Transport Infrastructure Legislative Analysis",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        fluidRow(
          column(width = 3,
            selectInput(ns("corridor_type"),
              "Infrastructure Type:",
              choices = c(
                "All Transport" = "all",
                "Federal Highways (BR)" = "highways",
                "Railways" = "railways",
                "Ports & Waterways" = "ports",
                "Airports" = "airports",
                "Multimodal Terminals" = "multimodal"
              ),
              selected = "all"
            ),
            
            conditionalPanel(
              condition = sprintf("input['%s'] == 'highways'", ns("corridor_type")),
              selectInput(ns("highway_select"),
                "Select Highway:",
                choices = c(
                  "All Highways" = "all",
                  "BR-116 (Dutra)" = "BR116",
                  "BR-101 (Coastal)" = "BR101",
                  "BR-364 (Integration)" = "BR364",
                  "BR-163 (Cuiabá-Santarém)" = "BR163",
                  "BR-230 (Transamazônica)" = "BR230"
                ),
                selected = "all"
              )
            ),
            
            conditionalPanel(
              condition = sprintf("input['%s'] == 'railways'", ns("corridor_type")),
              selectInput(ns("railway_select"),
                "Select Railway:",
                choices = c(
                  "All Railways" = "all",
                  "Norte-Sul" = "norte_sul",
                  "Transnordestina" = "transnordestina",
                  "FICO" = "fico",
                  "RUMO Network" = "rumo",
                  "MRS Network" = "mrs",
                  "VLI Network" = "vli"
                ),
                selected = "all"
              )
            )
          ),
          
          column(width = 3,
            sliderInput(ns("buffer_distance"),
              "Analysis Buffer (km):",
              min = 1,
              max = 100,
              value = 25,
              step = 5
            ),
            
            selectInput(ns("analysis_metric"),
              "Analysis Metric:",
              choices = c(
                "Document Density" = "density",
                "Legislative Activity" = "activity",
                "Regulatory Changes" = "regulatory",
                "Investment Related" = "investment",
                "Environmental Impact" = "environmental",
                "Safety Regulations" = "safety"
              ),
              selected = "density"
            )
          ),
          
          column(width = 3,
            dateRangeInput(ns("corridor_dates"),
              "Analysis Period:",
              start = Sys.Date() - 365,
              end = Sys.Date(),
              format = "dd/mm/yyyy"
            ),
            
            checkboxGroupInput(ns("doc_types"),
              "Document Types:",
              choices = c(
                "Federal Laws" = "lei_federal",
                "State Laws" = "lei_estadual",
                "Decrees" = "decreto",
                "Resolutions" = "resolucao",
                "Court Decisions" = "jurisprudencia"
              ),
              selected = c("lei_federal", "decreto")
            )
          ),
          
          column(width = 3,
            br(),
            actionButton(ns("analyze_corridor"),
              "Analyze Corridor",
              icon = icon("route"),
              class = "btn-success btn-block"
            ),
            br(),
            downloadButton(ns("download_corridor_report"),
              "Download Report",
              class = "btn-info btn-block"
            ),
            br(),
            actionButton(ns("compare_corridors"),
              "Compare Corridors",
              icon = icon("exchange-alt"),
              class = "btn-warning btn-block"
            )
          )
        )
      )
    ),
    
    # Main corridor map
    fluidRow(
      box(
        title = "Corridor Visualization",
        status = "info",
        solidHeader = TRUE,
        width = 8,
        
        leafletOutput(ns("corridor_map"), height = "600px"),
        
        # Corridor statistics
        wellPanel(
          style = "margin-top: 15px;",
          fluidRow(
            column(3,
              div(class = "text-center",
                h3(textOutput(ns("corridor_length")), style = "color: #007bff;"),
                p("Corridor Length (km)")
              )
            ),
            column(3,
              div(class = "text-center",
                h3(textOutput(ns("affected_states")), style = "color: #28a745;"),
                p("States Affected")
              )
            ),
            column(3,
              div(class = "text-center",
                h3(textOutput(ns("documents_found")), style = "color: #ffc107;"),
                p("Documents Found")
              )
            ),
            column(3,
              div(class = "text-center",
                h3(textOutput(ns("activity_index")), style = "color: #dc3545;"),
                p("Activity Index")
              )
            )
          )
        )
      ),
      
      # Side analysis panel
      box(
        title = "Corridor Analysis",
        status = "success",
        solidHeader = TRUE,
        width = 4,
        
        # Timeline chart
        h5("Legislative Activity Timeline"),
        plotlyOutput(ns("corridor_timeline"), height = "200px"),
        
        hr(),
        
        # Top documents
        h5("Key Documents"),
        DT::dataTableOutput(ns("key_documents"), height = "250px"),
        
        hr(),
        
        # State breakdown
        h5("State-by-State Analysis"),
        plotlyOutput(ns("state_breakdown"), height = "200px")
      )
    ),
    
    # Detailed analysis panels
    fluidRow(
      box(
        title = "Comparative Analysis",
        status = "warning",
        solidHeader = TRUE,
        width = 12,
        collapsible = TRUE,
        collapsed = TRUE,
        
        fluidRow(
          column(width = 6,
            h4("Infrastructure Investment Correlation"),
            plotlyOutput(ns("investment_correlation"), height = "300px")
          ),
          column(width = 6,
            h4("Modal Split Analysis"),
            plotlyOutput(ns("modal_split"), height = "300px")
          )
        ),
        
        hr(),
        
        fluidRow(
          column(width = 12,
            h4("Corridor Comparison Matrix"),
            DT::dataTableOutput(ns("comparison_matrix"))
          )
        )
      )
    )
  )
}

# TRANSPORT CORRIDOR SERVER
# =========================
transportCorridorServer <- function(id, legislative_data = NULL) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values
    corridor_values <- reactiveValues(
      current_corridor = NULL,
      buffer_zone = NULL,
      affected_documents = NULL,
      corridor_stats = NULL
    )
    
    # Build corridor geometry
    build_corridor <- function(type, selection, buffer_km) {
      if (type == "highways" && selection %in% names(brazil_highways)) {
        highway <- brazil_highways[[selection]]
        
        # Create line from coordinates
        coords <- do.call(rbind, highway$coordinates)
        line <- sf::st_linestring(coords)
        line_sf <- sf::st_sfc(line, crs = 4326)
        
        # Create buffer
        buffer <- sf::st_buffer(line_sf, dist = buffer_km * 1000)
        
        return(list(
          geometry = buffer,
          line = line_sf,
          name = highway$name,
          states = highway$states,
          cities = highway$key_cities
        ))
      } else if (type == "railways" && selection %in% names(brazil_railways)) {
        railway <- brazil_railways[[selection]]
        
        coords <- do.call(rbind, railway$key_points)
        line <- sf::st_linestring(coords)
        line_sf <- sf::st_sfc(line, crs = 4326)
        buffer <- sf::st_buffer(line_sf, dist = buffer_km * 1000)
        
        return(list(
          geometry = buffer,
          line = line_sf,
          name = railway$name,
          states = railway$states,
          operator = railway$operator
        ))
      } else if (type == "ports") {
        # Create circles around ports
        port_buffers <- lapply(brazil_ports, function(port) {
          point <- sf::st_point(c(port$lng, port$lat))
          sf::st_buffer(sf::st_sfc(point, crs = 4326), dist = buffer_km * 1000)
        })
        
        combined <- sf::st_union(do.call(c, port_buffers))
        
        return(list(
          geometry = combined,
          name = "Brazilian Port System",
          ports = names(brazil_ports)
        ))
      }
      
      return(NULL)
    }
    
    # Analyze corridor
    observeEvent(input$analyze_corridor, {
      req(input$corridor_type)
      
      showNotification("Analyzing transport corridor...", type = "message", id = "analyzing")
      
      # Build corridor geometry
      if (input$corridor_type == "highways") {
        corridor <- build_corridor("highways", input$highway_select, input$buffer_distance)
      } else if (input$corridor_type == "railways") {
        corridor <- build_corridor("railways", input$railway_select, input$buffer_distance)
      } else if (input$corridor_type == "ports") {
        corridor <- build_corridor("ports", "all", input$buffer_distance)
      } else {
        # Combined analysis
        corridor <- list(
          name = "All Transport Infrastructure",
          geometry = NULL
        )
      }
      
      corridor_values$current_corridor <- corridor
      
      # Find affected documents
      if (!is.null(legislative_data)) {
        # Filter by date and type
        docs <- legislative_data()
        
        if ("date" %in% names(docs)) {
          docs <- docs[docs$date >= input$corridor_dates[1] & 
                      docs$date <= input$corridor_dates[2], ]
        }
        
        # Spatial filter if geometry exists
        if (!is.null(corridor$geometry) && "lat" %in% names(docs) && "lng" %in% names(docs)) {
          doc_points <- sf::st_as_sf(docs, coords = c("lng", "lat"), crs = 4326)
          intersects <- sf::st_intersects(doc_points, corridor$geometry, sparse = FALSE)
          docs <- docs[intersects[,1], ]
        }
        
        corridor_values$affected_documents <- docs
      }
      
      removeNotification("analyzing")
      showNotification(
        sprintf("Found %d documents in corridor", nrow(corridor_values$affected_documents)),
        type = "success"
      )
    })
    
    # Render corridor map
    output$corridor_map <- renderLeaflet({
      map <- leaflet() %>%
        addProviderTiles("CartoDB.Positron") %>%
        setView(lng = -47.9, lat = -15.8, zoom = 4)
      
      # Add corridor geometry
      if (!is.null(corridor_values$current_corridor)) {
        corridor <- corridor_values$current_corridor
        
        if (!is.null(corridor$line)) {
          # Add the actual route
          map <- map %>%
            addPolylines(
              data = corridor$line,
              color = "#FF0000",
              weight = 3,
              opacity = 1,
              label = corridor$name
            )
        }
        
        if (!is.null(corridor$geometry)) {
          # Add buffer zone
          map <- map %>%
            addPolygons(
              data = corridor$geometry,
              fillColor = "#FF0000",
              fillOpacity = 0.2,
              weight = 1,
              color = "#FF0000",
              opacity = 0.5
            )
        }
        
        # Add affected documents
        if (!is.null(corridor_values$affected_documents) && 
            nrow(corridor_values$affected_documents) > 0) {
          docs <- corridor_values$affected_documents
          
          if ("lat" %in% names(docs) && "lng" %in% names(docs)) {
            map <- map %>%
              addCircleMarkers(
                data = docs,
                lng = ~lng, lat = ~lat,
                radius = 5,
                fillColor = "#0066CC",
                fillOpacity = 0.7,
                weight = 1,
                color = "white",
                popup = ~paste0(
                  "<b>", title, "</b><br>",
                  "Type: ", type, "<br>",
                  "Date: ", date
                )
              )
          }
        }
      }
      
      # Add ports
      if (input$corridor_type %in% c("all", "ports")) {
        for (port in brazil_ports) {
          map <- map %>%
            addMarkers(
              lng = port$lng,
              lat = port$lat,
              label = port$name,
              icon = makeIcon(
                iconUrl = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-blue.png",
                iconWidth = 25, iconHeight = 41
              )
            )
        }
      }
      
      map
    })
    
    # Statistics outputs
    output$corridor_length <- renderText({
      result <- tryCatch({
        if (!is.null(corridor_values$current_corridor)) {
          if (input$corridor_type == "highways" && input$highway_select %in% names(brazil_highways)) {
            extracted <- brazil_highways[[input$highway_select]]$description %>%
              stringr::str_extract("\\d+,?\\d*") %>%
              stringr::str_remove(",")
            scalar_chr(extracted, default = "N/A")
          } else if (input$corridor_type == "railways" && input$railway_select %in% names(brazil_railways)) {
            scalar_chr(as.character(brazil_railways[[input$railway_select]]$length_km), default = "N/A")
          } else {
            "N/A"
          }
        } else {
          "N/A"
        }
      }, error = function(e) "N/A")

      text_scalar(result, default = "N/A")
    })
    
    output$affected_states <- renderText({
      result <- tryCatch({
        if (!is.null(corridor_values$current_corridor)) {
          states <- corridor_values$current_corridor$states
          safe_n_distinct(states, default = 0L)
        } else {
          0L
        }
      }, error = function(e) 0L)

      text_scalar(result, default = "0")
    })
    
    output$documents_found <- renderText({
      result <- tryCatch({
        n_docs <- safe_nrow(corridor_values$affected_documents, default = 0L)
        format(n_docs, big.mark = ",")
      }, error = function(e) "0")

      text_scalar(result, default = "0")
    })
    
    output$activity_index <- renderText({
      result <- tryCatch({
        n_docs <- safe_nrow(corridor_values$affected_documents, default = 0L)
        if (n_docs > 0 && !is.null(input$corridor_dates) && length(input$corridor_dates) == 2) {
          # Calculate activity index (documents per month)
          days <- scalar_num(as.numeric(diff(input$corridor_dates)), default = 0)
          if (days > 0) {
            monthly_rate <- (n_docs / days) * 30
            scalar_num(round(monthly_rate, 1), default = 0)
          } else {
            0
          }
        } else {
          0
        }
      }, error = function(e) 0)

      text_scalar(result, default = "0")
    })
    
    # Timeline chart
    output$corridor_timeline <- renderPlotly({
      req(corridor_values$affected_documents)
      
      if (nrow(corridor_values$affected_documents) > 0 && "date" %in% names(corridor_values$affected_documents)) {
        docs <- corridor_values$affected_documents
        
        # Aggregate by month
        docs$month <- format(as.Date(docs$date), "%Y-%m")
        monthly <- aggregate(docs$title, by = list(month = docs$month), FUN = length)
        names(monthly)[2] <- "count"
        
        plot_ly(monthly, x = ~month, y = ~count, type = "scatter", mode = "lines+markers",
                line = list(color = "#007bff"),
                marker = list(color = "#007bff")) %>%
          layout(
            xaxis = list(title = ""),
            yaxis = list(title = "Documents"),
            margin = list(l = 40, r = 10, t = 10, b = 30)
          )
      } else {
        plotly_empty()
      }
    })
    
    # Key documents table
    output$key_documents <- DT::renderDataTable({
      req(corridor_values$affected_documents)
      
      if (nrow(corridor_values$affected_documents) > 0) {
        docs <- corridor_values$affected_documents
        
        # Select top documents (most recent or by relevance)
        top_docs <- head(docs[order(docs$date, decreasing = TRUE), ], 10)
        
        if (all(c("title", "type", "date") %in% names(top_docs))) {
          DT::datatable(
            top_docs[, c("title", "type", "date")],
            options = list(
              pageLength = 5,
              dom = 't',
              scrollY = "200px",
              scrollCollapse = TRUE
            ),
            rownames = FALSE
          )
        }
      }
    }, server = FALSE)
    
    # State breakdown chart
    output$state_breakdown <- renderPlotly({
      req(corridor_values$affected_documents)
      
      if (nrow(corridor_values$affected_documents) > 0 && "state" %in% names(corridor_values$affected_documents)) {
        state_counts <- table(corridor_values$affected_documents$state)
        
        plot_ly(
          x = names(state_counts),
          y = as.numeric(state_counts),
          type = "bar",
          marker = list(color = "#28a745")
        ) %>%
          layout(
            xaxis = list(title = ""),
            yaxis = list(title = "Documents"),
            margin = list(l = 40, r = 10, t = 10, b = 30)
          )
      } else {
        plotly_empty()
      }
    })
    
    # Download corridor report
    output$download_corridor_report <- downloadHandler(
      filename = function() {
        paste0("corridor_analysis_", Sys.Date(), ".csv")
      },
      content = function(file) {
        if (!is.null(corridor_values$affected_documents)) {
          write.csv(corridor_values$affected_documents, file, row.names = FALSE)
        }
      }
    )
    
    return(corridor_values)
  })
}

# Export module
list(
  ui = transportCorridorUI,
  server = transportCorridorServer,
  highways = brazil_highways,
  ports = brazil_ports,
  railways = brazil_railways
)