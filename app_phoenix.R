# ==============================================================================
# MONITOR LEGISLATIVO V4 - PHOENIX REBUILD (v2)
# ==============================================================================
# A rock-solid, monolithic app built for stability.
# This version includes working search functionality and a fix for the UI blur.
# ==============================================================================

# ==============================================================================
# 1. LOAD PACKAGES
# ==============================================================================
suppressPackageStartupMessages({
  library(shiny)
  library(shinythemes)
  library(DBI)
  library(RPostgres)
  library(DT)
  library(leaflet)
  library(sf)
  library(ggplot2)
})

# Load performance monitoring module
source("R/modules/performance_monitoring_module.R", local = TRUE)

# ==============================================================================
# 2. DATABASE CONNECTION LOGIC (PROVEN & STABLE)
# ==============================================================================
# Global connection object
secure_db_connection <- NULL
DB_AVAILABLE <- FALSE

get_database_config <- function() {
  # Method 1: PRIORITIZE Google Cloud Run Unix Socket
  is_in_cloud_run <- !is.na(Sys.getenv("K_SERVICE", unset = NA))
  if (is_in_cloud_run) {
    cat("✅ Detected Google Cloud Run environment\n")
    return(list(
      host = paste("/cloudsql", "mackmonitor:southamerica-east1:mackmonitor-db", sep = "/"),
      port = 5432,
      dbname = Sys.getenv("PGDATABASE", "monitor_legislativo"),
      user = Sys.getenv("PGUSER", "monitor_user"),
      password = Sys.getenv("PGPASSWORD", "")
    ))
  }
  
  # Method 2: Fallback to environment variables for local development
  cat("📋 Local environment detected. Using PGHOST/PGUSER...\n")
  return(list(
    host = Sys.getenv("PGHOST", "localhost"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE", "monitor_legislativo"),
    user = Sys.getenv("PGUSER", "postgres"),
    password = Sys.getenv("PGPASSWORD", "")
  ))
}

init_secure_database <- function() { 
  config <- get_database_config()
  
  tryCatch({
    conn <- dbConnect(
      RPostgres::Postgres(),
      host = config$host,
      port = config$port, 
      dbname = config$dbname,
      user = config$user,
      password = config$password,
      sslmode = "prefer",
      connect_timeout = 20
    )
    
    cat("✅ SECURE DATABASE CONNECTION ESTABLISHED\n")
    return(conn)
    
  }, error = function(e) {
    cat("❌ SECURE DATABASE CONNECTION FAILED:", e$message, "\n")
    return(NULL)
  })
}

# Establish connection on app startup
secure_db_connection <- init_secure_database()
DB_AVAILABLE <- !is.null(secure_db_connection)

# ==============================================================================
# 3. UI DEFINITION (STABLE & MONOLITHIC)
# ==============================================================================
ui <- navbarPage(
  title = "Monitor Legislativo",
  theme = shinytheme("cerulean"), # Re-enabled theme

  # -- Custom CSS to fix blur/rendering bug --
  header = tags$head(
    tags$style(HTML("
      body {
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
      }
    "))
  ),

  # -- HOME TAB (EXECUTIVE SUMMARY) --
  tabPanel(
    "Home",
    icon = icon("home"),
    fluidPage(
      h2("Monitor Legislativo - Executive Summary"),
      p("Visão geral da coleção de documentos legislativos brasileiros"),
      hr(),

      # Key Statistics Row
      fluidRow(
        column(3,
          wellPanel(
            style = "background-color: #f0f8ff; text-align: center;",
            h4(icon("file-alt"), " Total Documents"),
            h2(textOutput("home_total_docs", inline = TRUE))
          )
        ),
        column(3,
          wellPanel(
            style = "background-color: #f0fff0; text-align: center;",
            h4(icon("calendar"), " Document Types"),
            h2(textOutput("home_doc_types_count", inline = TRUE))
          )
        ),
        column(3,
          wellPanel(
            style = "background-color: #fff5f0; text-align: center;",
            h4(icon("clock"), " Latest Document"),
            h3(textOutput("home_latest_date", inline = TRUE))
          )
        ),
        column(3,
          wellPanel(
            style = "background-color: #f5f0ff; text-align: center;",
            h4(icon("chart-line"), " Oldest Document"),
            h3(textOutput("home_oldest_date", inline = TRUE))
          )
        )
      ),

      hr(),

      # Document Type Breakdown
      fluidRow(
        column(6,
          wellPanel(
            h4(icon("list"), " Documents by Type"),
            DT::dataTableOutput("home_type_breakdown")
          )
        ),
        column(6,
          wellPanel(
            h4(icon("calendar-alt"), " Recent Activity (Last 10)"),
            DT::dataTableOutput("home_recent_activity")
          )
        )
      )
    )
  ),

  # -- LIBRARY TAB --
  tabPanel(
    "Library",
    icon = icon("book"),
    fluidPage(
      h2("Biblioteca de Documentos Legislativos"),
      p("Pesquise, filtre e explore a coleção completa de documentos legislativos brasileiros."),
      hr(),
      wellPanel(
        h4("Filtros de Pesquisa"),
        fluidRow(
          column(6, textInput("library_search", "Termo de Pesquisa:", placeholder = "Ex: 'tributário' ou 'lei 14.133'")),
          column(3, selectInput("library_tipo", "Tipo de Documento:",
                 choices = c("Todos", "Lei", "Decreto", "Projeto de Lei", "Medida Provisória",
                            "Resolução", "Portaria", "Instrução Normativa", "Parecer",
                            "Acórdão", "Súmula"))),
          column(3, selectInput("library_mostrar", "Mostrar:", choices = c(100, 500, 1000, 5000, 10000, 999999), selected = 100))
        ),
        actionButton("library_apply", "Aplicar Filtros", icon = icon("search")),
        actionButton("library_clear", "Limpar", icon = icon("times"))
      ),
      hr(),
      h4("Resultados da Pesquisa"),
      DT::dataTableOutput("library_table")
    )
  ),

  # -- GEOGRAPHIC TAB --
  tabPanel(
    "Geographic",
    icon = icon("map-marked-alt"),
    fluidPage(
      h1("Geographic Visualization"),
      p("Visualização geográfica de documentos legislativos por estado"),
      hr(),
      fluidRow(
        column(3,
          selectInput("geo_filter_tipo", "Filtrar por Tipo:",
                     choices = c("Todos", "Lei", "Decreto", "Projeto de Lei",
                                "Medida Provisória", "Resolução", "Portaria",
                                "Instrução Normativa", "Parecer", "Acórdão", "Súmula"),
                     selected = "Todos")
        ),
        column(4,
          dateRangeInput("geo_date_range", "Período:",
                        start = NULL, end = NULL,
                        format = "dd/mm/yyyy",
                        language = "pt-BR",
                        separator = " até ")
        ),
        column(3,
          actionButton("geo_apply", "Aplicar Filtros",
                      class = "btn-primary",
                      style = "margin-top: 25px;"),
          actionButton("geo_clear", "Limpar",
                      class = "btn-secondary",
                      style = "margin-top: 25px; margin-left: 10px;")
        ),
        column(2,
          downloadButton("geo_download", "Exportar Dados",
                        class = "btn-success",
                        style = "margin-top: 25px;")
        )
      ),
      fluidRow(
        column(12,
          downloadButton("geo_download_map", "Exportar Mapa (PNG)",
                        class = "btn-info",
                        style = "margin-top: 10px; margin-bottom: 10px;")
        )
      ),
      hr(),
      fluidRow(
        column(8,
          # Main map
          leaflet::leafletOutput("geo_map", height = "600px")
        ),
        column(4,
          # Quick Win #1: State ranking table
          h4("Ranking de Estados"),
          DT::dataTableOutput("geo_state_ranking"),
          hr(),
          # Quick Win #2: Summary statistics
          h4("Estatísticas Resumidas"),
          uiOutput("geo_summary_stats"),
          hr(),
          # Quick Win #6: Performance metrics
          h5("Métricas de Desempenho"),
          div(style = "font-size: 12px; color: #666;",
            uiOutput("geo_performance_metrics")
          )
        )
      )
    )
  ),

  # -- ANALYTICS TAB --
  tabPanel(
    "Analytics",
    icon = icon("chart-bar"),
    fluidPage(
      h2("Análise de Documentos"),
      p("Distribuição por tipo e evolução mensal"),
      hr(),
      fluidRow(
        column(6, plotOutput("analytics_type_bar", height = "400px")),
        column(6, plotOutput("analytics_month_line", height = "400px"))
      )
    )
  ),

  # -- PLACEHOLDER TABS --
  tabPanel("Text Mining", h1("Text Mining"), p("This section is under development.")),

  # -- SYSTEM / PERFORMANCE MONITORING TAB --
  tabPanel(
    "System",
    icon = icon("server"),
    fluidPage(
      performanceMonitoringUI("perf_monitor")
    )
  )
)

# ==============================================================================
# 4. SERVER LOGIC (STABLE & MONOLITHIC - v3 with State Machine)
# ==============================================================================
server <- function(input, output, session) {
  # DEBUG: confirm server startup
  cat("=== SERVER FUNCTION STARTED ===\n")

  # -- LIBRARY SERVER LOGIC (REFACTORED TO BE MORE ROBUST) --

  # 1. A reactiveValues object to hold the current filter state.
  # This is the "single source of truth" for the query.
  filters <- reactiveValues(
    search = "",
    tipo = "Todos",
    mostrar = 100,
    trigger = 0  # Force reactive to execute on any change
  )

  # Fire a single trigger once the UI is fully bound (avoids infinite loop)
  session$onFlushed(function() {
    isolate({
      filters$trigger <- filters$trigger + 1
    })
  }, once = TRUE)

  # 2. Observer for the 'Apply' button.
  # This updates the reactiveValues, which in turn triggers the data query.
  observeEvent(input$library_apply, {
    cat("=== APPLY BUTTON CLICKED - input$library_apply =", input$library_apply, "===\n")
    filters$search <- input$library_search
    filters$tipo <- input$library_tipo
    filters$mostrar <- as.numeric(input$library_mostrar)
    filters$trigger <- filters$trigger + 1  # Increment trigger to force reactive update
  })

  # 3. Observer for the 'Clear' button.
  # This resets both the UI inputs and the reactive filter values.
  observeEvent(input$library_clear, {
    cat("=== CLEAR BUTTON CLICKED - input$library_clear =", input$library_clear, "===\n")
    # Reset UI
    updateTextInput(session, "library_search", value = "")
    updateSelectInput(session, "library_tipo", selected = "Todos")
    updateSelectInput(session, "library_mostrar", selected = 100)

    # Reset filters to trigger a refresh to the full list
    filters$search <- ""
    filters$tipo <- "Todos"
    filters$mostrar <- 100
    filters$trigger <- filters$trigger + 1  # Increment trigger to force reactive update
  })

  # 4. A reactive expression to fetch data from the database.
  # This automatically re-runs whenever 'filters' changes.
  library_data <- reactive({
    # Use the user's added check for DB availability
    if (!DB_AVAILABLE) {
      return(data.frame(Error = "Database connection not available"))
    }

    # Get current filter values from our reactiveValues
    # Read ALL reactive values to establish dependencies on any change
    current_search <- filters$search
    current_tipo <- filters$tipo
    current_mostrar <- as.numeric(filters$mostrar)
    current_trigger <- filters$trigger  # Read trigger last to establish dependency

    # Start with the base query
    query <- "SELECT id, titulo, tipo, data FROM documents"

    # Build WHERE clauses based on current filter values
    conditions <- list()

    # Search Term Filter
    if (current_search != "") {
      search_term <- gsub("'", "''", current_search)
      conditions <- c(conditions, paste0("titulo ILIKE '%", search_term, "%'"))
    }

    # Document Type Filter
    if (current_tipo != "Todos") {
      tipo_term <- gsub("'", "''", current_tipo)
      conditions <- c(conditions, paste0("tipo = '", tipo_term, "'"))
    }

    # Append WHERE clauses to the query
    if (length(conditions) > 0) {
      query <- paste(query, "WHERE", paste(conditions, collapse = " AND "))
    }

    # Add ORDER BY and LIMIT clauses
    query <- paste(query, "ORDER BY data DESC LIMIT", as.integer(current_mostrar))
    
    cat("Executing query:", query, "\n")
    
    # Execute query and return result
    tryCatch({
      result <- dbGetQuery(secure_db_connection, query)
      cat("Query returned", nrow(result), "rows\n")
      if (nrow(result) == 0) {
        return(data.frame(Message = "Nenhum documento encontrado para os filtros selecionados."))
      }
      result
    }, error = function(e) {
      data.frame(Error = e$message)
    })
  })

  # 5. Render the table with the data from our reactive expression.
  output$library_table <- DT::renderDataTable({
    cat("=== LIBRARY_TABLE OUTPUT RENDERING ===\n")
    library_data()
  }, options = list(pageLength = 10, scrollX = TRUE))

  # Force the output to bind to reactive graph even when tab is hidden
  # This establishes the reactive dependency so buttons can trigger queries
  outputOptions(output, "library_table", suspendWhenHidden = FALSE)

  # -- HOME TAB SERVER LOGIC (EXECUTIVE SUMMARY) --

  # Cached reactive for Home tab statistics
  # This executes all basic stats queries once and caches the results
  # Only re-executes when database connection changes or on manual invalidation
  home_stats <- reactive({
    if (!DB_AVAILABLE) {
      return(list(
        total_docs = NA,
        doc_types_count = NA,
        latest_date = NA,
        oldest_date = NA,
        error = FALSE
      ))
    }

    tryCatch({
      # Execute all basic stats in separate queries (will optimize to single query in Phase 3)
      total_result <- dbGetQuery(secure_db_connection, "SELECT COUNT(*) as total FROM documents")
      types_result <- dbGetQuery(secure_db_connection, "SELECT COUNT(DISTINCT tipo) as count FROM documents")
      latest_result <- dbGetQuery(secure_db_connection, "SELECT MAX(data) as latest FROM documents")
      oldest_result <- dbGetQuery(secure_db_connection, "SELECT MIN(data) as oldest FROM documents")

      list(
        total_docs = total_result$total,
        doc_types_count = types_result$count,
        latest_date = latest_result$latest,
        oldest_date = oldest_result$oldest,
        error = FALSE
      )
    }, error = function(e) {
      cat("Error fetching home stats:", e$message, "\n")
      list(
        total_docs = NA,
        doc_types_count = NA,
        latest_date = NA,
        oldest_date = NA,
        error = TRUE
      )
    })
  })

  # Total documents count - uses cached data
  output$home_total_docs <- renderText({
    stats <- home_stats()
    if (stats$error) return("Error")
    if (is.na(stats$total_docs)) return("N/A")
    format(stats$total_docs, big.mark = ",")
  })

  # Number of distinct document types - uses cached data
  output$home_doc_types_count <- renderText({
    stats <- home_stats()
    if (stats$error) return("Error")
    if (is.na(stats$doc_types_count)) return("N/A")
    as.character(stats$doc_types_count)
  })

  # Latest document date - uses cached data
  output$home_latest_date <- renderText({
    stats <- home_stats()
    if (stats$error) return("Error")
    if (is.null(stats$latest_date) || is.na(stats$latest_date)) return("N/A")
    format(as.Date(stats$latest_date), "%d/%m/%Y")
  })

  # Oldest document date - uses cached data
  output$home_oldest_date <- renderText({
    stats <- home_stats()
    if (stats$error) return("Error")
    if (is.null(stats$oldest_date) || is.na(stats$oldest_date)) return("N/A")
    format(as.Date(stats$oldest_date), "%d/%m/%Y")
  })

  # Cached reactive for Home tab type breakdown
  home_type_breakdown_data <- reactive({
    if (!DB_AVAILABLE) {
      return(data.frame(Message = "Database not available"))
    }

    tryCatch({
      dbGetQuery(secure_db_connection,
        "SELECT tipo AS \"Document Type\",
                COUNT(*) as \"Count\",
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as \"Percentage\"
         FROM documents
         GROUP BY tipo
         ORDER BY COUNT(*) DESC")
    }, error = function(e) {
      cat("Error fetching type breakdown:", e$message, "\n")
      data.frame(Error = e$message)
    })
  })

  # Document type breakdown table - uses cached data
  output$home_type_breakdown <- DT::renderDataTable({
    home_type_breakdown_data()
  }, options = list(pageLength = 10, scrollX = TRUE, dom = 't'))

  # Cached reactive for Home tab recent activity
  home_recent_activity_data <- reactive({
    if (!DB_AVAILABLE) {
      return(data.frame(Message = "Database not available"))
    }

    tryCatch({
      result <- dbGetQuery(secure_db_connection,
        "SELECT tipo AS \"Type\",
                data AS \"Date\",
                LEFT(titulo, 50) || '...' AS \"Title\"
         FROM documents
         ORDER BY data DESC
         LIMIT 10")

      # Format the date column
      if (nrow(result) > 0 && "Date" %in% names(result)) {
        result$Date <- format(as.Date(result$Date), "%d/%m/%Y")
      }

      result
    }, error = function(e) {
      cat("Error fetching recent activity:", e$message, "\n")
      data.frame(Error = e$message)
    })
  })

  # Recent activity table - uses cached data
  output$home_recent_activity <- DT::renderDataTable({
    home_recent_activity_data()
  }, options = list(pageLength = 10, scrollX = TRUE, dom = 't'))

  # -- GEOGRAPHIC SERVER LOGIC --

  # Reactive values for Geographic filters
  geo_filters <- reactiveValues(
    tipo = "Todos",
    date_start = NULL,
    date_end = NULL,
    trigger = 1
  )

  # Store current map data for export (PRD 4.3 - P1 High)
  current_map_data <- reactiveVal(NULL)

  # Store query results and performance metrics (Quick Win #1, #2, #6)
  geo_performance <- reactiveValues(
    query_time = NA,
    total_documents = 0,
    states_with_data = 0,
    date_range = list(min = NA, max = NA),
    memory_used_mb = NA
  )

  # Apply button observer
  observeEvent(input$geo_apply, {
    geo_filters$tipo <- input$geo_filter_tipo
    geo_filters$date_start <- input$geo_date_range[1]
    geo_filters$date_end <- input$geo_date_range[2]
    geo_filters$trigger <- geo_filters$trigger + 1
  })

  # Clear button observer
  observeEvent(input$geo_clear, {
    updateSelectInput(session, "geo_filter_tipo", selected = "Todos")
    updateDateRangeInput(session, "geo_date_range", start = NULL, end = NULL)
    geo_filters$tipo <- "Todos"
    geo_filters$date_start <- NULL
    geo_filters$date_end <- NULL
    geo_filters$trigger <- geo_filters$trigger + 1
  })

  # Download handler for filtered geographic data
  output$geo_download <- downloadHandler(
    filename = function() {
      paste0("geographic_data_", format(Sys.Date(), "%Y%m%d"), ".csv")
    },
    content = function(file) {
      if (!DB_AVAILABLE) {
        write.csv(data.frame(Error = "Database not available"), file, row.names = FALSE)
        return()
      }

      # Read current filter state
      current_tipo <- geo_filters$tipo
      current_date_start <- geo_filters$date_start
      current_date_end <- geo_filters$date_end

      # Build filtered query
      query <- "SELECT estado, COUNT(*) AS document_count FROM documents WHERE 1=1"

      if (current_tipo != "Todos") {
        query <- paste0(query, " AND tipo = '", current_tipo, "'")
      }

      if (!is.null(current_date_start) && !is.null(current_date_end)) {
        query <- paste0(query,
                       " AND data >= '", current_date_start, "'",
                       " AND data <= '", current_date_end, "'")
      }

      query <- paste0(query, " GROUP BY estado ORDER BY document_count DESC")

      # Execute query and write CSV
      tryCatch({
        data <- dbGetQuery(secure_db_connection, query)
        write.csv(data, file, row.names = FALSE)
      }, error = function(e) {
        write.csv(data.frame(Error = e$message), file, row.names = FALSE)
      })
    }
  )

  # Download handler for map export as PNG (PRD 4.3 - P1 High)
  output$geo_download_map <- downloadHandler(
    filename = function() {
      paste0("mapa_geografico_", format(Sys.Date(), "%Y%m%d"), ".png")
    },
    content = function(file) {
      map_data <- current_map_data()

      if (is.null(map_data)) {
        # Create empty plot with message
        p <- ggplot() +
          annotate("text", x = 0, y = 0, label = "Nenhum dado disponível para exportação\nClique em 'Aplicar Filtros' primeiro", size = 6) +
          theme_void()
        ggsave(file, plot = p, width = 10, height = 8, dpi = 300, bg = "white")
        return()
      }

      tryCatch({
        # Debug: print data structure
        cat("Export - Data class:", class(map_data), "\n")
        cat("Export - Columns:", names(map_data), "\n")
        cat("Export - n values:", paste(map_data$n, collapse=", "), "\n")

        # Ensure the object is recognized as sf (fixes class loss from reactiveVal)
        if (!inherits(map_data, "sf")) {
          cat("Export - Converting to sf object\n")
          map_data <- sf::st_as_sf(map_data)
        }

        # Create static choropleth map using ggplot2 + sf
        n_values <- map_data$n
        max_n <- max(n_values, na.rm = TRUE)
        cat("Export - max_n:", max_n, "\n")

        # Create the map
        p <- ggplot(data = map_data) +
          geom_sf(aes(fill = n), color = "#444444", size = 0.3) +
          scale_fill_gradient(
            low = "#fff5eb",
            high = "#d62728",
            name = "Nº Documentos",
            breaks = if(max_n > 0) pretty(c(0, max_n), n = 5) else c(0, 1),
            limits = c(0, max(max_n, 1))
          ) +
          labs(
            title = "Distribuição Geográfica de Documentos Legislativos",
            subtitle = paste("Dados extraídos em", format(Sys.Date(), "%d/%m/%Y")),
            caption = "Fonte: Monitor Legislativo - MackIntegridade"
          ) +
          theme_minimal(base_size = 12) +
          theme(
            plot.title = element_text(face = "bold", size = 16, hjust = 0.5),
            plot.subtitle = element_text(size = 12, hjust = 0.5, color = "gray40"),
            plot.caption = element_text(size = 10, hjust = 1, color = "gray50"),
            legend.position = "right",
            legend.title = element_text(face = "bold"),
            panel.grid = element_blank(),
            axis.text = element_blank(),
            axis.title = element_blank()
          )

        # Save as PNG with high resolution
        ggsave(file, plot = p, width = 12, height = 10, dpi = 300, bg = "white")

      }, error = function(e) {
        # Error handling - create error message plot
        p <- ggplot() +
          annotate("text", x = 0, y = 0,
                  label = paste("Erro ao exportar mapa:", e$message),
                  size = 6, color = "red") +
          theme_void()
        ggsave(file, plot = p, width = 10, height = 8, dpi = 300, bg = "white")
      })
    }
  )

  # Load IBGE state polygons once
  brazil_states_sf <- reactiveVal(NULL)

  observeEvent(TRUE, {  # run once
    if (is.null(brazil_states_sf())) {
      geo_url <- "https://raw.githubusercontent.com/codeforamerica/click_that_hood/master/public/data/brazil-states.geojson"
      shp <- tryCatch({
        raw_shp <- sf::st_read(geo_url, quiet = TRUE)
        # Add 'sigla' field to the shapefile for merging with database (uses 2-letter codes)
        # This ensures proper join between GeoJSON (full names) and database (abbreviations)
        if (!is.null(raw_shp) && "sigla" %in% names(raw_shp)) {
          raw_shp
        } else {
          NULL
        }
      }, error = function(e) NULL)
      brazil_states_sf(shp)
    }
  }, once = TRUE)

  # Initial base map render (runs once)
  output$geo_map <- leaflet::renderLeaflet({
    cat("=== CREATING BASE MAP ===\n")
    leaflet() %>%
      addTiles() %>%
      setView(lng = -54, lat = -15, zoom = 4)
  })

  # Observer to update map data when filters change (uses leafletProxy)
  observe({
    # Memory cleanup on exit (PRD 3.1, 5.2 - P0 Critical)
    on.exit({
      if (exists("shp_merged")) rm(shp_merged)
      if (exists("counts")) rm(counts)
      if (exists("db_counts")) rm(db_counts)
      gc(verbose = FALSE, reset = TRUE)
    })

    # Establish reactive dependency on filter trigger
    current_trigger <- geo_filters$trigger
    current_tipo <- geo_filters$tipo
    current_date_start <- geo_filters$date_start
    current_date_end <- geo_filters$date_end

    cat("=== UPDATING MAP DATA ===\n")
    cat("Trigger value:", current_trigger, "\n")
    cat("Filter tipo:", current_tipo, "\n")
    cat("Filter date_start:", as.character(current_date_start), "\n")
    cat("Filter date_end:", as.character(current_date_end), "\n")

    # Show loading indicator (PRD 4.1 - P1 High)
    withProgress(message = 'Atualizando mapa geográfico...', value = 0, {
      incProgress(0.2, detail = "Carregando dados dos estados")
      shp <- brazil_states_sf()

      # Build filtered query
      incProgress(0.2, detail = "Consultando banco de dados")
      counts <- data.frame()
      if (DB_AVAILABLE) {
        # Track query performance (Quick Win #6)
        query_start_time <- Sys.time()
        memory_before <- as.numeric(object.size(ls())) / 1024 / 1024  # MB

        # Start with base query
        query <- "SELECT estado, COUNT(*) AS n FROM documents WHERE 1=1"

        # Add document type filter
        if (current_tipo != "Todos") {
          query <- paste0(query, " AND tipo = '", current_tipo, "'")
        }

        # Add date range filter
        if (!is.null(current_date_start) && !is.null(current_date_end)) {
          query <- paste0(query,
                         " AND data >= '", current_date_start, "'",
                         " AND data <= '", current_date_end, "'")
        }

        query <- paste0(query, " GROUP BY estado")

        cat("Executing query:", query, "\n")
        db_counts <- tryCatch({
          result <- dbGetQuery(secure_db_connection, query)
          cat("Query returned", nrow(result), "rows\n")
          result
        }, error = function(e) {
          cat("Query error:", e$message, "\n")
          data.frame()
        })
        counts <- db_counts

        # Update performance metrics (Quick Win #6)
        query_end_time <- Sys.time()
        geo_performance$query_time <- as.numeric(difftime(query_end_time, query_start_time, units = "secs"))
        geo_performance$total_documents <- sum(counts$n, na.rm = TRUE)
        geo_performance$states_with_data <- nrow(counts[counts$n > 0, ])
        geo_performance$memory_used_mb <- as.numeric(object.size(ls())) / 1024 / 1024 - memory_before
      }

    # Guarantee counts has estado + n columns
    # Use 2-letter codes (sigla) not full names, since database uses abbreviations
    if (!("estado" %in% names(counts) && "n" %in% names(counts))) {
      if (!is.null(shp) && "sigla" %in% names(shp)) {
        counts <- data.frame(estado = shp$sigla, n = 0)
      } else {
        # Ultimate fallback with all Brazilian state codes
        counts <- data.frame(
          estado = c("AC","AL","AM","AP","BA","CE","DF","ES","GO","MA","MT","MS","MG",
                    "PA","PB","PR","PE","PI","RJ","RN","RS","RO","RR","SC","SE","SP","TO"),
          n = 0
        )
      }
    }

      # Use leafletProxy to update the existing map
      incProgress(0.2, detail = "Mesclando dados geográficos")
      if (!is.null(shp) && "sigla" %in% names(shp)) {
        # CRITICAL FIX: Merge on 'sigla' (2-letter codes like "SP") not 'name' (full names)
        # Database stores estado as abbreviations (SP, RJ, MG), GeoJSON has both 'name' and 'sigla'
        shp_merged <- merge(shp, counts, by.x = "sigla", by.y = "estado", all.x = TRUE)
        shp_merged$n[is.na(shp_merged$n)] <- 0
        # Ensure n is numeric (fix for max() returning wrong value)
        shp_merged$n <- as.numeric(shp_merged$n)

        # Store for export functionality (PRD 4.3 - P1 High)
        current_map_data(shp_merged)

        cat("Merge result - rows:", nrow(shp_merged), "| n range:", min(shp_merged$n), "-", max(shp_merged$n), "\n")
        cat("Document counts by state:\n")
        print(data.frame(estado = shp_merged$sigla, documentos = shp_merged$n))

        # Create palette with better gradient visualization
        # Use colorBin with quantile breaks for better visual differentiation
        incProgress(0.2, detail = "Criando paleta de cores")
        n_values <- shp_merged$n
        max_n <- max(n_values, na.rm = TRUE)

        # Create intelligent breaks for the color bins
        if (max_n == 0) {
          # All zeros - use single color
          pal <- colorBin("YlOrRd", domain = c(0, 1), bins = c(0, 0.5, 1))
        } else if (max_n <= 10) {
          # Few documents - use simple breaks
          pal <- colorBin("YlOrRd", domain = c(0, max_n), bins = 5)
        } else {
          # Use quantile-based breaks for good visual distribution
          # This ensures each color bin represents roughly equal number of observations
          breaks <- unique(quantile(n_values[n_values > 0], probs = seq(0, 1, 0.2), na.rm = TRUE))
          breaks <- c(0, breaks)
          pal <- colorBin("YlOrRd", domain = c(0, max_n), bins = breaks)
        }

        cat("Color palette created with", length(pal), "breaks\n")

        incProgress(0.2, detail = "Renderizando mapa")
        leafletProxy("geo_map") %>%
          clearShapes() %>%
          clearControls() %>%
          addPolygons(
            data = shp_merged,
            fillColor = ~pal(n),
            color = "#444",
            weight = 1,
            fillOpacity = 0.7,
            label = ~paste0(name, ": ", n, " documentos")
          ) %>%
          addLegend(
            "bottomright",
            pal = pal,
            values = n_values,
            title = "Nº Documentos",
            opacity = 1
          )
      } else {
      # Fallback simple centroid markers
      centroids <- data.frame(
        uf = c("AC","AL","AM","AP","BA","CE","DF","ES","GO","MA","MT","MS","MG","PA","PB","PR","PE","PI","RJ","RN","RS","RO","RR","SC","SE","SP","TO"),
        lat = c(-9.02,-9.62,-3.47,1.41,-12.96,-5.20,-15.78,-19.19,-15.83,-4.96,-12.64,-20.44,-18.10,-4.43,-7.06,-25.25,-8.28,-6.60,-22.84,-5.81,-30.00,-11.22,1.99,-27.33,-10.57,-23.55,-10.25),
        lng = c(-70.81,-36.82,-65.10,-51.77,-38.51,-39.30,-47.93,-40.34,-47.86,-45.27,-55.42,-54.65,-44.38,-52.48,-35.55,-52.02,-35.01,-42.28,-43.15,-36.59,-53.00,-63.02,-61.33,-50.50,-37.07,-46.63,-48.25)
      )
      if (nrow(counts) > 0) {
        centroids <- merge(centroids, counts, by.x = "uf", by.y = "estado", all.x = TRUE)
      }
      if (!"n" %in% names(centroids)) centroids$n <- 0
      centroids$n[is.na(centroids$n)] <- 0
      pal <- colorNumeric("YlOrRd", domain = centroids$n)

      leafletProxy("geo_map") %>%
        clearMarkers() %>%
        clearControls() %>%
        addCircleMarkers(data = centroids, ~lng, ~lat,
          radius = ~pmax(4, sqrt(n))*2,
          color = ~pal(n), stroke = FALSE, fillOpacity = 0.7,
          label = ~paste0(uf, ": ", n, " documentos")) %>%
        addLegend("bottomright", pal = pal, values = centroids$n,
          title = "Nº Documentos", opacity = 1)
    }
    }) # Close withProgress
  })

  # Force Geographic map to bind to reactive graph even when tab is hidden
  outputOptions(output, "geo_map", suspendWhenHidden = FALSE)

  # Quick Win #1: State Ranking Table
  output$geo_state_ranking <- DT::renderDataTable({
    req(current_map_data())

    tryCatch({
      map_data <- current_map_data()

      # Create ranking from map data
      ranking_data <- data.frame(
        Estado = map_data$name,
        Sigla = map_data$sigla,
        Documentos = map_data$n,
        stringsAsFactors = FALSE
      )

      # Sort by document count descending
      ranking_data <- ranking_data[order(-ranking_data$Documentos), ]

      # Only show states with data
      ranking_data <- ranking_data[ranking_data$Documentos > 0, ]

      DT::datatable(
        ranking_data,
        options = list(
          pageLength = 10,
          dom = 'tp',  # Only table and pagination
          ordering = FALSE,  # Already ordered
          searching = FALSE,
          scrollY = "400px",
          scrollCollapse = TRUE
        ),
        rownames = FALSE,
        class = 'compact stripe'
      ) %>%
        DT::formatStyle('Documentos',
                       background = DT::styleColorBar(range(ranking_data$Documentos), '#FFA07A'),
                       backgroundSize = '100% 90%',
                       backgroundRepeat = 'no-repeat',
                       backgroundPosition = 'center')
    }, error = function(e) {
      DT::datatable(data.frame(Info = "Clique em 'Aplicar Filtros' para ver o ranking"),
                   options = list(dom = 't'), rownames = FALSE)
    })
  })

  # Quick Win #2: Summary Statistics Panel
  output$geo_summary_stats <- renderUI({
    req(current_map_data())

    tryCatch({
      total_docs <- geo_performance$total_documents
      states_with_data <- geo_performance$states_with_data

      # Get date range from filters if available
      date_info <- if (!is.null(geo_filters$date_start) && !is.null(geo_filters$date_end)) {
        paste(format(geo_filters$date_start, "%d/%m/%Y"), "a",
              format(geo_filters$date_end, "%d/%m/%Y"))
      } else {
        "Todos os períodos"
      }

      # Get document type filter
      tipo_info <- if (geo_filters$tipo != "Todos") {
        geo_filters$tipo
      } else {
        "Todos os tipos"
      }

      tagList(
        tags$div(style = "padding: 10px; background: #f8f9fa; border-radius: 5px;",
          tags$p(style = "margin: 5px 0;",
            tags$strong("Total de Documentos: "),
            tags$span(style = "color: #007bff;", format(total_docs, big.mark = "."))
          ),
          tags$p(style = "margin: 5px 0;",
            tags$strong("Estados com Dados: "),
            tags$span(style = "color: #28a745;", paste0(states_with_data, " / 27"))
          ),
          tags$p(style = "margin: 5px 0;",
            tags$strong("Período: "),
            tags$span(style = "color: #6c757d;", date_info)
          ),
          tags$p(style = "margin: 5px 0;",
            tags$strong("Tipo de Documento: "),
            tags$span(style = "color: #6c757d;", tipo_info)
          )
        )
      )
    }, error = function(e) {
      tags$p("Aguardando dados...")
    })
  })

  # Quick Win #6: Performance Metrics Panel
  output$geo_performance_metrics <- renderUI({
    req(geo_performance$query_time)

    tryCatch({
      query_time <- geo_performance$query_time
      memory_used <- geo_performance$memory_used_mb

      query_color <- if (query_time < 1) "#28a745" else if (query_time < 3) "#ffc107" else "#dc3545"

      HTML(paste0(
        "<div style='padding: 5px;'>",
        "<p style='margin: 3px 0;'><strong>Tempo de Consulta:</strong> ",
        "<span style='color: ", query_color, ";'>",
        sprintf("%.2f", query_time), " segundos</span></p>",
        "<p style='margin: 3px 0;'><strong>Memória Utilizada:</strong> ",
        sprintf("%.1f", abs(memory_used)), " MB</p>",
        "<p style='margin: 3px 0; font-size: 11px; color: #999;'>",
        "Atualizado: ", format(Sys.time(), "%H:%M:%S"), "</p>",
        "</div>"
      ))
    }, error = function(e) {
      HTML("<p>Aguardando métricas...</p>")
    })
  })

  # -- ANALYTICS SERVER LOGIC --

  analytics_data <- reactive({
    if (!DB_AVAILABLE) return(NULL)

    tryCatch({
      list(
        by_type = dbGetQuery(secure_db_connection,
          "SELECT tipo AS type, COUNT(*) AS n FROM documents GROUP BY tipo ORDER BY n DESC"),
        by_month = dbGetQuery(secure_db_connection,
          "SELECT DATE_TRUNC('month', data) AS month, COUNT(*) AS n
             FROM documents
             GROUP BY month
             ORDER BY month")
      )
    }, error = function(e) NULL)
  })

  output$analytics_type_bar <- renderPlot({
    dat <- analytics_data()
    if (is.null(dat)) return()
    ggplot(dat$by_type, aes(x = reorder(type, n), y = n)) +
      geom_col(fill = "steelblue") +
      coord_flip() +
      labs(x = "Tipo", y = "Quantidade de Documentos", title = "Documentos por Tipo") +
      theme_minimal()
  })

  output$analytics_month_line <- renderPlot({
    dat <- analytics_data()
    if (is.null(dat)) return()
    ggplot(dat$by_month, aes(x = as.Date(month), y = n)) +
      geom_line(color = "firebrick", size = 1) +
      geom_point(color = "firebrick") +
      labs(x = "Mês", y = "Quantidade", title = "Documentos por Mês") +
      theme_minimal()
  })

  # -- PERFORMANCE MONITORING SERVER --
  # Performance monitoring uses the global secure_db_connection
  performanceMonitoringServer(
    "perf_monitor",
    db_connection = reactive({ secure_db_connection })
  )

  # Note: Database connection is NOT closed per-session because it's a GLOBAL connection
  # shared across all users. Cloud Run will terminate the container when inactive,
  # which will automatically clean up the connection. Closing it on session end would
  # break the connection for other active users.
}

# ==============================================================================
# 5. RUN APPLICATION
# ==============================================================================
shinyApp(ui = ui, server = server)
