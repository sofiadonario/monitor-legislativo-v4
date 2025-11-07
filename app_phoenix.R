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
  library(data.table)
  library(plotly)
})

# ==============================================================================
# 1.5 LOAD UTILITY FUNCTIONS AND MODULES
# ==============================================================================

# Load scalar safety utilities (required by transport corridor module)
if (file.exists("R/utils/scalar_utils.R")) {
  source("R/utils/scalar_utils.R")
  cat("✅ Scalar utility functions loaded\n")
} else {
  cat("⚠️ Scalar utility functions not found\n")
}

# Load enhanced geographic module
if (file.exists("modules/geographic_enhanced.R")) {
  source("modules/geographic_enhanced.R")
  cat("✅ Enhanced Geographic Module loaded\n")
} else {
  cat("⚠️ Enhanced Geographic Module not found - using basic features\n")
}

# Load transport corridor module
if (file.exists("modules/maps/transport_corridor_analysis.R")) {
  source("modules/maps/transport_corridor_analysis.R")
  cat("✅ Transport Corridor Analysis Module loaded\n")
} else {
  cat("⚠️ Transport Corridor Analysis Module not found\n")
}

# Load Brazilian geo integration (geocoding functions)
if (file.exists("R/visualization/brazilian_geo_integration.R")) {
  source("R/visualization/brazilian_geo_integration.R")
  cat("✅ Brazilian Geo Integration (Geocoding) loaded\n")
} else {
  cat("⚠️ Brazilian Geo Integration not found\n")
}

# ==============================================================================
# 2. DATABASE CONNECTION LOGIC (PROVEN & STABLE)
# ==============================================================================
# Global connection object
secure_db_connection <- NULL
DB_AVAILABLE <- FALSE

# Data extraction date from raw data files (./data_current/README.md)
DATA_EXTRACTION_DATE <- as.Date("2025-10-21")

get_database_config <- function() {
  # Method 1: PRIORITIZE Google Cloud Run Unix Socket
  is_in_cloud_run <- !is.na(Sys.getenv("K_SERVICE", unset = NA))
  if (is_in_cloud_run) {
    cat("✅ Detected Google Cloud Run environment\n")
    return(list(
      host = paste("/cloudsql", "mackmonitor:southamerica-east1:mackmonitor-db", sep = "/"),
      port = 5432,
      dbname = Sys.getenv("PGDATABASE", "mackmonitor-db"),
      user = Sys.getenv("PGUSER", "monitor_user"),
      password = Sys.getenv("PGPASSWORD", "")
    ))
  }
  
  # Method 2: Fallback to environment variables for local development
  cat("📋 Local environment detected. Using PGHOST/PGUSER...\n")
  
  # Read database config with proper defaults that match your .Renviron
  return(list(
    host = Sys.getenv("PGHOST", "34.39.228.246"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE", "mackmonitor-db"),
    user = Sys.getenv("PGUSER", "monitor_user"),
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

# Check which table name to use
DOCUMENTS_TABLE <- "lexml_documents"  # Default to lexml_documents
if (DB_AVAILABLE) {
  tables <- tryCatch(
    dbListTables(secure_db_connection),
    error = function(e) character(0)
  )
  
  if ("documents" %in% tables) {
    DOCUMENTS_TABLE <- "documents"
    cat("✅ Using 'documents' table\n")
  } else if ("lexml_documents" %in% tables) {
    DOCUMENTS_TABLE <- "lexml_documents"
    cat("✅ Using 'lexml_documents' table\n")
  } else {
    cat("⚠️ Warning: Neither 'documents' nor 'lexml_documents' table found\n")
    cat("   Available tables:", paste(tables, collapse = ", "), "\n")
  }
}

# Display connection status
if (DB_AVAILABLE) {
  cat("✅ Database connected successfully\n")
} else {
  cat("⚠️ Database not connected. Documents will not be available.\n")
  cat("   To configure database, set these environment variables:\n")
  cat("   PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD\n")
  cat("   Or run: source('setup_local_env.R')\n")
}

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

  # -- GEOGRAPHIC TAB (ENHANCED) --
  tabPanel(
    "Geographic",
    icon = icon("map-marked-alt"),
    fluidPage(
      h1("Geographic Visualization - Enhanced"),
      p("Visualização geográfica avançada de documentos legislativos com múltiplos níveis e modos"),
      div(
        style = "background-color: #f0f8ff; padding: 10px; border-radius: 5px; margin-bottom: 15px;",
        icon("info-circle"),
        strong(" Nota:"),
        " Base de dados atualizada em ",
        strong("21/10/2025"),
        " (data de extração dos dados brutos). ",
        em("Agora com visualização por município e múltiplos modos de análise!")
      ),
      hr(),

      # -- Enhanced Controls Row 1: Visualization Settings --
      wellPanel(
        style = "background-color: #f8f9fa;",
        h4(icon("sliders-h"), " Configurações de Visualização"),
        fluidRow(
          column(3,
            selectInput("geo_analysis_type", "Tipo de Análise:",
                       choices = c(
                         "Análise Geográfica Padrão" = "standard",
                         "Corredores de Transporte" = "transport"
                       ),
                       selected = "standard")
          ),
          column(3,
            conditionalPanel(
              condition = "input.geo_analysis_type == 'standard'",
              selectInput("geo_viz_mode", "Modo de Visualização:",
                         choices = c(
                           "Total de Documentos" = "absolute",
                           "Docs por 100k Habitantes" = "per_capita",
                           "Docs por km²" = "density",
                           "Atividade Recente" = "temporal"
                         ),
                         selected = "absolute")
            )
          ),
          column(3,
            conditionalPanel(
              condition = "input.geo_analysis_type == 'standard'",
              selectInput("geo_viz_level", "Nível Geográfico:",
                         choices = c(
                           "Estados" = "state",
                           "Municípios (Todos 5,570)" = "municipality"
                         ),
                         selected = "state")
            )
          ),
          column(3,
            conditionalPanel(
              condition = "input.geo_analysis_type == 'standard' && input.geo_viz_mode == 'temporal'",
              checkboxInput("geo_enable_animation",
                           "Ativar Animação Temporal",
                           value = FALSE)
            )
          ),
          column(3,
            div(
              style = "margin-top: 25px;",
              p(
                style = "font-size: 13px; color: #666; margin: 0;",
                icon("lightbulb"),
                strong(" Dica:"),
                " Use 'temporal' + animação para ver mudanças ao longo do tempo."
              )
            )
          )
        )
      ),

      # -- Enhanced Controls Row 2: Data Filters --
      wellPanel(
        style = "background-color: #ffffff;",
        h4(icon("filter"), " Filtros de Dados"),
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
                          start = NULL, end = DATA_EXTRACTION_DATE,
                          format = "dd/mm/yyyy",
                          language = "pt-BR",
                          separator = " até ")
          ),
          column(3,
            div(style = "margin-top: 25px;",
              actionButton("geo_apply", "Aplicar Filtros",
                          class = "btn-primary",
                          icon = icon("check")),
              actionButton("geo_clear", "Limpar",
                          class = "btn-secondary",
                          icon = icon("times"),
                          style = "margin-left: 10px;")
            )
          ),
          column(2,
            div(
              style = "margin-top: 25px;",
              textOutput("geo_stats_summary", inline = TRUE)
            )
          )
        )
      ),

      # -- Temporal Animation Controls (shown when animation enabled) --
      conditionalPanel(
        condition = "input.geo_enable_animation == true && input.geo_viz_mode == 'temporal'",
        wellPanel(
          style = "background-color: #e8f4f8;",
          h4(icon("film"), " Controles de Animação Temporal"),
          fluidRow(
            column(4,
              sliderInput("geo_animation_year",
                         "Ano de Visualização:",
                         min = 2000,
                         max = as.numeric(format(Sys.Date(), "%Y")),
                         value = as.numeric(format(Sys.Date(), "%Y")) - 5,
                         step = 1,
                         animate = animationOptions(interval = 1000, loop = TRUE),
                         sep = "")
            ),
            column(4,
              selectInput("geo_animation_period",
                         "Período de Agregação:",
                         choices = c(
                           "Anual" = "year",
                           "Trimestral" = "quarter",
                           "Mensal" = "month"
                         ),
                         selected = "year")
            ),
            column(4,
              div(style = "margin-top: 25px;",
                p(style = "font-size: 13px; color: #666;",
                  icon("play-circle"),
                  " Use o controle deslizante ou clique em ▶ para animar"
                )
              )
            )
          )
        )
      ),

      # -- Enhanced Controls Row 3: Export Options --
      wellPanel(
        style = "background-color: #f8f9fa;",
        h4(icon("download"), " Opções de Exportação"),
        fluidRow(
          column(12,
            div(
              style = "display: flex; gap: 10px; flex-wrap: wrap;",
              downloadButton("geo_download_csv", "CSV",
                           class = "btn-success btn-sm",
                           icon = icon("file-csv")),
              downloadButton("geo_download_geojson", "GeoJSON",
                           class = "btn-success btn-sm",
                           icon = icon("map")),
              downloadButton("geo_download_png", "PNG",
                           class = "btn-info btn-sm",
                           icon = icon("image")),
              downloadButton("geo_download_svg", "SVG",
                           class = "btn-info btn-sm",
                           icon = icon("vector-square")),
              downloadButton("geo_download_pdf", "PDF",
                           class = "btn-info btn-sm",
                           icon = icon("file-pdf")),
              tags$small(
                style = "align-self: center; color: #666; margin-left: 10px;",
                "Exportações incluem dados filtrados e metadados"
              )
            )
          )
        )
      ),

      hr(),

      # -- Transport Corridor Controls (shown when transport analysis selected) --
      conditionalPanel(
        condition = "input.geo_analysis_type == 'transport'",
        transportCorridorUI("transport_corridor")
      ),

      # -- Standard Geographic Map (shown when standard analysis selected) --
      conditionalPanel(
        condition = "input.geo_analysis_type == 'standard'",
        # -- Map Display with Loading Indicator --
        div(
          style = "position: relative;",
          uiOutput("geo_loading_indicator"),
          leaflet::leafletOutput("geo_map", height = "650px")
        )
      ),

      # -- Statistics Panel (shown only for standard analysis) --
      conditionalPanel(
        condition = "input.geo_analysis_type == 'standard'",
        hr(),
        wellPanel(
          style = "background-color: #f8f9fa; margin-top: 15px;",
          h4(icon("chart-bar"), " Estatísticas da Visualização"),
          fluidRow(
            column(3,
              div(
                style = "text-align: center; padding: 10px;",
                h3(textOutput("geo_stat_features", inline = TRUE),
                   style = "color: #1e3a8a; margin: 0;"),
                p("Unidades Geográficas", style = "margin: 5px 0 0 0; color: #666; font-size: 13px;")
              )
            ),
            column(3,
              div(
                style = "text-align: center; padding: 10px;",
                h3(textOutput("geo_stat_documents", inline = TRUE),
                   style = "color: #059669; margin: 0;"),
                p("Total de Documentos", style = "margin: 5px 0 0 0; color: #666; font-size: 13px;")
              )
            ),
            column(3,
              div(
                style = "text-align: center; padding: 10px;",
                h3(textOutput("geo_stat_avg", inline = TRUE),
                   style = "color: #dc2626; margin: 0;"),
                p("Média por Unidade", style = "margin: 5px 0 0 0; color: #666; font-size: 13px;")
              )
            ),
            column(3,
              div(
                style = "text-align: center; padding: 10px;",
                h3(textOutput("geo_stat_range", inline = TRUE),
                   style = "color: #ca8a04; margin: 0;"),
                p("Período dos Dados", style = "margin: 5px 0 0 0; color: #666; font-size: 13px;")
              )
            )
          ),
          hr(),
          fluidRow(
            column(12,
              div(
                style = "background-color: #f0f9ff; padding: 15px; border-left: 4px solid #3b82f6; margin-top: 10px;",
                h5(icon("map-pin"), " Informação sobre Geocodificação", style = "margin-top: 0; color: #1e40af;"),
                p(
                  style = "margin-bottom: 5px; font-size: 14px;",
                  "O sistema inclui capacidade de geocodificação baseada em texto para documentos legislativos."
                ),
                p(
                  style = "margin-bottom: 0; font-size: 13px; color: #666;",
                  icon("check-circle", style = "color: #059669;"),
                  " Detecção automática de estados e municípios brasileiros no texto dos documentos",
                  br(),
                  icon("check-circle", style = "color: #059669;"),
                  " Atribuição de coordenadas geográficas e códigos IBGE",
                  br(),
                  icon("info-circle", style = "color: #3b82f6;"),
                  " Para ativar a geocodificação em lote, consulte a documentação técnica"
                )
              )
            )
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
  tabPanel("Text Mining", h1("Text Mining"), p("This section is under development."))
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
      return(data.frame(
        Message = c("Database connection not available", 
                   "To configure the database:",
                   "1. Set environment variables: PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD",
                   "2. Or run: source('setup_local_env.R')",
                   "3. Then restart the application")
      ))
    }

    # Get current filter values from our reactiveValues
    # Read ALL reactive values to establish dependencies on any change
    current_search <- filters$search
    current_tipo <- filters$tipo
    current_mostrar <- as.numeric(filters$mostrar)
    current_trigger <- filters$trigger  # Read trigger last to establish dependency

    # Start with the base query using the detected table
    query <- paste("SELECT id, titulo, tipo, data FROM", DOCUMENTS_TABLE)

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
      total_result <- dbGetQuery(secure_db_connection, paste("SELECT COUNT(*) as total FROM", DOCUMENTS_TABLE))
      types_result <- dbGetQuery(secure_db_connection, paste("SELECT COUNT(DISTINCT tipo) as count FROM", DOCUMENTS_TABLE))
      latest_result <- dbGetQuery(secure_db_connection, paste("SELECT MAX(data) as latest FROM", DOCUMENTS_TABLE))
      oldest_result <- dbGetQuery(secure_db_connection, paste("SELECT MIN(data) as oldest FROM", DOCUMENTS_TABLE))

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
      query <- paste0(
        "SELECT tipo AS \"Document Type\", ",
        "COUNT(*) as \"Count\", ",
        "ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM ", DOCUMENTS_TABLE, "), 2) as \"Percentage\" ",
        "FROM ", DOCUMENTS_TABLE, " ",
        "GROUP BY tipo ",
        "ORDER BY COUNT(*) DESC"
      )
      dbGetQuery(secure_db_connection, query)
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
      query <- paste0(
        "SELECT tipo AS \"Type\", ",
        "data AS \"Date\", ",
        "LEFT(titulo, 50) || '...' AS \"Title\" ",
        "FROM ", DOCUMENTS_TABLE, " ",
        "ORDER BY data DESC ",
        "LIMIT 10"
      )
      result <- dbGetQuery(secure_db_connection, query)

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

  # ===========================================================================
  # -- ENHANCED GEOGRAPHIC SERVER LOGIC --
  # ===========================================================================

  # Reactive values for Geographic filters and settings
  geo_filters <- reactiveValues(
    tipo = "Todos",
    date_start = NULL,
    date_end = NULL,
    viz_mode = "absolute",
    viz_level = "state",
    trigger = 1
  )

  # Store current map data and statistics for export
  current_map_data <- reactiveVal(NULL)
  current_viz_stats <- reactiveVal(NULL)

  # Apply button observer - captures all filter and visualization settings
  observeEvent(input$geo_apply, {
    geo_filters$tipo <- input$geo_filter_tipo
    geo_filters$date_start <- input$geo_date_range[1]
    geo_filters$date_end <- input$geo_date_range[2]
    geo_filters$viz_mode <- input$geo_viz_mode
    geo_filters$viz_level <- input$geo_viz_level
    geo_filters$trigger <- geo_filters$trigger + 1

    showNotification("Atualizando visualização...", type = "message", duration = 2)
  })

  # Clear button observer
  observeEvent(input$geo_clear, {
    updateSelectInput(session, "geo_filter_tipo", selected = "Todos")
    updateDateRangeInput(session, "geo_date_range", start = NULL, end = NULL)
    updateSelectInput(session, "geo_viz_mode", selected = "absolute")
    updateSelectInput(session, "geo_viz_level", selected = "state")

    geo_filters$tipo <- "Todos"
    geo_filters$date_start <- NULL
    geo_filters$date_end <- NULL
    geo_filters$viz_mode <- "absolute"
    geo_filters$viz_level <- "state"
    geo_filters$trigger <- geo_filters$trigger + 1

    showNotification("Filtros limpos", type = "message", duration = 2)
  })

  # ===========================================================================
  # -- TRANSPORT CORRIDOR INTEGRATION --
  # ===========================================================================

  # Reactive data source for transport corridors
  transport_legislative_data <- reactive({
    if (!DB_AVAILABLE) {
      return(data.frame())
    }

    tryCatch({
      # Query legislative documents with geographic data
      query <- paste("
        SELECT
          id, titulo as title, tipo as type, data as date,
          estado as state, municipio,
          CAST(latitude AS NUMERIC) as lat,
          CAST(longitude AS NUMERIC) as lng
        FROM", DOCUMENTS_TABLE, "
        WHERE latitude IS NOT NULL
          AND longitude IS NOT NULL
        ORDER BY data DESC
        LIMIT 10000
      ")

      result <- dbGetQuery(secure_db_connection, query)
      cat("✅ Loaded", nrow(result), "documents for transport corridor analysis\n")
      return(result)
    }, error = function(e) {
      cat("❌ Error loading transport corridor data:", e$message, "\n")
      return(data.frame())
    })
  })

  # Call the transport corridor server module
  transportCorridorServer("transport_corridor", legislative_data = transport_legislative_data)

  # Auto-update when visualization settings change
  observeEvent(input$geo_viz_mode, {
    if (geo_filters$trigger > 1) {  # Skip initial load
      geo_filters$viz_mode <- input$geo_viz_mode
      geo_filters$trigger <- geo_filters$trigger + 1
    }
  }, ignoreInit = TRUE)

  observeEvent(input$geo_viz_level, {
    if (geo_filters$trigger > 1) {  # Skip initial load
      geo_filters$viz_level <- input$geo_viz_level
      geo_filters$trigger <- geo_filters$trigger + 1
    }
  }, ignoreInit = TRUE)

  # ===========================================================================
  # -- ENHANCED EXPORT HANDLERS --
  # ===========================================================================

  # CSV export handler
  output$geo_download_csv <- downloadHandler(
    filename = function() {
      paste0("geographic_data_", geo_filters$viz_level, "_", format(Sys.Date(), "%Y%m%d"), ".csv")
    },
    content = function(file) {
      data <- current_map_data()
      result <- export_geographic_data(data, format = "CSV", filename = basename(file))

      if (result$success && file.exists(result$file_path)) {
        file.copy(result$file_path, file, overwrite = TRUE)
      } else {
        write.csv(data.frame(Error = result$error %||% "Export failed"), file, row.names = FALSE)
      }
    }
  )

  # GeoJSON export handler
  output$geo_download_geojson <- downloadHandler(
    filename = function() {
      paste0("geographic_data_", geo_filters$viz_level, "_", format(Sys.Date(), "%Y%m%d"), ".geojson")
    },
    content = function(file) {
      data <- current_map_data()
      result <- export_geographic_data(data, format = "GeoJSON", filename = basename(file))

      if (result$success && file.exists(result$file_path)) {
        file.copy(result$file_path, file, overwrite = TRUE)
      } else {
        writeLines(paste("Error:", result$error %||% "No geographic data available"), file)
      }
    }
  )

  # PNG map export handler
  output$geo_download_png <- downloadHandler(
    filename = function() {
      paste0("geographic_map_", format(Sys.Date(), "%Y%m%d"), ".png")
    },
    content = function(file) {
      map_data <- current_map_data()

      if (is.null(map_data) || nrow(map_data) == 0) {
        p <- ggplot() +
          annotate("text", x = 0, y = 0,
                   label = "No data available\nApply filters first",
                   size = 6) +
          theme_void()
        ggsave(file, plot = p, width = 10, height = 8, dpi = 300, bg = "white")
        return()
      }

      tryCatch({
        if (!inherits(map_data, "sf")) {
          map_data <- sf::st_as_sf(map_data)
        }

        value_col <- switch(geo_filters$viz_mode,
          "absolute" = "document_count",
          "per_capita" = "docs_per_capita",
          "density" = "docs_per_km2",
          "temporal" = "recent_docs_pct",
          "document_count"
        )

        if (!value_col %in% names(map_data)) {
          value_col <- "document_count"
        }

        values <- map_data[[value_col]]
        values <- values[!is.na(values) & is.finite(values)]
        max_val <- max(values, na.rm = TRUE)

        p <- ggplot(data = map_data) +
          geom_sf(aes(fill = get(value_col)), color = "#444444", size = 0.3) +
          scale_fill_gradient(
            low = "#fff5eb",
            high = "#d62728",
            name = switch(geo_filters$viz_mode,
              "absolute" = "Documents",
              "per_capita" = "Docs/100k",
              "density" = "Docs/km²",
              "temporal" = "Recent %",
              "Documents"
            ),
            breaks = if(max_val > 0) pretty(c(0, max_val), n = 5) else c(0, 1),
            limits = c(0, max(max_val, 1))
          ) +
          labs(
            title = "Geographic Distribution of Legislative Documents",
            subtitle = paste("Data updated:", format(DATA_EXTRACTION_DATE, "%d/%m/%Y")),
            caption = "Source: Monitor Legislativo"
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

        ggsave(file, plot = p, width = 12, height = 10, dpi = 300, bg = "white")

      }, error = function(e) {
        p <- ggplot() +
          annotate("text", x = 0, y = 0,
                   label = paste("Export error:", e$message),
                   size = 6, color = "red") +
          theme_void()
        ggsave(file, plot = p, width = 10, height = 8, dpi = 300, bg = "white")
      })
    }
  )

  # SVG and PDF export handlers (placeholders for now - similar to PNG)
  output$geo_download_svg <- downloadHandler(
    filename = function() {
      paste0("geographic_map_", format(Sys.Date(), "%Y%m%d"), ".svg")
    },
    content = function(file) {
      showNotification("SVG export coming soon! Using PNG format.", type = "warning", duration = 3)
      # For now, redirect to PNG export
      file_png <- tempfile(fileext = ".png")
      output$geo_download_png$contentType
      output$geo_download_png$content(file_png)
      file.copy(file_png, file, overwrite = TRUE)
    }
  )

  output$geo_download_pdf <- downloadHandler(
    filename = function() {
      paste0("geographic_map_", format(Sys.Date(), "%Y%m%d"), ".pdf")
    },
    content = function(file) {
      showNotification("PDF export coming soon! Using PNG format.", type = "warning", duration = 3)
      file_png <- tempfile(fileext = ".png")
      output$geo_download_png$content(file_png)
      file.copy(file_png, file, overwrite = TRUE)
    }
  )

  # ===========================================================================
  # -- ENHANCED MAP RENDERING LOGIC --
  # ===========================================================================

  # Reactive expression for loading and processing geographic data
  enhanced_geo_data <- reactive({
    # Establish dependencies
    current_trigger <- geo_filters$trigger
    current_tipo <- geo_filters$tipo
    current_date_start <- geo_filters$date_start
    current_date_end <- geo_filters$date_end
    current_mode <- geo_filters$viz_mode
    current_level <- geo_filters$viz_level

    # Animation dependencies
    animation_enabled <- isTRUE(input$geo_enable_animation)
    animation_year <- if(animation_enabled) input$geo_animation_year else NULL
    animation_period <- if(animation_enabled) input$geo_animation_period else NULL

    cat("\n=== LOADING ENHANCED GEOGRAPHIC DATA ===\n")
    cat("Level:", current_level, "| Mode:", current_mode, "| Filter:", current_tipo, "\n")
    if (animation_enabled) {
      cat("Animation: ENABLED | Year:", animation_year, "| Period:", animation_period, "\n")
    }

    if (!DB_AVAILABLE) {
      cat("⚠️ Database not available\n")
      return(NULL)
    }

    # Build filters list
    filters <- list()
    if (current_tipo != "Todos") {
      filters$tipo <- current_tipo
    }

    # Apply temporal animation filter if enabled
    if (animation_enabled && !is.null(animation_year)) {
      if (animation_period == "year") {
        filters$date_start <- as.Date(paste0(animation_year, "-01-01"))
        filters$date_end <- as.Date(paste0(animation_year, "-12-31"))
      } else if (animation_period == "quarter") {
        # For now, show full year - can be enhanced later
        filters$date_start <- as.Date(paste0(animation_year, "-01-01"))
        filters$date_end <- as.Date(paste0(animation_year, "-12-31"))
      } else if (animation_period == "month") {
        # For now, show full year - can be enhanced later
        filters$date_start <- as.Date(paste0(animation_year, "-01-01"))
        filters$date_end <- as.Date(paste0(animation_year, "-12-31"))
      }
    } else if (!is.null(current_date_start) && !is.null(current_date_end)) {
      filters$date_start <- current_date_start
      filters$date_end <- current_date_end
    }

    # Load data using enhanced module
    tryCatch({
      data <- load_enhanced_geographic_data(
        db_conn = secure_db_connection,
        level = current_level,
        filters = filters,
        include_geometry = TRUE
      )

      if (!is.null(data) && nrow(data) > 0) {
        cat("✅ Loaded", nrow(data), "geographic features\n")

        # Calculate and store statistics
        stats <- calculate_viz_statistics(data)
        current_viz_stats(stats)

        # Store data for export
        current_map_data(data)

        return(data)
      } else {
        cat("⚠️ No geographic data returned\n")
        return(NULL)
      }

    }, error = function(e) {
      cat("❌ Error loading geographic data:", e$message, "\n")
      return(NULL)
    })
  })

  # Render enhanced choropleth map using leaflet
  output$geo_map <- leaflet::renderLeaflet({
    cat("=== RENDERING ENHANCED GEOGRAPHIC MAP ===\n")

    # Get enhanced data
    data <- enhanced_geo_data()

    if (is.null(data)) {
      cat("⚠️ No data available - creating empty map\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -54, lat = -15, zoom = 4) %>%
        addMarkers(lng = -54, lat = -15,
                  popup = "No data available. Please check database connection and apply filters."))
    }

    # Get current visualization settings
    current_mode <- geo_filters$viz_mode
    current_level <- geo_filters$viz_level

    # Build filters for context
    filters <- list()
    if (geo_filters$tipo != "Todos") {
      filters$tipo <- geo_filters$tipo
    }

    # Create enhanced choropleth map
    tryCatch({
      map <- create_enhanced_choropleth(
        data = data,
        mode = current_mode,
        level = current_level,
        filters = filters
      )

      cat("✅ Enhanced map rendered successfully\n")
      return(map)

    }, error = function(e) {
      cat("❌ Error rendering map:", e$message, "\n")
      # Return basic map on error
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -54, lat = -15, zoom = 4) %>%
        addMarkers(lng = -54, lat = -15,
                  popup = paste("Error rendering map:", e$message)))
    })
  })

  # Statistics outputs
  output$geo_stat_features <- renderText({
    stats <- current_viz_stats()
    if (is.null(stats)) return("--")
    format(stats$total_features, big.mark = ",")
  })

  output$geo_stat_documents <- renderText({
    stats <- current_viz_stats()
    if (is.null(stats)) return("--")
    format(stats$total_documents, big.mark = ",")
  })

  output$geo_stat_avg <- renderText({
    stats <- current_viz_stats()
    if (is.null(stats)) return("--")
    format(round(stats$avg_documents, 1), big.mark = ",")
  })

  output$geo_stat_range <- renderText({
    stats <- current_viz_stats()
    if (is.null(stats) || is.null(stats$date_range)) return("--")
    stats$date_range
  })

  # Loading indicator
  output$geo_loading_indicator <- renderUI({
    data <- enhanced_geo_data()
    if (is.null(data)) {
      div(
        style = "position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 1000; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
        icon("spinner", class = "fa-spin fa-3x"),
        h4("Carregando dados geográficos...", style = "margin-top: 10px;")
      )
    } else {
      NULL
    }
  })

  # Force Geographic map to bind to reactive graph even when tab is hidden
  outputOptions(output, "geo_map", suspendWhenHidden = FALSE)

  # -- ANALYTICS SERVER LOGIC --

  analytics_data <- reactive({
    if (!DB_AVAILABLE) return(NULL)

    tryCatch({
      list(
        by_type = dbGetQuery(secure_db_connection,
          paste("SELECT tipo AS type, COUNT(*) AS n FROM", DOCUMENTS_TABLE, "GROUP BY tipo ORDER BY n DESC")),
        by_month = dbGetQuery(secure_db_connection,
          paste0("SELECT DATE_TRUNC('month', data) AS month, COUNT(*) AS n ",
                 "FROM ", DOCUMENTS_TABLE, " ",
                 "GROUP BY month ",
                 "ORDER BY month"))
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

  # Note: Database connection is NOT closed per-session because it's a GLOBAL connection
  # shared across all users. Cloud Run will terminate the container when inactive,
  # which will automatically clean up the connection. Closing it on session end would
  # break the connection for other active users.
}

# ==============================================================================
# 5. RUN APPLICATION
# ==============================================================================
shinyApp(ui = ui, server = server)
