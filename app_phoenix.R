# ==============================================================================
# MONITOR LEGISLATIVO V4 - PHOENIX REBUILD
# ==============================================================================
# A rock-solid, monolithic app built for stability.
# This file contains the entire application.
# ==============================================================================

# ==============================================================================
# 1. LOAD PACKAGES
# ==============================================================================
suppressPackageStartupMessages({
  library(shiny)
  library(DBI)
  library(RPostgres)
  library(DT)
  library(leaflet)
  library(shinythemes)
})

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
  title = "Monitor Legislativo v4 (Phoenix)",
  theme = shinytheme("cerulean"), # A simple, safe theme

  # -- LIBRARY TAB --
  tabPanel(
    "Library",
    icon = icon("book"),
    fluidPage(
      h2(HTML("&#128218; Biblioteca de Documentos Legislativos")),
      p("Pesquise, filtre e explore a coleção completa de documentos legislativos brasileiros.",
        style = "color: #7f8c8d; margin-bottom: 30px;"),

      # Search and Filter Panel
      wellPanel(
        h4("Filtros de Pesquisa"),
        fluidRow(
          column(6, textInput("library_search", "Termo de Pesquisa:",
                              placeholder = "Ex: 'tributário' ou 'lei 14.133'")),
          column(3, selectInput("library_tipo", "Tipo de Documento:",
                               choices = c("Todos" = "", "Lei", "Decreto", "Portaria"))),
          column(3, selectInput("library_limit", "Mostrar:",
                               choices = c("50" = "50", "100" = "100", "250" = "250", "500" = "500"),
                               selected = "100"))
        ),
        fluidRow(
          column(12,
                 actionButton("library_apply", "Aplicar Filtros",
                             class = "btn-primary", icon = icon("search")),
                 actionButton("library_reset", "Limpar",
                             class = "btn-default", icon = icon("eraser"),
                             style = "margin-left: 10px;"))
        )
      ),

      # Results Display Panel
      wellPanel(
        h4("Resultados da Pesquisa"),
        DT::dataTableOutput("library_table")
      )
    )
  ),

  # -- GEOGRAPHIC TAB --
  tabPanel(
    "Geographic",
    icon = icon("map-marked-alt"),
    fluidPage(
      h1("Geographic Visualization"),
      p("A basic map to prove the concept of the visualization component."),
      hr(),
      leaflet::leafletOutput("geo_map", height = "600px")
    )
  ),

  # -- PLACEHOLDER TABS --
  tabPanel("Analytics", h1("Analytics"), p("This section is under development.")),
  tabPanel("Text Mining", h1("Text Mining"), p("This section is under development."))
)

# ==============================================================================
# 4. SERVER LOGIC (STABLE & MONOLITHIC)
# ==============================================================================
server <- function(input, output, session) {

  # -- LIBRARY SERVER LOGIC --

  # Reset filters
  observeEvent(input$library_reset, {
    updateTextInput(session, "library_search", value = "")
    updateSelectInput(session, "library_tipo", selected = "")
    updateSelectInput(session, "library_limit", selected = "100")
  })

  # Reactive value to trigger data reload
  library_trigger <- reactiveVal(0)

  # Trigger reload when apply button is clicked
  observeEvent(input$library_apply, {
    library_trigger(library_trigger() + 1)
  })

  # Load on startup
  observe({
    library_trigger(1)
  })

  # Reactive data fetching
  library_data <- eventReactive(library_trigger(), {
    req(DB_AVAILABLE)

    tryCatch({
      # Build SQL query with filters
      query <- "SELECT id, titulo, tipo, data, origem FROM legis_docs WHERE 1=1"

      # Add search filter if provided
      if (!is.null(input$library_search) && nzchar(input$library_search)) {
        search_term <- gsub("'", "''", input$library_search) # Escape single quotes
        query <- paste0(query, " AND titulo ILIKE '%", search_term, "%'")
      }

      # Add type filter if provided
      if (!is.null(input$library_tipo) && nzchar(input$library_tipo)) {
        tipo_term <- gsub("'", "''", input$library_tipo)
        query <- paste0(query, " AND tipo = '", tipo_term, "'")
      }

      # Add ordering and limit
      limit_val <- if (!is.null(input$library_limit)) input$library_limit else "100"
      query <- paste0(query, " ORDER BY data DESC LIMIT ", limit_val)

      cat("Executing query:", query, "\n")
      dbGetQuery(secure_db_connection, query)

    }, error = function(e) {
      cat("Query error:", e$message, "\n")
      data.frame(Erro = e$message)
    })
  })

  # Render the data table
  output$library_table <- DT::renderDataTable({
    library_data()
  }, options = list(
    pageLength = 25,
    scrollX = TRUE,
    dom = 'Bfrtip',
    language = list(
      search = "Buscar:",
      lengthMenu = "Mostrar _MENU_ registros por página",
      info = "Mostrando _START_ a _END_ de _TOTAL_ documentos",
      infoEmpty = "Nenhum documento encontrado",
      infoFiltered = "(filtrado de _MAX_ documentos no total)",
      paginate = list(
        first = "Primeiro",
        last = "Último",
        `next` = "Próximo",
        previous = "Anterior"
      )
    )
  ))

  # -- GEOGRAPHIC SERVER LOGIC --
  output$geo_map <- leaflet::renderLeaflet({
    leaflet() %>%
      addTiles() %>%
      setView(lng = -54, lat = -15, zoom = 4) %>%
      addMarkers(lng = -47.9292, lat = -15.7801, popup = "Brasília")
  })

  # Gracefully close the database connection when the app stops
  onSessionEnded(function() {
    if (DB_AVAILABLE) {
      dbDisconnect(secure_db_connection)
      cat("Database connection closed.\n")
    }
  })
}

# ==============================================================================
# 5. RUN APPLICATION
# ==============================================================================
shinyApp(ui = ui, server = server)
