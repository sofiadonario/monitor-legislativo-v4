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
          column(3, selectInput("library_tipo", "Tipo de Documento:", choices = c("Todos", "Lei", "Decreto", "Projeto de Lei"))),
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
# 4. SERVER LOGIC (STABLE & MONOLITHIC - v3 with State Machine)
# ==============================================================================
server <- function(input, output, session) {

  # -- LIBRARY SERVER LOGIC --
  
  # Use reactiveValues to store the state of the filters
  filters <- reactiveValues(
    search = "",
    tipo = "Todos",
    mostrar = 100
  )
  
  # When "Apply" is clicked, update the reactiveValues
  observeEvent(input$library_apply, {
    filters$search <- input$library_search
    filters$tipo <- input$library_tipo
    filters$mostrar <- as.numeric(input$library_mostrar)
  })

  # When "Clear" is clicked, reset the inputs and the reactiveValues
  observeEvent(input$library_clear, {
    updateTextInput(session, "library_search", value = "")
    updateSelectInput(session, "library_tipo", selected = "Todos")
    updateSelectInput(session, "library_mostrar", selected = 100)

    filters$search <- ""
    filters$tipo <- "Todos"
    filters$mostrar <- 100
  })

  # This is the core reactive expression for the library data.
  # It automatically re-executes whenever the 'filters' object changes.
  library_data <- reactive({
    req(DB_AVAILABLE)

    # Explicitly depend on all filter values to ensure reactivity
    current_search <- filters$search
    current_tipo <- filters$tipo
    current_mostrar <- filters$mostrar

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

  # Render the table with the data from our reactive expression
  output$library_table <- DT::renderDataTable({
    library_data()
  }, options = list(pageLength = 10, scrollX = TRUE))
  
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
