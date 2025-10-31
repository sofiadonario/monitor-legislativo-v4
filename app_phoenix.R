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

  # -- LIBRARY SERVER LOGIC (REFACTORED TO BE MORE ROBUST) --

  # 1. A reactiveValues object to hold the current filter state.
  # This is the "single source of truth" for the query.
  filters <- reactiveValues(
    search = "",
    tipo = "Todos",
    mostrar = 100,
    trigger = 0  # Force reactive to execute on any change
  )

  # Force initial execution by changing trigger after session starts
  observe({
    filters$trigger <- filters$trigger + 1
  })

  # 2. Observer for the 'Apply' button.
  # This updates the reactiveValues, which in turn triggers the data query.
  observeEvent(input$library_apply, {
    filters$search <- input$library_search
    filters$tipo <- input$library_tipo
    filters$mostrar <- as.numeric(input$library_mostrar)
  })

  # 3. Observer for the 'Clear' button.
  # This resets both the UI inputs and the reactive filter values.
  observeEvent(input$library_clear, {
    # Reset UI
    updateTextInput(session, "library_search", value = "")
    updateSelectInput(session, "library_tipo", selected = "Todos")
    updateSelectInput(session, "library_mostrar", selected = 100)
    
    # Reset filters to trigger a refresh to the full list
    filters$search <- ""
    filters$tipo <- "Todos"
    filters$mostrar <- 100
  })

  # 4. A reactive expression to fetch data from the database.
  # This automatically re-runs whenever 'filters' changes.
  library_data <- reactive({
    # Use the user's added check for DB availability
    if (!DB_AVAILABLE) {
      return(data.frame(Error = "Database connection not available"))
    }

    # Get current filter values from our reactiveValues
    # Read trigger to establish reactive dependency
    filters$trigger
    current_search <- filters$search
    current_tipo <- filters$tipo
    current_mostrar <- as.numeric(filters$mostrar)

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
    library_data()
  }, options = list(pageLength = 10, scrollX = TRUE))

  # -- HOME TAB SERVER LOGIC (EXECUTIVE SUMMARY) --

  # Total documents count
  output$home_total_docs <- renderText({
    if (!DB_AVAILABLE) return("N/A")

    tryCatch({
      result <- dbGetQuery(secure_db_connection, "SELECT COUNT(*) as total FROM documents")
      format(result$total, big.mark = ",")
    }, error = function(e) {
      "Error"
    })
  })

  # Number of distinct document types
  output$home_doc_types_count <- renderText({
    if (!DB_AVAILABLE) return("N/A")

    tryCatch({
      result <- dbGetQuery(secure_db_connection, "SELECT COUNT(DISTINCT tipo) as count FROM documents")
      as.character(result$count)
    }, error = function(e) {
      "Error"
    })
  })

  # Latest document date
  output$home_latest_date <- renderText({
    if (!DB_AVAILABLE) return("N/A")

    tryCatch({
      result <- dbGetQuery(secure_db_connection, "SELECT MAX(data) as latest FROM documents")
      if (is.null(result$latest) || is.na(result$latest)) {
        "N/A"
      } else {
        format(as.Date(result$latest), "%d/%m/%Y")
      }
    }, error = function(e) {
      "Error"
    })
  })

  # Oldest document date
  output$home_oldest_date <- renderText({
    if (!DB_AVAILABLE) return("N/A")

    tryCatch({
      result <- dbGetQuery(secure_db_connection, "SELECT MIN(data) as oldest FROM documents")
      if (is.null(result$oldest) || is.na(result$oldest)) {
        "N/A"
      } else {
        format(as.Date(result$oldest), "%d/%m/%Y")
      }
    }, error = function(e) {
      "Error"
    })
  })

  # Document type breakdown table
  output$home_type_breakdown <- DT::renderDataTable({
    if (!DB_AVAILABLE) {
      return(data.frame(Message = "Database not available"))
    }

    tryCatch({
      result <- dbGetQuery(secure_db_connection,
        "SELECT tipo AS \"Document Type\",
                COUNT(*) as \"Count\",
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as \"Percentage\"
         FROM documents
         GROUP BY tipo
         ORDER BY COUNT(*) DESC")
      result
    }, error = function(e) {
      data.frame(Error = e$message)
    })
  }, options = list(pageLength = 10, scrollX = TRUE, dom = 't'))

  # Recent activity table
  output$home_recent_activity <- DT::renderDataTable({
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
      data.frame(Error = e$message)
    })
  }, options = list(pageLength = 10, scrollX = TRUE, dom = 't'))

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
