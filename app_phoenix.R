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
      h1("Document Library"),
      p("A live view of the documents in the database."),
      hr(),
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
# 4. SERVER LOGIC (STABLE & MONOLITHIC)
# ==============================================================================
server <- function(input, output, session) {

  # -- LIBRARY SERVER LOGIC --
  output$library_table <- DT::renderDataTable({
    req(DB_AVAILABLE) # Require a database connection
    
    tryCatch({
      # A simple, safe query to show the app is working
      dbGetQuery(secure_db_connection, "SELECT id, titulo, tipo, data FROM legis_docs LIMIT 100")
    }, error = function(e) {
      # Show a clean error in the table if the query fails
      data.frame(Error = e$message)
    })
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
