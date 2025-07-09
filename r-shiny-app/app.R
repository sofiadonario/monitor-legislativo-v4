# Monitor Legislativo v4 - R Shiny Application with Database
# Railway Production Deployment - Connected to PostgreSQL with real data

library(shiny)
library(shinydashboard)
library(DT)
library(dplyr)
library(jsonlite)

# Load database connection module
source("R/database_connection.R")

# Initialize database connection
database_connected <- FALSE
database_error <- ""

cat("Attempting to initialize database connection...\n")
cat("DATABASE_URL present:", nchar(Sys.getenv("DATABASE_URL")) > 0, "\n")
cat("DATABASE_URL length:", nchar(Sys.getenv("DATABASE_URL")), "\n")
if (nchar(Sys.getenv("DATABASE_URL")) > 0) {
  # Show partial URL for debugging (hide password)
  url_masked <- gsub(":[^:@]+@", ":***@", Sys.getenv("DATABASE_URL"))
  cat("DATABASE_URL (masked):", url_masked, "\n")
}
database_connected <- init_database()

if (!database_connected) {
  database_error <- "Failed to connect to database - using sample data"
  cat("⚠️", database_error, "\n")
  
  # Fallback sample data
  sample_documents <- data.frame(
    id = 1:10,
    titulo = paste("Sample Document", 1:10),
    tipo = sample(c("lei", "decreto", "portaria"), 10, replace = TRUE),
    estado = sample(c("SP", "RJ", "MG", "RS"), 10, replace = TRUE),
    data_publicacao = Sys.Date() - sample(1:365, 10),
    url = paste0("https://example.com/doc/", 1:10),
    urn = paste0("urn:lex:br:sample:", 1:10),
    stringsAsFactors = FALSE
  )
} else {
  cat("✅ Database connected successfully!\n")
}

# UI with enhanced features
ui <- dashboardPage(
  dashboardHeader(title = "Monitor Legislativo v4"),
  dashboardSidebar(
    sidebarMenu(
      menuItem("Dashboard", tabName = "dashboard", icon = icon("dashboard")),
      menuItem("Documents", tabName = "documents", icon = icon("file-text")),
      menuItem("Search", tabName = "search", icon = icon("search"))
    )
  ),
  dashboardBody(
    tabItems(
      # Dashboard tab with statistics
      tabItem(tabName = "dashboard",
        fluidRow(
          # Connection status
          box(
            title = "System Status", 
            status = if(database_connected) "success" else "warning", 
            solidHeader = TRUE, 
            width = 6,
            h4("Monitor Legislativo v4"),
            p("Production deployment on Railway"),
            br(),
            h5("Database Connection:"),
            p(
              icon(if(database_connected) "check-circle" else "exclamation-triangle"), 
              if(database_connected) "Connected to PostgreSQL" else database_error,
              style = paste0("color: ", if(database_connected) "green" else "orange")
            ),
            if(database_connected) {
              div(
                h5("Database Statistics:"),
                verbatimTextOutput("dbStats")
              )
            }
          ),
          
          # Quick stats
          box(
            title = "Document Overview", 
            status = "info", 
            solidHeader = TRUE, 
            width = 6,
            valueBoxOutput("totalDocs", width = NULL),
            br(),
            if(database_connected) {
              div(
                h5("Document Types:"),
                DT::dataTableOutput("typeStats", height = "200px")
              )
            } else {
              p("Connect to database to see real statistics")
            }
          )
        )
      ),
      
      # Documents tab
      tabItem(tabName = "documents",
        fluidRow(
          box(
            title = if(database_connected) "Legislative Documents (Real Data)" else "Sample Documents", 
            status = "primary", 
            solidHeader = TRUE, 
            width = 12,
            if(!database_connected) {
              div(
                class = "alert alert-warning",
                icon("exclamation-triangle"), " Using sample data. Database connection failed."
              )
            },
            DT::dataTableOutput("documentsTable")
          )
        )
      ),
      
      # Search tab
      tabItem(tabName = "search",
        fluidRow(
          # Search filters
          box(
            title = "Advanced Search Filters", 
            status = "primary", 
            solidHeader = TRUE, 
            width = 12,
            if(database_connected) {
              div(
                fluidRow(
                  column(6,
                    textInput("searchText", "Search Text:", 
                             placeholder = "Enter keywords to search titles and content...")
                  ),
                  column(6,
                    selectizeInput("documentTypes", "Document Types:", 
                                 choices = NULL, 
                                 multiple = TRUE,
                                 options = list(placeholder = "Select document types (optional)"))
                  )
                ),
                fluidRow(
                  column(6,
                    selectizeInput("states", "States:", 
                                 choices = NULL, 
                                 multiple = TRUE,
                                 options = list(placeholder = "Select states (optional)"))
                  ),
                  column(3,
                    dateInput("dateFrom", "Date From:", 
                             value = NULL,
                             format = "yyyy-mm-dd")
                  ),
                  column(3,
                    dateInput("dateTo", "Date To:", 
                             value = NULL,
                             format = "yyyy-mm-dd")
                  )
                ),
                fluidRow(
                  column(12,
                    div(class = "text-center",
                      actionButton("searchBtn", "Search Documents", icon = icon("search"), class = "btn-primary btn-lg"),
                      " ",
                      actionButton("clearBtn", "Clear Filters", icon = icon("times"), class = "btn-secondary")
                    )
                  )
                ),
                hr(),
                div(id = "searchResultsContainer",
                  uiOutput("searchSummary"),
                  DT::dataTableOutput("searchResults")
                )
              )
            } else {
              div(
                class = "alert alert-warning",
                icon("database"), " Search requires database connection.",
                br(), br(),
                p("Please check the database connection in the Dashboard tab.")
              )
            }
          )
        )
      )
    )
  )
)

# Server logic
server <- function(input, output, session) {
  
  # Reactive values
  values <- reactiveValues(
    current_documents = NULL,
    search_results = NULL
  )
  
  # Initialize data on startup
  observe({
    if (database_connected) {
      values$current_documents <- get_documents(50)  # Get first 50 documents
      
      # Populate filter choices
      updateSelectizeInput(session, "documentTypes", choices = get_document_types())
      updateSelectizeInput(session, "states", choices = get_states())
    } else {
      values$current_documents <- sample_documents
    }
  })
  
  # Database statistics
  output$dbStats <- renderText({
    if (database_connected) {
      stats <- get_document_stats()
      paste(
        "Total Documents:", stats$total_documents, "\n",
        "Connection Status:", stats$connection_status
      )
    } else {
      "Database not connected"
    }
  })
  
  # Total documents value box
  output$totalDocs <- renderValueBox({
    if (database_connected) {
      stats <- get_document_stats()
      count <- stats$total_documents
      status_color <- "green"
    } else {
      count <- nrow(sample_documents)
      status_color <- "yellow"
    }
    
    valueBox(
      value = count,
      subtitle = "Total Documents",
      icon = icon("file-text"),
      color = status_color
    )
  })
  
  # Document type statistics table
  output$typeStats <- DT::renderDataTable({
    if (database_connected) {
      stats <- get_document_stats()
      if (nrow(stats$document_types) > 0) {
        DT::datatable(
          stats$document_types,
          options = list(
            pageLength = 5,
            searching = FALSE,
            paging = FALSE,
            info = FALSE
          ),
          rownames = FALSE,
          colnames = c("Type", "Count")
        )
      }
    }
  })
  
  # Main documents table
  output$documentsTable <- DT::renderDataTable({
    data <- values$current_documents
    
    if (is.null(data) || nrow(data) == 0) {
      # Show empty table
      empty_data <- data.frame(
        Message = "No documents available",
        stringsAsFactors = FALSE
      )
      return(DT::datatable(empty_data, options = list(searching = FALSE)))
    }
    
    # Format the data for display
    display_data <- data %>%
      select(titulo, tipo, estado, data_publicacao, urn) %>%
      rename(
        "Title" = titulo,
        "Type" = tipo, 
        "State" = estado,
        "Date" = data_publicacao,
        "URN" = urn
      )
    
    DT::datatable(
      display_data,
      options = list(
        pageLength = 25,
        scrollX = TRUE,
        columnDefs = list(
          list(width = "40%", targets = 0),  # Title column wider
          list(width = "15%", targets = 1:3), # Type, State, Date
          list(width = "30%", targets = 4)   # URN column
        )
      ),
      rownames = FALSE
    )
  })
  
  # Advanced search functionality
  observeEvent(input$searchBtn, {
    if (database_connected) {
      withProgress(message = 'Searching documents...', value = 0, {
        incProgress(0.3)
        
        # Get filter values
        search_text <- input$searchText
        doc_types <- input$documentTypes
        states_filter <- input$states
        date_from <- input$dateFrom
        date_to <- input$dateTo
        
        incProgress(0.7)
        
        # Perform advanced search
        values$search_results <- search_documents(
          search_text = search_text,
          document_types = doc_types,
          states = states_filter,
          date_from = date_from,
          date_to = date_to,
          limit = 200
        )
        
        incProgress(1)
      })
    }
  })
  
  # Clear filters functionality
  observeEvent(input$clearBtn, {
    updateTextInput(session, "searchText", value = "")
    updateSelectizeInput(session, "documentTypes", selected = NULL)
    updateSelectizeInput(session, "states", selected = NULL)
    updateDateInput(session, "dateFrom", value = NULL)
    updateDateInput(session, "dateTo", value = NULL)
    values$search_results <- NULL
  })
  
  # Search summary
  output$searchSummary <- renderUI({
    if (!is.null(values$search_results)) {
      result_count <- nrow(values$search_results)
      
      if (result_count > 0) {
        div(
          class = "alert alert-info",
          icon("info-circle"),
          strong(paste("Found", result_count, "documents")),
          if (result_count == 200) " (showing first 200 results)" else ""
        )
      } else {
        div(
          class = "alert alert-warning",
          icon("exclamation-triangle"),
          "No documents found matching your search criteria. Try adjusting your filters."
        )
      }
    }
  })
  
  # Search results table
  output$searchResults <- DT::renderDataTable({
    if (database_connected) {
      data <- values$search_results
      
      if (is.null(data)) {
        empty_data <- data.frame(
          Message = "Enter search terms and click Search",
          stringsAsFactors = FALSE
        )
        return(DT::datatable(empty_data, options = list(searching = FALSE)))
      }
      
      if (nrow(data) == 0) {
        empty_data <- data.frame(
          Message = paste("No results found for:", input$searchText),
          stringsAsFactors = FALSE
        )
        return(DT::datatable(empty_data, options = list(searching = FALSE)))
      }
      
      # Format search results
      display_data <- data %>%
        select(titulo, tipo, estado, data_publicacao, urn) %>%
        rename(
          "Title" = titulo,
          "Type" = tipo,
          "State" = estado, 
          "Date" = data_publicacao,
          "URN" = urn
        )
      
      DT::datatable(
        display_data,
        options = list(
          pageLength = 25,
          scrollX = TRUE
        ),
        rownames = FALSE
      )
    }
  })
  
  # Cleanup on session end
  session$onSessionEnded(function() {
    cleanup_database()
  })
}

# Print startup information
cat("=== Monitor Legislativo v4 with Database - Version 2.0 ===\n")
cat("Starting Monitor Legislativo v4 Shiny application...\n")
cat("PORT env var:", Sys.getenv("PORT"), "\n")
cat("Using port:", as.integer(Sys.getenv("PORT", "3838")), "\n")
cat("Host: 0.0.0.0\n")
cat("Database connected:", database_connected, "\n")
cat("App version: Database-enabled (", Sys.time(), ")\n")

# Set options before running app
options(
  shiny.host = "0.0.0.0",
  shiny.port = as.integer(Sys.getenv("PORT", "3838")),
  shiny.launch.browser = FALSE,
  shiny.autoreload = FALSE
)

# Run the application
cat("Starting Shiny app...\n")
app <- shinyApp(ui = ui, server = server)
runApp(app, host = "0.0.0.0", port = as.integer(Sys.getenv("PORT", "3838")), launch.browser = FALSE)