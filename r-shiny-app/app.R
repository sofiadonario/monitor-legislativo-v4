# Monitor Legislativo v4 - R Shiny Application with Database
# Railway Production Deployment - Connected to PostgreSQL with real data
# Enhanced with intelligent caching system for improved performance

library(shiny)
library(shinydashboard)
library(DT)
library(dplyr)
library(jsonlite)
library(plotly)
library(ggplot2)
library(shinyjs)
library(shinycssloaders)
library(leaflet)
library(stringr)
library(openxlsx)
library(readr)

# Load database connection module
source("R/database_connection.R")
# Load map generator module
source("R/map_generator.R")
# Load export utilities module
source("R/export_utils.R")
# Load cache utilities module
source("R/cache_utils.R")
# Load health check module
source("R/health_check.R")

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

# Initialize cache system
init_cache()

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
      id = "sidebarMenu",
      menuItem("Dashboard", tabName = "dashboard", icon = icon("dashboard")),
      menuItem("Documents", tabName = "documents", icon = icon("file-text")),
      menuItem("Search", tabName = "search", icon = icon("search")),
      menuItem("Analytics", tabName = "analytics", icon = icon("chart-bar")),
      menuItem("Map", tabName = "map", icon = icon("map")),
      menuItem("Health Check", tabName = "health", icon = icon("heartbeat"))
    )
  ),
  dashboardBody(
    useShinyjs(),
    
    # Custom CSS for better styling and animations
    tags$head(
      tags$style(HTML("
        .content-wrapper, .right-side {
          background-color: #f4f4f4;
        }
        
        .box {
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          transition: all 0.3s ease;
        }
        
        .box:hover {
          box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        
        .btn {
          border-radius: 4px;
          transition: all 0.3s ease;
        }
        
        .btn:hover {
          transform: translateY(-1px);
          box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }
        
        .alert {
          border-radius: 6px;
          animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        
        .progress-bar {
          transition: width 0.3s ease;
        }
        
        .tooltip {
          font-size: 12px;
        }
        
        .help-text {
          font-size: 11px;
          color: #666;
          margin-top: 5px;
        }
        
        .export-buttons {
          animation: fadeIn 0.5s ease;
        }
        
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        
        .cache-controls .btn {
          margin-right: 5px;
        }
        
        .search-controls {
          margin-bottom: 20px;
        }
        
        .history-item:hover {
          background-color: #f8f9fa;
          border-color: #007bff;
        }
        
        .saved-search-item:hover {
          background-color: #f8f9fa;
          border-color: #28a745;
        }
        
        .loading-overlay {
          position: relative;
        }
        
        .status-indicator {
          display: inline-block;
          width: 8px;
          height: 8px;
          border-radius: 50%;
          margin-right: 5px;
        }
        
        .status-connected {
          background-color: #28a745;
          animation: pulse 2s infinite;
        }
        
        .status-disconnected {
          background-color: #dc3545;
        }
        
        @keyframes pulse {
          0% { opacity: 1; }
          50% { opacity: 0.5; }
          100% { opacity: 1; }
        }
        
        .health-controls .btn {
          margin-right: 10px;
          margin-bottom: 5px;
        }
        
        .health-overview {
          margin-bottom: 20px;
        }
        
        .status-healthy {
          background-color: #28a745;
          animation: pulse 2s infinite;
        }
        
        .status-warning {
          background-color: #ffc107;
          animation: pulse 2s infinite;
        }
        
        .status-critical {
          background-color: #dc3545;
          animation: pulse 1s infinite;
        }
        
        .status-error {
          background-color: #dc3545;
          animation: pulse 1s infinite;
        }
      ")),
      
      # JavaScript for dynamic health indicator updates
      tags$script(HTML("
        Shiny.addCustomMessageHandler('updateHealthIndicator', function(status) {
          var indicator = document.getElementById('healthStatusIndicator');
          if (indicator) {
            indicator.className = 'status-indicator status-' + status;
          }
        });
      "))
    ),
    
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
              span(class = if(database_connected) "status-indicator status-connected" else "status-indicator status-disconnected"),
              icon(if(database_connected) "check-circle" else "exclamation-triangle"), 
              if(database_connected) "Connected to PostgreSQL" else database_error,
              style = paste0("color: ", if(database_connected) "green" else "orange")
            ),
            if(database_connected) {
              div(
                h5("Database Statistics:"),
                withSpinner(verbatimTextOutput("dbStats"), type = 4, color = "#3498db")
              )
            },
            br(),
            h5("Cache Status:"),
            p(
              icon("server"), 
              "Cache system active",
              style = "color: green"
            ),
            p(
              strong("Memory Cache:"), 
              textOutput("memoryCacheCount", inline = TRUE),
              style = "font-size: 12px;"
            ),
            p(
              strong("File Cache:"), 
              textOutput("fileCacheCount", inline = TRUE),
              style = "font-size: 12px;"
            ),
            br(),
            h5("System Health:"),
            p(
              span(id = "healthStatusIndicator", class = "status-indicator status-connected"),
              icon("heartbeat"), 
              textOutput("healthStatusText", inline = TRUE),
              style = "color: green"
            ),
            div(
              class = "health-controls",
              actionButton("refreshHealthBtn", "Refresh Health", icon = icon("refresh"), class = "btn-info btn-sm",
                          title = "Refresh health status"),
              style = "margin-top: 10px;"
            )
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
                withSpinner(DT::dataTableOutput("typeStats", height = "200px"), type = 4, color = "#17a2b8")
              )
            } else {
              p("Connect to database to see real statistics")
            }
          )
        ),
        
        # Cache management section
        box(
          title = "Cache Management", 
          status = "success", 
          solidHeader = TRUE, 
          width = 12,
          h5("Cache Statistics:"),
          withSpinner(verbatimTextOutput("cacheStats"), type = 4, color = "#28a745"),
          br(),
          div(
            class = "cache-controls",
            actionButton("clearCacheBtn", "Clear Cache", icon = icon("trash"), class = "btn-warning",
                        title = "Clear all cached data to free memory"),
            actionButton("refreshCacheBtn", "Refresh Cache", icon = icon("refresh"), class = "btn-info",
                        title = "Refresh all cached data from database")
          ),
          div(class = "help-text", "Cache improves performance by storing frequently accessed data")
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
            div(
              class = "export-buttons",
              style = "margin-bottom: 15px; text-align: right;",
              downloadButton("exportDocsCSV", "Export CSV", icon = icon("download"), class = "btn-success btn-sm",
                            title = "Export all documents to CSV format"),
              downloadButton("exportDocsExcel", "Export Excel", icon = icon("file-excel"), class = "btn-info btn-sm",
                            title = "Export all documents to Excel format"),
              downloadButton("exportDocsCitations", "Export Citations", icon = icon("quote-left"), class = "btn-warning btn-sm",
                            title = "Export citations in ABNT format")
            ),
            div(class = "help-text", "Click on column headers to sort. Use the search box to filter results."),
            withSpinner(DT::dataTableOutput("documentsTable"), type = 1, color = "#007bff")
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
            width = 8,
            if(database_connected) {
              div(
                fluidRow(
                  column(6,
                    textInput("searchText", "Search Text:", 
                             placeholder = "Enter keywords to search titles and content..."),
                    div(class = "help-text", "Search will look for matches in document titles and content")
                  ),
                  column(6,
                    selectizeInput("documentTypes", "Document Types:", 
                                 choices = NULL, 
                                 multiple = TRUE,
                                 options = list(placeholder = "Select document types (optional)")),
                    div(class = "help-text", "Filter by specific document types (laws, decrees, etc.)")
                  )
                ),
                fluidRow(
                  column(6,
                    selectizeInput("states", "States:", 
                                 choices = NULL, 
                                 multiple = TRUE,
                                 options = list(placeholder = "Select states (optional)")),
                    div(class = "help-text", "Filter by Brazilian states")
                  ),
                  column(3,
                    dateInput("dateFrom", "Date From:", 
                             value = NULL,
                             format = "yyyy-mm-dd"),
                    div(class = "help-text", "Start date for filtering")
                  ),
                  column(3,
                    dateInput("dateTo", "Date To:", 
                             value = NULL,
                             format = "yyyy-mm-dd"),
                    div(class = "help-text", "End date for filtering")
                  )
                ),
                fluidRow(
                  column(12,
                    div(class = "text-center search-controls",
                      actionButton("searchBtn", "Search Documents", icon = icon("search"), class = "btn-primary btn-lg",
                                  title = "Execute search with current filters"),
                      actionButton("clearBtn", "Clear Filters", icon = icon("times"), class = "btn-secondary",
                                  title = "Clear all search filters"),
                      actionButton("saveSearchBtn", "Save Search", icon = icon("star"), class = "btn-warning",
                                  title = "Save current search filters for later use")
                    )
                  )
                ),
                hr(),
                div(id = "searchResultsContainer",
                  uiOutput("searchSummary"),
                  div(
                    class = "export-buttons",
                    style = "margin-bottom: 15px; text-align: right;",
                    conditionalPanel(
                      condition = "output.searchResultsAvailable == true",
                      downloadButton("exportSearchCSV", "Export CSV", icon = icon("download"), class = "btn-success btn-sm",
                                    title = "Export search results to CSV"),
                      downloadButton("exportSearchExcel", "Export Excel", icon = icon("file-excel"), class = "btn-info btn-sm",
                                    title = "Export search results to Excel"),
                      downloadButton("exportSearchCitations", "Export Citations", icon = icon("quote-left"), class = "btn-warning btn-sm",
                                    title = "Export search results as citations")
                    )
                  ),
                  withSpinner(DT::dataTableOutput("searchResults"), type = 1, color = "#007bff")
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
          ),
          
          # Search History and Saved Searches panel
          box(
            title = "Search History & Saved Searches", 
            status = "info", 
            solidHeader = TRUE, 
            width = 4,
            tabsetPanel(
              tabPanel("History", 
                br(),
                actionButton("clearHistoryBtn", "Clear History", icon = icon("trash"), class = "btn-sm btn-danger",
                            title = "Clear all search history"),
                hr(),
                div(id = "searchHistoryContainer",
                  uiOutput("searchHistoryList")
                )
              ),
              tabPanel("Saved Searches",
                br(),
                div(id = "savedSearchesContainer",
                  uiOutput("savedSearchesList")
                )
              )
            )
          )
        )
      ),
      
      # Analytics tab
      tabItem(tabName = "analytics",
        fluidRow(
          # Analytics overview
          box(
            title = "Analytics Overview", 
            status = "info", 
            solidHeader = TRUE, 
            width = 12,
            if(database_connected) {
              div(
                fluidRow(
                  column(3,
                    withSpinner(valueBoxOutput("analyticsTotal", width = NULL), type = 4, color = "#007bff")
                  ),
                  column(3,
                    withSpinner(valueBoxOutput("analyticsStates", width = NULL), type = 4, color = "#28a745")
                  ),
                  column(3,
                    withSpinner(valueBoxOutput("analyticsTypes", width = NULL), type = 4, color = "#ffc107")
                  ),
                  column(3,
                    withSpinner(valueBoxOutput("analyticsDateRange", width = NULL), type = 4, color = "#6f42c1")
                  )
                )
              )
            } else {
              div(
                class = "alert alert-warning",
                icon("database"), " Analytics require database connection.",
                br(), br(),
                p("Please check the database connection in the Dashboard tab.")
              )
            }
          )
        ),
        if(database_connected) {
          fluidRow(
            # Documents by Year Chart
            box(
              title = "Documents by Year", 
              status = "primary", 
              solidHeader = TRUE, 
              width = 6,
              withSpinner(plotlyOutput("yearChart", height = "300px"), type = 2, color = "#3498db", color.background = "#f4f4f4")
            ),
            
            # Documents by State Chart
            box(
              title = "Documents by State (Top 10)", 
              status = "success", 
              solidHeader = TRUE, 
              width = 6,
              withSpinner(plotlyOutput("stateChart", height = "300px"), type = 2, color = "#27ae60", color.background = "#f4f4f4")
            )
          )
        },
        if(database_connected) {
          fluidRow(
            # Documents by Type Chart
            box(
              title = "Documents by Type", 
              status = "warning", 
              solidHeader = TRUE, 
              width = 6,
              withSpinner(plotlyOutput("typeChart", height = "300px"), type = 2, color = "#f39c12", color.background = "#f4f4f4")
            ),
            
            # Recent Documents
            box(
              title = "Recent Documents (Last 30 days)", 
              status = "info", 
              solidHeader = TRUE, 
              width = 6,
              withSpinner(DT::dataTableOutput("recentDocuments", height = "300px"), type = 1, color = "#17a2b8")
            )
          )
        }
      ),
      
      # Map tab
      tabItem(tabName = "map",
        fluidRow(
          # Map controls
          box(
            title = "Geographic Distribution of Documents", 
            status = "info", 
            solidHeader = TRUE, 
            width = 12,
            if(database_connected) {
              div(
                fluidRow(
                  column(12,
                    div(class = "text-center",
                      p("Click on a state to filter documents by that state"),
                      actionButton("resetMapFilter", "Reset Filter", icon = icon("refresh"), class = "btn-secondary",
                                  title = "Reset state filter and show all documents")
                    )
                  )
                ),
                hr(),
                withSpinner(leafletOutput("documentMap", height = "600px"), type = 3, color = "#17a2b8", color.background = "#f4f4f4")
              )
            } else {
              div(
                class = "alert alert-warning",
                icon("database"), " Map visualization requires database connection.",
                br(), br(),
                p("Please check the database connection in the Dashboard tab.")
              )
            }
          )
        ),
        if(database_connected) {
          fluidRow(
            # State statistics table
            box(
              title = "Document Count by State", 
              status = "primary", 
              solidHeader = TRUE, 
              width = 12,
              withSpinner(DT::dataTableOutput("stateStatsTable"), type = 1, color = "#007bff")
            )
          )
        }
      ),
      
      # Health Check tab
      tabItem(tabName = "health",
        fluidRow(
          # Health Status Overview
          box(
            title = "System Health Status", 
            status = "primary", 
            solidHeader = TRUE, 
            width = 12,
            div(
              class = "health-overview",
              style = "margin-bottom: 20px;",
              fluidRow(
                column(3,
                  withSpinner(valueBoxOutput("healthOverallStatus", width = NULL), type = 4, color = "#007bff")
                ),
                column(3,
                  withSpinner(valueBoxOutput("healthDatabaseStatus", width = NULL), type = 4, color = "#28a745")
                ),
                column(3,
                  withSpinner(valueBoxOutput("healthCacheStatus", width = NULL), type = 4, color = "#ffc107")
                ),
                column(3,
                  withSpinner(valueBoxOutput("healthMemoryStatus", width = NULL), type = 4, color = "#6f42c1")
                )
              )
            ),
            hr(),
            div(
              class = "health-controls",
              actionButton("runHealthCheckBtn", "Run Health Check", icon = icon("play"), class = "btn-primary",
                          title = "Run a comprehensive health check"),
              actionButton("downloadHealthLogBtn", "Download Health Log", icon = icon("download"), class = "btn-secondary",
                          title = "Download health check logs"),
              actionButton("clearHealthLogBtn", "Clear Health Log", icon = icon("trash"), class = "btn-warning",
                          title = "Clear health check logs"),
              style = "margin-bottom: 20px;"
            ),
            div(
              p(strong("Last Health Check:"), textOutput("lastHealthCheckTime", inline = TRUE), style = "margin-bottom: 10px;"),
              p(strong("Check Duration:"), textOutput("healthCheckDuration", inline = TRUE), style = "margin-bottom: 10px;"),
              p(strong("Automatic Checks:"), "Every 5 minutes", style = "margin-bottom: 10px;")
            )
          )
        ),
        
        fluidRow(
          # Detailed Health Metrics
          box(
            title = "Detailed Health Metrics", 
            status = "info", 
            solidHeader = TRUE, 
            width = 8,
            tabsetPanel(
              tabPanel("Database Health", 
                br(),
                withSpinner(verbatimTextOutput("databaseHealthDetails"), type = 4, color = "#28a745")
              ),
              tabPanel("Cache Health",
                br(),
                withSpinner(verbatimTextOutput("cacheHealthDetails"), type = 4, color = "#ffc107")
              ),
              tabPanel("File System Health",
                br(),
                withSpinner(verbatimTextOutput("filesystemHealthDetails"), type = 4, color = "#17a2b8")
              ),
              tabPanel("Memory Health",
                br(),
                withSpinner(verbatimTextOutput("memoryHealthDetails"), type = 4, color = "#6f42c1")
              )
            )
          ),
          
          # Health Check History
          box(
            title = "Health Check History", 
            status = "success", 
            solidHeader = TRUE, 
            width = 4,
            div(
              style = "max-height: 400px; overflow-y: auto;",
              withSpinner(verbatimTextOutput("healthCheckHistory"), type = 4, color = "#28a745")
            )
          )
        ),
        
        fluidRow(
          # Health Trends Chart
          box(
            title = "Health Trends", 
            status = "warning", 
            solidHeader = TRUE, 
            width = 12,
            withSpinner(plotlyOutput("healthTrendsChart", height = "300px"), type = 2, color = "#f39c12", color.background = "#f4f4f4")
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
    search_results = NULL,
    analytics_data = NULL,
    search_history = list(),
    saved_searches = list(),
    health_check_data = NULL,
    health_check_history = list(),
    last_health_check = NULL
  )
  
  # Initialize data on startup
  observe({
    if (database_connected) {
      values$current_documents <- cached_get_documents(50)  # Get first 50 documents (cached)
      values$analytics_data <- cached_get_search_analytics()  # Load analytics data (cached)
      
      # Populate filter choices (cached)
      updateSelectizeInput(session, "documentTypes", choices = cached_get_document_types())
      updateSelectizeInput(session, "states", choices = cached_get_states())
    } else {
      values$current_documents <- sample_documents
    }
    
    # Load search history and saved searches
    session_id <- session$token
    values$search_history <- get_search_history(session_id)
    values$saved_searches <- get_saved_searches(session_id)
    
    # Perform initial health check
    tryCatch({
      values$health_check_data <- perform_health_check()
      values$last_health_check <- Sys.time()
      log_health_check(values$health_check_data)
    }, error = function(e) {
      cat("Initial health check failed:", e$message, "\n")
    })
  })
  
  # Database statistics
  output$dbStats <- renderText({
    if (database_connected) {
      stats <- cached_get_document_stats()
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
      stats <- cached_get_document_stats()
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
      stats <- cached_get_document_stats()
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
      # Disable search button during search
      shinyjs::disable("searchBtn")
      shinyjs::disable("clearBtn")
      shinyjs::disable("saveSearchBtn")
      
      withProgress(message = 'Searching documents...', value = 0, {
        tryCatch({
          incProgress(0.2, detail = "Validating search parameters...")
          
          # Get filter values
          search_text <- input$searchText
          doc_types <- input$documentTypes
          states_filter <- input$states
          date_from <- input$dateFrom
          date_to <- input$dateTo
          
          incProgress(0.4, detail = "Executing database query...")
          
          # Perform advanced search
          values$search_results <- search_documents(
            search_text = search_text,
            document_types = doc_types,
            states = states_filter,
            date_from = date_from,
            date_to = date_to,
            limit = 200
          )
          
          incProgress(0.8, detail = "Saving search to history...")
          
          # Save to search history
          search_params <- list(
            search_text = search_text,
            document_types = doc_types,
            states = states_filter,
            date_from = date_from,
            date_to = date_to
          )
          
          # Only save if search has any criteria
          if (nchar(search_text) > 0 || !is.null(doc_types) || !is.null(states_filter) || 
              !is.null(date_from) || !is.null(date_to)) {
            session_id <- session$token
            save_search_history(search_params, session_id)
            # Reload search history
            values$search_history <- get_search_history(session_id)
          }
          
          incProgress(1, detail = "Search completed successfully!")
          
          # Show success notification
          result_count <- if (!is.null(values$search_results)) nrow(values$search_results) else 0
          showNotification(
            paste("Search completed!", result_count, "documents found."),
            type = "success",
            duration = 3
          )
        }, error = function(e) {
          # Handle search errors gracefully
          showNotification(
            paste("Search failed:", e$message),
            type = "error",
            duration = 5
          )
          cat("Search error:", e$message, "\n")
        })
      })
      
      # Re-enable buttons after search
      shinyjs::enable("searchBtn")
      shinyjs::enable("clearBtn")
      shinyjs::enable("saveSearchBtn")
    } else {
      showNotification("Database not connected. Please check connection.", type = "error", duration = 5)
    }
  })
  
  # Clear filters functionality
  observeEvent(input$clearBtn, {
    showModal(modalDialog(
      title = "Clear Search Filters",
      "Are you sure you want to clear all search filters and results?",
      footer = tagList(
        modalButton("Cancel"),
        actionButton("confirmClearFilters", "Clear All", class = "btn-warning")
      )
    ))
  })
  
  # Confirm clear filters
  observeEvent(input$confirmClearFilters, {
    updateTextInput(session, "searchText", value = "")
    updateSelectizeInput(session, "documentTypes", selected = NULL)
    updateSelectizeInput(session, "states", selected = NULL)
    updateDateInput(session, "dateFrom", value = NULL)
    updateDateInput(session, "dateTo", value = NULL)
    values$search_results <- NULL
    
    showNotification("Search filters cleared successfully!", type = "info", duration = 3)
    removeModal()
  })
  
  # Search summary
  output$searchSummary <- renderUI({
    if (!is.null(values$search_results)) {
      result_count <- nrow(values$search_results)
      
      # Build filter summary
      filter_parts <- c()
      if (!is.null(input$searchText) && nchar(input$searchText) > 0) {
        filter_parts <- c(filter_parts, paste("Text:", input$searchText))
      }
      if (!is.null(input$documentTypes) && length(input$documentTypes) > 0) {
        filter_parts <- c(filter_parts, paste("Types:", paste(input$documentTypes, collapse = ", ")))
      }
      if (!is.null(input$states) && length(input$states) > 0) {
        filter_parts <- c(filter_parts, paste("States:", paste(input$states, collapse = ", ")))
      }
      if (!is.null(input$dateFrom) || !is.null(input$dateTo)) {
        date_part <- "Date range:"
        if (!is.null(input$dateFrom)) date_part <- paste(date_part, "from", input$dateFrom)
        if (!is.null(input$dateTo)) date_part <- paste(date_part, "to", input$dateTo)
        filter_parts <- c(filter_parts, date_part)
      }
      
      if (result_count > 0) {
        div(
          class = "alert alert-info",
          icon("info-circle"),
          strong(paste("Found", result_count, "documents")),
          if (result_count == 200) " (showing first 200 results)" else "",
          if (!is.null(input$searchText) && nchar(input$searchText) > 0) {
            div(
              br(),
              icon("star"),
              em("Results ranked by relevance (title matches first, then content)")
            )
          },
          if (length(filter_parts) > 0) {
            div(
              br(),
              strong("Applied filters: "),
              paste(filter_parts, collapse = " | ")
            )
          }
        )
      } else {
        div(
          class = "alert alert-warning",
          icon("exclamation-triangle"),
          "No documents found matching your search criteria.",
          if (length(filter_parts) > 0) {
            div(
              br(),
              strong("Applied filters: "),
              paste(filter_parts, collapse = " | "),
              br(),
              "Try adjusting your filters."
            )
          } else {
            div(
              br(),
              "Try adding some search criteria."
            )
          }
        )
      }
    }
  })
  
  # Search results availability output for conditional panel
  output$searchResultsAvailable <- reactive({
    !is.null(values$search_results) && nrow(values$search_results) > 0
  })
  outputOptions(output, "searchResultsAvailable", suspendWhenHidden = FALSE)
  
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
      
      # Format search results with highlighting
      display_data <- data %>%
        select(titulo, tipo, estado, data_publicacao, urn) %>%
        rename(
          "Title" = titulo,
          "Type" = tipo,
          "State" = estado, 
          "Date" = data_publicacao,
          "URN" = urn
        )
      
      # Highlight search terms in titles if search text was provided
      if (!is.null(input$searchText) && nchar(input$searchText) > 0) {
        search_terms <- strsplit(input$searchText, "\\s+")[[1]]
        display_data$Title <- sapply(display_data$Title, function(title) {
          highlight_search_terms(title, search_terms)
        })
      }
      
      DT::datatable(
        display_data,
        options = list(
          pageLength = 25,
          scrollX = TRUE
        ),
        rownames = FALSE,
        escape = FALSE  # Allow HTML in cells for highlighting
      )
    }
  })
  
  # === Export Functionality ===
  
  # Documents export handlers
  output$exportDocsCSV <- downloadHandler(
    filename = function() {
      paste0("legislative_documents_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".csv")
    },
    content = function(file) {
      withProgress(message = 'Exporting to CSV...', value = 0, {
        tryCatch({
          incProgress(0.3, detail = "Preparing data...")
          
          data <- values$current_documents
          if (is.null(data) || nrow(data) == 0) {
            showNotification("No documents to export", type = "warning", duration = 3)
            return()
          }
          
          incProgress(0.7, detail = "Creating CSV file...")
          
          # Create temporary CSV file
          temp_file <- export_to_csv(data, "legislative_documents")
          if (!is.null(temp_file) && file.exists(temp_file)) {
            file.copy(temp_file, file)
            incProgress(1, detail = "Export completed!")
            showNotification("Documents exported to CSV successfully!", type = "success", duration = 3)
          } else {
            showNotification("Error creating CSV export", type = "error", duration = 5)
          }
        }, error = function(e) {
          showNotification(paste("Export error:", e$message), type = "error", duration = 5)
          cat("CSV export error:", e$message, "\n")
        })
      })
    }
  )
  
  output$exportDocsExcel <- downloadHandler(
    filename = function() {
      paste0("legislative_documents_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".xlsx")
    },
    content = function(file) {
      withProgress(message = 'Exporting to Excel...', value = 0, {
        tryCatch({
          incProgress(0.3, detail = "Preparing data...")
          
          data <- values$current_documents
          if (is.null(data) || nrow(data) == 0) {
            showNotification("No documents to export", type = "warning", duration = 3)
            return()
          }
          
          incProgress(0.7, detail = "Creating Excel file...")
          
          # Create temporary Excel file
          temp_file <- export_to_excel(data, "legislative_documents")
          if (!is.null(temp_file) && file.exists(temp_file)) {
            file.copy(temp_file, file)
            incProgress(1, detail = "Export completed!")
            showNotification("Documents exported to Excel successfully!", type = "success", duration = 3)
          } else {
            showNotification("Error creating Excel export", type = "error", duration = 5)
          }
        }, error = function(e) {
          showNotification(paste("Export error:", e$message), type = "error", duration = 5)
          cat("Excel export error:", e$message, "\n")
        })
      })
    }
  )
  
  output$exportDocsCitations <- downloadHandler(
    filename = function() {
      paste0("legislative_citations_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".txt")
    },
    content = function(file) {
      withProgress(message = 'Exporting citations...', value = 0, {
        tryCatch({
          incProgress(0.3, detail = "Preparing data...")
          
          data <- values$current_documents
          if (is.null(data) || nrow(data) == 0) {
            showNotification("No documents to export", type = "warning", duration = 3)
            return()
          }
          
          incProgress(0.7, detail = "Creating citation file...")
          
          # Create temporary citation file
          temp_file <- export_citations(data, "ABNT", "legislative_citations")
          if (!is.null(temp_file) && file.exists(temp_file)) {
            file.copy(temp_file, file)
            incProgress(1, detail = "Export completed!")
            showNotification("Citations exported successfully!", type = "success", duration = 3)
          } else {
            showNotification("Error creating citation export", type = "error", duration = 5)
          }
        }, error = function(e) {
          showNotification(paste("Export error:", e$message), type = "error", duration = 5)
          cat("Citation export error:", e$message, "\n")
        })
      })
    }
  )
  
  # Search results export handlers
  output$exportSearchCSV <- downloadHandler(
    filename = function() {
      paste0("search_results_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".csv")
    },
    content = function(file) {
      withProgress(message = 'Exporting search results...', value = 0, {
        tryCatch({
          incProgress(0.3, detail = "Preparing search results...")
          
          data <- values$search_results
          if (is.null(data) || nrow(data) == 0) {
            showNotification("No search results to export", type = "warning", duration = 3)
            return()
          }
          
          incProgress(0.7, detail = "Creating CSV file...")
          
          # Create temporary CSV file
          temp_file <- export_to_csv(data, "search_results")
          if (!is.null(temp_file) && file.exists(temp_file)) {
            file.copy(temp_file, file)
            incProgress(1, detail = "Export completed!")
            showNotification("Search results exported to CSV successfully!", type = "success", duration = 3)
          } else {
            showNotification("Error creating CSV export", type = "error", duration = 5)
          }
        }, error = function(e) {
          showNotification(paste("Export error:", e$message), type = "error", duration = 5)
          cat("Search CSV export error:", e$message, "\n")
        })
      })
    }
  )
  
  output$exportSearchExcel <- downloadHandler(
    filename = function() {
      paste0("search_results_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".xlsx")
    },
    content = function(file) {
      withProgress(message = 'Exporting search results...', value = 0, {
        tryCatch({
          incProgress(0.3, detail = "Preparing search results...")
          
          data <- values$search_results
          if (is.null(data) || nrow(data) == 0) {
            showNotification("No search results to export", type = "warning", duration = 3)
            return()
          }
          
          incProgress(0.7, detail = "Creating Excel file...")
          
          # Create temporary Excel file
          temp_file <- export_to_excel(data, "search_results")
          if (!is.null(temp_file) && file.exists(temp_file)) {
            file.copy(temp_file, file)
            incProgress(1, detail = "Export completed!")
            showNotification("Search results exported to Excel successfully!", type = "success", duration = 3)
          } else {
            showNotification("Error creating Excel export", type = "error", duration = 5)
          }
        }, error = function(e) {
          showNotification(paste("Export error:", e$message), type = "error", duration = 5)
          cat("Search Excel export error:", e$message, "\n")
        })
      })
    }
  )
  
  output$exportSearchCitations <- downloadHandler(
    filename = function() {
      paste0("search_citations_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".txt")
    },
    content = function(file) {
      withProgress(message = 'Exporting search citations...', value = 0, {
        tryCatch({
          incProgress(0.3, detail = "Preparing search results...")
          
          data <- values$search_results
          if (is.null(data) || nrow(data) == 0) {
            showNotification("No search results to export", type = "warning", duration = 3)
            return()
          }
          
          incProgress(0.7, detail = "Creating citation file...")
          
          # Create temporary citation file
          temp_file <- export_citations(data, "ABNT", "search_citations")
          if (!is.null(temp_file) && file.exists(temp_file)) {
            file.copy(temp_file, file)
            incProgress(1, detail = "Export completed!")
            showNotification("Search citations exported successfully!", type = "success", duration = 3)
          } else {
            showNotification("Error creating citation export", type = "error", duration = 5)
          }
        }, error = function(e) {
          showNotification(paste("Export error:", e$message), type = "error", duration = 5)
          cat("Search citation export error:", e$message, "\n")
        })
      })
    }
  )
  
  # === Analytics Section ===
  
  # Analytics value boxes
  output$analyticsTotal <- renderValueBox({
    if (database_connected && !is.null(values$analytics_data)) {
      count <- values$analytics_data$total_documents
      status_color <- "blue"
    } else {
      count <- 0
      status_color <- "red"
    }
    
    valueBox(
      value = count,
      subtitle = "Total Documents",
      icon = icon("file-text"),
      color = status_color
    )
  })
  
  output$analyticsStates <- renderValueBox({
    if (database_connected && !is.null(values$analytics_data)) {
      count <- nrow(values$analytics_data$documents_by_state)
      status_color <- "green"
    } else {
      count <- 0
      status_color <- "red"
    }
    
    valueBox(
      value = count,
      subtitle = "States",
      icon = icon("map"),
      color = status_color
    )
  })
  
  output$analyticsTypes <- renderValueBox({
    if (database_connected && !is.null(values$analytics_data)) {
      count <- nrow(values$analytics_data$documents_by_type)
      status_color <- "yellow"
    } else {
      count <- 0
      status_color <- "red"
    }
    
    valueBox(
      value = count,
      subtitle = "Document Types",
      icon = icon("tags"),
      color = status_color
    )
  })
  
  output$analyticsDateRange <- renderValueBox({
    if (database_connected && !is.null(values$analytics_data)) {
      min_date <- values$analytics_data$date_range$min
      max_date <- values$analytics_data$date_range$max
      if (!is.na(min_date) && !is.na(max_date)) {
        years <- as.numeric(format(max_date, "%Y")) - as.numeric(format(min_date, "%Y"))
        subtitle <- paste(years, "Years")
        status_color <- "purple"
      } else {
        subtitle <- "N/A"
        status_color <- "red"
      }
    } else {
      subtitle <- "N/A"
      status_color <- "red"
    }
    
    valueBox(
      value = ifelse(subtitle == "N/A", "N/A", years),
      subtitle = subtitle,
      icon = icon("calendar"),
      color = status_color
    )
  })
  
  # Documents by Year Chart
  output$yearChart <- renderPlotly({
    if (database_connected && !is.null(values$analytics_data)) {
      data <- values$analytics_data$documents_by_year
      
      if (nrow(data) > 0) {
        p <- ggplot(data, aes(x = year, y = count)) +
          geom_line(color = "#3498db", size = 1.2) +
          geom_point(color = "#2980b9", size = 3) +
          theme_minimal() +
          labs(
            title = "Documents Published by Year",
            x = "Year",
            y = "Number of Documents"
          ) +
          theme(
            plot.title = element_text(size = 14, face = "bold"),
            axis.title = element_text(size = 12),
            axis.text = element_text(size = 10)
          )
        
        ggplotly(p, tooltip = c("x", "y"))
      } else {
        # Empty plot
        p <- ggplot() + 
          geom_text(aes(x = 0, y = 0, label = "No data available"), size = 5) +
          theme_void()
        ggplotly(p)
      }
    } else {
      # Empty plot
      p <- ggplot() + 
        geom_text(aes(x = 0, y = 0, label = "Database not connected"), size = 5) +
        theme_void()
      ggplotly(p)
    }
  })
  
  # Documents by State Chart
  output$stateChart <- renderPlotly({
    if (database_connected && !is.null(values$analytics_data)) {
      data <- values$analytics_data$documents_by_state
      
      if (nrow(data) > 0) {
        p <- ggplot(data, aes(x = reorder(estado, count), y = count)) +
          geom_bar(stat = "identity", fill = "#27ae60") +
          coord_flip() +
          theme_minimal() +
          labs(
            title = "Documents by State (Top 10)",
            x = "State",
            y = "Number of Documents"
          ) +
          theme(
            plot.title = element_text(size = 14, face = "bold"),
            axis.title = element_text(size = 12),
            axis.text = element_text(size = 10)
          )
        
        ggplotly(p, tooltip = c("x", "y"))
      } else {
        # Empty plot
        p <- ggplot() + 
          geom_text(aes(x = 0, y = 0, label = "No data available"), size = 5) +
          theme_void()
        ggplotly(p)
      }
    } else {
      # Empty plot
      p <- ggplot() + 
        geom_text(aes(x = 0, y = 0, label = "Database not connected"), size = 5) +
        theme_void()
      ggplotly(p)
    }
  })
  
  # Documents by Type Chart
  output$typeChart <- renderPlotly({
    if (database_connected && !is.null(values$analytics_data)) {
      data <- values$analytics_data$documents_by_type
      
      if (nrow(data) > 0) {
        p <- ggplot(data, aes(x = "", y = count, fill = tipo)) +
          geom_bar(stat = "identity", width = 1) +
          coord_polar("y", start = 0) +
          theme_void() +
          labs(
            title = "Documents by Type",
            fill = "Type"
          ) +
          theme(
            plot.title = element_text(size = 14, face = "bold", hjust = 0.5),
            legend.title = element_text(size = 12),
            legend.text = element_text(size = 10)
          ) +
          scale_fill_brewer(palette = "Set3")
        
        ggplotly(p, tooltip = c("fill", "y"))
      } else {
        # Empty plot
        p <- ggplot() + 
          geom_text(aes(x = 0, y = 0, label = "No data available"), size = 5) +
          theme_void()
        ggplotly(p)
      }
    } else {
      # Empty plot
      p <- ggplot() + 
        geom_text(aes(x = 0, y = 0, label = "Database not connected"), size = 5) +
        theme_void()
      ggplotly(p)
    }
  })
  
  # Recent Documents Table
  output$recentDocuments <- DT::renderDataTable({
    if (database_connected && !is.null(values$analytics_data)) {
      data <- values$analytics_data$recent_documents
      
      if (nrow(data) > 0) {
        # Format the data for display
        display_data <- data %>%
          rename(
            "Title" = titulo,
            "Type" = tipo,
            "State" = estado,
            "Date" = data_publicacao
          ) %>%
          mutate(
            Date = as.Date(Date)
          )
        
        DT::datatable(
          display_data,
          options = list(
            pageLength = 10,
            scrollX = TRUE,
            searching = FALSE,
            paging = FALSE,
            info = FALSE,
            columnDefs = list(
              list(width = "50%", targets = 0),  # Title column wider
              list(width = "15%", targets = 1:3)  # Type, State, Date
            )
          ),
          rownames = FALSE
        )
      } else {
        # Show empty message
        empty_data <- data.frame(
          Message = "No recent documents found",
          stringsAsFactors = FALSE
        )
        DT::datatable(empty_data, options = list(searching = FALSE, paging = FALSE))
      }
    } else {
      # Show connection error message
      empty_data <- data.frame(
        Message = "Database not connected",
        stringsAsFactors = FALSE
      )
      DT::datatable(empty_data, options = list(searching = FALSE, paging = FALSE))
    }
  })
  
  # === Search History and Saved Searches Section ===
  
  # Render search history list
  output$searchHistoryList <- renderUI({
    history <- values$search_history
    
    if (length(history) == 0) {
      return(p("No search history yet", style = "color: #999;"))
    }
    
    # Create history items
    history_items <- lapply(seq_along(history), function(i) {
      search <- history[[i]]
      
      # Format search description
      desc_parts <- c()
      if (!is.null(search$search_text) && nchar(search$search_text) > 0) {
        desc_parts <- c(desc_parts, paste("Text:", search$search_text))
      }
      if (!is.null(search$document_types) && length(search$document_types) > 0) {
        desc_parts <- c(desc_parts, paste("Types:", paste(search$document_types, collapse = ", ")))
      }
      if (!is.null(search$states) && length(search$states) > 0) {
        desc_parts <- c(desc_parts, paste("States:", paste(search$states, collapse = ", ")))
      }
      if (!is.null(search$date_from) || !is.null(search$date_to)) {
        date_part <- "Dates:"
        if (!is.null(search$date_from)) date_part <- paste(date_part, search$date_from)
        if (!is.null(search$date_to)) date_part <- paste(date_part, "to", search$date_to)
        desc_parts <- c(desc_parts, date_part)
      }
      
      description <- if (length(desc_parts) > 0) {
        paste(desc_parts, collapse = " | ")
      } else {
        "All documents"
      }
      
      # Format timestamp
      time_ago <- difftime(Sys.time(), search$timestamp, units = "mins")
      if (time_ago < 60) {
        time_str <- paste(round(time_ago), "minutes ago")
      } else if (time_ago < 1440) {
        time_str <- paste(round(time_ago / 60), "hours ago")
      } else {
        time_str <- paste(round(time_ago / 1440), "days ago")
      }
      
      div(
        class = "history-item",
        style = "margin-bottom: 10px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; cursor: pointer;",
        onclick = paste0("Shiny.setInputValue('loadHistorySearch', ", i, ", {priority: 'event'})"),
        div(
          strong(description),
          style = "font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"
        ),
        div(
          time_str,
          style = "font-size: 11px; color: #666;"
        )
      )
    })
    
    do.call(tagList, history_items)
  })
  
  # Render saved searches list
  output$savedSearchesList <- renderUI({
    searches <- values$saved_searches
    
    if (length(searches) == 0) {
      return(p("No saved searches yet", style = "color: #999;"))
    }
    
    # Create saved search items
    search_items <- lapply(names(searches), function(name) {
      search <- searches[[name]]
      
      # Format search description
      desc_parts <- c()
      if (!is.null(search$search_text) && nchar(search$search_text) > 0) {
        desc_parts <- c(desc_parts, paste("Text:", search$search_text))
      }
      if (!is.null(search$document_types) && length(search$document_types) > 0) {
        desc_parts <- c(desc_parts, paste("Types:", paste(search$document_types, collapse = ", ")))
      }
      if (!is.null(search$states) && length(search$states) > 0) {
        desc_parts <- c(desc_parts, paste("States:", paste(search$states, collapse = ", ")))
      }
      
      description <- if (length(desc_parts) > 0) {
        paste(desc_parts, collapse = " | ")
      } else {
        "All documents"
      }
      
      div(
        class = "saved-search-item",
        style = "margin-bottom: 10px; padding: 8px; border: 1px solid #ddd; border-radius: 4px;",
        div(
          style = "display: flex; justify-content: space-between; align-items: center;",
          div(
            style = "flex: 1; cursor: pointer;",
            onclick = paste0("Shiny.setInputValue('loadSavedSearch', '", name, "', {priority: 'event'})"),
            div(
              strong(name),
              style = "font-size: 14px; color: #333;"
            ),
            div(
              description,
              style = "font-size: 11px; color: #666; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"
            )
          ),
          actionButton(
            inputId = paste0("deleteSaved_", gsub(" ", "_", name)),
            label = "",
            icon = icon("trash"),
            class = "btn-xs btn-danger",
            onclick = paste0("Shiny.setInputValue('deleteSavedSearch', '", name, "', {priority: 'event'})")
          )
        )
      )
    })
    
    do.call(tagList, search_items)
  })
  
  # Load search from history
  observeEvent(input$loadHistorySearch, {
    index <- as.numeric(input$loadHistorySearch)
    if (index <= length(values$search_history)) {
      search <- values$search_history[[index]]
      
      # Update search filters
      updateTextInput(session, "searchText", value = ifelse(is.null(search$search_text), "", search$search_text))
      updateSelectizeInput(session, "documentTypes", selected = search$document_types)
      updateSelectizeInput(session, "states", selected = search$states)
      updateDateInput(session, "dateFrom", value = search$date_from)
      updateDateInput(session, "dateTo", value = search$date_to)
      
      # Trigger search
      shinyjs::click("searchBtn")
    }
  })
  
  # Load saved search
  observeEvent(input$loadSavedSearch, {
    name <- input$loadSavedSearch
    if (name %in% names(values$saved_searches)) {
      search <- values$saved_searches[[name]]
      
      # Update search filters
      updateTextInput(session, "searchText", value = ifelse(is.null(search$search_text), "", search$search_text))
      updateSelectizeInput(session, "documentTypes", selected = search$document_types)
      updateSelectizeInput(session, "states", selected = search$states)
      updateDateInput(session, "dateFrom", value = search$date_from)
      updateDateInput(session, "dateTo", value = search$date_to)
      
      # Trigger search
      shinyjs::click("searchBtn")
    }
  })
  
  # Save current search
  observeEvent(input$saveSearchBtn, {
    # Get current search parameters
    search_text <- input$searchText
    doc_types <- input$documentTypes
    states_filter <- input$states
    date_from <- input$dateFrom
    date_to <- input$dateTo
    
    # Check if there are any search criteria
    if (nchar(search_text) > 0 || !is.null(doc_types) || !is.null(states_filter) || 
        !is.null(date_from) || !is.null(date_to)) {
      
      showModal(modalDialog(
        title = "Save Search",
        div(
          p("Save your current search criteria for quick access later."),
          textInput("saveSearchName", "Search Name:", placeholder = "Enter a descriptive name for this search"),
          div(class = "help-text", "Choose a name that will help you identify this search later.")
        ),
        footer = tagList(
          modalButton("Cancel"),
          actionButton("confirmSaveSearch", "Save Search", class = "btn-primary", icon = icon("save"))
        )
      ))
    } else {
      showNotification("Please enter search criteria before saving", type = "warning", duration = 3)
    }
  })
  
  # Confirm save search
  observeEvent(input$confirmSaveSearch, {
    name <- input$saveSearchName
    
    if (nchar(name) > 0) {
      # Disable save button during save
      shinyjs::disable("confirmSaveSearch")
      
      tryCatch({
        search_params <- list(
          search_text = input$searchText,
          document_types = input$documentTypes,
          states = input$states,
          date_from = input$dateFrom,
          date_to = input$dateTo
        )
        
        session_id <- session$token
        if (save_saved_search(search_params, name, session_id)) {
          # Reload saved searches
          values$saved_searches <- get_saved_searches(session_id)
          showNotification("Search saved successfully!", type = "success", duration = 3)
          removeModal()
        } else {
          showNotification("Error saving search - name may already exist", type = "error", duration = 5)
        }
      }, error = function(e) {
        showNotification(paste("Error saving search:", e$message), type = "error", duration = 5)
        cat("Save search error:", e$message, "\n")
      })
      
      # Re-enable save button
      shinyjs::enable("confirmSaveSearch")
    } else {
      showNotification("Please enter a name for the search", type = "warning", duration = 3)
    }
  })
  
  # Delete saved search
  observeEvent(input$deleteSavedSearch, {
    name <- input$deleteSavedSearch
    
    showModal(modalDialog(
      title = "Delete Saved Search",
      paste("Are you sure you want to delete the saved search '", name, "'?"),
      footer = tagList(
        modalButton("Cancel"),
        actionButton("confirmDeleteSearch", "Delete", class = "btn-danger", 
                    onclick = paste0("Shiny.setInputValue('confirmDeleteSearchName', '", name, "', {priority: 'event'})")),
        tags$script("$('#confirmDeleteSearch').click(function() { $('#confirmDeleteSearchName').val('', name); });")
      )
    ))
  })
  
  # Confirm delete saved search
  observeEvent(input$confirmDeleteSearchName, {
    name <- input$confirmDeleteSearchName
    session_id <- session$token
    
    tryCatch({
      if (delete_saved_search(name, session_id)) {
        # Reload saved searches
        values$saved_searches <- get_saved_searches(session_id)
        showNotification("Search deleted successfully", type = "success", duration = 3)
        removeModal()
      } else {
        showNotification("Error deleting search", type = "error", duration = 5)
      }
    }, error = function(e) {
      showNotification(paste("Error deleting search:", e$message), type = "error", duration = 5)
      cat("Delete search error:", e$message, "\n")
    })
  })
  
  # Clear search history
  observeEvent(input$clearHistoryBtn, {
    showModal(modalDialog(
      title = "Clear Search History",
      "Are you sure you want to clear all search history?",
      footer = tagList(
        modalButton("Cancel"),
        actionButton("confirmClearHistory", "Clear", class = "btn-danger")
      )
    ))
  })
  
  # Confirm clear history
  observeEvent(input$confirmClearHistory, {
    session_id <- session$token
    
    if (clear_search_history(session_id)) {
      values$search_history <- list()
      showNotification("Search history cleared", type = "success")
      removeModal()
    } else {
      showNotification("Error clearing search history", type = "error")
    }
  })
  
  # === Map Section ===
  
  # Reactive value for selected state filter
  selected_state <- reactiveVal(NULL)
  
  # Generate document map
  output$documentMap <- renderLeaflet({
    if (database_connected) {
      # Get state document counts (cached)
      state_counts <- cached_get_state_document_counts()
      
      # Generate the map
      map <- generate_document_map(state_counts)
      
      return(map)
    } else {
      # Return test map if no database
      return(generate_test_map())
    }
  })
  
  # Handle map click events
  observeEvent(input$documentMap_marker_click, {
    click <- input$documentMap_marker_click
    if (!is.null(click$id)) {
      selected_state(click$id)
      
      # Update the documents table with filtered data
      if (database_connected) {
        withProgress(message = paste('Loading documents for', click$id, '...'), value = 0, {
          tryCatch({
            incProgress(0.5, detail = "Filtering documents...")
            
            filtered_docs <- search_documents(states = click$id, limit = 50)
            values$current_documents <- filtered_docs
            
            incProgress(1, detail = "Filter applied successfully!")
            
            # Show success notification with document count
            doc_count <- if (!is.null(filtered_docs)) nrow(filtered_docs) else 0
            showNotification(
              paste("Showing", doc_count, "documents for state:", click$id),
              type = "info",
              duration = 3
            )
            
            # Navigate to documents tab to show filtered results
            updateTabItems(session, "sidebarMenu", selected = "documents")
          }, error = function(e) {
            showNotification(
              paste("Error filtering documents:", e$message),
              type = "error",
              duration = 5
            )
            cat("Map filter error:", e$message, "\n")
          })
        })
      }
    }
  })
  
  # Reset map filter
  observeEvent(input$resetMapFilter, {
    selected_state(NULL)
    
    # Reset documents to show all (cached)
    if (database_connected) {
      withProgress(message = 'Resetting filter...', value = 0, {
        tryCatch({
          incProgress(0.5, detail = "Loading all documents...")
          
          values$current_documents <- cached_get_documents(50)
          
          incProgress(1, detail = "Filter reset successfully!")
          
          showNotification("Filter reset - showing all documents", type = "info", duration = 3)
        }, error = function(e) {
          showNotification(
            paste("Error resetting filter:", e$message),
            type = "error",
            duration = 5
          )
          cat("Reset filter error:", e$message, "\n")
        })
      })
    } else {
      showNotification("Database not connected", type = "warning", duration = 3)
    }
  })
  
  # State statistics table
  output$stateStatsTable <- DT::renderDataTable({
    if (database_connected) {
      state_counts <- cached_get_state_document_counts()
      
      if (nrow(state_counts) > 0) {
        # Join with state names
        state_counts_with_names <- state_counts %>%
          left_join(brazil_states %>% select(estado, estado_nome), by = "estado") %>%
          select(estado, estado_nome, count) %>%
          rename(
            "State Code" = estado,
            "State Name" = estado_nome,
            "Document Count" = count
          )
        
        DT::datatable(
          state_counts_with_names,
          options = list(
            pageLength = 27,  # Show all Brazilian states
            scrollX = TRUE,
            columnDefs = list(
              list(width = "20%", targets = 0),
              list(width = "50%", targets = 1),
              list(width = "30%", targets = 2)
            )
          ),
          rownames = FALSE
        ) %>%
          formatCurrency("Document Count", currency = "", interval = 3, mark = ",", digits = 0)
      } else {
        # Empty data
        empty_data <- data.frame(
          Message = "No state data available",
          stringsAsFactors = FALSE
        )
        DT::datatable(empty_data, options = list(searching = FALSE, paging = FALSE))
      }
    } else {
      # Show connection error message
      empty_data <- data.frame(
        Message = "Database not connected",
        stringsAsFactors = FALSE
      )
      DT::datatable(empty_data, options = list(searching = FALSE, paging = FALSE))
    }
  })
  
  # === Cache Management Section ===
  
  # Periodic cache cleanup every 30 minutes
  observe({
    invalidateLater(1800000)  # 30 minutes in milliseconds
    cleanup_cache_files("data/cache", max_age_hours = 1)
  })
  
  # Periodic health check every 5 minutes
  observe({
    invalidateLater(300000)  # 5 minutes in milliseconds
    tryCatch({
      values$health_check_data <- perform_health_check()
      values$last_health_check <- Sys.time()
      log_health_check(values$health_check_data)
      
      # Store health check in history (keep last 20 checks)
      values$health_check_history <- c(values$health_check_history, list(values$health_check_data))
      if (length(values$health_check_history) > 20) {
        values$health_check_history <- values$health_check_history[(length(values$health_check_history) - 19):length(values$health_check_history)]
      }
    }, error = function(e) {
      cat("Periodic health check failed:", e$message, "\n")
    })
  })
  
  # Cache statistics output (updates every 30 seconds)
  output$cacheStats <- renderText({
    invalidateLater(30000)  # 30 seconds in milliseconds
    stats <- get_cache_stats()
    paste(
      "Memory Cache Entries:", stats$memory_cache_entries, "\n",
      "File Cache Entries:", stats$file_cache_entries, "\n",
      "File Cache Size:", stats$file_cache_size_mb, "MB\n",
      "Cache Directory:", stats$cache_directory, "\n",
      "Last Updated:", format(Sys.time(), "%Y-%m-%d %H:%M:%S")
    )
  })
  
  # Cache count outputs for system status box
  output$memoryCacheCount <- renderText({
    invalidateLater(30000)  # 30 seconds in milliseconds
    stats <- get_cache_stats()
    paste(stats$memory_cache_entries, "entries")
  })
  
  output$fileCacheCount <- renderText({
    invalidateLater(30000)  # 30 seconds in milliseconds
    stats <- get_cache_stats()
    paste(stats$file_cache_entries, "entries (", stats$file_cache_size_mb, "MB)")
  })
  
  # Health status text output
  output$healthStatusText <- renderText({
    if (!is.null(values$health_check_data)) {
      status <- values$health_check_data$overall_status
      # Update health indicator via JavaScript
      session$sendCustomMessage("updateHealthIndicator", status)
      paste("System", toupper(status))
    } else {
      "Checking..."
    }
  })
  
  # Clear cache button handler
  observeEvent(input$clearCacheBtn, {
    showModal(modalDialog(
      title = "Clear Cache",
      "Are you sure you want to clear all cached data? This will temporarily slow down the application until the cache is rebuilt.",
      footer = tagList(
        modalButton("Cancel"),
        actionButton("confirmClearCache", "Clear Cache", class = "btn-danger")
      )
    ))
  })
  
  # Confirm clear cache
  observeEvent(input$confirmClearCache, {
    # Disable cache buttons during clear
    shinyjs::disable("clearCacheBtn")
    shinyjs::disable("refreshCacheBtn")
    
    withProgress(message = 'Clearing cache...', value = 0, {
      tryCatch({
        incProgress(0.3, detail = "Clearing cache files...")
        clear_cache()
        
        incProgress(0.7, detail = "Refreshing data...")
        
        # Refresh analytics data if database is connected
        if (database_connected) {
          values$analytics_data <- cached_get_search_analytics()
          values$current_documents <- cached_get_documents(50)
        }
        
        incProgress(1, detail = "Cache cleared successfully!")
        showNotification("Cache cleared successfully!", type = "success", duration = 3)
        
        removeModal()
      }, error = function(e) {
        showNotification(paste("Error clearing cache:", e$message), type = "error", duration = 5)
        cat("Cache clear error:", e$message, "\n")
      })
    })
    
    # Re-enable cache buttons
    shinyjs::enable("clearCacheBtn")
    shinyjs::enable("refreshCacheBtn")
  })
  
  # Refresh cache button handler
  observeEvent(input$refreshCacheBtn, {
    if (database_connected) {
      # Disable cache buttons during refresh
      shinyjs::disable("refreshCacheBtn")
      shinyjs::disable("clearCacheBtn")
      
      withProgress(message = 'Refreshing cache...', value = 0, {
        tryCatch({
          incProgress(0.2, detail = "Clearing old cache...")
          
          # Clear cache first
          clear_cache()
          
          incProgress(0.5, detail = "Loading documents...")
          
          # Reload data with fresh cache
          values$current_documents <- cached_get_documents(50)
          
          incProgress(0.7, detail = "Loading analytics data...")
          values$analytics_data <- cached_get_search_analytics()
          
          incProgress(0.9, detail = "Updating filter options...")
          
          # Update filter choices
          updateSelectizeInput(session, "documentTypes", choices = cached_get_document_types())
          updateSelectizeInput(session, "states", choices = cached_get_states())
          
          incProgress(1, detail = "Cache refresh completed!")
          showNotification("Cache refreshed successfully!", type = "success", duration = 3)
        }, error = function(e) {
          showNotification(paste("Error refreshing cache:", e$message), type = "error", duration = 5)
          cat("Cache refresh error:", e$message, "\n")
        })
      })
      
      # Re-enable cache buttons
      shinyjs::enable("refreshCacheBtn")
      shinyjs::enable("clearCacheBtn")
    } else {
      showNotification("Database not connected - cannot refresh cache", type = "warning", duration = 3)
    }
  })
  
  # === Health Check Section ===
  
  # Health check value boxes
  output$healthOverallStatus <- renderValueBox({
    if (!is.null(values$health_check_data)) {
      status <- values$health_check_data$overall_status
      color <- switch(status,
        "healthy" = "green",
        "warning" = "yellow",
        "critical" = "red",
        "error" = "red"
      )
      icon_name <- switch(status,
        "healthy" = "check-circle",
        "warning" = "exclamation-triangle",
        "critical" = "times-circle",
        "error" = "times-circle"
      )
    } else {
      status <- "unknown"
      color <- "gray"
      icon_name <- "question-circle"
    }
    
    valueBox(
      value = toupper(status),
      subtitle = "Overall Status",
      icon = icon(icon_name),
      color = color
    )
  })
  
  output$healthDatabaseStatus <- renderValueBox({
    if (!is.null(values$health_check_data)) {
      status <- values$health_check_data$components$database$status
      color <- switch(status,
        "healthy" = "green",
        "warning" = "yellow",
        "critical" = "red",
        "error" = "red"
      )
    } else {
      status <- "unknown"
      color <- "gray"
    }
    
    valueBox(
      value = toupper(status),
      subtitle = "Database",
      icon = icon("database"),
      color = color
    )
  })
  
  output$healthCacheStatus <- renderValueBox({
    if (!is.null(values$health_check_data)) {
      status <- values$health_check_data$components$cache$status
      color <- switch(status,
        "healthy" = "green",
        "warning" = "yellow",
        "critical" = "red",
        "error" = "red"
      )
    } else {
      status <- "unknown"
      color <- "gray"
    }
    
    valueBox(
      value = toupper(status),
      subtitle = "Cache System",
      icon = icon("server"),
      color = color
    )
  })
  
  output$healthMemoryStatus <- renderValueBox({
    if (!is.null(values$health_check_data)) {
      status <- values$health_check_data$components$memory$status
      color <- switch(status,
        "healthy" = "green",
        "warning" = "yellow",
        "critical" = "red",
        "error" = "red"
      )
    } else {
      status <- "unknown"
      color <- "gray"
    }
    
    valueBox(
      value = toupper(status),
      subtitle = "Memory Usage",
      icon = icon("memory"),
      color = color
    )
  })
  
  # Health check detail outputs
  output$databaseHealthDetails <- renderText({
    if (!is.null(values$health_check_data)) {
      db_health <- values$health_check_data$components$database
      paste(
        "Status:", db_health$status, "\n",
        "Message:", db_health$message, "\n",
        "Timestamp:", db_health$timestamp, "\n",
        if (!is.null(db_health$document_count)) paste("Document Count:", db_health$document_count, "\n") else ""
      )
    } else {
      "No health check data available"
    }
  })
  
  output$cacheHealthDetails <- renderText({
    if (!is.null(values$health_check_data)) {
      cache_health <- values$health_check_data$components$cache
      paste(
        "Status:", cache_health$status, "\n",
        "Message:", cache_health$message, "\n",
        "Timestamp:", cache_health$timestamp, "\n",
        if (!is.null(cache_health$cache_stats)) {
          paste(
            "Memory Cache Entries:", cache_health$cache_stats$memory_cache_entries, "\n",
            "File Cache Entries:", cache_health$cache_stats$file_cache_entries, "\n",
            "File Cache Size:", cache_health$cache_stats$file_cache_size_mb, "MB\n"
          )
        } else ""
      )
    } else {
      "No health check data available"
    }
  })
  
  output$filesystemHealthDetails <- renderText({
    if (!is.null(values$health_check_data)) {
      fs_health <- values$health_check_data$components$filesystem
      paste(
        "Status:", fs_health$status, "\n",
        "Message:", fs_health$message, "\n",
        "Timestamp:", fs_health$timestamp, "\n",
        if (!is.null(fs_health$missing_directories)) {
          paste("Missing Directories:", paste(fs_health$missing_directories, collapse = ", "), "\n")
        } else ""
      )
    } else {
      "No health check data available"
    }
  })
  
  output$memoryHealthDetails <- renderText({
    if (!is.null(values$health_check_data)) {
      mem_health <- values$health_check_data$components$memory
      paste(
        "Status:", mem_health$status, "\n",
        "Message:", mem_health$message, "\n",
        "Timestamp:", mem_health$timestamp, "\n",
        if (!is.null(mem_health$used_memory_mb)) {
          paste(
            "Used Memory:", mem_health$used_memory_mb, "MB\n",
            "Max Memory:", mem_health$max_memory_mb, "MB\n"
          )
        } else ""
      )
    } else {
      "No health check data available"
    }
  })
  
  # Health check history output
  output$healthCheckHistory <- renderText({
    if (length(values$health_check_history) > 0) {
      history_text <- sapply(values$health_check_history, function(check) {
        paste0(
          "[", format(check$timestamp, "%H:%M:%S"), "] ",
          "Status: ", check$overall_status, 
          " (", check$check_duration_ms, "ms)"
        )
      })
      paste(rev(history_text), collapse = "\n")
    } else {
      "No health check history available"
    }
  })
  
  # Last health check time
  output$lastHealthCheckTime <- renderText({
    if (!is.null(values$last_health_check)) {
      format(values$last_health_check, "%Y-%m-%d %H:%M:%S")
    } else {
      "Never"
    }
  })
  
  # Health check duration
  output$healthCheckDuration <- renderText({
    if (!is.null(values$health_check_data)) {
      paste(values$health_check_data$check_duration_ms, "ms")
    } else {
      "N/A"
    }
  })
  
  # Health trends chart
  output$healthTrendsChart <- renderPlotly({
    if (length(values$health_check_history) > 0) {
      # Create trend data
      trend_data <- data.frame(
        timestamp = sapply(values$health_check_history, function(x) x$timestamp),
        status = sapply(values$health_check_history, function(x) x$overall_status),
        duration = sapply(values$health_check_history, function(x) x$check_duration_ms),
        stringsAsFactors = FALSE
      )
      
      # Convert status to numeric for plotting
      trend_data$status_numeric <- as.numeric(factor(trend_data$status, levels = c("healthy", "warning", "critical", "error")))
      trend_data$timestamp <- as.POSIXct(trend_data$timestamp)
      
      p <- ggplot(trend_data, aes(x = timestamp, y = status_numeric, color = status)) +
        geom_line(size = 1) +
        geom_point(size = 2) +
        scale_y_continuous(breaks = 1:4, labels = c("Healthy", "Warning", "Critical", "Error")) +
        scale_color_manual(values = c("healthy" = "green", "warning" = "orange", "critical" = "red", "error" = "red")) +
        theme_minimal() +
        labs(
          title = "Health Status Trends",
          x = "Time",
          y = "Status",
          color = "Status"
        )
      
      ggplotly(p, tooltip = c("x", "colour"))
    } else {
      # Empty plot
      p <- ggplot() + 
        geom_text(aes(x = 0, y = 0, label = "No health trend data available"), size = 5) +
        theme_void()
      ggplotly(p)
    }
  })
  
  # Manual health check button
  observeEvent(input$runHealthCheckBtn, {
    # Disable button during check
    shinyjs::disable("runHealthCheckBtn")
    
    withProgress(message = 'Running health check...', value = 0, {
      tryCatch({
        incProgress(0.3, detail = "Checking system health...")
        
        values$health_check_data <- perform_health_check()
        values$last_health_check <- Sys.time()
        log_health_check(values$health_check_data)
        
        # Add to history
        values$health_check_history <- c(values$health_check_history, list(values$health_check_data))
        if (length(values$health_check_history) > 20) {
          values$health_check_history <- values$health_check_history[(length(values$health_check_history) - 19):length(values$health_check_history)]
        }
        
        incProgress(1, detail = "Health check completed!")
        
        showNotification(
          paste("Health check completed! Status:", values$health_check_data$overall_status),
          type = if (values$health_check_data$overall_status == "healthy") "success" else "warning",
          duration = 3
        )
      }, error = function(e) {
        showNotification(paste("Health check failed:", e$message), type = "error", duration = 5)
        cat("Manual health check error:", e$message, "\n")
      })
    })
    
    # Re-enable button
    shinyjs::enable("runHealthCheckBtn")
  })
  
  # Refresh health status button (dashboard)
  observeEvent(input$refreshHealthBtn, {
    # Disable button during refresh
    shinyjs::disable("refreshHealthBtn")
    
    tryCatch({
      values$health_check_data <- perform_health_check()
      values$last_health_check <- Sys.time()
      log_health_check(values$health_check_data)
      
      showNotification("Health status refreshed!", type = "success", duration = 2)
    }, error = function(e) {
      showNotification(paste("Health refresh failed:", e$message), type = "error", duration = 5)
      cat("Health refresh error:", e$message, "\n")
    })
    
    # Re-enable button
    shinyjs::enable("refreshHealthBtn")
  })
  
  # Download health log button
  output$downloadHealthLogBtn <- downloadHandler(
    filename = function() {
      paste0("health_log_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".log")
    },
    content = function(file) {
      tryCatch({
        log_file <- file.path("logs", "health_check.log")
        if (file.exists(log_file)) {
          file.copy(log_file, file)
        } else {
          # Create empty log file
          writeLines("No health check logs available", file)
        }
      }, error = function(e) {
        writeLines(paste("Error accessing health log:", e$message), file)
      })
    }
  )
  
  # Clear health log button
  observeEvent(input$clearHealthLogBtn, {
    showModal(modalDialog(
      title = "Clear Health Log",
      "Are you sure you want to clear the health check log file?",
      footer = tagList(
        modalButton("Cancel"),
        actionButton("confirmClearHealthLog", "Clear Log", class = "btn-warning")
      )
    ))
  })
  
  # Confirm clear health log
  observeEvent(input$confirmClearHealthLog, {
    tryCatch({
      log_file <- file.path("logs", "health_check.log")
      if (file.exists(log_file)) {
        file.remove(log_file)
        showNotification("Health log cleared successfully!", type = "success", duration = 3)
      } else {
        showNotification("No health log file to clear", type = "info", duration = 3)
      }
      removeModal()
    }, error = function(e) {
      showNotification(paste("Error clearing health log:", e$message), type = "error", duration = 5)
      cat("Clear health log error:", e$message, "\n")
    })
  })
  
  # Clean up old export files on startup
  cleanup_old_exports()
  
  # Cleanup on session end
  session$onSessionEnded(function() {
    cleanup_database()
  })
}

# Print startup information
cat("=== Monitor Legislativo v4 with Database - Version 2.1 ===\n")
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

# Create a simple health endpoint wrapper
health_endpoint <- function(req, res) {
  if (grepl("^/health", req$PATH_INFO)) {
    tryCatch({
      health_data <- perform_health_check()
      status_code <- switch(health_data$overall_status,
        "healthy" = 200,
        "warning" = 200,
        "critical" = 503,
        "error" = 503
      )
      
      res$status <- status_code
      res$headers$`Content-Type` <- "application/json"
      res$body <- toJSON(health_data, pretty = TRUE, auto_unbox = TRUE)
    }, error = function(e) {
      res$status <- 500
      res$headers$`Content-Type` <- "application/json"
      res$body <- toJSON(list(
        overall_status = "error",
        message = paste("Health check failed:", e$message),
        timestamp = Sys.time()
      ), auto_unbox = TRUE)
    })
    return(res)
  }
  return(NULL)
}

# Run the application
cat("Starting Shiny app...\n")
cat("Health check endpoint available at /health\n")
app <- shinyApp(ui = ui, server = server)
runApp(app, host = "0.0.0.0", port = as.integer(Sys.getenv("PORT", "3838")), launch.browser = FALSE)