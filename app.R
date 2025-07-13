# MackMonitor - R Shiny Application with Database
# Railway Production Deployment - Connected to PostgreSQL with real data

library(shiny)
library(shinydashboard)
library(DT)
library(dplyr)
library(jsonlite)
library(plotly)
library(ggplot2)
library(leaflet)
library(stringr)

# Load database connection module
source("R/database_connection.R")

# Load map generator module for geographic visualization
source("R/map_generator.R")

# Initialize database connection with force refresh
database_connected <- FALSE
database_error <- ""

cat("🔄 Attempting to initialize database connection with force refresh...\n")
cat("DATABASE_URL present:", nchar(Sys.getenv("DATABASE_URL")) > 0, "\n")
cat("DATABASE_URL length:", nchar(Sys.getenv("DATABASE_URL")), "\n")
if (nchar(Sys.getenv("DATABASE_URL")) > 0) {
  # Show partial URL for debugging (hide password)
  url_masked <- gsub(":[^:@]+@", ":***@", Sys.getenv("DATABASE_URL"))
  cat("DATABASE_URL (masked):", url_masked, "\n")
}

# Force refresh database connection to ensure we get latest data
database_connected <- init_database()

# If connection failed, try force refresh
if (!database_connected) {
  cat("⚠️ Initial connection failed, trying force refresh...\n")
  database_connected <- force_refresh_database()
}

if (!database_connected) {
  database_error <- "Failed to connect to database - using sample data"
  cat("⚠️", database_error, "\n")
  
  # Fallback sample data
  sample_documents <- data.frame(
    id = 1:10,
    titulo = paste("Sample Document", 1:10),
    tipo = sample(c("lei", "decreto", "portaria"), 10, replace = TRUE),
    estado = sample(c("SP", "RJ", "MG", "RS"), 10, replace = TRUE),
    enacting_date = Sys.Date() - sample(1:365, 10),
    url = paste0("https://example.com/doc/", 1:10),
    urn = paste0("urn:lex:br:sample:", 1:10),
    stringsAsFactors = FALSE
  )
} else {
  cat("✅ Database connected successfully!\n")
}

# UI with enhanced features and custom styling
ui <- dashboardPage(
  dashboardHeader(title = "MackMonitor"),
  dashboardSidebar(
    sidebarMenu(
      menuItem("Dashboard", tabName = "dashboard", icon = icon("dashboard")),
      menuItem("Documents", tabName = "documents", icon = icon("file-text")),
      menuItem("Search", tabName = "search", icon = icon("search")),
      menuItem("Analytics", tabName = "analytics", icon = icon("chart-bar")),
      menuItem("About", tabName = "about", icon = icon("info-circle"))
    )
  ),
  dashboardBody(
    # Custom CSS for color scheme
    tags$head(
      tags$style(HTML("
        /* Primary color #e1001e */
        .main-header .navbar { background-color: #e1001e !important; }
        .main-header .logo { background-color: #c50019 !important; }
        .main-header .logo:hover { background-color: #a80016 !important; }
        
        /* Sidebar styling */
        .skin-blue .main-sidebar { background-color: #fae6e8 !important; }
        .sidebar-menu > li.active > a { background-color: #e1001e !important; color: white !important; }
        .sidebar-menu > li:hover > a { background-color: #f0ccce !important; color: #e1001e !important; }
        .sidebar-menu > li > a { color: #8b0013 !important; }
        
        /* Box headers */
        .box.box-primary > .box-header { background-color: #e1001e !important; border-bottom-color: #c50019 !important; }
        .box.box-success > .box-header { background-color: #28a745 !important; }
        .box.box-warning > .box-header { background-color: #ffc107 !important; }
        .box.box-info > .box-header { background-color: #17a2b8 !important; }
        
        /* Buttons */
        .btn-primary { background-color: #e1001e !important; border-color: #c50019 !important; }
        .btn-primary:hover { background-color: #c50019 !important; border-color: #a80016 !important; }
        .btn-lg { padding: 10px 20px !important; }
        
        /* Value boxes */
        .small-box.bg-red { background-color: #e1001e !important; }
        .small-box.bg-blue { background-color: #d63384 !important; }
        .small-box.bg-green { background-color: #20c997 !important; }
        .small-box.bg-yellow { background-color: #fd7e14 !important; }
        .small-box.bg-purple { background-color: #6f42c1 !important; }
        
        /* Links and accents */
        a { color: #e1001e !important; }
        a:hover { color: #c50019 !important; }
        
        /* Progress bars */
        .progress-bar { background-color: #e1001e !important; }
        
        /* Active tab styling */
        .nav-tabs-custom > .nav-tabs > li.active { border-top-color: #e1001e !important; }
      "))
    ),
    tabItems(
      # Dashboard tab with interactive map and overview
      tabItem(tabName = "dashboard",
        fluidRow(
          # Document Overview Bar
          box(
            title = "Document Overview", 
            status = "primary", 
            solidHeader = TRUE, 
            width = 12,
            height = "120px",
            fluidRow(
              column(3, valueBoxOutput("totalDocs", width = NULL)),
              column(3, valueBoxOutput("totalStates", width = NULL)),
              column(3, valueBoxOutput("totalTypes", width = NULL)),
              column(3, valueBoxOutput("dateRange", width = NULL))
            ),
            # Add refresh button
            if(database_connected) {
              div(
                style = "text-align: center; margin-top: 10px;",
                actionButton("refreshData", "🔄 Refresh Data", class = "btn-primary btn-sm")
              )
            }
          )
        ),
        fluidRow(
          # Interactive Map - Main Feature
          box(
            title = "Interactive Map - Legislative Documents by State", 
            status = "success", 
            solidHeader = TRUE, 
            width = 12,
            height = "600px",
            if(database_connected) {
              leafletOutput("dashboardMap", height = "550px")
            } else {
              div(
                class = "alert alert-warning",
                style = "text-align: center; margin-top: 200px;",
                h4(icon("database"), " Database Connection Required"),
                p("Connect to the database to see the interactive legislative map."),
                p("Check the About tab for connection details.")
              )
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
                    valueBoxOutput("analyticsTotal", width = NULL)
                  ),
                  column(3,
                    valueBoxOutput("analyticsStates", width = NULL)
                  ),
                  column(3,
                    valueBoxOutput("analyticsTypes", width = NULL)
                  ),
                  column(3,
                    valueBoxOutput("analyticsDateRange", width = NULL)
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
              plotlyOutput("yearChart", height = "300px")
            ),
            
            # Documents by Month Chart (Last 12 Months)
            box(
              title = "Documents by Month (Last 12 Months)", 
              status = "success", 
              solidHeader = TRUE, 
              width = 6,
              plotlyOutput("monthChart", height = "300px")
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
              plotlyOutput("typeChart", height = "300px")
            ),
            
            # Recent Documents
            box(
              title = "Recent Documents (Last 30 days)", 
              status = "info", 
              solidHeader = TRUE, 
              width = 6,
              DT::dataTableOutput("recentDocuments", height = "300px")
            )
          )
        },
        if(database_connected) {
          fluidRow(
            # Document Types Distribution Table
            box(
              title = "Document Types Distribution - Detailed View", 
              status = "primary", 
              solidHeader = TRUE, 
              width = 12,
              DT::dataTableOutput("typeStats", height = "300px")
            )
          )
        }
      ),
      
      # About tab with system status  
      tabItem(tabName = "about",
          fluidRow(
            # System Status
            box(
              title = "System Status", 
              status = if(database_connected) "success" else "warning", 
              solidHeader = TRUE, 
              width = 6,
              h4("MackMonitor"),
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
                  verbatimTextOutput("dbStats"),
                  hr(),
                  h5("Debug Information:"),
                  verbatimTextOutput("debugInfo")
                )
              }
            ),
            
            # Application Information
            box(
              title = "Application Information", 
              status = "info", 
              solidHeader = TRUE, 
              width = 6,
              h5("Version Information:"),
              p(strong("Version: "), "4.0 - Unified R-Shiny Service"),
              p(strong("Platform: "), "Railway Cloud Platform"),
              p(strong("Database: "), "PostgreSQL with Redis Cache"),
              p(strong("Geographic Data: "), "IBGE via geobr package"),
              br(),
              h5("Features:"),
              tags$ul(
                tags$li("Interactive Brazilian legislative map"),
                tags$li("Advanced document search with filters"),
                tags$li("Real-time analytics and visualizations"),
                tags$li("Document type and state-based filtering"),
                tags$li("Responsive design for all devices")
              )
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
    geographic_data = NULL
  )
  
  # Initialize data on startup with force refresh
  observe({
    cat("🔄 Initializing application data with force refresh...\n")
    
    if (database_connected && !is.null(db_pool)) {
      # Force refresh to ensure we get latest data
      cat("🔄 Force refreshing database queries...\n")
      
      # Get documents with debug logging
      cat("🔄 Loading documents...\n")
      values$current_documents <- get_documents()  # Get all documents
      cat("📊 Loaded", ifelse(is.null(values$current_documents), 0, nrow(values$current_documents)), "documents\n")
      
      # Get analytics data
      cat("🔄 Loading analytics data...\n")
      values$analytics_data <- get_search_analytics()  # Load analytics data
      cat("📊 Analytics data loaded\n")
      
      # Load geographic data for map (use 2020 - latest available year)
      tryCatch({
        cat("🔄 Loading geographic data...\n")
        values$geographic_data <- load_brazil_geography(year = 2020, cache_data = TRUE)
        cat("📊 Geographic data loaded\n")
      }, error = function(e) {
        cat("Error loading geographic data:", e$message, "\n")
        cat("🔄 Creating simple fallback map...\n")
        values$geographic_data <- NULL
      })
      
      # Populate filter choices
      cat("🔄 Populating filter choices...\n")
      updateSelectizeInput(session, "documentTypes", choices = get_document_types())
      updateSelectizeInput(session, "states", choices = get_states())
      cat("✅ Application initialization complete\n")
      
      # Force UI refresh by triggering reactive updates
      cat("🔄 Triggering UI refresh...\n")
      invalidateLater(1000)  # Force refresh after 1 second
    } else {
      cat("⚠️ Database not connected or pool is NULL. Database connected:", database_connected, "Pool exists:", !is.null(db_pool), "\n")
      if (database_connected && is.null(db_pool)) {
        cat("🔄 Attempting to reinitialize database pool...\n")
        # Try to reinitialize the database pool
        tryCatch({
          force_refresh_database()
          # Wait a moment and try again
          invalidateLater(2000)
        }, error = function(e) {
          cat("❌ Failed to reinitialize database pool:", e$message, "\n")
        })
      }
      values$current_documents <- sample_documents
    }
  })
  
  # Add reactive trigger to force UI updates
  observe({
    # This will trigger whenever current_documents changes
    if (!is.null(values$current_documents)) {
      cat("🔄 UI refresh triggered - documents count:", nrow(values$current_documents), "\n")
      # Force all UI components to refresh
      invalidateLater(500)
    }
  })
  
  # Database statistics
  output$dbStats <- renderText({
    if (database_connected && !is.null(db_pool)) {
      tryCatch({
        stats <- get_document_stats()
        paste(
          "Total Documents:", stats$total_documents, "\n",
          "Connection Status:", stats$connection_status
        )
      }, error = function(e) {
        paste(
          "Total Documents: 0\n",
          "Connection Status: Error -", e$message
        )
      })
    } else {
      paste(
        "Total Documents: 0\n",
        "Connection Status: No database connection"
      )
    }
  })
  
  # Debug information
  output$debugInfo <- renderText({
    if (database_connected && !is.null(db_pool)) {
      # Get actual query results for debugging
      tryCatch({
        # Test direct query to see what's actually in the database
        conn <- poolCheckout(db_pool)
        on.exit(poolReturn(conn))
        
        # Check documents table
        doc_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")$count
        doc_with_titles <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents WHERE titulo IS NOT NULL")$count
        
        # Check for Amazonas specifically
        amazonas_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents WHERE estado = 'Amazonas'")$count
        
        # Check for the corrected table
        corrected_count <- tryCatch({
          dbGetQuery(conn, "SELECT COUNT(*) as count FROM lexml_parsed_enhanced_fixed")$count
        }, error = function(e) {
          "Table not found"
        })
        
        paste(
          "=== DEBUG INFORMATION ===\n",
          "Documents table total:", doc_count, "\n",
          "Documents with titles:", doc_with_titles, "\n",
          "Amazonas documents:", amazonas_count, "\n",
          "Corrected table count:", corrected_count, "\n",
          "Current documents loaded:", ifelse(is.null(values$current_documents), 0, nrow(values$current_documents)), "\n",
          "Analytics data loaded:", ifelse(is.null(values$analytics_data), "No", "Yes"), "\n",
          "Database pool active:", !is.null(db_pool), "\n",
          "Force refresh enabled:", FORCE_REFRESH, "\n",
          "Time:", Sys.time()
        )
      }, error = function(e) {
        paste("Error getting debug info:", e$message)
      })
    } else {
      paste(
        "Database not connected - no debug info available\n",
        "Database connected:", database_connected, "\n",
        "Database pool exists:", !is.null(db_pool), "\n",
        "Current documents loaded:", ifelse(is.null(values$current_documents), 0, nrow(values$current_documents))
      )
    }
  })
  
  # Total documents value box - with reactive trigger
  output$totalDocs <- renderValueBox({
    # Force reactive update by checking current documents
    current_count <- ifelse(is.null(values$current_documents), 0, nrow(values$current_documents))
    
    if (database_connected && !is.null(db_pool)) {
      # Use direct database query for accurate count
      tryCatch({
        conn <- poolCheckout(db_pool)
        on.exit(poolReturn(conn))
        count <- as.numeric(dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")$count)
        status_color <- "green"
      }, error = function(e) {
        count <- current_count
        status_color <- "red"
      })
    } else {
      count <- current_count
      status_color <- "yellow"
    }
    
    valueBox(
      value = count,
      subtitle = "Total Documents",
      icon = icon("file-text"),
      color = status_color
    )
  })
  
  # Total states value box - with reactive trigger
  output$totalStates <- renderValueBox({
    # Force reactive update by checking current documents
    current_count <- ifelse(is.null(values$current_documents), 0, nrow(values$current_documents))
    
    if (database_connected && !is.null(db_pool)) {
      # Use direct database query for accurate count
      tryCatch({
        conn <- poolCheckout(db_pool)
        on.exit(poolReturn(conn))
        count <- as.numeric(dbGetQuery(conn, "SELECT COUNT(DISTINCT estado) as count FROM documents WHERE estado IS NOT NULL AND estado != ''")$count)
        status_color <- "green"
      }, error = function(e) {
        count <- ifelse(is.null(values$analytics_data), 0, nrow(values$analytics_data$documents_by_state))
        status_color <- "red"
      })
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
  
  # Total types value box - with reactive trigger
  output$totalTypes <- renderValueBox({
    # Force reactive update by checking current documents
    current_count <- ifelse(is.null(values$current_documents), 0, nrow(values$current_documents))
    
    if (database_connected && !is.null(db_pool)) {
      # Use direct database query for accurate count
      tryCatch({
        conn <- poolCheckout(db_pool)
        on.exit(poolReturn(conn))
        count <- as.numeric(dbGetQuery(conn, "SELECT COUNT(DISTINCT tipo) as count FROM documents WHERE tipo IS NOT NULL AND tipo != ''")$count)
        status_color <- "yellow"
      }, error = function(e) {
        count <- ifelse(is.null(values$analytics_data), 0, nrow(values$analytics_data$documents_by_type))
        status_color <- "red"
      })
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
  
  # Date range value box
  output$dateRange <- renderValueBox({
    if (database_connected && !is.null(values$analytics_data)) {
      min_date <- values$analytics_data$date_range$min
      max_date <- values$analytics_data$date_range$max
      if (!is.na(min_date) && !is.na(max_date)) {
        years <- as.numeric(format(max_date, "%Y")) - as.numeric(format(min_date, "%Y"))
        value <- years
        subtitle <- paste(years, "Years")
        status_color <- "purple"
      } else {
        value <- "N/A"
        subtitle <- "Date Range"
        status_color <- "red"
      }
    } else {
      value <- "N/A"
      subtitle <- "Date Range"
      status_color <- "red"
    }
    
    valueBox(
      value = value,
      subtitle = subtitle,
      icon = icon("calendar"),
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
      select(titulo, tipo, estado, enacting_date, urn) %>%
      rename(
        "Title" = titulo,
        "Type" = tipo, 
        "State" = estado,
        "Enacting Date" = enacting_date,
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
  
  # Refresh data functionality
  observeEvent(input$refreshData, {
    if (database_connected && !is.null(db_pool)) {
      cat("🔄 Manual refresh triggered by user...\n")
      
      # Force refresh database connection
      force_refresh_database()
      
      # Reload all data
      withProgress(message = 'Refreshing data...', value = 0, {
        incProgress(0.3)
        
        # Reload documents
        values$current_documents <- get_documents()
        cat("📊 Reloaded", ifelse(is.null(values$current_documents), 0, nrow(values$current_documents)), "documents\n")
        
        incProgress(0.3)
        
        # Reload analytics
        values$analytics_data <- get_search_analytics()
        cat("📊 Reloaded analytics data\n")
        
        incProgress(0.3)
        
        # Reload geographic data
        tryCatch({
          values$geographic_data <- load_brazil_geography(year = 2020, cache_data = TRUE)
          cat("📊 Reloaded geographic data\n")
        }, error = function(e) {
          cat("Error reloading geographic data:", e$message, "\n")
        })
        
        incProgress(1)
      })
      
      # Show success message
      showNotification("Data refreshed successfully!", type = "success")
    } else {
      cat("⚠️ Cannot refresh - database not connected or pool is NULL\n")
      cat("Database connected:", database_connected, "Pool exists:", !is.null(db_pool), "\n")
      
      # Try to reinitialize database
      if (database_connected && is.null(db_pool)) {
        cat("🔄 Attempting to reinitialize database pool...\n")
        tryCatch({
          force_refresh_database()
          showNotification("Database reconnected! Please refresh again.", type = "info")
        }, error = function(e) {
          showNotification(paste("Failed to reconnect database:", e$message), type = "error")
        })
      } else {
        showNotification("Database not connected!", type = "error")
      }
    }
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
        select(titulo, tipo, estado, enacting_date, urn) %>%
        rename(
          "Title" = titulo,
          "Type" = tipo,
          "State" = estado, 
          "Enacting Date" = enacting_date,
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
  
  # === Analytics Section ===
  
  # Analytics value boxes - with direct database queries
  output$analyticsTotal <- renderValueBox({
    # Force reactive update by checking current documents
    current_count <- ifelse(is.null(values$current_documents), 0, nrow(values$current_documents))
    
    if (database_connected && !is.null(db_pool)) {
      # Use direct database query for accurate count
      tryCatch({
        conn <- poolCheckout(db_pool)
        on.exit(poolReturn(conn))
        count <- as.numeric(dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")$count)
        status_color <- "green"
      }, error = function(e) {
        count <- current_count
        status_color <- "red"
      })
    } else {
      count <- current_count
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
    # Force reactive update by checking current documents
    current_count <- ifelse(is.null(values$current_documents), 0, nrow(values$current_documents))
    
    if (database_connected && !is.null(db_pool)) {
      # Use direct database query for accurate count
      tryCatch({
        conn <- poolCheckout(db_pool)
        on.exit(poolReturn(conn))
        count <- as.numeric(dbGetQuery(conn, "SELECT COUNT(DISTINCT estado) as count FROM documents WHERE estado IS NOT NULL AND estado != ''")$count)
        status_color <- "green"
      }, error = function(e) {
        count <- ifelse(is.null(values$analytics_data), 0, nrow(values$analytics_data$documents_by_state))
        status_color <- "red"
      })
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
    # Force reactive update by checking current documents
    current_count <- ifelse(is.null(values$current_documents), 0, nrow(values$current_documents))
    
    if (database_connected && !is.null(db_pool)) {
      # Use direct database query for accurate count
      tryCatch({
        conn <- poolCheckout(db_pool)
        on.exit(poolReturn(conn))
        count <- as.numeric(dbGetQuery(conn, "SELECT COUNT(DISTINCT tipo) as count FROM documents WHERE tipo IS NOT NULL AND tipo != ''")$count)
        status_color <- "yellow"
      }, error = function(e) {
        count <- ifelse(is.null(values$analytics_data), 0, nrow(values$analytics_data$documents_by_type))
        status_color <- "red"
      })
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
        # Ensure data is properly formatted
        data$count <- as.numeric(data$count)
        data$year <- as.numeric(data$year)
        
        # Remove any invalid years
        data <- data[!is.na(data$year) & !is.na(data$count), ]
        
        if (nrow(data) > 0) {
          p <- ggplot(data, aes(x = year, y = count)) +
            geom_line(color = "#e1001e", size = 1.2) +
            geom_point(color = "#c50019", size = 3) +
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
            geom_text(aes(x = 0, y = 0, label = "No valid data available"), size = 5) +
            theme_void()
          ggplotly(p)
        }
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
  
  # Dashboard Map - Simplified map rendering using cached data
  output$dashboardMap <- renderLeaflet({
    cat("🔄 Dashboard map rendering triggered\n")
    
    # Use cached documents data instead of direct database queries
    if (!is.null(values$current_documents) && nrow(values$current_documents) > 0) {
      cat("🔄 Using cached documents data:", nrow(values$current_documents), "documents\n")
      
      # Aggregate data by state using cached documents
      tryCatch({
        # Get state data with estado_codigo if available
        if ("estado_codigo" %in% names(values$current_documents)) {
          map_data <- values$current_documents %>%
            filter(!is.na(estado), estado != '', !is.na(estado_codigo), estado_codigo != '') %>%
            group_by(estado, estado_codigo) %>%
            summarise(documento_count = n(), .groups = "drop") %>%
            arrange(desc(documento_count))
        } else {
          map_data <- values$current_documents %>%
            filter(!is.na(estado), estado != '') %>%
            group_by(estado) %>%
            summarise(documento_count = n(), .groups = "drop") %>%
            arrange(desc(documento_count))
        }
        
        cat("🔄 Map data aggregated:", nrow(map_data), "states\n")
        cat("🔄 Total documents for map:", sum(map_data$documento_count), "\n")
        
        if (nrow(map_data) > 0) {
          # Create map with geographic data if available
          if (!is.null(values$geographic_data)) {
            cat("🔄 Creating map with geographic boundaries\n")
            
            map <- create_legislative_map(
              legislative_data = map_data,
              geography_data = values$geographic_data,
              focus_state = NULL,
              color_by = "count"
            )
            
            # If map creation succeeds, return it
            if (!is.null(map)) {
              cat("✅ Map with boundaries created successfully\n")
              return(map)
            }
          }
          
          # Fallback: create simple map with data overlay
          cat("🔄 Creating fallback map with data overlay\n")
          leaflet() %>%
            addTiles() %>%
            setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
            addControl(
              html = paste0(
                "<div style='padding: 10px; background: white; border-radius: 5px; max-width: 300px;'>",
                "<h4>Legislative Documents by State</h4>",
                "<strong>Total Documents:</strong> ", sum(map_data$documento_count), "<br>",
                "<strong>Total States:</strong> ", nrow(map_data), "<br><br>",
                "<strong>Top 10 States:</strong><br>",
                paste(head(map_data, 10)$estado, ": ", head(map_data, 10)$documento_count, collapse = "<br>"),
                "</div>"
              ),
              position = "topright"
            )
        } else {
          # No data available
          leaflet() %>%
            addTiles() %>%
            setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
            addControl(
              html = "<div style='padding: 10px; background: white; border-radius: 5px;'>
                      <b>No state data available</b><br>
                      No documents found in database
                      </div>",
              position = "topright"
            )
        }
      }, error = function(e) {
        cat("❌ Error processing map data:", e$message, "\n")
        
        # Error fallback map
        leaflet() %>%
          addTiles() %>%
          setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
          addControl(
            html = paste0(
              "<div style='padding: 10px; background: white; border-radius: 5px;'>",
              "<b>Map Error</b><br>",
              "Error: ", e$message,
              "</div>"
            ),
            position = "topright"
          )
      })
    } else {
      # No cached data available
      cat("⚠️ No cached documents data available\n")
      leaflet() %>%
        addTiles() %>%
        setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
        addControl(
          html = "<div style='padding: 10px; background: white; border-radius: 5px;'>
                  <b>Loading data...</b><br>
                  Please wait while data loads
                  </div>",
          position = "topright"
        )
    }
  })
  
  # Documents by Month Chart (Last 12 Months)
  output$monthChart <- renderPlotly({
    if (database_connected && !is.null(values$analytics_data)) {
      data <- values$analytics_data$documents_by_month
      
      if (nrow(data) > 0) {
        # Ensure data is properly formatted
        data$count <- as.numeric(data$count)
        data$year <- as.numeric(data$year)
        data$month <- as.numeric(data$month)
        
        # Create month labels for better display
        month_names <- c("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        
        data <- data %>%
          mutate(
            month_label = month_names[month],
            year_month_label = paste(month_label, year),
            date_for_sort = as.Date(paste(year, month, "01", sep = "-"))
          ) %>%
          arrange(date_for_sort) %>%
          mutate(year_month_label = factor(year_month_label, levels = year_month_label))
        
        # Remove any invalid data
        data <- data[!is.na(data$year) & !is.na(data$month) & !is.na(data$count), ]
        
        if (nrow(data) > 0) {
          p <- ggplot(data, aes(x = year_month_label, y = count, group = 1)) +
            geom_line(color = "#2ecc71", size = 1.2) +
            geom_point(color = "#27ae60", size = 3) +
            theme_minimal() +
            labs(
              title = "Documents Published by Month",
              x = "Month",
              y = "Number of Documents"
            ) +
            theme(
              plot.title = element_text(size = 14, face = "bold"),
              axis.title = element_text(size = 12),
              axis.text = element_text(size = 10),
              axis.text.x = element_text(angle = 45, hjust = 1)
            )
          
          ggplotly(p, tooltip = c("x", "y"))
        } else {
          # Empty plot
          p <- ggplot() + 
            geom_text(aes(x = 0, y = 0, label = "No valid monthly data available"), size = 5) +
            theme_void()
          ggplotly(p)
        }
      } else {
        # Empty plot
        p <- ggplot() + 
          geom_text(aes(x = 0, y = 0, label = "No monthly data available"), size = 5) +
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
        # Ensure data is properly formatted
        data$count <- as.numeric(data$count)
        data$tipo <- as.character(data$tipo)
        
        # Create a simple bar chart instead of pie chart to avoid plotly issues
        p <- ggplot(data, aes(x = reorder(tipo, count), y = count, fill = tipo)) +
          geom_bar(stat = "identity") +
          coord_flip() +
          theme_minimal() +
          labs(
            title = "Documents by Type",
            x = "Document Type",
            y = "Count"
          ) +
          theme(
            plot.title = element_text(size = 14, face = "bold"),
            legend.position = "none"
          ) +
          scale_fill_manual(values = c("#e1001e", "#f5737a", "#fbb3b8", "#c50019", "#a80016", "#8b0013"))
        
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
            "Enacting Date" = enacting_date
          ) %>%
          mutate(
            `Enacting Date` = as.Date(`Enacting Date`)
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
  
  # Cleanup on session end
  session$onSessionEnded(function() {
    cleanup_database()
  })
}

# Print startup information
cat("=== MackMonitor with Database - Version 2.0 ===\n")
cat("Starting MackMonitor Shiny application...\n")
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