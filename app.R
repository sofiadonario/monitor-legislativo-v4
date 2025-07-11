# Monitor Legislativo v4 - R Shiny Application with Database
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
      menuItem("Search", tabName = "search", icon = icon("search")),
      menuItem("Analytics", tabName = "analytics", icon = icon("chart-bar")),
      menuItem("About", tabName = "about", icon = icon("info-circle"))
    )
  ),
  dashboardBody(
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
            )
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
            
            # Documents by State Map
            box(
              title = "Interactive Map - Documents by State", 
              status = "success", 
              solidHeader = TRUE, 
              width = 6,
              leafletOutput("stateMap", height = "300px")
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
        
        # About tab with system status
        tabItem(tabName = "about",
          fluidRow(
            # System Status
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
          ),
          if(database_connected) {
            fluidRow(
              # Document Types Distribution
              box(
                title = "Document Types Distribution", 
                status = "primary", 
                solidHeader = TRUE, 
                width = 12,
                DT::dataTableOutput("typeStats", height = "300px")
              )
            )
          }
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
  
  # Initialize data on startup
  observe({
    if (database_connected) {
      values$current_documents <- get_documents()  # Get all documents
      values$analytics_data <- get_search_analytics()  # Load analytics data
      
      # Load geographic data for map (use 2020 - latest available year)
      tryCatch({
        values$geographic_data <- load_brazil_geography(year = 2020, cache_data = TRUE)
      }, error = function(e) {
        cat("Error loading geographic data:", e$message, "\n")
        values$geographic_data <- NULL
      })
      
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
      status_color <- "blue"
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
  
  # Total states value box
  output$totalStates <- renderValueBox({
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
  
  # Total types value box
  output$totalTypes <- renderValueBox({
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
        # Ensure data is properly formatted
        data$count <- as.numeric(data$count)
        data$year <- as.numeric(data$year)
        
        # Remove any invalid years
        data <- data[!is.na(data$year) & !is.na(data$count), ]
        
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
  
  # Dashboard Map - Main Interactive Map
  output$dashboardMap <- renderLeaflet({
    if (database_connected && !is.null(values$analytics_data) && !is.null(values$geographic_data)) {
      data <- values$analytics_data$documents_by_state
      
      if (nrow(data) > 0 && !is.null(values$geographic_data)) {
        # Transform data to match map expectations
        map_data <- data %>%
          rename(documento_count = count) %>%
          select(estado, documento_count)
        
        # Create the legislative map
        map <- create_legislative_map(
          legislative_data = map_data,
          geography_data = values$geographic_data,
          focus_state = NULL,
          color_by = "count"
        )
        
        return(map)
      } else {
        # Show empty map with Brazil boundaries
        leaflet() %>%
          addTiles() %>%
          setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
          addControl(
            html = "<div style='padding: 10px; background: white; border-radius: 5px;'>
                    <b>No data available</b><br>
                    Geographic data is loading...
                    </div>",
            position = "topright"
          )
      }
    } else {
      # Show basic map when not connected
      leaflet() %>%
        addTiles() %>%
        setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
        addControl(
          html = "<div style='padding: 10px; background: white; border-radius: 5px;'>
                  <b>Database not connected</b><br>
                  Connect to see legislative data by state
                  </div>",
          position = "topright"
        )
    }
  })
  
  # Interactive Map - Documents by State (Analytics Tab)
  output$stateMap <- renderLeaflet({
    if (database_connected && !is.null(values$analytics_data) && !is.null(values$geographic_data)) {
      data <- values$analytics_data$documents_by_state
      
      if (nrow(data) > 0 && !is.null(values$geographic_data)) {
        # Transform data to match map expectations
        map_data <- data %>%
          rename(documento_count = count) %>%
          select(estado, documento_count)
        
        # Create the legislative map
        map <- create_legislative_map(
          legislative_data = map_data,
          geography_data = values$geographic_data,
          focus_state = NULL,
          color_by = "count"
        )
        
        return(map)
      } else {
        # Show empty map with Brazil boundaries
        leaflet() %>%
          addTiles() %>%
          setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
          addControl(
            html = "<div style='padding: 10px; background: white; border-radius: 5px;'>
                    <b>No data available</b><br>
                    Geographic data is loading...
                    </div>",
            position = "topright"
          )
      }
    } else {
      # Show basic map when not connected
      leaflet() %>%
        addTiles() %>%
        setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
        addControl(
          html = "<div style='padding: 10px; background: white; border-radius: 5px;'>
                  <b>Database not connected</b><br>
                  Connect to see legislative data by state
                  </div>",
          position = "topright"
        )
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
          scale_fill_brewer(palette = "Set3")
        
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