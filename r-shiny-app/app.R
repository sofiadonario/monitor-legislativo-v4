# Monitor Legislativo v4 - R Shiny Application with Database
# Railway Production Deployment - Connected to PostgreSQL with real data

library(shiny)
library(shinydashboard)
library(DT)
library(dplyr)
library(jsonlite)
library(plotly)
library(ggplot2)
library(shinyjs)
library(leaflet)

# Load database connection module
source("R/database_connection.R")
# Load map generator module
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
      id = "sidebarMenu",
      menuItem("Dashboard", tabName = "dashboard", icon = icon("dashboard")),
      menuItem("Documents", tabName = "documents", icon = icon("file-text")),
      menuItem("Search", tabName = "search", icon = icon("search")),
      menuItem("Analytics", tabName = "analytics", icon = icon("chart-bar")),
      menuItem("Map", tabName = "map", icon = icon("map"))
    )
  ),
  dashboardBody(
    useShinyjs(),
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
            width = 8,
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
                      actionButton("clearBtn", "Clear Filters", icon = icon("times"), class = "btn-secondary"),
                      " ",
                      actionButton("saveSearchBtn", "Save Search", icon = icon("star"), class = "btn-warning")
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
                actionButton("clearHistoryBtn", "Clear History", icon = icon("trash"), class = "btn-sm btn-danger"),
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
            
            # Documents by State Chart
            box(
              title = "Documents by State (Top 10)", 
              status = "success", 
              solidHeader = TRUE, 
              width = 6,
              plotlyOutput("stateChart", height = "300px")
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
                      actionButton("resetMapFilter", "Reset Filter", icon = icon("refresh"), class = "btn-secondary")
                    )
                  )
                ),
                hr(),
                leafletOutput("documentMap", height = "600px")
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
              DT::dataTableOutput("stateStatsTable")
            )
          )
        }
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
    saved_searches = list()
  )
  
  # Initialize data on startup
  observe({
    if (database_connected) {
      values$current_documents <- get_documents(50)  # Get first 50 documents
      values$analytics_data <- get_search_analytics()  # Load analytics data
      
      # Populate filter choices
      updateSelectizeInput(session, "documentTypes", choices = get_document_types())
      updateSelectizeInput(session, "states", choices = get_states())
    } else {
      values$current_documents <- sample_documents
    }
    
    # Load search history and saved searches
    session_id <- session$token
    values$search_history <- get_search_history(session_id)
    values$saved_searches <- get_saved_searches(session_id)
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
        textInput("saveSearchName", "Search Name:", placeholder = "Enter a name for this search"),
        footer = tagList(
          modalButton("Cancel"),
          actionButton("confirmSaveSearch", "Save", class = "btn-primary")
        )
      ))
    } else {
      showNotification("Please enter search criteria before saving", type = "warning")
    }
  })
  
  # Confirm save search
  observeEvent(input$confirmSaveSearch, {
    name <- input$saveSearchName
    
    if (nchar(name) > 0) {
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
        showNotification("Search saved successfully!", type = "success")
        removeModal()
      } else {
        showNotification("Error saving search", type = "error")
      }
    } else {
      showNotification("Please enter a name for the search", type = "warning")
    }
  })
  
  # Delete saved search
  observeEvent(input$deleteSavedSearch, {
    name <- input$deleteSavedSearch
    session_id <- session$token
    
    if (delete_saved_search(name, session_id)) {
      # Reload saved searches
      values$saved_searches <- get_saved_searches(session_id)
      showNotification("Search deleted successfully", type = "success")
    } else {
      showNotification("Error deleting search", type = "error")
    }
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
      # Get state document counts
      state_counts <- get_state_document_counts()
      
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
      showNotification(paste("Filtering documents for state:", click$id), type = "info")
      
      # Update the documents table with filtered data
      if (database_connected) {
        filtered_docs <- search_documents(states = click$id, limit = 50)
        values$current_documents <- filtered_docs
        
        # Navigate to documents tab to show filtered results
        updateTabItems(session, "sidebarMenu", selected = "documents")
      }
    }
  })
  
  # Reset map filter
  observeEvent(input$resetMapFilter, {
    selected_state(NULL)
    showNotification("Filter reset - showing all documents", type = "info")
    
    # Reset documents to show all
    if (database_connected) {
      values$current_documents <- get_documents(50)
    }
  })
  
  # State statistics table
  output$stateStatsTable <- DT::renderDataTable({
    if (database_connected) {
      state_counts <- get_state_document_counts()
      
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