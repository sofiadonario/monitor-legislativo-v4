# Enhanced Geographic UI Module
# Implements progressive loading and improved user experience

library(shiny)
library(shinydashboard)
library(shinyWidgets)

# Geographic Analysis UI
geographic_ui_enhanced <- function(id) {
  ns <- NS(id)
  
  tagList(
    # Custom CSS for better styling
    tags$head(
      tags$style(HTML("
        .geographic-container {
          padding: 15px;
        }
        .map-container {
          min-height: 500px;
          border: 1px solid #ddd;
          border-radius: 4px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          position: relative;
        }
        .map-loading {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          text-align: center;
          color: white;
        }
        .stats-card {
          background: white;
          border-radius: 8px;
          padding: 20px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          margin-bottom: 20px;
        }
        .filter-panel {
          background: #f8f9fa;
          border-radius: 8px;
          padding: 15px;
          margin-bottom: 20px;
        }
        .performance-indicator {
          position: absolute;
          top: 10px;
          right: 10px;
          background: rgba(255,255,255,0.9);
          padding: 5px 10px;
          border-radius: 4px;
          font-size: 12px;
        }
      "))
    ),
    
    # Header with title and controls
    fluidRow(
      column(12,
        div(class = "geographic-container",
          h2("Geographic Analysis Dashboard", 
             style = "color: #2c3e50; margin-bottom: 20px;"),
          
          # Performance indicators
          fluidRow(
            valueBoxOutput(ns("total_states_box")),
            valueBoxOutput(ns("total_documents_box")),
            valueBoxOutput(ns("most_active_state_box")),
            valueBoxOutput(ns("data_freshness_box"))
          )
        )
      )
    ),
    
    # Filter panel
    fluidRow(
      column(12,
        div(class = "filter-panel",
          h4("Filters & Controls", style = "margin-bottom: 15px;"),
          fluidRow(
            column(3,
              selectInput(
                ns("date_range_filter"),
                "Date Range",
                choices = list(
                  "Last 7 days" = "week",
                  "Last 30 days" = "month",
                  "Last 90 days" = "quarter",
                  "Last year" = "year",
                  "All time" = "all"
                ),
                selected = "month"
              )
            ),
            column(3,
              selectizeInput(
                ns("category_filter"),
                "Categories",
                choices = NULL,
                multiple = TRUE,
                options = list(
                  placeholder = "Select categories...",
                  maxItems = 5
                )
              )
            ),
            column(3,
              selectizeInput(
                ns("state_filter"),
                "States",
                choices = NULL,
                multiple = TRUE,
                options = list(
                  placeholder = "Select states...",
                  maxItems = 10
                )
              )
            ),
            column(3,
              div(style = "padding-top: 25px;",
                actionButton(
                  ns("refresh_data"),
                  "Refresh Data",
                  icon = icon("sync"),
                  class = "btn-primary",
                  width = "100%"
                )
              )
            )
          ),
          
          # Advanced options
          fluidRow(
            column(12,
              div(style = "margin-top: 15px;",
                checkboxGroupInput(
                  ns("display_options"),
                  "Display Options",
                  choices = list(
                    "Enable WebGL acceleration" = "webgl",
                    "Show confidence intervals" = "confidence",
                    "Display sampling info" = "sampling",
                    "Auto-refresh (5 min)" = "autorefresh"
                  ),
                  selected = c("webgl"),
                  inline = TRUE
                )
              )
            )
          )
        )
      )
    ),
    
    # Main content area
    fluidRow(
      # Map column
      column(8,
        div(class = "stats-card",
          h4("Geographic Distribution", style = "margin-bottom: 15px;"),
          
          # Progress bar for loading
          conditionalPanel(
            condition = paste0("output['", ns("map_loading"), "'] == true"),
            div(class = "map-loading",
              h4("Loading geographic data..."),
              progressBar(
                id = ns("map_progress"),
                value = 0,
                display_pct = TRUE,
                striped = TRUE,
                animated = TRUE
              )
            )
          ),
          
          # Map container
          div(class = "map-container",
            plotlyOutput(ns("geographic_map"), height = "500px"),
            
            # Performance indicator
            div(class = "performance-indicator",
              textOutput(ns("performance_stats"))
            )
          ),
          
          # Map controls
          div(style = "margin-top: 15px;",
            fluidRow(
              column(4,
                sliderInput(
                  ns("sample_size"),
                  "Sample Size",
                  min = 1000,
                  max = 20000,
                  value = 5000,
                  step = 1000
                )
              ),
              column(4,
                radioButtons(
                  ns("map_type"),
                  "Map Type",
                  choices = list(
                    "Choropleth" = "choropleth",
                    "Scatter" = "scatter",
                    "Heatmap" = "heatmap"
                  ),
                  selected = "choropleth",
                  inline = TRUE
                )
              ),
              column(4,
                div(style = "padding-top: 25px;",
                  downloadButton(
                    ns("download_map"),
                    "Export Map",
                    class = "btn-success",
                    style = "width: 100%;"
                  )
                )
              )
            )
          )
        )
      ),
      
      # Statistics column
      column(4,
        # State ranking table
        div(class = "stats-card",
          h4("State Rankings", style = "margin-bottom: 15px;"),
          DT::dataTableOutput(ns("state_ranking_table"))
        ),
        
        # Summary statistics
        div(class = "stats-card",
          h4("Summary Statistics", style = "margin-bottom: 15px;"),
          uiOutput(ns("summary_stats"))
        ),
        
        # Data quality indicators
        div(class = "stats-card",
          h4("Data Quality", style = "margin-bottom: 15px;"),
          plotlyOutput(ns("data_quality_chart"), height = "200px")
        )
      )
    ),
    
    # Detailed analysis section
    fluidRow(
      column(12,
        div(class = "stats-card",
          h4("Temporal Analysis", style = "margin-bottom: 15px;"),
          tabsetPanel(
            tabPanel("Timeline",
              plotlyOutput(ns("temporal_chart"), height = "300px")
            ),
            tabPanel("Heatmap",
              plotlyOutput(ns("temporal_heatmap"), height = "300px")
            ),
            tabPanel("Trends",
              plotlyOutput(ns("trend_analysis"), height = "300px")
            )
          )
        )
      )
    ),
    
    # Municipality details (expandable)
    fluidRow(
      column(12,
        div(class = "stats-card",
          h4("Municipality Details", style = "margin-bottom: 15px;"),
          
          # State selector for municipality view
          selectInput(
            ns("municipality_state_select"),
            "Select State for Municipality View",
            choices = NULL,
            width = "300px"
          ),
          
          # Municipality table
          conditionalPanel(
            condition = paste0("input['", ns("municipality_state_select"), "'] != ''"),
            DT::dataTableOutput(ns("municipality_table"))
          )
        )
      )
    ),
    
    # Cache and performance metrics
    fluidRow(
      column(12,
        div(class = "stats-card",
          h4("System Performance", style = "margin-bottom: 15px;"),
          fluidRow(
            column(3,
              infoBoxOutput(ns("cache_hit_rate"), width = 12)
            ),
            column(3,
              infoBoxOutput(ns("query_time"), width = 12)
            ),
            column(3,
              infoBoxOutput(ns("memory_usage"), width = 12)
            ),
            column(3,
              infoBoxOutput(ns("last_refresh"), width = 12)
            )
          )
        )
      )
    )
  )
}

# Geographic Analysis Server
geographic_server_enhanced <- function(id, pool, cache = NULL) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns
    
    # Source optimization functions
    source("modules/geographic/geographic_optimization.R", local = TRUE)
    source("modules/geographic/geojson_handler.R", local = TRUE)
    
    # Initialize cache if not provided
    if (is.null(cache)) {
      cache <- create_geographic_cache(ttl_seconds = 300)
    }
    
    # Reactive values
    values <- reactiveValues(
      geographic_data = NULL,
      loading = FALSE,
      last_refresh = Sys.time(),
      performance_metrics = list()
    )
    
    # Loading indicator
    output$map_loading <- reactive({
      values$loading
    })
    outputOptions(output, "map_loading", suspendWhenHidden = FALSE)
    
    # Load geographic data with progress
    load_data <- function() {
      values$loading <- TRUE
      
      withProgress(message = "Loading geographic data...", value = 0, {
        incProgress(0.2, detail = "Connecting to database...")
        
        # Check cache first
        cache_key <- paste0("geo_data_", input$date_range_filter, "_", 
                           paste(input$category_filter, collapse = "_"))
        cached_data <- cache$get(cache_key)
        
        if (!is.null(cached_data)) {
          incProgress(0.8, detail = "Using cached data...")
          values$geographic_data <- cached_data
        } else {
          incProgress(0.4, detail = "Querying database...")
          
          # Build filters
          filters <- list(
            date_range = switch(input$date_range_filter,
              "week" = c(Sys.Date() - 7, Sys.Date()),
              "month" = c(Sys.Date() - 30, Sys.Date()),
              "quarter" = c(Sys.Date() - 90, Sys.Date()),
              "year" = c(Sys.Date() - 365, Sys.Date()),
              "all" = NULL
            ),
            categories = input$category_filter,
            states = input$state_filter
          )
          
          incProgress(0.6, detail = "Processing data...")
          
          # Load data with sampling if needed
          start_time <- Sys.time()
          geo_data <- aggregate_geographic_data(pool, filters)

          if (!is.null(geo_data) && is.data.frame(geo_data) && nrow(geo_data) > input$sample_size) {
            incProgress(0.7, detail = "Applying stratified sampling...")
            geo_data <- stratified_sample_documents(geo_data, input$sample_size)
          }
          
          query_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
          
          incProgress(0.8, detail = "Validating statistics...")
          geo_data <- validate_geographic_stats(geo_data)
          
          # Cache the result
          cache$set(cache_key, geo_data)
          values$geographic_data <- geo_data
          
          # Update performance metrics
          values$performance_metrics$query_time <- query_time
          values$performance_metrics$data_points <- nrow(geo_data)
          
          incProgress(1, detail = "Complete!")
        }
        
        values$last_refresh <- Sys.time()
      })
      
      values$loading <- FALSE
    }
    
    # Initial data load
    observe({
      load_data()
    })
    
    # Refresh button
    observeEvent(input$refresh_data, {
      cache$clear()  # Clear cache on manual refresh
      load_data()
    })
    
    # Auto-refresh
    observe({
      if ("autorefresh" %in% input$display_options) {
        invalidateLater(300000)  # 5 minutes
        load_data()
      }
    })
    
    # Render map
    output$geographic_map <- renderPlotly({
      cat("[TRACE] geographic:geographic_map start\n", file = stderr())
      req(values$geographic_data)
      
      use_webgl <- "webgl" %in% input$display_options
      show_sampling <- "sampling" %in% input$display_options
      
      create_webgl_choropleth(
        values$geographic_data,
        use_webgl = use_webgl,
        show_sampling_note = show_sampling && 
          !is.null(attr(values$geographic_data, "sampling_info"))
      )
    })
    
    # Value boxes
    output$total_states_box <- renderValueBox({
      safe_valueBox(
        value = if (!is.null(values$geographic_data)) {
          n_distinct(values$geographic_data$estado)
        } else { 0 },
        subtitle = "Active States",
        icon = icon("map-marked"),
        color = "blue"
      )
    })
    
    output$total_documents_box <- renderValueBox({
      safe_valueBox(
        value = if (!is.null(values$geographic_data)) {
          format(sum(values$geographic_data$doc_count), big.mark = ",")
        } else { 0 },
        subtitle = "Total Documents",
        icon = icon("file-alt"),
        color = "green"
      )
    })
    
    output$most_active_state_box <- renderValueBox({
      most_active <- if (!is.null(values$geographic_data) && nrow(values$geographic_data) > 0) {
        top_state <- values$geographic_data %>%
          arrange(desc(doc_count)) %>%
          slice(1)
        paste0(top_state$estado, " (", format(top_state$doc_count, big.mark = ","), ")")
      } else { "N/A" }
      
      safe_valueBox(
        value = most_active,
        subtitle = "Most Active State",
        icon = icon("trophy"),
        color = "yellow"
      )
    })
    
    output$data_freshness_box <- renderValueBox({
      freshness <- if (!is.null(values$geographic_data) && nrow(values$geographic_data) > 0) {
        latest <- max(values$geographic_data$latest_date, na.rm = TRUE)
        days_ago <- as.numeric(Sys.Date() - as.Date(latest))
        if (days_ago == 0) "Today"
        else if (days_ago == 1) "Yesterday"
        else paste0(days_ago, " days ago")
      } else { "N/A" }
      
      safe_valueBox(
        value = freshness,
        subtitle = "Latest Document",
        icon = icon("clock"),
        color = "purple"
      )
    })
    
    # State ranking table
    output$state_ranking_table <- DT::renderDataTable({
      req(values$geographic_data)
      
      ranking_data <- values$geographic_data %>%
        select(Estado = estado, Documents = doc_count, 
               `Last Update` = latest_date, Quality = data_quality) %>%
        arrange(desc(Documents))
      
      DT::datatable(
        ranking_data,
        options = list(
          pageLength = 10,
          dom = 't',
          ordering = TRUE,
          searching = FALSE
        ),
        rownames = FALSE
      ) %>%
        DT::formatDate("Last Update", method = "toLocaleDateString") %>%
        DT::formatStyle(
          "Quality",
          backgroundColor = DT::styleEqual(
            c("high", "medium", "low", "insufficient"),
            c("#28a745", "#ffc107", "#fd7e14", "#dc3545")
          ),
          color = "white"
        )
    })
    
    # Performance stats
    output$performance_stats <- renderText({
      if (!is.null(values$performance_metrics$query_time)) {
        sprintf("Query: %.2fs | Points: %s",
                values$performance_metrics$query_time,
                format(values$performance_metrics$data_points, big.mark = ","))
      } else {
        "Loading..."
      }
    })
    
    # Download handler
    output$download_map <- downloadHandler(
      filename = function() {
        paste0("geographic_distribution_", Sys.Date(), ".png")
      },
      content = function(file) {
        # Export the plotly map as static image
        if (!is.null(values$geographic_data)) {
          p <- create_webgl_choropleth(values$geographic_data, use_webgl = FALSE)
          plotly::orca(p, file = file, width = 1200, height = 800)
        }
      }
    )
    
    # Return reactive values for use by other modules
    return(list(
      geographic_data = reactive(values$geographic_data),
      refresh = load_data,
      cache_stats = reactive(list(
        size = cache$size(),
        last_refresh = values$last_refresh
      ))
    ))
  })
}

# Export the module
list(
  ui = geographic_ui_enhanced,
  server = geographic_server_enhanced
)
