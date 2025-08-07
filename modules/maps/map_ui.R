# Map UI Module
# This module contains the UI components for the Interactive Maps tab

mapUI <- function(id) {
  ns <- NS(id)
  
  tabItem(
    tabName = "maps",
    fluidRow(
      box(
        title = "Interactive Document Distribution Maps",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        # Control panel
        fluidRow(
          column(
            width = 3,
            selectInput(
              ns("map_type"),
              "Map Type:",
              choices = c(
                "State Distribution" = "state",
                "Municipality Heatmap" = "municipality", 
                "Regional Clusters" = "regional",
                "Document Density" = "density"
              ),
              selected = "state"
            )
          ),
          column(
            width = 3,
            selectInput(
              ns("map_metric"),
              "Display Metric:",
              choices = c(
                "Document Count" = "count",
                "Per Capita" = "per_capita",
                "Activity Index" = "activity",
                "Regulatory Density" = "density"
              ),
              selected = "count"
            )
          ),
          column(
            width = 3,
            selectInput(
              ns("map_category"),
              "Document Category:",
              choices = c(
                "All Categories" = "all",
                "Legislation" = "legislation",
                "Jurisprudence" = "jurisprudence", 
                "Doctrine" = "doctrine",
                "Transportation" = "transportation"
              ),
              selected = "all"
            )
          ),
          column(
            width = 3,
            dateRangeInput(
              ns("map_date_range"),
              "Date Range:",
              start = as.Date("1995-01-01"),
              end = Sys.Date(),
              format = "yyyy-mm-dd"
            )
          )
        ),
        
        # Additional controls
        fluidRow(
          column(
            width = 12,
            checkboxGroupInput(
              ns("map_options"),
              "Display Options:",
              choices = c(
                "Show state labels" = "labels",
                "Include population data" = "population",
                "Animate over time" = "animate"
              ),
              selected = c("labels", "population"),
              inline = TRUE
            )
          )
        ),
        
        # Map loading indicator
        conditionalPanel(
          condition = sprintf("$('#%s').hasClass('recalculating')", ns("interactive_brazil_map")),
          tags$div(
            class = "text-center",
            style = "padding: 20px;",
            tags$i(class = "fa fa-spinner fa-spin fa-2x"),
            tags$p("Loading map data...")
          )
        ),
        
        # Main map output
        plotlyOutput(ns("interactive_brazil_map"), height = "600px"),
        
        # Action buttons
        br(),
        fluidRow(
          column(
            width = 12,
            style = "text-align: center;",
            downloadButton(
              ns("download_map"), 
              "Download Map",
              class = "btn-primary"
            ),
            actionButton(
              ns("refresh_map"),
              "Refresh Data",
              icon = icon("refresh"),
              class = "btn-info",
              style = "margin-left: 10px;"
            )
          )
        )
      )
    ),
    
    # Municipality detail map
    fluidRow(
      box(
        title = "Municipality Detail Analysis",
        status = "info",
        solidHeader = TRUE,
        width = 6,
        collapsible = TRUE,
        collapsed = TRUE,
        plotlyOutput(ns("municipality_detail_map"), height = "400px")
      ),
      
      # Temporal evolution map
      box(
        title = "Temporal Evolution",
        status = "success",
        solidHeader = TRUE,
        width = 6,
        collapsible = TRUE,
        collapsed = TRUE,
        plotlyOutput(ns("temporal_map_animation"), height = "400px")
      )
    ),
    
    # Statistics table
    fluidRow(
      box(
        title = "State-by-State Statistics",
        status = "warning",
        solidHeader = TRUE,
        width = 12,
        collapsible = TRUE,
        collapsed = TRUE,
        DT::dataTableOutput(ns("map_statistics_table"))
      )
    )
  )
}