# Map UI Module
# This module contains the UI components for the Interactive Maps tab

mapUI <- function(id) {
  # Handle namespace function availability
  ns <- if (exists("NS") && is.function(NS)) {
    NS(id)
  } else {
    function(x) paste0(id, "-", x)
  }
  
  tabItem(
    tabName = "maps",
    fluidRow(
      box(
        title = "Interactive Choropleth Maps - Brazilian Legislative Documents",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        # Control panel
        fluidRow(
          column(
            width = 3,
            selectInput(
              ns("map_type"),
              "Visualization Type:",
              choices = c(
                "Choropleth (Filled States)" = "states",
                "Municipality Analysis" = "municipality", 
                "Regional Patterns" = "regions",
                "Density Mapping" = "density"
              ),
              selected = "states"
            )
          ),
          column(
            width = 3,
            selectInput(
              ns("map_metric"),
              "Display Metric:",
              choices = c(
                "Document Count" = "count",
                "Per Capita (per 100k)" = "per_capita",
                "Activity Index" = "activity",
                "Regulatory Density (per 1M)" = "density"
              ),
              selected = "count"
            ),
            # Metric description tooltip
            tags$small(
              class = "text-muted",
              style = "font-size: 11px; margin-top: 2px; display: block;",
              textOutput(ns("metric_description"))
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
        
        # Enhanced color scale and visualization controls
        fluidRow(
          column(
            width = 4,
            selectInput(
              ns("color_scale"),
              "Color Scale:",
              choices = c(
                "Viridis (Blue-Purple-Yellow)" = "Viridis",
                "Heat Map (Red)" = "Reds", 
                "Ocean (Blue)" = "Blues",
                "Earth (Green-Brown)" = "RdYlGn",
                "Plasma (Purple-Pink)" = "Plasma",
                "Spectral (Rainbow)" = "Spectral"
              ),
              selected = "Viridis"
            )
          ),
          column(
            width = 4,
            selectInput(
              ns("density_threshold"),
              "Density Display Threshold:",
              choices = c(
                "Show All States" = "all",
                "Above Average Only" = "above_avg",
                "Top 50%" = "top_50",
                "Top 25%" = "top_25",
                "Top 10%" = "top_10"
              ),
              selected = "all"
            )
          ),
          column(
            width = 4,
            sliderInput(
              ns("map_opacity"),
              "Map Opacity:",
              min = 0.3,
              max = 1.0,
              value = 0.85,
              step = 0.05
            )
          )
        ),
        
        # Additional controls
        fluidRow(
          column(
            width = 6,
            checkboxGroupInput(
              ns("map_options"),
              "Display Options:",
              choices = c(
                "Show state labels" = "labels",
                "Include population data" = "population",
                "Animate over time" = "animate",
                "High contrast mode" = "high_contrast"
              ),
              selected = c("labels", "population"),
              inline = TRUE
            )
          ),
          column(
            width = 6,
            checkboxGroupInput(
              ns("density_options"),
              "Density Enhancement:",
              choices = c(
                "Normalize by population" = "normalize_pop",
                "Show regional patterns" = "regional",
                "Highlight outliers" = "outliers",
                "Show trend indicators" = "trends"
              ),
              selected = c("normalize_pop"),
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
        
        # Data overview panel
        fluidRow(
          column(
            width = 12,
            wellPanel(
              style = "background-color: #f8f9fa; margin-bottom: 15px; padding: 15px;",
              fluidRow(
                column(
                  width = 3,
                  div(
                    style = "text-align: center;",
                    h4(textOutput(ns("total_documents")), style = "color: #007bff; margin-bottom: 5px;"),
                    p("Total Documents", style = "margin: 0; font-weight: bold; color: #666;")
                  )
                ),
                column(
                  width = 3,
                  div(
                    style = "text-align: center;",
                    h4(textOutput(ns("avg_density")), style = "color: #28a745; margin-bottom: 5px;"),
                    p("National Average", style = "margin: 0; font-weight: bold; color: #666;")
                  )
                ),
                column(
                  width = 3,
                  div(
                    style = "text-align: center;",
                    h4(textOutput(ns("highest_state")), style = "color: #dc3545; margin-bottom: 5px;"),
                    p("Highest State", style = "margin: 0; font-weight: bold; color: #666;")
                  )
                ),
                column(
                  width = 3,
                  div(
                    style = "text-align: center;",
                    h4(textOutput(ns("regional_leader")), style = "color: #ffc107; margin-bottom: 5px;"),
                    p("Leading Region", style = "margin: 0; font-weight: bold; color: #666;")
                  )
                )
              )
            )
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
              "Download Choropleth",
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
        width = 8,
        collapsible = TRUE,
        collapsed = TRUE,
        DT::dataTableOutput(ns("map_statistics_table"))
      ),
      
      # Help and guidance panel
      box(
        title = "Density Visualization Guide",
        status = "info",
        solidHeader = TRUE,
        width = 4,
        collapsible = TRUE,
        collapsed = TRUE,
        div(
          style = "padding: 10px;",
          h5("Understanding the Metrics", style = "color: #17a2b8; margin-bottom: 15px;"),
          tags$ul(
            tags$li(strong("Document Count:"), " Raw number of legislative documents"),
            tags$li(strong("Per Capita:"), " Documents per 100,000 inhabitants"),
            tags$li(strong("Activity Index:"), " Composite score considering both volume and population"),
            tags$li(strong("Regulatory Density:"), " Documents per million inhabitants (fine-grained analysis)")
          ),
          br(),
          h5("Color Scales", style = "color: #17a2b8; margin-bottom: 10px;"),
          tags$ul(
            tags$li(strong("Viridis:"), " Colorblind-friendly blue-purple-yellow"),
            tags$li(strong("Heat Map:"), " Traditional red intensity"),
            tags$li(strong("Ocean:"), " Blue gradient for density mapping"),
            tags$li(strong("Spectral:"), " Rainbow scale for maximum contrast")
          ),
          br(),
          h5("Accessibility Features", style = "color: #17a2b8; margin-bottom: 10px;"),
          tags$ul(
            tags$li("High contrast mode for better visibility"),
            tags$li("Adjustable opacity levels"),
            tags$li("Threshold filtering to focus on significant patterns"),
            tags$li("Screen reader compatible tooltips")
          )
        )
      )
    )
  )
}