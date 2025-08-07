# Simple Map Integration 
# This provides a simpler integration without complex module system

# Load required data
if (file.exists("data/brazil_states.R")) {
  source("data/brazil_states.R", local = TRUE)
  cat("✅ Brazilian states data loaded\n")
}

# Load data cleaning fix
if (file.exists("fixes/active/map_data_fix.R")) {
  source("fixes/active/map_data_fix.R", local = TRUE)
  cat("✅ Map data fix loaded\n")
}

# Simple function to create map UI
create_maps_tab_ui <- function() {
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
              "map_type",
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
              "map_metric",
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
              "map_category",
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
              "map_date_range",
              "Date Range:",
              start = as.Date("1995-01-01"),
              end = Sys.Date(),
              format = "yyyy-mm-dd"
            )
          )
        ),
        
        # Main map output
        plotlyOutput("interactive_brazil_map", height = "600px"),
        
        # Action buttons
        br(),
        fluidRow(
          column(
            width = 12,
            style = "text-align: center;",
            downloadButton(
              "download_map", 
              "Download Map",
              class = "btn-primary"
            ),
            actionButton(
              "refresh_map",
              "Refresh Data",
              icon = icon("refresh"),
              class = "btn-info",
              style = "margin-left: 10px;"
            )
          )
        )
      )
    ),
    
    # Municipality detail and temporal maps
    fluidRow(
      box(
        title = "Municipality Detail Analysis",
        status = "info",
        solidHeader = TRUE,
        width = 6,
        collapsible = TRUE,
        collapsed = TRUE,
        plotlyOutput("municipality_detail_map", height = "400px")
      ),
      box(
        title = "Temporal Evolution",
        status = "success", 
        solidHeader = TRUE,
        width = 6,
        collapsible = TRUE,
        collapsed = TRUE,
        plotlyOutput("temporal_map_animation", height = "400px")
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
        DT::dataTableOutput("map_statistics_table")
      )
    )
  )
}

# Mark functions as available in global environment
assign("SIMPLE_MAP_UI_AVAILABLE", TRUE, envir = .GlobalEnv)
assign("create_maps_tab_ui", create_maps_tab_ui, envir = .GlobalEnv)

# Verify the assignment worked
if (exists("SIMPLE_MAP_UI_AVAILABLE", envir = .GlobalEnv) && 
    exists("create_maps_tab_ui", envir = .GlobalEnv)) {
  cat("✅ Simple map integration loaded and verified\n")
} else {
  cat("⚠️ Simple map integration loaded but verification failed\n")
}