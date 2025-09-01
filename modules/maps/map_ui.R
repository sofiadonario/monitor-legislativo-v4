# Enhanced Interactive Maps UI Module
# Professional interface for Brazilian Legislative Document exploration
# with modern controls, accessibility features, and performance optimization

mapUI <- function(id) {
  # Handle namespace function availability
  ns <- if (exists("NS") && is.function(NS)) {
    NS(id)
  } else {
    function(x) paste0(id, "-", x)
  }
  
  # Custom CSS for modern interface
  map_custom_css <- tags$head(
    tags$style(HTML("
      .maps-control-panel { 
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 12px; 
        padding: 20px; 
        margin-bottom: 20px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        border: 1px solid #dee2e6;
      }
      
      .maps-section-header {
        color: #495057; 
        font-weight: 600; 
        font-size: 16px;
        margin-bottom: 15px;
        border-bottom: 2px solid #007bff;
        padding-bottom: 8px;
        display: flex;
        align-items: center;
      }
      
      .maps-section-header i {
        margin-right: 8px;
        color: #007bff;
      }
      
      .maps-metric-card {
        background: white;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        border-left: 4px solid #007bff;
        box-shadow: 0 2px 6px rgba(0,0,0,0.05);
        transition: all 0.3s ease;
      }
      
      .maps-metric-card:hover {
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        transform: translateY(-2px);
      }
      
      .maps-metric-value {
        font-size: 24px;
        font-weight: bold;
        color: #007bff;
        margin-bottom: 5px;
      }
      
      .maps-metric-label {
        font-size: 12px;
        color: #6c757d;
        text-transform: uppercase;
        font-weight: 500;
      }
      
      .maps-quick-actions {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin: 15px 0;
      }
      
      .maps-action-btn {
        padding: 8px 16px;
        border-radius: 20px;
        border: none;
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.3s ease;
      }
      
      .maps-action-btn-primary {
        background: #007bff;
        color: white;
      }
      
      .maps-action-btn-secondary {
        background: #6c757d;
        color: white;
      }
      
      .maps-action-btn:hover {
        transform: translateY(-1px);
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
      }
      
      .maps-toolbar {
        background: rgba(255,255,255,0.95);
        backdrop-filter: blur(10px);
        border-radius: 8px;
        padding: 10px;
        margin-bottom: 15px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        position: sticky;
        top: 0;
        z-index: 1000;
      }
      
      .maps-loading-overlay {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(255,255,255,0.9);
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
        z-index: 9999;
        border-radius: 8px;
      }
      
      .maps-spinner {
        width: 40px;
        height: 40px;
        border: 4px solid #f3f3f3;
        border-top: 4px solid #007bff;
        border-radius: 50%;
        animation: mapsSpinner 1s linear infinite;
      }
      
      @keyframes mapsSpinner {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      
      .maps-legend {
        position: absolute;
        bottom: 20px;
        right: 20px;
        background: rgba(255,255,255,0.95);
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        min-width: 200px;
        z-index: 999;
      }
      
      .maps-performance-badge {
        position: absolute;
        top: 15px;
        right: 15px;
        background: #28a745;
        color: white;
        padding: 5px 10px;
        border-radius: 15px;
        font-size: 11px;
        font-weight: 500;
      }
      
      .maps-accessibility-controls {
        background: #f8f9fa;
        border-radius: 6px;
        padding: 10px;
        margin: 10px 0;
        border: 1px solid #dee2e6;
      }
      
      @media (max-width: 768px) {
        .maps-control-panel { padding: 15px; }
        .maps-quick-actions { justify-content: center; }
        .maps-legend { position: relative; bottom: auto; right: auto; margin-top: 15px; }
      }
    "))
  )
  
  tabItem(
    tabName = "maps",
    map_custom_css,
    
    # Modern Control Panel
    div(class = "maps-control-panel",
      # Main Controls Header
      div(class = "maps-section-header",
        icon("globe-americas"),
        "Interactive Maps Dashboard - Brazilian Legislative Documents"
      ),
      
      # Professional Toolbar
      div(class = "maps-toolbar",
        fluidRow(
          column(width = 3,
            selectInput(
              ns("map_type"),
              "Visualization Type:",
              choices = c(
                "State Choropleth" = "states",
                "Municipality Detail" = "municipality", 
                "Regional Analysis" = "regions",
                "Density Heatmap" = "density",
                "Transport Corridors" = "corridors"
              ),
              selected = "states"
            )
          ),
          column(width = 3,
            selectInput(
              ns("map_metric"),
              "Display Metric:",
              choices = c(
                "Document Count" = "count",
                "Per Capita (per 100k)" = "per_capita",
                "Legislative Activity Index" = "activity",
                "Regulatory Density (per 1M)" = "density",
                "Temporal Intensity" = "temporal"
              ),
              selected = "count"
            )
          ),
          column(width = 3,
            selectInput(
              ns("map_category"),
              "Document Category:",
              choices = c(
                "All Categories" = "all",
                "Transportation Policy" = "transportation",
                "Federal Legislation" = "legislation",
                "State Regulations" = "state_regs",
                "Municipal Ordinances" = "municipal",
                "Court Decisions" = "jurisprudence"
              ),
              selected = "all"
            )
          ),
          column(width = 3,
            dateRangeInput(
              ns("map_date_range"),
              "Date Range:",
              start = as.Date("2000-01-01"),
              end = Sys.Date(),
              format = "dd/mm/yyyy"
            )
          )
        ),
        
        # Quick Action Buttons
        div(class = "maps-quick-actions",
          actionButton(ns("reset_view"), "Reset View", 
            class = "maps-action-btn maps-action-btn-secondary", 
            icon = icon("home")),
          actionButton(ns("fit_bounds"), "Fit to Data", 
            class = "maps-action-btn maps-action-btn-primary", 
            icon = icon("expand-arrows-alt")),
          actionButton(ns("fullscreen"), "Full Screen", 
            class = "maps-action-btn maps-action-btn-secondary", 
            icon = icon("expand")),
          downloadButton(ns("export_view"), "Export", 
            class = "maps-action-btn maps-action-btn-primary")
        )
      ),
        
      # Advanced Controls Section
      div(class = "maps-section-header",
        icon("cogs"),
        "Advanced Visualization Controls"
      ),
      
      fluidRow(
        # Layer & Styling Controls
        column(width = 4,
          div(class = "maps-metric-card",
            h5("Layer Controls", style = "color: #495057; margin-bottom: 15px;"),
            selectInput(
              ns("color_scale"),
              "Color Palette:",
              choices = c(
                "Government Blue" = "Blues",
                "Brazil Colors" = "RdYlGn", 
                "Viridis (Accessible)" = "Viridis",
                "Heat Intensity" = "Reds",
                "Ocean Depth" = "BuGn",
                "Academic Spectrum" = "Spectral"
              ),
              selected = "Blues"
            ),
            
            sliderInput(
              ns("map_opacity"),
              "Layer Opacity:",
              min = 0.3,
              max = 1.0,
              value = 0.85,
              step = 0.05
            ),
            
            selectInput(
              ns("density_threshold"),
              "Display Threshold:",
              choices = c(
                "Show All Regions" = "all",
                "Above National Average" = "above_avg",
                "Top 50% Most Active" = "top_50",
                "Top 25% High Activity" = "top_25",
                "Top 10% Exceptional" = "top_10"
              ),
              selected = "all"
            )
          )
        ),
        
        # Interactive Features
        column(width = 4,
          div(class = "maps-metric-card",
            h5("Interactive Features", style = "color: #495057; margin-bottom: 15px;"),
            checkboxGroupInput(
              ns("map_options"),
              "Display Options:",
              choices = c(
                "State/Region Labels" = "labels",
                "Population Overlay" = "population",
                "Temporal Animation" = "animate",
                "High Contrast Mode" = "high_contrast",
                "Show Grid Lines" = "grid",
                "Document Clustering" = "clustering"
              ),
              selected = c("labels", "population"),
              inline = FALSE
            )
          )
        ),
        
        # Analysis Tools
        column(width = 4,
          div(class = "maps-metric-card",
            h5("Spatial Analysis", style = "color: #495057; margin-bottom: 15px;"),
            checkboxGroupInput(
              ns("analysis_tools"),
              "Analysis Tools:",
              choices = c(
                "Population Normalization" = "normalize_pop",
                "Regional Patterns" = "regional",
                "Statistical Outliers" = "outliers",
                "Trend Indicators" = "trends",
                "Transport Corridors" = "corridors",
                "Metropolitan Areas" = "metro_areas"
              ),
              selected = c("normalize_pop"),
              inline = FALSE
            ),
            
            # Drawing Tools
            div(style = "margin-top: 15px;",
              h6("Drawing Tools:", style = "color: #6c757d; margin-bottom: 10px;"),
              div(class = "maps-quick-actions",
                actionButton(ns("draw_rectangle"), "Rectangle", 
                  class = "maps-action-btn maps-action-btn-secondary", 
                  icon = icon("square")),
                actionButton(ns("draw_circle"), "Circle", 
                  class = "maps-action-btn maps-action-btn-secondary", 
                  icon = icon("circle")),
                actionButton(ns("draw_polygon"), "Polygon", 
                  class = "maps-action-btn maps-action-btn-secondary", 
                  icon = icon("draw-polygon")),
                actionButton(ns("clear_drawings"), "Clear", 
                  class = "maps-action-btn maps-action-btn-secondary", 
                  icon = icon("eraser"))
              )
            )
          )
        )
      ),
        
      # Performance & Statistics Dashboard  
      div(class = "maps-section-header",
        icon("chart-bar"),
        "Data Overview & Performance Metrics"
      ),
      
      # Enhanced Statistics Panel
      fluidRow(
        column(width = 3,
          div(class = "maps-metric-card",
            div(class = "maps-metric-value", textOutput(ns("total_documents"))),
            div(class = "maps-metric-label", "Total Documents"),
            tags$small(class = "text-muted", "Brazilian Legislative Database")
          )
        ),
        column(width = 3,
          div(class = "maps-metric-card",
            div(class = "maps-metric-value", textOutput(ns("avg_density"))),
            div(class = "maps-metric-label", "National Average"),
            tags$small(class = "text-muted", "Per selected metric")
          )
        ),
        column(width = 3,
          div(class = "maps-metric-card",
            div(class = "maps-metric-value", textOutput(ns("highest_state"))),
            div(class = "maps-metric-label", "Leading State"),
            tags$small(class = "text-muted", "Highest activity region")
          )
        ),
        column(width = 3,
          div(class = "maps-metric-card",
            div(class = "maps-metric-value", textOutput(ns("coverage_percentage"))),
            div(class = "maps-metric-label", "Geographic Coverage"),
            tags$small(class = "text-muted", "States with data")
          )
        )
      ),
      
      # Performance Indicators
      fluidRow(
        column(width = 6,
          div(class = "maps-metric-card",
            h6("System Performance", style = "color: #495057; margin-bottom: 15px;"),
            fluidRow(
              column(width = 6,
                div(style = "display: flex; align-items: center; margin-bottom: 10px;",
                  tags$span("Render Time: ", style = "color: #6c757d; margin-right: 10px;"),
                  textOutput(ns("render_time"), inline = TRUE),
                  tags$span("ms", style = "color: #6c757d; margin-left: 5px;")
                )
              ),
              column(width = 6,
                div(style = "display: flex; align-items: center; margin-bottom: 10px;",
                  tags$span("Data Points: ", style = "color: #6c757d; margin-right: 10px;"),
                  textOutput(ns("visible_points"), inline = TRUE)
                )
              )
            ),
            # Performance badge
            div(id = ns("performance_indicator"), class = "maps-performance-badge",
              textOutput(ns("performance_status"))
            )
          )
        ),
        column(width = 6,
          div(class = "maps-metric-card",
            h6("Filter Status", style = "color: #495057; margin-bottom: 15px;"),
            uiOutput(ns("filter_summary")),
            
            # Quick filter reset
            div(style = "margin-top: 10px;",
              actionButton(ns("reset_filters"), "Reset All Filters",
                class = "maps-action-btn maps-action-btn-secondary",
                icon = icon("refresh"))
            )
          )
        )
      )
    ),
    
    # Map Container with Enhanced Loading States
    fluidRow(
      column(width = 12,
        div(style = "position: relative;",
          # Loading overlay
          conditionalPanel(
            condition = sprintf("$('#%s').hasClass('recalculating')", ns("interactive_brazil_map")),
            div(class = "maps-loading-overlay",
              div(class = "maps-spinner"),
              tags$p("Analyzing legislative data...", style = "margin-top: 15px; color: #6c757d; font-weight: 500;"),
              textOutput(ns("loading_status"))
            )
          ),
        
          # Enhanced Map Container
          box(
            title = NULL,
            status = "primary",
            solidHeader = FALSE,
            width = 12,
            height = "700px",
            
            # Map with overlays
            plotlyOutput(ns("interactive_brazil_map"), height = "650px"),
            
            # Map Legend (positioned absolutely)
            conditionalPanel(
              condition = sprintf("input['%s'] !== 'null' && input['%s'] !== ''", ns("map_type"), ns("map_metric")),
              div(class = "maps-legend",
                h6("Legend", style = "margin-bottom: 10px; color: #495057;"),
                uiOutput(ns("map_legend_content")),
                
                # Accessibility controls
                div(class = "maps-accessibility-controls",
                  h6("Accessibility", style = "font-size: 11px; margin-bottom: 8px;"),
                  div(style = "display: flex; gap: 10px; align-items: center;",
                    tags$label("Contrast:", style = "font-size: 10px; margin-right: 5px;"),
                    switchInput(ns("high_contrast"), value = FALSE, size = "mini"),
                    tags$label("Audio:", style = "font-size: 10px; margin-left: 10px; margin-right: 5px;"),
                    switchInput(ns("audio_cues"), value = FALSE, size = "mini")
                  )
                )
              )
            )
          )
        )
      )
    ),
    
    # Timeline Controls (when temporal analysis is enabled)
    conditionalPanel(
      condition = sprintf("input['%s'].includes('animate')", ns("map_options")),
      fluidRow(
        column(width = 12,
          div(class = "maps-control-panel", style = "margin-top: 20px;",
            div(class = "maps-section-header",
              icon("clock"),
              "Temporal Analysis Timeline"
            ),
            
            fluidRow(
              column(width = 8,
                sliderInput(
                  ns("timeline_range"),
                  label = NULL,
                  min = as.Date("1988-01-01"),
                  max = Sys.Date(),
                  value = c(as.Date("2000-01-01"), Sys.Date()),
                  timeFormat = "%b %Y",
                  animate = animationOptions(
                    interval = 1500,
                    loop = TRUE,
                    playButton = "Play Animation",
                    pauseButton = "Pause"
                  )
                )
              ),
              column(width = 4,
                div(style = "padding-top: 15px;",
                  actionButton(ns("play_timeline"), "Play Timeline", 
                    class = "maps-action-btn maps-action-btn-primary",
                    icon = icon("play")),
                  actionButton(ns("reset_timeline"), "Reset", 
                    class = "maps-action-btn maps-action-btn-secondary",
                    icon = icon("backward"),
                    style = "margin-left: 10px;")
                )
              )
            )
          )
        )
      )
    ),
    
    # Enhanced Action Panel
    fluidRow(
      column(width = 12,
        div(class = "maps-control-panel", style = "margin-top: 20px;",
          div(class = "maps-section-header",
            icon("tools"),
            "Export & Integration Tools"
          ),
          
          fluidRow(
            # Export Options
            column(width = 4,
              div(class = "maps-metric-card",
                h6("Export Options", style = "color: #495057; margin-bottom: 15px;"),
                div(class = "maps-quick-actions",
                  downloadButton(ns("download_map"), "Map Image", 
                    class = "maps-action-btn maps-action-btn-primary"),
                  downloadButton(ns("download_data"), "Data (CSV)", 
                    class = "maps-action-btn maps-action-btn-secondary"),
                  downloadButton(ns("download_report"), "Full Report", 
                    class = "maps-action-btn maps-action-btn-primary")
                )
              )
            ),
            
            # Integration Features
            column(width = 4,
              div(class = "maps-metric-card",
                h6("Cross-Tab Integration", style = "color: #495057; margin-bottom: 15px;"),
                div(class = "maps-quick-actions",
                  actionButton(ns("open_document_details"), "Document Details", 
                    class = "maps-action-btn maps-action-btn-primary",
                    icon = icon("file-alt")),
                  actionButton(ns("sync_library"), "Sync Library", 
                    class = "maps-action-btn maps-action-btn-secondary",
                    icon = icon("sync")),
                  actionButton(ns("view_analytics"), "Analytics", 
                    class = "maps-action-btn maps-action-btn-primary",
                    icon = icon("chart-line"))
                )
              )
            ),
            
            # Sharing & Collaboration
            column(width = 4,
              div(class = "maps-metric-card",
                h6("Share & Collaborate", style = "color: #495057; margin-bottom: 15px;"),
                div(class = "maps-quick-actions",
                  actionButton(ns("bookmark_view"), "Bookmark View", 
                    class = "maps-action-btn maps-action-btn-secondary",
                    icon = icon("bookmark")),
                  actionButton(ns("share_link"), "Share Link", 
                    class = "maps-action-btn maps-action-btn-primary",
                    icon = icon("share")),
                  actionButton(ns("print_map"), "Print Layout", 
                    class = "maps-action-btn maps-action-btn-secondary",
                    icon = icon("print"))
                )
              )
            )
          )
        )
      )
      )
    ),
    
    # Enhanced Analysis Panels
    fluidRow(
      column(width = 12,
        div(class = "maps-control-panel", style = "margin-top: 20px;",
          div(class = "maps-section-header",
            icon("chart-area"),
            "Detailed Analysis Views"
          ),
          
          # Tabbed Analysis Interface
          tabsetPanel(
            id = ns("analysis_tabs"),
            type = "pills",
            
            # Municipality Analysis Tab
            tabPanel("Municipality Detail", 
              div(style = "padding: 20px;",
                fluidRow(
                  column(width = 8,
                    plotlyOutput(ns("municipality_detail_map"), height = "450px")
                  ),
                  column(width = 4,
                    div(class = "maps-metric-card",
                      h6("Top Municipalities", style = "color: #495057; margin-bottom: 15px;"),
                      DT::dataTableOutput(ns("top_municipalities_table")),
                      
                      div(style = "margin-top: 15px;",
                        actionButton(ns("drill_down_municipality"), "Drill Down Analysis",
                          class = "maps-action-btn maps-action-btn-primary btn-block",
                          icon = icon("search-plus"))
                      )
                    )
                  )
                )
              )
            ),
            
            # Temporal Evolution Tab
            tabPanel("Temporal Analysis",
              div(style = "padding: 20px;",
                fluidRow(
                  column(width = 12,
                    plotlyOutput(ns("temporal_map_animation"), height = "450px")
                  )
                ),
                fluidRow(
                  column(width = 6,
                    div(class = "maps-metric-card",
                      h6("Temporal Trends", style = "color: #495057; margin-bottom: 15px;"),
                      plotlyOutput(ns("temporal_trend_chart"), height = "200px")
                    )
                  ),
                  column(width = 6,
                    div(class = "maps-metric-card",
                      h6("Seasonal Patterns", style = "color: #495057; margin-bottom: 15px;"),
                      plotlyOutput(ns("seasonal_pattern_chart"), height = "200px")
                    )
                  )
                )
              )
            ),
            
            # Comparison View Tab
            tabPanel("Map Comparison",
              div(style = "padding: 20px;",
                fluidRow(
                  column(width = 6,
                    div(class = "maps-metric-card",
                      h6("Reference Period", style = "color: #495057; margin-bottom: 15px;"),
                      dateRangeInput(ns("comparison_period_1"), 
                        label = "Select Period:",
                        start = as.Date("2018-01-01"),
                        end = as.Date("2020-12-31")
                      ),
                      plotlyOutput(ns("comparison_map_left"), height = "400px")
                    )
                  ),
                  column(width = 6,
                    div(class = "maps-metric-card",
                      h6("Comparison Period", style = "color: #495057; margin-bottom: 15px;"),
                      dateRangeInput(ns("comparison_period_2"), 
                        label = "Select Period:",
                        start = as.Date("2021-01-01"),
                        end = Sys.Date()
                      ),
                      plotlyOutput(ns("comparison_map_right"), height = "400px")
                    )
                  )
                ),
                fluidRow(
                  column(width = 12,
                    div(class = "maps-metric-card", style = "margin-top: 15px;",
                      h6("Difference Analysis", style = "color: #495057; margin-bottom: 15px;"),
                      plotlyOutput(ns("difference_map"), height = "300px")
                    )
                  )
                )
              )
            ),
            
            # Data Table Tab
            tabPanel("Statistical Overview",
              div(style = "padding: 20px;",
                fluidRow(
                  column(width = 12,
                    div(class = "maps-metric-card",
                      h6("Complete State-by-State Analysis", style = "color: #495057; margin-bottom: 15px;"),
                      
                      # Enhanced table controls
                      fluidRow(
                        column(width = 6,
                          selectInput(ns("table_grouping"), "Group By:",
                            choices = c("Individual States" = "states", 
                                      "Regions" = "regions",
                                      "Population Tiers" = "population"),
                            selected = "states"
                          )
                        ),
                        column(width = 6,
                          checkboxGroupInput(ns("table_columns"), "Show Columns:",
                            choices = c("Documents" = "docs", "Per Capita" = "per_capita",
                                      "Activity Index" = "activity", "Population" = "pop",
                                      "Area" = "area", "HDI" = "hdi"),
                            selected = c("docs", "per_capita", "activity"),
                            inline = TRUE
                          )
                        )
                      ),
                      
                      DT::dataTableOutput(ns("enhanced_statistics_table"))
                    )
                  )
                )
              )
            )
          )
        )
      )
    ),
    
    # User Guide & Help System
    conditionalPanel(
      condition = "false", # Hidden by default, shown via help button
      fluidRow(
        column(width = 12,
          div(id = ns("help_panel"), class = "maps-control-panel", style = "margin-top: 20px; display: none;",
            div(class = "maps-section-header",
              icon("question-circle"),
              "Interactive Maps User Guide"
            ),
            
            fluidRow(
              column(width = 4,
                div(class = "maps-metric-card",
                  h6("Getting Started", style = "color: #495057; margin-bottom: 15px;"),
                  tags$ul(style = "font-size: 13px; line-height: 1.6;",
                    tags$li("Select visualization type from the toolbar"),
                    tags$li("Choose your preferred metric (count, per capita, etc.)"),
                    tags$li("Apply filters by category and date range"),
                    tags$li("Use drawing tools for spatial selection"),
                    tags$li("Enable temporal animation for time-series analysis")
                  )
                )
              ),
              column(width = 4,
                div(class = "maps-metric-card",
                  h6("Understanding Metrics", style = "color: #495057; margin-bottom: 15px;"),
                  tags$ul(style = "font-size: 13px; line-height: 1.6;",
                    tags$li(strong("Document Count:"), " Total legislative documents"),
                    tags$li(strong("Per Capita:"), " Documents per 100,000 residents"),
                    tags$li(strong("Activity Index:"), " Weighted score by population"),
                    tags$li(strong("Density:"), " Documents per million inhabitants"),
                    tags$li(strong("Temporal Intensity:"), " Time-weighted activity")
                  )
                )
              ),
              column(width = 4,
                div(class = "maps-metric-card",
                  h6("Accessibility Features", style = "color: #495057; margin-bottom: 15px;"),
                  tags$ul(style = "font-size: 13px; line-height: 1.6;",
                    tags$li("High contrast mode for visibility"),
                    tags$li("Keyboard navigation support"),
                    tags$li("Screen reader compatibility"),
                    tags$li("Mobile-responsive design"),
                    tags$li("Color-blind friendly palettes")
                  )
                )
              )
            )
          )
        )
      )
    ),
    
    # Modal for Document Details Integration
    uiOutput(ns("document_detail_modal"))
  )
  )
}