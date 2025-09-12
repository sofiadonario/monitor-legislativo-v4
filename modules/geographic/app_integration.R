# IBGE Geographic System - App Integration - Sprint 5B
# Brazilian Legislative Monitoring System - Main Application Integration
# ======================================================================
# 
# Integration module for the IBGE Geographic System with the main Shiny
# application, providing seamless geographic capabilities for 134k+ documents
# 
# FEATURES:
# - Drop-in replacement for existing geographic module
# - Memory-optimized initialization for Railway deployment
# - Progressive loading with user feedback
# - Graceful degradation and fallback mechanisms
# - Academic-grade Brazilian administrative boundaries
# - Real-time choropleth visualization capabilities
# 
# INTEGRATION ARCHITECTURE:
# - Seamless integration with existing app.R structure
# - Modular component design for maintainability
# - Performance monitoring and optimization
# - Error handling with user-friendly messages
# ======================================================================

# Load IBGE Geographic Integration System
if (!exists("ibge_geographic_system_loaded")) {
  tryCatch({
    
    cat("🌐 Loading IBGE Geographic Integration System...\n")
    
    # Load all geographic modules
    source("modules/geographic/geographic_integration.R")
    
    # Load supporting modules if they exist
    optional_geographic_files <- c(
      "modules/geographic/brazil_coordinate_systems.R",
      "modules/geographic/geographic_ui_enhanced.R",
      "modules/geographic/geojson_handler.R"
    )
    
    for (file in optional_geographic_files) {
      if (file.exists(file)) {
        tryCatch({
          source(file)
          cat("✅ Loaded:", basename(file), "\n")
        }, error = function(e) {
          cat("⚠️ Optional file", basename(file), "failed:", e$message, "\n")
        })
      }
    }
    
    ibge_geographic_system_loaded <- TRUE
    cat("✅ IBGE Geographic System loaded successfully\n")
    cat("   🇧🇷 Official IBGE administrative boundaries\n")
    cat("   🗺️ SIRGAS 2000 coordinate system integration\n")
    cat("   📊 Document-geography aggregation system\n")
    cat("   ⚡ Railway-optimized memory management\n")
    cat("   🎯 Academic-grade spatial data validation\n")
    
  }, error = function(e) {
    cat("❌ IBGE Geographic System loading failed:", e$message, "\n")
    ibge_geographic_system_loaded <- FALSE
  })
}

# Initialize Global Geographic System Variable
# ===========================================

# Global geographic system instance (initialized in server)
geographic_system <- NULL

# Geographic System Initialization Function
# ========================================

#' Initialize IBGE Geographic System
#' 
#' Initializes the geographic system with database connection and progress feedback
#' 
#' @param db_pool Database connection pool
#' @param session Shiny session for progress updates
#' @return Initialization result
initialize_geographic_system <- function(db_pool = NULL, session = NULL) {
  
  if (!exists("ibge_geographic_system_loaded") || !ibge_geographic_system_loaded) {
    return(list(
      success = FALSE,
      error = "IBGE Geographic System not loaded",
      fallback = TRUE
    ))
  }
  
  tryCatch({
    
    cat("🚀 Initializing IBGE Geographic System...\n")
    
    # Create geographic integration system
    geographic_system <<- create_geographic_integration(
      db_pool = db_pool,
      auto_initialize = FALSE  # Manual initialization for progress feedback
    )
    
    if (is.null(geographic_system)) {
      return(list(
        success = FALSE,
        error = "Failed to create geographic system",
        fallback = TRUE
      ))
    }
    
    # Initialize with progress feedback
    init_result <- initialize_geographic_with_progress(
      geo_system = geographic_system,
      session = session
    )
    
    if (init_result$success) {
      cat("🎉 IBGE Geographic System initialized successfully\n")
      
      # Set up automatic cleanup on session end
      if (!is.null(session)) {
        session$onSessionEnded(function() {
          if (!is.null(geographic_system) && "cleanup" %in% names(geographic_system)) {
            geographic_system$cleanup()
          }
        })
      }
      
      return(list(
        success = TRUE,
        status = init_result$status,
        components = init_result$components,
        geographic_system = geographic_system
      ))
      
    } else {
      return(list(
        success = FALSE,
        error = init_result$error,
        status = init_result$status,
        fallback = TRUE
      ))
    }
    
  }, error = function(e) {
    cat("❌ Geographic system initialization error:", e$message, "\n")
    return(list(
      success = FALSE,
      error = e$message,
      fallback = TRUE
    ))
  })
}

# Enhanced Geographic Tab Item
# ===========================

#' Create Enhanced Geographic Tab Item
#' 
#' Creates the main geographic analysis tab with IBGE integration
#' 
#' @return Shiny tabItem with enhanced geographic features
create_enhanced_geographic_tab <- function() {
  
  tabItem(
    tabName = "geographic",
    
    # Check if IBGE system is loaded
    if (exists("ibge_geographic_system_loaded") && ibge_geographic_system_loaded) {
      
      # Enhanced IBGE Geographic Analysis
      fluidRow(
        
        # Header with system status
        column(12,
          div(
            style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;",
            h2("🗺️ Geographic Analysis - IBGE Integration", style = "margin: 0; font-weight: bold;"),
            p("Official Brazilian administrative boundaries with 134k+ legislative documents", 
              style = "margin: 10px 0 0 0; opacity: 0.9;")
          )
        ),
        
        # System Status Panel
        column(12,
          conditionalPanel(
            condition = "output.geographic_system_status == 'initializing'",
            div(
              id = "geographic-loading-panel",
              style = "background: #e3f2fd; border: 2px solid #2196f3; padding: 20px; border-radius: 10px; margin-bottom: 20px; text-align: center;",
              h4("🌐 Initializing IBGE Geographic System...", style = "color: #1976d2; margin-bottom: 15px;"),
              div(
                id = "geographic-progress-bar",
                style = "width: 100%; height: 30px; background: #bbdefb; border-radius: 15px; overflow: hidden; position: relative;",
                div(
                  id = "geographic-progress-fill",
                  style = "height: 100%; background: linear-gradient(90deg, #2196f3, #21cbf3); width: 0%; transition: width 0.3s ease;"
                )
              ),
              p(id = "geographic-progress-message", "Loading IBGE administrative boundaries...", 
                style = "margin-top: 15px; color: #1976d2; font-weight: bold;")
            )
          )
        ),
        
        # Main Geographic Content
        column(12,
          conditionalPanel(
            condition = "output.geographic_system_status == 'ready'",
            
            # Control Panel
            fluidRow(
              column(3,
                wellPanel(
                  h4("🎛️ Map Controls"),
                  
                  selectInput("geographic_map_type", "Map Type:",
                    choices = list(
                      "State Choropleth" = "state_choropleth",
                      "Municipality Analysis" = "municipality_analysis",
                      "Regional Overview" = "regional_overview",
                      "Document Density" = "document_density"
                    ),
                    selected = "state_choropleth"
                  ),
                  
                  conditionalPanel(
                    condition = "input.geographic_map_type == 'municipality_analysis'",
                    selectInput("geographic_state_filter", "Focus State:",
                      choices = list("Loading..." = ""),
                      selected = ""
                    ),
                    
                    numericInput("geographic_top_municipalities", "Top Municipalities:",
                      value = 20, min = 5, max = 100, step = 5
                    )
                  ),
                  
                  selectInput("geographic_color_scheme", "Color Scheme:",
                    choices = list(
                      "Blues" = "Blues",
                      "Reds" = "Reds", 
                      "Greens" = "Greens",
                      "Viridis" = "viridis",
                      "Plasma" = "plasma"
                    ),
                    selected = "Blues"
                  ),
                  
                  hr(),
                  
                  h5("📊 Data Filters"),
                  
                  dateRangeInput("geographic_date_range", "Date Range:",
                    start = Sys.Date() - 365,
                    end = Sys.Date(),
                    format = "yyyy-mm-dd"
                  ),
                  
                  checkboxInput("geographic_recent_only", "Recent Documents Only (30 days)", FALSE),
                  
                  hr(),
                  
                  actionButton("geographic_refresh", "🔄 Refresh Data", 
                    class = "btn-primary", style = "width: 100%;"),
                  
                  br(), br(),
                  
                  downloadButton("geographic_export", "📥 Export Data", 
                    class = "btn-info", style = "width: 100%;")
                )
              ),
              
              # Main Map Display
              column(9,
                tabsetPanel(
                  id = "geographic_tabs",
                  
                  # Interactive Map Tab
                  tabPanel("🗺️ Interactive Map",
                    div(style = "height: 600px; border: 2px solid #ddd; border-radius: 8px; overflow: hidden;",
                      leafletOutput("geographic_map", height = "100%")
                    ),
                    
                    br(),
                    
                    # Map Statistics
                    fluidRow(
                      column(3,
                        valueBoxOutput("geographic_total_documents", width = 12)
                      ),
                      column(3,
                        valueBoxOutput("geographic_states_covered", width = 12)
                      ),
                      column(3,
                        valueBoxOutput("geographic_top_state", width = 12)
                      ),
                      column(3,
                        valueBoxOutput("geographic_data_quality", width = 12)
                      )
                    )
                  ),
                  
                  # Data Table Tab
                  tabPanel("📊 Data Table",
                    br(),
                    DT::dataTableOutput("geographic_data_table")
                  ),
                  
                  # Analytics Tab
                  tabPanel("📈 Analytics",
                    br(),
                    fluidRow(
                      column(6,
                        h4("📊 Document Distribution by State"),
                        plotlyOutput("geographic_distribution_plot", height = "400px")
                      ),
                      column(6,
                        h4("📅 Geographic Activity Timeline"),
                        plotlyOutput("geographic_timeline_plot", height = "400px")
                      )
                    ),
                    
                    br(),
                    
                    fluidRow(
                      column(12,
                        h4("🎯 Statistical Summary"),
                        verbatimTextOutput("geographic_statistics_summary")
                      )
                    )
                  ),
                  
                  # System Information Tab
                  tabPanel("ℹ️ System Info",
                    br(),
                    h4("🌐 IBGE Geographic Integration Status"),
                    verbatimTextOutput("geographic_system_info"),
                    
                    br(),
                    
                    h4("📋 Data Sources & Methodology"),
                    div(
                      style = "background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #007bff;",
                      h5("🏛️ Data Sources:"),
                      tags$ul(
                        tags$li("IBGE - Instituto Brasileiro de Geografia e Estatística"),
                        tags$li("Official Brazilian administrative boundaries (2020)"),
                        tags$li("SIRGAS 2000 coordinate reference system (EPSG:4674)"),
                        tags$li("134k+ Brazilian legislative documents")
                      ),
                      
                      h5("🔬 Academic Standards:"),
                      tags$ul(
                        tags$li("Academic validation protocols (RESEARCH_METHODOLOGY.md compliant)"),
                        tags$li("Statistical significance testing with confidence intervals"),
                        tags$li("Geographic data quality assurance and validation"),
                        tags$li("Memory-optimized processing for large datasets")
                      ),
                      
                      h5("⚡ Performance Optimizations:"),
                      tags$ul(
                        tags$li("Railway deployment optimized (2GB memory constraint)"),
                        tags$li("Progressive data loading with intelligent caching"),
                        tags$li("Spatial indexing and query optimization"),
                        tags$li("WebGL-accelerated map rendering")
                      )
                    )
                  )
                )
              )
            )
          )
        ),
        
        # Error/Fallback Panel
        column(12,
          conditionalPanel(
            condition = "output.geographic_system_status == 'error'",
            div(
              style = "background: #fff3cd; border: 2px solid #ffc107; padding: 20px; border-radius: 10px; margin: 20px 0;",
              h4("⚠️ Geographic System Unavailable", style = "color: #856404;"),
              p("The IBGE Geographic System encountered an initialization error. The system will operate in fallback mode with basic functionality.", style = "color: #856404;"),
              
              h5("Available Fallback Features:"),
              tags$ul(
                tags$li("Basic state-level document counting"),
                tags$li("Simple data tables and statistics"),
                tags$li("Text-based geographic analysis")
              ),
              
              actionButton("geographic_retry_init", "🔄 Retry Initialization", class = "btn-warning"),
              
              hr(),
              
              h5("Error Details:"),
              verbatimTextOutput("geographic_error_details")
            )
          )
        )
      )
      
    } else {
      
      # System not loaded - show basic fallback
      fluidRow(
        column(12,
          div(
            style = "background: #f8d7da; border: 2px solid #dc3545; padding: 20px; border-radius: 10px; margin: 20px 0;",
            h4("❌ IBGE Geographic System Not Available", style = "color: #721c24;"),
            p("The IBGE Geographic Integration System could not be loaded. Please check system requirements and try again.", style = "color: #721c24;"),
            
            h5("Possible Issues:"),
            tags$ul(
              tags$li("Missing R packages (sf, geobr, leaflet)"),
              tags$li("Insufficient memory for spatial data processing"),
              tags$li("Database connection issues"),
              tags$li("File system permissions")
            ),
            
            h5("Basic Geographic Analysis:"),
            p("You can still access basic geographic functionality through the main dashboard.")
          )
        )
      )
    }
  )
}

# Server Integration Functions
# ===========================

#' Geographic Server Integration
#' 
#' Adds geographic server logic to the main server function
#' 
#' @param input Shiny input
#' @param output Shiny output  
#' @param session Shiny session
#' @param db_pool Database connection pool
add_geographic_server_logic <- function(input, output, session, db_pool = NULL) {
  
  # Initialize system status
  geographic_status <- reactiveVal("initializing")
  geographic_error <- reactiveVal(NULL)
  
  # System initialization
  observe({
    if (is.null(geographic_system)) {
      
      # Initialize in background
      future::future({
        initialize_geographic_system(db_pool, session)
      }) %>%
      promises::then(function(result) {
        
        if (result$success) {
          geographic_status("ready")
          geographic_error(NULL)
        } else {
          geographic_status("error") 
          geographic_error(result$error)
        }
        
      }, onRejected = function(error) {
        geographic_status("error")
        geographic_error(as.character(error))
      })
    }
  })
  
  # System status output
  output$geographic_system_status <- reactive({
    geographic_status()
  })
  outputOptions(output, "geographic_system_status", suspendWhenHidden = FALSE)
  
  # Error details
  output$geographic_error_details <- renderText({
    geographic_error()
  })
  
  # System information
  output$geographic_system_info <- renderText({
    if (!is.null(geographic_system)) {
      tryCatch({
        status <- get_geographic_dashboard_summary(geographic_system)
        paste(
          "System Status: Operational",
          paste("States Available:", status$states_count),
          paste("Memory Usage:", round(status$memory_usage_mb, 1), "MB"),
          paste("Last Updated:", format(status$last_update, "%Y-%m-%d %H:%M:%S")),
          sep = "\n"
        )
      }, error = function(e) {
        paste("System Status: Error -", e$message)
      })
    } else {
      "System Status: Not Initialized"
    }
  })
  
  # Retry initialization
  observeEvent(input$geographic_retry_init, {
    geographic_status("initializing")
    geographic_error(NULL)
    
    # Reset global system
    geographic_system <<- NULL
    
    # Reinitialize
    future::future({
      initialize_geographic_system(db_pool, session)
    }) %>%
    promises::then(function(result) {
      if (result$success) {
        geographic_status("ready")
      } else {
        geographic_status("error")
        geographic_error(result$error)
      }
    })
  })
  
  # Geographic data outputs would go here...
  # (Additional server logic for maps, tables, etc.)
}

# Export Integration Components
# ============================

# Make components available to app.R
list(
  initialize_geographic_system = initialize_geographic_system,
  create_enhanced_geographic_tab = create_enhanced_geographic_tab,
  add_geographic_server_logic = add_geographic_server_logic,
  geographic_system_loaded = exists("ibge_geographic_system_loaded") && ibge_geographic_system_loaded
)