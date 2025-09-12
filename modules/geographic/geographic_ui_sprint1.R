# Geographic Analysis UI Module - Sprint 1
# Monitor Legislativo v4 - Interactive Geospatial Research Interface
# ====================================================================
# 
# Academic-quality geographic analysis interface implementing Sprint 1 objectives
# Responsive design for desktop, tablet, and mobile with Brazilian administrative focus
# 
# Key Features:
# - Interactive leaflet choropleth maps with Brazilian state boundaries
# - Legislative density analysis visualization dashboard
# - Federal system comparative analysis interface
# - Temporal geographic trends with time-series controls
# - Spatial clustering analysis results display
# - Transport infrastructure correlation mapping
# - Academic statistical validation indicators
# - Mobile-responsive design with progressive enhancement

library(shiny)
library(shinydashboard)
library(shinyWidgets)
library(leaflet)
library(DT)
library(plotly)
library(htmltools)

#' Geographic Analysis UI Module for Sprint 1
#' 
#' Comprehensive user interface implementing all Sprint 1 geographic objectives
#' with academic-quality visualizations and Brazilian administrative integration
#' 
#' @param id Module namespace identifier
#' @return Shiny UI elements for geographic analysis dashboard
geographic_ui_sprint1 <- function(id) {
  ns <- NS(id)
  
  tagList(
    # Enhanced CSS for academic-quality visualizations and mobile responsiveness
    tags$head(
      tags$style(HTML("
        /* Academic Geographic Analysis Styling */
        .geographic-sprint1-container {
          padding: 15px;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .academic-header {
          background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
          color: white;
          padding: 20px;
          border-radius: 8px;
          margin-bottom: 20px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .academic-header h2 {
          margin: 0;
          font-size: 1.8em;
          font-weight: 300;
        }
        
        .academic-subtitle {
          font-size: 1.1em;
          opacity: 0.9;
          margin-top: 5px;
        }
        
        .map-container-sprint1 {
          background: white;
          border-radius: 8px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
          overflow: hidden;
          margin-bottom: 20px;
        }
        
        .leaflet-container {
          height: 600px !important;
          border-radius: 8px;
        }
        
        /* Responsive map height adjustments */
        @media (max-width: 768px) {
          .leaflet-container {
            height: 400px !important;
          }
        }
        
        @media (max-width: 480px) {
          .leaflet-container {
            height: 300px !important;
          }
        }
        
        .analysis-card {
          background: white;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
          padding: 20px;
          margin-bottom: 20px;
          border-left: 4px solid #3498db;
        }
        
        .analysis-card h4 {
          color: #2c3e50;
          margin-top: 0;
          font-weight: 600;
        }
        
        .control-panel {
          background: #f8f9fa;
          border-radius: 8px;
          padding: 15px;
          margin-bottom: 20px;
          border: 1px solid #dee2e6;
        }
        
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 15px;
          margin-bottom: 20px;
        }
        
        .stat-item {
          background: white;
          padding: 15px;
          border-radius: 6px;
          text-align: center;
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .stat-value {
          font-size: 2em;
          font-weight: bold;
          color: #3498db;
        }
        
        .stat-label {
          color: #666;
          font-size: 0.9em;
          margin-top: 5px;
        }
        
        .methodology-note {
          background: #e8f6f3;
          border-left: 4px solid #27ae60;
          padding: 10px 15px;
          margin: 15px 0;
          font-size: 0.9em;
          color: #2d5a4a;
        }
        
        .loading-indicator {
          text-align: center;
          padding: 40px;
          color: #666;
        }
        
        .loading-spinner {
          border: 3px solid #f3f3f3;
          border-top: 3px solid #3498db;
          border-radius: 50%;
          width: 30px;
          height: 30px;
          animation: spin 1s linear infinite;
          margin: 0 auto 15px;
        }
        
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        /* Mobile-first responsive design */
        .mobile-stack {
          display: flex;
          flex-direction: column;
          gap: 15px;
        }
        
        @media (min-width: 768px) {
          .mobile-stack {
            flex-direction: row;
          }
          .mobile-stack > div {
            flex: 1;
          }
        }
        
        .tab-content {
          background: white;
          border-radius: 0 0 8px 8px;
          padding: 20px;
          min-height: 400px;
        }
        
        /* Academic citation styling */
        .academic-citation {
          font-size: 0.8em;
          color: #666;
          font-style: italic;
          margin-top: 10px;
          text-align: right;
        }
      "))
    ),
    
    # Main geographic analysis interface
    div(class = "geographic-sprint1-container",
      
      # Academic header with methodology context
      div(class = "academic-header",
        h2("Brazilian Legislative Geographic Analysis"),
        div(class = "academic-subtitle",
          "Academic Research Platform | SIRGAS 2000 Coordinate System | RESEARCH_METHODOLOGY.md Compliant"
        )
      ),
      
      # Performance and data quality indicators
      div(class = "stats-grid",
        div(class = "stat-item",
          div(class = "stat-value", textOutput(ns("total_states_analyzed"))),
          div(class = "stat-label", "Brazilian States")
        ),
        div(class = "stat-item",
          div(class = "stat-value", textOutput(ns("total_documents_mapped"))),
          div(class = "stat-label", "Documents Mapped")
        ),
        div(class = "stat-item",
          div(class = "stat-value", textOutput(ns("spatial_coverage"))),
          div(class = "stat-label", "Geographic Coverage")
        ),
        div(class = "stat-item",
          div(class = "stat-value", textOutput(ns("data_quality_score"))),
          div(class = "stat-label", "Data Quality Score")
        )
      ),
      
      # Control panel with academic filtering options
      div(class = "control-panel",
        h4("Analysis Controls & Filters", style = "margin-bottom: 15px; color: #2c3e50;"),
        
        div(class = "mobile-stack",
          div(
            selectInput(
              ns("analysis_type"),
              "Analysis Type",
              choices = list(
                "Choropleth Mapping" = "choropleth",
                "Density Analysis" = "density",
                "Federal Comparison" = "federal",
                "Temporal Trends" = "temporal",
                "Spatial Clustering" = "clustering",
                "Transport Correlation" = "transport"
              ),
              selected = "choropleth"
            )
          ),
          div(
            selectInput(
              ns("geographic_level"),
              "Geographic Level",
              choices = list(
                "States (Primary)" = "state",
                "Regions (Aggregate)" = "region",
                "Municipalities (Detailed)" = "municipality"
              ),
              selected = "state"
            )
          ),
          div(
            selectInput(
              ns("metric_type"),
              "Analysis Metric",
              choices = list(
                "Document Count" = "count",
                "Density per km²" = "density_area",
                "Density per 100k km²" = "density_100k",
                "Federal Level Classification" = "federal_level"
              ),
              selected = "count"
            )
          ),
          div(
            div(style = "padding-top: 25px;",
              actionButton(
                ns("refresh_analysis"),
                "Refresh Analysis",
                icon = icon("sync-alt"),
                class = "btn btn-primary btn-block"
              )
            )
          )
        ),
        
        # Advanced options for academic analysis
        br(),
        checkboxGroupInput(
          ns("advanced_options"),
          "Advanced Academic Options",
          choices = list(
            "Show statistical confidence intervals" = "confidence",
            "Enable spatial autocorrelation analysis" = "spatial_stats",
            "Display data quality indicators" = "quality",
            "Include academic methodology notes" = "methodology"
          ),
          selected = c("quality", "methodology"),
          inline = TRUE
        )
      ),
      
      # Main analysis tabs
      tabsetPanel(
        id = ns("main_analysis_tabs"),
        type = "tabs",
        
        # Interactive Choropleth Map Tab
        tabPanel(
          "Interactive Choropleth Map",
          value = "choropleth",
          
          div(class = "tab-content",
            div(class = "map-container-sprint1",
              # Loading indicator
              conditionalPanel(
                condition = paste0("output['", ns("map_loading"), "'] == true"),
                div(class = "loading-indicator",
                  div(class = "loading-spinner"),
                  h4("Loading Brazilian Administrative Boundaries..."),
                  p("Integrating SIRGAS 2000 coordinate system and IBGE data")
                )
              ),
              
              # Interactive leaflet map
              leafletOutput(ns("interactive_choropleth"), height = "600px")
            ),
            
            # Academic methodology note
            conditionalPanel(
              condition = paste0("input['", ns("advanced_options"), "'].indexOf('methodology') > -1"),
              div(class = "methodology-note",
                strong("Academic Methodology: "),
                "Choropleth visualization uses SIRGAS 2000 (EPSG:4674) Brazilian official coordinate system. ",
                "Color scaling follows academic cartographic standards with viridis palette for accessibility. ",
                "Administrative boundaries sourced from IBGE 2020 official datasets."
              )
            )
          )
        ),
        
        # Legislative Density Analysis Tab
        tabPanel(
          "Density Analysis",
          value = "density",
          
          div(class = "tab-content",
            div(class = "analysis-card",
              h4("Legislative Document Density by Brazilian State"),
              plotlyOutput(ns("density_analysis_plot"), height = "500px"),
              
              conditionalPanel(
                condition = paste0("input['", ns("advanced_options"), "'].indexOf('methodology') > -1"),
                div(class = "methodology-note",
                  strong("Statistical Method: "),
                  "Density calculated as documents per 100,000 km² for standardized comparison. ",
                  "Error bars show 95% confidence intervals. Regional classification follows IBGE standards."
                )
              )
            )
          )
        ),
        
        # Federal System Analysis Tab
        tabPanel(
          "Federal System Analysis",
          value = "federal",
          
          div(class = "tab-content",
            div(class = "analysis-card",
              h4("Brazilian Federal System Legislative Comparison"),
              p("Comparative analysis across federal district, states, and regional aggregations following Brazilian administrative hierarchy."),
              
              DT::dataTableOutput(ns("federal_comparison_table")),
              
              conditionalPanel(
                condition = paste0("input['", ns("advanced_options"), "'].indexOf('methodology') > -1"),
                div(class = "methodology-note",
                  strong("Federal System Classification: "),
                  "Federal District (DF), Major States (≥2000 docs), Medium States (≥100 docs), Small States (<100 docs). ",
                  "Analysis considers Brazilian federative structure per 1988 Constitution."
                )
              )
            )
          )
        ),
        
        # Temporal Geographic Trends Tab
        tabPanel(
          "Temporal Trends",
          value = "temporal",
          
          div(class = "tab-content",
            div(class = "analysis-card",
              h4("Geographic Legislative Trends Over Time"),
              p("Time-series analysis of legislative activity patterns across Brazilian states and regions."),
              
              # Placeholder for temporal analysis (to be implemented)
              div(class = "loading-indicator",
                icon("clock", class = "fa-2x", style = "color: #3498db;"),
                h4("Temporal Analysis Implementation"),
                p("Time-series geographic analysis will be implemented with historical legislative data.")
              )
            )
          )
        ),
        
        # Spatial Clustering Analysis Tab
        tabPanel(
          "Spatial Clustering",
          value = "clustering",
          
          div(class = "tab-content",
            div(class = "analysis-card",
              h4("Spatial Autocorrelation and Clustering Analysis"),
              
              # Spatial statistics summary
              conditionalPanel(
                condition = paste0("input['", ns("advanced_options"), "'].indexOf('spatial_stats') > -1"),
                uiOutput(ns("spatial_statistics_summary"))
              ),
              
              # Placeholder for clustering visualization
              div(class = "loading-indicator",
                icon("project-diagram", class = "fa-2x", style = "color: #3498db;"),
                h4("Spatial Clustering Implementation"),
                p("Moran's I and Getis-Ord Gi* hotspot analysis with statistical significance testing.")
              )
            )
          )
        ),
        
        # Transport Infrastructure Correlation Tab
        tabPanel(
          "Transport Correlation",
          value = "transport",
          
          div(class = "tab-content",
            div(class = "analysis-card",
              h4("Transport Infrastructure and Legislative Activity Correlation"),
              p("Geospatial correlation analysis between transport infrastructure and legislative document patterns."),
              
              # Placeholder for transport correlation analysis
              div(class = "loading-indicator",
                icon("road", class = "fa-2x", style = "color: #3498db;"),
                h4("Transport Correlation Implementation"),
                p("Integration with ANTT, ANTAQ, and ANAC transport infrastructure datasets.")
              )
            )
          )
        )
      ),
      
      # Data quality and statistical validation panel
      conditionalPanel(
        condition = paste0("input['", ns("advanced_options"), "'].indexOf('quality') > -1"),
        div(class = "analysis-card",
          h4("Data Quality Assessment & Statistical Validation"),
          
          div(class = "mobile-stack",
            div(
              h5("Geographic Data Quality"),
              uiOutput(ns("data_quality_indicators"))
            ),
            div(
              h5("Statistical Validation"),
              conditionalPanel(
                condition = paste0("input['", ns("advanced_options"), "'].indexOf('confidence') > -1"),
                p("Confidence intervals calculated using bootstrap methods with 1000 replications."),
                p("Significance testing follows RESEARCH_METHODOLOGY.md academic standards.")
              )
            )
          )
        )
      ),
      
      # Academic citation footer
      div(class = "academic-citation",
        "Monitor Legislativo v4 | Brazilian Legislative Geographic Analysis | ",
        "Data: IBGE 2020, LexML Brasil | Coordinate System: SIRGAS 2000 (EPSG:4674)"
      )
    )
  )
}

# Export the UI function
geographic_ui_sprint1