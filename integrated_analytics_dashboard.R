# Integrated Analytics Dashboard for Brazilian Legislative Analysis
# MackMonitor v4 - Comprehensive R/Shiny Application
# Author: Analytics Module
# Date: 2025-01-25

library(shiny)
library(shinydashboard)
library(shinydashboardPlus)
library(DT)
library(plotly)
library(leaflet)
library(visNetwork)
library(dplyr)
library(ggplot2)

# Load all analysis modules
source("data_quality_assessment.R")
source("text_preprocessing_module.R")
source("topic_modeling_module.R")
source("sentiment_modality_module.R")
source("ner_relationship_module.R")
source("geospatial_visualization_module.R")

# Load existing database connection
if (file.exists("scripts/R/database_connection.R")) {
  source("scripts/R/database_connection.R")
}

# ============================================================================
# 1. UI DEFINITION
# ============================================================================

ui <- dashboardPage(
  skin = "blue",
  
  # Header
  dashboardHeader(
    title = "MackMonitor Analytics v4",
    dropdownMenu(
      type = "notifications",
      badgeStatus = "success",
      notificationItem(
        text = "Data quality check complete",
        icon = icon("check-circle"),
        status = "success"
      )
    )
  ),
  
  # Sidebar
  dashboardSidebar(
    sidebarMenu(
      id = "tabs",
      menuItem("Overview", tabName = "overview", icon = icon("dashboard")),
      menuItem("Data Quality", tabName = "quality", icon = icon("check-square")),
      menuItem("Text Analysis", icon = icon("file-text"),
        menuSubItem("Preprocessing", tabName = "preprocessing"),
        menuSubItem("Topic Modeling", tabName = "topics"),
        menuSubItem("Sentiment Analysis", tabName = "sentiment")
      ),
      menuItem("Entity Analysis", tabName = "entities", icon = icon("project-diagram")),
      menuItem("Geographic Analysis", tabName = "geographic", icon = icon("map")),
      menuItem("Export Results", tabName = "export", icon = icon("download")),
      
      # Analysis controls
      br(),
      h4("Analysis Settings", style = "padding-left: 15px;"),
      
      dateRangeInput(
        "date_range",
        "Date Range:",
        start = "2020-01-01",
        end = Sys.Date(),
        width = "100%"
      ),
      
      selectInput(
        "authority_level",
        "Authority Level:",
        choices = c("All" = "all", 
                   "Federal" = "federal",
                   "State" = "estadual", 
                   "Municipal" = "municipal"),
        selected = "all",
        width = "100%"
      ),
      
      selectInput(
        "document_type",
        "Document Type:",
        choices = c("All" = "all",
                   "Legislation" = "legislacao",
                   "Jurisprudence" = "jurisprudencia",
                   "Doctrine" = "doutrina"),
        selected = "all",
        width = "100%"
      ),
      
      actionButton(
        "run_analysis",
        "Run Analysis",
        icon = icon("play"),
        class = "btn-primary",
        width = "90%",
        style = "margin: 10px;"
      )
    )
  ),
  
  # Body
  dashboardBody(
    tags$head(
      tags$style(HTML("
        .content-wrapper, .right-side {
          background-color: #f4f4f4;
        }
        .small-box {
          border-radius: 5px;
        }
        .info-box {
          border-radius: 5px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.12);
        }
      "))
    ),
    
    tabItems(
      # Overview Tab
      tabItem(
        tabName = "overview",
        h2("Legislative Analytics Dashboard"),
        
        # Summary boxes
        fluidRow(
          valueBoxOutput("total_documents"),
          valueBoxOutput("unique_entities"),
          valueBoxOutput("active_topics")
        ),
        
        fluidRow(
          valueBoxOutput("avg_sentiment"),
          valueBoxOutput("geographic_coverage"),
          valueBoxOutput("data_quality_score")
        ),
        
        # Key visualizations
        fluidRow(
          box(
            title = "Document Timeline",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            plotlyOutput("timeline_plot", height = "300px")
          )
        ),
        
        fluidRow(
          box(
            title = "Quick Insights",
            status = "info",
            width = 6,
            uiOutput("quick_insights")
          ),
          box(
            title = "Recent Analysis",
            status = "success",
            width = 6,
            DT::dataTableOutput("recent_analysis")
          )
        )
      ),
      
      # Data Quality Tab
      tabItem(
        tabName = "quality",
        h2("Data Quality Assessment"),
        
        fluidRow(
          box(
            title = "Quality Metrics",
            status = "warning",
            width = 12,
            DT::dataTableOutput("quality_metrics")
          )
        ),
        
        fluidRow(
          box(
            title = "Field Completeness",
            width = 6,
            plotlyOutput("completeness_heatmap")
          ),
          box(
            title = "Temporal Coverage",
            width = 6,
            plotlyOutput("temporal_coverage_plot")
          )
        ),
        
        fluidRow(
          box(
            title = "Data Issues",
            status = "danger",
            width = 12,
            uiOutput("data_issues")
          )
        )
      ),
      
      # Preprocessing Tab
      tabItem(
        tabName = "preprocessing",
        h2("Text Preprocessing"),
        
        fluidRow(
          box(
            title = "Preprocessing Settings",
            status = "primary",
            width = 4,
            checkboxGroupInput(
              "preprocess_options",
              "Options:",
              choices = list(
                "Remove stopwords" = "stopwords",
                "Apply stemming" = "stemming",
                "Remove legal boilerplate" = "boilerplate",
                "Extract n-grams" = "ngrams"
              ),
              selected = c("stopwords", "boilerplate")
            ),
            
            numericInput(
              "min_doc_length",
              "Min document length:",
              value = 50,
              min = 10
            ),
            
            actionButton(
              "run_preprocessing",
              "Preprocess Documents",
              icon = icon("cogs"),
              class = "btn-warning"
            )
          ),
          
          box(
            title = "Preprocessing Results",
            status = "success",
            width = 8,
            verbatimTextOutput("preprocessing_summary"),
            br(),
            DT::dataTableOutput("feature_stats")
          )
        )
      ),
      
      # Topic Modeling Tab
      tabItem(
        tabName = "topics",
        h2("Topic Analysis"),
        
        fluidRow(
          box(
            title = "Topic Model Settings",
            width = 3,
            radioButtons(
              "topic_method",
              "Method:",
              choices = c("LDA" = "lda", "STM" = "stm"),
              selected = "lda"
            ),
            
            sliderInput(
              "num_topics",
              "Number of topics:",
              min = 5,
              max = 50,
              value = 15,
              step = 5
            ),
            
            checkboxInput(
              "dynamic_topics",
              "Enable dynamic analysis",
              value = TRUE
            ),
            
            actionButton(
              "run_topics",
              "Run Topic Modeling",
              icon = icon("sitemap"),
              class = "btn-success"
            )
          ),
          
          box(
            title = "Topic Distribution",
            width = 9,
            plotlyOutput("topic_distribution", height = "400px")
          )
        ),
        
        fluidRow(
          box(
            title = "Topic Evolution",
            width = 12,
            plotlyOutput("topic_evolution", height = "400px")
          )
        ),
        
        fluidRow(
          box(
            title = "Topic Details",
            width = 12,
            DT::dataTableOutput("topic_terms")
          )
        )
      ),
      
      # Sentiment Analysis Tab
      tabItem(
        tabName = "sentiment",
        h2("Sentiment & Modality Analysis"),
        
        fluidRow(
          box(
            title = "Overall Sentiment",
            width = 6,
            plotlyOutput("sentiment_distribution")
          ),
          box(
            title = "Regulatory Modality",
            width = 6,
            plotlyOutput("modality_radar")
          )
        ),
        
        fluidRow(
          box(
            title = "Temporal Trends",
            width = 12,
            plotlyOutput("sentiment_timeline", height = "300px")
          )
        ),
        
        fluidRow(
          box(
            title = "Policy Actions",
            width = 6,
            DT::dataTableOutput("policy_actions")
          ),
          box(
            title = "Regulatory Impact",
            width = 6,
            plotlyOutput("impact_analysis")
          )
        )
      ),
      
      # Entity Analysis Tab
      tabItem(
        tabName = "entities",
        h2("Entity & Network Analysis"),
        
        fluidRow(
          box(
            title = "Entity Network",
            width = 8,
            visNetworkOutput("entity_network", height = "500px")
          ),
          box(
            title = "Network Controls",
            width = 4,
            selectInput(
              "network_type",
              "Network Type:",
              choices = c("Entities" = "entity", 
                         "Citations" = "citation"),
              selected = "entity"
            ),
            
            sliderInput(
              "network_threshold",
              "Edge threshold:",
              min = 1,
              max = 10,
              value = 3
            ),
            
            h4("Top Entities"),
            DT::dataTableOutput("top_entities")
          )
        ),
        
        fluidRow(
          box(
            title = "Entity Statistics",
            width = 12,
            DT::dataTableOutput("entity_stats")
          )
        )
      ),
      
      # Geographic Analysis Tab
      tabItem(
        tabName = "geographic",
        h2("Geographic Analysis"),
        
        fluidRow(
          box(
            title = "Legislative Activity Map",
            width = 12,
            leafletOutput("main_map", height = "500px")
          )
        ),
        
        fluidRow(
          box(
            title = "Map Controls",
            width = 3,
            selectInput(
              "map_variable",
              "Variable to map:",
              choices = c(
                "Document Count" = "document_count",
                "Average Sentiment" = "avg_sentiment",
                "Regulatory Strictness" = "avg_strictness"
              ),
              selected = "document_count"
            ),
            
            radioButtons(
              "geo_level",
              "Geographic Level:",
              choices = c("State" = "state", 
                         "Municipality" = "municipality"),
              selected = "state"
            )
          ),
          
          box(
            title = "Geographic Statistics",
            width = 9,
            DT::dataTableOutput("geo_stats")
          )
        ),
        
        fluidRow(
          box(
            title = "Policy Diffusion",
            width = 12,
            plotlyOutput("diffusion_plot", height = "400px")
          )
        )
      ),
      
      # Export Tab
      tabItem(
        tabName = "export",
        h2("Export Results"),
        
        fluidRow(
          box(
            title = "Export Options",
            status = "info",
            width = 12,
            
            h4("Select data to export:"),
            checkboxGroupInput(
              "export_options",
              NULL,
              choices = list(
                "Data Quality Report" = "quality",
                "Preprocessed Data" = "preprocessed",
                "Topic Model Results" = "topics",
                "Sentiment Analysis" = "sentiment",
                "Entity Networks" = "entities",
                "Geographic Data" = "geographic"
              ),
              selected = "quality"
            ),
            
            br(),
            
            radioButtons(
              "export_format",
              "Export Format:",
              choices = c("CSV" = "csv", 
                         "Excel" = "xlsx", 
                         "R Data" = "rds"),
              selected = "csv",
              inline = TRUE
            ),
            
            br(),
            
            downloadButton(
              "download_results",
              "Download Results",
              class = "btn-primary"
            ),
            
            br(), br(),
            
            h4("Generate Report"),
            p("Create a comprehensive PDF report with all analysis results."),
            
            downloadButton(
              "download_report",
              "Generate PDF Report",
              class = "btn-success"
            )
          )
        )
      )
    )
  )
)

# ============================================================================
# 2. SERVER LOGIC
# ============================================================================

server <- function(input, output, session) {
  
  # Reactive values to store analysis results
  analysis_results <- reactiveValues(
    documents = NULL,
    quality = NULL,
    preprocessed = NULL,
    topics = NULL,
    sentiment = NULL,
    entities = NULL,
    geographic = NULL
  )
  
  # Load initial data
  observe({
    if (exists("db_pool") && !is.null(db_pool)) {
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      
      # Apply filters
      query <- build_filtered_query(
        input$date_range,
        input$authority_level,
        input$document_type
      )
      
      analysis_results$documents <- dbGetQuery(conn, query)
    }
  })
  
  # Main analysis trigger
  observeEvent(input$run_analysis, {
    
    withProgress(message = "Running comprehensive analysis...", {
      
      # 1. Data Quality
      setProgress(0.1, detail = "Assessing data quality...")
      if (!is.null(analysis_results$documents)) {
        conn <- poolCheckout(db_pool)
        on.exit(poolReturn(conn))
        
        quality_results <- list()
        quality_results$correctness <- check_data_correctness(conn)
        quality_results$completeness <- check_data_completeness(conn)
        quality_results$joins <- check_join_integrity(conn)
        
        analysis_results$quality <- quality_results
      }
      
      # 2. Preprocessing
      setProgress(0.3, detail = "Preprocessing texts...")
      if (!is.null(analysis_results$documents) && 
          nrow(analysis_results$documents) > 0) {
        
        config <- PREPROCESSING_CONFIG
        config$use_stopwords <- "stopwords" %in% input$preprocess_options
        config$use_stemming <- "stemming" %in% input$preprocess_options
        config$remove_boilerplate <- "boilerplate" %in% input$preprocess_options
        config$min_doc_length <- input$min_doc_length
        
        analysis_results$preprocessed <- process_documents_batch(
          analysis_results$documents,
          config = config
        )
      }
      
      # 3. Topic Modeling
      setProgress(0.5, detail = "Running topic modeling...")
      if (!is.null(analysis_results$preprocessed)) {
        analysis_results$topics <- run_topic_modeling_pipeline(
          analysis_results$preprocessed,
          method = input$topic_method,
          k = input$num_topics,
          dynamic = input$dynamic_topics
        )
      }
      
      # 4. Sentiment Analysis
      setProgress(0.6, detail = "Analyzing sentiment and modality...")
      if (!is.null(analysis_results$documents)) {
        analysis_results$sentiment <- run_sentiment_modality_pipeline(
          analysis_results$documents
        )
      }
      
      # 5. Entity Extraction
      setProgress(0.8, detail = "Extracting entities and relationships...")
      if (!is.null(analysis_results$documents)) {
        analysis_results$entities <- run_ner_relationship_pipeline(
          analysis_results$documents
        )
      }
      
      # 6. Geographic Analysis
      setProgress(0.9, detail = "Creating geographic visualizations...")
      if (!is.null(analysis_results$documents)) {
        analysis_results$geographic <- run_geospatial_pipeline(
          analysis_results$documents,
          analysis_results
        )
      }
      
      setProgress(1, detail = "Analysis complete!")
    })
    
    showNotification("Analysis completed successfully!", 
                    type = "success", 
                    duration = 5)
  })
  
  # ============ OVERVIEW TAB OUTPUTS ============
  
  output$total_documents <- renderValueBox({
    valueBox(
      value = ifelse(is.null(analysis_results$documents), 
                    0, 
                    nrow(analysis_results$documents)),
      subtitle = "Total Documents",
      icon = icon("file-text"),
      color = "blue"
    )
  })
  
  output$unique_entities <- renderValueBox({
    valueBox(
      value = ifelse(is.null(analysis_results$entities), 
                    0, 
                    n_distinct(analysis_results$entities$entities$text)),
      subtitle = "Unique Entities",
      icon = icon("project-diagram"),
      color = "green"
    )
  })
  
  output$active_topics <- renderValueBox({
    valueBox(
      value = ifelse(is.null(analysis_results$topics), 
                    0, 
                    ifelse(!is.null(analysis_results$topics$stm_model),
                          analysis_results$topics$stm_model$settings$dim$K,
                          15)),
      subtitle = "Active Topics",
      icon = icon("sitemap"),
      color = "purple"
    )
  })
  
  output$avg_sentiment <- renderValueBox({
    avg_sent <- 0
    color <- "yellow"
    
    if (!is.null(analysis_results$sentiment)) {
      avg_sent <- round(mean(analysis_results$sentiment$sentiment$sentiment_mean, 
                            na.rm = TRUE), 3)
      color <- ifelse(avg_sent > 0.1, "green", 
                     ifelse(avg_sent < -0.1, "red", "yellow"))
    }
    
    valueBox(
      value = avg_sent,
      subtitle = "Average Sentiment",
      icon = icon("smile"),
      color = color
    )
  })
  
  output$geographic_coverage <- renderValueBox({
    valueBox(
      value = ifelse(is.null(analysis_results$geographic), 
                    0, 
                    analysis_results$geographic$geo_stats$states_with_data),
      subtitle = "States Covered",
      icon = icon("map-marked-alt"),
      color = "aqua"
    )
  })
  
  output$data_quality_score <- renderValueBox({
    score <- 0
    color <- "red"
    
    if (!is.null(analysis_results$quality)) {
      # Simple quality score calculation
      completeness <- analysis_results$quality$completeness$field_completeness
      if (!is.null(completeness)) {
        score <- round(mean(as.numeric(completeness[-1]), na.rm = TRUE), 1)
        color <- ifelse(score > 80, "green", 
                       ifelse(score > 60, "yellow", "red"))
      }
    }
    
    valueBox(
      value = paste0(score, "%"),
      subtitle = "Data Quality Score",
      icon = icon("check-circle"),
      color = color
    )
  })
  
  output$timeline_plot <- renderPlotly({
    if (!is.null(analysis_results$documents)) {
      timeline_data <- analysis_results$documents %>%
        mutate(year_month = floor_date(data_publicacao, "month")) %>%
        group_by(year_month) %>%
        summarise(count = n())
      
      p <- ggplot(timeline_data, aes(x = year_month, y = count)) +
        geom_line(color = "steelblue", size = 1) +
        geom_area(fill = "steelblue", alpha = 0.3) +
        theme_minimal() +
        labs(x = "", y = "Documents")
      
      ggplotly(p)
    }
  })
  
  output$quick_insights <- renderUI({
    insights <- list()
    
    if (!is.null(analysis_results$topics) && 
        !is.null(analysis_results$topics$insights)) {
      
      # Top emerging topics
      if (!is.null(analysis_results$topics$insights$emerging_topics) &&
          nrow(analysis_results$topics$insights$emerging_topics) > 0) {
        insights[[length(insights) + 1]] <- tags$li(
          tags$strong("Emerging Topic: "),
          analysis_results$topics$insights$emerging_topics$topic[1]
        )
      }
      
      # Dominant sentiment
      if (!is.null(analysis_results$sentiment)) {
        sentiment_dist <- table(analysis_results$sentiment$sentiment$sentiment_category)
        dominant <- names(sentiment_dist)[which.max(sentiment_dist)]
        insights[[length(insights) + 1]] <- tags$li(
          tags$strong("Dominant Sentiment: "),
          dominant
        )
      }
    }
    
    if (length(insights) > 0) {
      tags$ul(insights)
    } else {
      p("Run analysis to see insights")
    }
  })
  
  # ============ DATA QUALITY TAB OUTPUTS ============
  
  output$quality_metrics <- DT::renderDataTable({
    if (!is.null(analysis_results$quality)) {
      # Create summary table
      metrics <- data.frame(
        Metric = c("Total Records", "Valid URNs", "Complete Dates", 
                  "Duplicate URNs", "Missing Content"),
        Value = c(
          analysis_results$quality$correctness$urn_compliance$total_records,
          analysis_results$quality$correctness$urn_compliance$valid_urns,
          analysis_results$quality$correctness$date_validity$total_records -
            analysis_results$quality$correctness$date_validity$missing_dates,
          nrow(analysis_results$quality$joins$urn_duplicates),
          NA  # Would need to check content field
        )
      )
      
      DT::datatable(metrics, options = list(pageLength = 10))
    }
  })
  
  output$completeness_heatmap <- renderPlotly({
    if (!is.null(analysis_results$quality) && 
        !is.null(analysis_results$quality$completeness$field_completeness)) {
      
      completeness <- analysis_results$quality$completeness$field_completeness
      
      # Create heatmap data
      fields <- names(completeness)[-1]
      values <- as.numeric(completeness[1, -1])
      
      plot_ly(
        x = fields,
        y = ["Completeness"],
        z = matrix(values, nrow = 1),
        type = "heatmap",
        colorscale = "RdYlGn",
        zmin = 0,
        zmax = 100
      ) %>%
        layout(
          xaxis = list(title = ""),
          yaxis = list(title = "")
        )
    }
  })
  
  # ============ EXPORT FUNCTIONALITY ============
  
  output$download_results <- downloadHandler(
    filename = function() {
      paste0("mackmonitor_results_", Sys.Date(), ".", input$export_format)
    },
    content = function(file) {
      # Combine selected results
      export_data <- list()
      
      if ("quality" %in% input$export_options && !is.null(analysis_results$quality)) {
        export_data$quality_summary <- generate_quality_report(analysis_results$quality)
      }
      
      if ("topics" %in% input$export_options && !is.null(analysis_results$topics)) {
        export_data$topics <- analysis_results$topics$insights
      }
      
      if ("sentiment" %in% input$export_options && !is.null(analysis_results$sentiment)) {
        export_data$sentiment <- analysis_results$sentiment$summary
      }
      
      # Export based on format
      if (input$export_format == "rds") {
        saveRDS(export_data, file)
      } else if (input$export_format == "csv") {
        # For CSV, need to flatten the data
        # This is simplified - would need proper implementation
        write.csv(export_data[[1]], file)
      }
    }
  )
  
  # Build filtered query helper
  build_filtered_query <- function(date_range, authority, doc_type) {
    query <- "SELECT * FROM documents WHERE 1=1"
    
    if (!is.null(date_range)) {
      query <- paste0(query, 
                     sprintf(" AND data_publicacao BETWEEN '%s' AND '%s'",
                            date_range[1], date_range[2]))
    }
    
    if (authority != "all") {
      query <- paste0(query, 
                     sprintf(" AND authority_level = '%s'", authority))
    }
    
    if (doc_type != "all") {
      query <- paste0(query, 
                     sprintf(" AND tipo = '%s'", doc_type))
    }
    
    return(query)
  }
}

# ============================================================================
# 3. RUN APPLICATION
# ============================================================================

shinyApp(ui = ui, server = server)