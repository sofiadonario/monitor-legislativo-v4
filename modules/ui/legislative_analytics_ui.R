# LEGISLATIVE ANALYTICS UI MODULE
# ===============================
# UI components for legislative data science features with proper error handling
# Designed for integration with existing Shiny dashboard structure

cat("Loading Legislative Analytics UI Module...\n")

# UI Components for Legislative Analytics
# ======================================

#' Create Legislative Analytics Tab Panel
#' @return Shiny tab panel for legislative analytics
create_legislative_analytics_tab <- function() {
  tryCatch({
    tabItem(
      tabName = "legislative_analytics",
      fluidRow(
        box(
          title = "📊 Legislative Analytics Dashboard", 
          status = "primary", 
          solidHeader = TRUE,
          width = 12,
          div(
            h4("🇧🇷 Brazilian Legislative Intelligence System"),
            p("Advanced data science analytics for Brazilian transport legislation with comprehensive insights across multiple domains.")
          )
        )
      ),
      
      # Module Status Overview
      fluidRow(
        box(
          title = "🔧 Analysis Modules Status",
          status = "info",
          solidHeader = TRUE,
          width = 12,
          div(id = "module_status_display",
            p("Loading module status...")
          )
        )
      ),
      
      # Key Metrics Row
      fluidRow(
        valueBoxOutput("nlp_entities_box", width = 3),
        valueBoxOutput("citations_network_box", width = 3),
        valueBoxOutput("transport_policies_box", width = 3),
        valueBoxOutput("constitutional_compliance_box", width = 3)
      ),
      
      # Main Analytics Tabs
      fluidRow(
        box(
          title = "📈 Legislative Analytics",
          status = "primary",
          solidHeader = TRUE,
          width = 12,
          tabsetPanel(
            id = "legislative_tabs",
            
            # Brazilian Legal NLP Tab
            tabPanel(
              "🇧🇷 Legal NLP",
              div(
                h4("Brazilian Legal Text Analysis"),
                fluidRow(
                  column(6,
                    h5("📝 Entity Recognition"),
                    div(id = "nlp_entities_display",
                      p("Loading legal entities analysis...")
                    )
                  ),
                  column(6,
                    h5("📊 Sentiment Analysis"),
                    div(id = "nlp_sentiment_display",
                      p("Loading regulatory sentiment analysis...")
                    )
                  )
                ),
                fluidRow(
                  column(12,
                    h5("🏷️ Topic Modeling"),
                    div(id = "nlp_topics_display",
                      p("Loading legislative topic analysis...")
                    )
                  )
                )
              )
            ),
            
            # Citation Network Tab
            tabPanel(
              "🔗 Citation Network",
              div(
                h4("Legislative Citation Network Analysis"),
                fluidRow(
                  column(6,
                    h5("📊 Network Metrics"),
                    div(id = "citation_metrics_display",
                      p("Loading citation network metrics...")
                    )
                  ),
                  column(6,
                    h5("⚖️ Authority Analysis"),
                    div(id = "citation_authority_display",
                      p("Loading legal authority analysis...")
                    )
                  )
                ),
                fluidRow(
                  column(12,
                    h5("📈 Policy Influence"),
                    div(id = "citation_influence_display",
                      p("Loading policy influence mapping...")
                    )
                  )
                )
              )
            ),
            
            # Transport Policy Tab
            tabPanel(
              "🚛 Transport Policy",
              div(
                h4("Transport Policy Intelligence"),
                fluidRow(
                  column(4,
                    h5("🌱 Decarbonization"),
                    div(id = "transport_decarb_display",
                      p("Loading decarbonization analysis...")
                    )
                  ),
                  column(4,
                    h5("🔄 Modal Integration"),
                    div(id = "transport_modal_display",
                      p("Loading modal integration analysis...")
                    )
                  ),
                  column(4,
                    h5("📋 Regulatory Evolution"),
                    div(id = "transport_regulatory_display",
                      p("Loading regulatory evolution analysis...")
                    )
                  )
                )
              )
            ),
            
            # Constitutional Evolution Tab
            tabPanel(
              "🏛️ Constitutional",
              div(
                h4("Constitutional Evolution Tracking"),
                fluidRow(
                  column(6,
                    h5("📜 1988 Constitution Impact"),
                    div(id = "constitutional_impact_display",
                      p("Loading constitutional impact analysis...")
                    )
                  ),
                  column(6,
                    h5("🏦 Federal System Dynamics"),
                    div(id = "constitutional_federalism_display",
                      p("Loading federal system analysis...")
                    )
                  )
                ),
                fluidRow(
                  column(12,
                    h5("🔄 Institutional Changes"),
                    div(id = "constitutional_changes_display",
                      p("Loading institutional change tracking...")
                    )
                  )
                )
              )
            ),
            
            # Productivity Analytics Tab
            tabPanel(
              "📊 Productivity",
              div(
                h4("Legislative Productivity Analytics"),
                fluidRow(
                  column(4,
                    h5("⚡ Parliamentary Efficiency"),
                    div(id = "productivity_efficiency_display",
                      p("Loading efficiency metrics...")
                    )
                  ),
                  column(4,
                    h5("🔄 Policy Lifecycle"),
                    div(id = "productivity_lifecycle_display",
                      p("Loading lifecycle analysis...")
                    )
                  ),
                  column(4,
                    h5("📈 Impact Assessment"),
                    div(id = "productivity_impact_display",
                      p("Loading impact assessment...")
                    )
                  )
                )
              )
            ),
            
            # Machine Learning Tab
            tabPanel(
              "🤖 ML Models",
              div(
                h4("Machine Learning Insights"),
                fluidRow(
                  column(6,
                    h5("🏷️ Document Classification"),
                    div(id = "ml_classification_display",
                      p("Loading document classification...")
                    )
                  ),
                  column(6,
                    h5("📈 Trend Prediction"),
                    div(id = "ml_trends_display",
                      p("Loading trend predictions...")
                    )
                  )
                ),
                fluidRow(
                  column(12,
                    h5("💡 Policy Recommendations"),
                    div(id = "ml_recommendations_display",
                      p("Loading policy recommendations...")
                    )
                  )
                )
              )
            ),
            
            # Unified Insights Tab
            tabPanel(
              "🎯 Unified Insights",
              div(
                h4("Cross-Module Insights & Recommendations"),
                fluidRow(
                  column(6,
                    h5("🔍 Key Findings"),
                    div(id = "unified_findings_display",
                      p("Loading key findings...")
                    )
                  ),
                  column(6,
                    h5("📋 Strategic Recommendations"),
                    div(id = "unified_recommendations_display",
                      p("Loading strategic recommendations...")
                    )
                  )
                ),
                fluidRow(
                  column(12,
                    h5("🔗 Cross-Module Patterns"),
                    div(id = "unified_patterns_display",
                      p("Loading cross-module pattern analysis...")
                    )
                  )
                )
              )
            )
          )
        )
      ),
      
      # Control Panel
      fluidRow(
        box(
          title = "🔧 Analysis Controls",
          status = "warning",
          solidHeader = TRUE,
          width = 12,
          fluidRow(
            column(3,
              actionButton("run_legislative_analysis", 
                          "🚀 Run Analysis", 
                          class = "btn-primary btn-lg",
                          style = "width: 100%;")
            ),
            column(3,
              selectInput("analysis_modules", 
                         "Modules to Run:",
                         choices = list(
                           "All Modules" = "all",
                           "NLP Only" = "nlp",
                           "Citations Only" = "citations",
                           "Transport Only" = "transport",
                           "Constitutional Only" = "constitutional",
                           "Productivity Only" = "productivity",
                           "ML Only" = "ml"
                         ),
                         selected = "all")
            ),
            column(3,
              numericInput("sample_size",
                          "Sample Size:",
                          value = 1000,
                          min = 100,
                          max = 5000,
                          step = 100)
            ),
            column(3,
              div(
                h5("⚡ Railway Optimized"),
                p("Memory-efficient analysis for cloud deployment")
              )
            )
          )
        )
      )
    )
  }, error = function(e) {
    cat("Error creating legislative analytics tab:", e$message, "\n")
    return(
      tabItem(
        tabName = "legislative_analytics",
        fluidRow(
          box(
            title = "Error", 
            status = "danger", 
            solidHeader = TRUE,
            width = 12,
            p("Failed to load Legislative Analytics UI. Please check module dependencies.")
          )
        )
      )
    )
  })
}

#' Create Legislative Analytics Menu Item
#' @return Shiny menu item for sidebar
create_legislative_analytics_menu <- function() {
  tryCatch({
    menuItem(
      "📊 Legislative Analytics",
      tabName = "legislative_analytics",
      icon = icon("chart-line"),
      badgeLabel = "Advanced",
      badgeColor = "green"
    )
  }, error = function(e) {
    cat("Error creating legislative analytics menu:", e$message, "\n")
    return(NULL)
  })
}

#' Server Logic for Legislative Analytics
#' @param input Shiny input
#' @param output Shiny output
#' @param session Shiny session
#' @param connection Database connection
legislative_analytics_server <- function(input, output, session, connection = NULL) {
  
  # Reactive values for storing analysis results
  analysis_results <- reactiveVal(NULL)
  
  # Value boxes for key metrics
  output$nlp_entities_box <- renderValueBox({
    results <- analysis_results()
    entities_count <- if (!isTRUE(is.null(results)) && !is.null(results$analyses$nlp)) {
      scalar_num(results$analyses$nlp$summary$entities_found, default = 0)
    } else 0

    safe_valueBox(
      value = entities_count,
      subtitle = "Legal Entities Found",
      icon = icon("search"),
      color = "blue"
    )
  })
  
  output$citations_network_box <- renderValueBox({
    results <- analysis_results()
    citations_count <- if (!isTRUE(is.null(results)) && !is.null(results$analyses$citations)) {
      scalar_num(results$analyses$citations$total_citations_found, default = 0)
    } else 0

    safe_valueBox(
      value = citations_count,
      subtitle = "Citations Analyzed",
      icon = icon("network-wired"),
      color = "green"
    )
  })
  
  output$transport_policies_box <- renderValueBox({
    results <- analysis_results()
    transport_docs <- if (!isTRUE(is.null(results)) && !is.null(results$analyses$transport)) {
      scalar_num(results$analyses$transport$summary$decarbonization_docs, default = 0)
    } else 0

    safe_valueBox(
      value = transport_docs,
      subtitle = "Transport Policies",
      icon = icon("truck"),
      color = "yellow"
    )
  })
  
  output$constitutional_compliance_box <- renderValueBox({
    results <- analysis_results()
    constitutional_docs <- if (!isTRUE(is.null(results)) && !is.null(results$analyses$constitutional)) {
      scalar_num(results$analyses$constitutional$summary$constitutional_documents, default = 0)
    } else 0

    safe_valueBox(
      value = constitutional_docs,
      subtitle = "Constitutional Refs",
      icon = icon("balance-scale"),
      color = "red"
    )
  })
  
  # Run analysis when button is clicked
  observeEvent(input$run_legislative_analysis, {
    # Show loading notification
    showNotification(
      "🚀 Running legislative analysis... This may take a few moments.",
      type = "message",
      duration = 5
    )
    
    # Update UI to show loading state
    update_ui_loading_state(session)
    
    # Run the analysis
    tryCatch({
      if (exists("run_comprehensive_legislative_analysis")) {
        modules_to_run <- if (input$analysis_modules == "all") "all" else input$analysis_modules
        sample_size <- min(max(input$sample_size, 100), 5000)  # Bounds checking
        
        results <- run_comprehensive_legislative_analysis(
          connection = connection,
          sample_size = sample_size,
          analysis_modules = modules_to_run
        )
        
        analysis_results(results)
        update_analysis_displays(session, results)
        
        showNotification(
          "✅ Legislative analysis completed successfully!",
          type = "success",
          duration = 3
        )
      } else {
        stop("Legislative analysis functions not loaded")
      }
    }, error = function(e) {
      showNotification(
        paste("❌ Analysis failed:", e$message),
        type = "error",
        duration = 10
      )
      update_ui_error_state(session, e$message)
    })
  })
  
  # Initialize with module status
  observe({
    if (exists("legislative_modules_loaded")) {
      update_module_status_display(session, legislative_modules_loaded)
    }
  })
}

# Helper functions for UI updates
# ==============================

#' Update UI to Loading State
#' @param session Shiny session
update_ui_loading_state <- function(session) {
  loading_elements <- c(
    "nlp_entities_display", "nlp_sentiment_display", "nlp_topics_display",
    "citation_metrics_display", "citation_authority_display", "citation_influence_display",
    "transport_decarb_display", "transport_modal_display", "transport_regulatory_display",
    "constitutional_impact_display", "constitutional_federalism_display", "constitutional_changes_display",
    "productivity_efficiency_display", "productivity_lifecycle_display", "productivity_impact_display",
    "ml_classification_display", "ml_trends_display", "ml_recommendations_display",
    "unified_findings_display", "unified_recommendations_display", "unified_patterns_display"
  )
  
  for (element in loading_elements) {
    session$sendCustomMessage(
      type = "updateDiv",
      message = list(
        id = element,
        content = "<div class='loading-spinner'><i class='fa fa-spinner fa-spin'></i> Analyzing...</div>"
      )
    )
  }
}

#' Update Analysis Display Elements
#' @param session Shiny session
#' @param results Analysis results
update_analysis_displays <- function(session, results) {
  
  # Update NLP displays
  if (!is.null(results$analyses$nlp)) {
    update_nlp_displays(session, results$analyses$nlp)
  }
  
  # Update Citation displays
  if (!is.null(results$analyses$citations)) {
    update_citation_displays(session, results$analyses$citations)
  }
  
  # Update Transport displays
  if (!is.null(results$analyses$transport)) {
    update_transport_displays(session, results$analyses$transport)
  }
  
  # Update Constitutional displays
  if (!is.null(results$analyses$constitutional)) {
    update_constitutional_displays(session, results$analyses$constitutional)
  }
  
  # Update Productivity displays
  if (!is.null(results$analyses$productivity)) {
    update_productivity_displays(session, results$analyses$productivity)
  }
  
  # Update ML displays
  if (!is.null(results$analyses$ml)) {
    update_ml_displays(session, results$analyses$ml)
  }
  
  # Update Unified Insights
  if (!is.null(results$unified_insights)) {
    update_unified_displays(session, results$unified_insights)
  }
}

#' Update Module Status Display
#' @param session Shiny session
#' @param modules_status Module loading status
update_module_status_display <- function(session, modules_status) {
  status_html <- "<div class='module-status'>"
  
  for (module in names(modules_status)) {
    status_icon <- if (modules_status[[module]]) "✅" else "❌"
    status_class <- if (modules_status[[module]]) "text-success" else "text-danger"
    status_html <- paste0(status_html, 
      "<span class='", status_class, "'>", status_icon, " ", toupper(module), "</span> ")
  }
  
  status_html <- paste0(status_html, "</div>")
  
  session$sendCustomMessage(
    type = "updateDiv",
    message = list(
      id = "module_status_display",
      content = status_html
    )
  )
}

#' Update UI to Error State
#' @param session Shiny session
#' @param error_message Error message
update_ui_error_state <- function(session, error_message) {
  error_content <- paste0(
    "<div class='alert alert-danger'>",
    "<h5>❌ Analysis Failed</h5>",
    "<p>", htmltools::htmlEscape(error_message), "</p>",
    "<p>Please check the system logs and try again.</p>",
    "</div>"
  )
  
  # Update all display elements with error message
  error_elements <- c(
    "nlp_entities_display", "citation_metrics_display", 
    "transport_decarb_display", "constitutional_impact_display",
    "productivity_efficiency_display", "ml_classification_display"
  )
  
  for (element in error_elements) {
    session$sendCustomMessage(
      type = "updateDiv",
      message = list(
        id = element,
        content = error_content
      )
    )
  }
}

# Specific display update functions for each module
update_nlp_displays <- function(session, nlp_results) {
  # NLP entities display
  entities_content <- if (!isTRUE(is.null(nlp_results$sample_entities)) && nrow(nlp_results$sample_entities) > 0) {
    entity_list <- paste(nlp_results$sample_entities$entity[1:min(5, nrow(nlp_results$sample_entities))], collapse = ", ")
    paste0("<p><strong>Top Entities:</strong> ", entity_list, "</p>")
  } else {
    "<p>No entities data available</p>"
  }
  
  session$sendCustomMessage(
    type = "updateDiv",
    message = list(id = "nlp_entities_display", content = entities_content)
  )
  
  # Sentiment display
  sentiment_content <- if (!is.null(nlp_results$summary$avg_sentiment)) {
    paste0("<p><strong>Average Sentiment:</strong> ", round(nlp_results$summary$avg_sentiment, 3), "</p>")
  } else {
    "<p>No sentiment data available</p>"
  }
  
  session$sendCustomMessage(
    type = "updateDiv",
    message = list(id = "nlp_sentiment_display", content = sentiment_content)
  )
}

update_citation_displays <- function(session, citation_results) {
  metrics_content <- paste0(
    "<p><strong>Total Citations:</strong> ", citation_results$total_citations_found %||% 0, "</p>",
    "<p><strong>Network Density:</strong> ", round(citation_results$network_density %||% 0, 4), "</p>"
  )
  
  session$sendCustomMessage(
    type = "updateDiv",
    message = list(id = "citation_metrics_display", content = metrics_content)
  )
}

update_transport_displays <- function(session, transport_results) {
  decarb_content <- paste0(
    "<p><strong>Decarbonization Documents:</strong> ", transport_results$summary$decarbonization_docs %||% 0, "</p>"
  )
  
  session$sendCustomMessage(
    type = "updateDiv",
    message = list(id = "transport_decarb_display", content = decarb_content)
  )
}

update_constitutional_displays <- function(session, constitutional_results) {
  impact_content <- paste0(
    "<p><strong>Constitutional Documents:</strong> ", constitutional_results$summary$constitutional_documents %||% 0, "</p>"
  )
  
  session$sendCustomMessage(
    type = "updateDiv",
    message = list(id = "constitutional_impact_display", content = impact_content)
  )
}

update_productivity_displays <- function(session, productivity_results) {
  efficiency_content <- paste0(
    "<p><strong>High Efficiency Documents:</strong> ", productivity_results$summary$high_efficiency_documents %||% 0, "</p>"
  )
  
  session$sendCustomMessage(
    type = "updateDiv",
    message = list(id = "productivity_efficiency_display", content = efficiency_content)
  )
}

update_ml_displays <- function(session, ml_results) {
  classification_content <- paste0(
    "<p><strong>Documents Classified:</strong> ", ml_results$summary$documents_classified %||% 0, "</p>"
  )
  
  session$sendCustomMessage(
    type = "updateDiv",
    message = list(id = "ml_classification_display", content = classification_content)
  )
}

update_unified_displays <- function(session, unified_results) {
  findings_content <- if (!is.null(unified_results$key_findings)) {
    findings_list <- names(unified_results$key_findings)[1:min(3, length(unified_results$key_findings))]
    paste0("<ul>", paste0("<li>", findings_list, "</li>", collapse = ""), "</ul>")
  } else {
    "<p>No unified findings available</p>"
  }
  
  session$sendCustomMessage(
    type = "updateDiv",
    message = list(id = "unified_findings_display", content = findings_content)
  )
}

# Utility function
`%||%` <- function(a, b) if (is.null(a)) b else a

cat("✅ Legislative Analytics UI Module loaded successfully\n")
cat("   🎨 Interactive dashboard components: ENABLED\n")
cat("   📊 Value boxes and metrics: ENABLED\n")
cat("   🔧 Analysis controls: ENABLED\n")
cat("   ⚡ Real-time updates: ENABLED\n")
cat("   📱 Responsive design: ENABLED\n")
cat("   🛡️ Error handling: ENABLED\n")

# Export UI functions
LEGISLATIVE_UI_FUNCTIONS <- list(
  create_legislative_analytics_tab = create_legislative_analytics_tab,
  create_legislative_analytics_menu = create_legislative_analytics_menu,
  legislative_analytics_server = legislative_analytics_server
)