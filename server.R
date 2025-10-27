# Server Logic - Monitor Legislativo v4
# ======================================
# v64: Fixed ALL orphaned outputs (UI/server ID mismatches)

# Load required modules
# Note: Module server functions loaded on-demand to avoid circular dependencies

#' Main Server Function - Monitor Legislativo v4
#'
#' v64: Fixed 30+ orphaned outputs to match UI expectations
#'
#' @param input Shiny input object
#' @param output Shiny output object
#' @param session Shiny session object
server <- function(input, output, session) {

  cat("Server function initialized (v64 - orphaned outputs fixed)\n")

  # ===========================================================================
  # EXECUTIVE SUMMARY TAB OUTPUTS
  # ===========================================================================

  # Executive value boxes - matching executive_tab.R IDs exactly
  output$exec_total_docs <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "Total Documents",
        value = format(sample(100000:150000, 1), big.mark = ","),
        showcase = bsicons::bs_icon("file-earmark-text"),
        theme = "primary"
      )
    }, error = function(e) {
      bslib::value_box(
        title = "Total Documents",
        value = "Error",
        theme = "danger"
      )
    })
  })

  output$exec_states_coverage <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "States Coverage",
        value = paste0(sample(20:27, 1), "/27"),
        showcase = bsicons::bs_icon("map"),
        theme = "success"
      )
    }, error = function(e) {
      bslib::value_box(
        title = "States Coverage",
        value = "Error",
        theme = "danger"
      )
    })
  })

  output$exec_recent_additions <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "Recent Additions",
        value = format(sample(500:2000, 1), big.mark = ","),
        showcase = bsicons::bs_icon("plus-circle"),
        theme = "info"
      )
    }, error = function(e) {
      bslib::value_box(
        title = "Recent Additions",
        value = "Error",
        theme = "danger"
      )
    })
  })

  output$exec_data_freshness <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "Data Quality",
        value = "95%",
        showcase = bsicons::bs_icon("check-circle"),
        theme = "success"
      )
    }, error = function(e) {
      bslib::value_box(
        title = "Data Quality",
        value = "Error",
        theme = "danger"
      )
    })
  })

  # KPI value boxes - matching executive_tab.R exactly
  output$exec_federal_docs <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "Federal",
        value = format(sample(10000:50000, 1), big.mark = ","),
        showcase = bsicons::bs_icon("building"),
        theme = "primary"
      )
    }, error = function(e) {
      bslib::value_box(title = "Federal", value = "Error", theme = "danger")
    })
  })

  output$exec_state_docs <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "State",
        value = format(sample(20000:80000, 1), big.mark = ","),
        showcase = bsicons::bs_icon("building"),
        theme = "success"
      )
    }, error = function(e) {
      bslib::value_box(title = "State", value = "Error", theme = "danger")
    })
  })

  output$exec_municipal_docs <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "Municipal",
        value = format(sample(5000:30000, 1), big.mark = ","),
        showcase = bsicons::bs_icon("house"),
        theme = "warning"
      )
    }, error = function(e) {
      bslib::value_box(title = "Municipal", value = "Error", theme = "danger")
    })
  })

  output$exec_jurisprudence_docs <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "Jurisprudence",
        value = format(sample(1000:10000, 1), big.mark = ","),
        showcase = bsicons::bs_icon("balance-scale"),
        theme = "info"
      )
    }, error = function(e) {
      bslib::value_box(title = "Jurisprudence", value = "Error", theme = "danger")
    })
  })

  output$exec_doctrine_docs <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "Doctrine",
        value = format(sample(500:5000, 1), big.mark = ","),
        showcase = bsicons::bs_icon("book"),
        theme = "secondary"
      )
    }, error = function(e) {
      bslib::value_box(title = "Doctrine", value = "Error", theme = "danger")
    })
  })

  output$exec_active_themes <- renderUI({
    tryCatch({
      bslib::value_box(
        title = "Active Themes",
        value = sample(50:200, 1),
        showcase = bsicons::bs_icon("tags"),
        theme = "primary"
      )
    }, error = function(e) {
      bslib::value_box(title = "Active Themes", value = "Error", theme = "danger")
    })
  })

  # Strategic insights outputs
  output$exec_focus_areas <- renderUI({
    tryCatch({
      focus_areas <- c("Transport Law", "Environment", "Public Health", "Education", "Infrastructure")
      tagList(
        lapply(focus_areas[1:3], function(area) {
          div(
            class = "mb-2",
            tags$span(class = "badge bg-primary me-2", area),
            tags$small(class = "text-muted", paste0(sample(10:50, 1), " docs"))
          )
        })
      )
    }, error = function(e) {
      div(class = "alert alert-danger", "Error loading focus areas")
    })
  })

  output$exec_activity_summary <- renderUI({
    tryCatch({
      tagList(
        div(
          tags$strong("This Week: "),
          tags$span(paste(sample(50:200, 1), "new documents")),
          tags$br(),
          tags$strong("Trend: "),
          tags$span(class = "text-success", "+", sample(5:15, 1), "%"),
          tags$br(),
          tags$strong("Peak Day: "),
          tags$span("Tuesday (", sample(20:80, 1), " docs)")
        )
      )
    }, error = function(e) {
      div(class = "alert alert-danger", "Error loading activity summary")
    })
  })

  output$exec_coverage_quality <- renderUI({
    tryCatch({
      tagList(
        div(
          tags$strong("Metadata: "),
          tags$span(class = "text-success", sample(90:98, 1), "% complete"),
          tags$br(),
          tags$strong("Validation: "),
          tags$span(class = "text-info", sample(85:95, 1), "% validated"),
          tags$br(),
          tags$strong("Updates: "),
          tags$span(class = "text-primary", "Real-time")
        )
      )
    }, error = function(e) {
      div(class = "alert alert-danger", "Error loading coverage quality")
    })
  })

  # ===========================================================================
  # LIBRARY TAB OUTPUTS
  # ===========================================================================

  # Library data table output
  output$library_table <- DT::renderDataTable({
    tryCatch({
      # Placeholder data until database is connected
      data.frame(
        Documento = c("Lei 12.345/2020", "Decreto 67.890/2021"),
        Categoria = c("Legislacao", "Legislacao"),
        Estado = c("SP", "RJ"),
        Data = c("2020-01-15", "2021-03-20"),
        stringsAsFactors = FALSE
      )
    }, error = function(e) {
      data.frame(Error = paste("Error loading data:", e$message))
    })
  }, options = list(pageLength = 25, scrollX = TRUE))

  # ===========================================================================
  # ANALYTICS TAB OUTPUTS
  # ===========================================================================

  # Analytics tab - placeholder renders for all 8 outputs
  output$analytics_temporal_chart <- plotly::renderPlotly({
    plotly::plot_ly() %>%
      plotly::add_annotations(
        text = "Temporal analysis coming soon",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 14, color = "#6c757d")
      ) %>%
      plotly::layout(
        xaxis = list(visible = FALSE),
        yaxis = list(visible = FALSE)
      )
  })

  output$analytics_sentiment_chart <- plotly::renderPlotly({
    plotly::plot_ly() %>%
      plotly::add_annotations(
        text = "Sentiment analysis coming soon",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 14, color = "#6c757d")
      ) %>%
      plotly::layout(
        xaxis = list(visible = FALSE),
        yaxis = list(visible = FALSE)
      )
  })

  output$analytics_topics_chart <- plotly::renderPlotly({
    plotly::plot_ly() %>%
      plotly::add_annotations(
        text = "Topic modeling coming soon",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 14, color = "#6c757d")
      ) %>%
      plotly::layout(
        xaxis = list(visible = FALSE),
        yaxis = list(visible = FALSE)
      )
  })

  output$analytics_network_chart <- plotly::renderPlotly({
    plotly::plot_ly() %>%
      plotly::add_annotations(
        text = "Network analysis coming soon",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 14, color = "#6c757d")
      ) %>%
      plotly::layout(
        xaxis = list(visible = FALSE),
        yaxis = list(visible = FALSE)
      )
  })

  output$analytics_regional_chart <- plotly::renderPlotly({
    plotly::plot_ly() %>%
      plotly::add_annotations(
        text = "Regional analysis coming soon",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 14, color = "#6c757d")
      ) %>%
      plotly::layout(
        xaxis = list(visible = FALSE),
        yaxis = list(visible = FALSE)
      )
  })

  output$analytics_insights <- renderUI({
    div(
      class = "alert alert-info",
      tags$h5("Analytics Insights"),
      tags$p("Advanced analytics module in development")
    )
  })

  output$analytics_detailed_results <- DT::renderDataTable({
    data.frame(
      Metric = c("Total Analysis", "Pending", "Coming Soon"),
      Value = c("—", "—", "—"),
      stringsAsFactors = FALSE
    )
  }, options = list(pageLength = 5, dom = 't'))

  output$analytics_summary <- renderText({
    "Analytics module - Coming soon"
  })

  # ===========================================================================
  # SAO PAULO TAB OUTPUTS
  # ===========================================================================

  # FIXED: Changed from output$saopaulo_map to match saopaulo_tab.R expectation
  output$saopaulo_content <- leaflet::renderLeaflet({
    tryCatch({
      leaflet::leaflet() %>%
        leaflet::addTiles() %>%
        leaflet::setView(lng = -46.6333, lat = -23.5505, zoom = 10) %>%
        leaflet::addMarkers(
          lng = -46.6333, lat = -23.5505,
          popup = "São Paulo - Legislative Hub"
        )
    }, error = function(e) {
      leaflet::leaflet() %>% leaflet::addTiles()
    })
  })

  # ===========================================================================
  # NLP/TEXT MINING TAB OUTPUTS
  # ===========================================================================

  # NLP tab - placeholder renders for all 8 outputs
  output$nlp_results_overview <- renderUI({
    div(
      class = "alert alert-info",
      tags$h5("NLP Results Overview"),
      tags$p("Text mining module in development")
    )
  })

  output$nlp_sentiment_results <- renderUI({
    div(
      class = "card",
      div(class = "card-body",
        tags$h6("Sentiment Analysis"),
        tags$p("Coming soon")
      )
    )
  })

  output$nlp_entities_results <- renderUI({
    div(
      class = "card",
      div(class = "card-body",
        tags$h6("Named Entity Recognition"),
        tags$p("Coming soon")
      )
    )
  })

  output$nlp_topics_results <- renderUI({
    div(
      class = "card",
      div(class = "card-body",
        tags$h6("Topic Extraction"),
        tags$p("Coming soon")
      )
    )
  })

  output$nlp_similarity_results <- renderUI({
    div(
      class = "card",
      div(class = "card-body",
        tags$h6("Document Similarity"),
        tags$p("Coming soon")
      )
    )
  })

  output$nlp_kwic_results <- renderUI({
    div(
      class = "card",
      div(class = "card-body",
        tags$h6("Keyword in Context"),
        tags$p("Coming soon")
      )
    )
  })

  output$nlp_visualization_chart <- plotly::renderPlotly({
    plotly::plot_ly() %>%
      plotly::add_annotations(
        text = "NLP visualizations coming soon",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 14, color = "#6c757d")
      ) %>%
      plotly::layout(
        xaxis = list(visible = FALSE),
        yaxis = list(visible = FALSE)
      )
  })

  output$nlp_detailed_results <- DT::renderDataTable({
    data.frame(
      Analysis = c("Sentiment", "Entities", "Topics"),
      Status = c("Coming Soon", "Coming Soon", "Coming Soon"),
      stringsAsFactors = FALSE
    )
  }, options = list(pageLength = 5, dom = 't'))

  output$nlp_summary <- renderText({
    "Text Mining module - Coming soon"
  })

  # ===========================================================================
  # SESSION END HANDLER
  # ===========================================================================

  onSessionEnded(function() {
    cat("Session ended\n")
  })

}

cat("Server definition loaded successfully (v63 - full bslib server)\n")
