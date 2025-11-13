#' Text Reuse Detection UI Module
#'
#' Shiny module UI for exploring text reuse patterns across legislative documents
#'
#' @author Monitor Legislativo Analytics Team
#' @date 2025-01-13

library(shiny)
library(bslib)
library(shinyWidgets)

text_reuse_ui <- function(id) {
  ns <- NS(id)

  page_fillable(
    h2("Text Reuse Detection", class = "mb-3"),
    p("Identify similar text passages across legislative documents using Locality-Sensitive Hashing (LSH)."),

    layout_sidebar(
      sidebar = sidebar(
        width = 300,
        title = "Analysis Settings",

        # Analysis mode selector
        radioButtons(
          ns("analysis_mode"),
          "Analysis Mode:",
          choices = c(
            "Search by Document" = "document",
            "Cluster View" = "clusters",
            "Cross-Jurisdiction" = "jurisdiction",
            "Timeline Analysis" = "timeline"
          ),
          selected = "document"
        ),

        hr(),

        # Document search (conditional)
        conditionalPanel(
          condition = "input.analysis_mode == 'document'",
          ns = ns,
          numericInput(
            ns("focal_doc_id"),
            "Document ID:",
            value = NULL,
            min = 1,
            step = 1
          ),
          actionButton(
            ns("search_doc"),
            "Find Similar Documents",
            class = "btn-primary w-100",
            icon = icon("search")
          )
        ),

        # Cluster settings (conditional)
        conditionalPanel(
          condition = "input.analysis_mode == 'clusters'",
          ns = ns,
          numericInput(
            ns("min_cluster_size"),
            "Minimum Cluster Size:",
            value = 3,
            min = 2,
            step = 1
          ),
          actionButton(
            ns("detect_clusters"),
            "Detect Clusters",
            class = "btn-primary w-100",
            icon = icon("project-diagram")
          )
        ),

        # Cross-jurisdiction settings (conditional)
        conditionalPanel(
          condition = "input.analysis_mode == 'jurisdiction'",
          ns = ns,
          selectInput(
            ns("jurisdiction_filter"),
            "Show:",
            choices = c(
              "All Cross-Jurisdiction" = "all",
              "Federal → State" = "fed_state",
              "State → State" = "state_state",
              "State → Municipal" = "state_muni",
              "Federal → Municipal" = "fed_muni"
            ),
            selected = "all"
          ),
          actionButton(
            ns("load_jurisdiction"),
            "Load Data",
            class = "btn-primary w-100",
            icon = icon("globe")
          )
        ),

        # Timeline settings (conditional)
        conditionalPanel(
          condition = "input.analysis_mode == 'timeline'",
          ns = ns,
          numericInput(
            ns("timeline_doc_id"),
            "Document ID:",
            value = NULL,
            min = 1,
            step = 1
          ),
          actionButton(
            ns("analyze_timeline"),
            "Analyze Timeline",
            class = "btn-primary w-100",
            icon = icon("clock")
          )
        ),

        hr(),

        # Shared settings
        sliderInput(
          ns("similarity_threshold"),
          "Similarity Threshold:",
          min = 0.5,
          max = 1.0,
          value = 0.7,
          step = 0.05
        ),

        # Year range filter
        sliderInput(
          ns("year_range"),
          "Year Range:",
          min = 1990,
          max = 2025,
          value = c(2000, 2025),
          step = 1,
          sep = ""
        ),

        # Nivel filter
        checkboxGroupInput(
          ns("nivel_filter"),
          "Jurisdiction Level:",
          choices = c("Federal", "Estadual", "Municipal"),
          selected = c("Federal", "Estadual", "Municipal")
        ),

        hr(),

        # Export options
        downloadButton(
          ns("download_results"),
          "Export Results (CSV)",
          class = "btn-secondary w-100 mb-2"
        ),

        downloadButton(
          ns("download_network"),
          "Export Network (JSON)",
          class = "btn-secondary w-100"
        ),

        hr(),

        # System info
        div(
          class = "small text-muted",
          uiOutput(ns("system_info"))
        )
      ),

      # Main content area
      navset_card_tab(
        id = ns("main_tabs"),

        # Tab 1: Search Results / Overview
        nav_panel(
          "Results",
          card(
            card_header("Analysis Results"),
            conditionalPanel(
              condition = "input.analysis_mode == 'document'",
              ns = ns,
              div(
                class = "mb-3",
                uiOutput(ns("focal_doc_info"))
              )
            ),
            conditionalPanel(
              condition = "input.analysis_mode == 'clusters'",
              ns = ns,
              div(
                class = "mb-3",
                uiOutput(ns("cluster_summary"))
              )
            ),
            div(
              style = "height: 500px; overflow-y: auto;",
              DT::dataTableOutput(ns("results_table"))
            )
          )
        ),

        # Tab 2: Network Visualization
        nav_panel(
          "Network",
          card(
            card_header(
              "Similarity Network",
              class = "d-flex justify-content-between align-items-center",
              div(
                actionButton(ns("reset_network"), "Reset View", size = "sm", class = "btn-outline-secondary"),
                actionButton(ns("export_network_img"), "Export Image", size = "sm", class = "btn-outline-secondary")
              )
            ),
            card_body(
              height = "600px",
              visNetworkOutput(ns("network_viz"), height = "100%")
            )
          )
        ),

        # Tab 3: Flow Diagram (Sankey)
        nav_panel(
          "Text Flow",
          card(
            card_header("Cross-Jurisdiction Text Flow"),
            card_body(
              height = "600px",
              networkD3::sankeyNetworkOutput(ns("sankey_viz"), height = "100%")
            )
          )
        ),

        # Tab 4: Text Comparison
        nav_panel(
          "Text Comparison",
          card(
            card_header("Side-by-Side Document Comparison"),
            div(
              class = "mb-3",
              fluidRow(
                column(
                  6,
                  selectInput(
                    ns("compare_doc1"),
                    "Document 1:",
                    choices = NULL
                  )
                ),
                column(
                  6,
                  selectInput(
                    ns("compare_doc2"),
                    "Document 2:",
                    choices = NULL
                  )
                )
              ),
              actionButton(ns("compare_texts"), "Compare", class = "btn-primary")
            ),
            fluidRow(
              column(
                6,
                card(
                  card_header(textOutput(ns("doc1_title"))),
                  div(
                    style = "height: 500px; overflow-y: auto; font-family: monospace; font-size: 0.9em;",
                    uiOutput(ns("doc1_text"))
                  )
                )
              ),
              column(
                6,
                card(
                  card_header(textOutput(ns("doc2_title"))),
                  div(
                    style = "height: 500px; overflow-y: auto; font-family: monospace; font-size: 0.9em;",
                    uiOutput(ns("doc2_text"))
                  )
                )
              )
            ),
            card(
              card_header("Common Text Passages"),
              div(
                style = "height: 200px; overflow-y: auto;",
                uiOutput(ns("common_text"))
              )
            )
          )
        ),

        # Tab 5: Timeline View
        nav_panel(
          "Timeline",
          card(
            card_header("Temporal Evolution of Text Reuse"),
            card_body(
              height = "600px",
              plotly::plotlyOutput(ns("timeline_plot"), height = "100%")
            )
          ),
          card(
            card_header("Chronological Adoption Table"),
            div(
              style = "height: 300px; overflow-y: auto;",
              DT::dataTableOutput(ns("timeline_table"))
            )
          )
        ),

        # Tab 6: Statistics
        nav_panel(
          "Statistics",
          layout_column_wrap(
            width = 1/2,
            card(
              card_header("Overall Statistics"),
              value_box(
                title = "Total Indexed Documents",
                value = textOutput(ns("stat_total_docs")),
                showcase = icon("database"),
                theme = "primary"
              ),
              value_box(
                title = "Similar Pairs Detected",
                value = textOutput(ns("stat_total_pairs")),
                showcase = icon("link"),
                theme = "info"
              ),
              value_box(
                title = "Average Similarity",
                value = textOutput(ns("stat_avg_similarity")),
                showcase = icon("chart-line"),
                theme = "success"
              ),
              value_box(
                title = "Text Reuse Clusters",
                value = textOutput(ns("stat_clusters")),
                showcase = icon("project-diagram"),
                theme = "warning"
              )
            ),
            card(
              card_header("Distribution Plots"),
              plotly::plotlyOutput(ns("similarity_distribution"), height = "250px"),
              plotly::plotlyOutput(ns("cluster_size_distribution"), height = "250px")
            )
          ),
          card(
            card_header("Top Text Reuse Patterns"),
            div(
              style = "height: 300px; overflow-y: auto;",
              DT::dataTableOutput(ns("top_patterns_table"))
            )
          )
        )
      )
    )
  )
}

# Helper UI components

similarity_badge <- function(similarity) {
  color <- if (similarity >= 0.9) {
    "success"
  } else if (similarity >= 0.75) {
    "info"
  } else if (similarity >= 0.6) {
    "warning"
  } else {
    "secondary"
  }

  tags$span(
    class = paste0("badge bg-", color),
    sprintf("%.1f%%", similarity * 100)
  )
}

jurisdiction_badge <- function(nivel) {
  color <- switch(
    nivel,
    "Federal" = "primary",
    "Estadual" = "success",
    "Municipal" = "info",
    "secondary"
  )

  tags$span(
    class = paste0("badge bg-", color),
    nivel
  )
}
