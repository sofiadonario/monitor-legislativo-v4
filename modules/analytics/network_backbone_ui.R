# ==============================================================================
# NETWORK BACKBONE ANALYSIS - UI MODULE
# ==============================================================================
# Monitor Legislativo v4 - Network Analysis User Interface
#
# This Shiny module provides the user interface for network backbone extraction
# and visualization, including controls for network type selection, backbone
# parameters, filtering, and interactive visualizations.
# ==============================================================================

#' Network Backbone UI Module
#'
#' @param id Module namespace ID
#'
#' @return Shiny UI element
#'
#' @export
network_backbone_ui <- function(id) {
  ns <- NS(id)

  tagList(
    # Header
    fluidRow(
      column(12,
        h2("Network Backbone Analysis",
           style = "margin-bottom: 20px; color: #2c3e50; font-weight: bold;"),
        p("Identify statistically significant relationships in legislative networks using backbone extraction algorithms.",
          style = "color: #7f8c8d; margin-bottom: 30px;")
      )
    ),

    # Control Panel
    fluidRow(
      # Left Panel - Network Configuration
      column(3,
        wellPanel(
          h4("Network Configuration", style = "font-weight: bold; margin-top: 0;"),

          # Network Type Selector
          selectInput(
            ns("network_type"),
            label = "Network Type",
            choices = c(
              "Citation Network" = "citation",
              "Co-Authorship Network" = "coauthorship",
              "Topic Network" = "topic"
            ),
            selected = "citation"
          ),

          # Conditional Topic Keywords Input
          conditionalPanel(
            condition = sprintf("input['%s'] == 'topic'", ns("network_type")),
            ns = ns,
            textAreaInput(
              ns("topic_keywords"),
              label = "Topic Keywords (one per line)",
              value = "transporte|rodovia|mobilidade\nambiental|sustentavel\nsaude|hospital",
              rows = 5,
              placeholder = "Enter keywords separated by | for each topic"
            ),
            helpText("Each line defines a topic with | separated keywords")
          ),

          hr(),

          # Backbone Extraction Method
          selectInput(
            ns("backbone_method"),
            label = "Backbone Method",
            choices = c(
              "Disparity Filter" = "disparity",
              "Statistical Significance" = "significance",
              "Degree-Based" = "degree"
            ),
            selected = "disparity"
          ),

          # Alpha Threshold Slider
          sliderInput(
            ns("alpha_threshold"),
            label = "Alpha Threshold",
            min = 0.01,
            max = 0.20,
            value = 0.05,
            step = 0.01
          ),
          helpText("Lower values = sparser backbone (more aggressive filtering)"),

          hr(),

          # Minimum Edge Weight
          numericInput(
            ns("min_citations"),
            label = "Minimum Edge Weight",
            value = 2,
            min = 1,
            max = 10,
            step = 1
          ),
          helpText("Minimum citations/collaborations for an edge"),

          hr(),

          # Build Network Button
          actionButton(
            ns("build_network"),
            label = "Build Network",
            icon = icon("project-diagram"),
            class = "btn-primary btn-block",
            style = "margin-bottom: 10px;"
          ),

          # Extract Backbone Button
          actionButton(
            ns("extract_backbone"),
            label = "Extract Backbone",
            icon = icon("filter"),
            class = "btn-success btn-block"
          )
        )
      ),

      # Right Panel - Filters
      column(3,
        wellPanel(
          h4("Filters", style = "font-weight: bold; margin-top: 0;"),

          # Year Range Slider
          sliderInput(
            ns("year_range"),
            label = "Year Range",
            min = 1990,
            max = as.numeric(format(Sys.Date(), "%Y")),
            value = c(2015, as.numeric(format(Sys.Date(), "%Y"))),
            step = 1,
            sep = ""
          ),

          # Jurisdiction Filter
          selectInput(
            ns("jurisdiction_filter"),
            label = "Jurisdiction",
            choices = c(
              "All" = "all",
              "Federal" = "federal",
              "State" = "estadual",
              "Municipal" = "municipal"
            ),
            selected = "all",
            multiple = FALSE
          ),

          # State Filter (conditional on jurisdiction)
          conditionalPanel(
            condition = sprintf("input['%s'] == 'estadual'", ns("jurisdiction_filter")),
            ns = ns,
            selectInput(
              ns("state_filter"),
              label = "State",
              choices = c("All States" = "all",
                         "SP" = "SP", "RJ" = "RJ", "MG" = "MG", "RS" = "RS",
                         "PR" = "PR", "SC" = "SC", "BA" = "BA", "PE" = "PE"),
              selected = "all"
            )
          ),

          # Document Type Filter
          selectInput(
            ns("doc_type_filter"),
            label = "Document Type",
            choices = c(
              "All Types" = "all",
              "Lei" = "lei",
              "Decreto" = "decreto",
              "Resolucao" = "resolucao",
              "Portaria" = "portaria"
            ),
            selected = "all",
            multiple = TRUE
          ),

          hr(),

          # Sampling for Large Networks
          checkboxInput(
            ns("enable_sampling"),
            label = "Enable Sampling (for large networks)",
            value = FALSE
          ),

          conditionalPanel(
            condition = sprintf("input['%s']", ns("enable_sampling")),
            ns = ns,
            numericInput(
              ns("max_nodes"),
              label = "Maximum Nodes",
              value = 1000,
              min = 100,
              max = 10000,
              step = 100
            )
          )
        )
      ),

      # Visualization Panel
      column(6,
        wellPanel(
          h4("Visualization Settings", style = "font-weight: bold; margin-top: 0;"),

          fluidRow(
            column(6,
              selectInput(
                ns("layout_algorithm"),
                label = "Layout Algorithm",
                choices = c(
                  "Fruchterman-Reingold" = "fr",
                  "Kamada-Kawai" = "kk",
                  "DrL (Large Networks)" = "drl",
                  "Large Graph Layout" = "lgl"
                ),
                selected = "fr"
              )
            ),
            column(6,
              selectInput(
                ns("node_size_by"),
                label = "Node Size By",
                choices = c(
                  "Degree" = "degree",
                  "Betweenness" = "betweenness",
                  "PageRank" = "pagerank",
                  "Constant" = "constant"
                ),
                selected = "degree"
              )
            )
          ),

          fluidRow(
            column(6,
              selectInput(
                ns("node_color_by"),
                label = "Node Color By",
                choices = c(
                  "Community" = "community",
                  "Type" = "type",
                  "Year" = "ano",
                  "Constant" = "constant"
                ),
                selected = "community"
              )
            ),
            column(6,
              selectInput(
                ns("community_method"),
                label = "Community Detection",
                choices = c(
                  "Louvain" = "louvain",
                  "Infomap" = "infomap",
                  "Walktrap" = "walktrap",
                  "Leiden" = "leiden"
                ),
                selected = "louvain"
              )
            )
          ),

          hr(),

          checkboxInput(
            ns("show_labels"),
            label = "Show Node Labels",
            value = FALSE
          ),

          conditionalPanel(
            condition = sprintf("input['%s']", ns("show_labels")),
            ns = ns,
            sliderInput(
              ns("label_threshold"),
              label = "Label Threshold (min degree)",
              min = 0,
              max = 50,
              value = 10,
              step = 1
            )
          )
        )
      )
    ),

    hr(),

    # Status and Progress
    fluidRow(
      column(12,
        uiOutput(ns("status_message"))
      )
    ),

    # Main Visualizations - Tabset
    fluidRow(
      column(12,
        tabsetPanel(
          id = ns("viz_tabs"),
          type = "tabs",

          # Interactive Network Tab
          tabPanel(
            "Interactive Network",
            icon = icon("project-diagram"),
            br(),
            fluidRow(
              column(12,
                shinycssloaders::withSpinner(
                  visNetworkOutput(ns("interactive_network"), height = "600px"),
                  type = 4,
                  color = "#3498db"
                )
              )
            ),
            br(),
            fluidRow(
              column(12,
                downloadButton(ns("download_gexf"), "Download GEXF for Gephi",
                              class = "btn-info")
              )
            )
          ),

          # Network Metrics Tab
          tabPanel(
            "Network Metrics",
            icon = icon("chart-bar"),
            br(),
            fluidRow(
              column(6,
                h4("Network Statistics", style = "font-weight: bold;"),
                shinycssloaders::withSpinner(
                  DT::dataTableOutput(ns("metrics_table")),
                  type = 4
                )
              ),
              column(6,
                h4("Metrics Dashboard", style = "font-weight: bold;"),
                shinycssloaders::withSpinner(
                  plotOutput(ns("metrics_dashboard"), height = "500px"),
                  type = 4
                )
              )
            )
          ),

          # Influential Nodes Tab
          tabPanel(
            "Influential Nodes",
            icon = icon("star"),
            br(),
            fluidRow(
              column(12,
                h4("Top Influential Nodes (by Centrality Measures)",
                   style = "font-weight: bold;"),
                numericInput(
                  ns("top_n_nodes"),
                  label = "Number of Top Nodes",
                  value = 20,
                  min = 5,
                  max = 100,
                  step = 5
                ),
                actionButton(
                  ns("calculate_influential"),
                  "Calculate Influential Nodes",
                  icon = icon("calculator"),
                  class = "btn-primary"
                ),
                br(), br(),
                shinycssloaders::withSpinner(
                  DT::dataTableOutput(ns("influential_nodes_table")),
                  type = 4
                )
              )
            )
          ),

          # Community Analysis Tab
          tabPanel(
            "Communities",
            icon = icon("users"),
            br(),
            fluidRow(
              column(6,
                h4("Community Detection Results", style = "font-weight: bold;"),
                shinycssloaders::withSpinner(
                  plotOutput(ns("community_plot"), height = "500px"),
                  type = 4
                )
              ),
              column(6,
                h4("Community Sizes", style = "font-weight: bold;"),
                shinycssloaders::withSpinner(
                  plotOutput(ns("community_sizes_plot"), height = "500px"),
                  type = 4
                )
              )
            ),
            br(),
            fluidRow(
              column(12,
                h4("Community Membership", style = "font-weight: bold;"),
                shinycssloaders::withSpinner(
                  DT::dataTableOutput(ns("community_table")),
                  type = 4
                )
              )
            )
          ),

          # Backbone Comparison Tab
          tabPanel(
            "Backbone Comparison",
            icon = icon("balance-scale"),
            br(),
            fluidRow(
              column(12,
                h4("Original vs. Backbone Network", style = "font-weight: bold;"),
                shinycssloaders::withSpinner(
                  plotOutput(ns("backbone_comparison"), height = "600px"),
                  type = 4
                )
              )
            ),
            br(),
            fluidRow(
              column(6,
                h4("Edge Reduction Statistics"),
                verbatimTextOutput(ns("reduction_stats"))
              ),
              column(6,
                h4("Degree Distribution Comparison"),
                shinycssloaders::withSpinner(
                  plotOutput(ns("degree_comparison"), height = "400px"),
                  type = 4
                )
              )
            )
          ),

          # Export Tab
          tabPanel(
            "Export",
            icon = icon("download"),
            br(),
            fluidRow(
              column(12,
                h4("Export Network Data", style = "font-weight: bold;"),
                p("Download network data in various formats for further analysis."),
                br()
              )
            ),
            fluidRow(
              column(4,
                wellPanel(
                  h5("Network Files", style = "font-weight: bold;"),
                  downloadButton(ns("download_graphml"), "GraphML Format",
                                class = "btn-block btn-primary"),
                  br(),
                  downloadButton(ns("download_gexf_export"), "GEXF Format (Gephi)",
                                class = "btn-block btn-primary"),
                  br(),
                  downloadButton(ns("download_edgelist"), "Edge List (CSV)",
                                class = "btn-block btn-primary")
                )
              ),
              column(4,
                wellPanel(
                  h5("Analysis Results", style = "font-weight: bold;"),
                  downloadButton(ns("download_metrics"), "Network Metrics (CSV)",
                                class = "btn-block btn-success"),
                  br(),
                  downloadButton(ns("download_centrality"), "Centrality Scores (CSV)",
                                class = "btn-block btn-success"),
                  br(),
                  downloadButton(ns("download_communities"), "Community Assignments (CSV)",
                                class = "btn-block btn-success")
                )
              ),
              column(4,
                wellPanel(
                  h5("Visualizations", style = "font-weight: bold;"),
                  downloadButton(ns("download_network_plot"), "Network Plot (PNG)",
                                class = "btn-block btn-info"),
                  br(),
                  downloadButton(ns("download_metrics_plot"), "Metrics Dashboard (PNG)",
                                class = "btn-block btn-info"),
                  br(),
                  downloadButton(ns("download_comparison_plot"), "Backbone Comparison (PNG)",
                                class = "btn-block btn-info")
                )
              )
            )
          )
        )
      )
    ),

    # Footer with References
    hr(),
    fluidRow(
      column(12,
        p(
          strong("Methodology:"),
          "Backbone extraction uses the disparity filter algorithm (Serrano et al., 2009) to identify statistically significant edges.",
          br(),
          em("Reference:"),
          "Serrano, M. Á., Boguñá, M., & Vespignani, A. (2009). Extracting the multiscale backbone of complex weighted networks. PNAS, 106(16), 6483-6488.",
          style = "color: #7f8c8d; font-size: 0.9em; margin-top: 20px;"
        )
      )
    )
  )
}

cat("Network backbone UI module loaded\n")
