# Survival Analysis UI Module
# Sprint 4 - PRD 4.1: Survival Analysis for Bill Progression
# UI components for visualizing and analyzing bill survival probabilities

#' UI for Survival Analysis Module
#'
#' @param id Module namespace ID
#' @return Shiny UI elements
survival_ui <- function(id) {
  ns <- NS(id)

  tagList(
    fluidRow(
      column(12,
        h2(icon("chart-line"), "Survival Analysis: Bill Progression"),
        p("Analyze the time-to-passage for legislative bills using survival analysis methods.",
          "Understand factors that influence bill progression through the legislative process.")
      )
    ),

    # Control Panel
    fluidRow(
      box(
        title = "Analysis Controls",
        status = "primary",
        solidHeader = TRUE,
        collapsible = TRUE,
        width = 12,

        fluidRow(
          column(3,
            selectInput(
              ns("analysis_mode"),
              "Analysis Mode",
              choices = c(
                "Exploratory (Kaplan-Meier)" = "explore",
                "Predictive (Cox & Parametric)" = "predict",
                "Full Analysis" = "full"
              ),
              selected = "explore"
            )
          ),

          column(3,
            selectInput(
              ns("stratify_by"),
              "Stratify By",
              choices = c(
                "None" = "none",
                "Document Type" = "doc_type",
                "Government Level" = "level",
                "Government Branch" = "branch"
              ),
              selected = "doc_type"
            )
          ),

          column(3,
            numericInput(
              ns("min_events"),
              "Minimum Events per Bill",
              value = 1,
              min = 1,
              max = 10,
              step = 1
            )
          ),

          column(3,
            br(),
            actionButton(
              ns("run_analysis"),
              "Run Analysis",
              icon = icon("play"),
              class = "btn-success",
              width = "100%"
            )
          )
        )
      )
    ),

    # Status and Summary
    fluidRow(
      column(4,
        valueBoxOutput(ns("total_bills"), width = 12)
      ),
      column(4,
        valueBoxOutput(ns("passed_bills"), width = 12)
      ),
      column(4,
        valueBoxOutput(ns("median_time"), width = 12)
      )
    ),

    # Kaplan-Meier Survival Curve
    fluidRow(
      box(
        title = "Kaplan-Meier Survival Curve",
        status = "info",
        solidHeader = TRUE,
        collapsible = TRUE,
        width = 12,

        plotOutput(ns("km_plot"), height = "500px"),

        br(),

        div(
          class = "well",
          h4("Interpretation:"),
          p(
            strong("Survival Curve:"), "Shows the probability of a bill remaining unpassed over time.",
            "A steeper decline indicates faster passage rates."
          ),
          p(
            strong("Median Survival Time:"), "The time at which 50% of bills have passed.",
            "Vertical line marks this threshold."
          ),
          p(
            strong("Confidence Intervals:"), "Shaded areas represent 95% confidence bands.",
            "Wider bands indicate greater uncertainty."
          )
        )
      )
    ),

    # Conditional UI for Predictive Models
    conditionalPanel(
      condition = sprintf("input['%s'] == 'predict' || input['%s'] == 'full'",
                         ns("analysis_mode"), ns("analysis_mode")),

      # Cox Model Results
      fluidRow(
        box(
          title = "Cox Proportional Hazards Model",
          status = "warning",
          solidHeader = TRUE,
          collapsible = TRUE,
          width = 6,

          plotOutput(ns("cox_hazard_plot"), height = "400px"),

          br(),

          h4("Hazard Ratios"),
          DT::dataTableOutput(ns("hazard_ratios_table"))
        ),

        box(
          title = "Model Diagnostics",
          status = "warning",
          solidHeader = TRUE,
          collapsible = TRUE,
          width = 6,

          h4("Proportional Hazards Test"),
          verbatimTextOutput(ns("ph_test")),

          br(),

          h4("Model Fit Statistics"),
          verbatimTextOutput(ns("cox_summary"))
        )
      ),

      # Parametric Models Comparison
      fluidRow(
        box(
          title = "Parametric Survival Models",
          status = "success",
          solidHeader = TRUE,
          collapsible = TRUE,
          width = 12,

          fluidRow(
            column(6,
              h4("Model Comparison"),
              DT::dataTableOutput(ns("model_comparison_table"))
            ),
            column(6,
              h4("Best Model Summary"),
              verbatimTextOutput(ns("best_model_summary"))
            )
          )
        )
      ),

      # Predictions for Pending Bills
      fluidRow(
        box(
          title = "Passage Probability Predictions",
          status = "primary",
          solidHeader = TRUE,
          collapsible = TRUE,
          width = 12,

          fluidRow(
            column(3,
              selectInput(
                ns("prediction_model"),
                "Model for Predictions",
                choices = c(
                  "Cox Model" = "cox",
                  "Weibull" = "weibull",
                  "Lognormal" = "lognormal",
                  "Gompertz" = "gompertz"
                ),
                selected = "cox"
              )
            ),

            column(3,
              selectInput(
                ns("time_horizon"),
                "Time Horizon (Days)",
                choices = c(30, 90, 180, 365, 730),
                selected = 365
              )
            ),

            column(3,
              numericInput(
                ns("top_n_predictions"),
                "Show Top N Bills",
                value = 20,
                min = 5,
                max = 100,
                step = 5
              )
            ),

            column(3,
              br(),
              downloadButton(
                ns("download_predictions"),
                "Download All Predictions",
                class = "btn-info",
                style = "width: 100%;"
              )
            )
          ),

          br(),

          DT::dataTableOutput(ns("predictions_table"))
        )
      )
    ),

    # Data Table: Bill Lifecycle Events
    fluidRow(
      box(
        title = "Bill Lifecycle Events",
        status = "info",
        solidHeader = TRUE,
        collapsible = TRUE,
        collapsed = TRUE,
        width = 12,

        fluidRow(
          column(4,
            selectInput(
              ns("filter_status"),
              "Filter by Status",
              choices = c("All", "Passed", "Failed", "Pending"),
              selected = "All"
            )
          ),

          column(4,
            selectInput(
              ns("filter_doc_type"),
              "Filter by Document Type",
              choices = NULL,  # Will be populated dynamically
              selected = NULL
            )
          ),

          column(4,
            downloadButton(
              ns("download_lifecycle"),
              "Download Lifecycle Data",
              class = "btn-info",
              style = "width: 100%; margin-top: 25px;"
            )
          )
        ),

        br(),

        DT::dataTableOutput(ns("lifecycle_table"))
      )
    ),

    # Help and Methodology
    fluidRow(
      box(
        title = "Methodology & References",
        status = "default",
        solidHeader = TRUE,
        collapsible = TRUE,
        collapsed = TRUE,
        width = 12,

        h4("Survival Analysis Methods"),

        h5("1. Kaplan-Meier Estimator"),
        p(
          "Non-parametric estimator of the survival function. Calculates the probability ",
          "that a bill remains unpassed beyond any given time point. Handles censored data ",
          "(bills still pending) appropriately."
        ),

        h5("2. Cox Proportional Hazards Model"),
        p(
          "Semi-parametric regression model that estimates the effect of covariates on the ",
          "hazard (instantaneous rate of passage). The hazard ratio (HR) quantifies the ",
          "multiplicative effect of a covariate:"
        ),
        tags$ul(
          tags$li("HR > 1: Increases hazard (faster passage)"),
          tags$li("HR < 1: Decreases hazard (slower passage)"),
          tags$li("HR = 1: No effect on passage rate")
        ),

        h5("3. Parametric Survival Models"),
        p(
          "Assumes a specific distribution for survival times. Common distributions:"
        ),
        tags$ul(
          tags$li(strong("Weibull:"), "Flexible shape parameter allows increasing, decreasing, or constant hazard"),
          tags$li(strong("Lognormal:"), "Assumes log of survival times is normally distributed"),
          tags$li(strong("Gompertz:"), "Exponentially increasing or decreasing hazard over time")
        ),

        h5("Key Concepts"),
        tags$ul(
          tags$li(strong("Event:"), "Bill passage (success event)"),
          tags$li(strong("Censoring:"), "Bills still pending or failed (right-censored observations)"),
          tags$li(strong("Time Origin:"), "Date of bill introduction"),
          tags$li(strong("Time Scale:"), "Days since introduction"),
          tags$li(strong("Covariates:"), "Document type, government level, branch, etc.")
        ),

        h5("References"),
        tags$ul(
          tags$li("Kleinbaum, D. G., & Klein, M. (2012). Survival Analysis: A Self-Learning Text (3rd ed.). Springer."),
          tags$li("Cox, D. R. (1972). Regression Models and Life-Tables. Journal of the Royal Statistical Society, 34(2), 187-220."),
          tags$li("Kaplan, E. L., & Meier, P. (1958). Nonparametric Estimation from Incomplete Observations. JASA, 53(282), 457-481."),
          tags$li("Therneau, T. M., & Grambsch, P. M. (2000). Modeling Survival Data: Extending the Cox Model. Springer.")
        )
      )
    )
  )
}
