# Voting Prediction UI Module
# Sprint 4 - PRD 4.2: Legislative Voting Behavior Prediction
# UI components for voting behavior prediction and ideology visualization

library(shiny)

# shinydashboard is optional - provide fallback for box()
if (requireNamespace("shinydashboard", quietly = TRUE)) {
  library(shinydashboard)
} else {
  box <- function(..., title = NULL, status = NULL, solidHeader = FALSE,
                  width = 12, collapsible = FALSE, collapsed = FALSE) {
    content <- list(...)
    title_elem <- if (!is.null(title)) shiny::h4(title) else NULL
    shiny::wellPanel(title_elem, content)
  }
}

#' UI for Voting Prediction Module
#'
#' @param id Module namespace ID
#' @return Shiny UI elements
voting_ui <- function(id) {
  ns <- NS(id)

  tagList(
    fluidRow(
      column(12,
        h2(icon("vote-yea"), "Voting Behavior Prediction"),
        p("Analyze legislator ideology and predict voting behavior using W-NOMINATE ideal points and machine learning models.")
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
                "Ideology Estimation (W-NOMINATE)" = "ideology",
                "Voting Prediction (ML Models)" = "predict",
                "Full Analysis" = "full"
              ),
              selected = "full"
            )
          ),

          column(3,
            numericInput(
              ns("min_votes"),
              "Minimum Votes per Legislator",
              value = 10,
              min = 5,
              max = 100,
              step = 5
            )
          ),

          column(3,
            numericInput(
              ns("nominate_dimensions"),
              "W-NOMINATE Dimensions",
              value = 2,
              min = 1,
              max = 2,
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
      column(3,
        valueBoxOutput(ns("total_legislators"), width = 12)
      ),
      column(3,
        valueBoxOutput(ns("total_votes"), width = 12)
      ),
      column(3,
        valueBoxOutput(ns("model_accuracy"), width = 12)
      ),
      column(3,
        valueBoxOutput(ns("model_auc"), width = 12)
      )
    ),

    # W-NOMINATE Ideal Point Space
    fluidRow(
      box(
        title = "W-NOMINATE Ideal Point Space",
        status = "info",
        solidHeader = TRUE,
        collapsible = TRUE,
        width = 12,

        plotOutput(ns("ideal_point_plot"), height = "500px"),

        br(),

        div(
          class = "well",
          h4("Interpretation:"),
          p(
            strong("First Dimension (X-axis):"), "Liberal-conservative ideological spectrum.",
            "Negative values = liberal; Positive values = conservative."
          ),
          p(
            strong("Second Dimension (Y-axis):"), "Secondary policy dimension.",
            "Often captures regional, cross-cutting, or issue-specific alignments."
          ),
          p(
            strong("Clustering:"), "Legislators close together in this space tend to vote similarly.",
            "Distance reflects ideological disagreement."
          )
        )
      )
    ),

    # Legislator Ideology Table
    fluidRow(
      box(
        title = "Legislator Ideal Points",
        status = "info",
        solidHeader = TRUE,
        collapsible = TRUE,
        collapsed = TRUE,
        width = 12,

        fluidRow(
          column(4,
            selectInput(
              ns("filter_party"),
              "Filter by Party",
              choices = NULL,  # Populated dynamically
              selected = NULL
            )
          ),

          column(4,
            selectInput(
              ns("filter_state"),
              "Filter by State",
              choices = NULL,  # Populated dynamically
              selected = NULL
            )
          ),

          column(4,
            downloadButton(
              ns("download_ideal_points"),
              "Download Ideal Points",
              class = "btn-info",
              style = "width: 100%; margin-top: 25px;"
            )
          )
        ),

        br(),

        DT::dataTableOutput(ns("ideal_points_table"))
      )
    ),

    # Conditional UI for Prediction Models
    conditionalPanel(
      condition = sprintf("input['%s'] == 'predict' || input['%s'] == 'full'",
                         ns("analysis_mode"), ns("analysis_mode")),

      # Model Performance Comparison
      fluidRow(
        box(
          title = "Model Performance Comparison",
          status = "warning",
          solidHeader = TRUE,
          collapsible = TRUE,
          width = 6,

          h4("Training & Test Metrics"),
          DT::dataTableOutput(ns("model_comparison_table")),

          br(),

          p(
            strong("Accuracy:"), "Proportion of correct predictions.",
            br(),
            strong("AUC:"), "Area Under ROC Curve. Measures discrimination ability (0.5 = random, 1.0 = perfect)."
          )
        ),

        box(
          title = "Feature Importance",
          status = "warning",
          solidHeader = TRUE,
          collapsible = TRUE,
          width = 6,

          plotOutput(ns("feature_importance_plot"), height = "300px"),

          br(),

          p(strong("XGBoost Feature Importance:"),
            "Shows which variables are most predictive of voting behavior.",
            "Higher gain = more important for predictions.")
        )
      ),

      # Voting Predictions
      fluidRow(
        box(
          title = "Voting Predictions for Bills",
          status = "primary",
          solidHeader = TRUE,
          collapsible = TRUE,
          width = 12,

          fluidRow(
            column(3,
              selectInput(
                ns("prediction_model"),
                "Model for Predictions",
                choices = c("XGBoost" = "xgboost", "Logistic Regression" = "logistic"),
                selected = "xgboost"
              )
            ),

            column(3,
              numericInput(
                ns("select_bill_id"),
                "Select Bill ID",
                value = NULL,
                min = 1,
                step = 1
              )
            ),

            column(3,
              numericInput(
                ns("top_n_predictions"),
                "Show Top N Legislators",
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

          h4("Predicted Votes by Legislator"),
          DT::dataTableOutput(ns("predictions_table")),

          br(),

          fluidRow(
            column(6,
              h4("Predicted Vote Distribution"),
              plotOutput(ns("vote_distribution_plot"), height = "250px")
            ),
            column(6,
              h4("Prediction Confidence"),
              plotOutput(ns("confidence_plot"), height = "250px")
            )
          )
        )
      ),

      # Bill Passage Likelihood
      fluidRow(
        box(
          title = "Bill Passage Likelihood Analysis",
          status = "success",
          solidHeader = TRUE,
          collapsible = TRUE,
          width = 12,

          p("Aggregate voting predictions across all legislators to estimate overall bill passage probability."),

          DT::dataTableOutput(ns("bill_passage_table")),

          br(),

          plotOutput(ns("passage_probability_plot"), height = "400px")
        )
      )
    ),

    # Help and Methodology
    fluidRow(
      box(
        title = "Methodology & References",
        status = "primary",
        solidHeader = TRUE,
        collapsible = TRUE,
        collapsed = TRUE,
        width = 12,

        h4("Voting Prediction Methods"),

        h5("1. W-NOMINATE Ideal Point Estimation"),
        p(
          "W-NOMINATE (Weighted Nominal Three-Step Estimation) is a scaling method that places ",
          "legislators in a low-dimensional ideological space based on their roll call voting patterns. ",
          "Legislators who vote similarly are positioned close together in this space."
        ),
        tags$ul(
          tags$li(strong("First Dimension:"), "Primary ideological dimension (typically liberal-conservative)"),
          tags$li(strong("Second Dimension:"), "Secondary dimension capturing cross-cutting issues"),
          tags$li(strong("Coordinates:"), "Range from -1 (most liberal) to +1 (most conservative)")
        ),

        h5("2. Machine Learning Voting Prediction"),
        p("Two complementary approaches for predicting individual legislator votes:"),

        tags$ul(
          tags$li(
            strong("XGBoost (Gradient Boosting):"),
            "Ensemble learning method that builds multiple decision trees sequentially. ",
            "Each tree corrects errors from previous trees. Handles non-linear relationships ",
            "and feature interactions effectively."
          ),
          tags$li(
            strong("Logistic Regression:"),
            "Baseline model that estimates probability of 'yes' vote using linear combination ",
            "of features. Interpretable coefficients show direction and magnitude of effects."
          )
        ),

        h5("Features Used for Prediction"),
        tags$ul(
          tags$li("Legislator ideal points (1st and 2nd dimensions)"),
          tags$li("Party affiliation"),
          tags$li("State/region"),
          tags$li("Bill characteristics (type, level, branch)")
        ),

        h5("Evaluation Metrics"),
        tags$ul(
          tags$li(strong("Accuracy:"), "Percentage of correct predictions"),
          tags$li(strong("AUC (Area Under ROC Curve):"), "Model's ability to discriminate between yes/no votes (0.5 = random, 1.0 = perfect)"),
          tags$li(strong("Feature Importance:"), "Contribution of each variable to prediction accuracy")
        ),

        h5("References"),
        tags$ul(
          tags$li("Poole, K. T., & Rosenthal, H. (1997). Congress: A Political-Economic History of Roll Call Voting. Oxford University Press."),
          tags$li("Clinton, J., Jackman, S., & Rivers, D. (2004). The Statistical Analysis of Roll Call Data. American Political Science Review, 98(2), 355-370."),
          tags$li("Chen, T., & Guestrin, C. (2016). XGBoost: A Scalable Tree Boosting System. KDD '16."),
          tags$li("Carroll, R., Lewis, J. B., Lo, J., Poole, K. T., & Rosenthal, H. (2009). Comparing NOMINATE and IDEAL. Political Analysis, 17(3), 286-295.")
        )
      )
    )
  )
}
