# Survival Analysis Server Module
# Sprint 4 - PRD 4.1: Survival Analysis for Bill Progression
# Server-side logic for survival analysis calculations and visualizations

#' Server logic for Survival Analysis Module
#'
#' @param id Module namespace ID
#' @param pool Database connection pool
survival_server <- function(id, pool) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns

    # Reactive values to store analysis results
    analysis_results <- reactiveValues(
      survival_data = NULL,
      km_fit = NULL,
      cox_fit = NULL,
      parametric_fits = NULL,
      predictions = NULL,
      hazard_ratios = NULL,
      model_comparison = NULL
    )

    # Populate document type filter choices
    observe({
      req(pool)

      doc_types <- pool %>%
        tbl("documentos") %>%
        distinct(tipo_documento) %>%
        collect() %>%
        pull(tipo_documento) %>%
        sort()

      updateSelectInput(session, "filter_doc_type",
                       choices = c("All", doc_types),
                       selected = "All")
    })

    # Run survival analysis
    observeEvent(input$run_analysis, {
      req(pool)

      # Show loading notification
      notification_id <- showNotification(
        "Running survival analysis...",
        duration = NULL,
        type = "message"
      )

      tryCatch({
        # Source survival analysis functions
        source("R/analytics/survival_analysis.R", local = TRUE)

        # Connect to database
        con <- poolCheckout(pool)
        on.exit(poolReturn(con))

        # Prepare survival data
        withProgress(message = "Preparing survival data", value = 0.2, {
          analysis_results$survival_data <- prepare_survival_data(
            con,
            min_events = input$min_events
          )
        })

        # Fit Kaplan-Meier model
        if (input$analysis_mode %in% c("explore", "full")) {
          withProgress(message = "Fitting Kaplan-Meier model", value = 0.4, {
            stratify <- if (input$stratify_by == "none") NULL else input$stratify_by
            analysis_results$km_fit <- fit_kaplan_meier(
              analysis_results$survival_data,
              stratify_by = stratify
            )
          })
        }

        # Fit predictive models
        if (input$analysis_mode %in% c("predict", "full")) {
          withProgress(message = "Fitting Cox model", value = 0.5, {
            analysis_results$cox_fit <- fit_cox_model(
              analysis_results$survival_data,
              covariates = c("doc_type", "level", "branch")
            )
          })

          withProgress(message = "Calculating hazard ratios", value = 0.6, {
            analysis_results$hazard_ratios <- calculate_hazard_ratios(
              analysis_results$cox_fit
            )
          })

          withProgress(message = "Fitting parametric models", value = 0.7, {
            analysis_results$parametric_fits <- fit_parametric_survival(
              analysis_results$survival_data,
              distributions = c("weibull", "lognormal", "gompertz"),
              covariates = c("doc_type", "level", "branch")
            )
          })

          withProgress(message = "Comparing models", value = 0.8, {
            analysis_results$model_comparison <- compare_survival_models(
              analysis_results$km_fit,
              analysis_results$cox_fit,
              analysis_results$parametric_fits
            )
          })

          # Generate predictions for pending bills
          withProgress(message = "Generating predictions", value = 0.9, {
            pending_bills <- analysis_results$survival_data %>%
              filter(status == "pending")

            if (nrow(pending_bills) > 0) {
              analysis_results$predictions <- predict_passage_probability(
                analysis_results$cox_fit,
                newdata = pending_bills,
                time_points = c(30, 90, 180, 365, 730)
              )
            }
          })
        }

        removeNotification(notification_id)
        showNotification("Analysis complete!", type = "message", duration = 3)

      }, error = function(e) {
        removeNotification(notification_id)
        showNotification(
          paste("Error:", e$message),
          type = "error",
          duration = 10
        )
      })
    })

    # Value boxes
    output$total_bills <- renderValueBox({
      req(analysis_results$survival_data)

      valueBox(
        nrow(analysis_results$survival_data),
        "Total Bills",
        icon = icon("file-alt"),
        color = "blue"
      )
    })

    output$passed_bills <- renderValueBox({
      req(analysis_results$survival_data)

      passed_count <- sum(analysis_results$survival_data$event == 1)
      passed_pct <- round(100 * passed_count / nrow(analysis_results$survival_data), 1)

      valueBox(
        paste0(passed_count, " (", passed_pct, "%)"),
        "Passed Bills",
        icon = icon("check-circle"),
        color = "green"
      )
    })

    output$median_time <- renderValueBox({
      req(analysis_results$km_fit)

      median_time <- summary(analysis_results$km_fit)$table["median"]

      if (is.na(median_time)) {
        valueBox(
          "N/A",
          "Median Time to Passage",
          icon = icon("clock"),
          color = "yellow"
        )
      } else {
        valueBox(
          paste(round(median_time), "days"),
          "Median Time to Passage",
          icon = icon("clock"),
          color = "yellow"
        )
      }
    })

    # Kaplan-Meier plot
    output$km_plot <- renderPlot({
      req(analysis_results$km_fit)

      km_plot <- plot_kaplan_meier(
        analysis_results$km_fit,
        title = "Kaplan-Meier Survival Curve: Bill Passage"
      )

      print(km_plot)
    })

    # Cox hazard ratios plot
    output$cox_hazard_plot <- renderPlot({
      req(analysis_results$cox_fit)

      plot_cox_hazard_ratios(analysis_results$cox_fit)
    })

    # Hazard ratios table
    output$hazard_ratios_table <- DT::renderDataTable({
      req(analysis_results$hazard_ratios)

      analysis_results$hazard_ratios %>%
        mutate(
          hazard_ratio = round(hazard_ratio, 3),
          ci_lower = round(ci_lower, 3),
          ci_upper = round(ci_upper, 3),
          p_value = format.pval(p_value, digits = 3)
        ) %>%
        DT::datatable(
          options = list(pageLength = 10, dom = 't'),
          rownames = FALSE,
          colnames = c("Covariate", "Hazard Ratio", "CI Lower", "CI Upper", "P-value", "Interpretation")
        ) %>%
        DT::formatStyle(
          'interpretation',
          backgroundColor = DT::styleEqual(
            c("Increases hazard (faster passage)", "Decreases hazard (slower passage)", "No significant effect"),
            c("#d4edda", "#fff3cd", "#f8f9fa")
          )
        )
    })

    # Proportional hazards test
    output$ph_test <- renderPrint({
      req(analysis_results$cox_fit)

      cox.zph(analysis_results$cox_fit)
    })

    # Cox model summary
    output$cox_summary <- renderPrint({
      req(analysis_results$cox_fit)

      summary(analysis_results$cox_fit)
    })

    # Model comparison table
    output$model_comparison_table <- DT::renderDataTable({
      req(analysis_results$model_comparison)

      analysis_results$model_comparison %>%
        mutate(
          AIC = round(AIC, 2),
          Concordance = round(Concordance, 3)
        ) %>%
        DT::datatable(
          options = list(pageLength = 10, dom = 't', ordering = TRUE),
          rownames = FALSE
        ) %>%
        DT::formatStyle(
          'AIC',
          background = DT::styleColorBar(range(analysis_results$model_comparison$AIC, na.rm = TRUE), 'lightblue'),
          backgroundSize = '98% 88%',
          backgroundRepeat = 'no-repeat',
          backgroundPosition = 'center'
        )
    })

    # Best model summary
    output$best_model_summary <- renderPrint({
      req(analysis_results$parametric_fits)
      req(analysis_results$parametric_fits$best)

      analysis_results$parametric_fits$best
    })

    # Predictions table
    output$predictions_table <- DT::renderDataTable({
      req(analysis_results$predictions)

      # Select model for predictions
      model_choice <- input$prediction_model
      time_horizon <- as.numeric(input$time_horizon)
      top_n <- input$top_n_predictions

      # Get appropriate column name
      time_col <- paste0("day_", time_horizon)

      # Prepare predictions table
      pred_table <- analysis_results$predictions %>%
        select(bill_id, titulo, doc_type, level, branch, all_of(time_col)) %>%
        rename(passage_prob = !!time_col) %>%
        arrange(desc(passage_prob)) %>%
        head(top_n) %>%
        mutate(
          passage_prob = round(passage_prob * 100, 1),
          passage_prob_display = paste0(passage_prob, "%")
        )

      pred_table %>%
        select(bill_id, titulo, doc_type, level, branch, passage_prob_display) %>%
        DT::datatable(
          options = list(pageLength = 20, scrollX = TRUE),
          rownames = FALSE,
          colnames = c("Bill ID", "Title", "Type", "Level", "Branch", "Passage Probability")
        ) %>%
        DT::formatStyle(
          'passage_prob_display',
          background = DT::styleColorBar(c(0, 100), 'lightgreen'),
          backgroundSize = '98% 88%',
          backgroundRepeat = 'no-repeat',
          backgroundPosition = 'center'
        )
    })

    # Lifecycle table
    output$lifecycle_table <- DT::renderDataTable({
      req(analysis_results$survival_data)

      # Apply filters
      filtered_data <- analysis_results$survival_data

      if (input$filter_status != "All") {
        filtered_data <- filtered_data %>%
          filter(status == tolower(input$filter_status))
      }

      if (input$filter_doc_type != "All") {
        filtered_data <- filtered_data %>%
          filter(doc_type == input$filter_doc_type)
      }

      # Prepare table
      filtered_data %>%
        select(bill_id, titulo, doc_type, level, branch, intro_date, status, time, event) %>%
        mutate(
          time = round(time),
          event_label = ifelse(event == 1, "Passed", "Censored")
        ) %>%
        select(-event) %>%
        DT::datatable(
          options = list(pageLength = 25, scrollX = TRUE),
          rownames = FALSE,
          colnames = c("Bill ID", "Title", "Type", "Level", "Branch", "Intro Date", "Status", "Days", "Outcome"),
          filter = 'top'
        )
    })

    # Download predictions
    output$download_predictions <- downloadHandler(
      filename = function() {
        paste0("survival_predictions_", Sys.Date(), ".csv")
      },
      content = function(file) {
        req(analysis_results$predictions)

        analysis_results$predictions %>%
          select(bill_id, titulo, doc_type, level, branch,
                 day_30, day_90, day_180, day_365, day_730) %>%
          write.csv(file, row.names = FALSE)
      }
    )

    # Download lifecycle data
    output$download_lifecycle <- downloadHandler(
      filename = function() {
        paste0("bill_lifecycle_", Sys.Date(), ".csv")
      },
      content = function(file) {
        req(analysis_results$survival_data)

        analysis_results$survival_data %>%
          select(bill_id, titulo, doc_type, level, branch,
                 intro_date, passage_date, failure_date,
                 status, time, event, num_events) %>%
          write.csv(file, row.names = FALSE)
      }
    )
  })
}
