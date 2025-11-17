# Voting Prediction Server Module
# Sprint 4 - PRD 4.2: Legislative Voting Behavior Prediction
# Server-side logic for voting prediction and ideology analysis

#' Server logic for Voting Prediction Module
#'
#' @param id Module namespace ID
#' @param pool Database connection pool
voting_server <- function(id, pool) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns

    # Reactive values to store analysis results
    analysis_results <- reactiveValues(
      voting_data = NULL,
      wnominate = NULL,
      ideal_points = NULL,
      xgboost_model = NULL,
      logistic_model = NULL,
      predictions = NULL,
      bill_passage = NULL
    )

    # Populate filter choices
    observe({
      req(pool)

      parties <- pool %>%
        tbl("legislators") %>%
        distinct(party) %>%
        collect() %>%
        pull(party) %>%
        sort() %>%
        na.omit()

      states <- pool %>%
        tbl("legislators") %>%
        distinct(state) %>%
        collect() %>%
        pull(state) %>%
        sort() %>%
        na.omit()

      updateSelectInput(session, "filter_party",
                       choices = c("All", parties),
                       selected = "All")

      updateSelectInput(session, "filter_state",
                       choices = c("All", states),
                       selected = "All")
    })

    # Run voting analysis
    observeEvent(input$run_analysis, {
      req(pool)

      # Show loading notification
      notification_id <- showNotification(
        "Running voting analysis...",
        duration = NULL,
        type = "message"
      )

      tryCatch({
        # Source voting prediction functions
        source("R/analytics/voting_prediction.R", local = TRUE)

        # Connect to database
        con <- poolCheckout(pool)
        on.exit(poolReturn(con))

        # Prepare voting data
        withProgress(message = "Preparing voting data", value = 0.2, {
          analysis_results$voting_data <- prepare_voting_data(con)
        })

        # Estimate W-NOMINATE ideal points
        if (input$analysis_mode %in% c("ideology", "full")) {
          withProgress(message = "Estimating W-NOMINATE ideal points", value = 0.4, {
            analysis_results$wnominate <- estimate_wnominate(
              analysis_results$voting_data$vote_matrix,
              dimensions = input$nominate_dimensions,
              min_votes = input$min_votes
            )
          })

          if (!is.null(analysis_results$wnominate)) {
            withProgress(message = "Updating ideal points in database", value = 0.5, {
              analysis_results$ideal_points <- update_ideal_points(
                con,
                analysis_results$wnominate,
                analysis_results$voting_data$legislators
              )
            })
          }
        } else {
          # Load existing ideal points
          analysis_results$ideal_points <- dbGetQuery(con, "
            SELECT id as legislator_id, dw_nominate_1, dw_nominate_2
            FROM legislators
            WHERE dw_nominate_1 IS NOT NULL
          ")
        }

        # Train ML models
        if (input$analysis_mode %in% c("predict", "full")) {
          withProgress(message = "Preparing ML features", value = 0.6, {
            features <- prepare_ml_features(
              analysis_results$voting_data,
              analysis_results$ideal_points
            )
          })

          withProgress(message = "Training XGBoost model", value = 0.7, {
            analysis_results$xgboost_model <- train_xgboost_model(features, train_ratio = 0.8)
          })

          withProgress(message = "Training Logistic Regression model", value = 0.8, {
            analysis_results$logistic_model <- train_logistic_model(features, train_ratio = 0.8)
          })

          withProgress(message = "Generating predictions", value = 0.9, {
            # Use best model for predictions
            best_model <- if (analysis_results$xgboost_model$test_auc > analysis_results$logistic_model$test_auc) {
              list(model = analysis_results$xgboost_model, type = "xgboost")
            } else {
              list(model = analysis_results$logistic_model, type = "logistic")
            }

            analysis_results$predictions <- predict_votes(
              best_model$model,
              features,
              best_model$type
            )

            # Calculate bill passage probabilities
            analysis_results$bill_passage <- analysis_results$predictions %>%
              group_by(bill_id) %>%
              summarize(
                total_legislators = n(),
                predicted_yes = sum(predicted_vote == "yes"),
                predicted_no = sum(predicted_vote == "no"),
                yes_percentage = 100 * predicted_yes / total_legislators,
                passage_probability = yes_percentage / 100,
                .groups = "drop"
              )
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
    output$total_legislators <- renderValueBox({
      req(analysis_results$voting_data)

      valueBox(
        nrow(analysis_results$voting_data$legislators),
        "Legislators",
        icon = icon("users"),
        color = "blue"
      )
    })

    output$total_votes <- renderValueBox({
      req(analysis_results$voting_data)

      valueBox(
        nrow(analysis_results$voting_data$votes),
        "Total Votes",
        icon = icon("vote-yea"),
        color = "green"
      )
    })

    output$model_accuracy <- renderValueBox({
      if (!is.null(analysis_results$xgboost_model)) {
        acc <- round(analysis_results$xgboost_model$test_accuracy * 100, 1)

        valueBox(
          paste0(acc, "%"),
          "XGBoost Accuracy",
          icon = icon("chart-line"),
          color = "yellow"
        )
      } else {
        valueBox(
          "N/A",
          "Model Accuracy",
          icon = icon("chart-line"),
          color = "yellow"
        )
      }
    })

    output$model_auc <- renderValueBox({
      if (!is.null(analysis_results$xgboost_model)) {
        auc <- round(analysis_results$xgboost_model$test_auc, 3)

        valueBox(
          auc,
          "XGBoost AUC",
          icon = icon("signal"),
          color = "purple"
        )
      } else {
        valueBox(
          "N/A",
          "Model AUC",
          icon = icon("signal"),
          color = "purple"
        )
      }
    })

    # Ideal point plot
    output$ideal_point_plot <- renderPlot({
      req(analysis_results$wnominate)
      req(analysis_results$voting_data$legislators)

      plot_ideal_points(
        analysis_results$wnominate,
        analysis_results$voting_data$legislators
      )
    })

    # Ideal points table
    output$ideal_points_table <- DT::renderDataTable({
      req(analysis_results$ideal_points)

      # Apply filters
      filtered_data <- analysis_results$ideal_points

      legislators_info <- analysis_results$voting_data$legislators

      # Merge with legislator info
      table_data <- filtered_data %>%
        left_join(legislators_info, by = "legislator_id")

      if (input$filter_party != "All") {
        table_data <- table_data %>% filter(party == input$filter_party)
      }

      if (input$filter_state != "All") {
        table_data <- table_data %>% filter(state == input$filter_state)
      }

      table_data %>%
        mutate(
          dw_nominate_1 = round(dw_nominate_1, 3),
          dw_nominate_2 = round(dw_nominate_2, 3)
        ) %>%
        select(legislator_id, party, state, dw_nominate_1, dw_nominate_2) %>%
        DT::datatable(
          options = list(pageLength = 20, scrollX = TRUE),
          rownames = FALSE,
          colnames = c("Legislator ID", "Party", "State", "1st Dimension", "2nd Dimension")
        )
    })

    # Model comparison table
    output$model_comparison_table <- DT::renderDataTable({
      req(analysis_results$xgboost_model)
      req(analysis_results$logistic_model)

      comparison <- data.frame(
        Model = c("XGBoost", "Logistic Regression"),
        Train_Accuracy = c(
          round(analysis_results$xgboost_model$train_accuracy, 3),
          round(analysis_results$logistic_model$train_accuracy, 3)
        ),
        Test_Accuracy = c(
          round(analysis_results$xgboost_model$test_accuracy, 3),
          round(analysis_results$logistic_model$test_accuracy, 3)
        ),
        Train_AUC = c(
          round(analysis_results$xgboost_model$train_auc, 3),
          round(analysis_results$logistic_model$train_auc, 3)
        ),
        Test_AUC = c(
          round(analysis_results$xgboost_model$test_auc, 3),
          round(analysis_results$logistic_model$test_auc, 3)
        )
      )

      comparison %>%
        DT::datatable(
          options = list(pageLength = 5, dom = 't'),
          rownames = FALSE,
          colnames = c("Model", "Train Accuracy", "Test Accuracy", "Train AUC", "Test AUC")
        ) %>%
        DT::formatStyle(
          'Test_AUC',
          background = DT::styleColorBar(range(comparison$Test_AUC), 'lightgreen'),
          backgroundSize = '98% 88%',
          backgroundRepeat = 'no-repeat',
          backgroundPosition = 'center'
        )
    })

    # Feature importance plot
    output$feature_importance_plot <- renderPlot({
      req(analysis_results$xgboost_model)
      req(analysis_results$xgboost_model$importance)

      importance_data <- analysis_results$xgboost_model$importance %>%
        head(10)

      ggplot(importance_data, aes(x = reorder(Feature, Gain), y = Gain)) +
        geom_col(fill = "steelblue") +
        coord_flip() +
        labs(
          title = "XGBoost Feature Importance (Top 10)",
          x = "Feature",
          y = "Gain"
        ) +
        theme_minimal() +
        theme(plot.title = element_text(face = "bold"))
    })

    # Predictions table
    output$predictions_table <- DT::renderDataTable({
      req(analysis_results$predictions)

      # Filter by bill if specified
      pred_table <- analysis_results$predictions

      if (!is.null(input$select_bill_id) && input$select_bill_id > 0) {
        pred_table <- pred_table %>% filter(bill_id == input$select_bill_id)
      }

      pred_table <- pred_table %>%
        arrange(desc(predicted_probability)) %>%
        head(input$top_n_predictions) %>%
        mutate(
          predicted_probability = round(predicted_probability * 100, 1)
        ) %>%
        select(legislator_id, party, state, predicted_vote, predicted_probability)

      pred_table %>%
        DT::datatable(
          options = list(pageLength = 20, scrollX = TRUE),
          rownames = FALSE,
          colnames = c("Legislator ID", "Party", "State", "Predicted Vote", "Confidence (%)")
        ) %>%
        DT::formatStyle(
          'predicted_vote',
          backgroundColor = DT::styleEqual(
            c("yes", "no"),
            c("#d4edda", "#f8d7da")
          )
        )
    })

    # Vote distribution plot
    output$vote_distribution_plot <- renderPlot({
      req(analysis_results$predictions)

      vote_counts <- analysis_results$predictions %>%
        count(predicted_vote)

      ggplot(vote_counts, aes(x = predicted_vote, y = n, fill = predicted_vote)) +
        geom_col() +
        scale_fill_manual(values = c("yes" = "#28a745", "no" = "#dc3545")) +
        labs(
          title = "Predicted Vote Distribution",
          x = "Predicted Vote",
          y = "Count"
        ) +
        theme_minimal() +
        theme(
          legend.position = "none",
          plot.title = element_text(face = "bold")
        )
    })

    # Confidence plot
    output$confidence_plot <- renderPlot({
      req(analysis_results$predictions)

      ggplot(analysis_results$predictions, aes(x = predicted_probability)) +
        geom_histogram(bins = 30, fill = "steelblue", alpha = 0.7) +
        labs(
          title = "Prediction Confidence Distribution",
          x = "Probability",
          y = "Count"
        ) +
        theme_minimal() +
        theme(plot.title = element_text(face = "bold"))
    })

    # Bill passage table
    output$bill_passage_table <- DT::renderDataTable({
      req(analysis_results$bill_passage)

      analysis_results$bill_passage %>%
        arrange(desc(passage_probability)) %>%
        mutate(
          yes_percentage = round(yes_percentage, 1),
          passage_probability = round(passage_probability, 3)
        ) %>%
        DT::datatable(
          options = list(pageLength = 20, scrollX = TRUE),
          rownames = FALSE,
          colnames = c("Bill ID", "Total Legislators", "Predicted Yes", "Predicted No",
                      "Yes %", "Passage Probability")
        ) %>%
        DT::formatStyle(
          'passage_probability',
          background = DT::styleColorBar(c(0, 1), 'lightgreen'),
          backgroundSize = '98% 88%',
          backgroundRepeat = 'no-repeat',
          backgroundPosition = 'center'
        )
    })

    # Passage probability plot
    output$passage_probability_plot <- renderPlot({
      req(analysis_results$bill_passage)

      plot_data <- analysis_results$bill_passage %>%
        arrange(desc(passage_probability)) %>%
        head(20) %>%
        mutate(bill_id = factor(bill_id, levels = bill_id))

      ggplot(plot_data, aes(x = bill_id, y = passage_probability, fill = passage_probability)) +
        geom_col() +
        scale_fill_gradient(low = "#f8d7da", high = "#d4edda") +
        coord_flip() +
        labs(
          title = "Top 20 Bills by Passage Probability",
          x = "Bill ID",
          y = "Passage Probability",
          fill = "Probability"
        ) +
        theme_minimal() +
        theme(plot.title = element_text(face = "bold"))
    })

    # Download ideal points
    output$download_ideal_points <- downloadHandler(
      filename = function() {
        paste0("ideal_points_", Sys.Date(), ".csv")
      },
      content = function(file) {
        req(analysis_results$ideal_points)

        legislators_info <- analysis_results$voting_data$legislators

        analysis_results$ideal_points %>%
          left_join(legislators_info, by = "legislator_id") %>%
          write.csv(file, row.names = FALSE)
      }
    )

    # Download predictions
    output$download_predictions <- downloadHandler(
      filename = function() {
        paste0("voting_predictions_", Sys.Date(), ".csv")
      },
      content = function(file) {
        req(analysis_results$predictions)

        analysis_results$predictions %>%
          write.csv(file, row.names = FALSE)
      }
    )
  })
}
