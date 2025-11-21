# Voting Behavior Prediction
# Sprint 4 - PRD 4.2: Legislative Voting Behavior Prediction
# Purpose: Predict individual legislator votes using W-NOMINATE and machine learning

library(DBI)
library(RPostgres)
library(pscl)
library(wnominate)
library(xgboost)
library(caret)
library(dplyr)
library(tidyr)
library(ggplot2)

#' Prepare voting data from database
#'
#' @param con Database connection
#' @return List with roll call matrix and legislator/bill metadata
prepare_voting_data <- function(con) {
  cat("Preparing voting data from database...\n")

  # Get all roll call votes
  votes <- dbGetQuery(con, "
    SELECT
      rcv.bill_id,
      rcv.legislator_id,
      rcv.vote,
      rcv.vote_date,
      l.party,
      l.state,
      d.tipo_documento,
      d.nivel,
      d.poder
    FROM roll_call_votes rcv
    JOIN legislators l ON rcv.legislator_id = l.id
    JOIN documentos d ON rcv.bill_id = d.id
    WHERE rcv.vote IN ('yes', 'no')
  ")

  if (nrow(votes) == 0) {
    stop("No voting data found. Please populate roll_call_votes table.")
  }

  cat(sprintf("Loaded %d votes\n", nrow(votes)))

  # Create roll call matrix (legislators × bills)
  vote_matrix <- votes %>%
    mutate(
      vote_numeric = case_when(
        vote == "yes" ~ 1,
        vote == "no" ~ 0,
        TRUE ~ NA_real_
      )
    ) %>%
    select(legislator_id, bill_id, vote_numeric) %>%
    pivot_wider(
      names_from = bill_id,
      values_from = vote_numeric,
      names_prefix = "bill_"
    )

  # Extract legislator IDs and convert to matrix
  legislator_ids <- vote_matrix$legislator_id
  vote_matrix <- as.matrix(vote_matrix[, -1])
  rownames(vote_matrix) <- legislator_ids

  # Get legislator metadata
  legislators <- votes %>%
    distinct(legislator_id, party, state) %>%
    arrange(legislator_id)

  # Get bill metadata
  bills <- votes %>%
    distinct(bill_id, tipo_documento, nivel, poder) %>%
    arrange(bill_id)

  cat(sprintf("Vote matrix: %d legislators × %d bills\n",
              nrow(vote_matrix), ncol(vote_matrix)))

  list(
    vote_matrix = vote_matrix,
    votes = votes,
    legislators = legislators,
    bills = bills
  )
}

#' Estimate W-NOMINATE ideal points
#'
#' @param vote_matrix Roll call matrix (legislators × bills)
#' @param dimensions Number of dimensions (typically 1 or 2)
#' @param min_votes Minimum votes required per legislator
#' @return wnominate object with ideal points
estimate_wnominate <- function(vote_matrix, dimensions = 2, min_votes = 10) {
  cat("\n=== Estimating W-NOMINATE Ideal Points ===\n")
  cat(sprintf("Dimensions: %d\n", dimensions))

  # Filter legislators with sufficient votes
  vote_counts <- rowSums(!is.na(vote_matrix))
  valid_legislators <- vote_counts >= min_votes

  cat(sprintf("Legislators with >= %d votes: %d/%d\n",
              min_votes,
              sum(valid_legislators),
              length(valid_legislators)))

  if (sum(valid_legislators) < 3) {
    stop("Insufficient legislators for W-NOMINATE estimation")
  }

  vote_matrix_filtered <- vote_matrix[valid_legislators, ]

  # Create rollcall object for wnominate
  rc <- rollcall(
    data = vote_matrix_filtered,
    yea = 1,
    nay = 0,
    missing = NA,
    notInLegis = NA,
    legis.names = rownames(vote_matrix_filtered),
    vote.names = colnames(vote_matrix_filtered),
    desc = "Legislative Roll Calls"
  )

  # Estimate W-NOMINATE
  cat("Running W-NOMINATE algorithm...\n")

  wnom <- tryCatch({
    wnominate(
      rc,
      dims = dimensions,
      polarity = c(1, 1),
      minvotes = min_votes,
      lop = 0.025,
      trials = 3,
      verbose = FALSE
    )
  }, error = function(e) {
    cat(sprintf("W-NOMINATE estimation failed: %s\n", e$message))
    return(NULL)
  })

  if (!is.null(wnom)) {
    cat(sprintf("W-NOMINATE estimation complete!\n"))
    cat(sprintf("  Fit: %.3f\n", wnom$fits[1]))
    cat(sprintf("  Correct classification: %.1f%%\n", wnom$fits[2] * 100))
  }

  wnom
}

#' Update legislator ideal points in database
#'
#' @param con Database connection
#' @param wnom wnominate object
#' @param legislators Legislator metadata
update_ideal_points <- function(con, wnom, legislators) {
  cat("\n=== Updating Ideal Points in Database ===\n")

  if (is.null(wnom)) {
    cat("No W-NOMINATE results to update\n")
    return(invisible(NULL))
  }

  # Extract ideal points
  ideal_points <- data.frame(
    legislator_id = rownames(wnom$legislators),
    dw_nominate_1 = wnom$legislators[, "coord1D"],
    dw_nominate_2 = if (ncol(wnom$legislators) > 1) wnom$legislators[, "coord2D"] else NA_real_,
    ideology_updated_at = Sys.time()
  )

  # Update database
  for (i in 1:nrow(ideal_points)) {
    dbExecute(con, "
      UPDATE legislators
      SET dw_nominate_1 = $1,
          dw_nominate_2 = $2,
          ideology_updated_at = $3
      WHERE id = $4
    ", params = list(
      ideal_points$dw_nominate_1[i],
      ideal_points$dw_nominate_2[i],
      ideal_points$ideology_updated_at[i],
      ideal_points$legislator_id[i]
    ))
  }

  cat(sprintf("Updated %d legislator ideal points\n", nrow(ideal_points)))
  invisible(ideal_points)
}

#' Plot W-NOMINATE ideal point space
#'
#' @param wnom wnominate object
#' @param legislators Legislator metadata with party information
#' @return ggplot object
plot_ideal_points <- function(wnom, legislators) {
  if (is.null(wnom)) {
    return(NULL)
  }

  # Extract coordinates
  coords <- as.data.frame(wnom$legislators)
  coords$legislator_id <- rownames(coords)

  # Merge with party information
  coords <- coords %>%
    left_join(legislators, by = "legislator_id")

  # Create plot
  ggplot(coords, aes(x = coord1D, y = coord2D, color = party)) +
    geom_point(size = 3, alpha = 0.7) +
    labs(
      title = "W-NOMINATE Ideal Point Estimates",
      subtitle = "Legislative Ideology Space",
      x = "First Dimension (Liberal-Conservative)",
      y = "Second Dimension",
      color = "Party"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(face = "bold", size = 14),
      legend.position = "bottom"
    )
}

#' Prepare features for ML voting prediction
#'
#' @param voting_data Voting data from prepare_voting_data()
#' @param ideal_points Ideal points from W-NOMINATE
#' @return Feature matrix for machine learning
prepare_ml_features <- function(voting_data, ideal_points = NULL) {
  cat("\n=== Preparing ML Features ===\n")

  votes <- voting_data$votes

  # Base features
  features <- votes %>%
    mutate(
      # Party features
      party_numeric = as.numeric(as.factor(party)),

      # State features
      state_numeric = as.numeric(as.factor(state)),

      # Bill features
      doc_type_numeric = as.numeric(as.factor(tipo_documento)),
      nivel_numeric = as.numeric(as.factor(nivel)),
      poder_numeric = as.numeric(as.factor(poder)),

      # Vote outcome (target)
      vote_binary = ifelse(vote == "yes", 1, 0)
    )

  # Add ideal points if available
  if (!is.null(ideal_points)) {
    features <- features %>%
      left_join(ideal_points, by = "legislator_id")
  }

  cat(sprintf("Prepared %d observations with %d features\n",
              nrow(features),
              ncol(features) - 1))  # -1 for target variable

  features
}

#' Train XGBoost voting prediction model
#'
#' @param features Feature matrix from prepare_ml_features()
#' @param train_ratio Proportion of data for training
#' @return List with trained model and evaluation metrics
train_xgboost_model <- function(features, train_ratio = 0.8) {
  cat("\n=== Training XGBoost Model ===\n")

  # Remove rows with missing values
  features <- features %>%
    select(vote_binary, party_numeric, state_numeric,
           doc_type_numeric, nivel_numeric, poder_numeric,
           dw_nominate_1, dw_nominate_2) %>%
    na.omit()

  # Split train/test
  set.seed(42)
  train_idx <- sample(1:nrow(features), size = floor(train_ratio * nrow(features)))

  train_data <- features[train_idx, ]
  test_data <- features[-train_idx, ]

  cat(sprintf("Train: %d | Test: %d\n", nrow(train_data), nrow(test_data)))

  # Prepare matrices
  train_x <- as.matrix(train_data[, -1])
  train_y <- train_data$vote_binary

  test_x <- as.matrix(test_data[, -1])
  test_y <- test_data$vote_binary

  # Train XGBoost
  xgb_model <- xgboost(
    data = train_x,
    label = train_y,
    max_depth = 6,
    eta = 0.3,
    nrounds = 100,
    objective = "binary:logistic",
    eval_metric = "auc",
    verbose = 0
  )

  # Predictions
  train_pred <- predict(xgb_model, train_x)
  test_pred <- predict(xgb_model, test_x)

  # Evaluation metrics
  train_auc <- as.numeric(pROC::auc(pROC::roc(train_y, train_pred, quiet = TRUE)))
  test_auc <- as.numeric(pROC::auc(pROC::roc(test_y, test_pred, quiet = TRUE)))

  train_acc <- mean((train_pred > 0.5) == train_y)
  test_acc <- mean((test_pred > 0.5) == test_y)

  cat(sprintf("\nTraining Performance:\n"))
  cat(sprintf("  Accuracy: %.3f\n", train_acc))
  cat(sprintf("  AUC: %.3f\n", train_auc))

  cat(sprintf("\nTest Performance:\n"))
  cat(sprintf("  Accuracy: %.3f\n", test_acc))
  cat(sprintf("  AUC: %.3f\n", test_auc))

  # Feature importance
  importance <- xgb.importance(model = xgb_model)
  cat("\nTop Feature Importances:\n")
  print(head(importance, 10))

  list(
    model = xgb_model,
    train_accuracy = train_acc,
    test_accuracy = test_acc,
    train_auc = train_auc,
    test_auc = test_auc,
    importance = importance
  )
}

#' Train logistic regression baseline model
#'
#' @param features Feature matrix from prepare_ml_features()
#' @param train_ratio Proportion of data for training
#' @return List with trained model and evaluation metrics
train_logistic_model <- function(features, train_ratio = 0.8) {
  cat("\n=== Training Logistic Regression Baseline ===\n")

  # Remove rows with missing values
  features <- features %>%
    select(vote_binary, party_numeric, state_numeric,
           doc_type_numeric, nivel_numeric, poder_numeric,
           dw_nominate_1, dw_nominate_2) %>%
    na.omit()

  # Split train/test
  set.seed(42)
  train_idx <- sample(1:nrow(features), size = floor(train_ratio * nrow(features)))

  train_data <- features[train_idx, ]
  test_data <- features[-train_idx, ]

  # Train logistic regression
  glm_model <- glm(
    vote_binary ~ .,
    data = train_data,
    family = binomial(link = "logit")
  )

  # Predictions
  train_pred <- predict(glm_model, train_data, type = "response")
  test_pred <- predict(glm_model, test_data, type = "response")

  # Evaluation metrics
  train_auc <- as.numeric(pROC::auc(pROC::roc(train_data$vote_binary, train_pred, quiet = TRUE)))
  test_auc <- as.numeric(pROC::auc(pROC::roc(test_data$vote_binary, test_pred, quiet = TRUE)))

  train_acc <- mean((train_pred > 0.5) == train_data$vote_binary)
  test_acc <- mean((test_pred > 0.5) == test_data$vote_binary)

  cat(sprintf("\nTraining Performance:\n"))
  cat(sprintf("  Accuracy: %.3f\n", train_acc))
  cat(sprintf("  AUC: %.3f\n", train_auc))

  cat(sprintf("\nTest Performance:\n"))
  cat(sprintf("  Accuracy: %.3f\n", test_acc))
  cat(sprintf("  AUC: %.3f\n", test_auc))

  list(
    model = glm_model,
    train_accuracy = train_acc,
    test_accuracy = test_acc,
    train_auc = train_auc,
    test_auc = test_auc
  )
}

#' Predict votes for new bills
#'
#' @param model Trained model (XGBoost or GLM)
#' @param newdata New data for prediction
#' @param model_type Type of model ("xgboost" or "logistic")
#' @return Data frame with predictions
predict_votes <- function(model, newdata, model_type = "xgboost") {
  cat("\n=== Predicting Votes ===\n")

  # Prepare features
  feature_cols <- c("party_numeric", "state_numeric", "doc_type_numeric",
                   "nivel_numeric", "poder_numeric", "dw_nominate_1", "dw_nominate_2")

  pred_features <- newdata %>%
    select(all_of(feature_cols)) %>%
    na.omit()

  # Make predictions
  if (model_type == "xgboost") {
    predictions <- predict(model$model, as.matrix(pred_features))
  } else if (model_type == "logistic") {
    predictions <- predict(model$model, pred_features, type = "response")
  } else {
    stop("Unknown model type. Use 'xgboost' or 'logistic'")
  }

  # Prepare output
  result <- newdata %>%
    mutate(
      predicted_probability = predictions,
      predicted_vote = ifelse(predictions > 0.5, "yes", "no")
    )

  cat(sprintf("Generated %d predictions\n", nrow(result)))

  result
}

#' Save voting predictions to database
#'
#' @param con Database connection
#' @param predictions Predictions data frame
#' @param model_type Model type used
save_voting_predictions <- function(con, predictions, model_type = "xgboost") {
  cat("\n=== Saving Predictions to Database ===\n")

  # Prepare for database insert
  pred_df <- predictions %>%
    select(bill_id, legislator_id, predicted_vote, predicted_probability) %>%
    mutate(
      model_type = model_type,
      predicted_at = Sys.time(),
      model_version = "v1.0"
    )

  # Insert to database
  dbWriteTable(con, "voting_predictions", pred_df, append = TRUE, row.names = FALSE)

  cat(sprintf("Saved %d predictions to database\n", nrow(pred_df)))
}

#' Main function for voting prediction
#'
#' @param mode Analysis mode: "ideology", "predict", "full"
#' @param save_to_db Whether to save results to database
main <- function(mode = "full", save_to_db = FALSE) {
  cat("=== Voting Behavior Prediction ===\n")
  cat(sprintf("Mode: %s\n", mode))
  cat(sprintf("Date: %s\n\n", Sys.Date()))

  # Connect to database
  con <- dbConnect(
    RPostgres::Postgres(),
    host = Sys.getenv("DB_HOST", "localhost"),
    port = as.integer(Sys.getenv("DB_PORT", "5432")),
    dbname = Sys.getenv("DB_NAME", "monitor_legislativo"),
    user = Sys.getenv("DB_USER", "monitor_user"),
    password = {
      pwd <- Sys.getenv("DB_PASSWORD", "")
      if (pwd == "") stop("DB_PASSWORD environment variable required. Set in .Renviron or system env.")
      pwd
    }
  )

  on.exit(dbDisconnect(con))

  tryCatch({
    # Prepare voting data
    voting_data <- prepare_voting_data(con)

    # Estimate W-NOMINATE ideal points
    if (mode %in% c("ideology", "full")) {
      cat("\n========================================\n")
      cat("W-NOMINATE IDEAL POINT ESTIMATION\n")
      cat("========================================\n")

      wnom <- estimate_wnominate(voting_data$vote_matrix, dimensions = 2)

      if (!is.null(wnom)) {
        # Plot ideal points
        ip_plot <- plot_ideal_points(wnom, voting_data$legislators)
        if (!is.null(ip_plot)) print(ip_plot)

        # Update database
        ideal_points <- update_ideal_points(con, wnom, voting_data$legislators)
      } else {
        ideal_points <- NULL
      }
    } else {
      # Load existing ideal points from database
      ideal_points <- dbGetQuery(con, "
        SELECT id as legislator_id, dw_nominate_1, dw_nominate_2
        FROM legislators
        WHERE dw_nominate_1 IS NOT NULL
      ")
    }

    # Machine learning prediction
    if (mode %in% c("predict", "full")) {
      cat("\n========================================\n")
      cat("MACHINE LEARNING VOTING PREDICTION\n")
      cat("========================================\n")

      # Prepare features
      features <- prepare_ml_features(voting_data, ideal_points)

      # Train models
      xgb_results <- train_xgboost_model(features, train_ratio = 0.8)
      glm_results <- train_logistic_model(features, train_ratio = 0.8)

      # Compare models
      cat("\n========================================\n")
      cat("MODEL COMPARISON\n")
      cat("========================================\n")

      comparison <- data.frame(
        Model = c("XGBoost", "Logistic Regression"),
        Train_Accuracy = c(xgb_results$train_accuracy, glm_results$train_accuracy),
        Test_Accuracy = c(xgb_results$test_accuracy, glm_results$test_accuracy),
        Train_AUC = c(xgb_results$train_auc, glm_results$train_auc),
        Test_AUC = c(xgb_results$test_auc, glm_results$test_auc)
      )

      print(comparison)

      # Save predictions if requested
      if (save_to_db) {
        # Use best model for predictions
        best_model <- if (xgb_results$test_auc > glm_results$test_auc) {
          list(model = xgb_results, type = "xgboost")
        } else {
          list(model = glm_results, type = "logistic")
        }

        predictions <- predict_votes(best_model$model, features, best_model$type)
        save_voting_predictions(con, predictions, best_model$type)
      }
    }

    cat("\n=== SUCCESS ===\n")
    cat("Voting behavior analysis complete!\n")

  }, error = function(e) {
    cat(sprintf("\n❌ ERROR: %s\n", e$message))
    traceback()
    quit(status = 1)
  })
}

# Run main if executed as script
if (!interactive()) {
  # Load pROC package for AUC calculation
  if (!requireNamespace("pROC", quietly = TRUE)) {
    install.packages("pROC", repos = "https://cloud.r-project.org")
  }
  library(pROC)

  main(mode = "full", save_to_db = TRUE)
}
