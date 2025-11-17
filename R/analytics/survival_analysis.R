# Survival Analysis for Bill Progression
# Sprint 4 - PRD 4.1: Survival Analysis for Bill Progression
# Purpose: Analyze time-to-event data for legislative bills using survival models

library(DBI)
library(RPostgres)
library(survival)
library(survminer)
library(flexsurv)
library(dplyr)
library(ggplot2)
library(tidyr)

#' Prepare survival data from database
#'
#' @param con Database connection
#' @param min_events Minimum number of events required per bill
#' @return Data frame ready for survival analysis
prepare_survival_data <- function(con, min_events = 1) {
  cat("Preparing survival data from database...\n")

  # Query bill lifecycle summary
  survival_data <- dbGetQuery(con, "
    SELECT
      bill_id,
      titulo,
      tipo_documento,
      nivel,
      poder,
      intro_date,
      passage_date,
      failure_date,
      days_to_passage,
      status,
      num_events
    FROM bill_lifecycle_summary
    WHERE intro_date IS NOT NULL
      AND num_events >= $1
  ", params = list(min_events))

  if (nrow(survival_data) == 0) {
    stop("No survival data found. Ensure bill_events table is populated.")
  }

  cat(sprintf("Loaded %d bills for survival analysis\n", nrow(survival_data)))

  # Create survival outcome variables
  survival_data <- survival_data %>%
    mutate(
      # Time variable (days since introduction)
      time = case_when(
        status == "passed" ~ days_to_passage,
        status == "failed" ~ as.numeric(failure_date - intro_date),
        status == "pending" ~ as.numeric(Sys.Date() - intro_date),
        TRUE ~ NA_real_
      ),
      # Event indicator (1 = passed, 0 = censored)
      event = case_when(
        status == "passed" ~ 1,
        status == "failed" ~ 0,
        status == "pending" ~ 0,
        TRUE ~ NA_real_
      ),
      # Stratification variables
      doc_type = tipo_documento,
      level = nivel,
      branch = poder
    ) %>%
    filter(!is.na(time), time > 0)

  cat(sprintf("Prepared %d observations\n", nrow(survival_data)))
  cat(sprintf("  Passed: %d (%.1f%%)\n",
              sum(survival_data$event == 1),
              100 * mean(survival_data$event == 1)))
  cat(sprintf("  Censored: %d (%.1f%%)\n",
              sum(survival_data$event == 0),
              100 * mean(survival_data$event == 0)))

  survival_data
}

#' Fit Kaplan-Meier survival curves
#'
#' @param survival_data Survival data from prepare_survival_data()
#' @param stratify_by Variable to stratify by (e.g., "doc_type", "level")
#' @return Survfit object
fit_kaplan_meier <- function(survival_data, stratify_by = NULL) {
  cat("\n=== Fitting Kaplan-Meier Estimator ===\n")

  # Create survival object
  surv_obj <- Surv(time = survival_data$time, event = survival_data$event)

  # Fit KM model
  if (!is.null(stratify_by) && stratify_by %in% names(survival_data)) {
    formula <- as.formula(paste("surv_obj ~", stratify_by))
    cat(sprintf("Stratifying by: %s\n", stratify_by))
  } else {
    formula <- surv_obj ~ 1
    cat("Fitting overall survival curve\n")
  }

  km_fit <- survfit(formula, data = survival_data)

  # Print summary
  cat("\nKaplan-Meier Summary:\n")
  print(summary(km_fit, times = c(30, 90, 180, 365, 730)))

  km_fit
}

#' Plot Kaplan-Meier survival curves
#'
#' @param km_fit Survfit object from fit_kaplan_meier()
#' @param title Plot title
#' @param xlab X-axis label
#' @param ylab Y-axis label
#' @return ggplot object
plot_kaplan_meier <- function(km_fit,
                              title = "Kaplan-Meier Survival Curve: Bill Passage",
                              xlab = "Days since Introduction",
                              ylab = "Probability of Passage") {

  ggsurvplot(
    km_fit,
    data = NULL,
    conf.int = TRUE,
    pval = TRUE,
    risk.table = TRUE,
    risk.table.height = 0.25,
    ggtheme = theme_minimal(),
    palette = "jco",
    title = title,
    xlab = xlab,
    ylab = ylab,
    break.x.by = 90,
    surv.median.line = "hv",
    legend.title = "Strata",
    legend.labs = NULL
  )
}

#' Fit Cox proportional hazards model
#'
#' @param survival_data Survival data from prepare_survival_data()
#' @param covariates Character vector of covariate names
#' @return Coxph object
fit_cox_model <- function(survival_data, covariates = c("doc_type", "level", "branch")) {
  cat("\n=== Fitting Cox Proportional Hazards Model ===\n")

  # Create survival object
  surv_obj <- Surv(time = survival_data$time, event = survival_data$event)

  # Build formula
  formula_str <- paste("surv_obj ~", paste(covariates, collapse = " + "))
  formula <- as.formula(formula_str)

  cat(sprintf("Formula: %s\n", formula_str))

  # Fit Cox model
  cox_fit <- coxph(formula, data = survival_data)

  # Print summary
  cat("\nCox Model Summary:\n")
  print(summary(cox_fit))

  # Test proportional hazards assumption
  cat("\nProportional Hazards Test:\n")
  ph_test <- cox.zph(cox_fit)
  print(ph_test)

  if (any(ph_test$table[, "p"] < 0.05)) {
    cat("\n⚠️ WARNING: Proportional hazards assumption may be violated for some covariates\n")
  } else {
    cat("\n✅ Proportional hazards assumption appears satisfied\n")
  }

  cox_fit
}

#' Plot Cox model hazard ratios
#'
#' @param cox_fit Coxph object from fit_cox_model()
#' @return ggplot object
plot_cox_hazard_ratios <- function(cox_fit) {
  # Extract coefficients and confidence intervals
  coef_df <- as.data.frame(summary(cox_fit)$conf.int)
  coef_df$variable <- rownames(coef_df)

  names(coef_df) <- c("hr", "neg_hr", "lower", "upper", "variable")

  # Create forest plot
  ggplot(coef_df, aes(x = variable, y = hr)) +
    geom_point(size = 3) +
    geom_errorbar(aes(ymin = lower, ymax = upper), width = 0.2) +
    geom_hline(yintercept = 1, linetype = "dashed", color = "red") +
    coord_flip() +
    labs(
      title = "Cox Model Hazard Ratios",
      subtitle = "Effect of Covariates on Bill Passage Hazard",
      x = "Covariate",
      y = "Hazard Ratio (95% CI)"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(face = "bold", size = 14),
      axis.text = element_text(size = 10)
    )
}

#' Fit parametric survival models
#'
#' @param survival_data Survival data from prepare_survival_data()
#' @param distributions Vector of distribution names to fit
#' @param covariates Character vector of covariate names
#' @return List of flexsurvreg objects
fit_parametric_survival <- function(survival_data,
                                   distributions = c("weibull", "lognormal", "gompertz"),
                                   covariates = c("doc_type", "level", "branch")) {

  cat("\n=== Fitting Parametric Survival Models ===\n")

  # Create survival object
  surv_obj <- Surv(time = survival_data$time, event = survival_data$event)

  # Build formula
  formula_str <- paste("surv_obj ~", paste(covariates, collapse = " + "))
  formula <- as.formula(formula_str)

  models <- list()
  aic_values <- numeric()

  for (dist in distributions) {
    cat(sprintf("\nFitting %s distribution...\n", dist))

    tryCatch({
      model <- flexsurvreg(formula, data = survival_data, dist = dist)
      models[[dist]] <- model
      aic_values[dist] <- AIC(model)

      cat(sprintf("  AIC: %.2f\n", AIC(model)))
      cat(sprintf("  Log-likelihood: %.2f\n", logLik(model)[1]))

    }, error = function(e) {
      cat(sprintf("  ❌ Failed to fit %s: %s\n", dist, e$message))
    })
  }

  # Select best model by AIC
  if (length(aic_values) > 0) {
    best_dist <- names(which.min(aic_values))
    cat(sprintf("\n✅ Best model by AIC: %s (AIC = %.2f)\n", best_dist, min(aic_values)))
  }

  list(
    models = models,
    aic = aic_values,
    best = if (length(aic_values) > 0) models[[best_dist]] else NULL
  )
}

#' Compare survival models
#'
#' @param km_fit Kaplan-Meier survfit object
#' @param cox_fit Cox model coxph object
#' @param parametric_fits List of parametric models from fit_parametric_survival()
#' @return Comparison table
compare_survival_models <- function(km_fit, cox_fit, parametric_fits) {
  cat("\n=== Model Comparison ===\n")

  comparison <- data.frame(
    Model = character(),
    AIC = numeric(),
    Concordance = numeric(),
    stringsAsFactors = FALSE
  )

  # Cox model
  comparison <- rbind(comparison, data.frame(
    Model = "Cox Proportional Hazards",
    AIC = AIC(cox_fit),
    Concordance = summary(cox_fit)$concordance[1]
  ))

  # Parametric models
  for (dist_name in names(parametric_fits$models)) {
    model <- parametric_fits$models[[dist_name]]
    comparison <- rbind(comparison, data.frame(
      Model = paste("Parametric -", dist_name),
      AIC = AIC(model),
      Concordance = NA_real_  # flexsurv doesn't provide concordance
    ))
  }

  # Sort by AIC
  comparison <- comparison %>% arrange(AIC)

  print(comparison)
  cat("\n")

  comparison
}

#' Predict passage probability for new bills
#'
#' @param model Fitted survival model (Cox or parametric)
#' @param newdata Data frame with covariates for new bills
#' @param time_points Vector of time points for prediction (days)
#' @return Data frame with predictions
predict_passage_probability <- function(model, newdata, time_points = c(30, 90, 180, 365, 730)) {
  cat("\n=== Predicting Bill Passage Probability ===\n")

  predictions <- list()

  if (inherits(model, "coxph")) {
    # Cox model predictions
    for (t in time_points) {
      surv_prob <- summary(survfit(model, newdata = newdata), times = t)$surv
      predictions[[paste0("day_", t)]] <- surv_prob
    }

  } else if (inherits(model, "flexsurvreg")) {
    # Parametric model predictions
    for (t in time_points) {
      surv_prob <- summary(model, newdata = newdata, t = t, type = "survival")[[1]]$est
      predictions[[paste0("day_", t)]] <- surv_prob
    }

  } else {
    stop("Model type not supported. Use coxph or flexsurvreg object.")
  }

  # Combine predictions
  pred_df <- as.data.frame(predictions)
  pred_df <- cbind(newdata, pred_df)

  cat(sprintf("Generated predictions for %d bills at %d time points\n",
              nrow(pred_df), length(time_points)))

  pred_df
}

#' Calculate hazard ratios for bill characteristics
#'
#' @param cox_fit Cox model from fit_cox_model()
#' @return Data frame with hazard ratios and confidence intervals
calculate_hazard_ratios <- function(cox_fit) {
  cat("\n=== Calculating Hazard Ratios ===\n")

  # Extract coefficients
  coef_summary <- summary(cox_fit)$conf.int

  hr_df <- data.frame(
    covariate = rownames(coef_summary),
    hazard_ratio = coef_summary[, "exp(coef)"],
    ci_lower = coef_summary[, "lower .95"],
    ci_upper = coef_summary[, "upper .95"],
    p_value = summary(cox_fit)$coefficients[, "Pr(>|z|)"]
  )

  rownames(hr_df) <- NULL

  # Interpret hazard ratios
  hr_df <- hr_df %>%
    mutate(
      interpretation = case_when(
        hazard_ratio > 1 & p_value < 0.05 ~ "Increases hazard (faster passage)",
        hazard_ratio < 1 & p_value < 0.05 ~ "Decreases hazard (slower passage)",
        TRUE ~ "No significant effect"
      )
    )

  print(hr_df)

  hr_df
}

#' Save survival analysis results to database
#'
#' @param con Database connection
#' @param survival_predictions Data frame with predictions
#' @param model_obj Fitted model object
#' @param model_type Model type ("cox", "weibull", "lognormal", "gompertz")
save_survival_results <- function(con, survival_predictions, model_obj, model_type) {
  cat("\n=== Saving Survival Analysis Results ===\n")

  # Prepare results for database
  results <- survival_predictions %>%
    select(bill_id, day_30, day_90, day_180, day_365) %>%
    mutate(
      model_type = model_type,
      predicted_passage_prob = day_365,
      predicted_days_to_passage = NA_integer_,  # Can be estimated from survival curve
      hazard_ratio = NA_real_,
      confidence_interval_lower = NA_real_,
      confidence_interval_upper = NA_real_,
      calculated_at = Sys.time(),
      model_version = "v1.0"
    )

  # Insert into database
  dbWriteTable(con, "survival_analysis_results", results, append = TRUE, row.names = FALSE)

  cat(sprintf("Saved %d predictions to survival_analysis_results table\n", nrow(results)))
}

#' Main function for survival analysis
#'
#' @param mode Analysis mode: "explore", "predict", "full"
#' @param stratify_by Variable to stratify KM curves
#' @param covariates Covariates for Cox and parametric models
#' @param save_to_db Whether to save results to database
main <- function(mode = "full",
                stratify_by = "doc_type",
                covariates = c("doc_type", "level", "branch"),
                save_to_db = FALSE) {

  cat("=== Survival Analysis for Bill Progression ===\n")
  cat(sprintf("Mode: %s\n", mode))
  cat(sprintf("Date: %s\n\n", Sys.Date()))

  # Connect to database
  con <- dbConnect(
    RPostgres::Postgres(),
    host = Sys.getenv("DB_HOST", "localhost"),
    port = as.integer(Sys.getenv("DB_PORT", "5432")),
    dbname = Sys.getenv("DB_NAME", "monitor_legislativo"),
    user = Sys.getenv("DB_USER", "monitor_user"),
    password = Sys.getenv("DB_PASSWORD", "Sdonario1")
  )

  on.exit(dbDisconnect(con))

  tryCatch({
    # Prepare data
    survival_data <- prepare_survival_data(con, min_events = 1)

    # Exploratory analysis
    if (mode %in% c("explore", "full")) {
      cat("\n========================================\n")
      cat("EXPLORATORY SURVIVAL ANALYSIS\n")
      cat("========================================\n")

      # Fit Kaplan-Meier
      km_fit <- fit_kaplan_meier(survival_data, stratify_by = stratify_by)

      # Plot KM curves
      km_plot <- plot_kaplan_meier(km_fit)
      print(km_plot)
    }

    # Model fitting
    if (mode %in% c("predict", "full")) {
      cat("\n========================================\n")
      cat("SURVIVAL MODEL FITTING\n")
      cat("========================================\n")

      # Fit Cox model
      cox_fit <- fit_cox_model(survival_data, covariates = covariates)

      # Plot hazard ratios
      hr_plot <- plot_cox_hazard_ratios(cox_fit)
      print(hr_plot)

      # Calculate hazard ratios
      hazard_ratios <- calculate_hazard_ratios(cox_fit)

      # Fit parametric models
      parametric_fits <- fit_parametric_survival(
        survival_data,
        distributions = c("weibull", "lognormal", "gompertz"),
        covariates = covariates
      )

      # Compare models
      if (exists("km_fit")) {
        model_comparison <- compare_survival_models(km_fit, cox_fit, parametric_fits)
      }

      # Make predictions for pending bills
      pending_bills <- survival_data %>% filter(status == "pending")

      if (nrow(pending_bills) > 0) {
        cat(sprintf("\n=== Making Predictions for %d Pending Bills ===\n", nrow(pending_bills)))

        predictions <- predict_passage_probability(
          cox_fit,
          newdata = pending_bills,
          time_points = c(30, 90, 180, 365, 730)
        )

        # Save to database if requested
        if (save_to_db) {
          save_survival_results(con, predictions, cox_fit, "cox")
        }
      }
    }

    cat("\n=== SUCCESS ===\n")
    cat("Survival analysis complete!\n")

  }, error = function(e) {
    cat(sprintf("\n❌ ERROR: %s\n", e$message))
    traceback()
    quit(status = 1)
  })
}

# Run main if executed as script
if (!interactive()) {
  main(mode = "full", save_to_db = TRUE)
}
