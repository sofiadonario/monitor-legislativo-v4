# Topic Modeling Module for Brazilian Legislative Documents
# MackMonitor v4 - Static and Dynamic Topic Analysis
# Author: Analytics Module
# Date: 2025-01-25

library(topicmodels)
library(stm)
library(ldatuning)
library(tidytext)
library(dplyr)
library(ggplot2)
library(lubridate)
library(quanteda)
library(purrr)
library(furrr)

# For dynamic topic modeling
if (!require("rollinglda")) {
  devtools::install_github("JonasRieger/rollinglda")
  library(rollinglda)
}

# ============================================================================
# 1. TOPIC MODEL CONFIGURATION
# ============================================================================

TOPIC_CONFIG <- list(
  # Model parameters
  min_topics = 5,
  max_topics = 50,
  topic_step = 5,
  
  # LDA parameters
  lda_alpha = 50/15,  # Document-topic density (50/K is common)
  lda_beta = 0.01,    # Topic-word density
  
  # STM parameters
  stm_init_type = "Spectral",
  stm_max_iterations = 100,
  stm_convergence_threshold = 1e-5,
  
  # Dynamic modeling
  time_slice = "year",  # year, quarter, month
  min_docs_per_slice = 50,
  rolling_window = 12,  # months
  
  # Evaluation metrics
  use_coherence = TRUE,
  use_exclusivity = TRUE,
  use_perplexity = TRUE,
  
  # Output settings
  top_terms_per_topic = 20,
  top_docs_per_topic = 10,
  
  # Interpretation
  topic_labels_method = "frex",  # frex, lift, score, prob
  min_topic_size = 0.01  # Minimum 1% of documents
)

# ============================================================================
# 2. STATIC TOPIC MODELING
# ============================================================================

#' Find optimal number of topics using multiple metrics
#' @param dfm Document-feature matrix
#' @param k_range Range of topic numbers to test
#' @param method Model type ("LDA" or "STM")
#' @return Data frame with evaluation metrics
find_optimal_topics <- function(dfm, 
                               k_range = seq(5, 50, 5),
                               method = "LDA") {
  
  cat(sprintf("Testing %s models with K = %s\n", 
              method, paste(k_range, collapse = ", ")))
  
  if (method == "LDA") {
    # Use ldatuning for LDA
    results <- FindTopicsNumber(
      dfm,
      topics = k_range,
      metrics = c("Griffiths2004", "CaoJuan2009", "Arun2010", "Deveaud2014"),
      method = "Gibbs",
      control = list(seed = 123),
      verbose = FALSE
    )
  } else if (method == "STM") {
    # Manual evaluation for STM
    results <- map_dfr(k_range, function(k) {
      cat(sprintf("  Testing K = %d...\n", k))
      
      # Fit STM model
      stm_model <- stm(
        dfm,
        K = k,
        init.type = TOPIC_CONFIG$stm_init_type,
        max.em.its = 50,  # Reduced for tuning
        verbose = FALSE
      )
      
      # Calculate metrics
      metrics <- list(
        K = k,
        semantic_coherence = mean(semanticCoherence(stm_model, dfm)),
        exclusivity = mean(exclusivity(stm_model)),
        heldout = NA  # Would require held-out set
      )
      
      return(metrics)
    })
  }
  
  return(results)
}

#' Fit LDA topic model
#' @param dfm Document-feature matrix
#' @param k Number of topics
#' @param config Topic modeling configuration
#' @return LDA model object
fit_lda_model <- function(dfm, k, config = TOPIC_CONFIG) {
  cat(sprintf("\nFitting LDA model with %d topics...\n", k))
  
  # Convert to tm format if needed
  dtm <- convert(dfm, to = "topicmodels")
  
  # Fit model
  lda_model <- LDA(
    dtm,
    k = k,
    method = "Gibbs",
    control = list(
      seed = 123,
      burnin = 1000,
      iter = 2000,
      thin = 100,
      alpha = config$lda_alpha,
      delta = config$lda_beta
    )
  )
  
  return(lda_model)
}

#' Fit STM topic model with metadata
#' @param dfm Document-feature matrix with metadata
#' @param k Number of topics
#' @param prevalence_formula Formula for topic prevalence
#' @param config Topic modeling configuration
#' @return STM model object
fit_stm_model <- function(dfm, k, 
                         prevalence_formula = ~ authority_level + s(year),
                         config = TOPIC_CONFIG) {
  
  cat(sprintf("\nFitting STM model with %d topics...\n", k))
  
  # Prepare metadata
  meta <- docvars(dfm)
  meta$year <- year(meta$date)
  
  # Fit model
  stm_model <- stm(
    documents = dfm,
    K = k,
    prevalence = prevalence_formula,
    data = meta,
    init.type = config$stm_init_type,
    max.em.its = config$stm_max_iterations,
    emtol = config$stm_convergence_threshold,
    verbose = TRUE
  )
  
  return(stm_model)
}

#' Extract and label topics from fitted model
#' @param model Topic model (LDA or STM)
#' @param dfm Original document-feature matrix
#' @param n_terms Number of top terms per topic
#' @param method Labeling method
#' @return Data frame with topic information
extract_topic_info <- function(model, dfm, 
                              n_terms = 20,
                              method = "frex") {
  
  if (class(model)[1] == "LDA") {
    # Extract LDA topics
    topics <- tidy(model, matrix = "beta") %>%
      group_by(topic) %>%
      top_n(n_terms, beta) %>%
      arrange(topic, desc(beta))
    
    # Get topic proportions
    gamma <- tidy(model, matrix = "gamma")
    topic_props <- gamma %>%
      group_by(topic) %>%
      summarise(avg_proportion = mean(gamma))
    
  } else if (class(model)[1] == "STM") {
    # Extract STM topics
    topic_words <- labelTopics(model, n = n_terms, frexweight = 0.7)
    
    # Convert to tidy format
    topics <- map_dfr(1:model$settings$dim$K, function(k) {
      data.frame(
        topic = k,
        term = topic_words[[method]][k, ],
        rank = 1:n_terms
      )
    })
    
    # Get topic proportions
    topic_props <- colMeans(model$theta)
    topic_props <- data.frame(
      topic = 1:length(topic_props),
      avg_proportion = topic_props
    )
  }
  
  # Add topic labels
  topic_labels <- topics %>%
    group_by(topic) %>%
    summarise(
      label = paste(head(term, 5), collapse = "_"),
      top_terms = paste(head(term, 10), collapse = ", ")
    )
  
  # Combine information
  topic_info <- topic_props %>%
    left_join(topic_labels, by = "topic") %>%
    arrange(desc(avg_proportion))
  
  return(list(
    topics = topics,
    topic_info = topic_info
  ))
}

# ============================================================================
# 3. DYNAMIC TOPIC MODELING
# ============================================================================

#' Prepare time-sliced data for dynamic modeling
#' @param dfm Document-feature matrix with date metadata
#' @param time_slice Time aggregation level
#' @param min_docs Minimum documents per slice
#' @return List of time-sliced DFMs
prepare_time_slices <- function(dfm, 
                               time_slice = "year",
                               min_docs = 50) {
  
  # Extract dates
  dates <- docvars(dfm, "date")
  
  # Create time periods
  if (time_slice == "year") {
    periods <- year(dates)
  } else if (time_slice == "quarter") {
    periods <- paste0(year(dates), "-Q", quarter(dates))
  } else if (time_slice == "month") {
    periods <- format(dates, "%Y-%m")
  }
  
  # Split by period
  period_groups <- split(1:ndoc(dfm), periods)
  
  # Filter periods with enough documents
  valid_periods <- names(period_groups)[
    sapply(period_groups, length) >= min_docs
  ]
  
  cat(sprintf("Created %d time slices (%d valid with >=%d docs)\n",
              length(period_groups), length(valid_periods), min_docs))
  
  # Create DFM for each period
  time_slices <- map(valid_periods, function(period) {
    idx <- period_groups[[period]]
    dfm_subset <- dfm[idx, ]
    docvars(dfm_subset, "period") <- period
    return(dfm_subset)
  })
  
  names(time_slices) <- valid_periods
  
  return(time_slices)
}

#' Fit rolling LDA model for dynamic topic analysis
#' @param dfm Document-feature matrix
#' @param k Number of topics
#' @param dates Document dates
#' @param window_months Rolling window size in months
#' @return Rolling LDA model
fit_rolling_lda <- function(dfm, k, dates, window_months = 12) {
  cat(sprintf("\nFitting rolling LDA with K=%d, window=%d months\n", 
              k, window_months))
  
  # Convert to required format
  docs <- convert(dfm, to = "lda")
  
  # Create monthly chunks
  dates_monthly <- format(dates, "%Y-%m")
  
  # Fit model
  roll_lda <- RollingLDA(
    texts = docs$documents,
    dates = dates_monthly,
    K = k,
    window = window_months,
    step = 1,  # Monthly steps
    alpha = TOPIC_CONFIG$lda_alpha,
    beta = TOPIC_CONFIG$lda_beta,
    num.iterations = 200
  )
  
  return(roll_lda)
}

#' Track topic evolution over time
#' @param model Dynamic topic model
#' @param time_slices Time-sliced data
#' @return Data frame with topic evolution metrics
track_topic_evolution <- function(model, time_slices) {
  if (class(model)[1] == "RollingLDA") {
    # Extract topic proportions over time
    evolution <- model$topics.over.time
    
  } else {
    # For static models on time slices
    evolution <- map_dfr(names(time_slices), function(period) {
      slice_model <- model[[period]]
      
      if (class(slice_model)[1] == "STM") {
        topic_props <- colMeans(slice_model$theta)
      } else {
        # LDA
        gamma <- posterior(slice_model)$topics
        topic_props <- colMeans(gamma)
      }
      
      data.frame(
        period = period,
        topic = 1:length(topic_props),
        proportion = topic_props
      )
    })
  }
  
  # Identify emerging, persistent, and fading topics
  topic_trends <- evolution %>%
    group_by(topic) %>%
    arrange(period) %>%
    mutate(
      trend = c(NA, diff(proportion)),
      first_period = min(period),
      last_period = max(period),
      avg_proportion = mean(proportion)
    ) %>%
    summarise(
      avg_trend = mean(trend, na.rm = TRUE),
      total_change = last(proportion) - first(proportion),
      volatility = sd(proportion),
      persistence = n() / n_distinct(evolution$period),
      avg_proportion = mean(avg_proportion)
    )
  
  # Classify topics
  topic_trends <- topic_trends %>%
    mutate(
      classification = case_when(
        total_change > 0.02 & avg_trend > 0 ~ "Emerging",
        total_change < -0.02 & avg_trend < 0 ~ "Fading",
        volatility < 0.01 & persistence > 0.8 ~ "Persistent",
        volatility > 0.03 ~ "Volatile",
        TRUE ~ "Stable"
      )
    )
  
  return(list(
    evolution = evolution,
    trends = topic_trends
  ))
}

# ============================================================================
# 4. TOPIC VISUALIZATION
# ============================================================================

#' Create topic evolution plot
#' @param evolution Topic evolution data
#' @param top_n Number of topics to show
#' @return ggplot object
plot_topic_evolution <- function(evolution, top_n = 10) {
  # Get top topics by average proportion
  top_topics <- evolution %>%
    group_by(topic) %>%
    summarise(avg_prop = mean(proportion)) %>%
    top_n(top_n, avg_prop) %>%
    pull(topic)
  
  # Filter and plot
  p <- evolution %>%
    filter(topic %in% top_topics) %>%
    mutate(topic = factor(topic)) %>%
    ggplot(aes(x = period, y = proportion, color = topic, group = topic)) +
    geom_line(size = 1.2) +
    geom_point(size = 2) +
    scale_y_continuous(labels = scales::percent) +
    theme_minimal() +
    theme(
      axis.text.x = element_text(angle = 45, hjust = 1),
      legend.position = "right"
    ) +
    labs(
      title = "Topic Evolution Over Time",
      x = "Time Period",
      y = "Average Topic Proportion",
      color = "Topic"
    )
  
  return(p)
}

#' Create topic correlation network
#' @param model Topic model
#' @param threshold Correlation threshold for edges
#' @return Network plot
plot_topic_network <- function(model, threshold = 0.1) {
  library(igraph)
  library(ggraph)
  
  # Get topic correlations
  if (class(model)[1] == "STM") {
    topic_corr <- topicCorr(model)$cor
  } else {
    # For LDA, use document-level correlations
    gamma <- posterior(model)$topics
    topic_corr <- cor(gamma)
  }
  
  # Create network
  diag(topic_corr) <- 0
  topic_corr[topic_corr < threshold] <- 0
  
  g <- graph_from_adjacency_matrix(
    topic_corr,
    mode = "undirected",
    weighted = TRUE
  )
  
  # Remove isolated nodes
  g <- delete.vertices(g, which(degree(g) == 0))
  
  # Plot
  p <- ggraph(g, layout = "fr") +
    geom_edge_link(aes(width = weight), alpha = 0.5) +
    geom_node_point(size = 5, color = "steelblue") +
    geom_node_text(aes(label = name), repel = TRUE) +
    theme_graph() +
    labs(title = "Topic Correlation Network")
  
  return(p)
}

# ============================================================================
# 5. TOPIC MODELING PIPELINE
# ============================================================================

#' Complete topic modeling pipeline
#' @param preprocessed_data Output from preprocessing module
#' @param method Model type ("LDA", "STM", or "both")
#' @param k Number of topics (NULL for optimization)
#' @param dynamic Whether to perform dynamic analysis
#' @return List with models and results
run_topic_modeling_pipeline <- function(preprocessed_data,
                                      method = "both",
                                      k = NULL,
                                      dynamic = TRUE) {
  
  cat("\n=== TOPIC MODELING PIPELINE ===\n")
  
  results <- list()
  dfm <- preprocessed_data$dfm
  
  # 1. Find optimal K if not specified
  if (is.null(k)) {
    cat("\n1. Finding optimal number of topics...\n")
    
    k_range <- seq(TOPIC_CONFIG$min_topics, 
                   TOPIC_CONFIG$max_topics, 
                   TOPIC_CONFIG$topic_step)
    
    if (method %in% c("LDA", "both")) {
      results$lda_tuning <- find_optimal_topics(dfm, k_range, "LDA")
      # Simple heuristic: use elbow in perplexity
      k_lda <- 15  # Default, would need proper elbow detection
    }
    
    if (method %in% c("STM", "both")) {
      results$stm_tuning <- find_optimal_topics(dfm, k_range, "STM")
      k_stm <- 15  # Default
    }
    
    k <- ifelse(method == "LDA", k_lda, k_stm)
  }
  
  # 2. Fit static models
  cat("\n2. Fitting static topic models...\n")
  
  if (method %in% c("LDA", "both")) {
    results$lda_model <- fit_lda_model(dfm, k)
    results$lda_topics <- extract_topic_info(results$lda_model, dfm)
  }
  
  if (method %in% c("STM", "both")) {
    results$stm_model <- fit_stm_model(dfm, k)
    results$stm_topics <- extract_topic_info(results$stm_model, dfm)
    
    # STM-specific analyses
    results$stm_effects <- estimateEffect(
      ~ authority_level + s(year),
      results$stm_model,
      metadata = docvars(dfm)
    )
  }
  
  # 3. Dynamic topic modeling
  if (dynamic) {
    cat("\n3. Performing dynamic topic analysis...\n")
    
    # Prepare time slices
    time_slices <- prepare_time_slices(dfm, 
                                      time_slice = TOPIC_CONFIG$time_slice,
                                      min_docs = TOPIC_CONFIG$min_docs_per_slice)
    
    # Fit rolling LDA
    if (length(time_slices) >= 3) {
      dates <- docvars(dfm, "date")
      results$rolling_lda <- fit_rolling_lda(dfm, k, dates, 
                                            TOPIC_CONFIG$rolling_window)
      
      # Track evolution
      results$topic_evolution <- track_topic_evolution(
        results$rolling_lda, time_slices
      )
    }
  }
  
  # 4. Generate visualizations
  cat("\n4. Creating visualizations...\n")
  
  results$plots <- list()
  
  if (!is.null(results$topic_evolution)) {
    results$plots$evolution <- plot_topic_evolution(
      results$topic_evolution$evolution
    )
  }
  
  if (!is.null(results$stm_model)) {
    results$plots$network <- plot_topic_network(results$stm_model)
  }
  
  # 5. Extract key insights
  results$insights <- extract_topic_insights(results)
  
  cat("\nTopic modeling pipeline complete!\n")
  
  return(results)
}

#' Extract key insights from topic models
#' @param results Topic modeling results
#' @return List of insights
extract_topic_insights <- function(results) {
  insights <- list()
  
  # Top topics
  if (!is.null(results$lda_topics)) {
    insights$top_lda_topics <- results$lda_topics$topic_info %>%
      head(10) %>%
      select(topic, label, avg_proportion, top_terms)
  }
  
  if (!is.null(results$stm_topics)) {
    insights$top_stm_topics <- results$stm_topics$topic_info %>%
      head(10) %>%
      select(topic, label, avg_proportion, top_terms)
  }
  
  # Topic trends
  if (!is.null(results$topic_evolution)) {
    insights$emerging_topics <- results$topic_evolution$trends %>%
      filter(classification == "Emerging") %>%
      arrange(desc(total_change))
    
    insights$fading_topics <- results$topic_evolution$trends %>%
      filter(classification == "Fading") %>%
      arrange(total_change)
    
    insights$persistent_topics <- results$topic_evolution$trends %>%
      filter(classification == "Persistent") %>%
      arrange(desc(avg_proportion))
  }
  
  return(insights)
}

# ============================================================================
# 6. EXPORT FUNCTIONS
# ============================================================================

#' Save topic modeling results
#' @param results Topic modeling results
#' @param output_dir Output directory
save_topic_results <- function(results, output_dir = "topic_modeling_output") {
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Save models
  if (!is.null(results$lda_model)) {
    saveRDS(results$lda_model, file.path(output_dir, "lda_model.rds"))
  }
  
  if (!is.null(results$stm_model)) {
    saveRDS(results$stm_model, file.path(output_dir, "stm_model.rds"))
  }
  
  # Save topic information
  if (!is.null(results$lda_topics)) {
    write.csv(results$lda_topics$topic_info,
              file.path(output_dir, "lda_topics.csv"),
              row.names = FALSE)
  }
  
  if (!is.null(results$stm_topics)) {
    write.csv(results$stm_topics$topic_info,
              file.path(output_dir, "stm_topics.csv"),
              row.names = FALSE)
  }
  
  # Save evolution data
  if (!is.null(results$topic_evolution)) {
    write.csv(results$topic_evolution$evolution,
              file.path(output_dir, "topic_evolution.csv"),
              row.names = FALSE)
    
    write.csv(results$topic_evolution$trends,
              file.path(output_dir, "topic_trends.csv"),
              row.names = FALSE)
  }
  
  # Save plots
  for (plot_name in names(results$plots)) {
    ggsave(
      file.path(output_dir, paste0(plot_name, "_plot.png")),
      results$plots[[plot_name]],
      width = 12,
      height = 8
    )
  }
  
  # Save insights summary
  saveRDS(results$insights, file.path(output_dir, "topic_insights.rds"))
  
  cat(sprintf("\nResults saved to %s/\n", output_dir))
}