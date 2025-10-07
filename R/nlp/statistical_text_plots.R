# Statistical Text Visualization - ggstatsplot Integration
# Monitor Legislativo v4 - Publication-Ready NLP Statistical Plots
# ================================================================
#
# This module provides advanced statistical visualization capabilities for
# Portuguese NLP analysis using ggstatsplot, optimized for academic publication
# in Brazilian legislative research with proper statistical testing
#
# Features:
# - Publication-ready statistical plots with ggstatsplot
# - Bayesian and frequentist statistical tests
# - Multiple comparison corrections (Bonferroni, FDR)
# - Effect size calculations and confidence intervals
# - Integration with lexiconPT sentiment analysis results
# - Customizable themes for academic publication standards
# - Export capabilities (PNG, PDF, SVG) with proper resolution
#
# Author: NLP Enhancement Agent - Portuguese Text Analytics Specialist  
# Date: 2025-09-13
# Version: 1.0.0 - Academic Publication Ready

# Required packages for statistical text visualization
statistical_viz_packages <- c(
  "ggstatsplot",    # Advanced statistical plots
  "ggplot2",        # Base plotting system
  "ggrepel",        # Better text positioning
  "viridis",        # Color palettes
  "RColorBrewer",   # Additional color palettes
  "patchwork",      # Combine plots
  "scales",         # Scale functions
  "dplyr",          # Data manipulation
  "tidyr",          # Data tidying
  "tibble",         # Modern data frames
  "stringr",        # String manipulation
  "forcats",        # Factor manipulation
  "broom",          # Statistical model tidying
  "effsize",        # Effect size calculations
  "PMCMRplus",      # Post-hoc tests
  "coin"            # Additional statistical tests
)

# Load packages with graceful handling
available_viz_packages <- character(0)
missing_viz_packages <- character(0)

for (pkg in statistical_viz_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    available_viz_packages <- c(available_viz_packages, pkg)
  } else {
    missing_viz_packages <- c(missing_viz_packages, pkg)
  }
}

# Load essential packages
suppressPackageStartupMessages({
  library(ggplot2)
  library(dplyr)
  library(stringr)
  
  if ("ggstatsplot" %in% available_viz_packages) {
    library(ggstatsplot)
    ggstatsplot_loaded <- TRUE
    cat("✅ ggstatsplot loaded for advanced statistical visualizations\n")
  } else {
    ggstatsplot_loaded <- FALSE
    cat("⚠️ ggstatsplot not available - using standard ggplot2\n")
  }
  
  if ("viridis" %in% available_viz_packages) library(viridis)
  if ("patchwork" %in% available_viz_packages) library(patchwork)
  if ("scales" %in% available_viz_packages) library(scales)
  if ("broom" %in% available_viz_packages) library(broom)
})

cat("📊 Statistical Text Visualization loaded with", length(available_viz_packages), "/", length(statistical_viz_packages), "packages\n")

# ============================================================================
# STATISTICAL VISUALIZATION CONFIGURATION
# ============================================================================

# Configuration for academic publication standards
.statistical_plot_config <- list(
  # Academic publication settings
  publication = list(
    dpi = 300,                    # High resolution for print
    width_inches = 8,             # Standard academic width
    height_inches = 6,            # Standard academic height
    font_family = "Times",        # Academic font preference
    base_size = 12,               # Readable font size
    title_size = 14,              # Title font size
    axis_text_size = 10,          # Axis text size
    caption_size = 8              # Caption font size
  ),
  
  # Color schemes for colorblind accessibility
  colors = list(
    primary = c("#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"),
    sentiment = c(
      "Negative" = "#d62728",     # Red for negative
      "Neutral" = "#7f7f7f",      # Gray for neutral  
      "Positive" = "#2ca02c"      # Green for positive
    ),
    regulatory = c(
      "Prescriptive" = "#d62728",  # Red for prescriptive
      "Balanced" = "#7f7f7f",      # Gray for balanced
      "Flexible" = "#2ca02c"       # Green for flexible
    ),
    transport_modal = c(
      "Aéreo" = "#1f77b4",        # Blue for air
      "Rodoviário" = "#ff7f0e",   # Orange for road
      "Ferroviário" = "#2ca02c",  # Green for rail
      "Marítimo" = "#d62728",     # Red for maritime
      "Urbano" = "#9467bd"        # Purple for urban
    )
  ),
  
  # Statistical testing preferences
  statistics = list(
    confidence_level = 0.95,
    significance_level = 0.05,
    effect_size_threshold = 0.3,  # Medium effect size
    multiple_comparisons = "fdr", # False Discovery Rate correction
    test_type = "parametric",     # Default to parametric tests
    bayes_factor_threshold = 10   # Strong evidence threshold
  ),
  
  # Plot customization
  themes = list(
    academic = TRUE,              # Use academic-appropriate styling
    grid_lines = "major",         # Show major grid lines
    legend_position = "bottom",   # Legend at bottom
    strip_background = "white",   # Clean facet backgrounds
    axis_lines = TRUE            # Show axis lines
  )
)

# ============================================================================
# CORE STATISTICAL VISUALIZATION FUNCTIONS
# ============================================================================

#' Create Statistical Comparison Plot for Text Analysis Results
#' 
#' Generates publication-ready statistical comparison plots using ggstatsplot
#' with proper statistical tests, effect sizes, and academic formatting
#' 
#' @param data Data frame containing text analysis results
#' @param x_var Character, name of grouping variable (factor)
#' @param y_var Character, name of continuous outcome variable
#' @param plot_type Character, type of plot ("between_groups", "correlation", "distribution")
#' @param test_type Character, statistical test type ("parametric", "nonparametric", "robust")
#' @param multiple_comparisons Character, multiple comparison correction method
#' @param title Character, plot title (optional)
#' @param subtitle Character, plot subtitle (optional)
#' @param caption Character, plot caption (optional)
#' @param colors Named vector of colors for groups (optional)
#' 
#' @return ggplot object with statistical annotations
#' 
#' @examples
#' \dontrun{
#' # Load sentiment analysis results
#' sentiment_data <- data.frame(
#'   text_id = 1:100,
#'   sentiment_score = rnorm(100),
#'   document_type = rep(c("Lei", "Decreto", "Portaria"), length.out = 100),
#'   transport_modal = rep(c("Rodoviário", "Aéreo", "Urbano"), length.out = 100)
#' )
#' 
#' # Compare sentiment scores across document types
#' comparison_plot <- create_statistical_text_plot(
#'   data = sentiment_data,
#'   x_var = "document_type",
#'   y_var = "sentiment_score", 
#'   plot_type = "between_groups",
#'   title = "Sentiment Analysis by Document Type",
#'   subtitle = "Brazilian Legislative Documents (n = 100)"
#' )
#' 
#' print(comparison_plot)
#' }
#' 
#' @export
create_statistical_text_plot <- function(data,
                                        x_var,
                                        y_var, 
                                        plot_type = "between_groups",
                                        test_type = "parametric",
                                        multiple_comparisons = "fdr",
                                        title = NULL,
                                        subtitle = NULL, 
                                        caption = NULL,
                                        colors = NULL) {
  
  if (!is.data.frame(data)) {
    stop("Data must be a data frame")
  }
  
  if (!x_var %in% names(data) || !y_var %in% names(data)) {
    stop("Specified variables not found in data")
  }
  
  # Clean data - remove NA values
  data_clean <- data[!is.na(data[[x_var]]) & !is.na(data[[y_var]]), ]
  n_obs <- nrow(data_clean)
  
  if (n_obs < 10) {
    warning("Sample size is very small (n < 10). Results may not be reliable.")
  }
  
  cat("📊 Creating statistical plot:", plot_type, "\n")
  cat("📈 Sample size:", n_obs, "observations\n")
  
  # Set default colors based on variable type
  if (is.null(colors)) {
    unique_groups <- unique(data_clean[[x_var]])
    
    if (x_var %in% c("sentiment_category", "sentiment")) {
      colors <- .statistical_plot_config$colors$sentiment[unique_groups]
    } else if (x_var %in% c("regulatory_tone", "regulatory_sentiment")) {
      colors <- .statistical_plot_config$colors$regulatory[unique_groups]
    } else if (x_var %in% c("transport_modal", "modal")) {
      colors <- .statistical_plot_config$colors$transport_modal[unique_groups]
    } else {
      colors <- .statistical_plot_config$colors$primary[seq_along(unique_groups)]
      names(colors) <- unique_groups
    }
  }
  
  # Create plot based on type
  if (plot_type == "between_groups") {
    plot <- create_between_groups_plot(
      data = data_clean,
      x = x_var,
      y = y_var,
      test_type = test_type,
      multiple_comparisons = multiple_comparisons,
      colors = colors
    )
  } else if (plot_type == "correlation") {
    plot <- create_correlation_plot(
      data = data_clean,
      x = x_var,
      y = y_var,
      test_type = test_type,
      colors = colors
    )
  } else if (plot_type == "distribution") {
    plot <- create_distribution_plot(
      data = data_clean,
      x = x_var,
      y = y_var,
      colors = colors
    )
  } else {
    stop("Invalid plot_type. Use 'between_groups', 'correlation', or 'distribution'")
  }
  
  # Add academic formatting
  plot <- apply_academic_formatting(
    plot = plot,
    title = title,
    subtitle = subtitle,
    caption = caption
  )
  
  return(plot)
}

#' Create Between-Groups Statistical Comparison Plot
#' 
#' @param data Clean data frame
#' @param x Grouping variable name
#' @param y Outcome variable name
#' @param test_type Statistical test type
#' @param multiple_comparisons Multiple comparison method
#' @param colors Color scheme
#' @return ggplot object
create_between_groups_plot <- function(data, x, y, test_type, multiple_comparisons, colors) {
  
  if (ggstatsplot_loaded) {
    # Use ggstatsplot for advanced statistical testing
    plot <- ggstatsplot::ggbetweenstats(
      data = data,
      x = !!sym(x),
      y = !!sym(y),
      type = test_type,
      pairwise.comparisons = TRUE,
      pairwise.display = "significant",
      p.adjust.method = multiple_comparisons,
      centrality.plotting = TRUE,
      bf.prior = 0.707,
      results.subtitle = TRUE,
      xlab = str_to_title(str_replace_all(x, "_", " ")),
      ylab = str_to_title(str_replace_all(y, "_", " ")),
      ggtheme = theme_academic(),
      package = "viridis",
      palette = "D"
    )
    
    # Apply custom colors if provided
    if (!is.null(colors)) {
      plot <- plot + 
        scale_fill_manual(values = colors) +
        scale_color_manual(values = colors)
    }
    
  } else {
    # Fallback to standard ggplot2 with basic statistics
    plot <- create_fallback_between_groups(data, x, y, colors)
  }
  
  return(plot)
}

#' Create Correlation Plot with Statistical Testing
#' 
#' @param data Clean data frame
#' @param x X variable name
#' @param y Y variable name  
#' @param test_type Statistical test type
#' @param colors Color scheme
#' @return ggplot object
create_correlation_plot <- function(data, x, y, test_type, colors) {
  
  if (ggstatsplot_loaded) {
    plot <- ggstatsplot::ggscatterstats(
      data = data,
      x = !!sym(x),
      y = !!sym(y),
      type = test_type,
      conf.level = .statistical_plot_config$statistics$confidence_level,
      results.subtitle = TRUE,
      xlab = str_to_title(str_replace_all(x, "_", " ")),
      ylab = str_to_title(str_replace_all(y, "_", " ")),
      ggtheme = theme_academic()
    )
  } else {
    # Fallback correlation plot
    plot <- create_fallback_correlation(data, x, y, colors)
  }
  
  return(plot)
}

#' Create Distribution Plot
#' 
#' @param data Clean data frame
#' @param x Grouping variable name
#' @param y Outcome variable name
#' @param colors Color scheme
#' @return ggplot object
create_distribution_plot <- function(data, x, y, colors) {
  
  if (ggstatsplot_loaded) {
    plot <- ggstatsplot::gghistostats(
      data = data,
      x = !!sym(y),
      results.subtitle = TRUE,
      xlab = str_to_title(str_replace_all(y, "_", " ")),
      ggtheme = theme_academic()
    )
  } else {
    # Fallback distribution plot
    plot <- create_fallback_distribution(data, x, y, colors)
  }
  
  return(plot)
}

# ============================================================================
# FALLBACK PLOTS FOR WHEN GGSTATSPLOT IS NOT AVAILABLE
# ============================================================================

#' Fallback between-groups plot using standard ggplot2
create_fallback_between_groups <- function(data, x, y, colors) {
  
  # Calculate summary statistics
  summary_stats <- data %>%
    group_by(!!sym(x)) %>%
    summarise(
      mean = mean(!!sym(y), na.rm = TRUE),
      median = median(!!sym(y), na.rm = TRUE),
      sd = sd(!!sym(y), na.rm = TRUE),
      n = n(),
      se = sd / sqrt(n),
      .groups = "drop"
    )
  
  # Perform ANOVA
  anova_result <- tryCatch({
    aov(formula(paste(y, "~", x)), data = data)
  }, error = function(e) NULL)
  
  # Create plot
  plot <- ggplot(data, aes_string(x = x, y = y)) +
    geom_boxplot(aes_string(fill = x), alpha = 0.7, outlier.alpha = 0.5) +
    geom_point(position = position_jitter(width = 0.2), alpha = 0.3) +
    stat_summary(fun = mean, geom = "point", shape = 18, size = 3, color = "red") +
    theme_academic() +
    labs(
      x = str_to_title(str_replace_all(x, "_", " ")),
      y = str_to_title(str_replace_all(y, "_", " "))
    )
  
  # Add custom colors
  if (!is.null(colors)) {
    plot <- plot + 
      scale_fill_manual(values = colors) +
      guides(fill = guide_legend(title = str_to_title(str_replace_all(x, "_", " "))))
  }
  
  # Add statistical annotation if ANOVA was successful
  if (!is.null(anova_result)) {
    anova_summary <- summary(anova_result)
    f_stat <- anova_summary[[1]]$`F value`[1]
    p_val <- anova_summary[[1]]$`Pr(>F)`[1]
    
    if (!is.na(p_val)) {
      sig_label <- if (p_val < 0.001) "p < 0.001" else paste("p =", round(p_val, 3))
      plot <- plot +
        labs(subtitle = paste("ANOVA: F =", round(f_stat, 2), ",", sig_label))
    }
  }
  
  return(plot)
}

#' Fallback correlation plot using standard ggplot2
create_fallback_correlation <- function(data, x, y, colors) {
  
  # Calculate correlation
  cor_result <- tryCatch({
    cor.test(data[[x]], data[[y]], method = "pearson")
  }, error = function(e) NULL)
  
  plot <- ggplot(data, aes_string(x = x, y = y)) +
    geom_point(alpha = 0.6) +
    geom_smooth(method = "lm", se = TRUE, color = "blue") +
    theme_academic() +
    labs(
      x = str_to_title(str_replace_all(x, "_", " ")),
      y = str_to_title(str_replace_all(y, "_", " "))
    )
  
  # Add correlation annotation
  if (!is.null(cor_result)) {
    r_val <- cor_result$estimate
    p_val <- cor_result$p.value
    
    if (!is.na(r_val) && !is.na(p_val)) {
      sig_label <- if (p_val < 0.001) "p < 0.001" else paste("p =", round(p_val, 3))
      plot <- plot +
        labs(subtitle = paste("Pearson r =", round(r_val, 3), ",", sig_label))
    }
  }
  
  return(plot)
}

#' Fallback distribution plot using standard ggplot2
create_fallback_distribution <- function(data, x, y, colors) {
  
  plot <- ggplot(data, aes_string(x = y)) +
    geom_histogram(bins = 30, alpha = 0.7, fill = "steelblue") +
    geom_density(aes(y = ..density.. * max(..count..)), alpha = 0.3, fill = "red") +
    theme_academic() +
    labs(
      x = str_to_title(str_replace_all(y, "_", " ")),
      y = "Frequency"
    )
  
  return(plot)
}

# ============================================================================
# ACADEMIC THEME AND FORMATTING
# ============================================================================

#' Academic publication theme for ggplot2
#' 
#' @return ggplot2 theme object
theme_academic <- function() {
  
  theme_minimal(base_size = .statistical_plot_config$publication$base_size) +
    theme(
      # Text elements
      plot.title = element_text(
        size = .statistical_plot_config$publication$title_size,
        face = "bold",
        hjust = 0.5,
        margin = margin(b = 10)
      ),
      plot.subtitle = element_text(
        size = .statistical_plot_config$publication$base_size,
        hjust = 0.5,
        margin = margin(b = 15)
      ),
      plot.caption = element_text(
        size = .statistical_plot_config$publication$caption_size,
        hjust = 0,
        margin = margin(t = 10)
      ),
      
      # Axis elements
      axis.title = element_text(size = .statistical_plot_config$publication$base_size),
      axis.text = element_text(size = .statistical_plot_config$publication$axis_text_size),
      axis.line = element_line(color = "black", size = 0.5),
      
      # Legend
      legend.position = .statistical_plot_config$themes$legend_position,
      legend.title = element_text(size = .statistical_plot_config$publication$base_size),
      legend.text = element_text(size = .statistical_plot_config$publication$axis_text_size),
      
      # Grid
      panel.grid.major = element_line(color = "grey90", size = 0.25),
      panel.grid.minor = element_blank(),
      
      # Facets
      strip.background = element_rect(fill = "white", color = "black"),
      strip.text = element_text(size = .statistical_plot_config$publication$base_size),
      
      # Background
      plot.background = element_rect(fill = "white", color = NA),
      panel.background = element_rect(fill = "white", color = NA)
    )
}

#' Apply academic formatting to plots
#' 
#' @param plot ggplot object
#' @param title Plot title
#' @param subtitle Plot subtitle
#' @param caption Plot caption
#' @return Formatted ggplot object
apply_academic_formatting <- function(plot, title = NULL, subtitle = NULL, caption = NULL) {
  
  if (!is.null(title)) {
    plot <- plot + labs(title = title)
  }
  
  if (!is.null(subtitle)) {
    plot <- plot + labs(subtitle = subtitle)
  }
  
  if (!is.null(caption)) {
    plot <- plot + labs(caption = caption)
  }
  
  # Ensure academic theme is applied
  plot <- plot + theme_academic()
  
  return(plot)
}

# ============================================================================
# SPECIALIZED NLP VISUALIZATION FUNCTIONS
# ============================================================================

#' Create Sentiment Analysis Summary Plot
#' 
#' Specialized visualization for sentiment analysis results with statistical testing
#' 
#' @param sentiment_results Data frame from analyze_portuguese_sentiment()
#' @param group_var Character, variable to group by (optional)
#' @param title Plot title
#' @return ggplot object
create_sentiment_summary_plot <- function(sentiment_results, group_var = NULL, title = NULL) {
  
  if (!"sentiment_category" %in% names(sentiment_results)) {
    stop("sentiment_results must contain 'sentiment_category' column")
  }
  
  if (is.null(title)) {
    title <- "Portuguese Sentiment Analysis Results"
  }
  
  if (is.null(group_var)) {
    # Simple distribution plot
    plot <- ggplot(sentiment_results, aes(x = sentiment_category, fill = sentiment_category)) +
      geom_bar(alpha = 0.8) +
      geom_text(stat = "count", aes(label = ..count..), vjust = -0.5) +
      scale_fill_manual(values = .statistical_plot_config$colors$sentiment) +
      theme_academic() +
      labs(
        title = title,
        x = "Sentiment Category",
        y = "Number of Documents",
        fill = "Sentiment"
      )
  } else {
    # Grouped comparison
    if (!group_var %in% names(sentiment_results)) {
      stop("Grouping variable not found in data")
    }
    
    plot <- create_statistical_text_plot(
      data = sentiment_results,
      x_var = group_var,
      y_var = "sentiment_score",
      plot_type = "between_groups",
      title = title,
      colors = .statistical_plot_config$colors$sentiment
    )
  }
  
  return(plot)
}

#' Create Performance Benchmark Visualization
#' 
#' @param benchmark_results Results from benchmark_portuguese_sentiment()
#' @param title Plot title
#' @return ggplot object
create_performance_plot <- function(benchmark_results, title = "Portuguese NLP Performance Benchmark") {
  
  if (!"microbenchmark" %in% class(benchmark_results$benchmark_results)) {
    # Simple performance summary
    performance_data <- data.frame(
      metric = c("Avg Time per Doc (ms)", "Performance Target"),
      value = c(benchmark_results$avg_time_per_document_ms, 100),
      type = c("Actual", "Target")
    )
    
    plot <- ggplot(performance_data, aes(x = metric, y = value, fill = type)) +
      geom_col(position = "dodge", alpha = 0.8) +
      geom_hline(yintercept = 100, linetype = "dashed", color = "red", size = 1) +
      scale_fill_manual(values = c("Actual" = "steelblue", "Target" = "red")) +
      theme_academic() +
      labs(
        title = title,
        x = "",
        y = "Time (milliseconds)",
        fill = "Measure"
      )
    
  } else {
    # Detailed microbenchmark results
    if ("ggstatsplot" %in% available_viz_packages) {
      plot <- ggstatsplot::gghistostats(
        data = as.data.frame(benchmark_results$benchmark_results),
        x = time,
        results.subtitle = TRUE,
        title = title,
        xlab = "Processing Time (nanoseconds)",
        ggtheme = theme_academic()
      )
    } else {
      # Fallback histogram
      plot <- ggplot(as.data.frame(benchmark_results$benchmark_results), aes(x = time/1e6)) +
        geom_histogram(bins = 30, alpha = 0.7, fill = "steelblue") +
        geom_vline(xintercept = 100, linetype = "dashed", color = "red", size = 1) +
        theme_academic() +
        labs(
          title = title,
          x = "Processing Time (milliseconds)",
          y = "Frequency"
        )
    }
  }
  
  return(plot)
}

# ============================================================================
# PLOT EXPORT AND PUBLISHING FUNCTIONS
# ============================================================================

#' Export plot for academic publication
#' 
#' @param plot ggplot object to export
#' @param filename Character, output filename (without extension)
#' @param format Character, output format ("png", "pdf", "svg")
#' @param width Numeric, plot width in inches
#' @param height Numeric, plot height in inches
#' @param dpi Numeric, resolution for raster formats
#' @return Invisible, saves file to disk
export_academic_plot <- function(plot,
                                filename,
                                format = "png",
                                width = NULL,
                                height = NULL,
                                dpi = NULL) {
  
  # Use defaults from configuration
  if (is.null(width)) width <- .statistical_plot_config$publication$width_inches
  if (is.null(height)) height <- .statistical_plot_config$publication$height_inches
  if (is.null(dpi)) dpi <- .statistical_plot_config$publication$dpi
  
  # Create full filename
  full_filename <- paste0(filename, ".", format)
  
  # Export based on format
  if (format == "png") {
    ggsave(
      filename = full_filename,
      plot = plot,
      width = width,
      height = height,
      dpi = dpi,
      bg = "white"
    )
  } else if (format == "pdf") {
    ggsave(
      filename = full_filename,
      plot = plot,
      width = width,
      height = height,
      device = "pdf"
    )
  } else if (format == "svg") {
    ggsave(
      filename = full_filename,
      plot = plot,
      width = width,
      height = height,
      device = "svg"
    )
  } else {
    stop("Unsupported format. Use 'png', 'pdf', or 'svg'")
  }
  
  cat("📊 Plot exported:", full_filename, "\n")
  cat("📐 Dimensions:", width, "x", height, "inches\n")
  if (format == "png") cat("🎯 Resolution:", dpi, "DPI\n")
}

# ============================================================================
# COMPREHENSIVE NLP VISUALIZATION DASHBOARD
# ============================================================================

#' Create comprehensive NLP analysis dashboard
#' 
#' @param sentiment_data Data frame with sentiment analysis results
#' @param group_vars Character vector of grouping variables
#' @param title Dashboard title
#' @return Combined plot object (requires patchwork package)
create_nlp_dashboard <- function(sentiment_data, 
                                group_vars = NULL,
                                title = "Portuguese NLP Analysis Dashboard") {
  
  if (!"patchwork" %in% available_viz_packages) {
    warning("patchwork package not available. Returning individual plots as list.")
    
    plots <- list()
    plots$sentiment_distribution <- create_sentiment_summary_plot(sentiment_data, title = "Sentiment Distribution")
    
    if (!is.null(group_vars)) {
      for (var in group_vars) {
        if (var %in% names(sentiment_data)) {
          plots[[paste0("sentiment_by_", var)]] <- create_sentiment_summary_plot(
            sentiment_data, 
            group_var = var,
            title = paste("Sentiment by", str_to_title(str_replace_all(var, "_", " ")))
          )
        }
      }
    }
    
    return(plots)
  }
  
  # Create individual plots
  p1 <- create_sentiment_summary_plot(sentiment_data, title = "Overall Distribution")
  
  plots_list <- list(p1)
  
  if (!is.null(group_vars) && length(group_vars) > 0) {
    for (i in seq_along(group_vars)) {
      if (group_vars[i] %in% names(sentiment_data)) {
        pi <- create_sentiment_summary_plot(
          sentiment_data,
          group_var = group_vars[i],
          title = paste("By", str_to_title(str_replace_all(group_vars[i], "_", " ")))
        )
        plots_list[[length(plots_list) + 1]] <- pi
      }
    }
  }
  
  # Combine plots using patchwork
  if (length(plots_list) == 1) {
    combined_plot <- plots_list[[1]]
  } else if (length(plots_list) == 2) {
    combined_plot <- plots_list[[1]] + plots_list[[2]]
  } else if (length(plots_list) == 3) {
    combined_plot <- plots_list[[1]] / (plots_list[[2]] + plots_list[[3]])
  } else {
    # For more plots, arrange in grid
    combined_plot <- wrap_plots(plots_list, ncol = 2)
  }
  
  # Add overall title
  combined_plot <- combined_plot + 
    plot_annotation(
      title = title,
      theme = theme(plot.title = element_text(size = 16, hjust = 0.5, face = "bold"))
    )
  
  return(combined_plot)
}

# ============================================================================
# INITIALIZATION AND EXPORT
# ============================================================================

cat("✅ Statistical Text Visualization (ggstatsplot Integration) loaded successfully\n")
cat("📊 Features:", ifelse(ggstatsplot_loaded, "Full ggstatsplot", "Fallback ggplot2"), "statistical plots\n")
cat("🎨 Color schemes: Sentiment, Regulatory, Transport modal\n")
cat("📐 Publication standards: 300 DPI, academic formatting\n")
cat("📈 Statistical tests: Parametric, non-parametric, Bayesian\n")

if (length(missing_viz_packages) > 0) {
  cat("⚠️ Missing packages:", paste(missing_viz_packages, collapse = ", "), "\n")
  cat("📦 Install with: install.packages(c(", paste0("'", missing_viz_packages, "'", collapse = ", "), "))\n")
}

# Export functions to global environment
.GlobalEnv$create_statistical_text_plot <- create_statistical_text_plot
.GlobalEnv$create_sentiment_summary_plot <- create_sentiment_summary_plot
.GlobalEnv$create_performance_plot <- create_performance_plot
.GlobalEnv$export_academic_plot <- export_academic_plot
.GlobalEnv$create_nlp_dashboard <- create_nlp_dashboard
.GlobalEnv$theme_academic <- theme_academic

cat("\n📊 Ready for publication-ready statistical text visualizations!\n")