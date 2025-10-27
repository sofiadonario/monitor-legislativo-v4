# Academic Visualizations Module - Monitor Legislativo v4
# Publication-Quality Visualizations for Brazilian Legislative Research
# =====================================================================

#' @title Academic-Quality Visualizations for Legislative Research
#' @description Comprehensive visualization suite with publication standards
#' following academic research methodology and Brazilian legal document analysis
#' @author Monitor Legislativo v4 Team
#' @date 2025-09-08

# Required libraries for academic visualizations
suppressPackageStartupMessages({
  library(ggplot2)
  library(plotly)
  library(viridis)
  library(RColorBrewer)
  library(scales)
  library(gridExtra)
  library(cowplot)
  library(patchwork)
  library(gganimate)
  library(corrplot)
  library(pheatmap)
  library(ggrepel)
  library(ggridges)
  library(ggbeeswarm)
  library(treemapify)
  library(networkD3)
  library(visNetwork)
  library(leaflet)
  library(sf)
  library(tmap)
  library(DT)
  library(knitr)
  library(kableExtra)
  library(formattable)
  library(gt)
})

#' Academic Theme for ggplot2
#' 
#' Creates publication-ready theme following academic standards
#' with customizable elements for Brazilian research context
#' 
#' @param base_size Base font size
#' @param base_family Font family
#' @param grid Include grid lines
#' @param border Add plot border
#' @return ggplot2 theme object
#' @export
theme_academic <- function(base_size = 12, 
                          base_family = "Arial",
                          grid = TRUE,
                          border = FALSE) {
  
  theme_minimal(base_size = base_size, base_family = base_family) +
    theme(
      # Text elements
      plot.title = element_text(
        size = base_size + 2,
        face = "bold",
        hjust = 0.5,
        margin = margin(b = 20)
      ),
      plot.subtitle = element_text(
        size = base_size,
        hjust = 0.5,
        color = "gray30",
        margin = margin(b = 15)
      ),
      plot.caption = element_text(
        size = base_size - 2,
        color = "gray50",
        hjust = 1,
        margin = margin(t = 15)
      ),
      
      # Axis elements
      axis.title = element_text(
        size = base_size,
        face = "bold",
        color = "black"
      ),
      axis.text = element_text(
        size = base_size - 1,
        color = "black"
      ),
      
      # Legend elements
      legend.title = element_text(
        size = base_size,
        face = "bold"
      ),
      legend.text = element_text(
        size = base_size - 1
      ),
      legend.position = "bottom",
      legend.box = "horizontal",
      
      # Panel elements
      panel.background = element_rect(fill = "white", color = NA),
      plot.background = element_rect(fill = "white", color = NA),
      
      # Grid elements
      panel.grid.major = if (grid) element_line(color = "gray90", size = 0.3) else element_blank(),
      panel.grid.minor = element_blank(),
      
      # Strip text (for facets)
      strip.text = element_text(
        size = base_size - 1,
        face = "bold",
        color = "black"
      ),
      strip.background = element_rect(
        fill = "gray95",
        color = "gray80"
      ),
      
      # Add border if requested
      panel.border = if (border) element_rect(color = "black", fill = NA, size = 0.5) else element_blank(),
      
      # Margins
      plot.margin = margin(20, 20, 20, 20)
    )
}

#' Academic Color Palettes
#' 
#' Defines color palettes suitable for academic publications
#' including colorblind-friendly and print-safe options
#' 
#' @param palette Palette name
#' @param n Number of colors
#' @param type Type of palette ("qualitative", "sequential", "diverging")
#' @return Vector of hex colors
#' @export
academic_colors <- function(palette = "default", n = 6, type = "qualitative") {
  
  palettes <- list(
    # Qualitative palettes (for categories)
    default = c("#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2", "#7f7f7f"),
    colorblind = c("#0173b2", "#de8f05", "#029e73", "#d55e00", "#cc78bc", "#ca9161", "#fbafe4", "#949494"),
    nature = c("#0072B2", "#E69F00", "#009E73", "#F0E442", "#CC79A7", "#56B4E9", "#D55E00", "#999999"),
    academic_blue = c("#003f7f", "#1e5aa8", "#4575b4", "#74add1", "#abd9e9", "#e0f3f8"),
    government = c("#1034a6", "#b31942", "#00843d", "#ffa500", "#800080", "#008b8b"),
    
    # Sequential palettes (for continuous data)
    blues = brewer.pal(min(n, 9), "Blues"),
    viridis = viridis(n),
    plasma = viridis(n, option = "plasma"),
    
    # Diverging palettes (for positive/negative data)
    red_blue = brewer.pal(min(n, 11), "RdBu"),
    spectral = brewer.pal(min(n, 11), "Spectral")
  )
  
  if (!palette %in% names(palettes)) {
    warning("Palette not found, using default")
    palette <- "default"
  }
  
  colors <- palettes[[palette]]
  
  # Extend or truncate as needed
  if (length(colors) < n) {
    colors <- rep(colors, ceiling(n / length(colors)))[1:n]
  } else if (length(colors) > n) {
    colors <- colors[1:n]
  }
  
  return(colors)
}

#' Create Legislative Activity Timeline
#' 
#' Generates publication-ready timeline visualization of legislative activity
#' with academic annotations and statistical overlays
#' 
#' @param temporal_data Data with date and count columns
#' @param title Plot title
#' @param highlight_events Optional data frame of events to highlight
#' @param trend_line Add trend line with confidence interval
#' @param academic_style Use academic formatting
#' @return ggplot object
#' @export
create_legislative_timeline <- function(temporal_data,
                                       title = "Legislative Activity Over Time",
                                       highlight_events = NULL,
                                       trend_line = TRUE,
                                       academic_style = TRUE) {
  
  # Ensure date column is Date type
  if (!"date" %in% names(temporal_data)) {
    stop("Data must contain 'date' column")
  }
  
  if (!"count" %in% names(temporal_data)) {
    stop("Data must contain 'count' column")
  }
  
  temporal_data$date <- as.Date(temporal_data$date)
  
  # Create base plot
  p <- ggplot(temporal_data, aes(x = date, y = count)) +
    geom_line(color = academic_colors("academic_blue")[3], size = 0.8, alpha = 0.8) +
    geom_point(color = academic_colors("academic_blue")[4], size = 1.2, alpha = 0.7)
  
  # Add trend line if requested
  if (trend_line) {
    p <- p + 
      geom_smooth(method = "loess", se = TRUE, color = academic_colors("default")[1], 
                 fill = academic_colors("academic_blue")[6], alpha = 0.3, size = 1.2)
  }
  
  # Add event highlights
  if (!isTRUE(is.null(highlight_events)) && "date" %in% names(highlight_events)) {
    p <- p +
      geom_vline(data = highlight_events, aes(xintercept = as.numeric(date)),
                 color = academic_colors("default")[4], linetype = "dashed", alpha = 0.7) +
      geom_text_repel(data = highlight_events, 
                      aes(x = date, y = max(temporal_data$count) * 0.9, label = label),
                      angle = 90, size = 3, hjust = 0, color = academic_colors("default")[4])
  }
  
  # Apply academic styling
  if (academic_style) {
    p <- p +
      theme_academic() +
      labs(
        title = title,
        subtitle = paste0("Brazilian Legislative Documents (", 
                         format(min(temporal_data$date), "%Y"), "-", 
                         format(max(temporal_data$date), "%Y"), ")"),
        x = "Date",
        y = "Number of Documents",
        caption = paste("Generated:", Sys.Date(), "| Monitor Legislativo v4 | Academic Research Framework")
      ) +
      scale_x_date(labels = date_format("%Y"), 
                   breaks = date_breaks("2 years"),
                   expand = expansion(mult = c(0.02, 0.02))) +
      scale_y_continuous(labels = comma_format(),
                        expand = expansion(mult = c(0, 0.05)))
  }
  
  return(p)
}

#' Create Academic Correlation Matrix Heatmap
#' 
#' Generates publication-ready correlation matrix with significance testing
#' and academic annotations for legislative data analysis
#' 
#' @param data Numeric data frame for correlation
#' @param method Correlation method ("pearson", "spearman", "kendall")
#' @param significance_test Include significance stars
#' @param academic_style Use academic formatting
#' @return ggplot object or corrplot
#' @export
create_correlation_heatmap <- function(data,
                                      method = "pearson", 
                                      significance_test = TRUE,
                                      academic_style = TRUE) {
  
  # Calculate correlation matrix
  cor_matrix <- cor(data, method = method, use = "complete.obs")
  
  # Calculate p-values if requested
  if (significance_test) {
    p_values <- cor_test_matrix(data, method = method)
  }
  
  # Convert to long format for ggplot
  cor_long <- expand.grid(Var1 = rownames(cor_matrix), Var2 = colnames(cor_matrix)) %>%
    mutate(
      correlation = as.vector(cor_matrix),
      abs_correlation = abs(correlation)
    )
  
  # Add significance stars
  if (significance_test && exists("p_values")) {
    cor_long$p_value <- as.vector(p_values)
    cor_long$significance <- case_when(
      cor_long$p_value < 0.001 ~ "***",
      cor_long$p_value < 0.01 ~ "**",
      cor_long$p_value < 0.05 ~ "*",
      TRUE ~ ""
    )
  }
  
  # Create heatmap
  p <- ggplot(cor_long, aes(x = Var1, y = Var2, fill = correlation)) +
    geom_tile(color = "white", size = 0.5) +
    scale_fill_gradient2(
      low = academic_colors("red_blue")[1],
      mid = "white",
      high = academic_colors("red_blue")[11],
      midpoint = 0,
      limit = c(-1, 1),
      name = paste0(stringr::str_to_title(method), "\nCorrelation")
    ) +
    geom_text(aes(label = paste0(round(correlation, 2), 
                                if (significance_test && exists("significance")) significance else "")),
              color = "black", size = 3) +
    coord_fixed() +
    theme_academic() +
    theme(
      axis.text.x = element_text(angle = 45, hjust = 1),
      axis.title = element_blank(),
      legend.position = "right",
      panel.grid = element_blank()
    ) +
    labs(
      title = "Correlation Matrix of Legislative Variables",
      subtitle = paste("Method:", stringr::str_to_title(method), 
                      if (significance_test) "| * p<0.05, ** p<0.01, *** p<0.001" else ""),
      caption = paste("Generated:", Sys.Date(), "| Monitor Legislativo v4")
    )
  
  return(p)
}

# Helper function for correlation p-values
cor_test_matrix <- function(data, method = "pearson") {
  n <- ncol(data)
  p_matrix <- matrix(NA, n, n)
  
  for (i in 1:n) {
    for (j in 1:n) {
      if (i != j) {
        test_result <- tryCatch({
          cor.test(data[, i], data[, j], method = method)
        }, error = function(e) list(p.value = NA))
        
        p_matrix[i, j] <- test_result$p.value
      } else {
        p_matrix[i, j] <- 0  # Diagonal
      }
    }
  }
  
  return(p_matrix)
}

#' Create Academic Bar Chart with Statistical Annotations
#' 
#' Generates publication-ready bar chart with confidence intervals,
#' significance testing, and academic formatting
#' 
#' @param data Data frame with categorical and numeric variables
#' @param x_var Categorical variable name
#' @param y_var Numeric variable name
#' @param fill_var Optional fill variable
#' @param error_bars Add error bars (confidence intervals)
#' @param significance_test Add significance testing annotations
#' @param academic_style Use academic formatting
#' @return ggplot object
#' @export
create_academic_barplot <- function(data,
                                   x_var,
                                   y_var,
                                   fill_var = NULL,
                                   error_bars = TRUE,
                                   significance_test = TRUE,
                                   academic_style = TRUE) {
  
  # Calculate summary statistics
  if (is.null(fill_var)) {
    summary_data <- data %>%
      group_by(.data[[x_var]]) %>%
      summarise(
        mean = mean(.data[[y_var]], na.rm = TRUE),
        sd = sd(.data[[y_var]], na.rm = TRUE),
        n = n(),
        se = sd / sqrt(n),
        ci_lower = mean - 1.96 * se,
        ci_upper = mean + 1.96 * se,
        .groups = "drop"
      )
  } else {
    summary_data <- data %>%
      group_by(.data[[x_var]], .data[[fill_var]]) %>%
      summarise(
        mean = mean(.data[[y_var]], na.rm = TRUE),
        sd = sd(.data[[y_var]], na.rm = TRUE),
        n = n(),
        se = sd / sqrt(n),
        ci_lower = mean - 1.96 * se,
        ci_upper = mean + 1.96 * se,
        .groups = "drop"
      )
  }
  
  # Create base plot
  if (is.null(fill_var)) {
    p <- ggplot(summary_data, aes(x = .data[[x_var]], y = mean)) +
      geom_col(fill = academic_colors("academic_blue")[3], alpha = 0.8, color = "white")
  } else {
    p <- ggplot(summary_data, aes(x = .data[[x_var]], y = mean, fill = .data[[fill_var]])) +
      geom_col(position = "dodge", alpha = 0.8, color = "white") +
      scale_fill_manual(values = academic_colors("default", n = length(unique(summary_data[[fill_var]]))))
  }
  
  # Add error bars
  if (error_bars) {
    if (is.null(fill_var)) {
      p <- p + 
        geom_errorbar(aes(ymin = ci_lower, ymax = ci_upper), 
                     width = 0.2, color = "black", size = 0.6)
    } else {
      p <- p +
        geom_errorbar(aes(ymin = ci_lower, ymax = ci_upper), 
                     position = position_dodge(width = 0.9),
                     width = 0.2, color = "black", size = 0.6)
    }
  }
  
  # Add significance testing
  if (significance_test && length(unique(data[[x_var]])) >= 2) {
    
    # Perform ANOVA or t-test
    if (length(unique(data[[x_var]])) == 2) {
      stat_test <- t.test(data[[y_var]] ~ data[[x_var]])
      p_value <- stat_test$p.value
      test_name <- "t-test"
    } else {
      stat_test <- aov(data[[y_var]] ~ data[[x_var]], data = data)
      p_value <- summary(stat_test)[[1]][1, "Pr(>F)"]
      test_name <- "ANOVA"
    }
    
    # Add p-value annotation
    significance_label <- case_when(
      p_value < 0.001 ~ paste0(test_name, ": p < 0.001***"),
      p_value < 0.01 ~ paste0(test_name, ": p < 0.01**"),
      p_value < 0.05 ~ paste0(test_name, ": p < 0.05*"),
      TRUE ~ paste0(test_name, ": p = ", round(p_value, 3), " (ns)")
    )
    
    p <- p +
      annotate("text", x = Inf, y = Inf, label = significance_label,
               hjust = 1.1, vjust = 1.5, size = 3, color = "black",
               fontface = "italic")
  }
  
  # Add value labels on bars
  p <- p +
    geom_text(aes(label = round(mean, 1)), 
             vjust = -0.5, size = 3, color = "black")
  
  # Apply academic styling
  if (academic_style) {
    p <- p +
      theme_academic() +
      labs(
        title = paste("Comparison of", stringr::str_to_title(gsub("_", " ", y_var)), 
                     "by", stringr::str_to_title(gsub("_", " ", x_var))),
        x = stringr::str_to_title(gsub("_", " ", x_var)),
        y = paste(stringr::str_to_title(gsub("_", " ", y_var)), 
                 if (error_bars) "(Mean ± 95% CI)" else "(Mean)"),
        caption = paste("Generated:", Sys.Date(), "| Monitor Legislativo v4 | Academic Research Framework")
      ) +
      scale_y_continuous(expand = expansion(mult = c(0, 0.1)))
  }
  
  return(p)
}

#' Create Interactive Academic Scatter Plot
#' 
#' Generates interactive scatter plot with regression lines,
#' confidence bands, and statistical annotations
#' 
#' @param data Data frame with numeric variables
#' @param x_var X-axis variable name
#' @param y_var Y-axis variable name
#' @param color_var Optional color variable
#' @param size_var Optional size variable
#' @param regression_line Add regression line
#' @param interactive Create interactive version with plotly
#' @return ggplot or plotly object
#' @export
create_academic_scatterplot <- function(data,
                                       x_var,
                                       y_var,
                                       color_var = NULL,
                                       size_var = NULL,
                                       regression_line = TRUE,
                                       interactive = TRUE) {
  
  # Create base plot
  p <- ggplot(data, aes(x = .data[[x_var]], y = .data[[y_var]]))
  
  # Add points with optional aesthetics
  if (!isTRUE(is.null(color_var)) && !is.null(size_var)) {
    p <- p + geom_point(aes(color = .data[[color_var]], size = .data[[size_var]]), alpha = 0.7)
  } else if (!is.null(color_var)) {
    p <- p + geom_point(aes(color = .data[[color_var]]), size = 2, alpha = 0.7)
  } else if (!is.null(size_var)) {
    p <- p + geom_point(aes(size = .data[[size_var]]), color = academic_colors("academic_blue")[3], alpha = 0.7)
  } else {
    p <- p + geom_point(size = 2, color = academic_colors("academic_blue")[3], alpha = 0.7)
  }
  
  # Add regression line
  if (regression_line) {
    
    # Calculate correlation
    correlation <- cor(data[[x_var]], data[[y_var]], use = "complete.obs")
    cor_test <- cor.test(data[[x_var]], data[[y_var]])
    
    # Add regression line with confidence band
    p <- p +
      geom_smooth(method = "lm", se = TRUE, 
                 color = academic_colors("default")[1], 
                 fill = academic_colors("academic_blue")[6], 
                 alpha = 0.3) +
      annotate("text", x = Inf, y = -Inf, 
               label = paste0("r = ", round(correlation, 3), 
                            ", p = ", round(cor_test$p.value, 4)),
               hjust = 1.1, vjust = -0.5, size = 3.5, 
               fontface = "italic", color = "black")
  }
  
  # Apply academic styling
  p <- p +
    theme_academic() +
    labs(
      title = paste("Relationship between", 
                   stringr::str_to_title(gsub("_", " ", x_var)), "and",
                   stringr::str_to_title(gsub("_", " ", y_var))),
      x = stringr::str_to_title(gsub("_", " ", x_var)),
      y = stringr::str_to_title(gsub("_", " ", y_var)),
      caption = paste("Generated:", Sys.Date(), "| Monitor Legislativo v4")
    )
  
  # Add color scale if applicable
  if (!is.null(color_var)) {
    if (is.numeric(data[[color_var]])) {
      p <- p + scale_color_viridis_c(name = stringr::str_to_title(gsub("_", " ", color_var)))
    } else {
      n_colors <- length(unique(data[[color_var]]))
      p <- p + scale_color_manual(values = academic_colors("default", n = n_colors),
                                 name = stringr::str_to_title(gsub("_", " ", color_var)))
    }
  }
  
  # Make interactive if requested
  if (interactive) {
    p <- ggplotly(p, tooltip = c("x", "y", if (!is.null(color_var)) "colour", if (!is.null(size_var)) "size")) %>%
      layout(
        title = list(
          text = paste("Relationship between", 
                      stringr::str_to_title(gsub("_", " ", x_var)), "and",
                      stringr::str_to_title(gsub("_", " ", y_var))),
          font = list(size = 16)
        )
      )
  }
  
  return(p)
}

#' Create Academic Summary Table
#' 
#' Generates publication-ready summary statistics table
#' with proper formatting and academic standards
#' 
#' @param data Data frame for summarization
#' @param group_var Optional grouping variable
#' @param numeric_vars Numeric variables to summarize
#' @param format Output format ("gt", "kable", "datatable")
#' @return Formatted table object
#' @export
create_academic_table <- function(data,
                                 group_var = NULL,
                                 numeric_vars = NULL,
                                 format = "gt") {
  
  # Select numeric variables if not specified
  if (is.null(numeric_vars)) {
    numeric_vars <- names(data)[sapply(data, is.numeric)]
  }
  
  # Create summary statistics
  if (is.null(group_var)) {
    summary_stats <- data %>%
      select(all_of(numeric_vars)) %>%
      summarise(across(everything(), list(
        n = ~sum(!is.na(.)),
        mean = ~mean(., na.rm = TRUE),
        sd = ~sd(., na.rm = TRUE),
        median = ~median(., na.rm = TRUE),
        min = ~min(., na.rm = TRUE),
        max = ~max(., na.rm = TRUE)
      ))) %>%
      pivot_longer(everything(), names_to = c("variable", "statistic"), names_sep = "_") %>%
      pivot_wider(names_from = statistic, values_from = value)
  } else {
    summary_stats <- data %>%
      group_by(.data[[group_var]]) %>%
      select(all_of(c(group_var, numeric_vars))) %>%
      summarise(across(all_of(numeric_vars), list(
        n = ~sum(!is.na(.)),
        mean = ~mean(., na.rm = TRUE),
        sd = ~sd(., na.rm = TRUE),
        median = ~median(., na.rm = TRUE)
      )), .groups = "drop") %>%
      pivot_longer(-all_of(group_var), names_to = c("variable", "statistic"), names_sep = "_") %>%
      pivot_wider(names_from = statistic, values_from = value)
  }
  
  # Format table based on requested format
  if (format == "gt") {
    
    formatted_table <- summary_stats %>%
      gt() %>%
      tab_header(
        title = "Summary Statistics",
        subtitle = "Descriptive Statistics for Legislative Variables"
      ) %>%
      fmt_number(
        columns = c(mean, sd, median, min, max),
        decimals = 2
      ) %>%
      fmt_number(
        columns = n,
        decimals = 0
      ) %>%
      cols_label(
        variable = "Variable",
        n = "N",
        mean = "Mean",
        sd = "SD",
        median = "Median",
        min = "Min",
        max = "Max"
      ) %>%
      tab_source_note(
        source_note = paste("Generated:", Sys.Date(), "| Monitor Legislativo v4")
      ) %>%
      tab_style(
        style = cell_text(weight = "bold"),
        locations = cells_column_labels()
      ) %>%
      tab_options(
        heading.title.font.size = px(16),
        heading.subtitle.font.size = px(14),
        table.font.size = px(12)
      )
    
  } else if (format == "kable") {
    
    formatted_table <- summary_stats %>%
      kable(
        caption = "Summary Statistics for Legislative Variables",
        digits = 2,
        col.names = c(
          if (!is.null(group_var)) stringr::str_to_title(gsub("_", " ", group_var)),
          "Variable", "N", "Mean", "SD", "Median", "Min", "Max"
        )
      ) %>%
      kable_styling(
        bootstrap_options = c("striped", "hover", "condensed"),
        full_width = FALSE,
        position = "center"
      ) %>%
      add_header_above(c(" " = if (is.null(group_var)) 1 else 2, "Descriptive Statistics" = 5))
    
  } else if (format == "datatable") {
    
    formatted_table <- datatable(
      summary_stats,
      caption = "Summary Statistics for Legislative Variables",
      options = list(
        pageLength = 15,
        scrollX = TRUE,
        dom = 'Bfrtip',
        buttons = c('copy', 'csv', 'excel', 'pdf', 'print')
      ),
      rownames = FALSE
    ) %>%
      formatRound(
        columns = c("mean", "sd", "median", "min", "max"),
        digits = 2
      ) %>%
      formatStyle(
        columns = colnames(summary_stats),
        backgroundColor = "white",
        border = "1px solid #ddd"
      )
  }
  
  return(formatted_table)
}

#' Generate Academic Figure Caption
#' 
#' Creates standardized figure captions following academic conventions
#' 
#' @param figure_number Figure number
#' @param title Figure title
#' @param description Detailed description
#' @param data_source Data source information
#' @param methodology Methodology notes
#' @return Formatted caption string
#' @export
generate_figure_caption <- function(figure_number,
                                   title,
                                   description,
                                   data_source = "Monitor Legislativo v4 Database",
                                   methodology = NULL) {
  
  caption <- paste0(
    "**Figure ", figure_number, ".** ",
    title, ". ",
    description
  )
  
  if (!is.null(methodology)) {
    caption <- paste0(caption, " ", methodology, ".")
  }
  
  caption <- paste0(
    caption,
    " Data source: ", data_source, ". ",
    "Generated: ", format(Sys.Date(), "%B %d, %Y"), "."
  )
  
  return(caption)
}

#' Save Academic Plot
#' 
#' Saves plots in publication-ready formats with proper dimensions
#' 
#' @param plot ggplot object
#' @param filename Output filename (without extension)
#' @param width Width in inches
#' @param height Height in inches
#' @param dpi Resolution
#' @param formats Vector of output formats
#' @return Vector of created file paths
#' @export
save_academic_plot <- function(plot,
                              filename,
                              width = 10,
                              height = 6,
                              dpi = 300,
                              formats = c("png", "pdf", "svg")) {
  
  # Create output directory
  output_dir <- "R/cache/plots"
  if (!dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  }
  
  saved_files <- c()
  
  for (format in formats) {
    filepath <- file.path(output_dir, paste0(filename, ".", format))
    
    ggsave(
      filename = filepath,
      plot = plot,
      width = width,
      height = height,
      dpi = dpi,
      device = format
    )
    
    saved_files <- c(saved_files, filepath)
    cat("📊 Plot saved:", filepath, "\n")
  }
  
  return(saved_files)
}

cat("✅ Academic Visualizations Module Loaded Successfully\n")
cat("🎨 Features: Publication-ready plots, academic themes, statistical annotations\n")
cat("📊 Chart types: Timeline, correlation, bar, scatter, tables\n")
cat("🖼️ Output formats: Static (ggplot2) and interactive (plotly)\n")
cat("📱 Academic standards: Publication-quality with proper citations\n\n")