# ============================================================================
# ADVANCED VISUALIZATIONS ENGINE - BRAZILIAN LEGISLATIVE ANALYTICS
# ============================================================================
# 
# Interactive visualizations for comprehensive legislative data analysis
# Network Graphs | Time Series Forecasting | Statistical Charts
# Geospatial Analysis | Multi-dimensional Clustering | Research Plots
# 
# Optimized for Shiny dashboards | plotly | networkD3 | visNetwork
# ============================================================================

cat("📊 Loading Advanced Visualizations Engine...\n")

# Load visualization packages
viz_packages <- c(
  "plotly", "ggplot2", "networkD3", "visNetwork", "DT", 
  "leaflet", "RColorBrewer", "scales", "ggrepel", "corrplot",
  "wordcloud2", "treemap", "sunburstR", "dygraphs", "htmlwidgets"
)

for (pkg in viz_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("⚠️ Package", pkg, "not available - using fallbacks\n")
  } else {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }
}

# ============================================================================
# INTERACTIVE NETWORK VISUALIZATIONS
# ============================================================================

#' Create Interactive Legal Citation Network Visualization
#' 
#' @param network_analysis Result from build_legal_citation_network()
#' @param layout_type Character, network layout algorithm
#' @param node_size_metric Character, metric for node sizing
#' @param color_scheme Character, color scheme for nodes
#' @return Interactive network visualization (plotly or networkD3)
create_interactive_citation_network <- function(network_analysis, 
                                              layout_type = "force_directed",
                                              node_size_metric = "degree",
                                              color_scheme = "authority_level") {
  
  cat("🕸️ Creating interactive citation network visualization...\n")
  
  tryCatch({
    if (isTRUE(is.null(network_analysis)) || "error" %in% names(network_analysis)) {
      return(create_fallback_network_viz())
    }
    
    network <- network_analysis$citation_network
    centrality <- network_analysis$centrality_analysis
    
    if (isTRUE(is.null(network)) || isTRUE(is.null(network$nodes)) || nrow(network$nodes) == 0) {
      return(create_fallback_network_viz())
    }
    
    # Prepare node data with enhanced attributes
    nodes <- network$nodes %>%
      left_join(
        if (!isTRUE(is.null(centrality)) && "centrality_measures" %in% names(centrality)) {
          centrality$centrality_measures
        } else {
          data.frame(node_id = network$nodes$id, degree = 1, betweenness = 0)
        },
        by = c("id" = "node_id")
      ) %>%
      mutate(
        # Node size based on selected metric
        size = case_when(
          node_size_metric == "degree" ~ pmax(degree * 2, 5),
          node_size_metric == "betweenness" ~ pmax(sqrt(betweenness), 5),
          node_size_metric == "frequency" ~ if ("frequency" %in% names(.)) pmax(sqrt(frequency) * 3, 5) else 10,
          TRUE ~ 10
        ),
        
        # Node color based on selected scheme
        color = case_when(
          color_scheme == "authority_level" & "category" %in% names(.) ~ 
            case_when(
              category == "constitutional" ~ "#8B0000",  # Dark red for constitutional
              category == "lei_federal" ~ "#4169E1",     # Royal blue for federal laws
              category == "decreto" ~ "#32CD32",         # Lime green for decrees
              category == "resolucao" ~ "#FF8C00",       # Dark orange for resolutions
              type == "document" ~ "#708090",            # Slate gray for documents
              TRUE ~ "#800080"                           # Purple for others
            ),
          color_scheme == "node_type" ~ if_else(type == "document", "#1f77b4", "#ff7f0e"),
          TRUE ~ "#1f77b4"
        ),
        
        # Enhanced tooltip information
        tooltip = paste0(
          "<b>", if_else(type == "document", "Document", "Citation"), ":</b> ", title, "<br>",
          if ("category" %in% names(.)) paste0("<b>Category:</b> ", category, "<br>") else "",
          if ("degree" %in% names(.)) paste0("<b>Connections:</b> ", degree, "<br>") else "",
          if ("frequency" %in% names(.)) paste0("<b>Frequency:</b> ", frequency, "<br>") else "",
          if ("year" %in% names(.)) paste0("<b>Year:</b> ", year, "<br>") else ""
        )
      )
    
    # Prepare edge data
    edges <- network$edges %>%
      mutate(
        width = case_when(
          "frequency" %in% names(.) ~ pmax(frequency / 2, 1),
          TRUE ~ 1
        ),
        color = case_when(
          "citation_type" %in% names(.) & citation_type == "constitutional" ~ "#8B0000",
          "authority_level" %in% names(.) & authority_level == "federal" ~ "#4169E1",
          TRUE ~ "#A9A9A9"
        )
      )
    
    # Create visualization based on available packages
    if (requireNamespace("visNetwork", quietly = TRUE)) {
      return(create_visnetwork_viz(nodes, edges, layout_type))
    } else if (requireNamespace("networkD3", quietly = TRUE)) {
      return(create_networkd3_viz(nodes, edges))
    } else {
      return(create_plotly_network_viz(nodes, edges))
    }
    
  }, error = function(e) {
    cat("⚠️ Network visualization failed, using fallback:", e$message, "\n")
    return(create_fallback_network_viz())
  })
}

#' Create visNetwork visualization
create_visnetwork_viz <- function(nodes, edges, layout_type) {
  
  # Prepare nodes for visNetwork
  vis_nodes <- nodes %>%
    select(
      id, 
      label = title, 
      size, 
      color,
      title = tooltip,
      group = type
    )
  
  # Prepare edges for visNetwork
  vis_edges <- edges %>%
    select(from, to, width, color) %>%
    mutate(arrows = "to")
  
  # Create network
  network_viz <- visNetwork::visNetwork(vis_nodes, vis_edges, width = "100%", height = "500px") %>%
    visNetwork::visOptions(highlightNearest = TRUE, selectedBy = "group") %>%
    visNetwork::visLayout(randomSeed = 123) %>%
    visNetwork::visInteraction(dragNodes = TRUE, dragView = TRUE, zoomView = TRUE)
  
  # Apply layout
  if (layout_type == "hierarchical") {
    network_viz <- network_viz %>% 
      visNetwork::visHierarchicalLayout(direction = "UD", sortMethod = "directed")
  } else if (layout_type == "circular") {
    network_viz <- network_viz %>%
      visNetwork::visLayout(randomSeed = 123)
  }
  
  return(network_viz)
}

#' Create networkD3 visualization  
create_networkd3_viz <- function(nodes, edges) {
  
  # Convert to networkD3 format (requires 0-indexed nodes)
  node_lookup <- data.frame(
    name = nodes$id,
    index = seq_len(nrow(nodes)) - 1
  )
  
  # Map edge indices
  d3_edges <- edges %>%
    left_join(node_lookup, by = c("from" = "name")) %>%
    rename(source = index) %>%
    left_join(node_lookup, by = c("to" = "name")) %>%
    rename(target = index) %>%
    select(source, target, width) %>%
    filter(!is.na(source), !is.na(target))
  
  # Create D3 nodes
  d3_nodes <- nodes %>%
    mutate(
      name = title,
      group = as.numeric(as.factor(type)),
      size = size
    ) %>%
    select(name, group, size)
  
  # Force directed network
  networkD3::forceNetwork(
    Links = d3_edges,
    Nodes = d3_nodes, 
    Source = "source",
    Target = "target",
    Value = "width",
    NodeID = "name",
    Group = "group",
    Nodesize = "size",
    opacity = 0.8,
    zoom = TRUE,
    bounded = TRUE,
    height = 500,
    width = "100%"
  )
}

#' Create plotly network visualization
create_plotly_network_viz <- function(nodes, edges) {
  
  # Simple force-directed layout approximation
  n_nodes <- nrow(nodes)
  
  # Random initial positions
  set.seed(123)
  positions <- data.frame(
    id = nodes$id,
    x = runif(n_nodes, -1, 1),
    y = runif(n_nodes, -1, 1)
  )
  
  nodes <- nodes %>% left_join(positions, by = "id")
  
  # Create plotly scatter plot
  p <- plot_ly(data = nodes,
               x = ~x, y = ~y,
               type = 'scatter',
               mode = 'markers+text',
               marker = list(
                 size = ~size,
                 color = ~color,
                 line = list(width = 1, color = 'white')
               ),
               text = ~substr(title, 1, 20),
               textposition = "middle center",
               hovertemplate = ~tooltip,
               showlegend = FALSE) %>%
    layout(
      title = "Legislative Citation Network",
      xaxis = list(showgrid = FALSE, zeroline = FALSE, showticklabels = FALSE),
      yaxis = list(showgrid = FALSE, zeroline = FALSE, showticklabels = FALSE),
      plot_bgcolor = 'rgba(0,0,0,0)',
      paper_bgcolor = 'rgba(0,0,0,0)'
    )
  
  return(p)
}

#' Create fallback network visualization
create_fallback_network_viz <- function() {
  
  # Simple demo network
  demo_data <- data.frame(
    x = c(0, 1, -1, 0.5, -0.5),
    y = c(1, 0, 0, -1, -1),
    label = c("Constituição", "Lei Federal", "Decreto", "Resolução", "Portaria"),
    size = c(20, 15, 12, 10, 8)
  )
  
  plot_ly(data = demo_data,
          x = ~x, y = ~y,
          type = 'scatter',
          mode = 'markers+text',
          marker = list(
            size = ~size,
            color = c("#8B0000", "#4169E1", "#32CD32", "#FF8C00", "#800080"),
            line = list(width = 2, color = 'white')
          ),
          text = ~label,
          textposition = "middle center",
          hovertemplate = "%{text}<br>Demo Network Node",
          showlegend = FALSE) %>%
    layout(
      title = "Citation Network (Demo Mode)",
      xaxis = list(showgrid = FALSE, zeroline = FALSE, showticklabels = FALSE, range = c(-2, 2)),
      yaxis = list(showgrid = FALSE, zeroline = FALSE, showticklabels = FALSE, range = c(-2, 2)),
      plot_bgcolor = 'rgba(0,0,0,0)',
      paper_bgcolor = 'rgba(0,0,0,0)'
    )
}

# ============================================================================
# TIME SERIES FORECASTING VISUALIZATIONS
# ============================================================================

#' Create Interactive Time Series Forecasting Visualization
#' 
#' @param time_series_analysis Result from advanced_time_series_analysis()
#' @param show_components Logical, whether to show seasonal decomposition
#' @param forecast_horizon Integer, number of periods to forecast
#' @return Interactive time series plot with forecasting
create_time_series_forecast_viz <- function(time_series_analysis,
                                           show_components = TRUE,
                                           forecast_horizon = 12) {
  
  cat("📈 Creating time series forecasting visualization...\n")
  
  tryCatch({
    if (isTRUE(is.null(time_series_analysis)) || "error" %in% names(time_series_analysis)) {
      return(create_fallback_timeseries_viz())
    }
    
    monthly_data <- time_series_analysis$monthly_series
    forecast_data <- time_series_analysis$forecast
    
    if (isTRUE(is.null(monthly_data)) || nrow(monthly_data) == 0) {
      return(create_fallback_timeseries_viz())
    }
    
    # Prepare historical data
    historical_plot <- monthly_data %>%
      mutate(
        date = as.Date(year_month),
        type = "Historical",
        lower_80 = NA,
        upper_80 = NA,
        lower_95 = NA,
        upper_95 = NA
      ) %>%
      rename(value = document_count) %>%
      select(date, value, type, lower_80, upper_80, lower_95, upper_95)
    
    # Prepare forecast data
    forecast_plot <- data.frame()
    if (!isTRUE(is.null(forecast_data)) && "forecast_values" %in% names(forecast_data)) {
      
      # Create future dates
      last_date <- max(monthly_data$year_month)
      future_dates <- seq.Date(last_date + months(1), 
                              last_date + months(forecast_horizon), 
                              by = "month")
      
      forecast_plot <- data.frame(
        date = future_dates,
        value = forecast_data$forecast_values[1:min(length(forecast_data$forecast_values), forecast_horizon)],
        type = "Forecast",
        lower_80 = if ("lower_80" %in% names(forecast_data)) {
          forecast_data$lower_80[1:min(length(forecast_data$lower_80), forecast_horizon)]
        } else NA,
        upper_80 = if ("upper_80" %in% names(forecast_data)) {
          forecast_data$upper_80[1:min(length(forecast_data$upper_80), forecast_horizon)]
        } else NA,
        lower_95 = if ("lower_95" %in% names(forecast_data)) {
          forecast_data$lower_95[1:min(length(forecast_data$lower_95), forecast_horizon)]
        } else NA,
        upper_95 = if ("upper_95" %in% names(forecast_data)) {
          forecast_data$upper_95[1:min(length(forecast_data$upper_95), forecast_horizon)]
        } else NA,
        stringsAsFactors = FALSE
      )
    }
    
    # Combine data
    combined_data <- rbind(historical_plot, forecast_plot)
    
    # Create main time series plot
    main_plot <- plot_ly(data = combined_data, x = ~date, y = ~value, 
                        color = ~type, type = 'scatter', mode = 'lines',
                        colors = c("Historical" = "#1f77b4", "Forecast" = "#ff7f0e"),
                        line = list(width = 2),
                        name = ~type) %>%
      layout(
        title = paste("Legislative Document Volume Forecast"),
        xaxis = list(title = "Date", type = "date"),
        yaxis = list(title = "Number of Documents"),
        hovermode = 'x unified'
      )
    
    # Add confidence intervals if available
    if (!all(is.na(combined_data$lower_95)) && !all(is.na(combined_data$upper_95))) {
      main_plot <- main_plot %>%
        add_ribbons(
          data = filter(combined_data, type == "Forecast"),
          ymin = ~lower_95, ymax = ~upper_95,
          fillcolor = "rgba(255, 127, 14, 0.2)",
          line = list(color = "rgba(255, 127, 14, 0)"),
          name = "95% Confidence Interval",
          showlegend = TRUE
        ) %>%
        add_ribbons(
          data = filter(combined_data, type == "Forecast"),
          ymin = ~lower_80, ymax = ~upper_80, 
          fillcolor = "rgba(255, 127, 14, 0.4)",
          line = list(color = "rgba(255, 127, 14, 0)"),
          name = "80% Confidence Interval",
          showlegend = TRUE
        )
    }
    
    # Add change points if available
    change_points <- time_series_analysis$change_points
    if (!isTRUE(is.null(change_points)) && !isTRUE(is.null(change_points$change_points)) && length(change_points$change_points) > 0) {
      
      # Calculate change point dates
      cp_dates <- monthly_data$year_month[change_points$change_points]
      
      for (cp_date in cp_dates) {
        main_plot <- main_plot %>%
          add_segments(
            x = cp_date, xend = cp_date,
            y = min(combined_data$value, na.rm = TRUE), 
            yend = max(combined_data$value, na.rm = TRUE),
            line = list(color = "red", dash = "dash", width = 1),
            name = "Policy Change Point",
            showlegend = if (cp_date == cp_dates[1]) TRUE else FALSE
          )
      }
    }
    
    # Create decomposition plot if requested
    if (show_components && !is.null(time_series_analysis$decomposition)) {
      decomp <- time_series_analysis$decomposition
      
      if (!isTRUE(is.null(decomp)) && "seasonal" %in% names(decomp)) {
        decomp_data <- data.frame(
          date = monthly_data$year_month,
          original = monthly_data$document_count,
          trend = decomp$trend[1:nrow(monthly_data)],
          seasonal = decomp$seasonal[1:nrow(monthly_data)],
          remainder = decomp$remainder[1:nrow(monthly_data)]
        )
        
        # Create subplot for components
        trend_plot <- plot_ly(decomp_data, x = ~date, y = ~trend, type = 'scatter', mode = 'lines',
                             name = 'Trend', line = list(color = '#2ca02c'))
        
        seasonal_plot <- plot_ly(decomp_data, x = ~date, y = ~seasonal, type = 'scatter', mode = 'lines',
                               name = 'Seasonal', line = list(color = '#d62728'))
        
        # Combine plots
        main_plot <- subplot(main_plot, trend_plot, seasonal_plot, 
                           nrows = 3, shareX = TRUE, heights = c(0.5, 0.25, 0.25))
      }
    }
    
    return(main_plot)
    
  }, error = function(e) {
    cat("⚠️ Time series visualization failed:", e$message, "\n")
    return(create_fallback_timeseries_viz())
  })
}

#' Create fallback time series visualization
create_fallback_timeseries_viz <- function() {
  
  # Generate demo time series data
  dates <- seq.Date(as.Date("2020-01-01"), as.Date("2024-12-01"), by = "month")
  values <- 50 + 10 * sin(2 * pi * seq_along(dates) / 12) + cumsum(rnorm(length(dates), 0, 2))
  
  demo_data <- data.frame(date = dates, value = values)
  
  plot_ly(data = demo_data, x = ~date, y = ~value, type = 'scatter', mode = 'lines',
          line = list(color = '#1f77b4', width = 2),
          name = 'Demo Time Series') %>%
    layout(
      title = "Legislative Document Volume (Demo Mode)",
      xaxis = list(title = "Date"),
      yaxis = list(title = "Number of Documents"),
      showlegend = FALSE
    )
}

# ============================================================================
# ADVANCED STATISTICAL VISUALIZATIONS
# ============================================================================

#' Create Correlation Matrix Heatmap
#' 
#' @param correlation_analysis Result from regression analysis
#' @param interactive Logical, whether to create interactive plot
#' @return Correlation heatmap visualization
create_correlation_heatmap <- function(correlation_analysis, interactive = TRUE) {
  
  cat("🔥 Creating correlation heatmap...\n")
  
  tryCatch({
    if (isTRUE(is.null(correlation_analysis)) || 
        !("correlation_analysis" %in% names(correlation_analysis)) || isTRUE(is.null(correlation_analysis$correlation_analysis$correlation_matrix))) {
      return(create_fallback_correlation_viz())
    }
    
    cor_matrix <- correlation_analysis$correlation_analysis$correlation_matrix
    
    if (interactive && requireNamespace("plotly", quietly = TRUE)) {
      # Interactive heatmap with plotly
      plot_ly(
        z = ~as.matrix(cor_matrix),
        x = colnames(cor_matrix),
        y = rownames(cor_matrix),
        type = "heatmap",
        colorscale = list(
          c(0, "#d73027"),
          c(0.5, "#ffffbf"), 
          c(1, "#1a9850")
        ),
        hovertemplate = "X: %{x}<br>Y: %{y}<br>Correlation: %{z:.3f}<extra></extra>"
      ) %>%
        layout(
          title = "Variable Correlation Matrix",
          xaxis = list(title = "Variables"),
          yaxis = list(title = "Variables")
        )
    } else {
      # Static heatmap with ggplot2
      cor_df <- expand.grid(Var1 = rownames(cor_matrix), Var2 = colnames(cor_matrix))
      cor_df$value <- as.vector(cor_matrix)
      
      ggplot(cor_df, aes(Var1, Var2, fill = value)) +
        geom_tile(color = "white") +
        scale_fill_gradient2(low = "#d73027", high = "#1a9850", mid = "#ffffbf",
                           midpoint = 0, limit = c(-1, 1), space = "Lab",
                           name = "Correlation") +
        theme_minimal() +
        theme(axis.text.x = element_text(angle = 45, vjust = 1, hjust = 1)) +
        labs(title = "Variable Correlation Matrix", x = "", y = "") +
        coord_fixed()
    }
    
  }, error = function(e) {
    cat("⚠️ Correlation heatmap failed:", e$message, "\n")
    return(create_fallback_correlation_viz())
  })
}

#' Create fallback correlation visualization
create_fallback_correlation_viz <- function() {
  
  # Demo correlation matrix
  vars <- c("Documents", "Year", "Complexity", "Citations")
  demo_cor <- matrix(c(1.0, 0.3, -0.2, 0.8,
                      0.3, 1.0, 0.1, 0.4, 
                      -0.2, 0.1, 1.0, -0.3,
                      0.8, 0.4, -0.3, 1.0), 
                    nrow = 4, dimnames = list(vars, vars))
  
  plot_ly(
    z = ~demo_cor,
    x = vars,
    y = vars,
    type = "heatmap",
    colorscale = list(
      c(0, "#d73027"),
      c(0.5, "#ffffbf"),
      c(1, "#1a9850")
    )
  ) %>%
    layout(
      title = "Variable Correlation Matrix (Demo Mode)",
      xaxis = list(title = "Variables"),
      yaxis = list(title = "Variables")
    )
}

#' Create Sentiment Analysis Visualization
#' 
#' @param sentiment_analysis Result from comprehensive_sentiment_topic_analysis()
#' @param visualization_type Character, type of sentiment visualization
#' @return Sentiment analysis visualization
create_sentiment_analysis_viz <- function(sentiment_analysis, 
                                        visualization_type = "distribution") {
  
  cat("🎭 Creating sentiment analysis visualization...\n")
  
  tryCatch({
    if (isTRUE(is.null(sentiment_analysis)) || 
        !("sentiment_analysis" %in% names(sentiment_analysis)) ||
        nrow(sentiment_analysis$sentiment_analysis) == 0) {
      return(create_fallback_sentiment_viz())
    }
    
    sentiment_data <- sentiment_analysis$sentiment_analysis
    
    if (visualization_type == "distribution") {
      # Sentiment distribution histogram
      plot_ly(data = sentiment_data, x = ~sentiment_score, type = "histogram",
              nbinsx = 30, name = "Sentiment Distribution") %>%
        add_histogram(x = ~sentiment_score[sentiment_class == "positive"], 
                     name = "Positive", opacity = 0.7) %>%
        add_histogram(x = ~sentiment_score[sentiment_class == "negative"], 
                     name = "Negative", opacity = 0.7) %>%
        layout(
          title = "Legislative Document Sentiment Distribution",
          xaxis = list(title = "Sentiment Score"),
          yaxis = list(title = "Number of Documents"),
          barmode = "overlay"
        )
        
    } else if (visualization_type == "policy_tone") {
      # Policy tone analysis
      tone_summary <- sentiment_data %>%
        count(policy_tone, sentiment_class) %>%
        group_by(policy_tone) %>%
        mutate(percentage = n / sum(n) * 100)
      
      plot_ly(data = tone_summary, x = ~policy_tone, y = ~percentage, 
              color = ~sentiment_class, type = 'bar') %>%
        layout(
          title = "Policy Tone Analysis",
          xaxis = list(title = "Policy Tone"),
          yaxis = list(title = "Percentage"),
          barmode = 'stack'
        )
        
    } else if (visualization_type == "temporal") {
      # Temporal sentiment if available
      if ("temporal_sentiment" %in% names(sentiment_analysis) && 
          !is.null(sentiment_analysis$temporal_sentiment)) {
        
        temporal_data <- sentiment_analysis$temporal_sentiment
        
        plot_ly(data = temporal_data, x = ~year, y = ~avg_sentiment, 
                type = 'scatter', mode = 'lines+markers',
                line = list(color = '#1f77b4', width = 3),
                marker = list(size = 8, color = '#1f77b4')) %>%
          layout(
            title = "Legislative Sentiment Trends Over Time",
            xaxis = list(title = "Year"),
            yaxis = list(title = "Average Sentiment Score")
          )
      } else {
        return(create_fallback_sentiment_viz())
      }
    }
    
  }, error = function(e) {
    cat("⚠️ Sentiment visualization failed:", e$message, "\n")
    return(create_fallback_sentiment_viz())
  })
}

#' Create fallback sentiment visualization
create_fallback_sentiment_viz <- function() {
  
  # Demo sentiment data
  demo_sentiment <- data.frame(
    sentiment_score = rnorm(100, 0, 0.3),
    sentiment_class = sample(c("positive", "negative", "neutral"), 100, 
                           replace = TRUE, prob = c(0.4, 0.3, 0.3))
  )
  
  plot_ly(data = demo_sentiment, x = ~sentiment_score, type = "histogram",
          nbinsx = 20, name = "Demo Sentiment Distribution") %>%
    layout(
      title = "Legislative Document Sentiment (Demo Mode)",
      xaxis = list(title = "Sentiment Score"),
      yaxis = list(title = "Number of Documents")
    )
}

#' Create Topic Modeling Visualization
#' 
#' @param topic_analysis Result from comprehensive_sentiment_topic_analysis()
#' @param visualization_type Character, type of topic visualization
#' @return Topic modeling visualization
create_topic_modeling_viz <- function(topic_analysis, 
                                    visualization_type = "treemap") {
  
  cat("🏷️ Creating topic modeling visualization...\n")
  
  tryCatch({
    if (isTRUE(is.null(topic_analysis)) || 
        !("topic_modeling" %in% names(topic_analysis)) || isTRUE(is.null(topic_analysis$topic_modeling$topic_distribution))) {
      return(create_fallback_topic_viz())
    }
    
    topic_dist <- topic_analysis$topic_modeling$topic_distribution
    topic_df <- data.frame(
      topic = names(topic_dist),
      count = as.numeric(topic_dist),
      stringsAsFactors = FALSE
    ) %>%
      arrange(desc(count)) %>%
      head(15)  # Top 15 topics
    
    if (visualization_type == "treemap" && requireNamespace("treemap", quietly = TRUE)) {
      # Treemap visualization (would need to convert to plotly for interactivity)
      plot_ly(
        type = "treemap",
        labels = topic_df$topic,
        values = topic_df$count,
        parents = "",
        textinfo = "label+value"
      ) %>%
        layout(title = "Legislative Topic Distribution")
        
    } else if (visualization_type == "sunburst") {
      # Sunburst chart (hierarchical topics)
      plot_ly(
        type = "sunburst",
        labels = topic_df$topic,
        values = topic_df$count,
        parents = ""
      ) %>%
        layout(title = "Legislative Topic Hierarchy")
        
    } else {
      # Default bar chart
      plot_ly(data = topic_df, x = ~reorder(topic, count), y = ~count,
              type = 'bar', orientation = 'h',
              marker = list(color = rainbow(nrow(topic_df)))) %>%
        layout(
          title = "Top Legislative Topics",
          xaxis = list(title = "Topic"),
          yaxis = list(title = "Number of Documents"),
          margin = list(l = 200)
        )
    }
    
  }, error = function(e) {
    cat("⚠️ Topic visualization failed:", e$message, "\n")
    return(create_fallback_topic_viz())
  })
}

#' Create fallback topic visualization
create_fallback_topic_viz <- function() {
  
  # Demo topic data
  demo_topics <- data.frame(
    topic = c("Transporte Rodoviário", "Sustentabilidade", "Segurança Viária", 
             "Infraestrutura", "Combustíveis", "Regulação", "Tecnologia"),
    count = c(45, 32, 28, 25, 20, 18, 15)
  )
  
  plot_ly(data = demo_topics, x = ~reorder(topic, count), y = ~count,
          type = 'bar', orientation = 'h',
          marker = list(color = rainbow(nrow(demo_topics)))) %>%
    layout(
      title = "Legislative Topics (Demo Mode)",
      xaxis = list(title = "Topic"),
      yaxis = list(title = "Number of Documents"),
      margin = list(l = 150)
    )
}

# ============================================================================
# POLICY DIFFUSION VISUALIZATIONS
# ============================================================================

#' Create Policy Diffusion Network Visualization
#' 
#' @param diffusion_analysis Result from analyze_policy_diffusion_network()
#' @param layout_algorithm Character, network layout algorithm
#' @return Interactive policy diffusion network
create_policy_diffusion_viz <- function(diffusion_analysis, 
                                       layout_algorithm = "force_directed") {
  
  cat("🌐 Creating policy diffusion visualization...\n")
  
  tryCatch({
    if (isTRUE(is.null(diffusion_analysis)) || "error" %in% names(diffusion_analysis)) {
      return(create_fallback_diffusion_viz())
    }
    
    network <- diffusion_analysis$diffusion_network
    leadership <- diffusion_analysis$innovation_leadership
    
    if (isTRUE(is.null(network)) || isTRUE(is.null(network$nodes))) {
      return(create_fallback_diffusion_viz())
    }
    
    # Enhance nodes with leadership information
    enhanced_nodes <- network$nodes
    if (!isTRUE(is.null(leadership)) && "overall_leadership" %in% names(leadership)) {
      enhanced_nodes <- enhanced_nodes %>%
        left_join(
          leadership$overall_leadership %>% 
            select(jurisdiction, leadership_score, policy_diversity),
          by = "jurisdiction"
        ) %>%
        mutate(
          leadership_score = replace_na(leadership_score, 0),
          policy_diversity = replace_na(policy_diversity, 0),
          # Size based on leadership score
          size = pmax(sqrt(leadership_score) * 20 + 10, 10),
          # Color based on policy diversity
          color = case_when(
            policy_diversity >= 4 ~ "#d62728",  # Red for high diversity
            policy_diversity >= 2 ~ "#ff7f0e",  # Orange for medium
            TRUE ~ "#1f77b4"                    # Blue for low
          ),
          # Enhanced tooltip
          title = paste0(
            "<b>", jurisdiction, "</b><br>",
            "Policy Areas: ", policy_diversity, "<br>",
            "Leadership Score: ", round(leadership_score, 2), "<br>",
            "Total Documents: ", n
          )
        )
    }
    
    # Create interactive network
    if (requireNamespace("visNetwork", quietly = TRUE) && !is.null(network$edges)) {
      
      vis_nodes <- enhanced_nodes %>%
        select(
          id = jurisdiction,
          label = jurisdiction,
          size,
          color,
          title
        )
      
      vis_edges <- network$edges %>%
        mutate(
          arrows = "to",
          width = similarity * 5 + 1,
          color = "#A9A9A9"
        ) %>%
        select(from, to, arrows, width, color)
      
      visNetwork::visNetwork(vis_nodes, vis_edges, width = "100%", height = "500px") %>%
        visNetwork::visOptions(highlightNearest = TRUE) %>%
        visNetwork::visLayout(randomSeed = 123) %>%
        visNetwork::visInteraction(dragNodes = TRUE, dragView = TRUE, zoomView = TRUE) %>%
        visNetwork::visLegend(
          useGroups = FALSE,
          addNodes = list(
            list(label = "High Policy Diversity", color = "#d62728", shape = "dot"),
            list(label = "Medium Policy Diversity", color = "#ff7f0e", shape = "dot"), 
            list(label = "Low Policy Diversity", color = "#1f77b4", shape = "dot")
          )
        )
        
    } else {
      # Fallback plotly visualization
      create_plotly_diffusion_network(enhanced_nodes)
    }
    
  }, error = function(e) {
    cat("⚠️ Policy diffusion visualization failed:", e$message, "\n")
    return(create_fallback_diffusion_viz())
  })
}

#' Create plotly diffusion network
create_plotly_diffusion_network <- function(nodes) {
  
  # Simple circular layout
  n_nodes <- nrow(nodes)
  angles <- seq(0, 2 * pi, length.out = n_nodes + 1)[1:n_nodes]
  
  nodes$x <- cos(angles)
  nodes$y <- sin(angles)
  
  plot_ly(data = nodes,
          x = ~x, y = ~y,
          type = 'scatter',
          mode = 'markers+text',
          marker = list(
            size = ~size,
            color = ~color,
            line = list(width = 2, color = 'white')
          ),
          text = ~jurisdiction,
          textposition = "middle center",
          hovertemplate = ~title,
          showlegend = FALSE) %>%
    layout(
      title = "Policy Diffusion Network",
      xaxis = list(showgrid = FALSE, zeroline = FALSE, showticklabels = FALSE),
      yaxis = list(showgrid = FALSE, zeroline = FALSE, showticklabels = FALSE),
      plot_bgcolor = 'rgba(0,0,0,0)',
      paper_bgcolor = 'rgba(0,0,0,0)'
    )
}

#' Create fallback diffusion visualization
create_fallback_diffusion_viz <- function() {
  
  # Demo policy diffusion network
  demo_states <- c("SP", "RJ", "MG", "RS", "PR", "SC", "DF")
  demo_data <- data.frame(
    jurisdiction = demo_states,
    policy_diversity = c(5, 4, 3, 4, 3, 2, 5),
    leadership_score = c(0.8, 0.6, 0.4, 0.7, 0.5, 0.3, 0.9)
  )
  
  # Circular layout
  n_nodes <- nrow(demo_data)
  angles <- seq(0, 2 * pi, length.out = n_nodes + 1)[1:n_nodes]
  demo_data$x <- cos(angles)
  demo_data$y <- sin(angles)
  
  plot_ly(data = demo_data,
          x = ~x, y = ~y,
          type = 'scatter',
          mode = 'markers+text',
          marker = list(
            size = ~leadership_score * 30 + 10,
            color = ~policy_diversity,
            colorscale = "Viridis",
            line = list(width = 2, color = 'white')
          ),
          text = ~jurisdiction,
          textposition = "middle center",
          hovertemplate = "%{text}<br>Demo Policy Network",
          showlegend = FALSE) %>%
    layout(
      title = "Policy Diffusion Network (Demo Mode)",
      xaxis = list(showgrid = FALSE, zeroline = FALSE, showticklabels = FALSE),
      yaxis = list(showgrid = FALSE, zeroline = FALSE, showticklabels = FALSE),
      plot_bgcolor = 'rgba(0,0,0,0)',
      paper_bgcolor = 'rgba(0,0,0,0)'
    )
}

cat("✅ Advanced Visualizations Engine loaded successfully\n")
cat("   🕸️ Interactive network visualizations: ENABLED\n")
cat("   📈 Time series forecasting plots: ENABLED\n")
cat("   🔥 Correlation matrix heatmaps: ENABLED\n")
cat("   🎭 Sentiment analysis charts: ENABLED\n")
cat("   🏷️ Topic modeling visualizations: ENABLED\n")
cat("   🌐 Policy diffusion networks: ENABLED\n")
cat("   📊 Statistical chart library: ENABLED\n")