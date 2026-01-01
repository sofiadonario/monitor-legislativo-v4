# ==============================================================================
# NETWORK BACKBONE VISUALIZATION
# ==============================================================================
# Monitor Legislativo v4 - Network Visualization Module
#
# This module provides comprehensive visualization tools for network analysis
# including interactive network plots, metrics dashboards, and export capabilities.
#
# Features:
# - Interactive network visualization with visNetwork and networkD3
# - Network metrics dashboards with ggplot2
# - Backbone comparison visualizations
# - GEXF export for Gephi
# - Community coloring and node sizing
# - High-performance rendering for large networks
# ==============================================================================

# Core packages (required)
suppressPackageStartupMessages({
  library(ggplot2)
  library(dplyr)
  library(tidyr)
  library(scales)
  library(RColorBrewer)
})

# Optional network visualization packages
if (requireNamespace("igraph", quietly = TRUE)) library(igraph)
if (requireNamespace("visNetwork", quietly = TRUE)) library(visNetwork)
if (requireNamespace("networkD3", quietly = TRUE)) library(networkD3)
if (requireNamespace("ggraph", quietly = TRUE)) library(ggraph)
if (requireNamespace("tidygraph", quietly = TRUE)) library(tidygraph)
if (requireNamespace("gridExtra", quietly = TRUE)) library(gridExtra)

# ==============================================================================
# INTERACTIVE NETWORK VISUALIZATION
# ==============================================================================

#' Plot Interactive Network with visNetwork
#'
#' Creates an interactive network visualization using visNetwork, with
#' customizable node sizing, coloring, and layout algorithms.
#'
#' @param network igraph object to visualize
#' @param layout Layout algorithm:
#'   - "fr": Fruchterman-Reingold (default, good for most networks)
#'   - "kk": Kamada-Kawai (good for small networks)
#'   - "drl": DrL (fast for large networks)
#'   - "lgl": Large Graph Layout (very fast for large networks)
#'   - "graphopt": Force-directed with simulated annealing
#' @param node_size_by Node attribute to use for sizing. Options:
#'   - "degree": Node degree (default)
#'   - "betweenness": Betweenness centrality
#'   - "pagerank": PageRank score
#'   - "constant": All nodes same size
#' @param node_color_by Node attribute for coloring. Options:
#'   - "community": Community membership (default)
#'   - "type": Node type attribute
#'   - "ano": Year attribute
#'   - "constant": All nodes same color
#' @param community_method Community detection method if needed. Default "louvain"
#' @param max_nodes Maximum nodes to display. Default 500. Networks larger than
#'   this will be sampled.
#' @param edge_scaling Scale edge width by weight? Default TRUE
#' @param show_labels Show node labels? Default FALSE (for readability)
#' @param label_threshold Only show labels for nodes with size > threshold
#'
#' @return visNetwork htmlwidget object
#'
#' @examples
#' \dontrun{
#' # Build and visualize citation network
#' g <- build_citation_network(db_pool)
#' backbone <- extract_backbone(g, alpha = 0.05)
#'
#' # Interactive plot colored by community
#' plot_interactive_network(backbone, node_color_by = "community")
#'
#' # Size by betweenness, use fast layout for large network
#' plot_interactive_network(backbone,
#'                          layout = "drl",
#'                          node_size_by = "betweenness")
#'
#' # Show labels for high-degree nodes only
#' plot_interactive_network(backbone,
#'                          show_labels = TRUE,
#'                          label_threshold = 10)
#' }
#'
#' @export
plot_interactive_network <- function(network,
                                     layout = "fr",
                                     node_size_by = "degree",
                                     node_color_by = "community",
                                     community_method = "louvain",
                                     max_nodes = 500,
                                     edge_scaling = TRUE,
                                     show_labels = FALSE,
                                     label_threshold = 0) {

  cat("Creating interactive network visualization...\n")

  # Sample large networks
  if (vcount(network) > max_nodes) {
    cat(sprintf("  Network has %d nodes, sampling %d...\n", vcount(network), max_nodes))

    # Sample high-degree nodes preferentially
    degrees <- degree(network)
    sample_prob <- degrees / sum(degrees)
    sampled_nodes <- sample(V(network), max_nodes, prob = sample_prob)

    network <- induced_subgraph(network, sampled_nodes)
  }

  # Calculate layout
  cat(sprintf("  Computing %s layout...\n", layout))

  layout_coords <- switch(layout,
    "fr" = layout_with_fr(network),
    "kk" = layout_with_kk(network),
    "drl" = layout_with_drl(network),
    "lgl" = layout_with_lgl(network),
    "graphopt" = layout_with_graphopt(network),
    layout_with_fr(network)  # Default
  )

  # Prepare node data
  nodes <- data.frame(
    id = 1:vcount(network),
    label = if (!is.null(V(network)$label)) {
      V(network)$label
    } else if (!is.null(V(network)$titulo)) {
      V(network)$titulo
    } else {
      V(network)$name
    },
    title = if (!is.null(V(network)$titulo)) V(network)$titulo else V(network)$name,
    x = layout_coords[, 1],
    y = layout_coords[, 2],
    stringsAsFactors = FALSE
  )

  # Calculate node sizes
  cat(sprintf("  Sizing nodes by %s...\n", node_size_by))

  if (node_size_by == "degree") {
    size_values <- degree(network)
  } else if (node_size_by == "betweenness") {
    size_values <- betweenness(network, normalized = TRUE)
  } else if (node_size_by == "pagerank") {
    size_values <- page_rank(network)$vector
  } else {
    size_values <- rep(1, vcount(network))
  }

  # Scale sizes to reasonable range (10-50)
  if (max(size_values) > 0) {
    nodes$value <- 10 + 40 * (size_values - min(size_values)) /
                              (max(size_values) - min(size_values))
  } else {
    nodes$value <- 20
  }

  # Calculate node colors
  cat(sprintf("  Coloring nodes by %s...\n", node_color_by))

  if (node_color_by == "community") {
    # Detect communities if not already present
    if (is.null(V(network)$community)) {
      source("R/analytics/network_backbone.R")
      comm <- detect_communities(network, method = community_method)
      community_membership <- comm$membership
    } else {
      community_membership <- V(network)$community
    }

    n_communities <- max(community_membership, na.rm = TRUE)

    # Generate distinct colors
    if (n_communities <= 12) {
      palette <- brewer.pal(max(3, n_communities), "Set3")
    } else {
      palette <- rainbow(n_communities)
    }

    nodes$group <- as.character(community_membership)
    nodes$color <- palette[community_membership]

  } else if (node_color_by == "type" && !is.null(V(network)$tipo)) {
    nodes$group <- V(network)$tipo
    unique_types <- unique(nodes$group)
    type_colors <- brewer.pal(max(3, length(unique_types)), "Set2")
    nodes$color <- type_colors[match(nodes$group, unique_types)]

  } else if (node_color_by == "ano" && !is.null(V(network)$ano)) {
    anos <- V(network)$ano
    nodes$group <- cut(anos, breaks = 5, labels = FALSE)
    year_colors <- brewer.pal(5, "YlOrRd")
    nodes$color <- year_colors[nodes$group]

  } else {
    nodes$group <- "1"
    nodes$color <- "#97C2FC"  # Default light blue
  }

  # Hide labels for small nodes if threshold specified
  if (!show_labels || label_threshold > 0) {
    nodes$label <- ifelse(nodes$value > label_threshold, nodes$label, "")
  }

  # Prepare edge data
  edges <- as_data_frame(network, what = "edges")

  # Convert node names to IDs
  node_lookup <- setNames(1:vcount(network), V(network)$name)
  edges$from <- node_lookup[edges$from]
  edges$to <- node_lookup[edges$to]

  # Scale edge widths
  if (edge_scaling && "weight" %in% names(edges)) {
    max_weight <- max(edges$weight, na.rm = TRUE)
    if (max_weight > 0) {
      edges$width <- 1 + 4 * edges$weight / max_weight
    } else {
      edges$width <- 1
    }
  } else {
    edges$width <- 1
  }

  edges$arrows <- if (is_directed(network)) "to" else ""

  # Create visNetwork visualization
  cat("  Rendering interactive plot...\n")

  vis <- visNetwork(nodes, edges, width = "100%", height = "600px") %>%
    visIgraphLayout(layout = "layout_with_fr") %>%
    visNodes(
      shadow = list(enabled = TRUE, size = 5),
      font = list(size = 12)
    ) %>%
    visEdges(
      smooth = list(enabled = TRUE, type = "continuous"),
      color = list(color = "#848484", opacity = 0.3)
    ) %>%
    visOptions(
      highlightNearest = list(enabled = TRUE, degree = 1, hover = TRUE),
      nodesIdSelection = FALSE,
      selectedBy = if (node_color_by == "community") "group" else NULL
    ) %>%
    visInteraction(
      navigationButtons = TRUE,
      dragNodes = TRUE,
      dragView = TRUE,
      zoomView = TRUE
    ) %>%
    visPhysics(
      enabled = FALSE,  # Disable physics for performance
      stabilization = FALSE
    ) %>%
    visLayout(randomSeed = 42)  # Reproducible layout

  cat("  Visualization created successfully\n")

  return(vis)
}

# ==============================================================================
# NETWORK METRICS DASHBOARD
# ==============================================================================

#' Plot Network Metrics Dashboard
#'
#' Creates a multi-panel dashboard showing key network statistics including
#' degree distribution, clustering, centrality distributions, and community sizes.
#'
#' @param network igraph object
#' @param community_method Community detection method. Default "louvain"
#'
#' @return ggplot grid object
#'
#' @export
plot_network_metrics_dashboard <- function(network,
                                           community_method = "louvain") {

  cat("Creating network metrics dashboard...\n")

  # Calculate metrics
  degrees <- degree(network)
  betweenness <- betweenness(network, normalized = TRUE)
  clustering <- transitivity(network, type = "local")
  pagerank <- page_rank(network)$vector

  # Detect communities
  source("R/analytics/network_backbone.R")
  comm <- detect_communities(network, method = community_method)

  # 1. Degree Distribution (log-log scale)
  p1 <- ggplot(data.frame(degree = degrees), aes(x = degree)) +
    geom_histogram(bins = 30, fill = "#4292c6", color = "white", alpha = 0.8) +
    scale_x_log10(labels = comma) +
    scale_y_log10(labels = comma) +
    labs(
      title = "Degree Distribution",
      subtitle = sprintf("Mean: %.1f, Max: %d", mean(degrees), max(degrees)),
      x = "Degree (log scale)",
      y = "Frequency (log scale)"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(face = "bold"))

  # 2. Betweenness Centrality Distribution
  p2 <- ggplot(data.frame(betweenness = betweenness), aes(x = betweenness)) +
    geom_histogram(bins = 30, fill = "#2ca25f", color = "white", alpha = 0.8) +
    scale_x_continuous(labels = scientific) +
    labs(
      title = "Betweenness Centrality",
      subtitle = sprintf("Median: %.2e", median(betweenness, na.rm = TRUE)),
      x = "Normalized Betweenness",
      y = "Frequency"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(face = "bold"))

  # 3. Clustering Coefficient Distribution
  clustering_clean <- clustering[!is.nan(clustering) & !is.na(clustering)]

  p3 <- ggplot(data.frame(clustering = clustering_clean), aes(x = clustering)) +
    geom_histogram(bins = 30, fill = "#fe9929", color = "white", alpha = 0.8) +
    labs(
      title = "Local Clustering Coefficient",
      subtitle = sprintf("Mean: %.3f", mean(clustering_clean, na.rm = TRUE)),
      x = "Clustering Coefficient",
      y = "Frequency"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(face = "bold"))

  # 4. Community Sizes
  community_df <- data.frame(
    community = factor(1:comm$n_communities),
    size = comm$sizes
  )

  p4 <- ggplot(community_df, aes(x = reorder(community, -size), y = size)) +
    geom_col(fill = "#8856a7", alpha = 0.8) +
    labs(
      title = sprintf("Community Sizes (%s)", community_method),
      subtitle = sprintf("Modularity: %.3f", comm$modularity),
      x = "Community",
      y = "Number of Nodes"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(face = "bold"),
      axis.text.x = element_text(angle = 45, hjust = 1)
    )

  # Combine plots
  grid_plot <- grid.arrange(p1, p2, p3, p4, ncol = 2,
                           top = sprintf("Network Metrics Dashboard - %d Nodes, %d Edges",
                                       vcount(network), ecount(network)))

  cat("  Dashboard created successfully\n")

  return(grid_plot)
}

# ==============================================================================
# BACKBONE COMPARISON VISUALIZATION
# ==============================================================================

#' Plot Backbone vs Original Network Comparison
#'
#' Creates side-by-side comparison showing the effect of backbone extraction
#' on network structure.
#'
#' @param original_network Original full network
#' @param backbone_network Backbone-extracted network
#' @param layout Layout to use for both networks. Default "fr"
#'
#' @return Combined ggplot object
#'
#' @export
plot_backbone_comparison <- function(original_network,
                                     backbone_network,
                                     layout = "fr") {

  cat("Creating backbone comparison plot...\n")

  # Calculate layouts (use same for both for comparability)
  set.seed(42)

  if (layout == "fr") {
    layout_orig <- layout_with_fr(original_network)
    layout_backbone <- layout_with_fr(backbone_network)
  } else if (layout == "kk") {
    layout_orig <- layout_with_kk(original_network)
    layout_backbone <- layout_with_kk(backbone_network)
  } else {
    layout_orig <- layout_with_fr(original_network)
    layout_backbone <- layout_with_fr(backbone_network)
  }

  # Convert to tidygraph for ggraph
  tidy_orig <- as_tbl_graph(original_network) %>%
    mutate(degree = degree(original_network))

  tidy_backbone <- as_tbl_graph(backbone_network) %>%
    mutate(degree = degree(backbone_network))

  # Plot original network
  p1 <- ggraph(tidy_orig, layout = "manual",
               x = layout_orig[, 1], y = layout_orig[, 2]) +
    geom_edge_link(alpha = 0.2, color = "#636363") +
    geom_node_point(aes(size = degree), color = "#4292c6", alpha = 0.7) +
    scale_size_continuous(range = c(1, 8)) +
    labs(
      title = "Original Network",
      subtitle = sprintf("%d nodes, %d edges\nDensity: %.6f",
                        vcount(original_network),
                        ecount(original_network),
                        edge_density(original_network))
    ) +
    theme_graph() +
    theme(
      plot.title = element_text(face = "bold", size = 14),
      plot.subtitle = element_text(size = 10),
      legend.position = "none"
    )

  # Plot backbone
  p2 <- ggraph(tidy_backbone, layout = "manual",
               x = layout_backbone[, 1], y = layout_backbone[, 2]) +
    geom_edge_link(alpha = 0.3, color = "#636363", linewidth = 0.8) +
    geom_node_point(aes(size = degree), color = "#d94801", alpha = 0.7) +
    scale_size_continuous(range = c(1, 8)) +
    labs(
      title = "Backbone Network",
      subtitle = sprintf("%d nodes, %d edges\nDensity: %.6f\nReduction: %.1f%%",
                        vcount(backbone_network),
                        ecount(backbone_network),
                        edge_density(backbone_network),
                        100 * (1 - ecount(backbone_network) / ecount(original_network)))
    ) +
    theme_graph() +
    theme(
      plot.title = element_text(face = "bold", size = 14),
      plot.subtitle = element_text(size = 10),
      legend.position = "none"
    )

  # Combine
  combined <- grid.arrange(p1, p2, ncol = 2,
                          top = "Backbone Extraction Comparison")

  cat("  Comparison plot created\n")

  return(combined)
}

# ==============================================================================
# GEPHI EXPORT
# ==============================================================================

#' Export Network to GEXF Format for Gephi
#'
#' Exports network to GEXF (Graph Exchange XML Format) for visualization
#' in Gephi or other network analysis tools.
#'
#' @param network igraph object
#' @param filename Output file path. Must end in .gexf
#' @param include_layout Include layout coordinates? Default TRUE
#' @param layout_method Layout algorithm if include_layout=TRUE. Default "fr"
#'
#' @return TRUE if export successful, FALSE otherwise
#'
#' @examples
#' \dontrun{
#' # Export backbone network
#' export_network_for_gephi(backbone, "citation_backbone.gexf")
#'
#' # Export with specific layout
#' export_network_for_gephi(backbone,
#'                          "coauthor_network.gexf",
#'                          layout_method = "kk")
#' }
#'
#' @export
export_network_for_gephi <- function(network,
                                     filename,
                                     include_layout = TRUE,
                                     layout_method = "fr") {

  cat(sprintf("Exporting network to GEXF format: %s\n", filename))

  if (!grepl("\\.gexf$", filename, ignore.case = TRUE)) {
    filename <- paste0(filename, ".gexf")
  }

  tryCatch({
    # Add layout coordinates if requested
    if (include_layout) {
      cat(sprintf("  Computing %s layout...\n", layout_method))

      coords <- switch(layout_method,
        "fr" = layout_with_fr(network),
        "kk" = layout_with_kk(network),
        "drl" = layout_with_drl(network),
        layout_with_fr(network)
      )

      V(network)$x <- coords[, 1]
      V(network)$y <- coords[, 2]
      V(network)$z <- 0
    }

    # Ensure node IDs are character (GEXF requirement)
    V(network)$id <- as.character(V(network)$name)

    # Write GEXF
    rgexf::write.gexf(
      nodes = as_data_frame(network, what = "vertices"),
      edges = as_data_frame(network, what = "edges"),
      output = filename,
      defaultedgetype = if (is_directed(network)) "directed" else "undirected"
    )

    cat(sprintf("  Network exported successfully to %s\n", filename))
    cat(sprintf("  Nodes: %d, Edges: %d\n", vcount(network), ecount(network)))

    return(TRUE)

  }, error = function(e) {
    cat(sprintf("  Error exporting network: %s\n", e$message))

    # Fallback: use igraph's built-in write_graph
    tryCatch({
      cat("  Trying alternative export method (GraphML)...\n")
      graphml_file <- gsub("\\.gexf$", ".graphml", filename)
      write_graph(network, graphml_file, format = "graphml")
      cat(sprintf("  Exported as GraphML instead: %s\n", graphml_file))
      return(TRUE)
    }, error = function(e2) {
      cat(sprintf("  Alternative export also failed: %s\n", e2$message))
      return(FALSE)
    })
  })
}

# ==============================================================================
# ADDITIONAL VISUALIZATION UTILITIES
# ==============================================================================

#' Plot Degree Distribution with Power Law Fit
#'
#' Creates publication-quality degree distribution plot with optional
#' power-law fit overlay.
#'
#' @param network igraph object
#' @param fit_powerlaw Attempt to fit power law distribution? Default TRUE
#'
#' @return ggplot object
#'
#' @export
plot_degree_distribution <- function(network, fit_powerlaw = TRUE) {

  degrees <- degree(network)
  degree_table <- as.data.frame(table(degrees))
  names(degree_table) <- c("degree", "frequency")
  degree_table$degree <- as.numeric(as.character(degree_table$degree))

  p <- ggplot(degree_table, aes(x = degree, y = frequency)) +
    geom_point(color = "#2171b5", size = 3, alpha = 0.7) +
    scale_x_log10(labels = comma) +
    scale_y_log10(labels = comma) +
    labs(
      title = "Degree Distribution (Log-Log Scale)",
      subtitle = sprintf("Network: %d nodes, %d edges", vcount(network), ecount(network)),
      x = "Degree (k)",
      y = "Frequency P(k)"
    ) +
    theme_minimal() +
    theme(
      plot.title = element_text(face = "bold", size = 14),
      axis.title = element_text(size = 12)
    )

  # Add power law fit if requested
  if (fit_powerlaw && nrow(degree_table) > 5) {
    tryCatch({
      # Simple linear fit in log-log space
      fit <- lm(log10(frequency) ~ log10(degree), data = degree_table)
      slope <- coef(fit)[2]

      # Add fitted line
      p <- p +
        geom_smooth(method = "lm", se = FALSE, color = "#d94801", linetype = "dashed") +
        annotate("text",
                x = max(degree_table$degree) * 0.5,
                y = max(degree_table$frequency) * 0.1,
                label = sprintf("Power law exponent: %.2f", -slope),
                hjust = 0, color = "#d94801", size = 4)
    }, error = function(e) {
      # Silently skip if fitting fails
    })
  }

  return(p)
}

#' Plot Community Network
#'
#' Visualizes network with nodes colored by community and positioned
#' to highlight community structure.
#'
#' @param network igraph object
#' @param community_membership Community membership vector
#' @param layout Layout method. Default "fr"
#'
#' @return ggplot object
#'
#' @export
plot_community_network <- function(network,
                                   community_membership,
                                   layout = "fr") {

  # Add community to network
  V(network)$community <- as.factor(community_membership)

  # Convert to tidygraph
  tidy_g <- as_tbl_graph(network)

  # Generate community colors
  n_comm <- max(community_membership)
  if (n_comm <= 12) {
    colors <- brewer.pal(max(3, n_comm), "Set3")
  } else {
    colors <- rainbow(n_comm)
  }

  # Create plot
  p <- ggraph(tidy_g, layout = layout) +
    geom_edge_link(alpha = 0.2, color = "#636363") +
    geom_node_point(aes(color = community, size = degree(network)), alpha = 0.8) +
    scale_color_manual(values = colors) +
    scale_size_continuous(range = c(2, 10)) +
    labs(
      title = "Community Structure",
      subtitle = sprintf("%d communities detected", n_comm),
      color = "Community",
      size = "Degree"
    ) +
    theme_graph() +
    theme(
      plot.title = element_text(face = "bold", size = 14),
      legend.position = "right"
    )

  return(p)
}

#' Create Network Summary Statistics Table
#'
#' Generates a formatted table of key network statistics suitable for
#' display in Shiny or reports.
#'
#' @param network igraph object
#' @param metrics_list Optional pre-calculated metrics from calculate_network_metrics()
#'
#' @return Data frame with formatted statistics
#'
#' @export
create_network_summary_table <- function(network, metrics_list = NULL) {

  if (is.null(metrics_list)) {
    source("R/analytics/network_backbone.R")
    metrics_list <- calculate_network_metrics(network)
  }

  summary_df <- data.frame(
    Metric = c(
      "Nodes",
      "Edges",
      "Density",
      "Components",
      "Largest Component",
      "Mean Degree",
      "Max Degree",
      "Clustering (Global)",
      "Clustering (Average)",
      "Diameter",
      "Avg Path Length",
      "Communities",
      "Modularity"
    ),
    Value = c(
      format(metrics_list$n_nodes, big.mark = ","),
      format(metrics_list$n_edges, big.mark = ","),
      sprintf("%.6f", metrics_list$density),
      format(metrics_list$n_components, big.mark = ","),
      sprintf("%s (%.1f%%)",
             format(metrics_list$largest_component_size, big.mark = ","),
             metrics_list$largest_component_pct),
      sprintf("%.2f", metrics_list$mean_degree),
      format(metrics_list$max_degree, big.mark = ","),
      sprintf("%.4f", metrics_list$transitivity_global %||% NA),
      sprintf("%.4f", metrics_list$transitivity_average %||% NA),
      format(metrics_list$diameter %||% NA, big.mark = ","),
      sprintf("%.4f", metrics_list$average_path_length %||% NA),
      format(metrics_list$n_communities %||% NA, big.mark = ","),
      sprintf("%.4f", metrics_list$modularity %||% NA)
    ),
    stringsAsFactors = FALSE
  )

  return(summary_df)
}

# Define %||% operator if not available
if (!exists("%||%")) {
  `%||%` <- function(a, b) if (is.null(a) || is.na(a)) b else a
}

cat("Network visualization module loaded successfully\n")
