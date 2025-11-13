# ==============================================================================
# NETWORK BACKBONE EXTRACTION - PERFORMANCE BENCHMARKS
# ==============================================================================
# Monitor Legislativo v4 - Performance Testing and Benchmarking
#
# This script provides comprehensive performance benchmarks for the network
# backbone extraction system, measuring execution times, memory usage, and
# scalability across different network sizes.
# ==============================================================================

suppressPackageStartupMessages({
  library(igraph)
  library(dplyr)
  library(ggplot2)
  library(microbenchmark)
  library(profvis)
})

# Load network modules
if (file.exists("R/analytics/network_backbone.R")) {
  source("R/analytics/network_backbone.R")
}
if (file.exists("R/database/connection.R")) {
  source("R/database/connection.R")
}

# ==============================================================================
# SYNTHETIC NETWORK GENERATION FOR TESTING
# ==============================================================================

#' Generate Synthetic Citation Network
#'
#' Creates a synthetic citation network for benchmarking purposes.
#' Uses Barabási-Albert preferential attachment model.
#'
#' @param n_nodes Number of nodes
#' @param power Power of preferential attachment (default: 1)
#' @param m Number of edges to add per new node (default: 2)
#'
#' @return igraph object
generate_synthetic_citation_network <- function(n_nodes, power = 1, m = 2) {

  cat(sprintf("Generating synthetic citation network with %d nodes...\n", n_nodes))

  # Generate scale-free network (similar to real citation networks)
  g <- sample_pa(
    n = n_nodes,
    power = power,
    m = m,
    directed = TRUE
  )

  # Add weights (citation counts)
  E(g)$weight <- sample(1:10, ecount(g), replace = TRUE)

  # Add node attributes
  V(g)$name <- paste0("doc_", 1:n_nodes)
  V(g)$titulo <- paste("Document", 1:n_nodes)
  V(g)$tipo <- sample(c("lei", "decreto", "resolucao"), n_nodes, replace = TRUE)
  V(g)$ano <- sample(2010:2023, n_nodes, replace = TRUE)

  cat(sprintf("  Generated: %d nodes, %d edges\n", vcount(g), ecount(g)))

  return(g)
}

# ==============================================================================
# BENCHMARK 1: NETWORK CONSTRUCTION TIME
# ==============================================================================

#' Benchmark Network Construction
#'
#' Measures time to build networks of varying sizes
benchmark_network_construction <- function() {

  cat("\n")
  cat("="*80, "\n")
  cat("BENCHMARK 1: Network Construction Time\n")
  cat("="*80, "\n\n")

  network_sizes <- c(100, 500, 1000, 5000, 10000)
  results <- data.frame(
    n_nodes = integer(),
    n_edges = integer(),
    time_seconds = numeric(),
    memory_mb = numeric()
  )

  for (n in network_sizes) {
    cat(sprintf("\nTesting with %d nodes...\n", n))

    # Measure memory before
    gc()
    mem_before <- as.numeric(mem_used()) / 1024^2

    # Time network generation
    start_time <- Sys.time()

    net <- generate_synthetic_citation_network(n, m = 3)

    end_time <- Sys.time()
    elapsed <- as.numeric(difftime(end_time, start_time, units = "secs"))

    # Measure memory after
    gc()
    mem_after <- as.numeric(mem_used()) / 1024^2
    mem_used_mb <- mem_after - mem_before

    results <- rbind(results, data.frame(
      n_nodes = vcount(net),
      n_edges = ecount(net),
      time_seconds = elapsed,
      memory_mb = mem_used_mb
    ))

    cat(sprintf("  Completed in %.2f seconds\n", elapsed))
    cat(sprintf("  Memory used: %.2f MB\n", mem_used_mb))
  }

  # Plot results
  p1 <- ggplot(results, aes(x = n_nodes, y = time_seconds)) +
    geom_line(color = "#2171b5", size = 1) +
    geom_point(color = "#2171b5", size = 3) +
    scale_x_log10(labels = scales::comma) +
    scale_y_continuous(labels = scales::comma) +
    labs(
      title = "Network Construction Time vs. Size",
      x = "Number of Nodes",
      y = "Time (seconds)"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(face = "bold"))

  p2 <- ggplot(results, aes(x = n_nodes, y = memory_mb)) +
    geom_line(color = "#31a354", size = 1) +
    geom_point(color = "#31a354", size = 3) +
    scale_x_log10(labels = scales::comma) +
    scale_y_continuous(labels = scales::comma) +
    labs(
      title = "Memory Usage vs. Network Size",
      x = "Number of Nodes",
      y = "Memory (MB)"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(face = "bold"))

  print(results)

  return(list(
    results = results,
    plot_time = p1,
    plot_memory = p2
  ))
}

# ==============================================================================
# BENCHMARK 2: BACKBONE EXTRACTION TIME
# ==============================================================================

#' Benchmark Backbone Extraction
#'
#' Compares performance of different backbone extraction methods
benchmark_backbone_extraction <- function() {

  cat("\n")
  cat("="*80, "\n")
  cat("BENCHMARK 2: Backbone Extraction Time\n")
  cat("="*80, "\n\n")

  # Test network sizes
  network_sizes <- c(1000, 5000, 10000)
  methods <- c("disparity", "significance", "degree")
  alpha_values <- c(0.01, 0.05, 0.10)

  results <- data.frame(
    n_nodes = integer(),
    n_edges = integer(),
    method = character(),
    alpha = numeric(),
    time_seconds = numeric(),
    edges_removed_pct = numeric(),
    stringsAsFactors = FALSE
  )

  for (n in network_sizes) {
    cat(sprintf("\n--- Testing with %d node network ---\n", n))

    # Generate test network
    net <- generate_synthetic_citation_network(n, m = 3)
    original_edges <- ecount(net)

    for (method in methods) {
      for (alpha in alpha_values) {

        cat(sprintf("\n  Method: %s, Alpha: %.2f\n", method, alpha))

        # Time backbone extraction
        start_time <- Sys.time()

        tryCatch({
          backbone <- extract_backbone(
            network = net,
            alpha = alpha,
            method = method
          )

          end_time <- Sys.time()
          elapsed <- as.numeric(difftime(end_time, start_time, units = "secs"))

          backbone_edges <- ecount(backbone)
          reduction_pct <- 100 * (1 - backbone_edges / original_edges)

          results <- rbind(results, data.frame(
            n_nodes = vcount(net),
            n_edges = original_edges,
            method = method,
            alpha = alpha,
            time_seconds = elapsed,
            edges_removed_pct = reduction_pct,
            stringsAsFactors = FALSE
          ))

          cat(sprintf("    Time: %.2f seconds\n", elapsed))
          cat(sprintf("    Edges removed: %.1f%%\n", reduction_pct))

        }, error = function(e) {
          cat(sprintf("    ERROR: %s\n", e$message))
        })
      }
    }
  }

  # Plot results
  p <- ggplot(results, aes(x = n_nodes, y = time_seconds, color = method, linetype = factor(alpha))) +
    geom_line(size = 1) +
    geom_point(size = 2) +
    scale_x_log10(labels = scales::comma) +
    scale_y_log10() +
    scale_color_brewer(palette = "Set1") +
    labs(
      title = "Backbone Extraction Time by Method and Alpha",
      x = "Number of Nodes",
      y = "Time (seconds, log scale)",
      color = "Method",
      linetype = "Alpha"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(face = "bold"))

  print(results)

  return(list(
    results = results,
    plot = p
  ))
}

# ==============================================================================
# BENCHMARK 3: CENTRALITY CALCULATION TIME
# ==============================================================================

#' Benchmark Centrality Metrics Calculation
#'
#' Measures time to compute different centrality metrics
benchmark_centrality_metrics <- function() {

  cat("\n")
  cat("="*80, "\n")
  cat("BENCHMARK 3: Centrality Metrics Calculation\n")
  cat("="*80, "\n\n")

  network_sizes <- c(500, 1000, 2000, 5000)
  metrics <- c("degree", "betweenness", "closeness", "pagerank", "eigenvector")

  results <- data.frame(
    n_nodes = integer(),
    metric = character(),
    time_seconds = numeric(),
    stringsAsFactors = FALSE
  )

  for (n in network_sizes) {
    cat(sprintf("\n--- Testing with %d node network ---\n", n))

    net <- generate_synthetic_citation_network(n, m = 3)

    for (metric in metrics) {
      cat(sprintf("  Computing %s...\n", metric))

      # Benchmark the centrality calculation
      bench_result <- microbenchmark(
        {
          if (metric == "degree") {
            degree(net)
          } else if (metric == "betweenness") {
            betweenness(net, normalized = TRUE)
          } else if (metric == "closeness") {
            closeness(net, normalized = TRUE)
          } else if (metric == "pagerank") {
            page_rank(net)
          } else if (metric == "eigenvector") {
            eigen_centrality(net)
          }
        },
        times = 5,
        unit = "s"
      )

      median_time <- median(bench_result$time) / 1e9  # Convert to seconds

      results <- rbind(results, data.frame(
        n_nodes = vcount(net),
        metric = metric,
        time_seconds = median_time,
        stringsAsFactors = FALSE
      ))

      cat(sprintf("    Median time: %.3f seconds\n", median_time))
    }
  }

  # Plot results
  p <- ggplot(results, aes(x = n_nodes, y = time_seconds, color = metric)) +
    geom_line(size = 1) +
    geom_point(size = 2) +
    scale_x_log10(labels = scales::comma) +
    scale_y_log10() +
    scale_color_brewer(palette = "Set2") +
    labs(
      title = "Centrality Calculation Time by Metric",
      x = "Number of Nodes",
      y = "Time (seconds, log scale)",
      color = "Metric"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(face = "bold"))

  print(results)

  return(list(
    results = results,
    plot = p
  ))
}

# ==============================================================================
# BENCHMARK 4: COMMUNITY DETECTION TIME
# ==============================================================================

#' Benchmark Community Detection Algorithms
benchmark_community_detection <- function() {

  cat("\n")
  cat("="*80, "\n")
  cat("BENCHMARK 4: Community Detection Algorithms\n")
  cat("="*80, "\n\n")

  network_sizes <- c(500, 1000, 2000, 5000, 10000)
  methods <- c("louvain", "infomap", "walktrap", "leiden")

  results <- data.frame(
    n_nodes = integer(),
    method = character(),
    time_seconds = numeric(),
    n_communities = integer(),
    modularity = numeric(),
    stringsAsFactors = FALSE
  )

  for (n in network_sizes) {
    cat(sprintf("\n--- Testing with %d node network ---\n", n))

    net <- generate_synthetic_citation_network(n, m = 3)

    for (method in methods) {
      cat(sprintf("  Method: %s\n", method))

      start_time <- Sys.time()

      tryCatch({
        comm <- detect_communities(net, method = method)

        end_time <- Sys.time()
        elapsed <- as.numeric(difftime(end_time, start_time, units = "secs"))

        results <- rbind(results, data.frame(
          n_nodes = vcount(net),
          method = method,
          time_seconds = elapsed,
          n_communities = comm$n_communities,
          modularity = comm$modularity,
          stringsAsFactors = FALSE
        ))

        cat(sprintf("    Time: %.2f seconds\n", elapsed))
        cat(sprintf("    Communities: %d, Modularity: %.4f\n",
                   comm$n_communities, comm$modularity))

      }, error = function(e) {
        cat(sprintf("    ERROR: %s\n", e$message))
      })
    }
  }

  # Plot results
  p <- ggplot(results, aes(x = n_nodes, y = time_seconds, color = method)) +
    geom_line(size = 1) +
    geom_point(size = 2) +
    scale_x_log10(labels = scales::comma) +
    scale_y_log10() +
    scale_color_brewer(palette = "Dark2") +
    labs(
      title = "Community Detection Time by Algorithm",
      x = "Number of Nodes",
      y = "Time (seconds, log scale)",
      color = "Algorithm"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(face = "bold"))

  print(results)

  return(list(
    results = results,
    plot = p
  ))
}

# ==============================================================================
# BENCHMARK 5: VISUALIZATION RENDERING TIME
# ==============================================================================

#' Benchmark Visualization Rendering
benchmark_visualization <- function() {

  cat("\n")
  cat("="*80, "\n")
  cat("BENCHMARK 5: Visualization Rendering Time\n")
  cat("="*80, "\n\n")

  network_sizes <- c(100, 500, 1000, 2000)
  layout_methods <- c("fr", "kk", "drl")

  results <- data.frame(
    n_nodes = integer(),
    layout_method = character(),
    layout_time = numeric(),
    render_time = numeric(),
    stringsAsFactors = FALSE
  )

  for (n in network_sizes) {
    cat(sprintf("\n--- Testing with %d node network ---\n", n))

    net <- generate_synthetic_citation_network(n, m = 3)

    for (layout in layout_methods) {
      cat(sprintf("  Layout: %s\n", layout))

      # Time layout calculation
      start_layout <- Sys.time()

      coords <- switch(layout,
        "fr" = layout_with_fr(net),
        "kk" = layout_with_kk(net),
        "drl" = layout_with_drl(net)
      )

      end_layout <- Sys.time()
      layout_time <- as.numeric(difftime(end_layout, start_layout, units = "secs"))

      # Time rendering (static plot)
      start_render <- Sys.time()

      # Create simple ggraph plot
      suppressWarnings({
        p <- ggraph(net, layout = "manual", x = coords[,1], y = coords[,2]) +
          geom_edge_link(alpha = 0.2) +
          geom_node_point(size = 2) +
          theme_void()
      })

      end_render <- Sys.time()
      render_time <- as.numeric(difftime(end_render, start_render, units = "secs"))

      results <- rbind(results, data.frame(
        n_nodes = vcount(net),
        layout_method = layout,
        layout_time = layout_time,
        render_time = render_time,
        stringsAsFactors = FALSE
      ))

      cat(sprintf("    Layout time: %.2f seconds\n", layout_time))
      cat(sprintf("    Render time: %.2f seconds\n", render_time))
    }
  }

  # Plot results
  results_long <- results %>%
    tidyr::pivot_longer(cols = c(layout_time, render_time),
                       names_to = "operation",
                       values_to = "time")

  p <- ggplot(results_long, aes(x = n_nodes, y = time, fill = operation)) +
    geom_col(position = "stack") +
    facet_wrap(~layout_method) +
    scale_fill_brewer(palette = "Pastel1") +
    labs(
      title = "Visualization Time: Layout + Rendering",
      x = "Number of Nodes",
      y = "Time (seconds)",
      fill = "Operation"
    ) +
    theme_minimal() +
    theme(plot.title = element_text(face = "bold"))

  print(results)

  return(list(
    results = results,
    plot = p
  ))
}

# ==============================================================================
# MASTER BENCHMARK RUNNER
# ==============================================================================

#' Run All Benchmarks
#'
#' Executes all benchmark tests and generates comprehensive report
#'
#' @param save_results Save results to files? Default TRUE
#' @param output_dir Directory for output files
#'
#' @export
run_all_benchmarks <- function(save_results = TRUE,
                               output_dir = "benchmarks") {

  cat("\n")
  cat("##############################################################################\n")
  cat("##                                                                          ##\n")
  cat("##           NETWORK BACKBONE EXTRACTION - PERFORMANCE BENCHMARKS          ##\n")
  cat("##                      Monitor Legislativo v4                             ##\n")
  cat("##                                                                          ##\n")
  cat("##############################################################################\n")
  cat("\n")
  cat(sprintf("Started: %s\n", Sys.time()))
  cat("\n")

  # Create output directory
  if (save_results && !dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE)
    cat(sprintf("Created output directory: %s\n\n", output_dir))
  }

  # Run benchmarks
  bench1 <- benchmark_network_construction()
  bench2 <- benchmark_backbone_extraction()
  bench3 <- benchmark_centrality_metrics()
  bench4 <- benchmark_community_detection()
  bench5 <- benchmark_visualization()

  # Save results
  if (save_results) {
    cat("\n")
    cat("Saving results...\n")

    # Save CSV files
    write.csv(bench1$results,
              file.path(output_dir, "network_construction_results.csv"),
              row.names = FALSE)
    write.csv(bench2$results,
              file.path(output_dir, "backbone_extraction_results.csv"),
              row.names = FALSE)
    write.csv(bench3$results,
              file.path(output_dir, "centrality_metrics_results.csv"),
              row.names = FALSE)
    write.csv(bench4$results,
              file.path(output_dir, "community_detection_results.csv"),
              row.names = FALSE)
    write.csv(bench5$results,
              file.path(output_dir, "visualization_results.csv"),
              row.names = FALSE)

    # Save plots
    ggsave(file.path(output_dir, "plot_construction_time.png"),
           plot = bench1$plot_time, width = 10, height = 6, dpi = 300)
    ggsave(file.path(output_dir, "plot_construction_memory.png"),
           plot = bench1$plot_memory, width = 10, height = 6, dpi = 300)
    ggsave(file.path(output_dir, "plot_backbone_extraction.png"),
           plot = bench2$plot, width = 12, height = 7, dpi = 300)
    ggsave(file.path(output_dir, "plot_centrality_metrics.png"),
           plot = bench3$plot, width = 12, height = 7, dpi = 300)
    ggsave(file.path(output_dir, "plot_community_detection.png"),
           plot = bench4$plot, width = 12, height = 7, dpi = 300)
    ggsave(file.path(output_dir, "plot_visualization.png"),
           plot = bench5$plot, width = 12, height = 7, dpi = 300)

    cat(sprintf("\nResults saved to: %s\n", output_dir))
  }

  cat("\n")
  cat("##############################################################################\n")
  cat("##                        BENCHMARKS COMPLETE                               ##\n")
  cat("##############################################################################\n")
  cat("\n")
  cat(sprintf("Completed: %s\n", Sys.time()))
  cat("\n")

  return(list(
    construction = bench1,
    backbone = bench2,
    centrality = bench3,
    community = bench4,
    visualization = bench5
  ))
}

# Helper function for memory measurement
mem_used <- function() {
  sum(gc()[, 2])
}

cat("Network backbone benchmarking module loaded\n")
cat("Run: run_all_benchmarks() to execute all performance tests\n")
