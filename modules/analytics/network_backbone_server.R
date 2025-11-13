# ==============================================================================
# NETWORK BACKBONE ANALYSIS - SERVER MODULE
# ==============================================================================
# Monitor Legislativo v4 - Network Analysis Server Logic
#
# This Shiny module provides the server-side logic for network backbone
# extraction, including network construction, backbone extraction,
# visualization rendering, and data export.
# ==============================================================================

# Load required modules
if (file.exists("R/analytics/network_backbone.R")) {
  source("R/analytics/network_backbone.R")
}
if (file.exists("R/analytics/backbone_visualization.R")) {
  source("R/analytics/backbone_visualization.R")
}

#' Network Backbone Server Module
#'
#' @param id Module namespace ID
#' @param db_connection Reactive expression returning database connection pool
#'
#' @export
network_backbone_server <- function(id, db_connection) {
  moduleServer(id, function(input, output, session) {

    # Reactive values to store network states
    rv <- reactiveValues(
      original_network = NULL,
      backbone_network = NULL,
      current_network = NULL,
      metrics = NULL,
      communities = NULL,
      influential_nodes = NULL,
      status_message = NULL,
      status_type = "info"
    )

    # ===========================================================================
    # NETWORK CONSTRUCTION
    # ===========================================================================

    # Build Network
    observeEvent(input$build_network, {

      req(db_connection())

      # Show progress
      rv$status_message <- "Building network... This may take a few minutes."
      rv$status_type <- "info"

      # Build date range
      date_range <- c(
        paste0(input$year_range[1], "-01-01"),
        paste0(input$year_range[2], "-12-31")
      )

      # Determine max documents based on sampling
      max_docs <- if (input$enable_sampling) input$max_nodes else NULL

      tryCatch({
        # Build network based on type
        if (input$network_type == "citation") {

          rv$original_network <- build_citation_network(
            db_connection = db_connection(),
            min_citations = input$min_citations,
            include_metadata = TRUE,
            max_documents = max_docs,
            date_range = date_range
          )

        } else if (input$network_type == "coauthorship") {

          rv$original_network <- build_coauthorship_network(
            db_connection = db_connection(),
            min_collaborations = input$min_citations,
            date_range = date_range
          )

        } else if (input$network_type == "topic") {

          # Parse topic keywords
          topics_raw <- strsplit(input$topic_keywords, "\n")[[1]]
          topics_raw <- topics_raw[nchar(trimws(topics_raw)) > 0]

          topics_list <- lapply(seq_along(topics_raw), function(i) {
            keywords <- strsplit(topics_raw[i], "\\|")[[1]]
            keywords <- trimws(keywords)
            keywords[nchar(keywords) > 0]
          })
          names(topics_list) <- paste0("topic_", seq_along(topics_list))

          rv$original_network <- build_topic_network(
            db_connection = db_connection(),
            topics_keywords = topics_list,
            min_shared_topics = input$min_citations
          )

        }

        # Set current network to original
        rv$current_network <- rv$original_network
        rv$backbone_network <- NULL

        # Calculate initial metrics
        if (!is.null(rv$original_network)) {
          rv$metrics <- calculate_network_metrics(
            rv$original_network,
            include_communities = TRUE,
            community_method = input$community_method
          )

          rv$status_message <- sprintf(
            "Network built successfully! %d nodes, %d edges. Density: %.6f",
            vcount(rv$original_network),
            ecount(rv$original_network),
            edge_density(rv$original_network)
          )
          rv$status_type <- "success"

        } else {
          rv$status_message <- "Network construction failed. Please check your filters and try again."
          rv$status_type <- "error"
        }

      }, error = function(e) {
        rv$status_message <- paste("Error building network:", e$message)
        rv$status_type <- "error"
      })
    })

    # Extract Backbone
    observeEvent(input$extract_backbone, {

      req(rv$original_network)

      rv$status_message <- "Extracting network backbone..."
      rv$status_type <- "info"

      tryCatch({
        rv$backbone_network <- extract_backbone(
          network = rv$original_network,
          alpha = input$alpha_threshold,
          method = input$backbone_method,
          directed = is_directed(rv$original_network)
        )

        # Set current network to backbone
        rv$current_network <- rv$backbone_network

        # Recalculate metrics for backbone
        rv$metrics <- calculate_network_metrics(
          rv$backbone_network,
          include_communities = TRUE,
          community_method = input$community_method
        )

        # Calculate reduction statistics
        orig_edges <- ecount(rv$original_network)
        backbone_edges <- ecount(rv$backbone_network)
        reduction <- 100 * (1 - backbone_edges / orig_edges)

        rv$status_message <- sprintf(
          "Backbone extracted! Reduced from %d to %d edges (%.1f%% reduction)",
          orig_edges, backbone_edges, reduction
        )
        rv$status_type <- "success"

      }, error = function(e) {
        rv$status_message <- paste("Error extracting backbone:", e$message)
        rv$status_type <- "error"
      })
    })

    # ===========================================================================
    # STATUS MESSAGE DISPLAY
    # ===========================================================================

    output$status_message <- renderUI({
      req(rv$status_message)

      alert_class <- switch(rv$status_type,
        "success" = "alert-success",
        "error" = "alert-danger",
        "warning" = "alert-warning",
        "info" = "alert-info",
        "alert-info"
      )

      icon_name <- switch(rv$status_type,
        "success" = "check-circle",
        "error" = "exclamation-triangle",
        "warning" = "exclamation-circle",
        "info" = "info-circle",
        "info-circle"
      )

      div(
        class = paste("alert", alert_class),
        icon(icon_name),
        " ",
        rv$status_message
      )
    })

    # ===========================================================================
    # VISUALIZATIONS
    # ===========================================================================

    # Interactive Network
    output$interactive_network <- renderVisNetwork({
      req(rv$current_network)

      plot_interactive_network(
        network = rv$current_network,
        layout = input$layout_algorithm,
        node_size_by = input$node_size_by,
        node_color_by = input$node_color_by,
        community_method = input$community_method,
        max_nodes = if (input$enable_sampling) input$max_nodes else 500,
        show_labels = input$show_labels,
        label_threshold = if (input$show_labels) input$label_threshold else 0
      )
    })

    # Network Metrics Table
    output$metrics_table <- DT::renderDataTable({
      req(rv$metrics)

      metrics_df <- create_network_summary_table(
        network = rv$current_network,
        metrics_list = rv$metrics
      )

      DT::datatable(
        metrics_df,
        options = list(
          pageLength = 15,
          dom = 't',
          ordering = FALSE
        ),
        rownames = FALSE,
        class = 'cell-border stripe'
      )
    })

    # Metrics Dashboard
    output$metrics_dashboard <- renderPlot({
      req(rv$current_network)

      plot_network_metrics_dashboard(
        network = rv$current_network,
        community_method = input$community_method
      )
    })

    # ===========================================================================
    # INFLUENTIAL NODES
    # ===========================================================================

    observeEvent(input$calculate_influential, {
      req(rv$current_network)

      tryCatch({
        rv$influential_nodes <- identify_influential_nodes(
          network = rv$current_network,
          top_n = input$top_n_nodes
        )
      }, error = function(e) {
        showNotification(
          paste("Error calculating influential nodes:", e$message),
          type = "error"
        )
      })
    })

    output$influential_nodes_table <- DT::renderDataTable({
      req(rv$influential_nodes)

      DT::datatable(
        rv$influential_nodes,
        options = list(
          pageLength = 20,
          scrollX = TRUE,
          order = list(list(ncol(rv$influential_nodes) - 1, 'asc'))  # Sort by composite rank
        ),
        rownames = FALSE,
        class = 'cell-border stripe'
      ) %>%
        DT::formatRound(columns = grep("rank|degree|betweenness|pagerank|eigenvector",
                                      names(rv$influential_nodes)), digits = 4)
    })

    # ===========================================================================
    # COMMUNITY ANALYSIS
    # ===========================================================================

    output$community_plot <- renderPlot({
      req(rv$current_network)

      # Detect communities
      comm <- detect_communities(rv$current_network, method = input$community_method)

      if (!is.null(comm$membership)) {
        plot_community_network(
          network = rv$current_network,
          community_membership = comm$membership,
          layout = input$layout_algorithm
        )
      } else {
        plot.new()
        text(0.5, 0.5, "Community detection failed", cex = 1.5)
      }
    })

    output$community_sizes_plot <- renderPlot({
      req(rv$current_network)

      comm <- detect_communities(rv$current_network, method = input$community_method)

      if (!is.null(comm$sizes) && length(comm$sizes) > 0) {
        comm_df <- data.frame(
          community = factor(1:length(comm$sizes)),
          size = comm$sizes
        )

        ggplot(comm_df, aes(x = reorder(community, -size), y = size)) +
          geom_col(fill = "#3498db", alpha = 0.8) +
          geom_text(aes(label = size), vjust = -0.5, size = 3) +
          labs(
            title = sprintf("Community Sizes (%s algorithm)", input$community_method),
            subtitle = sprintf("Modularity: %.4f | %d communities",
                             comm$modularity, comm$n_communities),
            x = "Community",
            y = "Number of Nodes"
          ) +
          theme_minimal() +
          theme(
            plot.title = element_text(face = "bold", size = 14),
            axis.text.x = element_text(angle = 45, hjust = 1)
          )
      }
    })

    output$community_table <- DT::renderDataTable({
      req(rv$current_network)

      comm <- detect_communities(rv$current_network, method = input$community_method)

      if (!is.null(comm$membership)) {
        comm_df <- data.frame(
          node = V(rv$current_network)$name,
          label = if (!is.null(V(rv$current_network)$label)) {
            V(rv$current_network)$label
          } else {
            V(rv$current_network)$name
          },
          community = comm$membership,
          degree = degree(rv$current_network),
          stringsAsFactors = FALSE
        )

        DT::datatable(
          comm_df,
          options = list(
            pageLength = 25,
            order = list(list(2, 'asc'))  # Sort by community
          ),
          rownames = FALSE,
          filter = 'top',
          class = 'cell-border stripe'
        )
      }
    })

    # ===========================================================================
    # BACKBONE COMPARISON
    # ===========================================================================

    output$backbone_comparison <- renderPlot({
      req(rv$original_network, rv$backbone_network)

      plot_backbone_comparison(
        original_network = rv$original_network,
        backbone_network = rv$backbone_network,
        layout = input$layout_algorithm
      )
    })

    output$reduction_stats <- renderPrint({
      req(rv$original_network, rv$backbone_network)

      orig_nodes <- vcount(rv$original_network)
      orig_edges <- ecount(rv$original_network)
      orig_density <- edge_density(rv$original_network)

      back_nodes <- vcount(rv$backbone_network)
      back_edges <- ecount(rv$backbone_network)
      back_density <- edge_density(rv$backbone_network)

      cat("ORIGINAL NETWORK\n")
      cat(sprintf("  Nodes: %d\n", orig_nodes))
      cat(sprintf("  Edges: %d\n", orig_edges))
      cat(sprintf("  Density: %.6f\n\n", orig_density))

      cat("BACKBONE NETWORK\n")
      cat(sprintf("  Nodes: %d\n", back_nodes))
      cat(sprintf("  Edges: %d\n", back_edges))
      cat(sprintf("  Density: %.6f\n\n", back_density))

      cat("REDUCTION\n")
      cat(sprintf("  Node reduction: %.1f%%\n", 100 * (1 - back_nodes / orig_nodes)))
      cat(sprintf("  Edge reduction: %.1f%%\n", 100 * (1 - back_edges / orig_edges)))
      cat(sprintf("  Density change: %.1fx\n", back_density / orig_density))
    })

    output$degree_comparison <- renderPlot({
      req(rv$original_network, rv$backbone_network)

      # Combine degree distributions
      deg_df <- rbind(
        data.frame(
          network = "Original",
          degree = degree(rv$original_network)
        ),
        data.frame(
          network = "Backbone",
          degree = degree(rv$backbone_network)
        )
      )

      ggplot(deg_df, aes(x = degree, fill = network)) +
        geom_histogram(alpha = 0.6, position = "identity", bins = 30) +
        scale_fill_manual(values = c("Original" = "#3498db", "Backbone" = "#e74c3c")) +
        scale_x_log10(labels = scales::comma) +
        scale_y_log10(labels = scales::comma) +
        labs(
          title = "Degree Distribution Comparison",
          x = "Degree (log scale)",
          y = "Frequency (log scale)",
          fill = "Network"
        ) +
        theme_minimal() +
        theme(
          plot.title = element_text(face = "bold"),
          legend.position = "top"
        )
    })

    # ===========================================================================
    # EXPORT HANDLERS
    # ===========================================================================

    # GEXF Export (from main network tab)
    output$download_gexf <- downloadHandler(
      filename = function() {
        paste0("network_backbone_", Sys.Date(), ".gexf")
      },
      content = function(file) {
        req(rv$current_network)
        export_network_for_gephi(
          network = rv$current_network,
          filename = file,
          layout_method = input$layout_algorithm
        )
      }
    )

    # GraphML Export
    output$download_graphml <- downloadHandler(
      filename = function() {
        paste0("network_", Sys.Date(), ".graphml")
      },
      content = function(file) {
        req(rv$current_network)
        write_graph(rv$current_network, file, format = "graphml")
      }
    )

    # GEXF Export (from export tab)
    output$download_gexf_export <- downloadHandler(
      filename = function() {
        paste0("network_", Sys.Date(), ".gexf")
      },
      content = function(file) {
        req(rv$current_network)
        export_network_for_gephi(
          network = rv$current_network,
          filename = file,
          layout_method = input$layout_algorithm
        )
      }
    )

    # Edge List CSV
    output$download_edgelist <- downloadHandler(
      filename = function() {
        paste0("network_edgelist_", Sys.Date(), ".csv")
      },
      content = function(file) {
        req(rv$current_network)
        edge_df <- as_data_frame(rv$current_network, what = "edges")
        write.csv(edge_df, file, row.names = FALSE)
      }
    )

    # Metrics CSV
    output$download_metrics <- downloadHandler(
      filename = function() {
        paste0("network_metrics_", Sys.Date(), ".csv")
      },
      content = function(file) {
        req(rv$metrics)
        metrics_df <- create_network_summary_table(
          network = rv$current_network,
          metrics_list = rv$metrics
        )
        write.csv(metrics_df, file, row.names = FALSE)
      }
    )

    # Centrality Scores CSV
    output$download_centrality <- downloadHandler(
      filename = function() {
        paste0("centrality_scores_", Sys.Date(), ".csv")
      },
      content = function(file) {
        req(rv$current_network)

        centrality_df <- data.frame(
          node = V(rv$current_network)$name,
          label = if (!is.null(V(rv$current_network)$label)) {
            V(rv$current_network)$label
          } else {
            V(rv$current_network)$name
          },
          degree = degree(rv$current_network),
          betweenness = betweenness(rv$current_network, normalized = TRUE),
          pagerank = page_rank(rv$current_network)$vector,
          stringsAsFactors = FALSE
        )

        write.csv(centrality_df, file, row.names = FALSE)
      }
    )

    # Community Assignments CSV
    output$download_communities <- downloadHandler(
      filename = function() {
        paste0("community_assignments_", Sys.Date(), ".csv")
      },
      content = function(file) {
        req(rv$current_network)

        comm <- detect_communities(rv$current_network, method = input$community_method)

        if (!is.null(comm$membership)) {
          comm_df <- data.frame(
            node = V(rv$current_network)$name,
            label = if (!is.null(V(rv$current_network)$label)) {
              V(rv$current_network)$label
            } else {
              V(rv$current_network)$name
            },
            community = comm$membership,
            stringsAsFactors = FALSE
          )

          write.csv(comm_df, file, row.names = FALSE)
        }
      }
    )

    # Network Plot PNG
    output$download_network_plot <- downloadHandler(
      filename = function() {
        paste0("network_plot_", Sys.Date(), ".png")
      },
      content = function(file) {
        req(rv$current_network)

        # Create ggraph plot
        comm <- detect_communities(rv$current_network, method = input$community_method)

        p <- plot_community_network(
          network = rv$current_network,
          community_membership = comm$membership,
          layout = input$layout_algorithm
        )

        ggsave(file, plot = p, width = 12, height = 10, dpi = 300)
      }
    )

    # Metrics Dashboard PNG
    output$download_metrics_plot <- downloadHandler(
      filename = function() {
        paste0("metrics_dashboard_", Sys.Date(), ".png")
      },
      content = function(file) {
        req(rv$current_network)

        png(file, width = 12, height = 10, units = "in", res = 300)
        plot_network_metrics_dashboard(
          network = rv$current_network,
          community_method = input$community_method
        )
        dev.off()
      }
    )

    # Backbone Comparison PNG
    output$download_comparison_plot <- downloadHandler(
      filename = function() {
        paste0("backbone_comparison_", Sys.Date(), ".png")
      },
      content = function(file) {
        req(rv$original_network, rv$backbone_network)

        png(file, width = 14, height = 7, units = "in", res = 300)
        plot_backbone_comparison(
          original_network = rv$original_network,
          backbone_network = rv$backbone_network,
          layout = input$layout_algorithm
        )
        dev.off()
      }
    )

  })
}

cat("Network backbone server module loaded\n")
