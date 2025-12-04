#' Text Reuse Detection Server Module
#'
#' Shiny module server logic for text reuse analysis
#'
#' @author Monitor Legislativo Analytics Team
#' @date 2025-01-13

library(shiny)
library(DBI)
library(dplyr)
library(visNetwork)
library(networkD3)
library(plotly)
library(DT)
library(igraph)
library(htmltools)

text_reuse_server <- function(id, db_connection) {
  moduleServer(id, function(input, output, session) {

    # Reactive values to store results
    rv <- reactiveValues(
      similar_docs = NULL,
      clusters = NULL,
      jurisdiction_data = NULL,
      timeline_data = NULL,
      focal_doc_info = NULL,
      network_data = NULL,
      comparison_docs = NULL
    )

    # ========================================================================
    # SYSTEM INFO
    # ========================================================================

    output$system_info <- renderUI({
      req(db_connection())

      stats <- tryCatch({
        source("R/analytics/text_reuse_lsh.R")
        lsh_index_stats(db_connection())
      }, error = function(e) {
        list(
          total_indexed = 0,
          total_buckets = 0,
          total_pairs = 0
        )
      })

      tagList(
        div(strong("System Status")),
        div(sprintf("Indexed: %s docs", format(stats$total_indexed, big.mark = ","))),
        div(sprintf("LSH Buckets: %s", format(stats$total_buckets, big.mark = ","))),
        div(sprintf("Detected Pairs: %s", format(stats$total_pairs, big.mark = ",")))
      )
    })

    # ========================================================================
    # DOCUMENT SEARCH MODE
    # ========================================================================

    observeEvent(input$search_doc, {
      req(input$focal_doc_id)
      req(db_connection())

      source("R/analytics/text_reuse_lsh.R")

      showModal(modalDialog(
        title = "Searching...",
        "Finding similar documents...",
        footer = NULL,
        easyClose = FALSE
      ))

      tryCatch({
        # Get focal document info - use actual column names
        focal_info <- dbGetQuery(
          db_connection(),
          "SELECT id, titulo, COALESCE(ano, 0) as ano, COALESCE(nivel, 'N/A') as nivel, COALESCE(estado, 'N/A') as uf, tipo as tipo_documento FROM documents WHERE id = $1",
          params = list(input$focal_doc_id)
        )

        if (nrow(focal_info) == 0) {
          removeModal()
          showNotification("Document not found", type = "error")
          return()
        }

        rv$focal_doc_info <- focal_info

        # Find similar documents
        similar <- find_similar_documents(
          db_connection = db_connection(),
          document_id = input$focal_doc_id,
          threshold = input$similarity_threshold,
          max_results = 100
        )

        # Apply filters
        if (nrow(similar) > 0) {
          similar <- similar %>%
            filter(
              ano >= input$year_range[1],
              ano <= input$year_range[2],
              nivel %in% input$nivel_filter
            )
        }

        rv$similar_docs <- similar
        removeModal()

        showNotification(
          sprintf("Found %d similar documents", nrow(similar)),
          type = "message"
        )

      }, error = function(e) {
        removeModal()
        showNotification(paste("Error:", e$message), type = "error")
      })
    })

    # Display focal document info
    output$focal_doc_info <- renderUI({
      req(rv$focal_doc_info)

      doc <- rv$focal_doc_info

      div(
        class = "alert alert-info",
        h5(strong("Focal Document")),
        p(
          strong("ID:"), doc$id, br(),
          strong("Title:"), doc$titulo, br(),
          strong("Year:"), doc$ano, br(),
          strong("Level:"), jurisdiction_badge(doc$nivel),
          if (!is.na(doc$uf)) tagList(" - ", doc$uf),
          br(),
          strong("Type:"), doc$tipo_documento
        )
      )
    })

    # ========================================================================
    # CLUSTER DETECTION MODE
    # ========================================================================

    observeEvent(input$detect_clusters, {
      req(db_connection())

      source("R/analytics/text_reuse_lsh.R")

      showModal(modalDialog(
        title = "Detecting Clusters...",
        "This may take a few minutes...",
        footer = NULL,
        easyClose = FALSE
      ))

      tryCatch({
        clusters <- detect_text_reuse_clusters(
          db_connection = db_connection(),
          min_cluster_size = input$min_cluster_size,
          threshold = input$similarity_threshold
        )

        rv$clusters <- clusters
        removeModal()

        showNotification(
          sprintf("Found %d clusters", length(clusters)),
          type = "message"
        )

      }, error = function(e) {
        removeModal()
        showNotification(paste("Error:", e$message), type = "error")
      })
    })

    output$cluster_summary <- renderUI({
      req(rv$clusters)

      total_clusters <- length(rv$clusters)
      total_docs <- sum(sapply(rv$clusters, function(x) x$size))
      largest_cluster <- max(sapply(rv$clusters, function(x) x$size))
      avg_size <- mean(sapply(rv$clusters, function(x) x$size))

      div(
        class = "alert alert-success",
        h5(strong("Cluster Summary")),
        p(
          strong("Total Clusters:"), total_clusters, br(),
          strong("Documents in Clusters:"), total_docs, br(),
          strong("Largest Cluster:"), largest_cluster, "documents", br(),
          strong("Average Size:"), sprintf("%.1f documents", avg_size)
        )
      )
    })

    # ========================================================================
    # CROSS-JURISDICTION MODE
    # ========================================================================

    observeEvent(input$load_jurisdiction, {
      req(db_connection())

      source("R/analytics/text_reuse_lsh.R")

      showModal(modalDialog(
        title = "Loading Data...",
        "Analyzing cross-jurisdiction text reuse...",
        footer = NULL,
        easyClose = FALSE
      ))

      tryCatch({
        data <- cross_jurisdiction_reuse(
          db_connection = db_connection(),
          threshold = input$similarity_threshold
        )

        # Apply filters
        if (nrow(data) > 0) {
          data <- data %>%
            filter(
              doc1_ano >= input$year_range[1],
              doc1_ano <= input$year_range[2],
              doc2_ano >= input$year_range[1],
              doc2_ano <= input$year_range[2]
            )

          # Apply jurisdiction filter
          if (input$jurisdiction_filter != "all") {
            data <- data %>%
              filter(
                case_when(
                  input$jurisdiction_filter == "fed_state" ~
                    (doc1_nivel == "Federal" & doc2_nivel == "Estadual") |
                    (doc1_nivel == "Estadual" & doc2_nivel == "Federal"),
                  input$jurisdiction_filter == "state_state" ~
                    (doc1_nivel == "Estadual" & doc2_nivel == "Estadual" & doc1_uf != doc2_uf),
                  input$jurisdiction_filter == "state_muni" ~
                    (doc1_nivel == "Estadual" & doc2_nivel == "Municipal") |
                    (doc1_nivel == "Municipal" & doc2_nivel == "Estadual"),
                  input$jurisdiction_filter == "fed_muni" ~
                    (doc1_nivel == "Federal" & doc2_nivel == "Municipal") |
                    (doc1_nivel == "Municipal" & doc2_nivel == "Federal"),
                  TRUE ~ TRUE
                )
              )
          }
        }

        rv$jurisdiction_data <- data
        removeModal()

        showNotification(
          sprintf("Found %d cross-jurisdiction pairs", nrow(data)),
          type = "message"
        )

      }, error = function(e) {
        removeModal()
        showNotification(paste("Error:", e$message), type = "error")
      })
    })

    # ========================================================================
    # TIMELINE ANALYSIS MODE
    # ========================================================================

    observeEvent(input$analyze_timeline, {
      req(input$timeline_doc_id)
      req(db_connection())

      source("R/analytics/text_reuse_lsh.R")

      showModal(modalDialog(
        title = "Analyzing Timeline...",
        "Tracking text reuse over time...",
        footer = NULL,
        easyClose = FALSE
      ))

      tryCatch({
        timeline <- temporal_reuse_analysis(
          db_connection = db_connection(),
          focal_doc_id = input$timeline_doc_id,
          threshold = input$similarity_threshold
        )

        rv$timeline_data <- timeline
        rv$focal_doc_info <- timeline$focal_document
        removeModal()

        showNotification(
          sprintf("Found %d related documents", timeline$total_related),
          type = "message"
        )

      }, error = function(e) {
        removeModal()
        showNotification(paste("Error:", e$message), type = "error")
      })
    })

    # ========================================================================
    # RESULTS TABLE
    # ========================================================================

    output$results_table <- DT::renderDataTable({
      data <- switch(
        input$analysis_mode,
        "document" = rv$similar_docs,
        "clusters" = {
          if (is.null(rv$clusters) || length(rv$clusters) == 0) return(NULL)
          # Flatten clusters for table view
          do.call(rbind, lapply(1:length(rv$clusters), function(i) {
            cluster <- rv$clusters[[i]]
            cluster$documents %>%
              mutate(cluster_id = i, cluster_size = cluster$size, avg_similarity = cluster$avg_similarity)
          }))
        },
        "jurisdiction" = rv$jurisdiction_data,
        "timeline" = if (!is.null(rv$timeline_data)) rv$timeline_data$related_documents else NULL,
        NULL
      )

      req(data)

      if (input$analysis_mode == "document") {
        data %>%
          select(
            ID = similar_doc_id,
            Title = titulo,
            Year = ano,
            Level = nivel,
            Similarity = jaccard_similarity
          ) %>%
          datatable(
            options = list(
              pageLength = 25,
              order = list(list(4, 'desc'))  # Sort by similarity
            ),
            rownames = FALSE
          ) %>%
          formatPercentage('Similarity', 1)

      } else if (input$analysis_mode == "clusters") {
        data %>%
          select(
            `Cluster ID` = cluster_id,
            `Cluster Size` = cluster_size,
            `Doc ID` = id,
            Title = titulo,
            Year = ano,
            Level = nivel,
            UF = uf,
            `Avg Similarity` = avg_similarity
          ) %>%
          datatable(
            options = list(
              pageLength = 25,
              order = list(list(0, 'asc'))
            ),
            rownames = FALSE
          ) %>%
          formatPercentage('Avg Similarity', 1)

      } else if (input$analysis_mode == "jurisdiction") {
        data %>%
          select(
            `Doc 1` = doc1_id,
            `Title 1` = doc1_titulo,
            `Level 1` = doc1_nivel,
            `UF 1` = doc1_uf,
            `Year 1` = doc1_ano,
            `Doc 2` = doc2_id,
            `Title 2` = doc2_titulo,
            `Level 2` = doc2_nivel,
            `UF 2` = doc2_uf,
            `Year 2` = doc2_ano,
            Similarity = jaccard_similarity,
            `Reuse Type` = reuse_type
          ) %>%
          datatable(
            options = list(
              pageLength = 25,
              order = list(list(10, 'desc'))
            ),
            rownames = FALSE
          ) %>%
          formatPercentage('Similarity', 1)

      } else if (input$analysis_mode == "timeline") {
        data %>%
          select(
            `Doc ID` = related_doc_id,
            Title = titulo,
            Year = ano,
            Level = nivel,
            UF = uf,
            Similarity = jaccard_similarity,
            `Temporal Relation` = temporal_relation
          ) %>%
          datatable(
            options = list(
              pageLength = 25,
              order = list(list(2, 'asc'))  # Sort by year
            ),
            rownames = FALSE
          ) %>%
          formatPercentage('Similarity', 1)
      }
    })

    # ========================================================================
    # NETWORK VISUALIZATION
    # ========================================================================

    output$network_viz <- renderVisNetwork({
      data <- switch(
        input$analysis_mode,
        "document" = rv$similar_docs,
        "clusters" = rv$clusters,
        "jurisdiction" = rv$jurisdiction_data,
        "timeline" = if (!is.null(rv$timeline_data)) rv$timeline_data$related_documents else NULL,
        NULL
      )

      req(data)

      if (input$analysis_mode == "document") {
        req(rv$focal_doc_info)

        # Create network from focal document and similar docs
        nodes <- data.frame(
          id = c(rv$focal_doc_info$id, data$similar_doc_id),
          label = c(
            paste0("FOCAL: ", substr(rv$focal_doc_info$titulo, 1, 30)),
            paste0(data$similar_doc_id, ": ", substr(data$titulo, 1, 30))
          ),
          title = c(
            rv$focal_doc_info$titulo,
            data$titulo
          ),
          group = c(rv$focal_doc_info$nivel, data$nivel),
          value = c(20, data$jaccard_similarity * 15 + 5),  # Node size
          color = ifelse(
            c(rv$focal_doc_info$id, data$similar_doc_id) == rv$focal_doc_info$id,
            "#e74c3c",  # Red for focal
            "#3498db"   # Blue for others
          )
        )

        edges <- data.frame(
          from = rv$focal_doc_info$id,
          to = data$similar_doc_id,
          value = data$jaccard_similarity * 10,  # Edge width
          title = paste0("Similarity: ", round(data$jaccard_similarity * 100, 1), "%"),
          color = list(opacity = 0.5)
        )

      } else if (input$analysis_mode == "clusters" && !is.null(rv$clusters)) {

        # Build network from clusters
        all_nodes <- list()
        all_edges <- list()

        for (i in 1:min(5, length(rv$clusters))) {  # Show top 5 clusters
          cluster <- rv$clusters[[i]]
          cluster_docs <- cluster$documents

          # Add nodes
          for (j in 1:nrow(cluster_docs)) {
            all_nodes[[length(all_nodes) + 1]] <- data.frame(
              id = cluster_docs$id[j],
              label = paste0(cluster_docs$id[j]),
              title = cluster_docs$titulo[j],
              group = paste("Cluster", i),
              value = 10
            )
          }

          # Add edges (connect all pairs within cluster)
          if (nrow(cluster_docs) > 1) {
            for (j in 1:(nrow(cluster_docs) - 1)) {
              for (k in (j + 1):nrow(cluster_docs)) {
                all_edges[[length(all_edges) + 1]] <- data.frame(
                  from = cluster_docs$id[j],
                  to = cluster_docs$id[k],
                  value = 5,
                  title = paste0("Cluster ", i)
                )
              }
            }
          }
        }

        nodes <- do.call(rbind, all_nodes)
        edges <- if (length(all_edges) > 0) do.call(rbind, all_edges) else data.frame()

      } else if (input$analysis_mode == "jurisdiction") {
        req(rv$jurisdiction_data)

        # Create nodes from unique documents
        doc1_nodes <- rv$jurisdiction_data %>%
          select(id = doc1_id, titulo = doc1_titulo, nivel = doc1_nivel, uf = doc1_uf) %>%
          distinct()

        doc2_nodes <- rv$jurisdiction_data %>%
          select(id = doc2_id, titulo = doc2_titulo, nivel = doc2_nivel, uf = doc2_uf) %>%
          distinct()

        nodes <- rbind(doc1_nodes, doc2_nodes) %>%
          distinct() %>%
          mutate(
            label = paste0(nivel, "\n", ifelse(is.na(uf), "", uf)),
            title = titulo,
            group = nivel,
            value = 10
          )

        edges <- rv$jurisdiction_data %>%
          select(
            from = doc1_id,
            to = doc2_id,
            value = jaccard_similarity
          ) %>%
          mutate(
            value = value * 10,
            title = paste0("Similarity: ", round(value * 10, 1), "%")
          )

      } else {
        return(NULL)
      }

      # Render network
      visNetwork(nodes, edges) %>%
        visOptions(
          highlightNearest = list(enabled = TRUE, degree = 1),
          nodesIdSelection = TRUE
        ) %>%
        visPhysics(
          stabilization = TRUE,
          barnesHut = list(gravitationalConstant = -2000, springLength = 200)
        ) %>%
        visInteraction(
          navigationButtons = TRUE,
          zoomView = TRUE
        ) %>%
        visLegend()
    })

    # ========================================================================
    # SANKEY DIAGRAM
    # ========================================================================

    output$sankey_viz <- renderSankeyNetwork({
      req(input$analysis_mode == "jurisdiction")
      req(rv$jurisdiction_data)

      data <- rv$jurisdiction_data

      # Create nodes: unique combinations of nivel + uf
      create_node_name <- function(nivel, uf) {
        if (is.na(uf)) return(nivel)
        paste(nivel, uf, sep = " - ")
      }

      nodes_from <- data %>%
        mutate(node = create_node_name(doc1_nivel, doc1_uf)) %>%
        select(node) %>%
        distinct()

      nodes_to <- data %>%
        mutate(node = create_node_name(doc2_nivel, doc2_uf)) %>%
        select(node) %>%
        distinct()

      nodes <- rbind(nodes_from, nodes_to) %>%
        distinct() %>%
        mutate(id = row_number() - 1)  # 0-indexed for D3

      # Create links
      links <- data %>%
        mutate(
          source = create_node_name(doc1_nivel, doc1_uf),
          target = create_node_name(doc2_nivel, doc2_uf)
        ) %>%
        group_by(source, target) %>%
        summarise(value = n(), .groups = "drop") %>%
        left_join(nodes, by = c("source" = "node")) %>%
        rename(source_id = id) %>%
        left_join(nodes, by = c("target" = "node")) %>%
        rename(target_id = id)

      sankeyNetwork(
        Links = links,
        Nodes = nodes,
        Source = "source_id",
        Target = "target_id",
        Value = "value",
        NodeID = "node",
        units = "documents",
        fontSize = 12,
        nodeWidth = 30
      )
    })

    # ========================================================================
    # TIMELINE PLOT
    # ========================================================================

    output$timeline_plot <- renderPlotly({
      req(input$analysis_mode == "timeline")
      req(rv$timeline_data)

      focal_year <- rv$timeline_data$focal_document$ano
      related <- rv$timeline_data$related_documents

      if (nrow(related) == 0) {
        return(plotly_empty())
      }

      # Create timeline plot
      plot_data <- related %>%
        arrange(ano) %>%
        mutate(
          year_diff = ano - focal_year,
          position = ifelse(ano < focal_year, -1, 1),
          label = paste0(titulo, "\n", nivel, " (", ano, ")\nSim: ", round(jaccard_similarity * 100, 1), "%")
        )

      plot_ly(plot_data) %>%
        add_segments(
          x = ~ano, xend = ~ano,
          y = 0, yend = ~position * jaccard_similarity,
          color = ~nivel,
          hoverinfo = "text",
          text = ~label
        ) %>%
        add_markers(
          x = ~ano,
          y = ~position * jaccard_similarity,
          color = ~nivel,
          size = ~jaccard_similarity * 100,
          hoverinfo = "text",
          text = ~label
        ) %>%
        add_segments(
          x = focal_year, xend = focal_year,
          y = -1, yend = 1,
          line = list(color = "red", width = 3, dash = "dash"),
          name = "Focal Document",
          hoverinfo = "text",
          text = paste0("Focal: ", rv$timeline_data$focal_document$titulo)
        ) %>%
        layout(
          title = "Text Reuse Timeline",
          xaxis = list(title = "Year"),
          yaxis = list(title = "Similarity (Earlier ← | → Later)", range = c(-1, 1)),
          hovermode = "closest"
        )
    })

    output$timeline_table <- DT::renderDataTable({
      req(rv$timeline_data)
      rv$timeline_data$related_documents %>%
        arrange(ano) %>%
        select(
          Year = ano,
          `Doc ID` = related_doc_id,
          Title = titulo,
          Level = nivel,
          UF = uf,
          Similarity = jaccard_similarity,
          Relation = temporal_relation
        ) %>%
        datatable(
          options = list(pageLength = 10),
          rownames = FALSE
        ) %>%
        formatPercentage('Similarity', 1)
    })

    # ========================================================================
    # TEXT COMPARISON
    # ========================================================================

    # Update document selection dropdowns
    observe({
      choices <- NULL

      if (input$analysis_mode == "document" && !is.null(rv$similar_docs)) {
        choices <- setNames(
          c(rv$focal_doc_info$id, rv$similar_docs$similar_doc_id),
          c(
            paste0("[FOCAL] ", rv$focal_doc_info$titulo),
            paste0("[", rv$similar_docs$similar_doc_id, "] ", rv$similar_docs$titulo)
          )
        )
      } else if (input$analysis_mode == "jurisdiction" && !is.null(rv$jurisdiction_data)) {
        all_ids <- unique(c(rv$jurisdiction_data$doc1_id, rv$jurisdiction_data$doc2_id))
        titles <- dbGetQuery(
          db_connection(),
          sprintf("SELECT id, titulo FROM documents WHERE id IN (%s)", paste(all_ids, collapse = ","))
        )
        choices <- setNames(titles$id, paste0("[", titles$id, "] ", titles$titulo))
      }

      updateSelectInput(session, "compare_doc1", choices = choices)
      updateSelectInput(session, "compare_doc2", choices = choices)
    })

    observeEvent(input$compare_texts, {
      req(input$compare_doc1, input$compare_doc2)
      req(db_connection())

      source("R/analytics/text_reuse_lsh.R")

      # Get documents - use ementa instead of texto_completo
      docs <- dbGetQuery(
        db_connection(),
        sprintf("SELECT id, titulo, COALESCE(ementa, '') as texto_completo FROM documents WHERE id IN (%d, %d)",
                input$compare_doc1, input$compare_doc2)
      )

      rv$comparison_docs <- docs
    })

    output$doc1_title <- renderText({
      req(rv$comparison_docs)
      rv$comparison_docs$titulo[rv$comparison_docs$id == input$compare_doc1]
    })

    output$doc2_title <- renderText({
      req(rv$comparison_docs)
      rv$comparison_docs$titulo[rv$comparison_docs$id == input$compare_doc2]
    })

    output$doc1_text <- renderUI({
      req(rv$comparison_docs)
      text <- rv$comparison_docs$texto_completo[rv$comparison_docs$id == input$compare_doc1]
      pre(substr(text, 1, 5000))  # Show first 5000 chars
    })

    output$doc2_text <- renderUI({
      req(rv$comparison_docs)
      text <- rv$comparison_docs$texto_completo[rv$comparison_docs$id == input$compare_doc2]
      pre(substr(text, 1, 5000))
    })

    output$common_text <- renderUI({
      req(rv$comparison_docs)
      req(input$compare_doc1, input$compare_doc2)

      source("R/analytics/text_reuse_lsh.R")

      excerpt <- get_common_text_excerpt(
        db_connection(),
        input$compare_doc1,
        input$compare_doc2,
        max_length = 1000
      )

      div(
        class = "alert alert-info",
        h6(strong("Sample of Common Text:")),
        p(excerpt)
      )
    })

    # ========================================================================
    # STATISTICS TAB
    # ========================================================================

    observe({
      req(db_connection())

      source("R/analytics/text_reuse_lsh.R")

      stats <- lsh_index_stats(db_connection())

      output$stat_total_docs <- renderText({
        format(stats$total_indexed, big.mark = ",")
      })

      output$stat_total_pairs <- renderText({
        format(stats$total_pairs, big.mark = ",")
      })

      output$stat_avg_similarity <- renderText({
        if (is.na(stats$avg_similarity)) {
          "N/A"
        } else {
          sprintf("%.1f%%", stats$avg_similarity * 100)
        }
      })

      # Get cluster count
      cluster_count <- dbGetQuery(
        db_connection(),
        "SELECT COUNT(*) as n FROM text_reuse_clusters"
      )$n

      output$stat_clusters <- renderText({
        format(cluster_count, big.mark = ",")
      })
    })

    output$similarity_distribution <- renderPlotly({
      req(db_connection())

      data <- dbGetQuery(
        db_connection(),
        "SELECT jaccard_similarity FROM text_reuse_pairs LIMIT 10000"
      )

      if (nrow(data) == 0) {
        return(plotly_empty())
      }

      plot_ly(data, x = ~jaccard_similarity, type = "histogram", nbinsx = 50) %>%
        layout(
          title = "Similarity Distribution",
          xaxis = list(title = "Jaccard Similarity"),
          yaxis = list(title = "Count")
        )
    })

    output$cluster_size_distribution <- renderPlotly({
      req(db_connection())

      data <- dbGetQuery(
        db_connection(),
        "SELECT cluster_size FROM text_reuse_clusters"
      )

      if (nrow(data) == 0) {
        return(plotly_empty())
      }

      plot_ly(data, x = ~cluster_size, type = "histogram", nbinsx = 30) %>%
        layout(
          title = "Cluster Size Distribution",
          xaxis = list(title = "Cluster Size"),
          yaxis = list(title = "Count")
        )
    })

    output$top_patterns_table <- DT::renderDataTable({
      req(db_connection())

      data <- dbGetQuery(
        db_connection(),
        "SELECT * FROM mv_cross_jurisdiction_reuse
         ORDER BY reuse_count DESC LIMIT 50"
      )

      if (nrow(data) == 0) return(NULL)

      data %>%
        datatable(
          options = list(pageLength = 10),
          rownames = FALSE
        ) %>%
        formatRound(c('avg_similarity', 'min_similarity', 'max_similarity'), 3)
    })

    # ========================================================================
    # EXPORT FUNCTIONS
    # ========================================================================

    output$download_results <- downloadHandler(
      filename = function() {
        paste0("text_reuse_results_", Sys.Date(), ".csv")
      },
      content = function(file) {
        data <- switch(
          input$analysis_mode,
          "document" = rv$similar_docs,
          "clusters" = if (!is.null(rv$clusters)) {
            do.call(rbind, lapply(rv$clusters, function(x) x$documents))
          } else NULL,
          "jurisdiction" = rv$jurisdiction_data,
          "timeline" = if (!is.null(rv$timeline_data)) rv$timeline_data$related_documents else NULL,
          NULL
        )

        req(data)
        write.csv(data, file, row.names = FALSE)
      }
    )

    output$download_network <- downloadHandler(
      filename = function() {
        paste0("text_reuse_network_", Sys.Date(), ".json")
      },
      content = function(file) {
        # Export network data as JSON
        data <- rv$network_data
        req(data)
        jsonlite::write_json(data, file, pretty = TRUE)
      }
    )

  })
}
