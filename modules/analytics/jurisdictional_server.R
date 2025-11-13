# ==============================================================================
# MULTI-JURISDICTIONAL COMPARISON SERVER MODULE
# ==============================================================================
# Server logic for jurisdictional comparison analytics dashboard.
#
# Features:
# - Reactive data queries with caching
# - Dynamic chart generation with plotly
# - CSV/Excel export functionality
# - Error handling and validation
# - Performance optimization for large datasets
#
# Author: Monitor Legislativo v4 - Data Science Team
# Date: 2025-11-13
# ==============================================================================

# Source analytics functions
if (file.exists("R/analytics/multi_jurisdictional_comparison.R")) {
  source("R/analytics/multi_jurisdictional_comparison.R")
}

#' Multi-Jurisdictional Comparison Server Module
#'
#' Server logic for the jurisdictional comparison dashboard.
#'
#' @param id Character string. Module namespace ID.
#' @param db_connection Reactive or static database connection object.
#' @param db_available Logical. Whether database is available.
#' @param documents_table Character. Name of documents table.
#'
#' @import shiny
#' @import plotly
#' @import dplyr
#' @import DT
#'
#' @export
jurisdictionalServer <- function(id, db_connection, db_available, documents_table = "documents") {
  moduleServer(id, function(input, output, session) {

    # ========================================================================
    # REACTIVE VALUES
    # ========================================================================

    rv <- reactiveValues(
      comparison_data = NULL,
      state_data = NULL,
      cross_level_data = NULL,
      clustering_results = NULL,
      temporal_trends = NULL,
      last_update = NULL
    )

    # ========================================================================
    # QUICK STATS
    # ========================================================================

    output$stat_total_jurisdictions <- renderText({
      if (!db_available) return("--")
      "3"  # Federal, Estadual, Municipal
    })

    output$stat_total_states <- renderText({
      if (!db_available) return("--")
      "27"  # All Brazilian states + DF
    })

    output$stat_total_documents <- renderText({
      if (!db_available) return("--")

      tryCatch({
        conn <- if (is.reactive(db_connection)) db_connection() else db_connection
        result <- dbGetQuery(conn, sprintf("SELECT COUNT(*) as total FROM %s", documents_table))
        format(result$total, big.mark = ".", decimal.mark = ",")
      }, error = function(e) {
        "--"
      })
    })

    output$stat_date_range <- renderText({
      paste0(input$year_range[1], "-", input$year_range[2])
    })

    output$footer_doc_count <- renderText({
      output$stat_total_documents
    })

    # ========================================================================
    # STATE SELECTOR HELPERS
    # ========================================================================

    observeEvent(input$select_all_states, {
      all_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
                      "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
                      "RS", "RO", "RR", "SC", "SP", "SE", "TO")
      updateCheckboxGroupInput(session, "selected_states", selected = all_states)
    })

    observeEvent(input$clear_all_states, {
      updateCheckboxGroupInput(session, "selected_states", selected = character(0))
    })

    observeEvent(input$select_sudeste, {
      updateCheckboxGroupInput(session, "selected_states", selected = c("SP", "RJ", "MG", "ES"))
    })

    observeEvent(input$select_sul, {
      updateCheckboxGroupInput(session, "selected_states", selected = c("RS", "SC", "PR"))
    })

    observeEvent(input$select_nordeste, {
      updateCheckboxGroupInput(session, "selected_states", selected = c("BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE", "AL"))
    })

    # ========================================================================
    # FILTER HANDLERS
    # ========================================================================

    observeEvent(input$reset_filters, {
      updateSliderInput(session, "year_range", value = c(2015, 2025))
      updateSelectInput(session, "metric_type", selected = "count")
      updateRadioButtons(session, "comparison_mode", selected = "all_jurisdictions")
      updateCheckboxGroupInput(session, "selected_states", selected = c("SP", "RJ", "MG"))
      updateTextInput(session, "topic_keywords", value = "tributário, imposto, ICMS")

      showNotification("Filtros resetados", type = "message", duration = 2)
    })

    # ========================================================================
    # DATA LOADING (REACTIVE)
    # ========================================================================

    # Main comparison data (jurisdiction-level)
    comparison_data_reactive <- eventReactive(input$apply_filters, {
      if (!db_available) {
        showNotification("Database não disponível", type = "error", duration = 3)
        return(NULL)
      }

      conn <- if (is.reactive(db_connection)) db_connection() else db_connection

      withProgress(message = "Carregando dados...", value = 0, {

        incProgress(0.3, detail = "Consultando jurisdições")

        data <- tryCatch({
          compare_by_jurisdiction(
            conn,
            start_year = input$year_range[1],
            end_year = input$year_range[2]
          )
        }, error = function(e) {
          showNotification(paste("Erro:", e$message), type = "error", duration = 5)
          return(NULL)
        })

        incProgress(0.7, detail = "Processando resultados")

        rv$comparison_data <- data
        rv$last_update <- Sys.time()

        incProgress(1.0)
        data
      })
    }, ignoreNULL = FALSE)

    # State comparison data
    state_data_reactive <- eventReactive(input$apply_filters, {
      if (!db_available || input$comparison_mode != "state_to_state") {
        return(NULL)
      }

      if (is.null(input$selected_states) || length(input$selected_states) == 0) {
        showNotification("Selecione pelo menos um estado", type = "warning", duration = 3)
        return(NULL)
      }

      conn <- if (is.reactive(db_connection)) db_connection() else db_connection

      withProgress(message = "Comparando estados...", value = 0, {

        incProgress(0.3, detail = "Consultando dados estaduais")

        data <- tryCatch({
          compare_by_state(
            conn,
            states_vector = input$selected_states,
            start_year = input$year_range[1],
            end_year = input$year_range[2]
          )
        }, error = function(e) {
          showNotification(paste("Erro:", e$message), type = "error", duration = 5)
          return(NULL)
        })

        incProgress(0.7, detail = "Processando comparações")

        rv$state_data <- data

        incProgress(1.0)
        data
      })
    }, ignoreNULL = FALSE)

    # Cross-level analysis data
    cross_level_data_reactive <- eventReactive(input$apply_filters, {
      if (!db_available || input$comparison_mode != "cross_level") {
        return(NULL)
      }

      if (is.null(input$topic_keywords) || nchar(input$topic_keywords) == 0) {
        showNotification("Digite palavras-chave para análise", type = "warning", duration = 3)
        return(NULL)
      }

      conn <- if (is.reactive(db_connection)) db_connection() else db_connection

      # Parse keywords
      keywords <- trimws(unlist(strsplit(input$topic_keywords, ",")))
      keywords <- keywords[nchar(keywords) > 0]

      if (length(keywords) == 0) {
        showNotification("Nenhuma palavra-chave válida fornecida", type = "warning", duration = 3)
        return(NULL)
      }

      withProgress(message = "Analisando temas cross-level...", value = 0, {

        incProgress(0.3, detail = "Buscando documentos")

        data <- tryCatch({
          cross_level_analysis(conn, keywords)
        }, error = function(e) {
          showNotification(paste("Erro:", e$message), type = "error", duration = 5)
          return(NULL)
        })

        incProgress(0.7, detail = "Processando análise")

        rv$cross_level_data <- data

        incProgress(1.0)
        data
      })
    }, ignoreNULL = FALSE)

    # Temporal trends data
    temporal_trends_reactive <- eventReactive(input$apply_filters, {
      if (!db_available) return(NULL)

      conn <- if (is.reactive(db_connection)) db_connection() else db_connection

      withProgress(message = "Carregando tendências temporais...", value = 0, {

        incProgress(0.3, detail = "Consultando séries temporais")

        data <- tryCatch({
          temporal_jurisdiction_trends(
            conn,
            metric = input$metric_type,
            start_year = input$year_range[1],
            end_year = input$year_range[2]
          )
        }, error = function(e) {
          showNotification(paste("Erro:", e$message), type = "error", duration = 5)
          return(NULL)
        })

        incProgress(0.7, detail = "Processando tendências")

        rv$temporal_trends <- data

        incProgress(1.0)
        data
      })
    }, ignoreNULL = FALSE)

    # Clustering data
    clustering_data_reactive <- eventReactive(input$apply_filters, {
      if (!db_available) return(NULL)

      conn <- if (is.reactive(db_connection)) db_connection() else db_connection

      withProgress(message = "Realizando clustering de estados...", value = 0, {

        incProgress(0.3, detail = "Coletando features")

        data <- tryCatch({
          state_clustering(
            conn,
            start_year = input$year_range[1],
            end_year = input$year_range[2]
          )
        }, error = function(e) {
          showNotification(paste("Erro ao realizar clustering:", e$message), type = "error", duration = 5)
          return(NULL)
        })

        incProgress(0.7, detail = "Agrupando estados")

        rv$clustering_results <- data

        incProgress(1.0)
        data
      })
    }, ignoreNULL = FALSE)

    # ========================================================================
    # VISUALIZATIONS
    # ========================================================================

    # Bar Chart - Volume by Jurisdiction
    output$bar_chart_volume <- renderPlotly({
      data <- if (input$comparison_mode == "state_to_state") {
        state_data_reactive()
      } else if (input$comparison_mode == "cross_level") {
        cross_level_data_reactive()
      } else {
        comparison_data_reactive()
      }

      if (is.null(data) || nrow(data) == 0) {
        return(plot_ly() %>%
          layout(
            title = "Sem dados disponíveis",
            annotations = list(
              text = "Clique em 'Aplicar Filtros' para carregar dados",
              showarrow = FALSE,
              font = list(size = 16)
            )
          ))
      }

      # Determine columns based on mode
      if (input$comparison_mode == "state_to_state") {
        x_col <- data$state
        y_col <- data$total_documents
        title_text <- "Volume de Documentos por Estado"
      } else if (input$comparison_mode == "cross_level") {
        x_col <- data$jurisdiction_level
        y_col <- data$document_count
        title_text <- paste("Distribuição do Tema:", input$topic_keywords)
      } else {
        x_col <- data$jurisdiction_level
        y_col <- data$doc_count
        title_text <- "Volume de Documentos por Nível Jurisdicional"
      }

      plot_ly(
        data,
        x = ~x_col,
        y = ~y_col,
        type = "bar",
        marker = list(
          color = c("#667eea", "#764ba2", "#f093fb", "#4facfe"),
          line = list(color = "white", width = 2)
        ),
        hovertemplate = paste0(
          "<b>%{x}</b><br>",
          "Documentos: %{y:,.0f}<br>",
          "<extra></extra>"
        )
      ) %>%
        layout(
          title = list(text = title_text, font = list(size = 16, family = "Arial")),
          xaxis = list(title = ""),
          yaxis = list(title = "Número de Documentos"),
          hovermode = "closest",
          plot_bgcolor = "#f8f9fa",
          paper_bgcolor = "white"
        )
    })

    # Pie Chart - Distribution
    output$pie_chart_distribution <- renderPlotly({
      data <- comparison_data_reactive()

      if (is.null(data) || nrow(data) == 0) {
        return(plot_ly() %>%
          layout(
            title = "Sem dados disponíveis",
            annotations = list(
              text = "Aguardando dados",
              showarrow = FALSE
            )
          ))
      }

      plot_ly(
        data,
        labels = ~jurisdiction_level,
        values = ~doc_count,
        type = "pie",
        marker = list(
          colors = c("#667eea", "#764ba2", "#f093fb", "#4facfe")
        ),
        textposition = "inside",
        textinfo = "label+percent",
        hovertemplate = paste0(
          "<b>%{label}</b><br>",
          "Documentos: %{value:,.0f}<br>",
          "Percentual: %{percent}<br>",
          "<extra></extra>"
        )
      ) %>%
        layout(
          title = list(text = "Distribuição Percentual por Jurisdição", font = list(size = 16)),
          showlegend = TRUE,
          paper_bgcolor = "white"
        )
    })

    # Line Chart - Temporal Trends
    output$line_chart_temporal <- renderPlotly({
      data <- temporal_trends_reactive()

      if (is.null(data) || nrow(data) == 0) {
        return(plot_ly() %>%
          layout(
            title = "Sem dados temporais disponíveis",
            annotations = list(
              text = "Aguardando dados",
              showarrow = FALSE
            )
          ))
      }

      # Create plot with one line per jurisdiction level
      p <- plot_ly()

      jurisdictions <- unique(data$jurisdiction_level)
      colors <- c("#667eea", "#764ba2", "#f093fb", "#4facfe", "#43e97b")

      for (i in seq_along(jurisdictions)) {
        jurisdiction_data <- data[data$jurisdiction_level == jurisdictions[i], ]

        p <- p %>%
          add_trace(
            data = jurisdiction_data,
            x = ~date,
            y = ~value,
            type = "scatter",
            mode = "lines+markers",
            name = jurisdictions[i],
            line = list(color = colors[i], width = 2),
            marker = list(size = 4),
            hovertemplate = paste0(
              "<b>", jurisdictions[i], "</b><br>",
              "Data: %{x|%Y-%m}<br>",
              "Valor: %{y:,.0f}<br>",
              "<extra></extra>"
            )
          )
      }

      p %>%
        layout(
          title = list(text = "Evolução Temporal por Jurisdição", font = list(size = 16)),
          xaxis = list(title = "Data"),
          yaxis = list(title = switch(input$metric_type,
            "count" = "Número de Documentos",
            "diversity" = "Tipos Únicos",
            "avg_length" = "Comprimento Médio",
            "complexity" = "Índice de Complexidade"
          )),
          hovermode = "x unified",
          plot_bgcolor = "#f8f9fa",
          paper_bgcolor = "white",
          legend = list(x = 0.05, y = 0.95)
        )
    })

    # Comparison Table
    output$comparison_table <- DT::renderDataTable({
      data <- if (input$comparison_mode == "state_to_state") {
        state_data_reactive()
      } else if (input$comparison_mode == "cross_level") {
        cross_level_data_reactive()
      } else {
        comparison_data_reactive()
      }

      if (is.null(data) || nrow(data) == 0) {
        return(data.frame(Mensagem = "Sem dados disponíveis. Clique em 'Aplicar Filtros'."))
      }

      DT::datatable(
        data,
        options = list(
          pageLength = 25,
          scrollX = TRUE,
          dom = 'Bfrtip',
          buttons = c('copy', 'csv', 'excel'),
          language = list(
            url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
          )
        ),
        rownames = FALSE,
        class = "display"
      ) %>%
        DT::formatRound(columns = which(sapply(data, is.numeric)), digits = 2)
    })

    # Heatmap - State × Document Type
    output$heatmap_state_type <- renderPlotly({
      if (!db_available) {
        return(plot_ly() %>%
          layout(
            title = "Database não disponível",
            annotations = list(text = "Conecte-se ao banco de dados", showarrow = FALSE)
          ))
      }

      conn <- if (is.reactive(db_connection)) db_connection() else db_connection

      # Query for heatmap data
      tryCatch({
        query <- sprintf("
          SELECT
            estado AS state,
            tipo AS document_type,
            COUNT(*) AS count
          FROM %s
          WHERE estado IS NOT NULL
            AND estado NOT IN ('Federal', 'Nacional', 'Justiça Trabalho')
            AND LENGTH(estado) = 2
            AND tipo IS NOT NULL
            AND ano >= %d AND ano <= %d
          GROUP BY estado, tipo
          ORDER BY estado, count DESC
        ", documents_table, input$year_range[1], input$year_range[2])

        heatmap_data <- dbGetQuery(conn, query)

        if (nrow(heatmap_data) == 0) {
          return(plot_ly() %>%
            layout(
              title = "Sem dados para o período selecionado",
              annotations = list(text = "Ajuste os filtros", showarrow = FALSE)
            ))
        }

        # Pivot data for heatmap
        heatmap_matrix <- heatmap_data %>%
          tidyr::pivot_wider(
            names_from = document_type,
            values_from = count,
            values_fill = 0
          ) %>%
          as.data.frame()

        rownames(heatmap_matrix) <- heatmap_matrix$state
        heatmap_matrix$state <- NULL
        heatmap_matrix <- as.matrix(heatmap_matrix)

        # Limit to top 15 document types for readability
        if (ncol(heatmap_matrix) > 15) {
          col_sums <- colSums(heatmap_matrix)
          top_cols <- names(sort(col_sums, decreasing = TRUE)[1:15])
          heatmap_matrix <- heatmap_matrix[, top_cols]
        }

        plot_ly(
          z = heatmap_matrix,
          x = colnames(heatmap_matrix),
          y = rownames(heatmap_matrix),
          type = "heatmap",
          colors = colorRamp(c("#ffffff", "#667eea", "#1e40af")),
          hovertemplate = paste0(
            "Estado: %{y}<br>",
            "Tipo: %{x}<br>",
            "Documentos: %{z:,.0f}<br>",
            "<extra></extra>"
          )
        ) %>%
          layout(
            title = list(text = "Mapa de Calor: Estado × Tipo de Documento", font = list(size = 16)),
            xaxis = list(title = "Tipo de Documento", tickangle = -45),
            yaxis = list(title = "Estado"),
            margin = list(l = 80, r = 50, b = 150, t = 80),
            paper_bgcolor = "white"
          )

      }, error = function(e) {
        plot_ly() %>%
          layout(
            title = paste("Erro:", e$message),
            annotations = list(text = "Erro ao gerar heatmap", showarrow = FALSE)
          )
      })
    })

    # Dendrogram - State Clustering
    output$dendrogram_states <- renderPlot({
      clustering <- clustering_data_reactive()

      if (is.null(clustering) || is.null(clustering$dendrogram)) {
        plot.new()
        text(0.5, 0.5, "Aguardando dados de clustering\nClique em 'Aplicar Filtros'",
             cex = 1.5, col = "gray50")
        return()
      }

      # Plot dendrogram
      par(mar = c(5, 4, 4, 2))
      plot(clustering$dendrogram,
           main = "Dendrograma de Clustering de Estados",
           xlab = "Estados",
           ylab = "Distância (Ward)",
           sub = paste("Clusters ótimos:", clustering$optimal_clusters),
           cex.main = 1.3,
           cex.lab = 1.1)

      # Add colored rectangles for clusters
      rect.hclust(clustering$dendrogram,
                  k = clustering$optimal_clusters,
                  border = c("#667eea", "#764ba2", "#f093fb", "#4facfe", "#43e97b")[1:clustering$optimal_clusters])
    })

    # Clustering Info
    output$clustering_info <- renderUI({
      clustering <- clustering_data_reactive()

      if (is.null(clustering)) {
        return(div(
          class = "alert alert-info",
          p("Aguardando dados de clustering")
        ))
      }

      tagList(
        p(strong("Método:"), " Hierarchical Clustering (Ward's)"),
        p(strong("Distância:"), " Euclidiana"),
        p(strong("Número de Estados:"), nrow(clustering$cluster_data)),
        p(strong("Clusters Identificados:"), clustering$optimal_clusters),
        p(strong("Features Utilizadas:")),
        tags$ul(
          tags$li("Volume de documentos"),
          tags$li("Diversidade de tipos"),
          tags$li("Comprimento médio"),
          tags$li("Diversidade de poderes"),
          tags$li("Tendência temporal")
        )
      )
    })

    # Cluster Assignments Table
    output$cluster_assignments_table <- DT::renderDataTable({
      clustering <- clustering_data_reactive()

      if (is.null(clustering) || is.null(clustering$cluster_data)) {
        return(data.frame(Mensagem = "Sem dados"))
      }

      cluster_summary <- clustering$cluster_data %>%
        select(cluster, state, total_volume) %>%
        arrange(cluster, desc(total_volume))

      DT::datatable(
        cluster_summary,
        options = list(
          pageLength = 10,
          dom = 't',
          scrollY = "400px",
          scrollCollapse = TRUE
        ),
        colnames = c("Cluster", "Estado", "Volume"),
        rownames = FALSE
      )
    })

    # Radar Chart - Multi-metric Comparison
    output$radar_chart_multimetric <- renderPlotly({
      data <- if (input$comparison_mode == "state_to_state") {
        state_data_reactive()
      } else {
        comparison_data_reactive()
      }

      if (is.null(data) || nrow(data) == 0) {
        return(plot_ly() %>%
          layout(
            title = "Sem dados disponíveis",
            annotations = list(text = "Aguardando dados", showarrow = FALSE)
          ))
      }

      # Normalize metrics to 0-1 scale for radar chart
      metrics_cols <- if (input$comparison_mode == "state_to_state") {
        c("total_documents", "avg_docs_per_month", "diversity_index", "avg_length", "growth_rate")
      } else {
        c("doc_count", "avg_per_month", "diversity_index", "avg_doc_length", "growth_rate")
      }

      # Check which columns exist
      metrics_cols <- metrics_cols[metrics_cols %in% names(data)]

      if (length(metrics_cols) < 3) {
        return(plot_ly() %>%
          layout(
            title = "Métricas insuficientes para radar chart",
            annotations = list(text = "Selecione outro modo de comparação", showarrow = FALSE)
          ))
      }

      # Normalize
      data_normalized <- data
      for (col in metrics_cols) {
        data_normalized[[paste0(col, "_norm")]] <- scales::rescale(data[[col]], to = c(0, 100), na.rm = TRUE)
      }

      # Create radar chart
      p <- plot_ly(type = "scatterpolar", fill = "toself", mode = "markers")

      # Get entity column name
      entity_col <- if (input$comparison_mode == "state_to_state") "state" else "jurisdiction_level"

      # Add trace for each entity (max 5 for readability)
      entities <- head(data_normalized[[entity_col]], 5)
      colors <- c("#667eea", "#764ba2", "#f093fb", "#4facfe", "#43e97b")

      for (i in seq_along(entities)) {
        entity_data <- data_normalized[data_normalized[[entity_col]] == entities[i], ]

        values <- unlist(entity_data[paste0(metrics_cols, "_norm")])

        p <- p %>%
          add_trace(
            r = values,
            theta = metrics_cols,
            name = entities[i],
            marker = list(color = colors[i]),
            line = list(color = colors[i], width = 2)
          )
      }

      p %>%
        layout(
          title = list(text = "Comparação Multidimensional (Normalizado)", font = list(size = 16)),
          polar = list(
            radialaxis = list(
              visible = TRUE,
              range = c(0, 100)
            )
          ),
          showlegend = TRUE,
          paper_bgcolor = "white"
        )
    })

    # ========================================================================
    # EXPORT HANDLERS
    # ========================================================================

    # CSV Export
    output$download_comparison_csv <- downloadHandler(
      filename = function() {
        paste0("jurisdictional_comparison_", format(Sys.Date(), "%Y%m%d"), ".csv")
      },
      content = function(file) {
        data <- if (input$comparison_mode == "state_to_state") {
          state_data_reactive()
        } else if (input$comparison_mode == "cross_level") {
          cross_level_data_reactive()
        } else {
          comparison_data_reactive()
        }

        if (is.null(data) || nrow(data) == 0) {
          write.csv(data.frame(Error = "No data available"), file, row.names = FALSE)
          return()
        }

        write.csv(data, file, row.names = FALSE, fileEncoding = "UTF-8")
      }
    )

    # Excel Export
    output$download_comparison_excel <- downloadHandler(
      filename = function() {
        paste0("jurisdictional_comparison_", format(Sys.Date(), "%Y%m%d"), ".xlsx")
      },
      content = function(file) {
        if (!requireNamespace("writexl", quietly = TRUE)) {
          showNotification("Pacote 'writexl' não instalado", type = "error", duration = 5)
          return()
        }

        data <- if (input$comparison_mode == "state_to_state") {
          state_data_reactive()
        } else if (input$comparison_mode == "cross_level") {
          cross_level_data_reactive()
        } else {
          comparison_data_reactive()
        }

        if (is.null(data) || nrow(data) == 0) {
          writexl::write_xlsx(list(Error = data.frame(Message = "No data available")), file)
          return()
        }

        # Create Excel with multiple sheets
        sheets <- list(
          "Comparison_Data" = data,
          "Metadata" = data.frame(
            Generated = format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
            Mode = input$comparison_mode,
            Year_Range = paste(input$year_range, collapse = " - "),
            Metric = input$metric_type
          )
        )

        writexl::write_xlsx(sheets, file)
      }
    )

  })
}
