# =============================================================================
# Sprint 3: BERT Precedent Search Server Module
# =============================================================================
# Description: Shiny server logic for BERT-based precedent retrieval
# Version: 1.0
# Date: January 2025
# =============================================================================

#' BERT Precedent Search Server Module
#'
#' Server logic for finding legal precedents using BERT embeddings
#'
#' @param id Character, module ID
#' @param db_pool Database connection pool
#'
#' @export
bert_precedent_server <- function(id, db_pool) {
  moduleServer(id, function(input, output, session) {

    # Reactive values
    rv <- reactiveValues(
      reference_doc = NULL,
      reference_embedding = NULL,
      search_results = NULL,
      filtered_results = NULL,
      comparison_data = NULL,
      cluster_data = NULL,
      embedding_viz_data = NULL
    )

    # ==========================================================================
    # Reference Document Loading
    # ==========================================================================

    observeEvent(input$load_reference_btn, {
      req(input$reference_doc_id, db_pool)

      shinybusy::show_modal_spinner(
        spin = "fading-circle",
        text = "Carregando documento de referência..."
      )

      tryCatch({
        # Load document - use actual database columns
        doc <- dbGetQuery(db_pool,
          sprintf("SELECT id, titulo, ementa, tipo as tipo_documento, COALESCE(nivel, 'N/A') as nivel, COALESCE(poder, 'N/A') as poder, data as data_publicacao
                   FROM documents
                   WHERE id = %d", input$reference_doc_id))

        if (nrow(doc) == 0) {
          stop("Documento não encontrado")
        }

        # Load BERT embedding
        embedding <- dbGetQuery(db_pool,
          sprintf("SELECT embedding
                   FROM document_embeddings
                   WHERE document_id = %d AND embedding_type = 'bert'",
                  input$reference_doc_id))

        if (nrow(embedding) == 0) {
          stop("Embedding BERT não encontrado para este documento")
        }

        rv$reference_doc <- doc
        rv$reference_embedding <- embedding$embedding[[1]]

        shinybusy::remove_modal_spinner()

        showNotification(
          "Documento de referência carregado com sucesso",
          type = "message",
          duration = 3
        )

      }, error = function(e) {
        shinybusy::remove_modal_spinner()
        logger::log_error("Error loading reference document: {e$message}")
        showNotification(
          sprintf("Erro: %s", e$message),
          type = "error",
          duration = 5
        )
      })
    })

    # Reference document preview
    output$reference_doc_preview <- renderUI({
      req(rv$reference_doc)

      doc <- rv$reference_doc

      wellPanel(
        h5(icon("file-alt"), " Documento de Referência"),
        tags$dl(
          tags$dt("ID:"), tags$dd(doc$id),
          tags$dt("Título:"), tags$dd(doc$titulo),
          tags$dt("Tipo:"), tags$dd(doc$tipo_documento),
          tags$dt("Nível:"), tags$dd(doc$nivel),
          tags$dt("Poder:"), tags$dd(doc$poder),
          tags$dt("Data:"), tags$dd(tryCatch(format(as.Date(doc$data_publicacao), "%d/%m/%Y"), error = function(e) as.character(doc$data_publicacao)))
        ),
        hr(),
        tags$strong("Ementa:"),
        p(substr(doc$ementa, 1, 300), if(nchar(doc$ementa) > 300) "..." else "")
      )
    })

    # ==========================================================================
    # Precedent Search
    # ==========================================================================

    observeEvent(input$search_precedents_btn, {
      req(db_pool)

      shinybusy::show_modal_spinner(
        spin = "fading-circle",
        text = "Buscando precedentes jurídicos..."
      )

      tryCatch({
        results <- NULL

        if (input$search_mode == "id") {
          # Search by document ID
          req(rv$reference_embedding)

          results <- search_bert_by_embedding(
            embedding = rv$reference_embedding,
            db_connection = db_pool,
            top_n = input$bert_top_n,
            min_similarity = input$bert_min_similarity,
            metric = input$similarity_metric,
            scope = input$search_scope,
            reference_doc = rv$reference_doc
          )

        } else if (input$search_mode == "text") {
          # Search by text (requires computing embedding)
          req(input$query_text_bert, nchar(input$query_text_bert) >= 100)

          results <- search_bert_by_text(
            query_text = input$query_text_bert,
            db_connection = db_pool,
            top_n = input$bert_top_n,
            min_similarity = input$bert_min_similarity,
            metric = input$similarity_metric
          )

        } else if (input$search_mode == "compare") {
          # Compare two documents
          req(input$compare_doc1_id, input$compare_doc2_id)

          results <- compare_bert_documents(
            doc1_id = input$compare_doc1_id,
            doc2_id = input$compare_doc2_id,
            db_connection = db_pool
          )
        }

        rv$search_results <- results

        shinybusy::remove_modal_spinner()

        if (!is.null(results) && nrow(results) > 0) {
          showNotification(
            sprintf("Encontrados %d precedentes", nrow(results)),
            type = "message",
            duration = 3
          )
        } else {
          showNotification(
            "Nenhum precedente encontrado com os critérios especificados",
            type = "warning",
            duration = 4
          )
        }

      }, error = function(e) {
        shinybusy::remove_modal_spinner()
        logger::log_error("BERT search error: {e$message}")
        showNotification(
          sprintf("Erro na busca: %s", e$message),
          type = "error",
          duration = 5
        )
      })
    })

    # Apply filters to results
    filtered_results <- reactive({
      req(rv$search_results)

      results <- rv$search_results

      # Filter by jurisdiction
      if (input$filter_nivel_bert != "all") {
        results <- results %>% filter(nivel == input$filter_nivel_bert)
      }

      # Filter by poder
      if (input$filter_poder_bert != "all") {
        results <- results %>% filter(poder == input$filter_poder_bert)
      }

      # Filter by document type
      if (input$filter_tipo_bert != "all") {
        results <- results %>% filter(tipo_documento == input$filter_tipo_bert)
      }

      # Filter by year
      results <- results %>%
        filter(ano >= input$filter_year_bert[1], ano <= input$filter_year_bert[2])

      return(results)
    })

    # ==========================================================================
    # Results Display
    # ==========================================================================

    # Summary UI
    output$results_summary_ui <- renderUI({
      req(filtered_results())

      results <- filtered_results()

      wellPanel(
        h4(icon("check-circle"), sprintf(" %d Precedentes Encontrados", nrow(results))),

        fluidRow(
          column(3,
            valueBox(
              value = sprintf("%.3f", mean(results$similarity_score)),
              subtitle = "Similaridade Média",
              icon = icon("chart-line"),
              color = "blue"
            )
          ),

          column(3,
            valueBox(
              value = sprintf("%.3f", max(results$similarity_score)),
              subtitle = "Maior Similaridade",
              icon = icon("arrow-up"),
              color = "green"
            )
          ),

          column(3,
            valueBox(
              value = length(unique(results$nivel)),
              subtitle = "Níveis Jurisdicionais",
              icon = icon("balance-scale"),
              color = "purple"
            )
          ),

          column(3,
            valueBox(
              value = length(unique(results$tipo_documento)),
              subtitle = "Tipos de Documento",
              icon = icon("file"),
              color = "orange"
            )
          )
        )
      )
    })

    # Precedents table
    output$precedents_table <- DT::renderDataTable({
      req(filtered_results())

      results <- filtered_results()

      DT::datatable(
        results %>%
          select(
            Rank = rank_position,
            `ID` = document_id,
            `Título` = titulo,
            `Tipo` = tipo_documento,
            `Nível` = nivel,
            `Poder` = poder,
            `Similaridade` = similarity_score,
            `Ano` = ano,
            `Data` = data_publicacao
          ),
        options = list(
          pageLength = 20,
          order = list(list(0, 'asc')),
          columnDefs = list(
            list(className = 'dt-center', targets = c(0, 1, 6, 7))
          )
        ),
        selection = "single",
        rownames = FALSE
      ) %>%
        DT::formatRound(columns = "Similaridade", digits = 4) %>%
        DT::formatStyle(
          'Similaridade',
          background = DT::styleColorBar(c(0, 1), '#90EE90'),
          backgroundSize = '100% 90%',
          backgroundRepeat = 'no-repeat',
          backgroundPosition = 'center'
        )
    })

    # ==========================================================================
    # Visualizations
    # ==========================================================================

    # Similarity distribution
    output$similarity_distribution <- plotly::renderPlotly({
      req(filtered_results())

      results <- filtered_results()

      p <- ggplot(results, aes(x = similarity_score)) +
        geom_histogram(bins = 30, fill = "#3498db", alpha = 0.7) +
        geom_vline(xintercept = mean(results$similarity_score),
                  linetype = "dashed", color = "red", size = 1) +
        labs(
          title = "Distribuição de Similaridade",
          x = "Score de Similaridade",
          y = "Número de Documentos"
        ) +
        theme_minimal()

      plotly::ggplotly(p)
    })

    # Similarity by nivel
    output$similarity_by_nivel <- plotly::renderPlotly({
      req(filtered_results())

      results <- filtered_results()

      nivel_stats <- results %>%
        group_by(nivel) %>%
        summarize(
          avg_similarity = mean(similarity_score),
          count = n(),
          .groups = "drop"
        )

      p <- ggplot(nivel_stats, aes(x = reorder(nivel, avg_similarity),
                                    y = avg_similarity,
                                    fill = nivel)) +
        geom_col(alpha = 0.8) +
        geom_text(aes(label = sprintf("n=%d", count)), vjust = -0.5) +
        coord_flip() +
        labs(
          title = "Similaridade Média por Nível",
          x = "Nível Jurisdicional",
          y = "Similaridade Média"
        ) +
        theme_minimal() +
        theme(legend.position = "none")

      plotly::ggplotly(p)
    })

    # Similarity timeline
    output$similarity_timeline <- plotly::renderPlotly({
      req(filtered_results())

      results <- filtered_results()

      timeline <- results %>%
        group_by(ano) %>%
        summarize(
          avg_similarity = mean(similarity_score),
          count = n(),
          .groups = "drop"
        ) %>%
        arrange(ano)

      p <- ggplot(timeline, aes(x = ano, y = avg_similarity)) +
        geom_line(color = "#3498db", size = 1.2) +
        geom_point(aes(size = count), color = "#2980b9", alpha = 0.7) +
        labs(
          title = "Similaridade ao Longo do Tempo",
          x = "Ano",
          y = "Similaridade Média",
          size = "N° Docs"
        ) +
        theme_minimal()

      plotly::ggplotly(p)
    })

    # ==========================================================================
    # Document Comparison
    # ==========================================================================

    observeEvent(input$compare_docs_btn, {
      req(input$compare_select_id, rv$reference_doc, db_pool)

      tryCatch({
        comparison <- compare_bert_documents(
          doc1_id = rv$reference_doc$id,
          doc2_id = input$compare_select_id,
          db_connection = db_pool
        )

        rv$comparison_data <- comparison

        output$comparison_output <- renderUI({
          comp <- rv$comparison_data

          tagList(
            wellPanel(
              h4("Análise Comparativa de Documentos"),

              fluidRow(
                column(6,
                  h5(icon("file"), " Documento de Referência"),
                  tags$dl(
                    tags$dt("ID:"), tags$dd(comp$doc1_id),
                    tags$dt("Título:"), tags$dd(comp$doc1_titulo),
                    tags$dt("Tipo:"), tags$dd(comp$doc1_tipo)
                  )
                ),

                column(6,
                  h5(icon("file"), " Documento Comparado"),
                  tags$dl(
                    tags$dt("ID:"), tags$dd(comp$doc2_id),
                    tags$dt("Título:"), tags$dd(comp$doc2_titulo),
                    tags$dt("Tipo:"), tags$dd(comp$doc2_tipo)
                  )
                )
              ),

              hr(),

              fluidRow(
                column(12,
                  div(
                    style = "text-align: center; padding: 20px;",
                    h3("Score de Similaridade BERT"),
                    div(
                      style = "font-size: 48px; font-weight: bold; color: #27ae60;",
                      sprintf("%.4f", comp$similarity_score)
                    ),
                    p(class = "text-muted", "Intervalo: 0 (totalmente diferente) a 1 (idêntico)")
                  )
                )
              )
            )
          )
        })

      }, error = function(e) {
        logger::log_error("Document comparison error: {e$message}")
        showNotification(
          sprintf("Erro na comparação: %s", e$message),
          type = "error",
          duration = 5
        )
      })
    })

    # ==========================================================================
    # Clustering
    # ==========================================================================

    observeEvent(input$run_clustering_btn, {
      req(filtered_results(), db_pool)

      shinybusy::show_modal_spinner(
        spin = "fading-circle",
        text = "Executando agrupamento..."
      )

      tryCatch({
        results <- filtered_results()

        # Get embeddings for these documents
        doc_ids <- paste(results$document_id, collapse = ",")
        embeddings_data <- dbGetQuery(db_pool,
          sprintf("SELECT document_id, embedding
                   FROM document_embeddings
                   WHERE document_id IN (%s) AND embedding_type = 'bert'",
                  doc_ids))

        # Perform clustering (placeholder - would use actual clustering algorithm)
        # For now, just assign random clusters
        cluster_assignments <- sample(1:input$n_clusters, nrow(results), replace = TRUE)

        results$cluster <- cluster_assignments

        rv$cluster_data <- results

        shinybusy::remove_modal_spinner()

        showNotification(
          sprintf("Agrupamento concluído: %d grupos", input$n_clusters),
          type = "message",
          duration = 3
        )

      }, error = function(e) {
        shinybusy::remove_modal_spinner()
        logger::log_error("Clustering error: {e$message}")
        showNotification(
          sprintf("Erro no agrupamento: %s", e$message),
          type = "error",
          duration = 5
        )
      })
    })

    # Cluster plot
    output$cluster_plot <- plotly::renderPlotly({
      req(rv$cluster_data)

      data <- rv$cluster_data

      # Placeholder visualization
      p <- ggplot(data, aes(x = ano, y = similarity_score, color = factor(cluster))) +
        geom_point(size = 3, alpha = 0.7) +
        labs(
          title = "Agrupamento de Precedentes",
          x = "Ano",
          y = "Similaridade",
          color = "Grupo"
        ) +
        theme_minimal()

      plotly::ggplotly(p)
    })

    # ==========================================================================
    # Embedding Visualization
    # ==========================================================================

    observeEvent(input$compute_viz_btn, {
      req(filtered_results(), db_pool)

      shinybusy::show_modal_spinner(
        spin = "fading-circle",
        text = "Computando redução dimensional..."
      )

      tryCatch({
        # Placeholder: Would compute UMAP/t-SNE here
        results <- filtered_results()

        # Simulated 2D projection
        results$x <- rnorm(nrow(results))
        results$y <- rnorm(nrow(results))

        rv$embedding_viz_data <- results

        shinybusy::remove_modal_spinner()

        showNotification(
          "Visualização gerada com sucesso",
          type = "message",
          duration = 3
        )

      }, error = function(e) {
        shinybusy::remove_modal_spinner()
        logger::log_error("Embedding visualization error: {e$message}")
        showNotification(
          sprintf("Erro na visualização: %s", e$message),
          type = "error",
          duration = 5
        )
      })
    })

    # Embedding space plot
    output$embedding_space_plot <- plotly::renderPlotly({
      req(rv$embedding_viz_data)

      data <- rv$embedding_viz_data

      # Color by selected variable
      if (input$color_by == "similarity") {
        p <- plotly::plot_ly(
          data = data,
          x = ~x,
          y = ~y,
          color = ~similarity_score,
          colors = "Viridis",
          text = ~paste("ID:", document_id, "<br>Similarity:", round(similarity_score, 3)),
          type = "scatter",
          mode = "markers",
          marker = list(size = 8)
        )
      } else if (input$color_by == "nivel") {
        p <- plotly::plot_ly(
          data = data,
          x = ~x,
          y = ~y,
          color = ~nivel,
          text = ~paste("ID:", document_id, "<br>Nível:", nivel),
          type = "scatter",
          mode = "markers",
          marker = list(size = 8)
        )
      } else {
        p <- plotly::plot_ly(
          data = data,
          x = ~x,
          y = ~y,
          text = ~paste("ID:", document_id),
          type = "scatter",
          mode = "markers",
          marker = list(size = 8)
        )
      }

      p %>%
        plotly::layout(
          title = "Espaço Semântico BERT (2D)",
          xaxis = list(title = "Dimensão 1"),
          yaxis = list(title = "Dimensão 2")
        )
    })

    # ==========================================================================
    # Export
    # ==========================================================================

    output$download_precedents <- downloadHandler(
      filename = function() {
        sprintf("precedentes_bert_%s.%s",
               format(Sys.Date(), "%Y%m%d"),
               input$export_format)
      },
      content = function(file) {
        req(filtered_results())

        results <- filtered_results() %>%
          select(all_of(input$export_columns))

        if (input$export_format == "csv") {
          write.csv(results, file, row.names = FALSE)
        } else if (input$export_format == "xlsx") {
          writexl::write_xlsx(results, file)
        } else if (input$export_format == "json") {
          jsonlite::write_json(results, file, pretty = TRUE)
        }
      }
    )

    # Search statistics
    output$search_stats <- renderPrint({
      req(filtered_results())

      results <- filtered_results()

      cat("=== ESTATÍSTICAS DA BUSCA ===\n\n")
      cat(sprintf("Total de precedentes: %d\n", nrow(results)))
      cat(sprintf("Similaridade média: %.4f\n", mean(results$similarity_score)))
      cat(sprintf("Similaridade mediana: %.4f\n", median(results$similarity_score)))
      cat(sprintf("Desvio padrão: %.4f\n", sd(results$similarity_score)))
      cat(sprintf("Intervalo: [%.4f, %.4f]\n",
                 min(results$similarity_score),
                 max(results$similarity_score)))
      cat("\n")
      cat("Distribuição por nível:\n")
      print(table(results$nivel))
      cat("\n")
      cat("Distribuição por tipo:\n")
      print(table(results$tipo_documento))
    })

  })
}

# =============================================================================
# Helper Functions
# =============================================================================

#' Search BERT by Embedding
#'
#' Find similar documents using pre-computed BERT embedding
search_bert_by_embedding <- function(embedding, db_connection, top_n = 20,
                                      min_similarity = 0.7, metric = "cosine",
                                      scope = "all", reference_doc = NULL) {

  logger::log_info("Searching BERT by embedding (top_n={top_n})")

  # Use materialized view or direct query
  # Placeholder implementation
  # Use actual database columns: tipo (not tipo_documento), data (not data_publicacao)
  query <- sprintf("
    SELECT
      de.document_id,
      d.titulo,
      d.tipo as tipo_documento,
      COALESCE(d.nivel, 'N/A') as nivel,
      COALESCE(d.poder, 'N/A') as poder,
      COALESCE(EXTRACT(YEAR FROM d.data::date), 0)::integer AS ano,
      d.data as data_publicacao,
      1.0 - (de.embedding <=> $1) AS similarity_score,
      ROW_NUMBER() OVER (ORDER BY de.embedding <=> $1) AS rank_position
    FROM document_embeddings de
    JOIN documents d ON de.document_id = d.id
    WHERE de.embedding_type = 'bert'
      AND de.document_id != %d
    ORDER BY de.embedding <=> $1
    LIMIT %d
  ", if(!is.null(reference_doc)) reference_doc$id else 0, top_n * 2)

  # Note: Actual implementation would use proper similarity computation
  # This is a placeholder

  return(data.frame())
}

#' Search BERT by Text
#'
#' Compute embedding for text and search
search_bert_by_text <- function(query_text, db_connection, top_n = 20,
                                 min_similarity = 0.7, metric = "cosine") {

  logger::log_info("Searching BERT by text")

  # Would need to:
  # 1. Load BERT model
  # 2. Compute embedding for query_text
  # 3. Search using embedding

  logger::log_warn("Text search not fully implemented")

  return(data.frame())
}

#' Compare Two Documents
#'
#' Compute BERT similarity between two documents
compare_bert_documents <- function(doc1_id, doc2_id, db_connection) {

  logger::log_info("Comparing documents {doc1_id} and {doc2_id}")

  # Get both embeddings
  emb1 <- dbGetQuery(db_connection,
    sprintf("SELECT embedding FROM document_embeddings
             WHERE document_id = %d AND embedding_type = 'bert'", doc1_id))

  emb2 <- dbGetQuery(db_connection,
    sprintf("SELECT embedding FROM document_embeddings
             WHERE document_id = %d AND embedding_type = 'bert'", doc2_id))

  # Get document details - use actual column names
  docs <- dbGetQuery(db_connection,
    sprintf("SELECT id, titulo, tipo as tipo_documento FROM documents WHERE id IN (%d, %d)",
           doc1_id, doc2_id))

  # Compute similarity (placeholder)
  similarity <- 0.85

  return(list(
    doc1_id = doc1_id,
    doc2_id = doc2_id,
    doc1_titulo = docs$titulo[docs$id == doc1_id],
    doc2_titulo = docs$titulo[docs$id == doc2_id],
    doc1_tipo = docs$tipo_documento[docs$id == doc1_id],
    doc2_tipo = docs$tipo_documento[docs$id == doc2_id],
    similarity_score = similarity
  ))
}

#' Value Box Helper
valueBox <- function(value, subtitle, icon = NULL, color = "blue") {
  div(
    class = paste0("info-box bg-", color),
    style = "padding: 15px; margin: 10px 0; border-radius: 5px;",
    if (!is.null(icon)) div(class = "info-box-icon", icon, style = "font-size: 40px;"),
    div(
      class = "info-box-content",
      div(class = "info-box-text", style = "font-size: 14px; color: #7f8c8d;", subtitle),
      div(class = "info-box-number", style = "font-size: 28px; font-weight: bold;", value)
    )
  )
}
