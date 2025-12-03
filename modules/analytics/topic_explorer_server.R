# =============================================================================
# Sprint 3: Topic Explorer Server Module
# =============================================================================
# Description: Shiny server logic for STM topic exploration
# Version: 1.0
# Date: January 2025
# =============================================================================

#' Topic Explorer Server Module
#'
#' Server logic for exploring STM topics, prevalence, and covariate effects
#'
#' @param id Character, module ID
#' @param db_pool Database connection pool
#'
#' @export
topic_explorer_server <- function(id, db_pool) {
  moduleServer(id, function(input, output, session) {

    # Reactive values
    rv <- reactiveValues(
      available_models = NULL,
      current_model = NULL,
      model_metadata = NULL,
      topics_data = NULL,
      doc_topics_data = NULL,
      covariate_effects = NULL
    )

    # ==========================================================================
    # Model Loading
    # ==========================================================================

    # Load available models on startup
    observe({
      req(db_pool)

      tryCatch({
        models <- dbGetQuery(db_pool,
          "SELECT id, num_topics, prevalence_formula, content_formula,
                  convergence_status, created_at
           FROM stm_models
           ORDER BY created_at DESC")

        if (nrow(models) > 0) {
          model_choices <- setNames(
            models$id,
            sprintf("K=%d (%s)", models$num_topics,
                   format(models$created_at, "%Y-%m-%d"))
          )

          updateSelectInput(
            session,
            "model_select",
            choices = c("Selecione um modelo" = "", model_choices),
            selected = ""
          )

          rv$available_models <- models
        } else {
          showNotification(
            "Nenhum modelo STM encontrado. Execute o treinamento primeiro.",
            type = "warning",
            duration = 5
          )
        }

      }, error = function(e) {
        # Only show notification for real errors, not missing table
        if (!grepl("does not exist", e$message, ignore.case = TRUE)) {
          logger::log_error("Error loading STM models: {e$message}")
          showNotification(
            sprintf("Erro ao carregar modelos: %s", e$message),
            type = "error",
            duration = 5
          )
        }
        # Silently ignore "relation does not exist" errors - table not created yet
      })
    })

    # Load selected model data
    observeEvent(input$model_select, {
      req(input$model_select, input$model_select != "")

      shinybusy::show_modal_spinner(
        spin = "fading-circle",
        text = "Carregando modelo STM..."
      )

      tryCatch({
        model_id <- as.integer(input$model_select)

        # Get model metadata
        metadata <- dbGetQuery(db_pool,
          sprintf("SELECT * FROM stm_models WHERE id = %d", model_id))

        # Get topics
        topics <- dbGetQuery(db_pool,
          sprintf("SELECT * FROM stm_topics WHERE model_id = %d
                   ORDER BY topic_number", model_id))

        # Get document-topic proportions (sample for performance)
        doc_topics <- dbGetQuery(db_pool,
          sprintf("SELECT dt.*, d.nivel, d.poder, EXTRACT(YEAR FROM d.data_publicacao)::integer as ano
                   FROM document_topics dt
                   JOIN documents d ON dt.document_id = d.id
                   WHERE dt.model_id = %d
                     AND dt.rank_position <= 3",  # Top 3 topics per document
                  model_id))

        rv$model_metadata <- metadata
        rv$topics_data <- topics
        rv$doc_topics_data <- doc_topics

        # Update topic selectors
        topic_choices <- setNames(
          topics$topic_number,
          sprintf("Tópico %d: %s", topics$topic_number,
                 sapply(topics$top_words, function(x) {
                   words <- strsplit(x, ",")[[1]][1:5]
                   paste(words, collapse = ", ")
                 }))
        )

        updateSelectInput(session, "topic_select", choices = topic_choices)
        updateSelectInput(session, "wordcloud_topic", choices = topic_choices)
        updateSelectInput(session, "repr_topic_select", choices = topic_choices)
        updateSelectInput(session, "search_topic", choices = topic_choices)
        updateSelectInput(session, "trend_topic_select", choices = topic_choices)

        shinybusy::remove_modal_spinner()

        showNotification(
          sprintf("Modelo carregado: %d tópicos", nrow(topics)),
          type = "message",
          duration = 3
        )

      }, error = function(e) {
        shinybusy::remove_modal_spinner()
        logger::log_error("Error loading model data: {e$message}")
        showNotification(
          sprintf("Erro ao carregar modelo: %s", e$message),
          type = "error",
          duration = 5
        )
      })
    })

    # ==========================================================================
    # Value Boxes
    # ==========================================================================

    output$total_topics_box <- renderUI({
      req(rv$topics_data)

      valueBox(
        value = nrow(rv$topics_data),
        subtitle = "Total de Tópicos",
        icon = icon("lightbulb"),
        color = "blue"
      )
    })

    output$total_documents_box <- renderUI({
      req(rv$doc_topics_data)

      valueBox(
        value = format(length(unique(rv$doc_topics_data$document_id)), big.mark = ","),
        subtitle = "Documentos Analisados",
        icon = icon("file-alt"),
        color = "green"
      )
    })

    output$vocab_size_box <- renderUI({
      req(rv$model_metadata)

      # Estimate vocab size (would need to store in DB for accuracy)
      valueBox(
        value = "~50k",
        subtitle = "Tamanho do Vocabulário",
        icon = icon("book"),
        color = "purple"
      )
    })

    # Model info
    output$model_info_ui <- renderUI({
      req(rv$model_metadata)

      meta <- rv$model_metadata

      tagList(
        p(strong("Detalhes do Modelo:")),
        p(sprintf("Tópicos: %d", meta$num_topics)),
        p(sprintf("Convergência: %s", meta$convergence_status)),
        p(sprintf("Criado: %s", format(meta$created_at, "%Y-%m-%d %H:%M")))
      )
    })

    # ==========================================================================
    # Topic Browser
    # ==========================================================================

    output$topic_words_ui <- renderUI({
      req(rv$topics_data, input$topic_select)

      topic_data <- rv$topics_data %>%
        filter(topic_number == as.integer(input$topic_select))

      if (nrow(topic_data) == 0) return(NULL)

      # Parse top words (stored as comma-separated string)
      words <- strsplit(topic_data$top_words, ",")[[1]]
      words <- head(words, input$top_words_n)

      # Display as tags
      tagList(
        lapply(words, function(w) {
          span(class = "badge badge-info", style = "margin: 3px; font-size: 14px;", w)
        })
      )
    })

    output$topic_proportion_ui <- renderUI({
      req(rv$topics_data, input$topic_select)

      topic_data <- rv$topics_data %>%
        filter(topic_number == as.integer(input$topic_select))

      if (nrow(topic_data) == 0) return(NULL)

      proportion <- topic_data$expected_proportion * 100

      tagList(
        div(
          style = "font-size: 24px; font-weight: bold; color: #2c3e50;",
          sprintf("%.2f%%", proportion)
        ),
        p(class = "text-muted",
          "Proporção esperada deste tópico no corpus")
      )
    })

    # ==========================================================================
    # Visualizations
    # ==========================================================================

    # Prevalence plot
    output$prevalence_plot <- plotly::renderPlotly({
      req(rv$topics_data)

      topics <- rv$topics_data %>%
        arrange(desc(expected_proportion)) %>%
        mutate(
          topic_label = sprintf("T%d", topic_number),
          prevalence_pct = expected_proportion * 100
        )

      p <- ggplot(topics, aes(x = reorder(topic_label, prevalence_pct),
                              y = prevalence_pct)) +
        geom_col(fill = "#3498db", alpha = 0.8) +
        coord_flip() +
        labs(
          title = "Prevalência dos Tópicos",
          x = "Tópico",
          y = "Proporção Esperada (%)"
        ) +
        theme_minimal() +
        theme(axis.text.y = element_text(size = 10))

      plotly::ggplotly(p)
    })

    # Correlation network
    output$correlation_network <- visNetwork::renderVisNetwork({
      req(rv$topics_data)

      # Placeholder: Would need topic correlation matrix from STM model
      # For now, create simple network based on prevalence

      topics <- rv$topics_data

      nodes <- data.frame(
        id = topics$topic_number,
        label = sprintf("T%d", topics$topic_number),
        value = topics$expected_proportion * 100,
        title = topics$topic_label,
        color = "#3498db"
      )

      # Create edges based on similar prevalence (placeholder logic)
      edges <- data.frame(
        from = integer(0),
        to = integer(0),
        value = numeric(0)
      )

      visNetwork::visNetwork(nodes, edges) %>%
        visNetwork::visNodes(
          font = list(size = 14),
          borderWidth = 2
        ) %>%
        visNetwork::visEdges(
          arrows = "to",
          smooth = TRUE
        ) %>%
        visNetwork::visOptions(
          highlightNearest = list(enabled = TRUE, degree = 1),
          nodesIdSelection = TRUE
        ) %>%
        visNetwork::visPhysics(
          stabilization = TRUE,
          barnesHut = list(gravitationalConstant = -5000)
        )
    })

    # Word cloud
    observeEvent(input$generate_wordcloud, {
      req(rv$topics_data, input$wordcloud_topic)

      output$wordcloud_plot <- renderPlot({
        topic_data <- rv$topics_data %>%
          filter(topic_number == as.integer(input$wordcloud_topic))

        if (nrow(topic_data) == 0) return(NULL)

        # Parse words and create frequency data
        words <- strsplit(topic_data$top_words, ",")[[1]]
        words <- head(words, input$wordcloud_words)

        # Assign decreasing frequencies
        freq <- rev(seq_along(words))

        # Create word cloud
        wordcloud::wordcloud(
          words = words,
          freq = freq,
          min.freq = 1,
          max.words = input$wordcloud_words,
          random.order = FALSE,
          rot.per = 0.35,
          colors = RColorBrewer::brewer.pal(8, "Dark2")
        )
      })
    })

    # Covariate effects
    output$effects_plot <- plotly::renderPlotly({
      req(rv$doc_topics_data, input$covariate_select)

      # Calculate average topic proportions by covariate
      if (input$covariate_select == "nivel") {
        # Compare two levels
        level1 <- input$nivel_value1
        level2 <- input$nivel_value2

        effects <- rv$doc_topics_data %>%
          filter(nivel %in% c(level1, level2)) %>%
          group_by(topic_number, nivel) %>%
          summarize(avg_proportion = mean(proportion), .groups = "drop") %>%
          tidyr::pivot_wider(
            names_from = nivel,
            values_from = avg_proportion,
            values_fill = 0
          ) %>%
          mutate(
            difference = get(level1) - get(level2)
          ) %>%
          arrange(desc(abs(difference))) %>%
          head(input$topics_to_show)

        p <- ggplot(effects, aes(x = reorder(sprintf("T%d", topic_number), difference),
                                 y = difference)) +
          geom_col(aes(fill = difference > 0), alpha = 0.8) +
          scale_fill_manual(
            values = c("TRUE" = "#27ae60", "FALSE" = "#e74c3c"),
            labels = c(sprintf("Maior em %s", level2), sprintf("Maior em %s", level1))
          ) +
          coord_flip() +
          labs(
            title = sprintf("Diferença de Prevalência: %s vs %s", level1, level2),
            x = "Tópico",
            y = "Diferença de Proporção",
            fill = "Categoria"
          ) +
          theme_minimal()

      } else if (input$covariate_select == "poder") {
        # Average by poder
        effects <- rv$doc_topics_data %>%
          group_by(topic_number, poder) %>%
          summarize(avg_proportion = mean(proportion), .groups = "drop") %>%
          arrange(desc(avg_proportion)) %>%
          group_by(poder) %>%
          slice_head(n = input$topics_to_show) %>%
          ungroup()

        p <- ggplot(effects, aes(x = reorder(sprintf("T%d", topic_number), avg_proportion),
                                 y = avg_proportion,
                                 fill = poder)) +
          geom_col(position = "dodge", alpha = 0.8) +
          coord_flip() +
          labs(
            title = "Prevalência por Poder",
            x = "Tópico",
            y = "Proporção Média",
            fill = "Poder"
          ) +
          theme_minimal()

      } else {
        # Time trends
        p <- ggplot() +
          annotate("text", x = 0.5, y = 0.5,
                  label = "Selecione covariável válida",
                  size = 6, color = "gray") +
          theme_void()
      }

      plotly::ggplotly(p)
    })

    # ==========================================================================
    # Representative Documents
    # ==========================================================================

    output$representative_docs_table <- DT::renderDataTable({
      req(rv$doc_topics_data, input$repr_topic_select, db_pool)

      topic_num <- as.integer(input$repr_topic_select)

      # Get top documents for this topic
      top_docs <- rv$doc_topics_data %>%
        filter(topic_number == topic_num) %>%
        arrange(desc(proportion)) %>%
        head(input$repr_docs_n)

      if (nrow(top_docs) == 0) return(NULL)

      # Fetch document details
      doc_ids <- paste(top_docs$document_id, collapse = ",")
      docs <- dbGetQuery(db_pool,
        sprintf("SELECT id, titulo, tipo_documento, nivel, data_publicacao
                 FROM documents
                 WHERE id IN (%s)", doc_ids))

      # Join with proportions
      result <- top_docs %>%
        left_join(docs, by = c("document_id" = "id")) %>%
        select(
          Rank = rank_position,
          `ID` = document_id,
          `Título` = titulo,
          `Tipo` = tipo_documento,
          `Nível` = nivel,
          `Proporção` = proportion,
          `Data` = data_publicacao
        )

      DT::datatable(
        result,
        options = list(
          pageLength = input$repr_docs_n,
          dom = 't'
        ),
        rownames = FALSE
      ) %>%
        DT::formatRound(columns = "Proporção", digits = 3) %>%
        DT::formatStyle(
          'Proporção',
          background = DT::styleColorBar(c(0, 1), '#90EE90'),
          backgroundSize = '100% 90%',
          backgroundRepeat = 'no-repeat',
          backgroundPosition = 'center'
        )
    })

    # ==========================================================================
    # Document Search by Topic
    # ==========================================================================

    observeEvent(input$search_by_topic_btn, {
      req(input$search_topic, db_pool)

      output$topic_search_results <- DT::renderDataTable({
        topic_num <- as.integer(input$search_topic)
        min_prop <- input$min_topic_proportion

        # Get documents with high proportion of this topic
        matching_docs <- rv$doc_topics_data %>%
          filter(
            topic_number == topic_num,
            proportion >= min_prop
          ) %>%
          arrange(desc(proportion))

        if (nrow(matching_docs) == 0) {
          showNotification(
            "Nenhum documento encontrado com os critérios especificados",
            type = "warning",
            duration = 3
          )
          return(NULL)
        }

        # Fetch document details
        doc_ids <- paste(matching_docs$document_id, collapse = ",")
        docs <- dbGetQuery(db_pool,
          sprintf("SELECT id, titulo, tipo_documento, nivel, data_publicacao, ementa
                   FROM documents
                   WHERE id IN (%s)", doc_ids))

        result <- matching_docs %>%
          left_join(docs, by = c("document_id" = "id")) %>%
          select(
            `ID` = document_id,
            `Título` = titulo,
            `Tipo` = tipo_documento,
            `Nível` = nivel,
            `Proporção` = proportion,
            `Data` = data_publicacao
          )

        DT::datatable(
          result,
          options = list(
            pageLength = 25,
            order = list(list(4, 'desc'))  # Sort by proportion
          ),
          rownames = FALSE
        ) %>%
          DT::formatRound(columns = "Proporção", digits = 3) %>%
          DT::formatStyle(
            'Proporção',
            background = DT::styleColorBar(range(result$Proporção), '#87CEEB'),
            backgroundSize = '100% 90%',
            backgroundRepeat = 'no-repeat',
            backgroundPosition = 'center'
          )
      })

      showNotification(
        sprintf("Busca concluída para Tópico %s", input$search_topic),
        type = "message",
        duration = 2
      )
    })

    # ==========================================================================
    # Time Trends
    # ==========================================================================

    output$time_trend_plot <- plotly::renderPlotly({
      req(rv$doc_topics_data, input$trend_topic_select)

      # Filter data
      trend_data <- rv$doc_topics_data %>%
        filter(topic_number %in% as.integer(input$trend_topic_select))

      if (input$trend_nivel != "all") {
        trend_data <- trend_data %>%
          filter(nivel == input$trend_nivel)
      }

      # Calculate average proportion by year and topic
      trends <- trend_data %>%
        group_by(ano, topic_number) %>%
        summarize(avg_proportion = mean(proportion), .groups = "drop") %>%
        arrange(ano)

      if (nrow(trends) == 0) return(NULL)

      p <- ggplot(trends, aes(x = ano, y = avg_proportion,
                              color = factor(topic_number),
                              group = factor(topic_number))) +
        geom_line(size = 1.2, alpha = 0.8) +
        geom_point(size = 2) +
        labs(
          title = "Tendência Temporal dos Tópicos",
          x = "Ano",
          y = "Proporção Média",
          color = "Tópico"
        ) +
        theme_minimal() +
        theme(legend.position = "right")

      plotly::ggplotly(p)
    })

  })
}

# =============================================================================
# Helper Functions
# =============================================================================

#' Value Box Helper (Consistent with other modules)
#'
#' Simple value box for displaying metrics
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
