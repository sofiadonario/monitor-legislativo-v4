# =============================================================================
# Sprint 3: Semantic Search Server Module
# =============================================================================
# Description: Shiny server logic for semantic similarity search
# Version: 1.0
# Date: January 2025
# =============================================================================

#' Semantic Search Server Module
#'
#' Server logic for semantic similarity search
#'
#' @param id Character, module ID
#' @param db_pool Database connection pool
#'
#' @export
semantic_search_server <- function(id, db_pool) {
  moduleServer(id, function(input, output, session) {

    # Reactive values
    rv <- reactiveValues(
      search_results = NULL,
      query_doc_id = NULL,
      query_embedding = NULL
    )

    # Search button click
    observeEvent(input$search_btn, {
      req(db_pool)

      # Show loading
      shinybusy::show_modal_spinner(
        spin = "fading-circle",
        text = "Buscando documentos similares..."
      )

      tryCatch({
        # Get search results based on method
        if (input$search_method == "id") {
          # Search by document ID
          req(input$document_id)

          results <- search_similar_by_id(
            document_id = input$document_id,
            db_connection = db_pool,
            embedding_type = input$embedding_type,
            top_n = input$top_n,
            min_similarity = input$min_similarity
          )

          rv$query_doc_id <- input$document_id

        } else if (input$search_method == "text") {
          # Search by text
          req(input$query_text, nchar(input$query_text) > 10)

          results <- search_similar_by_text(
            query_text = input$query_text,
            db_connection = db_pool,
            embedding_type = input$embedding_type,
            top_n = input$top_n,
            min_similarity = input$min_similarity
          )

        } else if (input$search_method == "keyword") {
          # Search by keyword
          req(input$query_keyword)

          results <- search_similar_by_keyword(
            keyword = input$query_keyword,
            db_connection = db_pool,
            embedding_type = input$embedding_type,
            top_n = input$top_n,
            min_similarity = input$min_similarity
          )
        }

        rv$search_results <- results

        shinybusy::remove_modal_spinner()

        # Show success notification
        showNotification(
          sprintf("Encontrados %d documentos similares", nrow(results)),
          type = "message",
          duration = 3
        )

      }, error = function(e) {
        shinybusy::remove_modal_spinner()

        showNotification(
          sprintf("Erro na busca: %s", e$message),
          type = "error",
          duration = 5
        )

        logger::log_error("Semantic search error: {e$message}")
      })
    })

    # Results UI
    output$search_results_ui <- renderUI({
      req(rv$search_results)

      results <- rv$search_results

      tagList(
        wellPanel(
          h4(icon("check-circle"), sprintf(" %d Documentos Similares Encontrados", nrow(results))),

          fluidRow(
            column(4,
              valueBox(
                value = sprintf("%.2f", mean(results$similarity_score)),
                subtitle = "Similaridade Média",
                icon = icon("chart-line"),
                color = "blue"
              )
            ),

            column(4,
              valueBox(
                value = sprintf("%.2f", max(results$similarity_score)),
                subtitle = "Maior Similaridade",
                icon = icon("arrow-up"),
                color = "green"
              )
            ),

            column(4,
              valueBox(
                value = length(unique(results$nivel)),
                subtitle = "Níveis Jurisdicionais",
                icon = icon("balance-scale"),
                color = "purple"
              )
            )
          )
        )
      )
    })

    # Results table
    output$results_table <- DT::renderDataTable({
      req(rv$search_results)

      results <- apply_filters(rv$search_results, input)

      DT::datatable(
        results %>%
          select(
            Rank = rank_position,
            `ID` = similar_document_id,
            `Título` = titulo,
            `Tipo` = tipo_documento,
            `Nível` = nivel,
            `Similaridade` = similarity_score,
            `Ano` = ano
          ),
        options = list(
          pageLength = 10,
          order = list(list(0, 'asc')),  # Order by rank
          columnDefs = list(
            list(className = 'dt-center', targets = c(0, 1, 5, 6))
          )
        ),
        selection = "single",
        rownames = FALSE
      ) %>%
        DT::formatRound(columns = "Similaridade", digits = 3) %>%
        DT::formatStyle(
          'Similaridade',
          background = DT::styleColorBar(c(0, 1), 'lightblue'),
          backgroundSize = '100% 90%',
          backgroundRepeat = 'no-repeat',
          backgroundPosition = 'center'
        )
    })

    # Similarity distribution plot
    output$similarity_dist <- plotly::renderPlotly({
      req(rv$search_results)

      results <- apply_filters(rv$search_results, input)

      p <- ggplot(results, aes(x = similarity_score)) +
        geom_histogram(bins = 20, fill = "#3498db", alpha = 0.7) +
        geom_vline(xintercept = mean(results$similarity_score),
                  linetype = "dashed", color = "red", size = 1) +
        labs(
          title = "Distribuição de Scores de Similaridade",
          x = "Score de Similaridade",
          y = "Número de Documentos"
        ) +
        theme_minimal()

      plotly::ggplotly(p)
    })

    # Embedding visualization (placeholder)
    output$embedding_viz <- plotly::renderPlotly({
      # Placeholder for UMAP/t-SNE visualization
      # Would require actual embedding data and dimensionality reduction

      plotly::plot_ly() %>%
        plotly::add_text(
          x = 0.5, y = 0.5,
          text = "Visualização em desenvolvimento\nRequer cálculo de UMAP/t-SNE",
          textfont = list(size = 16, color = "gray")
        ) %>%
        plotly::layout(
          xaxis = list(visible = FALSE),
          yaxis = list(visible = FALSE)
        )
    })

    # Similarity network (placeholder)
    output$similarity_network <- visNetwork::renderVisNetwork({
      req(rv$search_results)

      # Placeholder network visualization
      # Would build graph from similarity matrix

      nodes <- data.frame(
        id = 1,
        label = "Query\nDocument",
        color = "red"
      )

      edges <- data.frame(
        from = integer(0),
        to = integer(0)
      )

      visNetwork::visNetwork(nodes, edges) %>%
        visNetwork::visNodes(font = list(size = 14)) %>%
        visNetwork::visEdges(arrows = "to") %>%
        visNetwork::visOptions(highlightNearest = TRUE)
    })

  })
}

# =============================================================================
# Helper Functions
# =============================================================================

#' Search Similar Documents by ID
#'
#' Find similar documents using pre-computed similarity cache
#'
#' @param document_id Integer, query document ID
#' @param db_connection Database connection
#' @param embedding_type Character, "word2vec" or "glove"
#' @param top_n Integer, number of results
#' @param min_similarity Numeric, minimum similarity threshold
#'
#' @return Data frame with similar documents
search_similar_by_id <- function(document_id,
                                  db_connection,
                                  embedding_type = "word2vec",
                                  top_n = 10,
                                  min_similarity = 0.5) {

  logger::log_info("Searching similar documents for ID {document_id}")

  # Use materialized view for fast retrieval
  query <- sprintf("
    SELECT
      ssc.rank_position,
      ssc.doc2_id AS similar_document_id,
      ssc.similarity_score,
      d.titulo,
      d.tipo_documento,
      d.nivel,
      d.estado_mapeado,
      EXTRACT(YEAR FROM d.data_publicacao)::integer AS ano,
      d.data_publicacao
    FROM semantic_similarity_cache ssc
    JOIN documents d ON ssc.doc2_id = d.id
    WHERE ssc.doc1_id = %d
      AND ssc.embedding_type = '%s'
      AND ssc.similarity_score >= %f
      AND ssc.rank_position <= %d
    ORDER BY ssc.rank_position
  ", document_id, embedding_type, min_similarity, top_n)

  results <- dbGetQuery(db_connection, query)

  if (nrow(results) == 0) {
    logger::log_warn("No similar documents found for ID {document_id}")
  } else {
    logger::log_info("Found {nrow(results)} similar documents")
  }

  return(results)
}

#' Search Similar Documents by Text
#'
#' Compute embedding for query text and find similar documents
#'
#' @param query_text Character, query text
#' @param db_connection Database connection
#' @param embedding_type Character, "word2vec" or "glove"
#' @param top_n Integer, number of results
#' @param min_similarity Numeric, minimum similarity threshold
#'
#' @return Data frame with similar documents
search_similar_by_text <- function(query_text,
                                    db_connection,
                                    embedding_type = "word2vec",
                                    top_n = 10,
                                    min_similarity = 0.5) {

  logger::log_info("Searching by text query (length: {nchar(query_text)})")

  # This would require:
  # 1. Load word vectors from database
  # 2. Compute document embedding for query text
  # 3. Compute similarity with all documents
  # 4. Return top N

  # Placeholder implementation
  logger::log_warn("Text search not fully implemented yet")

  return(data.frame(
    rank_position = integer(0),
    similar_document_id = integer(0),
    similarity_score = numeric(0),
    titulo = character(0),
    tipo_documento = character(0),
    nivel = character(0),
    estado_mapeado = character(0),
    ano = integer(0),
    data_publicacao = as.Date(character(0))
  ))
}

#' Search Similar Documents by Keyword
#'
#' Find documents containing keyword, then return their neighbors
#'
#' @param keyword Character, search keyword
#' @param db_connection Database connection
#' @param embedding_type Character, "word2vec" or "glove"
#' @param top_n Integer, number of results
#' @param min_similarity Numeric, minimum similarity threshold
#'
#' @return Data frame with similar documents
search_similar_by_keyword <- function(keyword,
                                       db_connection,
                                       embedding_type = "word2vec",
                                       top_n = 10,
                                       min_similarity = 0.5) {

  logger::log_info("Searching by keyword: {keyword}")

  # Find documents containing keyword
  query_find <- sprintf("
    SELECT id
    FROM documents
    WHERE texto ILIKE '%%%s%%'
    LIMIT 1
  ", keyword)

  doc_id_result <- dbGetQuery(db_connection, query_find)

  if (nrow(doc_id_result) == 0) {
    logger::log_warn("No documents found containing keyword: {keyword}")
    return(data.frame())
  }

  doc_id <- doc_id_result$id[1]

  # Use ID search
  return(search_similar_by_id(
    document_id = doc_id,
    db_connection = db_connection,
    embedding_type = embedding_type,
    top_n = top_n,
    min_similarity = min_similarity
  ))
}

#' Apply Filters to Search Results
#'
#' Filter results by jurisdiction, type, year
#'
#' @param results Data frame, search results
#' @param input Shiny input object
#'
#' @return Filtered data frame
apply_filters <- function(results, input) {

  filtered <- results

  # Filter by jurisdiction level
  if (!is.null(input$filter_nivel) && input$filter_nivel != "all") {
    filtered <- filtered %>% filter(nivel == input$filter_nivel)
  }

  # Filter by document type
  if (!is.null(input$filter_tipo) && input$filter_tipo != "all") {
    filtered <- filtered %>% filter(tipo_documento == input$filter_tipo)
  }

  # Filter by year
  if (!is.null(input$filter_year)) {
    filtered <- filtered %>%
      filter(ano >= input$filter_year[1], ano <= input$filter_year[2])
  }

  return(filtered)
}

#' Value Box Helper (if not using shinydashboard)
#'
#' Simple value box for displaying metrics
valueBox <- function(value, subtitle, icon = NULL, color = "blue") {
  div(
    class = paste0("info-box bg-", color),
    style = "padding: 15px; margin: 10px 0;",
    if (!is.null(icon)) div(class = "info-box-icon", icon),
    div(
      class = "info-box-content",
      div(class = "info-box-text", subtitle),
      div(class = "info-box-number", value)
    )
  )
}
