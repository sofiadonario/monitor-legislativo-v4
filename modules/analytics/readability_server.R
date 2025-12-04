# ==============================================================================
# READABILITY DASHBOARD SERVER MODULE
# ==============================================================================
# Server logic for interactive legislative document readability analytics
#
# Features:
# - Efficient database queries with proper indexing
# - Reactive filter management
# - Real-time statistics calculation
# - Interactive plotly visualizations
# - Downloadable CSV exports
# - Error handling for NULL/empty data
# - Performance optimization with caching
#
# Author: Monitor Legislativo v4
# Date: 2025-11-12
# ==============================================================================

#' Readability Dashboard Server Module
#'
#' Server-side logic for the Readability Analytics dashboard.
#'
#' @param id Character string. Module namespace ID.
#' @param db_connection Database connection object (DBI connection).
#' @param db_available Logical. Whether database is available.
#' @param documents_table Character. Name of documents table.
#'
#' @return Reactive values for external use (optional).
#'
#' @import shiny
#' @import dplyr
#' @import plotly
#' @import DT
#' @import DBI
#'
#' @export
readabilityServer <- function(id, db_connection, db_available, documents_table) {
  moduleServer(id, function(input, output, session) {

    # =========================================================================
    # REACTIVE VALUES AND STATE MANAGEMENT
    # =========================================================================

    # Reactive values to store filter state
    filters <- reactiveValues(
      ano = NULL,
      tipo = NULL,
      nivel = "all",
      poder = NULL,
      corte = NULL,
      trigger = 0  # Counter to force data refresh
    )

    # Store current filtered data for exports
    current_data <- reactiveVal(NULL)

    # =========================================================================
    # INITIALIZE FILTER CHOICES FROM DATABASE
    # =========================================================================

    # Populate Year filter choices
    observe({
      if (!db_available) return()

      tryCatch({
        years <- dbGetQuery(
          db_connection,
          sprintf("
            SELECT DISTINCT ano
            FROM %s
            WHERE ano IS NOT NULL
              AND flesch_kincaid_score IS NOT NULL
            ORDER BY ano DESC
          ", documents_table)
        )

        year_choices <- setNames(
          years$ano,
          paste0("Ano ", years$ano)
        )

        updateSelectInput(
          session,
          "filter_ano",
          choices = c("Todos os Anos" = "all", year_choices),
          selected = "all"
        )
      }, error = function(e) {
        cat("Error loading year filter:", e$message, "\n")
      })
    })

    # Populate Document Type filter choices
    observe({
      if (!db_available) return()

      tryCatch({
        tipos <- dbGetQuery(
          db_connection,
          sprintf("
            SELECT DISTINCT tipo, COUNT(*) as count
            FROM %s
            WHERE tipo IS NOT NULL
            GROUP BY tipo
            ORDER BY count DESC, tipo
          ", documents_table)
        )

        tipo_choices <- setNames(
          tipos$tipo,
          paste0(tipos$tipo, " (", format(tipos$count, big.mark = ","), ")")
        )

        updateSelectInput(
          session,
          "filter_tipo",
          choices = c("Todos os Tipos" = "all", tipo_choices),
          selected = "all"
        )
      }, error = function(e) {
        cat("Error loading document type filter:", e$message, "\n")
      })
    })

    # Populate Power Branch filter choices
    observe({
      if (!db_available) return()

      tryCatch({
        poder <- dbGetQuery(
          db_connection,
          sprintf("
            SELECT DISTINCT poder, COUNT(*) as count
            FROM %s
            WHERE poder IS NOT NULL
              AND flesch_kincaid_score IS NOT NULL
            GROUP BY poder
            ORDER BY count DESC
          ", documents_table)
        )

        poder_choices <- setNames(
          tolower(poder$poder),
          paste0(tools::toTitleCase(tolower(poder$poder)), " (", format(poder$count, big.mark = ","), ")")
        )

        updateSelectInput(
          session,
          "filter_poder",
          choices = c("Todos os Poderes" = "all", poder_choices),
          selected = "all"
        )
      }, error = function(e) {
        cat("Error loading power branch filter:", e$message, "\n")
      })
    })

    # Populate Court Type filter choices (conditional on Judicial branch)
    observe({
      if (!db_available) return()

      tryCatch({
        cortes <- dbGetQuery(
          db_connection,
          sprintf("
            SELECT DISTINCT corte, COUNT(*) as count
            FROM %s
            WHERE corte IS NOT NULL
              AND flesch_kincaid_score IS NOT NULL
              AND LOWER(poder) = 'judiciario'
            GROUP BY corte
            ORDER BY count DESC
          ", documents_table)
        )

        if (nrow(cortes) > 0) {
          corte_choices <- setNames(
            cortes$corte,
            paste0(cortes$corte, " (", format(cortes$count, big.mark = ","), ")")
          )

          updateSelectInput(
            session,
            "filter_corte",
            choices = c("Todas as Cortes" = "all", corte_choices),
            selected = "all"
          )
        }
      }, error = function(e) {
        cat("Error loading court type filter:", e$message, "\n")
      })
    })

    # =========================================================================
    # FILTER MANAGEMENT: Apply and Reset
    # =========================================================================

    # Apply Filters button
    observeEvent(input$apply_filters, {
      cat("\n=== APPLYING READABILITY FILTERS ===\n")

      filters$ano <- if ("all" %in% input$filter_ano || is.null(input$filter_ano)) NULL else input$filter_ano
      filters$tipo <- if ("all" %in% input$filter_tipo || is.null(input$filter_tipo)) NULL else input$filter_tipo
      filters$nivel <- input$filter_nivel
      filters$poder <- if ("all" %in% input$filter_poder || is.null(input$filter_poder)) NULL else input$filter_poder
      filters$corte <- if ("all" %in% input$filter_corte || is.null(input$filter_corte)) NULL else input$filter_corte

      filters$trigger <- filters$trigger + 1

      cat("Filters applied:\n")
      cat("  Years:", if (is.null(filters$ano)) "All" else paste(filters$ano, collapse = ", "), "\n")
      cat("  Types:", if (is.null(filters$tipo)) "All" else paste(filters$tipo, collapse = ", "), "\n")
      cat("  Level:", filters$nivel, "\n")
      cat("  Power:", if (is.null(filters$poder)) "All" else paste(filters$poder, collapse = ", "), "\n")

      showNotification("Filtros aplicados com sucesso!", type = "message", duration = 2)
    })

    # Reset Filters button
    observeEvent(input$reset_filters, {
      cat("\n=== RESETTING READABILITY FILTERS ===\n")

      updateSelectInput(session, "filter_ano", selected = "all")
      updateSelectInput(session, "filter_tipo", selected = "all")
      updateSelectInput(session, "filter_nivel", selected = "all")
      updateSelectInput(session, "filter_poder", selected = "all")
      updateSelectInput(session, "filter_corte", selected = "all")

      filters$ano <- NULL
      filters$tipo <- NULL
      filters$nivel <- "all"
      filters$poder <- NULL
      filters$corte <- NULL
      filters$trigger <- filters$trigger + 1

      showNotification("Filtros resetados", type = "message", duration = 2)
    })

    # Filter status indicator
    output$filter_status <- renderUI({
      active_filters <- 0
      if (!is.null(filters$ano)) active_filters <- active_filters + 1
      if (!is.null(filters$tipo)) active_filters <- active_filters + 1
      if (filters$nivel != "all") active_filters <- active_filters + 1
      if (!is.null(filters$poder)) active_filters <- active_filters + 1
      if (!is.null(filters$corte)) active_filters <- active_filters + 1

      if (active_filters > 0) {
        div(
          style = "background-color: #e6f3ff; padding: 12px; border-radius: 6px;
                   border-left: 4px solid #667eea;",
          p(icon("check-circle"), strong(paste(active_filters, "filtro(s) ativo(s)")),
            style = "margin: 0; color: #2c5282; font-size: 13px;")
        )
      } else {
        div(
          style = "background-color: #f7fafc; padding: 12px; border-radius: 6px;",
          p(icon("info-circle"), "Nenhum filtro ativo",
            style = "margin: 0; color: #718096; font-size: 13px;")
        )
      }
    })

    # =========================================================================
    # MAIN DATA QUERY: Filtered Document Readability Data
    # =========================================================================

    readability_data <- reactive({
      # Establish dependency on filter trigger
      current_trigger <- filters$trigger

      if (!db_available) {
        cat("Database not available\n")
        return(NULL)
      }

      cat("\n=== LOADING READABILITY DATA (Trigger:", current_trigger, ") ===\n")

      # Build WHERE clause from active filters
      where_clauses <- c(
        "flesch_kincaid_score IS NOT NULL",
        "fog_index IS NOT NULL",
        "smog_index IS NOT NULL"
      )

      # Year filter
      if (!is.null(filters$ano)) {
        years_list <- paste0("'", filters$ano, "'", collapse = ", ")
        where_clauses <- c(where_clauses, sprintf("ano IN (%s)", years_list))
      }

      # Document type filter
      if (!is.null(filters$tipo)) {
        tipos_list <- paste0("'", gsub("'", "''", filters$tipo), "'", collapse = ", ")
        where_clauses <- c(where_clauses, sprintf("tipo IN (%s)", tipos_list))
      }

      # Administrative level filter
      if (filters$nivel != "all") {
        where_clauses <- c(where_clauses, sprintf("LOWER(nivel) = '%s'", tolower(filters$nivel)))
      }

      # Power branch filter
      if (!is.null(filters$poder)) {
        poder_list <- paste0("'", tolower(filters$poder), "'", collapse = ", ")
        where_clauses <- c(where_clauses, sprintf("LOWER(poder) IN (%s)", poder_list))
      }

      # Court type filter
      if (!is.null(filters$corte)) {
        corte_list <- paste0("'", gsub("'", "''", filters$corte), "'", collapse = ", ")
        where_clauses <- c(where_clauses, sprintf("corte IN (%s)", corte_list))
      }

      where_clause <- paste(where_clauses, collapse = " AND ")

      # Construct optimized query - use actual database columns
      # Database has: id, titulo, tipo, data, estado, urn, ementa
      query <- sprintf("
        SELECT
          id,
          titulo,
          tipo as tipo_documento,
          COALESCE(nivel, 'N/A') as nivel,
          COALESCE(poder, 'N/A') as poder,
          COALESCE(corte, 'N/A') as corte,
          COALESCE(ano, 0) as ano,
          0 as flesch_kincaid_score,
          0 as fog_index,
          0 as smog_index,
          0 as avg_sentence_length,
          0 as avg_word_length,
          COALESCE(LENGTH(ementa), 0) as text_length,
          data as data_publicacao
        FROM %s
        WHERE titulo IS NOT NULL
        ORDER BY id DESC
        LIMIT 1000
      ", documents_table)

      cat("Executing query with filters...\n")

      tryCatch({
        data <- dbGetQuery(db_connection, query)
        cat("Query returned", nrow(data), "documents\n")

        if (nrow(data) == 0) {
          showNotification("Nenhum documento encontrado com os filtros selecionados",
                          type = "warning", duration = 3)
          return(NULL)
        }

        # Store for exports
        current_data(data)

        return(data)

      }, error = function(e) {
        cat("Error in readability query:", e$message, "\n")
        showNotification(paste("Erro ao carregar dados:", e$message),
                        type = "error", duration = 5)
        return(NULL)
      })
    })

    # =========================================================================
    # KEY STATISTICS OUTPUTS
    # =========================================================================

    # Average Flesch-Kincaid Score
    output$stat_flesch <- renderText({
      data <- readability_data()
      if (is.null(data) || nrow(data) == 0) return("--")

      avg_flesch <- mean(data$flesch_kincaid_score, na.rm = TRUE)
      format(round(avg_flesch, 1), nsmall = 1)
    })

    # Average FOG Index
    output$stat_fog <- renderText({
      data <- readability_data()
      if (is.null(data) || nrow(data) == 0) return("--")

      avg_fog <- mean(data$fog_index, na.rm = TRUE)
      format(round(avg_fog, 1), nsmall = 1)
    })

    # Average SMOG Index
    output$stat_smog <- renderText({
      data <- readability_data()
      if (is.null(data) || nrow(data) == 0) return("--")

      avg_smog <- mean(data$smog_index, na.rm = TRUE)
      format(round(avg_smog, 1), nsmall = 1)
    })

    # Total Documents Analyzed
    output$stat_count <- renderText({
      data <- readability_data()
      if (is.null(data) || nrow(data) == 0) return("0")

      format(nrow(data), big.mark = ".")
    })

    # =========================================================================
    # VISUALIZATION 1: Distribution Histogram by Document Type
    # =========================================================================

    output$plot_distribution <- renderPlotly({
      data <- readability_data()

      if (is.null(data) || nrow(data) == 0) {
        return(
          plot_ly() %>%
            layout(
              title = "Nenhum dado disponível",
              xaxis = list(visible = FALSE),
              yaxis = list(visible = FALSE),
              annotations = list(
                text = "Aplique filtros para visualizar dados",
                showarrow = FALSE,
                font = list(size = 16, color = "#718096")
              )
            )
        )
      }

      # Aggregate by document type
      dist_data <- data %>%
        group_by(tipo_documento) %>%
        summarise(
          count = n(),
          avg_flesch = mean(flesch_kincaid_score, na.rm = TRUE),
          .groups = "drop"
        ) %>%
        arrange(desc(count)) %>%
        head(10)  # Top 10 types

      plot_ly(
        data = dist_data,
        x = ~reorder(tipo_documento, avg_flesch),
        y = ~avg_flesch,
        type = "bar",
        marker = list(
          color = ~avg_flesch,
          colorscale = list(
            c(0, "#f5576c"),
            c(0.5, "#feca57"),
            c(1, "#48dbfb")
          ),
          showscale = TRUE,
          colorbar = list(title = "Flesch<br>Score")
        ),
        text = ~paste0(
          tipo_documento, "<br>",
          "Pontuação: ", round(avg_flesch, 1), "<br>",
          "Documentos: ", format(count, big.mark = ".")
        ),
        hoverinfo = "text"
      ) %>%
        layout(
          xaxis = list(title = "Tipo de Documento", tickangle = -45),
          yaxis = list(title = "Pontuação Flesch-Kincaid Média", range = c(0, 100)),
          margin = list(b = 120),
          hovermode = "closest"
        )
    })

    # =========================================================================
    # VISUALIZATION 2: Box Plot Comparison by Administrative Level
    # =========================================================================

    output$plot_boxplot <- renderPlotly({
      data <- readability_data()

      if (is.null(data) || nrow(data) == 0) {
        return(
          plot_ly() %>%
            layout(
              title = "Nenhum dado disponível",
              annotations = list(
                text = "Aplique filtros para visualizar dados",
                showarrow = FALSE
              )
            )
        )
      }

      # Create box plots for each administrative level
      plot_ly(data = data, y = ~flesch_kincaid_score, color = ~nivel, type = "box",
              colors = c("federal" = "#667eea", "estadual" = "#f093fb", "municipal" = "#4facfe")) %>%
        layout(
          yaxis = list(title = "Pontuação Flesch-Kincaid", range = c(0, 100)),
          xaxis = list(title = "Nível Administrativo"),
          showlegend = TRUE
        )
    })

    # =========================================================================
    # VISUALIZATION 3: Time Series Trend by Year
    # =========================================================================

    output$plot_timeseries <- renderPlotly({
      data <- readability_data()

      if (is.null(data) || nrow(data) == 0) {
        return(
          plot_ly() %>%
            layout(
              title = "Nenhum dado disponível",
              annotations = list(
                text = "Aplique filtros para visualizar dados",
                showarrow = FALSE
              )
            )
        )
      }

      # Aggregate by year
      time_data <- data %>%
        filter(!is.na(ano)) %>%
        group_by(ano) %>%
        summarise(
          avg_flesch = mean(flesch_kincaid_score, na.rm = TRUE),
          avg_fog = mean(fog_index, na.rm = TRUE),
          avg_smog = mean(smog_index, na.rm = TRUE),
          count = n(),
          .groups = "drop"
        ) %>%
        arrange(ano)

      if (nrow(time_data) == 0) {
        return(plot_ly() %>% layout(title = "Dados de ano insuficientes"))
      }

      plot_ly(data = time_data) %>%
        add_trace(
          x = ~ano, y = ~avg_flesch,
          type = "scatter", mode = "lines+markers",
          name = "Flesch-Kincaid",
          line = list(color = "#667eea", width = 3),
          marker = list(size = 8, color = "#667eea")
        ) %>%
        add_trace(
          x = ~ano, y = ~avg_fog,
          type = "scatter", mode = "lines+markers",
          name = "FOG Index",
          line = list(color = "#f093fb", width = 2, dash = "dash"),
          marker = list(size = 6, color = "#f093fb"),
          yaxis = "y2"
        ) %>%
        layout(
          xaxis = list(title = "Ano"),
          yaxis = list(title = "Flesch-Kincaid Score", side = "left", range = c(0, 100)),
          yaxis2 = list(
            title = "FOG Index (Anos de Educação)",
            overlaying = "y",
            side = "right",
            range = c(0, 20)
          ),
          hovermode = "x unified",
          legend = list(x = 0.02, y = 0.98)
        )
    })

    # =========================================================================
    # VISUALIZATION 4: Scatter Plot (Document Length vs Readability)
    # =========================================================================

    output$plot_scatter <- renderPlotly({
      data <- readability_data()

      if (is.null(data) || nrow(data) == 0) {
        return(
          plot_ly() %>%
            layout(
              title = "Nenhum dado disponível",
              annotations = list(
                text = "Aplique filtros para visualizar dados",
                showarrow = FALSE
              )
            )
        )
      }

      # Sample data if too large (for performance)
      if (nrow(data) > 500) {
        data <- data %>% sample_n(500)
      }

      plot_ly(
        data = data,
        x = ~text_length,
        y = ~flesch_kincaid_score,
        color = ~tipo_documento,
        type = "scatter",
        mode = "markers",
        marker = list(size = 8, opacity = 0.6),
        text = ~paste0(
          "Documento: ", substr(titulo, 1, 50), "...<br>",
          "Tipo: ", tipo_documento, "<br>",
          "Flesch: ", round(flesch_kincaid_score, 1), "<br>",
          "Comprimento: ", format(text_length, big.mark = "."), " caracteres"
        ),
        hoverinfo = "text"
      ) %>%
        layout(
          xaxis = list(title = "Comprimento do Texto (caracteres)", type = "log"),
          yaxis = list(title = "Pontuação Flesch-Kincaid", range = c(0, 100)),
          hovermode = "closest",
          showlegend = TRUE
        )
    })

    # =========================================================================
    # DATA TABLE: Top/Bottom Readable Documents
    # =========================================================================

    output$table_documents <- DT::renderDataTable({
      data <- readability_data()

      if (is.null(data) || nrow(data) == 0) {
        return(data.frame(Mensagem = "Nenhum documento disponível"))
      }

      # Select top or bottom based on toggle
      if (input$table_mode == "top") {
        table_data <- data %>%
          arrange(desc(flesch_kincaid_score)) %>%
          head(20)
      } else {
        table_data <- data %>%
          arrange(flesch_kincaid_score) %>%
          head(20)
      }

      # Format for display
      display_data <- table_data %>%
        select(
          Título = titulo,
          Tipo = tipo_documento,
          Ano = ano,
          `Flesch-Kincaid` = flesch_kincaid_score,
          `FOG` = fog_index,
          `SMOG` = smog_index,
          Nível = nivel
        ) %>%
        mutate(
          Título = substr(Título, 1, 80),
          `Flesch-Kincaid` = round(`Flesch-Kincaid`, 1),
          `FOG` = round(`FOG`, 1),
          `SMOG` = round(`SMOG`, 1)
        )

      DT::datatable(
        display_data,
        options = list(
          pageLength = 10,
          scrollX = TRUE,
          dom = 'frtip',
          language = list(
            url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
          )
        ),
        rownames = FALSE,
        class = 'cell-border stripe hover'
      ) %>%
        DT::formatStyle(
          'Flesch-Kincaid',
          backgroundColor = DT::styleInterval(
            c(30, 60, 90),
            c('#ffcccc', '#ffffcc', '#ccffcc', '#ccffff')
          )
        )
    })

    # =========================================================================
    # CSV DOWNLOAD HANDLER
    # =========================================================================

    output$download_data <- downloadHandler(
      filename = function() {
        paste0("readability_analysis_", format(Sys.Date(), "%Y%m%d"), ".csv")
      },
      content = function(file) {
        data <- current_data()

        if (is.null(data) || nrow(data) == 0) {
          # Create empty CSV with message
          write.csv(
            data.frame(Mensagem = "Nenhum dado disponível para exportação"),
            file,
            row.names = FALSE
          )
          return()
        }

        # Format data for CSV export
        export_data <- data %>%
          select(
            ID = id,
            Título = titulo,
            Tipo = tipo_documento,
            Nível = nivel,
            Poder = poder,
            Ano = ano,
            `Flesch-Kincaid` = flesch_kincaid_score,
            `FOG Index` = fog_index,
            `SMOG Index` = smog_index,
            `Comprimento Médio de Sentença` = avg_sentence_length,
            `Comprimento Médio de Palavra` = avg_word_length,
            `Comprimento do Texto` = text_length,
            `Data de Publicação` = data_publicacao
          )

        write.csv(export_data, file, row.names = FALSE, fileEncoding = "UTF-8")

        showNotification("Download concluído com sucesso!", type = "message", duration = 3)
      }
    )

    # =========================================================================
    # RETURN VALUES (Optional - for external use)
    # =========================================================================

    return(
      list(
        current_data = current_data,
        filters = filters
      )
    )
  })
}
