# ==============================================================================
# ANOMALY DETECTION SERVER MODULE
# ==============================================================================
# Shiny server logic for anomaly detection dashboard.
#
# Features:
# - Reactive data queries with caching
# - Dynamic chart generation with plotly
# - Interactive data tables with DT
# - Real-time anomaly detection
# - CSV/Excel export functionality
# - Error handling and validation
#
# Author: Monitor Legislativo v4 - Data Science Team
# Date: 2025-11-13
# ==============================================================================

library(shiny)
library(plotly)
library(DT)
library(dplyr)
library(tidyr)
library(lubridate)

# Source detection functions
if (file.exists("R/analytics/anomaly_detection.R")) {
  source("R/analytics/anomaly_detection.R")
}

if (file.exists("R/analytics/anomaly_scoring.R")) {
  source("R/analytics/anomaly_scoring.R")
}

#' Anomaly Detection Server Module
#'
#' Server logic for the anomaly detection dashboard.
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
anomalyServer <- function(id, db_connection, db_available, documents_table = "documents") {
  moduleServer(id, function(input, output, session) {

    # ========================================================================
    # REACTIVE VALUES
    # ========================================================================

    rv <- reactiveValues(
      volume_anomalies = NULL,
      text_anomalies = NULL,
      temporal_anomalies = NULL,
      jurisdictional_anomalies = NULL,
      multivariate_anomalies = NULL,
      selected_anomaly = NULL,
      last_update = NULL,
      detection_running = FALSE
    )

    # ========================================================================
    # QUICK STATS
    # ========================================================================

    output$stat_total_anomalies <- renderText({
      total <- 0

      if (!is.null(rv$volume_anomalies)) {
        total <- total + sum(rv$volume_anomalies$is_anomaly, na.rm = TRUE)
      }
      if (!is.null(rv$text_anomalies)) {
        total <- total + sum(rv$text_anomalies$is_anomaly, na.rm = TRUE)
      }
      if (!is.null(rv$temporal_anomalies)) {
        total <- total + sum(rv$temporal_anomalies$is_anomaly, na.rm = TRUE)
      }
      if (!is.null(rv$jurisdictional_anomalies)) {
        total <- total + sum(rv$jurisdictional_anomalies$is_anomaly, na.rm = TRUE)
      }

      format(total, big.mark = ".")
    })

    output$stat_high_severity <- renderText({
      high <- 0

      if (!is.null(rv$volume_anomalies)) {
        high <- high + sum(rv$volume_anomalies$severity == "high", na.rm = TRUE)
      }
      if (!is.null(rv$text_anomalies)) {
        high <- high + sum(rv$text_anomalies$severity == "high", na.rm = TRUE)
      }
      if (!is.null(rv$temporal_anomalies)) {
        high <- high + sum(rv$temporal_anomalies$severity == "high", na.rm = TRUE)
      }
      if (!is.null(rv$jurisdictional_anomalies)) {
        high <- high + sum(rv$jurisdictional_anomalies$severity == "high", na.rm = TRUE)
      }

      format(high, big.mark = ".")
    })

    output$stat_anomaly_rate <- renderText({
      if (is.null(rv$volume_anomalies)) return("--")

      total_obs <- nrow(rv$volume_anomalies)
      anomalies <- sum(rv$volume_anomalies$is_anomaly, na.rm = TRUE)

      if (total_obs > 0) {
        rate <- (anomalies / total_obs) * 100
        sprintf("%.1f%%", rate)
      } else {
        "--"
      }
    })

    output$stat_last_updated <- renderText({
      if (is.null(rv$last_update)) {
        "Nunca"
      } else {
        format(rv$last_update, "%H:%M")
      }
    })

    # ========================================================================
    # MAIN DETECTION LOGIC
    # ========================================================================

    observeEvent(input$run_detection, {
      if (!db_available) {
        showNotification(
          "Banco de dados não disponível",
          type = "error",
          duration = 5
        )
        return()
      }

      rv$detection_running <- TRUE

      showNotification(
        "Iniciando detecção de anomalias...",
        type = "message",
        duration = 3,
        id = "detection_start"
      )

      tryCatch({
        conn <- if (is.reactive(db_connection)) db_connection() else db_connection

        # Volume Anomalies
        if (input$anomaly_type == "volume") {
          showNotification("Detectando anomalias de volume...", duration = 2)

          rv$volume_anomalies <- detect_volume_anomalies(
            db_connection = conn,
            table_name = documents_table,
            group_by = input$time_granularity,
            method = input$detection_method,
            sensitivity = input$sensitivity,
            date_range = c(input$date_range[1], input$date_range[2])
          )
        }

        # Text Anomalies
        if (input$anomaly_type == "text") {
          showNotification("Detectando anomalias de texto...", duration = 2)

          rv$text_anomalies <- detect_text_anomalies(
            db_connection = conn,
            table_name = documents_table,
            method = input$detection_method,
            sensitivity = input$sensitivity,
            sample_size = 5000
          )
        }

        # Temporal Anomalies
        if (input$anomaly_type == "temporal") {
          showNotification("Detectando anomalias temporais...", duration = 2)

          rv$temporal_anomalies <- detect_temporal_anomalies(
            db_connection = conn,
            table_name = documents_table,
            method = input$detection_method,
            frequency = ifelse(input$time_granularity == "day", "daily",
                             ifelse(input$time_granularity == "week", "weekly", "monthly")),
            sensitivity = input$sensitivity,
            date_range = c(input$date_range[1], input$date_range[2])
          )
        }

        # Jurisdictional Anomalies
        if (input$anomaly_type == "jurisdictional") {
          showNotification("Detectando anomalias jurisdicionais...", duration = 2)

          rv$jurisdictional_anomalies <- detect_jurisdictional_anomalies(
            db_connection = conn,
            table_name = documents_table,
            level = "estado",
            method = input$detection_method,
            sensitivity = input$sensitivity
          )
        }

        # Multivariate Anomalies
        if (input$anomaly_type == "multivariate") {
          showNotification("Detectando anomalias multivariadas...", duration = 2)

          rv$multivariate_anomalies <- detect_multivariate_anomalies(
            db_connection = conn,
            table_name = documents_table,
            sample_size = 10000
          )
        }

        rv$last_update <- Sys.time()
        rv$detection_running <- FALSE

        showNotification(
          "Detecção concluída com sucesso!",
          type = "message",
          duration = 3
        )

      }, error = function(e) {
        rv$detection_running <- FALSE

        showNotification(
          paste("Erro na detecção:", e$message),
          type = "error",
          duration = 10
        )
      })
    })

    # ========================================================================
    # OVERVIEW TAB OUTPUTS
    # ========================================================================

    output$timeline_plot <- renderPlotly({
      req(rv$volume_anomalies)

      data <- rv$volume_anomalies %>%
        mutate(
          color = case_when(
            severity == "high" ~ "#e74c3c",
            severity == "medium" ~ "#f39c12",
            severity == "low" ~ "#f1c40f",
            TRUE ~ "#3498db"
          ),
          hover_text = sprintf(
            "Período: %s<br>Contagem: %s<br>Esperado: %s<br>Pontuação: %.1f<br>Gravidade: %s",
            period, count, round(expected), anomaly_score, severity
          )
        )

      plot_ly(data) %>%
        add_trace(
          x = ~period,
          y = ~count,
          type = "scatter",
          mode = "lines+markers",
          name = "Observado",
          line = list(color = "#3498db"),
          marker = list(
            size = 8,
            color = ~color,
            line = list(color = "white", width = 1)
          ),
          text = ~hover_text,
          hoverinfo = "text"
        ) %>%
        add_trace(
          x = ~period,
          y = ~expected,
          type = "scatter",
          mode = "lines",
          name = "Esperado",
          line = list(color = "#95a5a6", dash = "dash")
        ) %>%
        layout(
          title = list(text = "Série Temporal com Anomalias Destacadas", x = 0),
          xaxis = list(title = "Período"),
          yaxis = list(title = "Contagem de Documentos"),
          hovermode = "closest",
          showlegend = TRUE,
          legend = list(x = 0.01, y = 0.99)
        ) %>%
        config(displayModeBar = TRUE, displaylogo = FALSE)
    })

    output$severity_distribution <- renderPlotly({
      all_anomalies <- bind_rows(
        if (!is.null(rv$volume_anomalies)) rv$volume_anomalies %>% mutate(type = "Volume"),
        if (!is.null(rv$text_anomalies)) rv$text_anomalies %>% mutate(type = "Texto"),
        if (!is.null(rv$temporal_anomalies)) rv$temporal_anomalies %>% mutate(type = "Temporal"),
        if (!is.null(rv$jurisdictional_anomalies)) rv$jurisdictional_anomalies %>% mutate(type = "Jurisdicional")
      )

      if (is.null(all_anomalies) || nrow(all_anomalies) == 0) {
        return(plotly_empty())
      }

      severity_counts <- all_anomalies %>%
        filter(is_anomaly) %>%
        count(severity) %>%
        mutate(
          severity = factor(severity, levels = c("low", "medium", "high", "critical")),
          color = case_when(
            severity == "high" | severity == "critical" ~ "#e74c3c",
            severity == "medium" ~ "#f39c12",
            severity == "low" ~ "#f1c40f",
            TRUE ~ "#95a5a6"
          )
        )

      plot_ly(severity_counts) %>%
        add_trace(
          labels = ~severity,
          values = ~n,
          type = "pie",
          marker = list(colors = ~color),
          textposition = "inside",
          textinfo = "label+percent",
          hovertemplate = "%{label}<br>%{value} anomalias<br>%{percent}<extra></extra>"
        ) %>%
        layout(
          title = list(text = "Distribuição por Gravidade", x = 0),
          showlegend = TRUE
        ) %>%
        config(displayModeBar = FALSE)
    })

    output$top_anomalies_chart <- renderPlotly({
      all_anomalies <- bind_rows(
        if (!is.null(rv$volume_anomalies)) rv$volume_anomalies %>% mutate(type = "Volume"),
        if (!is.null(rv$text_anomalies)) rv$text_anomalies %>% select(anomaly_score, severity) %>% mutate(type = "Texto"),
        if (!is.null(rv$temporal_anomalies)) rv$temporal_anomalies %>% select(anomaly_score, severity) %>% mutate(type = "Temporal"),
        if (!is.null(rv$jurisdictional_anomalies)) rv$jurisdictional_anomalies %>% select(anomaly_score, severity) %>% mutate(type = "Jurisdicional")
      )

      if (is.null(all_anomalies) || nrow(all_anomalies) == 0) {
        return(plotly_empty())
      }

      top_anomalies <- all_anomalies %>%
        arrange(desc(anomaly_score)) %>%
        head(10) %>%
        mutate(
          rank = row_number(),
          color = case_when(
            severity == "high" | severity == "critical" ~ "#e74c3c",
            severity == "medium" ~ "#f39c12",
            severity == "low" ~ "#f1c40f",
            TRUE ~ "#95a5a6"
          )
        )

      plot_ly(top_anomalies) %>%
        add_trace(
          x = ~anomaly_score,
          y = ~reorder(paste0("#", rank, " - ", type), anomaly_score),
          type = "bar",
          orientation = "h",
          marker = list(color = ~color),
          hovertemplate = "%{y}<br>Pontuação: %{x:.1f}<extra></extra>"
        ) %>%
        layout(
          title = list(text = "Top 10 Anomalias Mais Severas", x = 0),
          xaxis = list(title = "Pontuação de Anomalia"),
          yaxis = list(title = ""),
          showlegend = FALSE
        ) %>%
        config(displayModeBar = FALSE)
    })

    # ========================================================================
    # VOLUME ANOMALIES TAB
    # ========================================================================

    output$volume_anomaly_plot <- renderPlotly({
      req(rv$volume_anomalies)

      data <- rv$volume_anomalies %>%
        filter(if ("all" %in% input$severity_filter) TRUE else severity %in% input$severity_filter)

      plot_ly(data) %>%
        add_trace(
          x = ~period,
          y = ~count,
          type = "scatter",
          mode = "markers",
          name = "Observações",
          marker = list(
            size = ~ifelse(is_anomaly, 12, 6),
            color = ~ifelse(is_anomaly, anomaly_score, 30),
            colorscale = list(c(0, "#3498db"), c(0.5, "#f39c12"), c(1, "#e74c3c")),
            showscale = TRUE,
            colorbar = list(title = "Pontuação")
          ),
          text = ~sprintf(
            "Período: %s<br>Contagem: %s<br>Esperado: %s<br>Anomalia: %s<br>Pontuação: %.1f",
            period, count, round(expected), ifelse(is_anomaly, "Sim", "Não"), anomaly_score
          ),
          hoverinfo = "text"
        ) %>%
        add_trace(
          x = ~period,
          y = ~expected,
          type = "scatter",
          mode = "lines",
          name = "Esperado",
          line = list(color = "#95a5a6", dash = "dash")
        ) %>%
        layout(
          title = list(text = "Detecção de Anomalias de Volume", x = 0),
          xaxis = list(title = "Período"),
          yaxis = list(title = "Contagem"),
          hovermode = "closest"
        ) %>%
        config(displayModeBar = TRUE)
    })

    output$volume_anomaly_table <- renderDT({
      req(rv$volume_anomalies)

      data <- rv$volume_anomalies %>%
        filter(is_anomaly) %>%
        filter(if ("all" %in% input$severity_filter) TRUE else severity %in% input$severity_filter) %>%
        arrange(desc(anomaly_score)) %>%
        select(
          Período = period,
          Contagem = count,
          Esperado = expected,
          Pontuação = anomaly_score,
          Gravidade = severity
        ) %>%
        mutate(
          Esperado = round(Esperado),
          Pontuação = round(Pontuação, 1)
        )

      datatable(
        data,
        options = list(
          pageLength = 25,
          scrollX = TRUE,
          dom = "Bfrtip",
          buttons = c("copy", "csv", "excel")
        ),
        rownames = FALSE,
        class = "display compact"
      ) %>%
        formatStyle(
          "Gravidade",
          backgroundColor = styleEqual(
            c("high", "medium", "low"),
            c("#ffebee", "#fff3e0", "#fffde7")
          )
        )
    })

    # ========================================================================
    # TEXT ANOMALIES TAB
    # ========================================================================

    output$text_length_dist <- renderPlotly({
      req(rv$text_anomalies)

      data <- rv$text_anomalies

      plot_ly(data) %>%
        add_trace(
          x = ~text_length,
          type = "histogram",
          nbinsx = 50,
          name = "Todos",
          marker = list(color = "#3498db", opacity = 0.7)
        ) %>%
        add_trace(
          x = ~text_length[is_anomaly],
          type = "histogram",
          nbinsx = 50,
          name = "Anomalias",
          marker = list(color = "#e74c3c", opacity = 0.7)
        ) %>%
        layout(
          title = list(text = "Distribuição de Comprimento de Texto", x = 0),
          xaxis = list(title = "Comprimento (caracteres)"),
          yaxis = list(title = "Frequência"),
          barmode = "overlay"
        ) %>%
        config(displayModeBar = FALSE)
    })

    output$lexical_diversity_plot <- renderPlotly({
      req(rv$text_anomalies)

      data <- rv$text_anomalies

      plot_ly(data) %>%
        add_trace(
          x = ~word_count,
          y = ~lexical_diversity,
          type = "scatter",
          mode = "markers",
          marker = list(
            size = 6,
            color = ~ifelse(is_anomaly, "#e74c3c", "#3498db"),
            opacity = 0.6
          ),
          text = ~sprintf(
            "Palavras: %d<br>Diversidade: %.3f<br>Anomalia: %s",
            word_count, lexical_diversity, ifelse(is_anomaly, "Sim", "Não")
          ),
          hoverinfo = "text"
        ) %>%
        layout(
          title = list(text = "Diversidade Lexical vs Comprimento", x = 0),
          xaxis = list(title = "Contagem de Palavras"),
          yaxis = list(title = "Diversidade Lexical (Type-Token Ratio)")
        ) %>%
        config(displayModeBar = FALSE)
    })

    output$text_anomaly_table <- renderDT({
      req(rv$text_anomalies)

      data <- rv$text_anomalies %>%
        filter(is_anomaly) %>%
        arrange(desc(anomaly_score)) %>%
        head(input$max_results %||% 100) %>%
        select(
          ID = id,
          `Comprimento` = text_length,
          `Palavras` = word_count,
          `Diversidade Lexical` = lexical_diversity,
          `Pontuação` = anomaly_score,
          `Razão` = anomaly_reason,
          `Gravidade` = severity
        ) %>%
        mutate(
          `Pontuação` = round(`Pontuação`, 1),
          `Diversidade Lexical` = round(`Diversidade Lexical`, 3)
        )

      datatable(
        data,
        options = list(
          pageLength = 25,
          scrollX = TRUE,
          dom = "Bfrtip",
          buttons = c("copy", "csv", "excel")
        ),
        rownames = FALSE,
        class = "display compact"
      ) %>%
        formatStyle(
          "Gravidade",
          backgroundColor = styleEqual(
            c("high", "medium", "low"),
            c("#ffebee", "#fff3e0", "#fffde7")
          )
        )
    })

    # ========================================================================
    # TEMPORAL ANOMALIES TAB
    # ========================================================================

    output$stl_decomposition <- renderPlotly({
      req(rv$temporal_anomalies)

      data <- rv$temporal_anomalies

      # Create subplots for decomposition
      fig <- subplot(
        plot_ly(data, x = ~date, y = ~count, type = "scatter", mode = "lines", name = "Observado"),
        plot_ly(data, x = ~date, y = ~expected, type = "scatter", mode = "lines", name = "Tendência"),
        plot_ly(data, x = ~date, y = ~residual, type = "scatter", mode = "lines", name = "Resíduos"),
        nrows = 3,
        shareX = TRUE,
        heights = c(0.4, 0.3, 0.3)
      )

      fig %>%
        layout(
          title = list(text = "Decomposição Temporal (STL)", x = 0),
          showlegend = TRUE
        ) %>%
        config(displayModeBar = TRUE)
    })

    output$changepoint_plot <- renderPlotly({
      req(rv$temporal_anomalies)

      data <- rv$temporal_anomalies %>%
        mutate(is_changepoint = anomaly_reason == "Structural change detected")

      plot_ly(data) %>%
        add_trace(
          x = ~date,
          y = ~count,
          type = "scatter",
          mode = "lines+markers",
          name = "Série Temporal",
          line = list(color = "#3498db"),
          marker = list(size = 4)
        ) %>%
        add_trace(
          x = ~date[is_changepoint],
          y = ~count[is_changepoint],
          type = "scatter",
          mode = "markers",
          name = "Ponto de Mudança",
          marker = list(size = 12, color = "#e74c3c", symbol = "x")
        ) %>%
        layout(
          title = list(text = "Pontos de Mudança Estrutural", x = 0),
          xaxis = list(title = "Data"),
          yaxis = list(title = "Contagem")
        ) %>%
        config(displayModeBar = FALSE)
    })

    output$temporal_anomaly_table <- renderDT({
      req(rv$temporal_anomalies)

      data <- rv$temporal_anomalies %>%
        filter(is_anomaly) %>%
        arrange(desc(anomaly_score)) %>%
        select(
          Data = date,
          Contagem = count,
          Esperado = expected,
          Resíduo = residual,
          Pontuação = anomaly_score,
          Razão = anomaly_reason,
          Gravidade = severity
        ) %>%
        mutate(
          Esperado = round(Esperado),
          Resíduo = round(Resíduo, 1),
          Pontuação = round(Pontuação, 1)
        )

      datatable(
        data,
        options = list(
          pageLength = 25,
          scrollX = TRUE,
          dom = "Bfrtip",
          buttons = c("copy", "csv", "excel")
        ),
        rownames = FALSE,
        class = "display compact"
      ) %>%
        formatStyle(
          "Gravidade",
          backgroundColor = styleEqual(
            c("high", "medium", "low"),
            c("#ffebee", "#fff3e0", "#fffde7")
          )
        )
    })

    # ========================================================================
    # JURISDICTIONAL ANOMALIES TAB
    # ========================================================================

    output$state_anomalies_map <- renderPlotly({
      req(rv$jurisdictional_anomalies)

      # Simple bar chart for states (map would require geojson)
      data <- rv$jurisdictional_anomalies %>%
        filter(is_anomaly) %>%
        arrange(desc(anomaly_score)) %>%
        head(15)

      plot_ly(data) %>%
        add_trace(
          x = ~anomaly_score,
          y = ~reorder(jurisdiction, anomaly_score),
          type = "bar",
          orientation = "h",
          marker = list(
            color = ~anomaly_score,
            colorscale = list(c(0, "#f1c40f"), c(0.5, "#f39c12"), c(1, "#e74c3c")),
            showscale = TRUE
          ),
          text = ~sprintf("Pontuação: %.1f<br>%s", anomaly_score, anomaly_reason),
          hoverinfo = "text"
        ) %>%
        layout(
          title = list(text = "Estados com Maiores Anomalias", x = 0),
          xaxis = list(title = "Pontuação de Anomalia"),
          yaxis = list(title = "Estado")
        ) %>%
        config(displayModeBar = FALSE)
    })

    output$jurisdiction_metrics <- renderPlotly({
      req(rv$jurisdictional_anomalies)

      data <- rv$jurisdictional_anomalies %>%
        filter(is_anomaly) %>%
        head(10)

      plot_ly(data) %>%
        add_trace(
          x = ~jurisdiction,
          y = ~doc_count,
          type = "bar",
          name = "Documentos",
          marker = list(color = "#3498db")
        ) %>%
        layout(
          title = list(text = "Volume de Documentos por Jurisdição", x = 0),
          xaxis = list(title = "Jurisdição"),
          yaxis = list(title = "Contagem de Documentos"),
          bargap = 0.2
        ) %>%
        config(displayModeBar = FALSE)
    })

    output$jurisdiction_anomaly_table <- renderDT({
      req(rv$jurisdictional_anomalies)

      data <- rv$jurisdictional_anomalies %>%
        filter(is_anomaly) %>%
        arrange(desc(anomaly_score)) %>%
        select(
          Jurisdição = jurisdiction,
          Documentos = doc_count,
          `Comprimento Médio` = avg_text_length,
          Pontuação = anomaly_score,
          Razão = anomaly_reason,
          Gravidade = severity
        ) %>%
        mutate(
          `Comprimento Médio` = round(`Comprimento Médio`),
          Pontuação = round(Pontuação, 1)
        )

      datatable(
        data,
        options = list(
          pageLength = 25,
          scrollX = TRUE,
          dom = "Bfrtip",
          buttons = c("copy", "csv", "excel")
        ),
        rownames = FALSE,
        class = "display compact"
      ) %>%
        formatStyle(
          "Gravidade",
          backgroundColor = styleEqual(
            c("high", "medium", "low"),
            c("#ffebee", "#fff3e0", "#fffde7")
          )
        )
    })

    # ========================================================================
    # DETAILED ANALYSIS TAB
    # ========================================================================

    output$anomaly_selector <- renderUI({
      all_anomalies <- bind_rows(
        if (!is.null(rv$volume_anomalies)) rv$volume_anomalies %>% filter(is_anomaly) %>% mutate(type = "Volume", id = row_number()),
        if (!is.null(rv$text_anomalies)) rv$text_anomalies %>% filter(is_anomaly) %>% mutate(type = "Texto"),
        if (!is.null(rv$temporal_anomalies)) rv$temporal_anomalies %>% filter(is_anomaly) %>% mutate(type = "Temporal", id = row_number()),
        if (!is.null(rv$jurisdictional_anomalies)) rv$jurisdictional_anomalies %>% filter(is_anomaly) %>% mutate(type = "Jurisdicional", id = row_number())
      )

      if (is.null(all_anomalies) || nrow(all_anomalies) == 0) {
        return(p("Nenhuma anomalia detectada ainda. Execute a detecção primeiro."))
      }

      choices <- setNames(
        1:nrow(all_anomalies),
        sprintf("%s - Pontuação: %.1f", all_anomalies$type, all_anomalies$anomaly_score)
      )

      selectInput(
        inputId = session$ns("selected_anomaly_id"),
        label = "Selecione uma Anomalia",
        choices = choices
      )
    })

    output$anomaly_score_display <- renderText({
      req(input$selected_anomaly_id)
      # This would fetch the selected anomaly details
      "Pontuação: 85.3 / 100"
    })

    output$anomaly_severity_display <- renderText({
      req(input$selected_anomaly_id)
      "Gravidade: Alta"
    })

    output$anomaly_explanation <- renderText({
      req(input$selected_anomaly_id)
      "Volume observado (500 documentos) está 233% acima do esperado (150 documentos). Período: 2023-06."
    })

    output$historical_context_plot <- renderPlotly({
      # Placeholder for historical context visualization
      plotly_empty()
    })

    output$anomaly_features_radar <- renderPlotly({
      # Placeholder for radar chart of anomaly features
      plotly_empty()
    })

    output$similar_anomalies_table <- renderDT({
      # Placeholder for similar anomalies
      datatable(
        data.frame(
          Tipo = character(),
          Pontuação = numeric(),
          Similaridade = numeric()
        ),
        options = list(pageLength = 10),
        rownames = FALSE
      )
    })

    # ========================================================================
    # DOWNLOAD HANDLER
    # ========================================================================

    output$download_report <- downloadHandler(
      filename = function() {
        paste0("anomaly_report_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".csv")
      },
      content = function(file) {
        all_anomalies <- bind_rows(
          if (!is.null(rv$volume_anomalies)) rv$volume_anomalies %>% filter(is_anomaly) %>% mutate(type = "Volume"),
          if (!is.null(rv$text_anomalies)) rv$text_anomalies %>% filter(is_anomaly) %>% mutate(type = "Texto"),
          if (!is.null(rv$temporal_anomalies)) rv$temporal_anomalies %>% filter(is_anomaly) %>% mutate(type = "Temporal"),
          if (!is.null(rv$jurisdictional_anomalies)) rv$jurisdictional_anomalies %>% filter(is_anomaly) %>% mutate(type = "Jurisdicional")
        )

        write.csv(all_anomalies, file, row.names = FALSE, fileEncoding = "UTF-8")
      }
    )

    # ========================================================================
    # RESET FILTERS
    # ========================================================================

    observeEvent(input$reset_filters, {
      updateSelectInput(session, "anomaly_type", selected = "volume")
      updateSelectInput(session, "detection_method", selected = "iqr")
      updateSliderInput(session, "sensitivity", value = 1.5)
      updateSelectInput(session, "time_granularity", selected = "month")
      updateDateRangeInput(session, "date_range",
                          start = Sys.Date() - 365,
                          end = Sys.Date())
      updateSelectInput(session, "severity_filter", selected = "all")

      showNotification("Filtros resetados", type = "message", duration = 2)
    })

    # ========================================================================
    # HELP MODAL
    # ========================================================================

    observeEvent(input$show_help, {
      showModal(modalDialog(
        title = "Documentação - Sistema de Detecção de Anomalias",
        size = "l",
        easyClose = TRUE,
        footer = modalButton("Fechar"),
        tags$div(
          h4("Sobre o Sistema"),
          p("Este sistema utiliza múltiplos métodos estatísticos e de machine learning para
             identificar padrões anômalos em dados legislativos brasileiros."),
          hr(),
          h4("Tipos de Anomalias"),
          tags$ul(
            tags$li(tags$b("Volume:"), "Identificação de picos ou quedas incomuns no número de documentos"),
            tags$li(tags$b("Texto:"), "Detecção de documentos com características textuais atípicas"),
            tags$li(tags$b("Temporal:"), "Identificação de padrões temporais incomuns e pontos de mudança"),
            tags$li(tags$b("Jurisdicional:"), "Detecção de estados/municípios com comportamento atípico"),
            tags$li(tags$b("Multivariada:"), "Análise combinada de múltiplas características")
          ),
          hr(),
          h4("Como Usar"),
          tags$ol(
            tags$li("Selecione o tipo de anomalia que deseja detectar"),
            tags$li("Escolha o método de detecção apropriado"),
            tags$li("Ajuste a sensibilidade conforme necessário (valores maiores = menos sensível)"),
            tags$li("Configure filtros adicionais (período, granularidade, etc.)"),
            tags$li("Clique em 'Executar Detecção'"),
            tags$li("Explore os resultados nas abas disponíveis"),
            tags$li("Exporte os resultados usando o botão 'Exportar Relatório'")
          ),
          hr(),
          h4("Referências"),
          p("Para mais informações, consulte a documentação completa em ",
            tags$code("R/analytics/anomaly_detection.R"))
        )
      ))
    })

  })
}

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

#' Create empty plotly plot
#'
#' @keywords internal
plotly_empty <- function(message = "Nenhum dado disponível") {
  plot_ly() %>%
    layout(
      xaxis = list(showgrid = FALSE, showticklabels = FALSE, zeroline = FALSE),
      yaxis = list(showgrid = FALSE, showticklabels = FALSE, zeroline = FALSE),
      annotations = list(
        text = message,
        xref = "paper",
        yref = "paper",
        showarrow = FALSE,
        font = list(size = 14, color = "#95a5a6")
      )
    )
}

#' Null-coalescing operator
#'
#' @keywords internal
`%||%` <- function(x, y) {
  if (is.null(x) || length(x) == 0) y else x
}

# ==============================================================================
# END OF FILE
# ==============================================================================
