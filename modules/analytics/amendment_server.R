#' Amendment Pattern Analysis Server Module
#'
#' Shiny module server logic for amendment pattern analysis
#'
#' @author Monitor Legislativo Analytics Team
#' @date 2025-01-13

library(shiny)
library(DBI)
library(dplyr)
library(plotly)
library(DT)

# visNetwork is optional
VISNETWORK_AVAILABLE <- requireNamespace("visNetwork", quietly = TRUE)
if (VISNETWORK_AVAILABLE) {
  library(visNetwork)
}

#' Amendment Analysis Server
#'
#' @param id Module namespace ID
#' @param db_connection Reactive database connection
#' @export
amendment_server <- function(id, db_connection) {
  moduleServer(id, function(input, output, session) {

    # Source the core analytics functions
    source("R/analytics/amendment_patterns.R", local = TRUE)

    # Reactive values to store results
    rv <- reactiveValues(
      amendments = NULL,
      timeline_data = NULL,
      hotspots = NULL,
      cascades = NULL,
      velocity = NULL,
      cross_jurisdiction = NULL,
      last_update = NULL
    )

    # ========================================================================
    # VALUE BOXES (Header)
    # ========================================================================

    output$total_amendments_box <- renderValueBox({
      count <- if (!is.null(rv$amendments)) nrow(rv$amendments) else 0

      valueBox(
        value = format(count, big.mark = ","),
        subtitle = "Total de Emendas",
        icon = icon("file-signature"),
        color = "blue"
      )
    })

    output$hotspots_box <- renderValueBox({
      count <- if (!is.null(rv$hotspots)) nrow(rv$hotspots) else 0

      valueBox(
        value = count,
        subtitle = "Hotspots Identificados",
        icon = icon("fire"),
        color = "red"
      )
    })

    output$cascades_box <- renderValueBox({
      count <- if (!is.null(rv$cascades)) nrow(rv$cascades) else 0

      valueBox(
        value = count,
        subtitle = "Cascatas Detectadas",
        icon = icon("sitemap"),
        color = "orange"
      )
    })

    output$velocity_box <- renderValueBox({
      avg_vel <- if (!is.null(rv$velocity) && nrow(rv$velocity) > 0) {
        mean(rv$velocity$velocity, na.rm = TRUE)
      } else {
        0
      }

      valueBox(
        value = sprintf("%.1f", avg_vel),
        subtitle = "Velocidade Média (emendas/ano)",
        icon = icon("tachometer-alt"),
        color = "green"
      )
    })

    # ========================================================================
    # MAIN ANALYSIS EXECUTION
    # ========================================================================

    observeEvent(input$run_analysis, {
      req(db_connection())

      showModal(modalDialog(
        title = "Executando Análise...",
        "Por favor aguarde enquanto processamos os dados.",
        footer = NULL,
        easyClose = FALSE
      ))

      tryCatch({
        # Extract parameters
        year_range <- input$year_range
        jurisdiction <- if (input$jurisdiction_filter == "all") NULL else input$jurisdiction_filter

        # Run core identification
        amendments <- identify_amendments(
          db_connection = db_connection(),
          year_range = year_range,
          jurisdiction_filter = jurisdiction
        )

        rv$amendments <- amendments
        rv$last_update <- Sys.time()

        # Run mode-specific analyses
        if (input$analysis_mode == "timeline" && (!is.null(input$focal_doc_id) || input$focal_doc_urn != "")) {
          doc_id <- if (input$focal_doc_urn != "") input$focal_doc_urn else input$focal_doc_id

          timeline <- build_amendment_timeline(
            db_connection = db_connection(),
            doc_id = doc_id,
            max_depth = input$max_depth
          )

          rv$timeline_data <- timeline

        } else if (input$analysis_mode == "hotspots") {
          hotspots <- detect_amendment_hotspots(
            db_connection = db_connection(),
            min_amendments = input$min_amendments,
            top_n = input$top_n_hotspots
          )

          rv$hotspots <- hotspots

        } else if (input$analysis_mode == "cascades") {
          cascades <- analyze_amendment_cascades(
            db_connection = db_connection(),
            min_chain_length = input$min_chain_length
          )

          rv$cascades <- cascades

        } else if (input$analysis_mode == "velocity") {
          velocity <- calculate_amendment_velocity(
            db_connection = db_connection(),
            window_years = input$window_years,
            by_jurisdiction = input$by_jurisdiction
          )

          rv$velocity <- velocity

        } else if (input$analysis_mode == "cross_jurisdiction") {
          cross_juris <- cross_jurisdiction_amendments(
            db_connection = db_connection()
          )

          rv$cross_jurisdiction <- cross_juris
        }

        removeModal()

        showNotification(
          sprintf("Análise concluída! %d emendas identificadas.", nrow(amendments)),
          type = "message"
        )

      }, error = function(e) {
        removeModal()
        showNotification(
          paste("Erro na análise:", e$message),
          type = "error",
          duration = 10
        )
      })
    })

    # Refresh data
    observeEvent(input$refresh_data, {
      rv$amendments <- NULL
      rv$timeline_data <- NULL
      rv$hotspots <- NULL
      rv$cascades <- NULL
      rv$velocity <- NULL
      rv$cross_jurisdiction <- NULL
      rv$last_update <- NULL

      showNotification("Dados limpos. Execute a análise novamente.", type = "message")
    })

    # ========================================================================
    # OVERVIEW TAB
    # ========================================================================

    output$overview_stats <- renderUI({
      req(rv$amendments)

      amendments <- rv$amendments

      total <- nrow(amendments)
      by_type <- table(amendments$amendment_type)
      by_jurisdiction <- if ("nivel" %in% names(amendments)) {
        table(amendments$nivel)
      } else {
        NULL
      }

      year_range <- range(amendments$ano, na.rm = TRUE)

      tagList(
        div(
          p(strong("Total de Emendas:"), format(total, big.mark = ",")),
          p(strong("Período:"), paste(year_range, collapse = " - ")),
          hr(),
          h5("Por Tipo:"),
          tags$ul(
            lapply(names(by_type), function(type) {
              tags$li(strong(type), ": ", by_type[type])
            })
          ),
          if (!is.null(by_jurisdiction)) {
            tagList(
              hr(),
              h5("Por Jurisdição:"),
              tags$ul(
                lapply(names(by_jurisdiction), function(juris) {
                  tags$li(strong(juris), ": ", by_jurisdiction[juris])
                })
              )
            )
          }
        )
      )
    })

    output$amendment_distribution <- renderPlotly({
      req(rv$amendments)

      data <- rv$amendments %>%
        count(amendment_type, name = "count")

      plot_ly(data, labels = ~amendment_type, values = ~count, type = "pie") %>%
        layout(title = "Distribuição por Tipo")
    })

    output$recent_amendments_table <- DT::renderDataTable({
      req(rv$amendments)

      rv$amendments %>%
        arrange(desc(ano)) %>%
        head(50) %>%
        select(
          ID = id,
          Título = titulo,
          Tipo = amendment_type,
          Ano = ano,
          Jurisdição = nivel,
          `Leis Referenciadas` = referenced_laws
        ) %>%
        datatable(
          options = list(
            pageLength = 10,
            scrollX = TRUE
          ),
          rownames = FALSE
        )
    })

    # ========================================================================
    # TIMELINE TAB
    # ========================================================================

    output$focal_doc_info <- renderUI({
      req(rv$timeline_data)

      focal <- rv$timeline_data$focal

      div(
        class = "alert alert-info",
        h4(strong("Documento Focal")),
        p(
          strong("ID:"), focal$id, br(),
          strong("Título:"), focal$titulo, br(),
          strong("Ano:"), focal$ano, br(),
          if (!is.na(focal$nivel)) tagList(strong("Jurisdição:"), focal$nivel, br()),
          if (!is.na(focal$tipo)) tagList(strong("Tipo:"), focal$tipo)
        )
      )
    })

    output$timeline_network <- renderVisNetwork({
      req(rv$timeline_data)

      network <- rv$timeline_data$network
      nodes <- network$nodes
      edges <- network$edges

      if (nrow(nodes) == 0) {
        return(NULL)
      }

      # Prepare nodes for visNetwork
      nodes <- nodes %>%
        mutate(
          title = paste0(label, " (", year, ")"),
          color = case_when(
            type == "focal" ~ "#e74c3c",
            type == "amends_focal" ~ "#3498db",
            type == "amended_by_focal" ~ "#2ecc71",
            TRUE ~ "#95a5a6"
          ),
          size = case_when(
            type == "focal" ~ 30,
            TRUE ~ 20
          )
        )

      # Prepare edges
      if (nrow(edges) > 0) {
        edges <- edges %>%
          mutate(
            arrows = "to",
            color = list(color = "#95a5a6", opacity = 0.6)
          )
      }

      visNetwork(nodes, edges) %>%
        visOptions(
          highlightNearest = list(enabled = TRUE, degree = 1),
          nodesIdSelection = TRUE
        ) %>%
        visPhysics(
          stabilization = TRUE,
          barnesHut = list(gravitationalConstant = -5000, springLength = 150)
        ) %>%
        visInteraction(
          navigationButtons = TRUE,
          zoomView = TRUE
        ) %>%
        visLegend(
          addNodes = list(
            list(label = "Focal", color = "#e74c3c", shape = "dot", size = 20),
            list(label = "Emenda o Focal", color = "#3498db", shape = "dot", size = 15),
            list(label = "Emendado pelo Focal", color = "#2ecc71", shape = "dot", size = 15)
          ),
          useGroups = FALSE
        )
    })

    output$timeline_plot <- renderPlotly({
      req(rv$timeline_data)

      timeline <- rv$timeline_data$timeline
      focal_year <- rv$timeline_data$focal$ano

      if (nrow(timeline) == 0) {
        return(plotly_empty())
      }

      plot_ly(timeline) %>%
        add_segments(
          x = ~ano, xend = ~ano,
          y = 0, yend = 1,
          color = ~direction,
          hoverinfo = "text",
          text = ~paste0(titulo, "\n", ano)
        ) %>%
        add_markers(
          x = ~ano,
          y = 1,
          color = ~direction,
          hoverinfo = "text",
          text = ~paste0(titulo, "\n", ano)
        ) %>%
        add_segments(
          x = focal_year, xend = focal_year,
          y = 0, yend = 1,
          line = list(color = "red", width = 3, dash = "dash"),
          name = "Documento Focal",
          hoverinfo = "text",
          text = "Documento Focal"
        ) %>%
        layout(
          title = "Timeline de Emendas",
          xaxis = list(title = "Ano"),
          yaxis = list(title = "", showticklabels = FALSE),
          hovermode = "closest"
        )
    })

    output$timeline_table <- DT::renderDataTable({
      req(rv$timeline_data)

      rv$timeline_data$timeline %>%
        arrange(ano) %>%
        select(
          ID = id,
          Título = titulo,
          Ano = ano,
          Tipo = tipo,
          Direção = direction
        ) %>%
        datatable(
          options = list(pageLength = 25),
          rownames = FALSE
        )
    })

    # ========================================================================
    # HOTSPOTS TAB
    # ========================================================================

    output$hotspots_summary <- renderUI({
      req(rv$hotspots)

      hotspots <- rv$hotspots %>% head(10)

      tagList(
        tags$ol(
          lapply(1:nrow(hotspots), function(i) {
            h <- hotspots[i, ]
            tags$li(
              strong(h$refs), br(),
              sprintf("Emendas: %d", h$amendment_count), br(),
              if (!is.na(h$doc_year)) sprintf("Ano: %d", h$doc_year) else "",
              br(),
              tags$span(
                class = paste0("badge badge-", if(h$category == "Muito Alto") "danger" else if(h$category == "Alto") "warning" else "info"),
                h$category
              )
            )
          })
        )
      )
    })

    output$hotspots_chart <- renderPlotly({
      req(rv$hotspots)

      data <- rv$hotspots %>%
        head(20) %>%
        mutate(
          label = paste0(refs, if_else(!is.na(doc_year), paste0(" (", doc_year, ")"), ""))
        )

      plot_ly(data, x = ~amendment_count, y = ~reorder(label, amendment_count), type = "bar",
              orientation = "h",
              marker = list(
                color = ~hotspot_score,
                colorscale = "Reds",
                showscale = TRUE,
                colorbar = list(title = "Score")
              ),
              text = ~paste0(amendment_count, " emendas"),
              hoverinfo = "text") %>%
        layout(
          title = "Top Leis Mais Emendadas",
          xaxis = list(title = "Número de Emendas"),
          yaxis = list(title = ""),
          margin = list(l = 200)
        )
    })

    output$hotspots_heatmap <- renderPlotly({
      req(rv$hotspots, rv$amendments)

      # Create year x hotspot heatmap
      hotspot_refs <- rv$hotspots$refs[1:min(10, nrow(rv$hotspots))]

      amendments_filtered <- rv$amendments %>%
        filter(!is.na(referenced_laws)) %>%
        mutate(refs_list = str_split(referenced_laws, ";\\s*")) %>%
        unnest(refs_list) %>%
        filter(refs_list %in% hotspot_refs) %>%
        count(ano, refs_list) %>%
        complete(ano, refs_list, fill = list(n = 0))

      plot_ly(amendments_filtered, x = ~ano, y = ~refs_list, z = ~n, type = "heatmap",
              colors = "Reds") %>%
        layout(
          title = "Frequência de Emendas ao Longo do Tempo",
          xaxis = list(title = "Ano"),
          yaxis = list(title = "Lei")
        )
    })

    output$hotspots_table <- DT::renderDataTable({
      req(rv$hotspots)

      rv$hotspots %>%
        select(
          Rank = hotspot_rank,
          Referência = refs,
          `N° Emendas` = amendment_count,
          `Título Original` = doc_title,
          Ano = doc_year,
          Tipo = doc_type,
          Categoria = category,
          Score = hotspot_score
        ) %>%
        datatable(
          options = list(
            pageLength = 25,
            order = list(list(0, 'asc'))
          ),
          rownames = FALSE
        ) %>%
        formatRound('Score', 1)
    })

    # ========================================================================
    # CASCADES TAB
    # ========================================================================

    output$cascade_network <- renderVisNetwork({
      req(rv$cascades)

      if (nrow(rv$cascades) == 0) {
        return(NULL)
      }

      # Build network from top cascades
      top_cascades <- rv$cascades %>% head(5)

      all_nodes <- list()
      all_edges <- list()

      for (i in 1:nrow(top_cascades)) {
        cascade <- top_cascades[i, ]
        chain_ids <- str_split(cascade$chain, " → ")[[1]]

        # Add nodes
        for (j in seq_along(chain_ids)) {
          all_nodes[[length(all_nodes) + 1]] <- data.frame(
            id = chain_ids[j],
            label = chain_ids[j],
            group = paste("Cascade", i),
            level = j
          )
        }

        # Add edges
        if (length(chain_ids) > 1) {
          for (j in 1:(length(chain_ids) - 1)) {
            all_edges[[length(all_edges) + 1]] <- data.frame(
              from = chain_ids[j],
              to = chain_ids[j + 1],
              cascade_id = i
            )
          }
        }
      }

      nodes <- do.call(rbind, all_nodes) %>% distinct()
      edges <- if (length(all_edges) > 0) do.call(rbind, all_edges) else data.frame()

      visNetwork(nodes, edges) %>%
        visHierarchicalLayout(direction = "LR", sortMethod = "directed") %>%
        visOptions(highlightNearest = TRUE) %>%
        visEdges(arrows = "to") %>%
        visInteraction(navigationButtons = TRUE)
    })

    output$cascade_distribution <- renderPlotly({
      req(rv$cascades)

      data <- rv$cascades %>%
        count(chain_length, name = "count")

      plot_ly(data, x = ~chain_length, y = ~count, type = "bar") %>%
        layout(
          title = "Distribuição de Comprimento de Cascatas",
          xaxis = list(title = "Comprimento da Cadeia"),
          yaxis = list(title = "Número de Cascatas")
        )
    })

    output$cascades_table <- DT::renderDataTable({
      req(rv$cascades)

      rv$cascades %>%
        select(
          ID = cascade_id,
          Comprimento = chain_length,
          Cadeia = chain,
          Categoria = category,
          Score = complexity_score
        ) %>%
        datatable(
          options = list(
            pageLength = 20,
            order = list(list(1, 'desc'))
          ),
          rownames = FALSE
        )
    })

    # ========================================================================
    # VELOCITY TAB
    # ========================================================================

    output$velocity_plot <- renderPlotly({
      req(rv$velocity)

      if (input$by_jurisdiction) {
        plot_ly(rv$velocity, x = ~ano, y = ~amendment_count, color = ~nivel,
                type = "scatter", mode = "lines+markers") %>%
          add_lines(y = ~rolling_avg, line = list(dash = "dash"), showlegend = FALSE) %>%
          layout(
            title = "Velocidade de Emendas por Jurisdição",
            xaxis = list(title = "Ano"),
            yaxis = list(title = "Número de Emendas")
          )
      } else {
        plot_ly(rv$velocity, x = ~ano, y = ~amendment_count, type = "scatter",
                mode = "lines+markers", name = "Emendas") %>%
          add_lines(y = ~rolling_avg, line = list(dash = "dash"), name = "Média Móvel") %>%
          layout(
            title = "Velocidade de Emendas ao Longo do Tempo",
            xaxis = list(title = "Ano"),
            yaxis = list(title = "Número de Emendas")
          )
      }
    })

    output$acceleration_plot <- renderPlotly({
      req(rv$velocity)

      plot_ly(rv$velocity, x = ~ano, y = ~acceleration, type = "bar",
              marker = list(
                color = ~acceleration,
                colorscale = list(c(0, "red"), c(0.5, "white"), c(1, "green")),
                cmin = -max(abs(rv$velocity$acceleration), na.rm = TRUE),
                cmax = max(abs(rv$velocity$acceleration), na.rm = TRUE)
              )) %>%
        layout(
          title = "Aceleração (Mudança na Velocidade)",
          xaxis = list(title = "Ano"),
          yaxis = list(title = "Aceleração")
        )
    })

    output$velocity_stats <- renderUI({
      req(rv$velocity)

      data <- rv$velocity

      avg_velocity <- mean(data$velocity, na.rm = TRUE)
      avg_acceleration <- mean(data$acceleration, na.rm = TRUE)
      trend_summary <- table(data$trend)

      tagList(
        p(strong("Velocidade Média:"), sprintf("%.1f emendas/ano", avg_velocity)),
        p(strong("Aceleração Média:"), sprintf("%.2f", avg_acceleration)),
        hr(),
        h5("Tendências:"),
        tags$ul(
          lapply(names(trend_summary), function(trend) {
            tags$li(strong(trend), ": ", trend_summary[trend], " anos")
          })
        )
      )
    })

    output$velocity_table <- DT::renderDataTable({
      req(rv$velocity)

      display_cols <- if (input$by_jurisdiction) {
        c("ano", "nivel", "amendment_count", "rolling_avg", "velocity", "velocity_pct", "trend")
      } else {
        c("ano", "amendment_count", "rolling_avg", "velocity", "velocity_pct", "trend")
      }

      rv$velocity %>%
        select(all_of(display_cols)) %>%
        datatable(
          options = list(
            pageLength = 25,
            order = list(list(0, 'desc'))
          ),
          rownames = FALSE
        ) %>%
        formatRound(c('rolling_avg', 'velocity_pct'), 2)
    })

    # ========================================================================
    # CROSS-JURISDICTION TAB
    # ========================================================================

    output$jurisdiction_sankey <- renderPlotly({
      req(rv$cross_jurisdiction)

      patterns <- rv$cross_jurisdiction$cross_jurisdiction_patterns

      if (nrow(patterns) == 0) {
        return(plotly_empty())
      }

      # Parse flow patterns
      flow_counts <- patterns %>%
        count(flow_type, name = "count") %>%
        separate(flow_type, into = c("source", "target"), sep = " → ", remove = FALSE)

      # Create Sankey
      nodes <- data.frame(
        name = unique(c(flow_counts$source, flow_counts$target))
      )

      links <- flow_counts %>%
        left_join(nodes %>% mutate(source_id = row_number() - 1), by = c("source" = "name")) %>%
        left_join(nodes %>% mutate(target_id = row_number() - 1), by = c("target" = "name"))

      plot_ly(
        type = "sankey",
        node = list(
          label = nodes$name,
          pad = 15,
          thickness = 20
        ),
        link = list(
          source = links$source_id,
          target = links$target_id,
          value = links$count
        )
      ) %>%
        layout(title = "Fluxos de Emendas Entre Jurisdições")
    })

    output$diffusion_speed <- renderPlotly({
      req(rv$cross_jurisdiction)

      patterns <- rv$cross_jurisdiction$cross_jurisdiction_patterns %>%
        filter(diffusion_speed > 0)

      if (nrow(patterns) == 0) {
        return(plotly_empty())
      }

      plot_ly(patterns, x = ~diffusion_speed, type = "histogram", nbinsx = 20) %>%
        layout(
          title = "Velocidade de Difusão Entre Jurisdições",
          xaxis = list(title = "Velocidade (emendas/ano)"),
          yaxis = list(title = "Frequência")
        )
    })

    output$jurisdiction_flow_chart <- renderPlotly({
      req(rv$cross_jurisdiction)

      flows <- rv$cross_jurisdiction$flows_by_level

      if (nrow(flows) == 0) {
        return(plotly_empty())
      }

      plot_ly(flows, x = ~ano, y = ~amendment_count, color = ~nivel,
              type = "scatter", mode = "lines+markers") %>%
        layout(
          title = "Emendas ao Longo do Tempo por Nível",
          xaxis = list(title = "Ano"),
          yaxis = list(title = "Número de Emendas")
        )
    })

    output$cross_jurisdiction_table <- DT::renderDataTable({
      req(rv$cross_jurisdiction)

      rv$cross_jurisdiction$cross_jurisdiction_patterns %>%
        select(
          `Tipo de Fluxo` = flow_type,
          `Jurisdições` = jurisdictions,
          Anos = years,
          Contagem = count,
          `Período (anos)` = span_years,
          `Velocidade de Difusão` = diffusion_speed
        ) %>%
        datatable(
          options = list(
            pageLength = 20,
            order = list(list(3, 'desc'))
          ),
          rownames = FALSE
        ) %>%
        formatRound('Velocidade de Difusão', 2)
    })

    # ========================================================================
    # STATISTICS TAB
    # ========================================================================

    output$stat_total_docs <- renderValueBox({
      count <- if (!is.null(rv$amendments)) nrow(rv$amendments) else 0

      valueBox(
        value = format(count, big.mark = ","),
        subtitle = "Documentos Analisados",
        icon = icon("file-alt"),
        color = "aqua"
      )
    })

    output$stat_amendment_rate <- renderValueBox({
      rate <- if (!is.null(rv$amendments) && nrow(rv$amendments) > 0) {
        years <- diff(range(rv$amendments$ano, na.rm = TRUE))
        if (years > 0) {
          nrow(rv$amendments) / years
        } else {
          0
        }
      } else {
        0
      }

      valueBox(
        value = sprintf("%.1f", rate),
        subtitle = "Taxa de Emenda (por ano)",
        icon = icon("percentage"),
        color = "green"
      )
    })

    output$stat_avg_velocity <- renderValueBox({
      avg <- if (!is.null(rv$velocity) && nrow(rv$velocity) > 0) {
        mean(rv$velocity$velocity, na.rm = TRUE)
      } else {
        0
      }

      valueBox(
        value = sprintf("%.1f", avg),
        subtitle = "Velocidade Média",
        icon = icon("tachometer-alt"),
        color = "yellow"
      )
    })

    output$stat_complexity <- renderValueBox({
      complexity <- if (!is.null(rv$cascades) && nrow(rv$cascades) > 0) {
        mean(rv$cascades$complexity_score, na.rm = TRUE)
      } else {
        0
      }

      valueBox(
        value = sprintf("%.0f", complexity),
        subtitle = "Score de Complexidade",
        icon = icon("project-diagram"),
        color = "purple"
      )
    })

    output$historical_trend <- renderPlotly({
      req(rv$amendments)

      yearly <- rv$amendments %>%
        count(ano, name = "count")

      plot_ly(yearly, x = ~ano, y = ~count, type = "scatter", mode = "lines+markers") %>%
        layout(
          title = "Tendência Histórica",
          xaxis = list(title = "Ano"),
          yaxis = list(title = "Número de Emendas")
        )
    })

    output$type_distribution <- renderPlotly({
      req(rv$amendments)

      by_type <- rv$amendments %>%
        count(amendment_type, name = "count")

      plot_ly(by_type, labels = ~amendment_type, values = ~count, type = "pie") %>%
        layout(title = "Distribuição por Tipo de Emenda")
    })

    output$jurisdiction_distribution <- renderPlotly({
      req(rv$amendments)

      if (!"nivel" %in% names(rv$amendments)) {
        return(plotly_empty())
      }

      by_juris <- rv$amendments %>%
        count(nivel, name = "count")

      plot_ly(by_juris, x = ~nivel, y = ~count, type = "bar") %>%
        layout(
          title = "Distribuição por Jurisdição",
          xaxis = list(title = "Nível"),
          yaxis = list(title = "Número de Emendas")
        )
    })

    output$seasonality_plot <- renderPlotly({
      req(rv$amendments)

      # Check for data column (actual name) or data_publicacao (alias)
      date_col <- if ("data" %in% names(rv$amendments)) "data" else if ("data_publicacao" %in% names(rv$amendments)) "data_publicacao" else NULL
      if (is.null(date_col)) {
        return(plotly_empty())
      }

      monthly <- rv$amendments %>%
        filter(!is.na(.data[[date_col]])) %>%
        mutate(month = tryCatch(month(as.Date(.data[[date_col]])), error = function(e) NA)) %>%
        filter(!is.na(month)) %>%
        count(month, name = "count")

      month_names <- c("Jan", "Fev", "Mar", "Abr", "Mai", "Jun",
                      "Jul", "Ago", "Set", "Out", "Nov", "Dez")

      monthly <- monthly %>%
        mutate(month_name = month_names[month])

      plot_ly(monthly, x = ~month_name, y = ~count, type = "bar") %>%
        layout(
          title = "Sazonalidade (Mês de Publicação)",
          xaxis = list(title = "Mês"),
          yaxis = list(title = "Número de Emendas")
        )
    })

    # ========================================================================
    # EXPORT FUNCTIONALITY
    # ========================================================================

    output$download_results <- downloadHandler(
      filename = function() {
        paste0("amendment_analysis_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".csv")
      },
      content = function(file) {
        data <- switch(
          input$analysis_mode,
          "overview" = rv$amendments,
          "timeline" = if (!is.null(rv$timeline_data)) rv$timeline_data$timeline else NULL,
          "hotspots" = rv$hotspots,
          "cascades" = rv$cascades,
          "velocity" = rv$velocity,
          "cross_jurisdiction" = if (!is.null(rv$cross_jurisdiction)) {
            rv$cross_jurisdiction$cross_jurisdiction_patterns
          } else NULL,
          rv$amendments
        )

        if (!is.null(data)) {
          write.csv(data, file, row.names = FALSE, fileEncoding = "UTF-8")
        }
      }
    )

  })
}

cat("✅ Amendment Analysis Server Module loaded successfully\n")
