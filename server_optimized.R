# ==============================================================================
# MONITOR LEGISLATIVO V4 - OPTIMIZED SERVER
# ==============================================================================
# Key patterns demonstrated:
# 1. eventReactive for explicit user actions (no auto-firing)
# 2. bindCache for expensive renders
# 3. req() to halt early when data not ready
# 4. leafletProxy for incremental map updates
# 5. promises::future_promise for async heavy work
# ==============================================================================

server <- function(input, output, session) {
  cat("[SERVER] Session started:", as.character(Sys.time()), "\n")

  # Health check endpoint for Railway
  session$registerDataObj("health", list(status = "OK"), function(data, req) {
    list(status = 200L, headers = list("Content-Type" = "text/plain"), body = "OK")
  })

  # REACTIVE DATA SOURCES
  # =====================

  # 1. Dashboard metrics (reactive value that refreshes on timer)
  # --------------------------------------------------------------
  dashboard_metrics <- reactive({
    # Auto-refresh every 5 minutes
    invalidateLater(300000, session)

    tryCatch({
      get_dashboard_metrics()  # Uses cached version from global.R
    }, error = function(e) {
      list(
        total_documents = 0,
        states_with_docs = 0,
        municipalities_with_docs = 0,
        last_updated = Sys.time()
      )
    })
  })

  # 2. Search results - ONLY fire on explicit button click
  # -------------------------------------------------------
  search_results <- eventReactive(input$search_btn, {
    # Validate inputs first
    req(input$search_text)

    search_term <- input$search_text
    if (nchar(search_term) < 3) {
      showNotification("Digite pelo menos 3 caracteres", type = "warning")
      return(data.frame())
    }

    # Show loading indicator
    showNotification("Buscando documentos...", id = "search_loading", duration = NULL)

    # Perform search
    results <- tryCatch({
      filters <- list(search = search_term)
      if (!is.null(input$filter_state) && input$filter_state != "all") {
        filters$state <- input$filter_state
      }
      get_documents(filters = filters, limit = 500)
    }, error = function(e) {
      cat("❌ Search error:", conditionMessage(e), "\n")
      data.frame()
    })

    # Remove loading indicator
    removeNotification("search_loading")

    results
  }, ignoreNULL = FALSE, ignoreInit = TRUE)

  # EXECUTIVE DASHBOARD OUTPUTS
  # ============================

  # Value boxes - use renderUI instead of renderValueBox for safety
  output$total_docs_box <- renderUI({
    metrics <- dashboard_metrics()
    safe_valueBox(
      value = format(metrics$total_documents, big.mark = "."),
      subtitle = "Documentos Legislativos",
      icon = icon("file-text"),
      color = "blue"
    )
  })

  output$states_box <- renderUI({
    metrics <- dashboard_metrics()
    safe_valueBox(
      value = sprintf("%d/27", metrics$states_with_docs),
      subtitle = "Estados Cobertos",
      icon = icon("map"),
      color = "green"
    )
  })

  output$municipalities_box <- renderUI({
    metrics <- dashboard_metrics()
    safe_valueBox(
      value = format(metrics$municipalities_with_docs, big.mark = "."),
      subtitle = "Municípios",
      icon = icon("city"),
      color = "yellow"
    )
  })

  # STATE CHART - with bindCache for performance
  # ---------------------------------------------
  output$state_chart <- renderPlotly({
    # CRITICAL: Halt if data not ready
    data <- prepare_state_chart_data()
    req(nrow(data) > 0)

    # Build plot
    tryCatch({
      plot_ly(
        data = data,
        x = ~count,
        y = ~reorder(state, count),
        type = "bar",
        orientation = "h",
        marker = list(color = "#3498db")
      ) %>%
        layout(
          title = "Documentos por Estado",
          xaxis = list(title = "Quantidade"),
          yaxis = list(title = ""),
          margin = list(l = 100)
        )
    }, error = function(e) {
      cat("❌ Chart error:", conditionMessage(e), "\n")
      plotly_empty() %>% layout(title = "Erro ao carregar gráfico")
    })
  }) %>%
    bindCache("state_chart_v1")  # Cache the rendered plot

  # CATEGORY CHART - with bindCache
  # --------------------------------
  output$category_chart <- renderPlotly({
    data <- prepare_category_chart_data()
    req(nrow(data) > 0)

    tryCatch({
      plot_ly(
        data = data,
        x = ~count,
        y = ~reorder(category, count),
        type = "bar",
        orientation = "h",
        marker = list(color = "#e74c3c")
      ) %>%
        layout(
          title = "Documentos por Categoria",
          xaxis = list(title = "Quantidade"),
          yaxis = list(title = ""),
          margin = list(l = 150)
        )
    }, error = function(e) {
      cat("❌ Chart error:", conditionMessage(e), "\n")
      plotly_empty() %>% layout(title = "Erro ao carregar gráfico")
    })
  }) %>%
    bindCache("category_chart_v1")

  # SEARCH RESULTS TABLE
  # ====================
  output$search_results_table <- renderDT({
    # Halt if no results yet
    req(input$search_btn > 0)
    results <- search_results()
    req(nrow(results) > 0)

    # Prepare display
    display_data <- results %>%
      select(titulo, categoria, estado, data_publicacao) %>%
      mutate(
        titulo = substr(titulo, 1, 100),
        data_publicacao = as.character(data_publicacao)
      )

    datatable(
      display_data,
      options = list(
        pageLength = 25,
        scrollX = TRUE,
        language = list(url = "//cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json")
      ),
      colnames = c("Título", "Categoria", "Estado", "Data"),
      rownames = FALSE
    )
  })

  # GEOGRAPHIC MAP (BRAZIL)
  # ========================

  # Base map - render once at startup
  output$brazil_map <- renderLeaflet({
    req(LEAFLET_AVAILABLE)

    leaflet() %>%
      addTiles(urlTemplate = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png") %>%
      setView(lng = -47.8828, lat = -15.7942, zoom = 4) %>%
      addControl(
        "<div style='background: white; padding: 10px;'><strong>Monitor Legislativo v4</strong></div>",
        position = "topright"
      )
  })

  # Update map with state choropleth - ONLY when button clicked
  observeEvent(input$load_map_btn, {
    req(LEAFLET_AVAILABLE, !is.null(brazil_states_sf))

    # Fetch document counts by state (uses cached function)
    state_data <- prepare_state_chart_data()
    req(nrow(state_data) > 0)

    # Join with geometry
    states_with_data <- brazil_states_sf %>%
      left_join(state_data, by = c("abbrev_state" = "state"))

    # Create color palette
    pal <- colorNumeric(
      palette = "YlOrRd",
      domain = states_with_data$count,
      na.color = "#cccccc"
    )

    # Use leafletProxy to update existing map (faster than full re-render)
    leafletProxy("brazil_map") %>%
      clearShapes() %>%
      addPolygons(
        data = states_with_data,
        fillColor = ~pal(count),
        fillOpacity = 0.7,
        color = "white",
        weight = 1,
        label = ~sprintf("%s: %d documentos", name_state, count %||% 0),
        highlightOptions = highlightOptions(
          weight = 3,
          color = "#666",
          fillOpacity = 0.9,
          bringToFront = TRUE
        )
      ) %>%
      addLegend(
        pal = pal,
        values = states_with_data$count,
        title = "Documentos",
        position = "bottomright"
      )
  })

  # ASYNC HEAVY COMPUTATION EXAMPLE
  # ================================
  # Use promises for expensive operations that would block the UI

  output$heavy_analysis <- renderText({
    req(input$run_analysis_btn > 0)

    # Show loading state immediately
    "Processando análise complexa..."
  })

  # Actual heavy work runs in background
  analysis_result <- eventReactive(input$run_analysis_btn, {
    promises::future_promise({
      # This runs in a separate R process (doesn't block UI)
      Sys.sleep(5)  # Simulate heavy computation
      "Análise concluída: 42 padrões identificados"
    })
  })

  # Update output when promise resolves
  observe({
    req(input$run_analysis_btn > 0)
    analysis_result() %...>% {
      output$heavy_analysis <- renderText(.)
    }
  })

  # SESSION CLEANUP
  # ===============
  session$onSessionEnded(function() {
    cat("[SERVER] Session ended:", as.character(Sys.time()), "\n")
  })

  cat("[SERVER] Server logic initialized\n")
}
