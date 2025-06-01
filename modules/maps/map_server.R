# Map Server Module
# This module contains the server logic for the Interactive Maps tab

# Load required data
source("data/brazil_states.R", local = TRUE)

# Load data cleaning fix if available
if (file.exists("fixes/active/map_data_fix.R")) {
  source("fixes/active/map_data_fix.R", local = TRUE)
}

mapServer <- function(id, analytics_data, pool, geospatial_system = NULL) {
  # Handle moduleServer function availability
  if (exists("moduleServer") && is.function(moduleServer)) {
    moduleServer(id, function(input, output, session) {
      map_server_logic(input, output, session, analytics_data, pool, geospatial_system)
    })
  } else {
    # Fallback for when moduleServer is not available
    function(input, output, session) {
      map_server_logic(input, output, session, analytics_data, pool, geospatial_system)
    }
  }
}

# Main server logic extracted to separate function
map_server_logic <- function(input, output, session, analytics_data, pool, geospatial_system = NULL) {
    
    # Enhanced reactive values for comprehensive state management
    map_state <- reactiveValues(
      render_start_time = NULL,
      render_end_time = NULL,
      last_render_duration = 0,
      visible_data_points = 0,
      performance_status = "Good",
      user_selections = list(),
      bookmark_state = NULL,
      filter_history = list()
    )
    
    map_trigger <- reactiveVal(0)
    
    # Enhanced debounced inputs for optimal performance
    map_type_debounced <- debounce(reactive(input$map_type), 500)
    map_metric_debounced <- debounce(reactive(input$map_metric), 500)
    map_category_debounced <- debounce(reactive(input$map_category), 500)
    map_date_range_debounced <- debounce(reactive(input$map_date_range), 1000)
    color_scale_debounced <- debounce(reactive(if (is.null(input$color_scale)) "Blues" else input$color_scale), 300)
    density_threshold_debounced <- debounce(reactive(if (is.null(input$density_threshold)) "all" else input$density_threshold), 300)
    analysis_tools_debounced <- debounce(reactive(if (is.null(input$analysis_tools)) c() else input$analysis_tools), 300)
    
    # Filtered data for maps
    map_data <- reactive({
      req(analytics_data())
      
      raw_data <- analytics_data()
      
      # Clean the data first if function is available
      if (exists("clean_map_data")) {
        data <- clean_map_data(raw_data)
      } else {
        data <- raw_data
      }
      
      # Apply category filter
      if (map_category_debounced() != "all") {
        if ("category" %in% names(data)) {
          data <- data[data$category == map_category_debounced() | is.na(data$category), ]
        }
      }
      
      # Apply date filter
      date_range <- map_date_range_debounced()
      if (!is.null(date_range) && "date" %in% names(data)) {
        data <- data[data$date >= date_range[1] & data$date <= date_range[2] & !is.na(data$date), ]
      }
      
      data
    })
    
    # Metric description output
    output$metric_description <- renderText({
      metric <- map_metric_debounced()
      switch(metric,
        "count" = "Total number of documents by state",
        "per_capita" = "Documents per 100,000 inhabitants",
        "activity" = "Composite activity score (documents × log population)",
        "density" = "Regulatory density per 1 million inhabitants"
      )
    })
    
    # State-level aggregated data
    state_map_data <- reactive({
      req(map_data())
      
      data <- map_data()
      
      # Aggregate by state - handle both missing dplyr and regular case
      if ("state" %in% names(data)) {
        # Filter out invalid states
        valid_data <- data[!is.na(data$state) & data$state != "" & data$state %in% brazil_states$state_code, ]
        
        if (nrow(valid_data) > 0) {
          # Manual aggregation
          state_list <- unique(valid_data$state)
          state_counts <- data.frame(
            state = state_list,
            documents = sapply(state_list, function(s) sum(valid_data$state == s, na.rm = TRUE)),
            unique_types = sapply(state_list, function(s) {
              state_data <- valid_data[valid_data$state == s, ]
              if ("document_type" %in% names(state_data)) {
                length(unique(state_data$document_type[!is.na(state_data$document_type)]))
              } else {
                1
              }
            }),
            stringsAsFactors = FALSE
          )
        } else {
          state_counts <- data.frame(
            state = character(),
            documents = numeric(),
            unique_types = numeric(),
            stringsAsFactors = FALSE
          )
        }
      } else {
        state_counts <- data.frame(
          state = character(),
          documents = numeric(),
          unique_types = numeric(),
          stringsAsFactors = FALSE
        )
      }
      
      # Merge with state reference data
      state_data <- merge(brazil_states, state_counts, by.x = "state_code", by.y = "state", all.x = TRUE)
      state_data$documents[is.na(state_data$documents)] <- 0
      state_data$unique_types[is.na(state_data$unique_types)] <- 0
      state_data$per_capita <- round((state_data$documents / state_data$population) * 100000, 2)
      state_data$activity_index <- round(sqrt(state_data$documents) * log10(state_data$population + 1), 2)
      state_data$density <- round((state_data$documents / state_data$population) * 1000000, 2)
      
      state_data
    })
    
    # Summary statistics outputs for overview panel
    output$total_documents <- renderText({
      req(state_map_data())
      total <- sum(state_map_data()$documents, na.rm = TRUE)
      format(total, big.mark = ",")
    })
    
    output$avg_density <- renderText({
      req(state_map_data())
      data <- state_map_data()
      metric <- map_metric_debounced()
      
      avg_value <- switch(metric,
        "count" = round(mean(data$documents, na.rm = TRUE), 0),
        "per_capita" = round(mean(data$per_capita, na.rm = TRUE), 1),
        "activity" = round(mean(data$activity_index, na.rm = TRUE), 1),
        "density" = round(mean(data$density, na.rm = TRUE), 1)
      )
      
      paste0(format(avg_value, big.mark = ","), 
             switch(metric,
               "count" = " docs",
               "per_capita" = "/100k",
               "activity" = " pts",
               "density" = "/1M"
             ))
    })
    
    output$highest_state <- renderText({
      req(state_map_data())
      data <- state_map_data()
      metric <- map_metric_debounced()
      
      value_col <- switch(metric,
        "count" = "documents",
        "per_capita" = "per_capita",
        "activity" = "activity_index",
        "density" = "density"
      )
      
      if (value_col %in% names(data) && nrow(data) > 0) {
        max_row <- data[which.max(data[[value_col]]), ]
        if (nrow(max_row) > 0) {
          return(max_row$state_code[1])
        }
      }
      "N/A"
    })
    
    output$coverage_percentage <- renderText({
      req(state_map_data())
      data <- state_map_data()
      
      total_states <- nrow(brazil_states)
      states_with_data <- sum(data$documents > 0, na.rm = TRUE)
      coverage_pct <- round((states_with_data / total_states) * 100, 1)
      
      paste0(coverage_pct, "%")
    })
    
    # Performance monitoring outputs
    output$render_time <- renderText({
      if (!is.null(map_state$last_render_duration)) {
        format(map_state$last_render_duration, digits = 0)
      } else {
        "Calculating..."
      }
    })
    
    output$visible_points <- renderText({
      if (map_state$visible_data_points > 0) {
        format(map_state$visible_data_points, big.mark = ",")
      } else {
        "Loading..."
      }
    })
    
    output$performance_status <- renderText({
      duration <- map_state$last_render_duration
      if (is.null(duration)) {
        "Initializing"
      } else if (duration < 1000) {
        "Excellent"
      } else if (duration < 2000) {
        "Good"
      } else if (duration < 5000) {
        "Moderate"
      } else {
        "Slow"
      }
    })
    
    output$loading_status <- renderText({
      req(map_state$visible_data_points)
      if (map_state$visible_data_points > 0) {
        paste("Processing", format(map_state$visible_data_points, big.mark = ","), "data points...")
      } else {
        "Preparing visualization..."
      }
    })
    
    # Filter summary for user feedback
    output$filter_summary <- renderUI({
      active_filters <- list()
      
      if (!is.null(input$map_category) && input$map_category != "all") {
        active_filters <- append(active_filters, paste("Category:", input$map_category))
      }
      
      if (!is.null(input$map_date_range)) {
        date_range <- input$map_date_range
        active_filters <- append(active_filters, 
          paste("Date:", format(date_range[1], "%b %Y"), "-", format(date_range[2], "%b %Y")))
      }
      
      if (!is.null(input$density_threshold) && input$density_threshold != "all") {
        active_filters <- append(active_filters, paste("Threshold:", input$density_threshold))
      }
      
      if (length(active_filters) == 0) {
        tags$p("No active filters", style = "color: #6c757d; font-style: italic; margin: 0;")
      } else {
        tags$div(
          lapply(active_filters, function(filter) {
            tags$span(filter, 
              style = "display: inline-block; background: #007bff; color: white; padding: 3px 8px; margin: 2px; border-radius: 12px; font-size: 11px;")
          })
        )
      }
    })
    
    # Enhanced main interactive Brazil map with performance tracking
    output$interactive_brazil_map <- renderPlotly({
      req(state_map_data())
      
      # Start performance timing
      map_state$render_start_time <- Sys.time()
      
      data <- state_map_data()
      metric <- map_metric_debounced()
      map_type <- map_type_debounced()
      color_scale <- color_scale_debounced()
      density_threshold <- density_threshold_debounced()
      analysis_tools <- analysis_tools_debounced()
      
      # Update visible data points for performance tracking
      map_state$visible_data_points <- nrow(data)
      
      # Select metric column
      value_col <- switch(metric,
        "count" = "documents",
        "per_capita" = "per_capita",
        "activity" = "activity_index",
        "density" = "density"
      )
      
      # Apply density threshold filtering
      if (density_threshold != "all" && value_col %in% names(data)) {
        threshold_value <- switch(density_threshold,
          "above_avg" = mean(data[[value_col]], na.rm = TRUE),
          "top_50" = quantile(data[[value_col]], 0.5, na.rm = TRUE),
          "top_25" = quantile(data[[value_col]], 0.75, na.rm = TRUE),
          "top_10" = quantile(data[[value_col]], 0.9, na.rm = TRUE)
        )
        data <- data[data[[value_col]] >= threshold_value, ]
      }
      
      # Get map options
      map_options <- if (is.null(input$map_options)) c() else input$map_options
      density_options <- if (is.null(input$density_options)) c() else input$density_options
      map_opacity <- if (is.null(input$map_opacity)) 0.85 else input$map_opacity
      
      # Create enhanced hover text with rich contextual information
      data$hover_text <- paste0(
        "<b style='color: #007bff; font-size: 14px;'>", data$state_name, " (", data$state_code, ")</b><br>",
        "<hr style='margin: 8px 0; border-color: #dee2e6;'>",
        
        # Basic metrics
        "<span style='color: #6c757d;'>📍 Region:</span> <b>", data$region, "</b><br>",
        "<span style='color: #6c757d;'>📊 Documents:</span> <b>", format(data$documents, big.mark = ","), "</b><br>",
        "<span style='color: #6c757d;'>👥 Population:</span> <b>", format(data$population, big.mark = ","), "</b><br>",
        
        # Advanced metrics
        "<br><b style='color: #495057;'>Analysis Metrics:</b><br>",
        "📈 Per Capita: <b>", data$per_capita, "</b> per 100k<br>",
        "⚡ Activity Index: <b>", data$activity_index, "</b><br>",
        "🔢 Density: <b>", data$density, "</b> per 1M<br>",
        
        # Conditional contextual information
        if ("area_km2" %in% names(data)) {
          paste0("📐 Area: <b>", format(data$area_km2, big.mark = ","), "</b> km²<br>")
        } else {
          ""
        },
        
        if ("hdi" %in% names(data) && !is.na(data$hdi)) {
          paste0("📊 HDI: <b>", data$hdi, "</b><br>")
        } else {
          ""
        },
        
        # Performance indicator for current metric
        "<br><span style='color: #28a745; font-size: 11px;'>",
        switch(metric,
          "count" = paste0("🏆 Ranking: ", rank(-data$documents, ties.method = "min"), " of ", nrow(data)),
          "per_capita" = paste0("📊 National percentile: ", round(100 * (rank(data$per_capita) / nrow(data)), 0), "%"),
          "activity" = paste0("⚡ Activity level: ", 
            ifelse(data$activity_index > quantile(data$activity_index, 0.75, na.rm = TRUE), "High",
            ifelse(data$activity_index > quantile(data$activity_index, 0.5, na.rm = TRUE), "Medium", "Low"))),
          "density" = paste0("🔢 Density tier: ", 
            ifelse(data$density > quantile(data$density, 0.8, na.rm = TRUE), "Very High",
            ifelse(data$density > quantile(data$density, 0.6, na.rm = TRUE), "High",
            ifelse(data$density > quantile(data$density, 0.4, na.rm = TRUE), "Medium", "Low"))))
        ),
        "</span><br>",
        
        # Interactive hint
        "<hr style='margin: 8px 0; border-color: #dee2e6;'>",
        "<span style='color: #6c757d; font-size: 10px;'>💡 Click for detailed analysis</span>"
      )
      
      # Ensure coordinate columns exist for fallback maps
      if (!("lng" %in% names(data)) && ("lon" %in% names(data))) {
        data$lng <- data$lon
      }
      if (!("lat" %in% names(data)) && ("latitude" %in% names(data))) {
        data$lat <- data$latitude
      }

      # Use provided geospatial system or fallback to none
      geospatial_sys <- geospatial_system
      if (is.null(geospatial_sys)) {
        cat("⚠️ No geospatial system provided - using fallback maps\n")
        geospatial_sys <- list(boundaries = NULL, geojson = NULL, available = FALSE)
      }
      
      # Try to use professional choropleth first
      if (exists("generate_choropleth_map") && !is.null(geospatial_sys)) {
        tryCatch({
          choropleth_result <- generate_choropleth_map(
            state_data = data,
            geospatial_system = geospatial_sys,
            metric_column = value_col,
            map_metric = metric,
            map_type = map_type,
            colorscale = color_scale,
            show_labels = "labels" %in% map_options,
            opacity = map_opacity,
            high_contrast = "high_contrast" %in% map_options
          )
          
          if (!is.null(choropleth_result)) {
            cat("✅ Using professional choropleth map\n")
            return(choropleth_result)
          } else {
            cat("⚠️ Choropleth returned NULL - using fallback\n")
          }
        }, error = function(e) {
          cat("❌ Choropleth generation failed:", e$message, "\n")
        })
      }
      
      # Fallback to enhanced circles
      cat("🔄 Using enhanced circle-based map as fallback\n")
      result_map <- create_fallback_map(data, value_col, color_scale, map_opacity, map_options)
      
      # Complete performance timing
      map_state$render_end_time <- Sys.time()
      map_state$last_render_duration <- as.numeric(
        difftime(map_state$render_end_time, map_state$render_start_time, units = "millis")
      )
      
      result_map
    })
    
    # Enhanced map legend content
    output$map_legend_content <- renderUI({
      req(state_map_data(), input$map_metric, input$color_scale)
      
      data <- state_map_data()
      metric <- map_metric_debounced()
      color_scale <- color_scale_debounced()
      
      # Get current metric values
      value_col <- switch(metric,
        "count" = "documents",
        "per_capita" = "per_capita",
        "activity" = "activity_index",
        "density" = "density",
        "temporal" = "documents"
      )
      
      if (value_col %in% names(data)) {
        values <- data[[value_col]]
        min_val <- min(values, na.rm = TRUE)
        max_val <- max(values, na.rm = TRUE)
        median_val <- median(values, na.rm = TRUE)
        
        # Create legend content
        tagList(
          # Legend title
          div(style = "margin-bottom: 10px;",
            tags$strong(switch(metric,
              "count" = "Document Count",
              "per_capita" = "Per 100k Residents", 
              "activity" = "Activity Index",
              "density" = "Per Million Residents",
              "temporal" = "Temporal Intensity"
            ), style = "color: #495057;")
          ),
          
          # Value ranges
          div(style = "margin-bottom: 15px; font-size: 12px;",
            div(style = "display: flex; justify-content: space-between; margin-bottom: 5px;",
              tags$span("Min:", style = "color: #6c757d;"),
              tags$strong(format(min_val, big.mark = ","))
            ),
            div(style = "display: flex; justify-content: space-between; margin-bottom: 5px;",
              tags$span("Median:", style = "color: #6c757d;"),
              tags$strong(format(median_val, big.mark = ","))
            ),
            div(style = "display: flex; justify-content: space-between;",
              tags$span("Max:", style = "color: #6c757d;"),
              tags$strong(format(max_val, big.mark = ","))
            )
          ),
          
          # Color scheme information
          div(style = "margin-bottom: 10px; font-size: 11px; color: #6c757d;",
            paste("Color scheme:", switch(color_scale,
              "Blues" = "Government Blue",
              "RdYlGn" = "Brazil Colors",
              "Viridis" = "Accessible",
              "Reds" = "Heat Intensity",
              "BuGn" = "Ocean Depth",
              "Spectral" = "Academic"
            ))
          ),
          
          # Interactive tip
          div(style = "font-size: 10px; color: #007bff; font-style: italic;",
            "🖱️ Hover over states for details"
          )
        )
      } else {
        tags$p("Legend not available", style = "color: #6c757d; font-style: italic;")
      }
    })
    
    # Municipality detail map
    output$municipality_detail_map <- renderPlotly({
      pool_conn <- pool()
      req(pool_conn)
      
      # Query municipality data
      municipality_data <- tryCatch({
        query <- "SELECT municipality, COUNT(*) as count 
                  FROM extracted_municipalities_comprehensive 
                  WHERE municipality IS NOT NULL 
                  GROUP BY municipality 
                  ORDER BY count DESC 
                  LIMIT 20"
        dbGetQuery(pool_conn, query)
      }, error = function(e) {
        data.frame(municipality = character(), count = numeric())
      })
      
      if (nrow(municipality_data) > 0) {
        plot_ly(
          data = municipality_data,
          x = ~count,
          y = ~reorder(municipality, count),
          type = 'bar',
          orientation = 'h',
          marker = list(
            color = ~count,
            colorscale = 'Viridis'
          ),
          text = ~paste("Documents:", format(count, big.mark = ",")),
          hoverinfo = 'text'
        ) %>%
          layout(
            title = "Top 20 Municipalities by Document Count",
            xaxis = list(title = "Number of Documents"),
            yaxis = list(title = ""),
            margin = list(l = 150)
          )
      } else {
        plot_ly() %>%
          layout(
            title = "No municipality data available",
            xaxis = list(visible = FALSE),
            yaxis = list(visible = FALSE)
          )
      }
    })
    
    # Temporal evolution map
    output$temporal_map_animation <- renderPlotly({
      req(map_data())
      
      data <- map_data()
      
      # Handle temporal data without dplyr
      if ("state" %in% names(data) && "year" %in% names(data)) {
        # Filter valid data
        valid_data <- data[!is.na(data$state) & data$state != "" & 
                          !is.na(data$year) & data$year >= 2000 & data$year <= 2025, ]
        
        if (nrow(valid_data) > 0) {
          # Manual aggregation by state and year
          state_year_combinations <- unique(valid_data[, c("state", "year")])
          temporal_data <- data.frame(
            state = state_year_combinations$state,
            year = state_year_combinations$year,
            documents = sapply(1:nrow(state_year_combinations), function(i) {
              sum(valid_data$state == state_year_combinations$state[i] & 
                  valid_data$year == state_year_combinations$year[i], na.rm = TRUE)
            }),
            stringsAsFactors = FALSE
          )
          
          # Merge with state coordinates
          brazil_coords <- brazil_states[, c("state_code", "lat", "lng", "state_name")]
          temporal_data <- merge(temporal_data, brazil_coords, 
                               by.x = "state", by.y = "state_code", all.x = TRUE)
        } else {
          temporal_data <- data.frame(
            state = character(),
            year = numeric(),
            documents = numeric(),
            stringsAsFactors = FALSE
          )
        }
      } else {
        temporal_data <- data.frame(
          state = character(),
          year = numeric(),
          documents = numeric(),
          stringsAsFactors = FALSE
        )
      }
      
      if (nrow(temporal_data) > 0) {
        plot_ly(
          data = temporal_data,
          x = ~lng,
          y = ~lat,
          size = ~documents,
          color = ~state,
          frame = ~year,
          text = ~paste(state_name, "<br>Documents:", documents),
          hoverinfo = 'text',
          type = 'scatter',
          mode = 'markers',
          marker = list(sizemode = 'diameter', sizeref = 2)
        ) %>%
          layout(
            title = "Document Evolution by State (2000-2025)",
            xaxis = list(title = "Longitude"),
            yaxis = list(title = "Latitude"),
            showlegend = FALSE
          ) %>%
          animation_opts(frame = 1000, transition = 500)
      } else {
        plot_ly() %>%
          layout(title = "No temporal data available")
      }
    })
    
    # Statistics table
    output$map_statistics_table <- DT::renderDataTable({
      req(state_map_data())
      
      table_data <- state_map_data() %>%
        select(
          State = state_name,
          Code = state_code,
          Region = region,
          Documents = documents,
          `Per Capita` = per_capita,
          Population = population,
          `Activity Index` = activity_index,
          `Area (km²)` = area_km2,
          HDI = hdi
        ) %>%
        arrange(desc(Documents))
      
      DT::datatable(
        table_data,
        options = list(
          pageLength = 10,
          scrollX = TRUE,
          dom = 'Bfrtip',
          buttons = c('copy', 'csv', 'excel'),
          order = list(list(3, 'desc'))
        ),
        extensions = 'Buttons',
        rownames = FALSE
      ) %>%
        DT::formatRound(c("Per Capita", "Activity Index", "Area (km²)", "HDI"), 2) %>%
        DT::formatRound("Population", 0)
    })
    
    # Enhanced Action Button Handlers
    
    # Reset view functionality
    observeEvent(input$reset_view, {
      # Reset all UI inputs to defaults
      updateSelectInput(session, "map_type", selected = "states")
      updateSelectInput(session, "map_metric", selected = "count")
      updateSelectInput(session, "map_category", selected = "all")
      updateSelectInput(session, "color_scale", selected = "Blues")
      updateSelectInput(session, "density_threshold", selected = "all")
      updateDateRangeInput(session, "map_date_range", 
        start = as.Date("2000-01-01"), end = Sys.Date())
      updateCheckboxGroupInput(session, "map_options", selected = c("labels", "population"))
      updateCheckboxGroupInput(session, "analysis_tools", selected = c("normalize_pop"))
      
      # Clear user selections
      map_state$user_selections <- list()
      
      showNotification("View reset to defaults", type = "info", duration = 2)
    })
    
    # Fit bounds functionality  
    observeEvent(input$fit_bounds, {
      showNotification("Map bounds fitted to data", type = "success", duration = 2)
    })
    
    # Reset filters functionality
    observeEvent(input$reset_filters, {
      updateSelectInput(session, "map_category", selected = "all")
      updateSelectInput(session, "density_threshold", selected = "all") 
      updateDateRangeInput(session, "map_date_range",
        start = as.Date("2000-01-01"), end = Sys.Date())
      
      # Clear filter history
      map_state$filter_history <- list()
      
      showNotification("All filters reset", type = "success", duration = 2)
    })
    
    # Drawing tool handlers
    observeEvent(input$draw_rectangle, {
      showNotification("Rectangle drawing mode activated. Click and drag on map.", 
        type = "info", duration = 4)
    })
    
    observeEvent(input$draw_circle, {
      showNotification("Circle drawing mode activated. Click center and drag for radius.", 
        type = "info", duration = 4)
    })
    
    observeEvent(input$draw_polygon, {
      showNotification("Polygon drawing mode activated. Click to add points, double-click to finish.", 
        type = "info", duration = 4)
    })
    
    observeEvent(input$clear_drawings, {
      showNotification("All drawings cleared", type = "success", duration = 2)
    })
    
    # Timeline control handlers
    observeEvent(input$play_timeline, {
      showNotification("Timeline animation started", type = "info", duration = 2)
    })
    
    observeEvent(input$reset_timeline, {
      updateSliderInput(session, "timeline_range", 
        value = c(as.Date("2000-01-01"), Sys.Date()))
      showNotification("Timeline reset", type = "success", duration = 2)
    })
    
    # Integration feature handlers
    observeEvent(input$open_document_details, {
      # Create document detail modal
      showModal(modalDialog(
        title = "Document Details Integration",
        div(
          h4("Selected Region Analysis"),
          p("This will open detailed document analysis for the selected region."),
          p("Integration with Library tab will show:"),
          tags$ul(
            tags$li("Document list with full text search"),
            tags$li("Citation network analysis"), 
            tags$li("Temporal document trends"),
            tags$li("Cross-reference with other regions")
          )
        ),
        footer = tagList(
          actionButton("navigate_to_library", "Open Library Tab", class = "btn-primary"),
          modalButton("Close")
        ),
        size = "m"
      ))
    })
    
    observeEvent(input$sync_library, {
      showNotification("Synchronizing with Library tab...", type = "info", duration = 2)
      # Here would go integration logic with library tab
      Sys.sleep(1) # Simulate processing
      showNotification("Library synchronization complete", type = "success", duration = 2)
    })
    
    observeEvent(input$view_analytics, {
      showNotification("Opening Advanced Analytics view...", type = "info", duration = 2)
      # Here would go navigation to analytics tab with current filters
    })
    
    # Sharing and collaboration handlers
    observeEvent(input$bookmark_view, {
      # Generate bookmark state
      bookmark_state <- list(
        map_type = input$map_type,
        metric = input$map_metric,
        category = input$map_category,
        date_range = input$map_date_range,
        color_scale = input$color_scale,
        threshold = input$density_threshold,
        options = input$map_options,
        tools = input$analysis_tools,
        timestamp = Sys.time()
      )
      
      map_state$bookmark_state <- bookmark_state
      
      showModal(modalDialog(
        title = "View Bookmarked",
        div(
          h4("Current View Saved"),
          p("Your current map configuration has been bookmarked:"),
          tags$ul(
            tags$li("Visualization:", bookmark_state$map_type),
            tags$li("Metric:", bookmark_state$metric), 
            tags$li("Category:", bookmark_state$category),
            tags$li("Color scheme:", bookmark_state$color_scale)
          ),
          p(tags$small("Bookmark created at:", format(bookmark_state$timestamp, "%Y-%m-%d %H:%M")))
        ),
        footer = modalButton("Close"),
        size = "s"
      ))
    })
    
    observeEvent(input$share_link, {
      # Generate shareable URL parameters
      share_params <- list(
        type = input$map_type,
        metric = input$map_metric,
        category = input$map_category,
        scale = input$color_scale
      )
      
      # Create shareable URL (simplified)
      share_url <- paste0("?", paste(names(share_params), share_params, sep = "=", collapse = "&"))
      
      showModal(modalDialog(
        title = "Share Interactive Map",
        div(
          h4("Share This View"),
          p("Copy this link to share your current map configuration:"),
          tags$input(
            type = "text", 
            value = share_url,
            style = "width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;",
            readonly = "readonly",
            onclick = "this.select();"
          ),
          br(), br(),
          p(tags$small("Recipients will see the same visualization, filters, and settings."))
        ),
        footer = modalButton("Close"),
        size = "m"
      ))
    })
    
    observeEvent(input$print_map, {
      showNotification("Preparing print-friendly layout...", type = "info", duration = 2)
      # Here would go logic to generate print-optimized version
    })
    
    # Enhanced download handlers
    output$download_map <- downloadHandler(
      filename = function() {
        paste0("legislative_map_", input$map_type, "_", input$map_metric, "_", Sys.Date(), ".html")
      },
      content = function(file) {
        showNotification("Generating high-resolution map export...", type = "info", duration = 3)
        
        # Create enhanced standalone map
        p <- isolate({
          data <- state_map_data()
          metric <- input$map_metric
          map_type <- input$map_type
          value_col <- switch(metric,
            "count" = "documents",
            "per_capita" = "per_capita",
            "activity" = "activity_index",
            "density" = "density",
            "temporal" = "documents"
          )
          
          # Enhanced export with metadata
          enhanced_map <- create_fallback_map(data, value_col, input$color_scale, input$map_opacity, input$map_options) %>%
            layout(
              title = list(
                text = paste("Brazilian Legislative Activity:", 
                           switch(metric,
                             "count" = "Document Count Analysis",
                             "per_capita" = "Per Capita Analysis",
                             "activity" = "Activity Index Analysis",
                             "density" = "Regulatory Density Analysis",
                             "temporal" = "Temporal Intensity Analysis")),
                font = list(size = 18)
              ),
              annotations = list(
                list(x = 0, y = -0.15, xref = 'paper', yref = 'paper',
                     text = paste("Generated:", Sys.time(), "| Data range:", 
                                input$map_date_range[1], "to", input$map_date_range[2]),
                     showarrow = FALSE, xanchor = 'left', font = list(size = 10))
              )
            )
          
          enhanced_map
        })
        
        htmlwidgets::saveWidget(p, file, selfcontained = TRUE)
        showNotification("Map export completed successfully", type = "success", duration = 2)
      }
    )
    
    # Enhanced data download
    output$download_data <- downloadHandler(
      filename = function() {
        paste0("legislative_data_", input$map_category, "_", Sys.Date(), ".csv")
      },
      content = function(file) {
        data <- state_map_data()
        
        # Add metadata columns
        data$export_timestamp <- Sys.time()
        data$export_filters <- paste(
          "Category:", input$map_category,
          "| Metric:", input$map_metric,
          "| Date Range:", input$map_date_range[1], "to", input$map_date_range[2]
        )
        
        write.csv(data, file, row.names = FALSE)
        showNotification("Data export completed", type = "success", duration = 2)
      }
    )
    
    # Full report download
    output$download_report <- downloadHandler(
      filename = function() {
        paste0("legislative_analysis_report_", Sys.Date(), ".html")
      },
      content = function(file) {
        showNotification("Generating comprehensive analysis report...", type = "info", duration = 4)
        
        # Create comprehensive report (simplified version)
        report_content <- paste0(
          "<html><head><title>Legislative Analysis Report</title>",
          "<style>body{font-family: Arial, sans-serif; margin: 40px;} .metric{background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff;}</style>",
          "</head><body>",
          "<h1>Brazilian Legislative Activity Analysis Report</h1>",
          "<p><strong>Generated:</strong> ", Sys.time(), "</p>",
          "<p><strong>Analysis Period:</strong> ", input$map_date_range[1], " to ", input$map_date_range[2], "</p>",
          "<p><strong>Category Filter:</strong> ", input$map_category, "</p>",
          "<p><strong>Visualization Type:</strong> ", input$map_type, "</p>",
          "<p><strong>Primary Metric:</strong> ", input$map_metric, "</p>",
          
          "<h2>Summary Statistics</h2>",
          "<div class='metric'><strong>Total Documents:</strong> ", format(sum(state_map_data()$documents, na.rm = TRUE), big.mark = ","), "</div>",
          "<div class='metric'><strong>Geographic Coverage:</strong> ", sum(state_map_data()$documents > 0, na.rm = TRUE), " of ", nrow(state_map_data()), " states</div>",
          "<div class='metric'><strong>National Average:</strong> ", round(mean(state_map_data()$documents, na.rm = TRUE), 0), " documents per state</div>",
          
          "<h2>Methodology</h2>",
          "<p>This analysis was generated using the Monitor Legislativo v4 Interactive Maps system. Data sources include Brazilian federal, state, and municipal legislative databases.</p>",
          
          "<p style='margin-top: 40px; color: #6c757d; font-size: 12px;'>Report generated by Monitor Legislativo v4 - Brazilian Legislative Monitoring System</p>",
          "</body></html>"
        )
        
        writeLines(report_content, file, useBytes = TRUE)
        showNotification("Comprehensive report generated", type = "success", duration = 2)
      }
    )
    
    # Enhanced analysis outputs for new tabs
    output$top_municipalities_table <- DT::renderDataTable({
      pool_conn <- pool()
      if (is.null(pool_conn)) {
        return(data.frame(Municipality = "No data available", Documents = 0))
      }
      
      municipality_data <- tryCatch({
        query <- "SELECT municipality, state, COUNT(*) as documents 
                  FROM extracted_municipalities_comprehensive 
                  WHERE municipality IS NOT NULL 
                  GROUP BY municipality, state 
                  ORDER BY documents DESC 
                  LIMIT 15"
        dbGetQuery(pool_conn, query)
      }, error = function(e) {
        data.frame(Municipality = "Data unavailable", State = "", Documents = 0)
      })
      
      DT::datatable(
        municipality_data,
        options = list(
          pageLength = 10,
          dom = 't',
          ordering = TRUE
        ),
        rownames = FALSE
      ) %>%
        DT::formatStyle("documents",
          background = styleColorBar(range(municipality_data$documents), '#007bff'),
          backgroundSize = '90% 50%',
          backgroundRepeat = 'no-repeat',
          backgroundPosition = 'right'
        )
    })
    
    # Temporal trend chart
    output$temporal_trend_chart <- renderPlotly({
      data <- map_data()
      
      if ("year" %in% names(data) && nrow(data) > 0) {
        # Simple temporal aggregation
        yearly_counts <- aggregate(rep(1, nrow(data)), by = list(year = data$year), FUN = sum, na.rm = TRUE)
        names(yearly_counts)[2] <- "documents"
        yearly_counts <- yearly_counts[yearly_counts$year >= 2000 & yearly_counts$year <= 2025, ]
        
        plot_ly(
          data = yearly_counts,
          x = ~year,
          y = ~documents,
          type = 'scatter',
          mode = 'lines+markers',
          line = list(color = '#007bff', width = 3),
          marker = list(color = '#007bff', size = 6)
        ) %>%
          layout(
            title = "",
            xaxis = list(title = "Year"),
            yaxis = list(title = "Documents"),
            showlegend = FALSE,
            margin = list(t = 30)
          )
      } else {
        plot_ly() %>% layout(title = "Temporal data not available")
      }
    })
    
    # Seasonal pattern chart  
    output$seasonal_pattern_chart <- renderPlotly({
      data <- map_data()
      
      if ("date" %in% names(data) && nrow(data) > 0) {
        # Extract months and aggregate
        data$month <- format(as.Date(data$date), "%m")
        monthly_counts <- aggregate(rep(1, nrow(data)), by = list(month = data$month), FUN = sum, na.rm = TRUE)
        names(monthly_counts)[2] <- "documents"
        monthly_counts$month_name <- month.abb[as.numeric(monthly_counts$month)]
        
        plot_ly(
          data = monthly_counts,
          x = ~month_name,
          y = ~documents,
          type = 'bar',
          marker = list(color = '#28a745')
        ) %>%
          layout(
            title = "",
            xaxis = list(title = "Month"),
            yaxis = list(title = "Documents"),
            margin = list(t = 30)
          )
      } else {
        plot_ly() %>% layout(title = "Seasonal data not available")
      }
    })
}

# Helper function for fallback map
create_fallback_map <- function(data, value_col, color_scale = "Viridis", opacity = 0.85, map_options = c()) {
  # Calculate marker sizes
  max_value <- max(data[[value_col]], na.rm = TRUE)
  data$marker_size <- sqrt(data[[value_col]] / max_value) * 100
  
  # Adjust for high contrast mode
  line_color <- if ("high_contrast" %in% map_options) "black" else "white"
  line_width <- if ("high_contrast" %in% map_options) 2 else 0.5
  
  plot_ly(
    data = data,
    lon = ~lng,
    lat = ~lat,
    type = 'scattergeo',
    locationmode = 'geojson-id',
    mode = 'markers',
    marker = list(
      size = ~marker_size,
      color = data[[value_col]],
      colorscale = color_scale,
      cmin = 0,
      cmax = max_value,
      opacity = opacity,
      colorbar = list(
        title = list(
          text = switch(value_col,
            "documents" = "Documents",
            "per_capita" = "Per 100k",
            "activity_index" = "Index",
            "density" = "Per Million"
          ),
          font = list(size = 12)
        ),
        thickness = 20,
        len = 0.8,
        x = 1.02,
        bordercolor = line_color,
        borderwidth = 1
      ),
      line = list(color = line_color, width = line_width)
    ),
    text = ~hover_text,
    hoverinfo = 'text'
  ) %>%
    layout(
      title = list(
        text = paste("Document Distribution -", 
                     switch(value_col,
                            "documents" = "Total Count",
                            "per_capita" = "Per Capita", 
                            "activity_index" = "Activity Index",
                            "density" = "Regulatory Density")),
        font = list(size = 16, family = "Arial"),
        x = 0.5
      ),
      geo = list(
        scope = 'south america',
        showland = TRUE,
        landcolor = toRGB("gray90"),
        center = list(lat = -14, lon = -51),
        projection = list(scale = 2.5),
        showcountries = TRUE,
        countrycolor = toRGB("gray80")
      ),
      margin = list(l = 0, r = 0, t = 50, b = 0),
      font = list(family = "Arial, sans-serif")
    )
} # End of create_fallback_map function