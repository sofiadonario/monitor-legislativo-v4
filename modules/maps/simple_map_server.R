# Simple Map Server Implementation
# Direct server logic without module system

cat("Loading simple map server implementation...\n")

# Main interactive Brazil map
output$interactive_brazil_map <- renderPlotly({
  tryCatch({
    cat("[TRACE] maps_simple:interactive_brazil_map start\n", file = stderr())
    cat("🗺️ Starting interactive Brazil map generation (simple)\n")
    
    # Get data
    data <- analytics_data()
    if (isTRUE(is.null(data)) || nrow(data) == 0) {
      return(plot_ly() %>% layout(title = "No data available"))
    }
    
    # Clean data if function available
    if (exists("clean_map_data")) {
      data <- clean_map_data(data)
    }
    
    # Apply filters
    if (exists("input") && !isTRUE(is.null(input$map_category)) && input$map_category != "all") {
      if ("category" %in% names(data)) {
        data <- data[data$category == input$map_category | is.na(data$category), ]
      }
    }
    
    # Aggregate by state
    if ("state" %in% names(data)) {
      valid_data <- data[!is.na(data$state) & data$state != "" & data$state %in% brazil_states$state_code, ]
      
      if (!isTRUE(is.null(valid_data)) && is.data.frame(valid_data) && nrow(valid_data) > 0) {
        state_list <- unique(valid_data$state)
        state_counts <- data.frame(
          state = state_list,
          documents = sapply(state_list, function(s) sum(valid_data$state == s, na.rm = TRUE)),
          stringsAsFactors = FALSE
        )
      } else {
        state_counts <- data.frame(state = character(), documents = numeric(), stringsAsFactors = FALSE)
      }
    } else {
      state_counts <- data.frame(state = character(), documents = numeric(), stringsAsFactors = FALSE)
    }
    
    # Merge with state reference data
    state_data <- merge(brazil_states, state_counts, by.x = "state_code", by.y = "state", all.x = TRUE)
    state_data$documents[is.na(state_data$documents)] <- 0
    state_data$per_capita <- round((state_data$documents / state_data$population) * 100000, 2)
    
    # Create hover text
    state_data$hover_text <- paste0(
      "<b>", state_data$state_name, " (", state_data$state_code, ")</b><br>",
      "Documents: ", format(state_data$documents, big.mark = ","), "<br>",
      "Population: ", format(state_data$population, big.mark = ","), "<br>",
      "Per Capita: ", state_data$per_capita
    )
    
    # Create map
    if (exists("generate_choropleth_map")) {
      tryCatch({
        generate_choropleth_map(state_data, "documents", "Brazilian Legislative Documents")
      }, error = function(e) {
        create_simple_fallback_map(state_data)
      })
    } else {
      create_simple_fallback_map(state_data)
    }
    
  }, error = function(e) {
    cat("❌ Error in map generation:", e$message, "\n")
    plot_ly() %>% layout(title = paste("Error generating map:", e$message))
  })
})

# Municipality detail map
output$municipality_detail_map <- renderPlotly({
  tryCatch({
    cat("[TRACE] maps_simple:municipality_detail_map start\n", file = stderr())
    # Simple bar chart of top states by document count
    data <- analytics_data()
    if (exists("clean_map_data")) {
      data <- clean_map_data(data)
    }
    
    if ("state" %in% names(data)) {
      state_summary <- data.frame(
        state = names(table(data$state)),
        count = as.numeric(table(data$state)),
        stringsAsFactors = FALSE
      )
      state_summary <- state_summary[order(state_summary$count, decreasing = TRUE), ]
      state_summary <- head(state_summary, 15)
      
      plot_ly(
        data = state_summary,
        x = ~count,
        y = ~reorder(state, count),
        type = 'bar',
        orientation = 'h',
        marker = list(color = 'steelblue')
      ) %>%
        layout(
          title = "Top 15 States by Document Count",
          xaxis = list(title = "Documents"),
          yaxis = list(title = "")
        )
    } else {
      plot_ly() %>% layout(title = "No state data available")
    }
  }, error = function(e) {
    plot_ly() %>% layout(title = "Error loading municipality data")
  })
})

# Temporal evolution map
output$temporal_map_animation <- renderPlotly({
  tryCatch({
    cat("[TRACE] maps_simple:temporal_map_animation start\n", file = stderr())
    data <- analytics_data()
    if (exists("clean_map_data")) {
      data <- clean_map_data(data)
    }
    
    if ("year" %in% names(data) && "state" %in% names(data)) {
      yearly_data <- data[!is.na(data$year) & data$year >= 2020 & data$year <= 2025, ]
      if (!isTRUE(is.null(yearly_data)) && is.data.frame(yearly_data) && nrow(yearly_data) > 0) {
        plot_ly(
          data = yearly_data,
          x = ~year,
          color = ~state,
          type = 'histogram'
        ) %>%
          layout(title = "Document Distribution Over Time")
      } else {
        plot_ly() %>% layout(title = "No temporal data available")
      }
    } else {
      plot_ly() %>% layout(title = "No temporal data columns found")
    }
  }, error = function(e) {
    plot_ly() %>% layout(title = "Error loading temporal data")
  })
})

# Statistics table
output$map_statistics_table <- DT::renderDataTable({
  tryCatch({
    data <- analytics_data()
    if (exists("clean_map_data")) {
      data <- clean_map_data(data)
    }
    
    if ("state" %in% names(data)) {
      state_stats <- aggregate(rep(1, nrow(data)), by = list(state = data$state), FUN = sum, na.rm = TRUE)
      names(state_stats) <- c("State", "Documents")
      state_stats <- state_stats[order(state_stats$Documents, decreasing = TRUE), ]
      
      DT::datatable(state_stats, options = list(pageLength = 10))
    } else {
      DT::datatable(data.frame(Message = "No state data available"))
    }
  }, error = function(e) {
    DT::datatable(data.frame(Error = paste("Error:", e$message)))
  })
})

# Simple fallback map function
create_simple_fallback_map <- function(state_data) {
  max_docs <- max(state_data$documents, na.rm = TRUE)
  if (max_docs == 0) max_docs <- 1
  
  state_data$marker_size <- pmax((state_data$documents / max_docs) * 50, 5)
  
  plot_ly(
    data = state_data,
    lon = ~lng,
    lat = ~lat,
    type = 'scattergeo',
    mode = 'markers',
    marker = list(
      size = ~marker_size,
      color = ~documents,
      colorscale = 'Viridis',
      line = list(color = 'white', width = 0.5)
    ),
    text = ~hover_text,
    hoverinfo = 'text'
  ) %>%
    layout(
      title = "Brazilian Legislative Documents by State",
      geo = list(
        scope = 'south america',
        showland = TRUE,
        landcolor = 'lightgray',
        center = list(lat = -14, lon = -51),
        projection = list(scale = 3)
      )
    )
}

cat("✅ Simple map server implementation loaded\n")
