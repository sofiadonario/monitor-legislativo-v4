# Map Server Module
# This module contains the server logic for the Interactive Maps tab

# Load required data
source("data/brazil_states.R", local = TRUE)

# Load data cleaning fix if available
if (file.exists("fixes/active/map_data_fix.R")) {
  source("fixes/active/map_data_fix.R", local = TRUE)
}

mapServer <- function(id, analytics_data, pool) {
  # Handle moduleServer function availability
  if (exists("moduleServer") && is.function(moduleServer)) {
    moduleServer(id, function(input, output, session) {
      map_server_logic(input, output, session, analytics_data, pool)
    })
  } else {
    # Fallback for when moduleServer is not available
    function(input, output, session) {
      map_server_logic(input, output, session, analytics_data, pool)
    }
  }
}

# Main server logic extracted to separate function
map_server_logic <- function(input, output, session, analytics_data, pool) {
    
    # Reactive values for performance optimization
    map_trigger <- reactiveVal(0)
    
    # Debounced inputs for performance
    map_type_debounced <- debounce(reactive(input$map_type), 500)
    map_metric_debounced <- debounce(reactive(input$map_metric), 500)
    map_category_debounced <- debounce(reactive(input$map_category), 500)
    map_date_range_debounced <- debounce(reactive(input$map_date_range), 1000)
    
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
    
    # Main interactive Brazil map
    output$interactive_brazil_map <- renderPlotly({
      req(state_map_data())
      
      data <- state_map_data()
      metric <- map_metric_debounced()
      
      # Select metric column
      value_col <- switch(metric,
        "count" = "documents",
        "per_capita" = "per_capita",
        "activity" = "activity_index",
        "density" = "density"
      )
      
      # Create hover text
      data$hover_text <- paste0(
        "<b>", data$state_name, " (", data$state_code, ")</b><br>",
        "Region: ", data$region, "<br>",
        "Documents: ", format(data$documents, big.mark = ","), "<br>",
        "Population: ", format(data$population, big.mark = ","), "<br>",
        "Per Capita: ", data$per_capita, " per 100k<br>",
        "Activity Index: ", data$activity_index
      )
      
      # Try to use choropleth generator if available
      if (exists("generate_choropleth_map")) {
        tryCatch({
          generate_choropleth_map(
            data = data,
            value_column = value_col,
            title = paste("Brazilian Documents -", 
                         switch(metric,
                                "count" = "Total Count",
                                "per_capita" = "Per Capita",
                                "activity" = "Activity Index",
                                "density" = "Regulatory Density")),
            show_labels = "labels" %in% input$map_options
          )
        }, error = function(e) {
          # Fallback to simple scatter map
          create_fallback_map(data, value_col)
        })
      } else {
        # Direct fallback implementation
        create_fallback_map(data, value_col)
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
    
    # Refresh map data
    observeEvent(input$refresh_map, {
      map_trigger(map_trigger() + 1)
      showNotification("Map data refreshed", type = "success", duration = 2)
    })
    
    # Download map handler
    output$download_map <- downloadHandler(
      filename = function() {
        paste0("brazil_map_", Sys.Date(), ".html")
      },
      content = function(file) {
        # Create a standalone HTML file with the plot
        p <- isolate({
          data <- state_map_data()
          metric <- input$map_metric
          value_col <- switch(metric,
            "count" = "documents",
            "per_capita" = "per_capita",
            "activity" = "activity_index",
            "density" = "density"
          )
          
          if (exists("generate_choropleth_map")) {
            generate_choropleth_map(data, value_col, 
                                  paste("Brazilian Documents -", metric),
                                  show_labels = "labels" %in% input$map_options)
          } else {
            create_fallback_map(data, value_col)
          }
        })
        
        htmlwidgets::saveWidget(p, file, selfcontained = TRUE)
      }
    )
}

# Helper function for fallback map
create_fallback_map <- function(data, value_col) {
  # Calculate marker sizes
  max_value <- max(data[[value_col]], na.rm = TRUE)
  data$marker_size <- sqrt(data[[value_col]] / max_value) * 100
  
  plot_ly(
    data = data,
    lon = ~lng,
    lat = ~lat,
    type = 'scattergeo',
    locationmode = 'geojson-id',
    mode = 'markers',
    marker = list(
      size = ~marker_size,
      color = ~get(value_col),
      colorscale = 'Viridis',
      cmin = 0,
      cmax = max_value,
      colorbar = list(
        title = switch(value_col,
          "documents" = "Documents",
          "per_capita" = "Per 100k",
          "activity_index" = "Index",
          "density" = "Per Million"
        )
      ),
      line = list(color = 'white', width = 0.5)
    ),
    text = ~hover_text,
    hoverinfo = 'text'
  ) %>%
    layout(
      title = paste("Document Distribution -", 
                   switch(value_col,
                          "documents" = "Total Count",
                          "per_capita" = "Per Capita", 
                          "activity_index" = "Activity Index",
                          "density" = "Regulatory Density")),
      geo = list(
        scope = 'south america',
        showland = TRUE,
        landcolor = toRGB("gray90"),
        center = list(lat = -14, lon = -51),
        projection = list(scale = 2.5),
        showcountries = TRUE,
        countrycolor = toRGB("gray80")
      ),
      margin = list(l = 0, r = 0, t = 50, b = 0)
    )
} # End of create_fallback_map function