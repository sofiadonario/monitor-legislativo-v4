# Dashboard Updates for Refined CSV Data Integration
# Updates to be applied to app.R for using ./data_current CSV files

# Updated value box functions for document overview

# Total documents value box - now using refined CSV data
output$totalDocs <- renderValueBox({
  # Use refined CSV data from Geral.csv
  if (!is.null(values$document_overview_stats)) {
    count <- values$document_overview_stats$total_documents
    status_color <- "blue"  # Blue for CSV data
  } else if (database_connected && !is.null(db_pool)) {
    # Fallback to database query
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      count <- as.numeric(dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")$count)
      status_color <- "green"
    }, error = function(e) {
      count <- ifelse(is.null(values$current_documents), 0, nrow(values$current_documents))
      status_color <- "red"
    })
  } else {
    count <- ifelse(is.null(values$current_documents), 0, nrow(values$current_documents))
    status_color <- "yellow"
  }
  
  valueBox(
    value = count,
    subtitle = "Total Documents (Geral.csv)",
    icon = icon("file-text"),
    color = status_color
  )
})

# Total states value box - now shows all 27 states researched
output$totalStates <- renderValueBox({
  if (!is.null(values$document_overview_stats)) {
    states_with_docs <- values$document_overview_stats$coverage_summary$states_with_documents
    total_states <- values$document_overview_stats$coverage_summary$total_states
    display_text <- paste(states_with_docs, "/", total_states)
    status_color <- "blue"
  } else if (database_connected && !is.null(db_pool)) {
    # Fallback to database query
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      count <- as.numeric(dbGetQuery(conn, "SELECT COUNT(DISTINCT estado) as count FROM documents WHERE estado IS NOT NULL AND estado != ''")$count)
      display_text <- paste(count, "states")
      status_color <- "green"
    }, error = function(e) {
      count <- ifelse(is.null(values$analytics_data), 0, nrow(values$analytics_data$documents_by_state))
      display_text <- paste(count, "states")
      status_color <- "red"
    })
  } else {
    count <- ifelse(is.null(values$analytics_data), 0, nrow(values$analytics_data$documents_by_state))
    display_text <- paste(count, "states")
    status_color <- "yellow"
  }
  
  valueBox(
    value = display_text,
    subtitle = "States Researched",
    icon = icon("map"),
    color = status_color
  )
})

# Total types value box - showing document type distribution
output$totalTypes <- renderValueBox({
  if (!is.null(values$document_overview_stats)) {
    type_count <- nrow(values$document_overview_stats$by_document_type)
    status_color <- "blue"
  } else if (database_connected && !is.null(db_pool)) {
    # Fallback to database query
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      type_count <- as.numeric(dbGetQuery(conn, "SELECT COUNT(DISTINCT tipo) as count FROM documents WHERE tipo IS NOT NULL AND tipo != ''")$count)
      status_color <- "green"
    }, error = function(e) {
      type_count <- ifelse(is.null(values$analytics_data), 0, length(unique(values$analytics_data$documents_by_type$type)))
      status_color <- "red"
    })
  } else {
    type_count <- ifelse(is.null(values$analytics_data), 0, length(unique(values$analytics_data$documents_by_type$type)))
    status_color <- "yellow"
  }
  
  valueBox(
    value = type_count,
    subtitle = "Document Types",
    icon = icon("tags"),
    color = status_color
  )
})

# Date range value box - showing data collection period
output$dateRange <- renderValueBox({
  if (!is.null(values$document_overview_stats)) {
    # For CSV data, show a fixed range since it's from July 2025 collection
    display_text <- "2025-07-14"
    subtitle_text <- "Collection Date"
    status_color <- "blue"
  } else if (database_connected && !is.null(db_pool)) {
    # Fallback to database query
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      date_range <- dbGetQuery(conn, "SELECT MIN(data_publicacao) as min_date, MAX(data_publicacao) as max_date FROM documents WHERE data_publicacao IS NOT NULL")
      if (!is.null(date_range) && !is.na(date_range$min_date)) {
        min_year <- format(as.Date(date_range$min_date), "%Y")
        max_year <- format(as.Date(date_range$max_date), "%Y")
        display_text <- if (min_year == max_year) min_year else paste(min_year, "-", max_year)
        subtitle_text <- "Date Range"
      } else {
        display_text <- "N/A"
        subtitle_text <- "Date Range"
      }
      status_color <- "green"
    }, error = function(e) {
      display_text <- "N/A"
      subtitle_text <- "Date Range"
      status_color <- "red"
    })
  } else {
    display_text <- "N/A"
    subtitle_text <- "Date Range"
    status_color <- "yellow"
  }
  
  valueBox(
    value = display_text,
    subtitle = subtitle_text,
    icon = icon("calendar"),
    color = status_color
  )
})

# Updated map rendering for legislative documents
output$legislativeMap <- renderLeaflet({
  if (!is.null(values$legislation_layers) && !is.null(values$geographic_data)) {
    
    # Create base map
    map <- leaflet() %>%
      addTiles() %>%
      setView(lng = -47.8825, lat = -15.7942, zoom = 4)  # Center on Brazil
    
    # Add jurisdiction layers with different colors
    legislation_data <- values$legislation_layers$data
    
    # Federal layer (red)
    if (nrow(legislation_data$federal) > 0) {
      federal_counts <- legislation_data$federal %>%
        count(Display_state, name = "count") %>%
        filter(!is.na(Display_state))
      
      # Add federal documents as markers
      map <- map %>%
        addCircleMarkers(
          lng = -47.8825, lat = -15.7942, # Center of Brazil for federal
          radius = 10,
          color = "red",
          fillOpacity = 0.7,
          popup = paste("Federal Legislative Documents:", nrow(legislation_data$federal)),
          group = "Federal"
        )
    }
    
    # State layer (blue)
    if (nrow(legislation_data$state) > 0) {
      state_counts <- legislation_data$state %>%
        count(Display_state, name = "count") %>%
        filter(!is.na(Display_state))
      
      # Add state markers (simplified positioning)
      for (i in 1:nrow(state_counts)) {
        map <- map %>%
          addCircleMarkers(
            lng = -47 + runif(1, -10, 10), # Random positioning for demo
            lat = -15 + runif(1, -10, 10),
            radius = sqrt(state_counts$count[i]) + 5,
            color = "blue",
            fillOpacity = 0.7,
            popup = paste(state_counts$Display_state[i], ":", state_counts$count[i], "documents"),
            group = "State"
          )
      }
    }
    
    # Municipal layer (green)
    if (nrow(legislation_data$municipal) > 0) {
      municipal_counts <- legislation_data$municipal %>%
        count(Display_state, Municipality, name = "count") %>%
        filter(!is.na(Display_state) & !is.na(Municipality))
      
      # Add municipal markers
      for (i in 1:nrow(municipal_counts)) {
        map <- map %>%
          addCircleMarkers(
            lng = -47 + runif(1, -15, 15), # Random positioning for demo
            lat = -15 + runif(1, -15, 15),
            radius = sqrt(municipal_counts$count[i]) + 3,
            color = "green",
            fillOpacity = 0.7,
            popup = paste(municipal_counts$Municipality[i], ",", municipal_counts$Display_state[i], ":", municipal_counts$count[i], "documents"),
            group = "Municipal"
          )
      }
    }
    
    # Add layer controls
    map <- map %>%
      addLayersControl(
        overlayGroups = c("Federal", "State", "Municipal"),
        options = layersControlOptions(collapsed = FALSE)
      ) %>%
      addLegend(
        position = "bottomright",
        colors = c("red", "blue", "green"),
        labels = c("Federal", "State", "Municipal"),
        title = "Jurisdiction Level"
      )
    
    return(map)
  }
  
  # Fallback empty map
  leaflet() %>%
    addTiles() %>%
    setView(lng = -47.8825, lat = -15.7942, zoom = 4)
})

# Updated map rendering for jurisprudence documents
output$jurisprudenceMap <- renderLeaflet({
  if (!is.null(values$jurisprudence_layers) && !is.null(values$geographic_data)) {
    
    # Create base map
    map <- leaflet() %>%
      addTiles() %>%
      setView(lng = -47.8825, lat = -15.7942, zoom = 4)  # Center on Brazil
    
    # Add jurisdiction layers with different colors
    jurisprudence_data <- values$jurisprudence_layers$data
    
    # Federal layer (purple)
    if (nrow(jurisprudence_data$federal) > 0) {
      map <- map %>%
        addCircleMarkers(
          lng = -47.8825, lat = -15.7942, # Center of Brazil for federal
          radius = 10,
          color = "purple",
          fillOpacity = 0.7,
          popup = paste("Federal Jurisprudence Documents:", nrow(jurisprudence_data$federal)),
          group = "Federal"
        )
    }
    
    # State layer (orange)
    if (nrow(jurisprudence_data$state) > 0) {
      state_counts <- jurisprudence_data$state %>%
        count(Display_state, name = "count") %>%
        filter(!is.na(Display_state))
      
      # Add state markers
      for (i in 1:nrow(state_counts)) {
        map <- map %>%
          addCircleMarkers(
            lng = -47 + runif(1, -10, 10), # Random positioning for demo
            lat = -15 + runif(1, -10, 10),
            radius = sqrt(state_counts$count[i]) + 5,
            color = "orange",
            fillOpacity = 0.7,
            popup = paste(state_counts$Display_state[i], ":", state_counts$count[i], "jurisprudence documents"),
            group = "State"
          )
      }
    }
    
    # Regional layer (yellow)
    if (nrow(jurisprudence_data$regional) > 0) {
      regional_counts <- jurisprudence_data$regional %>%
        count(Display_state, name = "count") %>%
        filter(!is.na(Display_state))
      
      for (i in 1:nrow(regional_counts)) {
        map <- map %>%
          addCircleMarkers(
            lng = -47.8825, lat = -15.7942, # DF position
            radius = sqrt(regional_counts$count[i]) + 5,
            color = "yellow",
            fillOpacity = 0.7,
            popup = paste("Regional (DF):", regional_counts$count[i], "jurisprudence documents"),
            group = "Regional"
          )
      }
    }
    
    # Add layer controls
    map <- map %>%
      addLayersControl(
        overlayGroups = c("Federal", "State", "Regional"),
        options = layersControlOptions(collapsed = FALSE)
      ) %>%
      addLegend(
        position = "bottomright",
        colors = c("purple", "orange", "yellow"),
        labels = c("Federal", "State", "Regional"),
        title = "Jurisdiction Level"
      )
    
    return(map)
  }
  
  # Fallback empty map
  leaflet() %>%
    addTiles() %>%
    setView(lng = -47.8825, lat = -15.7942, zoom = 4)
})

cat("📋 Dashboard updates for refined CSV data integration ready\n")