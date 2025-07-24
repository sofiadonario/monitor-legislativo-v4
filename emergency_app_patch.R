# Emergency App Patch
# Overrides app.R map outputs to use working emergency functions

cat("🚨 EMERGENCY APP PATCH - Overriding broken map outputs\n")

# ============================================================================
# 1. EMERGENCY MAP OUTPUT OVERRIDES
# ============================================================================

#' Emergency total documents map output
#' Overrides the broken output$totalDocumentsMap
create_emergency_total_documents_map <- function() {
  tryCatch({
    cat("🔄 Creating emergency total documents map...\n")
    
    # Use emergency map data function
    map_data <- get_emergency_map1_data()
    
    if (nrow(map_data) == 0) {
      cat("⚠️ No map data available, showing fallback map\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
        addMarker(lng = -47.86, lat = -15.83, 
                 popup = "No geographic data available - Using emergency fallback"))
    }
    
    cat("✅ Map data loaded:", nrow(map_data), "jurisdictions\n")
    
    # Create map with state markers
    map <- leaflet(map_data) %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4)
    
    # Add markers for each jurisdiction
    for (i in 1:nrow(map_data)) {
      row <- map_data[i, ]
      if (row$count > 0) {
        popup_text <- paste0(
          "<b>", row$jurisdicao, "</b><br/>",
          "Documents: ", row$count
        )
        
        map <- map %>%
          addCircleMarkers(
            lng = -47.86, lat = -15.83,  # Center of Brazil
            radius = sqrt(row$count) / 10,
            popup = popup_text,
            fillOpacity = 0.7,
            color = "blue"
          )
      }
    }
    
    cat("✅ Emergency total documents map created\n")
    return(map)
    
  }, error = function(e) {
    cat("❌ Error creating emergency total map:", e$message, "\n")
    return(leaflet() %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
      addMarker(lng = -47.86, lat = -15.83, 
               popup = paste("Emergency map error:", e$message)))
  })
}

#' Emergency legislation map output
#' Overrides the broken output$legislationMap
create_emergency_legislation_map <- function() {
  tryCatch({
    cat("🔄 Creating emergency legislation map...\n")
    
    # Use emergency map data function
    map_data <- get_emergency_map2_data()
    
    if (nrow(map_data) == 0) {
      cat("⚠️ No legislation data available, showing fallback map\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
        addMarker(lng = -47.86, lat = -15.83, 
                 popup = "No legislation data available - Using emergency fallback"))
    }
    
    cat("✅ Legislation map data loaded:", nrow(map_data), "states\n")
    
    # Create map with state markers
    map <- leaflet(map_data) %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4)
    
    # Add markers for each state
    for (i in 1:nrow(map_data)) {
      row <- map_data[i, ]
      if (row$count > 0) {
        popup_text <- paste0(
          "<b>", row$estado, "</b><br/>",
          "Legislation Documents: ", row$count
        )
        
        map <- map %>%
          addCircleMarkers(
            lng = -47.86, lat = -15.83,  # Center of Brazil
            radius = sqrt(row$count) / 8,
            popup = popup_text,
            fillOpacity = 0.7,
            color = "orange"
          )
      }
    }
    
    cat("✅ Emergency legislation map created\n")
    return(map)
    
  }, error = function(e) {
    cat("❌ Error creating emergency legislation map:", e$message, "\n")
    return(leaflet() %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
      addMarker(lng = -47.86, lat = -15.83, 
               popup = paste("Emergency legislation map error:", e$message)))
  })
}

#' Emergency jurisprudence map output
#' Overrides the broken output$jurisprudenceMap
create_emergency_jurisprudence_map <- function() {
  tryCatch({
    cat("🔄 Creating emergency jurisprudence map...\n")
    
    # Use emergency map data function
    map_data <- get_emergency_map3_data()
    
    if (nrow(map_data) == 0) {
      cat("⚠️ No jurisprudence data available, showing fallback map\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
        addMarker(lng = -47.86, lat = -15.83, 
                 popup = "No jurisprudence data available - Using emergency fallback"))
    }
    
    cat("✅ Jurisprudence map data loaded:", nrow(map_data), "states\n")
    
    # Create map with state markers
    map <- leaflet(map_data) %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4)
    
    # Add markers for each state
    for (i in 1:nrow(map_data)) {
      row <- map_data[i, ]
      if (row$count > 0) {
        popup_text <- paste0(
          "<b>", row$estado, "</b><br/>",
          "Jurisprudence Documents: ", row$count
        )
        
        map <- map %>%
          addCircleMarkers(
            lng = -47.86, lat = -15.83,  # Center of Brazil
            radius = sqrt(row$count) / 8,
            popup = popup_text,
            fillOpacity = 0.7,
            color = "red"
          )
      }
    }
    
    cat("✅ Emergency jurisprudence map created\n")
    return(map)
    
  }, error = function(e) {
    cat("❌ Error creating emergency jurisprudence map:", e$message, "\n")
    return(leaflet() %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
      addMarker(lng = -47.86, lat = -15.83, 
               popup = paste("Emergency jurisprudence map error:", e$message)))
  })
}

# ============================================================================
# 2. EMERGENCY VALUE BOX OVERRIDES
# ============================================================================

#' Emergency document count value box
#' Overrides the broken value box for document count
get_emergency_document_count_value <- function() {
  tryCatch({
    metrics <- get_emergency_dashboard_metrics()
    return(metrics$total_docs)
  }, error = function(e) {
    cat("❌ Error getting emergency document count:", e$message, "\n")
    return(0)
  })
}

#' Emergency states count value box
#' Overrides the broken value box for states count
get_emergency_states_count_value <- function() {
  tryCatch({
    metrics <- get_emergency_dashboard_metrics()
    return(metrics$states_with_docs)
  }, error = function(e) {
    cat("❌ Error getting emergency states count:", e$message, "\n")
    return(0)
  })
}

#' Emergency municipalities count value box
#' Overrides the broken value box for municipalities count
get_emergency_municipalities_count_value <- function() {
  tryCatch({
    metrics <- get_emergency_dashboard_metrics()
    return(metrics$municipalities_with_docs)
  }, error = function(e) {
    cat("❌ Error getting emergency municipalities count:", e$message, "\n")
    return(0)
  })
}

#' Emergency date range value box
#' Overrides the broken value box for date range
get_emergency_date_range_value <- function() {
  tryCatch({
    metrics <- get_emergency_dashboard_metrics()
    return(metrics$date_range)
  }, error = function(e) {
    cat("❌ Error getting emergency date range:", e$message, "\n")
    return("Error loading date range")
  })
}

# ============================================================================
# 3. OVERRIDE APP FUNCTIONS
# ============================================================================

# Override the app functions with emergency versions
assign("create_emergency_total_documents_map", create_emergency_total_documents_map, envir = .GlobalEnv)
assign("create_emergency_legislation_map", create_emergency_legislation_map, envir = .GlobalEnv)
assign("create_emergency_jurisprudence_map", create_emergency_jurisprudence_map, envir = .GlobalEnv)
assign("get_emergency_document_count_value", get_emergency_document_count_value, envir = .GlobalEnv)
assign("get_emergency_states_count_value", get_emergency_states_count_value, envir = .GlobalEnv)
assign("get_emergency_municipalities_count_value", get_emergency_municipalities_count_value, envir = .GlobalEnv)
assign("get_emergency_date_range_value", get_emergency_date_range_value, envir = .GlobalEnv)

cat("✅ Emergency app patch loaded\n")
cat("📊 Functions available for override:\n")
cat("  - create_emergency_total_documents_map()\n")
cat("  - create_emergency_legislation_map()\n")
cat("  - create_emergency_jurisprudence_map()\n")
cat("  - get_emergency_document_count_value()\n")
cat("  - get_emergency_states_count_value()\n")
cat("  - get_emergency_municipalities_count_value()\n")
cat("  - get_emergency_date_range_value()\n")
cat("\n")
cat("🚨 These functions should be used in app.R instead of broken ones\n") 