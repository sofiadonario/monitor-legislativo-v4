# Emergency Dashboard Fix
# Rollback to working unified documents view to fix complete dashboard failure

cat("🚨 EMERGENCY DASHBOARD FIX - Rolling back to working unified approach\n")

# ============================================================================
# 1. EMERGENCY DASHBOARD METRICS FIX
# ============================================================================

#' Emergency dashboard metrics using unified documents view
#' This replaces the broken get_lexml_dashboard_metrics() function
get_emergency_dashboard_metrics <- function() {
  if (!database_connected || is.null(db_pool)) {
    return(list(
      total_docs = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      date_range = "Database not connected"
    ))
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Use unified documents view instead of broken lexml_* tables
    result <- dbGetQuery(conn, "
      SELECT 
        COUNT(*) as total_docs,
        COUNT(DISTINCT estado) as states_with_docs,
        COUNT(DISTINCT municipality) as municipalities_with_docs,
        MIN(data_publicacao) as min_date,
        MAX(data_publicacao) as max_date
      FROM documents 
      WHERE estado IS NOT NULL
    ")
    
    # Calculate date range
    date_range <- "No date range"
    if (!is.na(result$min_date) && !is.na(result$max_date)) {
      date_range <- paste0(
        format(as.Date(result$min_date), "%Y-%m-%d"), 
        " to ", 
        format(as.Date(result$max_date), "%Y-%m-%d")
      )
    }
    
    metrics <- list(
      total_docs = as.numeric(result$total_docs),
      states_with_docs = as.numeric(result$states_with_docs),
      municipalities_with_docs = as.numeric(result$municipalities_with_docs),
      date_range = date_range
    )
    
    cat("✅ Emergency dashboard metrics loaded:", metrics$total_docs, "documents\n")
    return(metrics)
    
  }, error = function(e) {
    cat("❌ Error in emergency dashboard metrics:", e$message, "\n")
    return(list(
      total_docs = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      date_range = "Error loading data"
    ))
  })
}

# ============================================================================
# 2. EMERGENCY MAP DATA FIX
# ============================================================================

#' Emergency map data using unified documents view
#' This replaces the broken get_map1_data() function
get_emergency_map1_data <- function() {
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Use unified documents view with proper state mapping
    result <- dbGetQuery(conn, "
      SELECT 
        COALESCE(estado, 'BR') as jurisdicao,
        COUNT(*) as count
      FROM documents 
      GROUP BY estado
      ORDER BY count DESC
    ")
    
    if (nrow(result) == 0) {
      cat("⚠️ No map data found in documents view\n")
      return(data.frame())
    }
    
    # Map 'BR' to 'DF' for federal documents
    result$jurisdicao[result$jurisdicao == 'BR'] <- 'DF'
    
    cat("✅ Emergency map 1 data loaded:", nrow(result), "jurisdictions\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error in emergency map 1 data:", e$message, "\n")
    return(data.frame())
  })
}

#' Emergency map data for legislation
#' This replaces the broken get_map2_data() function
get_emergency_map2_data <- function() {
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Use unified documents view for legislation
    result <- dbGetQuery(conn, "
      SELECT 
        COALESCE(estado, 'BR') as estado,
        'geral' as modal,
        COUNT(*) as count
      FROM documents 
      WHERE tipo IN ('lei', 'decreto', 'portaria', 'resolucao')
      GROUP BY estado
      ORDER BY count DESC
    ")
    
    if (nrow(result) == 0) {
      cat("⚠️ No legislation data found in documents view\n")
      return(data.frame())
    }
    
    # Map 'BR' to 'DF' for federal documents
    result$estado[result$estado == 'BR'] <- 'DF'
    
    cat("✅ Emergency map 2 data loaded:", nrow(result), "states\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error in emergency map 2 data:", e$message, "\n")
    return(data.frame())
  })
}

#' Emergency map data for jurisprudence
#' This replaces the broken get_map3_data() function
get_emergency_map3_data <- function() {
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Use unified documents view for jurisprudence
    result <- dbGetQuery(conn, "
      SELECT 
        COALESCE(estado, 'BR') as estado,
        'geral' as modal,
        COUNT(*) as count
      FROM documents 
      WHERE tipo IN ('jurisprudencia', 'acordao', 'sentenca')
      GROUP BY estado
      ORDER BY count DESC
    ")
    
    if (nrow(result) == 0) {
      cat("⚠️ No jurisprudence data found in documents view\n")
      return(data.frame())
    }
    
    # Map 'BR' to 'DF' for federal documents
    result$estado[result$estado == 'BR'] <- 'DF'
    
    cat("✅ Emergency map 3 data loaded:", nrow(result), "states\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error in emergency map 3 data:", e$message, "\n")
    return(data.frame())
  })
}

# ============================================================================
# 3. EMERGENCY VALUE BOX FIXES
# ============================================================================

#' Emergency document count value box
get_emergency_document_count <- function() {
  metrics <- get_emergency_dashboard_metrics()
  return(metrics$total_docs)
}

#' Emergency states count value box
get_emergency_states_count <- function() {
  metrics <- get_emergency_dashboard_metrics()
  return(metrics$states_with_docs)
}

#' Emergency municipalities count value box
get_emergency_municipalities_count <- function() {
  metrics <- get_emergency_dashboard_metrics()
  return(metrics$municipalities_with_docs)
}

#' Emergency date range value box
get_emergency_date_range <- function() {
  metrics <- get_emergency_dashboard_metrics()
  return(metrics$date_range)
}

# ============================================================================
# 4. EMERGENCY MAP RENDERING FIXES
# ============================================================================

#' Emergency total documents map
create_emergency_total_map <- function() {
  tryCatch({
    map_data <- get_emergency_map1_data()
    
    if (nrow(map_data) == 0) {
      cat("⚠️ No map data available, showing fallback map\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
        addMarker(lng = -47.86, lat = -15.83, 
                 popup = "No geographic data available - Using emergency fallback"))
    }
    
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

# ============================================================================
# 5. OVERRIDE BROKEN FUNCTIONS
# ============================================================================

# Override the broken functions with emergency versions
assign("get_lexml_dashboard_metrics", get_emergency_dashboard_metrics, envir = .GlobalEnv)
assign("get_map1_data", get_emergency_map1_data, envir = .GlobalEnv)
assign("get_map2_data", get_emergency_map2_data, envir = .GlobalEnv)
assign("get_map3_data", get_emergency_map3_data, envir = .GlobalEnv)
assign("create_emergency_total_map", create_emergency_total_map, envir = .GlobalEnv)

cat("✅ Emergency dashboard fix loaded\n")
cat("📊 Functions overridden:\n")
cat("  - get_lexml_dashboard_metrics() → get_emergency_dashboard_metrics()\n")
cat("  - get_map1_data() → get_emergency_map1_data()\n")
cat("  - get_map2_data() → get_emergency_map2_data()\n")
cat("  - get_map3_data() → get_emergency_map3_data()\n")
cat("\n")
cat("🚨 This is an emergency rollback to the working unified documents view\n")
cat("📝 The dashboard should now show actual data instead of zeros\n") 