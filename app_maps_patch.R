# App Maps Patch - Replace problematic map implementations with working versions

# Load the comprehensive fix
source("fix_maps_and_geographic_data.R")

# ============================================================================
# PATCH MAP OUTPUT FUNCTIONS
# ============================================================================

# Replace the problematic totalDocumentsMap output
output$totalDocumentsMap <- renderLeaflet({
  cat("🔄 Creating total documents map with working function\n")
  create_total_documents_map()
})

# Replace the problematic legislationMap output  
output$legislationMap <- renderLeaflet({
  cat("🔄 Creating legislation map with working function\n")
  create_legislation_map()
})

# Replace the problematic jurisprudenceMap output
output$jurisprudenceMap <- renderLeaflet({
  cat("🔄 Creating jurisprudence map with working function\n")
  create_jurisprudence_map()
})

# ============================================================================
# PATCH STATE AND MUNICIPALITY COUNTS
# ============================================================================

# Replace state count with working function
output$stateCount <- renderValueBox({
  state_dist <- get_state_distribution()
  count <- ifelse(nrow(state_dist) > 0, nrow(state_dist), 0)
  
  valueBox(
    value = count,
    subtitle = "States with Documents",
    icon = icon("map-marker"),
    color = "blue"
  )
})

# Replace municipality count with working function
output$municipalityCount <- renderValueBox({
  mun_dist <- get_municipality_distribution()
  count <- ifelse(nrow(mun_dist) > 0, nrow(mun_dist), 0)
  
  valueBox(
    value = count,
    subtitle = "Municipalities with Documents", 
    icon = icon("building"),
    color = "green"
  )
})

# ============================================================================
# PATCH STATE DISTRIBUTION CHART
# ============================================================================

# Replace state distribution chart
output$stateDistribution <- renderPlotly({
  state_dist <- get_state_distribution()
  
  if (nrow(state_dist) == 0) {
    # Return empty plot with message
    plot_ly() %>%
      add_annotations(
        text = "No state data available",
        xref = "paper", yref = "paper",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 16)
      ) %>%
      layout(
        title = "State Distribution",
        xaxis = list(showgrid = FALSE, showticklabels = FALSE),
        yaxis = list(showgrid = FALSE, showticklabels = FALSE)
      )
  } else {
    # Create bar chart of top states
    top_states <- head(state_dist, 10)
    
    plot_ly(top_states, x = ~estado, y = ~count, type = 'bar') %>%
      layout(
        title = "Documents by State (Top 10)",
        xaxis = list(title = "State"),
        yaxis = list(title = "Document Count"),
        showlegend = FALSE
      )
  }
})

# ============================================================================
# PATCH MUNICIPALITY DISTRIBUTION CHART
# ============================================================================

# Replace municipality distribution chart
output$municipalityDistribution <- renderPlotly({
  mun_dist <- get_municipality_distribution()
  
  if (nrow(mun_dist) == 0) {
    # Return empty plot with message
    plot_ly() %>%
      add_annotations(
        text = "No municipality data available",
        xref = "paper", yref = "paper",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 16)
      ) %>%
      layout(
        title = "Municipality Distribution",
        xaxis = list(showgrid = FALSE, showticklabels = FALSE),
        yaxis = list(showgrid = FALSE, showticklabels = FALSE)
      )
  } else {
    # Create bar chart of top municipalities
    plot_ly(mun_dist, x = ~municipality, y = ~count, type = 'bar') %>%
      layout(
        title = "Documents by Municipality (Top 20)",
        xaxis = list(title = "Municipality"),
        yaxis = list(title = "Document Count"),
        showlegend = FALSE
      )
  }
})

# ============================================================================
# PATCH DOCUMENT TYPE DISTRIBUTION
# ============================================================================

# Replace document type distribution with working function
output$documentTypeDistribution <- renderPlotly({
  if (!database_connected || is.null(db_pool)) {
    return(plot_ly() %>%
      add_annotations(
        text = "Database not connected",
        xref = "paper", yref = "paper",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 16)
      ) %>%
      layout(
        title = "Document Type Distribution",
        xaxis = list(showgrid = FALSE, showticklabels = FALSE),
        yaxis = list(showgrid = FALSE, showticklabels = FALSE)
      ))
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    result <- dbGetQuery(conn, "
      SELECT 
        categoria as type,
        COUNT(*) as count
      FROM documents 
      WHERE categoria IS NOT NULL AND categoria != ''
      GROUP BY categoria
      ORDER BY count DESC
    ")
    
    if (nrow(result) == 0) {
      return(plot_ly() %>%
        add_annotations(
          text = "No document type data available",
          xref = "paper", yref = "paper",
          x = 0.5, y = 0.5,
          showarrow = FALSE,
          font = list(size = 16)
        ) %>%
        layout(
          title = "Document Type Distribution",
          xaxis = list(showgrid = FALSE, showticklabels = FALSE),
          yaxis = list(showgrid = FALSE, showticklabels = FALSE)
        ))
    }
    
    # Create pie chart
    plot_ly(result, labels = ~type, values = ~count, type = 'pie') %>%
      layout(title = "Document Type Distribution")
    
  }, error = function(e) {
    cat("❌ Error creating document type distribution:", e$message, "\n")
    return(plot_ly() %>%
      add_annotations(
        text = paste("Error:", e$message),
        xref = "paper", yref = "paper",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 16)
      ) %>%
      layout(
        title = "Document Type Distribution",
        xaxis = list(showgrid = FALSE, showticklabels = FALSE),
        yaxis = list(showgrid = FALSE, showticklabels = FALSE)
      ))
  })
})

cat("✅ App maps patch loaded successfully\n")
cat("📊 Patched functions:\n")
cat("  - totalDocumentsMap\n")
cat("  - legislationMap\n") 
cat("  - jurisprudenceMap\n")
cat("  - stateCount\n")
cat("  - municipalityCount\n")
cat("  - stateDistribution\n")
cat("  - municipalityDistribution\n")
cat("  - documentTypeDistribution\n") 