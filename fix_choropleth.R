#!/usr/bin/env Rscript
# Fix for Choropleth Map Visualization Issues
# ============================================

cat("====================================\n")
cat("FIXING CHOROPLETH MAP VISUALIZATION\n")
cat("====================================\n")

# Load required packages
suppressPackageStartupMessages({
  library(sf)
  library(geobr)
  library(jsonlite)
  library(plotly)
})

# Create directory for geographic data
dir.create("data/geo", recursive = TRUE, showWarnings = FALSE)

cat("\n📍 Downloading Brazilian state boundaries...\n")

# Download official Brazilian state boundaries
brazil_states <- tryCatch({
  geobr::read_state(year = 2020, simplified = TRUE)
}, error = function(e) {
  cat("⚠️ Failed to download from geobr:", e$message, "\n")
  cat("   Creating fallback boundaries...\n")
  NULL
})

if (!is.null(brazil_states)) {
  cat("✅ Downloaded boundaries for", nrow(brazil_states), "states\n")
  
  # Convert to GeoJSON
  cat("\n🗺️ Converting to GeoJSON format...\n")
  
  # Simplify geometry for performance
  brazil_states_simple <- st_simplify(brazil_states, dTolerance = 0.01)
  
  # Create properties for plotly
  brazil_states_simple$properties <- lapply(seq_len(nrow(brazil_states_simple)), function(i) {
    list(
      state_code = brazil_states_simple$abbrev_state[i],
      state_name = brazil_states_simple$name_state[i],
      region = brazil_states_simple$name_region[i]
    )
  })
  
  # Convert to GeoJSON
  brazil_geojson <- geojson_json(brazil_states_simple)
  
  # Save to file
  write(brazil_geojson, "data/geo/brazil_states.geojson")
  cat("✅ Saved GeoJSON to data/geo/brazil_states.geojson\n")
  
  # Also create a simplified R object for direct use
  brazil_geo_data <- list(
    type = "FeatureCollection",
    features = lapply(seq_len(nrow(brazil_states_simple)), function(i) {
      list(
        type = "Feature",
        properties = list(
          state_code = brazil_states_simple$abbrev_state[i],
          state_name = brazil_states_simple$name_state[i]
        ),
        geometry = st_as_text(brazil_states_simple$geom[i])
      )
    })
  )
  
  saveRDS(brazil_geo_data, "data/geo/brazil_states.rds")
  cat("✅ Saved R object to data/geo/brazil_states.rds\n")
  
} else {
  cat("\n⚠️ Creating manual fallback boundaries...\n")
  
  # Create simplified boundaries manually
  # Brazilian states with approximate center coordinates
  states_data <- data.frame(
    state_code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                   "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
                   "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    state_name = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
                   "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
                   "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
                   "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro",
                   "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", "Roraima",
                   "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
    lat = c(-9.0, -9.7, 1.4, -3.4, -12.5, -5.5, -15.8, -19.2, -15.9, -4.3,
            -12.6, -20.5, -18.5, -5.5, -7.2, -24.9, -8.3, -7.9, -22.3, -5.8,
            -30.0, -11.5, 2.8, -27.3, -22.3, -10.6, -10.2),
    lon = c(-70.5, -35.7, -51.8, -65.9, -41.7, -39.3, -47.9, -40.3, -49.3, -44.3,
            -56.1, -54.6, -44.6, -52.3, -35.0, -51.5, -35.0, -42.8, -42.6, -35.2,
            -51.2, -62.8, -60.7, -48.6, -46.6, -37.1, -48.0),
    stringsAsFactors = FALSE
  )
  
  # Save as simple CSV for fallback
  write.csv(states_data, "data/geo/brazil_states_centers.csv", row.names = FALSE)
  cat("✅ Created fallback state centers\n")
}

# Create enhanced choropleth function that handles the closure error
cat("\n🔧 Creating enhanced choropleth function...\n")

enhanced_choropleth <- '
# Enhanced Choropleth Function with Error Handling
create_safe_choropleth <- function(state_data, metric_column = "document_count", 
                                  title = "Brazilian Legislative Documents by State") {
  
  # Load required libraries
  if (!requireNamespace("plotly", quietly = TRUE)) {
    stop("plotly package required for choropleth maps")
  }
  
  # Try to load GeoJSON data
  geojson_data <- NULL
  if (file.exists("data/geo/brazil_states.geojson")) {
    tryCatch({
      geojson_data <- jsonlite::fromJSON("data/geo/brazil_states.geojson")
    }, error = function(e) {
      cat("Could not load GeoJSON:", e$message, "\\n")
    })
  }
  
  # If no GeoJSON, create heatmap fallback
  if (is.null(geojson_data) || !is.list(geojson_data)) {
    cat("Creating heatmap-style choropleth fallback\\n")
    
    # State positions for grid layout
    state_positions <- list(
      AC = c(1, 3), AL = c(9, 2), AP = c(6, 1), AM = c(3, 2), BA = c(8, 3),
      CE = c(9, 1), DF = c(6, 4), ES = c(8, 5), GO = c(6, 3), MA = c(7, 1),
      MT = c(5, 3), MS = c(5, 5), MG = c(7, 4), PA = c(5, 1), PB = c(10, 2),
      PR = c(6, 6), PE = c(10, 3), PI = c(8, 2), RJ = c(8, 6), RN = c(10, 1),
      RS = c(6, 7), RO = c(3, 3), RR = c(4, 1), SC = c(7, 6), SP = c(7, 5),
      SE = c(9, 4), TO = c(6, 2)
    )
    
    # Prepare plot data
    plot_data <- data.frame(
      state = character(),
      x = numeric(),
      y = numeric(),
      value = numeric(),
      text = character(),
      stringsAsFactors = FALSE
    )
    
    for (state in names(state_positions)) {
      pos <- state_positions[[state]]
      val <- state_data[state_data$state_code == state, metric_column]
      if (length(val) == 0) val <- 0
      
      plot_data <- rbind(plot_data, data.frame(
        state = state,
        x = pos[1],
        y = pos[2],
        value = as.numeric(val),
        text = paste0(state, ": ", format(val, big.mark = ","))
      ))
    }
    
    # Create heatmap-style plot
    p <- plot_ly(
      data = plot_data,
      x = ~x,
      y = ~y,
      z = ~value,
      text = ~text,
      type = "heatmap",
      colorscale = "Viridis",
      hovertemplate = "%{text}<extra></extra>",
      showscale = TRUE
    ) %>%
      layout(
        title = title,
        xaxis = list(visible = FALSE),
        yaxis = list(visible = FALSE),
        annotations = lapply(seq_len(nrow(plot_data)), function(i) {
          list(
            x = plot_data$x[i],
            y = plot_data$y[i],
            text = plot_data$state[i],
            showarrow = FALSE,
            font = list(color = "white", size = 12)
          )
        })
      )
    
    return(p)
  }
  
  # Create proper choropleth with GeoJSON
  p <- plot_ly() %>%
    add_trace(
      type = "choropleth",
      geojson = geojson_data,
      locations = state_data$state_code,
      z = state_data[[metric_column]],
      text = paste0(state_data$state_name, "<br>",
                   "Documents: ", format(state_data[[metric_column]], big.mark = ",")),
      hovertemplate = "%{text}<extra></extra>",
      colorscale = "Viridis",
      marker = list(line = list(width = 0.5, color = "white"))
    ) %>%
    layout(
      title = title,
      geo = list(
        scope = "south america",
        projection = list(type = "mercator"),
        center = list(lat = -15, lon = -55),
        showcountries = FALSE,
        showframe = FALSE
      )
    )
  
  return(p)
}
'

# Save the enhanced function
writeLines(enhanced_choropleth, "scripts/R/safe_choropleth.R")
cat("✅ Created enhanced choropleth function\n")

# Test the choropleth with sample data
cat("\n🧪 Testing choropleth with sample data...\n")

test_data <- data.frame(
  state_code = c("SP", "RJ", "MG", "BA", "RS", "PR", "PE", "CE"),
  state_name = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Bahia", 
                 "Rio Grande do Sul", "Paraná", "Pernambuco", "Ceará"),
  document_count = c(25000, 18000, 15000, 12000, 10000, 9000, 7500, 6000),
  stringsAsFactors = FALSE
)

# Source and test the function
source("scripts/R/safe_choropleth.R")

tryCatch({
  test_plot <- create_safe_choropleth(test_data)
  cat("✅ Choropleth function works correctly\n")
  
  # Save test plot
  htmlwidgets::saveWidget(test_plot, "test_choropleth.html")
  cat("✅ Test choropleth saved to test_choropleth.html\n")
}, error = function(e) {
  cat("⚠️ Choropleth test failed:", e$message, "\n")
})

cat("\n🎉 Choropleth fix complete!\n")
cat("====================================\n")
'

# Save the enhanced function
writeLines(enhanced_choropleth, "scripts/R/safe_choropleth.R")
cat("✅ Created enhanced choropleth function\n")

# Test the choropleth with sample data
cat("\n🧪 Testing choropleth with sample data...\n")

test_data <- data.frame(
  state_code = c("SP", "RJ", "MG", "BA", "RS", "PR", "PE", "CE"),
  state_name = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Bahia", 
                 "Rio Grande do Sul", "Paraná", "Pernambuco", "Ceará"),
  document_count = c(25000, 18000, 15000, 12000, 10000, 9000, 7500, 6000),
  stringsAsFactors = FALSE
)

# Source and test the function
source("scripts/R/safe_choropleth.R")

tryCatch({
  test_plot <- create_safe_choropleth(test_data)
  cat("✅ Choropleth function works correctly\n")
  
  # Save test plot
  htmlwidgets::saveWidget(test_plot, "test_choropleth.html")
  cat("✅ Test choropleth saved to test_choropleth.html\n")
}, error = function(e) {
  cat("⚠️ Choropleth test failed:", e$message, "\n")
})

cat("\n🎉 Choropleth fix complete!\n")
cat("====================================\n")