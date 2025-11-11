
# Enhanced Choropleth Function (Grid-based fallback)
create_safe_choropleth <- function(state_data, metric_column = "document_count", 
                                  title = "Brazilian Legislative Documents by State",
                                  colorscale = "Viridis") {
  
  # Load required libraries
  if (!requireNamespace("plotly", quietly = TRUE)) {
    stop("plotly package required for choropleth maps")
  }
  
  cat("🗺️ Creating grid-based choropleth map\n")
  
  # Load grid positions
  grid_data <- NULL
  if (file.exists("data/geo/brazil_states_grid.csv")) {
    grid_data <- read.csv("data/geo/brazil_states_grid.csv", stringsAsFactors = FALSE)
  } else {
    # Fallback grid positions
    grid_data <- data.frame(
      state_code = c("SP", "RJ", "MG", "BA", "RS", "PR", "PE", "CE", "GO", "MT"),
      state_name = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Bahia", 
                     "Rio Grande do Sul", "Paraná", "Pernambuco", "Ceará", "Goiás", "Mato Grosso"),
      x = c(7, 8, 7, 8, 6, 6, 9, 9, 6, 5),
      y = c(7, 8, 6, 5, 9, 8, 4, 3, 4, 4),
      stringsAsFactors = FALSE
    )
  }
  
  # Merge data with grid positions
  plot_data <- merge(grid_data, state_data, by = "state_code", all.x = TRUE)
  
  # Fill missing values with 0
  plot_data[[metric_column]][is.na(plot_data[[metric_column]])] <- 0
  
  # Create hover text
  plot_data$hover_text <- paste0(
    "<b>", plot_data$state_name, "</b><br>",
    "State: ", plot_data$state_code, "<br>",
    "Documents: ", format(plot_data[[metric_column]], big.mark = ","),
    "<extra></extra>"
  )
  
  # Create the plot
  p <- plot_ly(
    data = plot_data,
    x = ~x,
    y = ~y,
    z = ~get(metric_column),
    text = ~hover_text,
    type = "heatmap",
    colorscale = colorscale,
    hovertemplate = "%{text}",
    showscale = TRUE,
    colorbar = list(
      title = list(text = "Document Count", side = "right"),
      titleside = "right"
    )
  ) %>%
    layout(
      title = list(
        text = title,
        font = list(size = 16)
      ),
      xaxis = list(
        visible = FALSE,
        fixedrange = TRUE
      ),
      yaxis = list(
        visible = FALSE,
        fixedrange = TRUE
      ),
      # Add state code annotations
      annotations = lapply(seq_len(nrow(plot_data)), function(i) {
        list(
          x = plot_data$x[i],
          y = plot_data$y[i],
          text = plot_data$state_code[i],
          showarrow = FALSE,
          font = list(
            color = if(plot_data[[metric_column]][i] > max(plot_data[[metric_column]], na.rm = TRUE) * 0.6) "white" else "black",
            size = 10,
            family = "Arial, sans-serif"
          )
        )
      }),
      margin = list(l = 50, r = 100, t = 80, b = 50),
      plot_bgcolor = "rgba(0,0,0,0)",
      paper_bgcolor = "rgba(0,0,0,0)"
    ) %>%
    config(
      displayModeBar = TRUE,
      displaylogo = FALSE,
      modeBarButtonsToRemove = c("pan2d", "select2d", "lasso2d", "autoScale2d")
    )
  
  cat("✅ Grid choropleth created successfully\n")
  return(p)
}

# Alternative scatter-based choropleth for better performance
create_scatter_choropleth <- function(state_data, metric_column = "document_count", 
                                     title = "Legislative Documents by State") {
  
  cat("🔄 Creating scatter-based choropleth\n")
  
  # Load grid positions
  if (file.exists("data/geo/brazil_states_grid.csv")) {
    grid_data <- read.csv("data/geo/brazil_states_grid.csv", stringsAsFactors = FALSE)
  } else {
    stop("Grid data not available")
  }
  
  # Merge data
  plot_data <- merge(grid_data, state_data, by = "state_code", all.x = TRUE)
  plot_data[[metric_column]][is.na(plot_data[[metric_column]])] <- 0
  
  # Create color scale
  max_val <- max(plot_data[[metric_column]], na.rm = TRUE)
  min_val <- min(plot_data[[metric_column]], na.rm = TRUE)
  
  # Normalize values for color scaling
  plot_data$normalized_value <- (plot_data[[metric_column]] - min_val) / (max_val - min_val)
  
  # Create the scatter plot
  p <- plot_ly(
    data = plot_data,
    x = ~x,
    y = ~y,
    color = ~get(metric_column),
    colors = "Viridis",
    size = ~pmax(get(metric_column) / max(get(metric_column), na.rm = TRUE) * 100 + 20, 20),
    text = ~paste0("<b>", state_name, "</b><br>",
                   "Documents: ", format(get(metric_column), big.mark = ",")),
    hovertemplate = "%{text}<extra></extra>",
    type = "scatter",
    mode = "markers+text",
    textposition = "middle center",
    textfont = list(color = "white", size = 8),
    marker = list(
      opacity = 0.8,
      line = list(width = 1, color = "white")
    )
  ) %>%
    add_text(
      x = ~x,
      y = ~y,
      text = ~state_code,
      textfont = list(color = "white", size = 10),
      showlegend = FALSE
    ) %>%
    layout(
      title = title,
      xaxis = list(visible = FALSE),
      yaxis = list(visible = FALSE),
      showlegend = FALSE,
      margin = list(l = 50, r = 50, t = 80, b = 50)
    )
  
  return(p)
}

