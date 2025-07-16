# Server logic for species charts that should be added to app.R

# Documents by Species Chart
output$speciesChart <- renderPlotly({
  if (database_connected && !is.null(values$analytics_data)) {
    data <- values$analytics_data$documents_by_species
    
    if (nrow(data) > 0) {
      # Ensure data is properly formatted
      data$count <- as.numeric(data$count)
      data$species <- as.character(data$species)
      
      # Take top 10 species to avoid overcrowding
      data <- data %>% 
        arrange(desc(count)) %>% 
        head(10)
      
      # Create a horizontal bar chart for species
      p <- ggplot(data, aes(x = reorder(species, count), y = count, fill = gender)) +
        geom_bar(stat = "identity") +
        coord_flip() +
        theme_minimal() +
        labs(
          title = "Top 10 Document Species",
          x = "Species",
          y = "Count"
        ) +
        theme(
          plot.title = element_text(size = 14, face = "bold"),
          axis.title = element_text(size = 12),
          axis.text = element_text(size = 10),
          legend.position = "bottom"
        ) +
        scale_fill_manual(values = c("legislation" = "#e1001e", "jurisprudence" = "#17a2b8"))
      
      ggplotly(p, tooltip = c("x", "y", "fill"))
    } else {
      # Empty plot
      p <- ggplot() + 
        geom_text(aes(x = 0, y = 0, label = "No species data available"), size = 5) +
        theme_void()
      ggplotly(p)
    }
  } else {
    # Empty plot
    p <- ggplot() + 
      geom_text(aes(x = 0, y = 0, label = "Database not connected"), size = 5) +
      theme_void()
    ggplotly(p)
  }
})

# Gender vs Species Distribution Chart
output$genderSpeciesChart <- renderPlotly({
  if (database_connected && !is.null(values$analytics_data)) {
    data <- values$analytics_data$documents_by_gender_species
    
    if (nrow(data) > 0) {
      # Ensure data is properly formatted
      data$count <- as.numeric(data$count)
      data$species <- as.character(data$species)
      data$gender <- as.character(data$gender)
      
      # Create grouped bar chart showing species within each gender
      p <- ggplot(data, aes(x = species, y = count, fill = gender)) +
        geom_bar(stat = "identity", position = "dodge") +
        theme_minimal() +
        labs(
          title = "Documents by Gender and Species",
          x = "Species",
          y = "Count",
          fill = "Gender"
        ) +
        theme(
          plot.title = element_text(size = 14, face = "bold"),
          axis.title = element_text(size = 12),
          axis.text = element_text(size = 9),
          axis.text.x = element_text(angle = 45, hjust = 1),
          legend.position = "bottom"
        ) +
        scale_fill_manual(values = c("legislation" = "#e1001e", "jurisprudence" = "#17a2b8"))
      
      ggplotly(p, tooltip = c("x", "y", "fill"))
    } else {
      # Empty plot
      p <- ggplot() + 
        geom_text(aes(x = 0, y = 0, label = "No gender/species data available"), size = 5) +
        theme_void()
      ggplotly(p)
    }
  } else {
    # Empty plot
    p <- ggplot() + 
      geom_text(aes(x = 0, y = 0, label = "Database not connected"), size = 5) +
      theme_void()
    ggplotly(p)
  }
})