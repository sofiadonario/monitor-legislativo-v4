# Test script to verify map functionality
library(leaflet)
library(dplyr)

# Source the map generator
source("R/map_generator.R")

# Test the map generation
test_data <- data.frame(
  estado = c("SP", "RJ", "MG", "RS", "PR"),
  count = c(150, 120, 100, 80, 60)
)

# Generate test map
test_map <- generate_document_map(test_data)

# Check if it's a leaflet object
cat("Map object class:", class(test_map), "\n")
cat("Test completed successfully!\n")