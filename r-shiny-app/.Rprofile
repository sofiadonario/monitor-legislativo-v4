# .Rprofile for Monitor Legislativo v4 R Shiny App
# Set CRAN mirror
options(repos = c(CRAN = "https://cloud.r-project.org/"))

# Install required packages
required_packages <- c(
  # Core Shiny
  "shiny",
  "shinydashboard",
  "DT",
  "shinyjs",
  "shinyWidgets",
  
  # Data manipulation
  "dplyr",
  "tidyr",
  "stringr",
  "lubridate",
  "purrr",
  
  # Web and APIs
  "httr",
  "jsonlite",
  "yaml",
  "curl",
  
  # Geographic data
  "sf",
  "leaflet",
  
  # Database
  "DBI",
  "RSQLite",
  
  # Authentication
  "digest",
  
  # Export
  "openxlsx",
  "xml2",
  "htmltools",
  
  # Visualization
  "ggplot2",
  "viridis",
  "scales",
  
  # Logging
  "futile.logger"
)

# Install packages if not already installed
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    install.packages(pkg, dependencies = TRUE)
  }
}