# Legislative Monitor R Environment Setup
# This file loads all required packages and sets up the environment

# Set CRAN mirror
options(repos = c(CRAN = "https://cloud.r-project.org/"))

# Required packages - install if not available
required_packages <- c(
  # Core Shiny
  "shiny",
  "shinydashboard",
  "shinyWidgets",
  "DT",
  
  # Data manipulation
  "dplyr",
  "tidyr",
  "purrr",
  "stringr",
  "lubridate",
  "jsonlite",
  
  # HTTP requests
  "httr",
  "curl",
  "rvest",
  
  # Database
  "DBI",
  "RSQLite",
  
  # Geographic data
  "sf",
  "geobr",
  "leaflet",
  "tmap",
  
  # Visualization
  "ggplot2",
  "plotly",
  "RColorBrewer",
  "viridis",
  
  # Export packages
  "openxlsx",
  "xml2",
  "htmltools",
  "knitr",
  "rmarkdown",
  
  # Configuration
  "yaml",
  "config",
  
  # Logging
  "futile.logger",
  
  # Authentication
  "digest",
  
  # Text processing
  "tm",
  "textclean"
)

# Function to install missing packages
install_if_missing <- function(packages) {
  new_packages <- packages[!(packages %in% installed.packages()[,"Package"])]
  if(length(new_packages)) {
    message("Installing missing packages: ", paste(new_packages, collapse = ", "))
    install.packages(new_packages, dependencies = TRUE)
  }
}

# Install missing packages
install_if_missing(required_packages)

# Load all packages
lapply(required_packages, library, character.only = TRUE)

# Set up logging
flog.appender(appender.file("data/app.log"))
flog.threshold(INFO)

# Load configuration
config <- yaml::read_yaml("config.yml")

# Set options
options(
  shiny.maxRequestSize = 30*1024^2,  # 30MB
  digits = 4,
  scipen = 999
)

# Environment variables
Sys.setenv(TZ = "America/Sao_Paulo")

message("Legislative Monitor R environment loaded successfully!")
message("Available APIs: ", length(config$apis$federal) + length(config$apis$states))
message("Geographic data year: ", config$geographic$geobr$year)