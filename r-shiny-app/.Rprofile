# Academic Legislative Monitor - R Environment Setup
# This file automatically configures the R environment

# Set CRAN repository
options(
  repos = c(CRAN = "https://cloud.r-project.org/"),
  timeout = 300,
  scipen = 999,
  shiny.maxRequestSize = 50*1024^2  # 50MB upload limit
)

# Function to install missing packages
install_if_missing <- function(packages) {
  # Load utils package first to get installed.packages function
  if (!requireNamespace("utils", quietly = TRUE)) {
    return()
  }
  
  installed_pkgs <- utils::installed.packages()[,"Package"]
  missing_packages <- packages[!packages %in% installed_pkgs]
  
  if (length(missing_packages) > 0) {
    message("Installing missing packages: ", paste(missing_packages, collapse = ", "))
    utils::install.packages(missing_packages, dependencies = TRUE)
  }
}

# Core Shiny packages
core_packages <- c(
  "shiny",
  "shinydashboard",
  "DT",
  "shinyjs",
  "shinyWidgets"
)

# Data manipulation packages
data_packages <- c(
  "dplyr",
  "tidyr",
  "stringr",
  "lubridate",
  "purrr",
  "textclean",
  "futile.logger"
)

# API and web packages
api_packages <- c(
  "httr",
  "jsonlite",
  "yaml",
  "curl"
)

# Geographic packages
geo_packages <- c(
  "sf",
  "geobr",
  "leaflet"
)

# Database packages
db_packages <- c(
  "DBI",
  "RSQLite"
)

# Authentication packages
auth_packages <- c(
  "digest"
)

# Export packages
export_packages <- c(
  "openxlsx",
  "xml2",
  "htmltools"
)

# Visualization packages
viz_packages <- c(
  "ggplot2",
  "viridis",
  "scales"
)

# Install all required packages
all_packages <- c(
  core_packages,
  data_packages,
  api_packages,
  geo_packages,
  db_packages,
  auth_packages,
  export_packages,
  viz_packages
)

message("\n=====================================")
message("Academic Legislative Monitor R Setup")
message("=====================================\n")

install_if_missing(all_packages)

# Load commonly used packages quietly
suppressPackageStartupMessages({
  library(shiny)
  library(shinydashboard)
  library(dplyr)
  library(DT)
})

message("\n✅ R environment configured successfully!")
message("📦 All required packages are available")
message("🚀 Ready to run the application\n")

