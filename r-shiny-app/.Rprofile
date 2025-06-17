# Minimal R Profile for Deployment Troubleshooting
options(repos = c(CRAN = "https://cloud.r-project.org/"))

# Essential packages only
essential_packages <- c(
  "shiny",
  "shinydashboard", 
  "DT",
  "dplyr",
  "httr",
  "jsonlite",
  "leaflet",
  "digest"
)

# Install missing packages
new_packages <- essential_packages[!(essential_packages %in% installed.packages()[,"Package"])]
if(length(new_packages)) {
  install.packages(new_packages, dependencies = TRUE)
}

# Load packages quietly
suppressMessages({
  lapply(essential_packages, library, character.only = TRUE)
})

# Basic settings
options(shiny.maxRequestSize = 30*1024^2)

