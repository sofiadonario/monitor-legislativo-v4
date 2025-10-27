# Minimal global.R - ensures required packages are loaded before app.R runs
# This file is auto-sourced by Shiny before app.R
# CRITICAL: Load jsonlite first to avoid validate() masking conflicts
library(jsonlite)
library(plotly)  # Required for plotlyOutput() in UI files
