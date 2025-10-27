# Minimal global.R - ensures shinydashboard is available before app.R runs
# This file is auto-sourced by Shiny before app.R
# CRITICAL: Load jsonlite BEFORE shinydashboard to avoid validate() masking conflicts
library(jsonlite)
