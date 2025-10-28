# UI Definition - Monitor Legislativo v4
# ======================================
# v82: RADICAL SIMPLIFICATION to guarantee app runs for presentation

# Load required packages
suppressPackageStartupMessages({
  library(shiny)
  library(bslib)
  library(plotly)
  library(leaflet)
  library(DT)
})

#' Main UI Function - Monitor Legislativo v4
#'
#' @param request Shiny HTTP request object
#' @return Complete Shiny UI
ui <- function(request) {

  page_navbar(
    title = "Monitor Legislativo v4",
    theme = bs_theme(
      version = 5,
      bg = "#ffffff",
      fg = "#2c3e50",
      primary = "#3498db",
      secondary = "#95a5a6",
      success = "#27ae60",
      info = "#3498db",
      warning = "#f39c12",
      danger = "#e74c3c"
    ),

    # Executive Summary Tab - Placeholder
    nav_panel(
      title = "Executive Summary",
      icon = icon("chart-line"),
      value = "executive",
      h2("Executive Summary"),
      p("This section is currently under development.")
    ),

    # Library Tab - Placeholder
    nav_panel(
      title = "Library",
      icon = icon("book"),
      value = "library",
      h2("Library"),
      p("This section is currently under development.")
    ),

    # Analytics Tab - Placeholder
    nav_panel(
      title = "Analytics",
      icon = icon("chart-bar"),
      value = "analytics",
      h2("Analytics"),
      p("This section is currently under development.")
    ),

    # São Paulo Tab - Placeholder
    nav_panel(
      title = "São Paulo",
      icon = icon("map-marked-alt"),
      value = "saopaulo",
      h2("São Paulo"),
      p("This section is currently under development.")
    ),

    # NLP Tab - Placeholder
    nav_panel(
      title = "Text Mining",
      icon = icon("brain"),
      value = "nlp",
      h2("Text Mining"),
      p("This section is currently under development.")
    )
  )
}

cat("✅ UI definition loaded successfully (v82 - simplified)\n")