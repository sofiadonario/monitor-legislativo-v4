# UI Definition - Monitor Legislativo v4
# ======================================
# v85: BYPASS bslib page_navbar() - use base Shiny navbarPage() to avoid extent=0 error
# This replaces bslib::page_navbar() with shiny::navbarPage() which doesn't use C++ callbacks

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

  navbarPage(
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
    tabPanel(
      title = "Executive Summary",
      icon = icon("chart-line"),
      value = "executive",
      h2("Executive Summary"),
      p("This section is currently under development.")
    ),

    # Library Tab - Placeholder
    tabPanel(
      title = "Library",
      icon = icon("book"),
      value = "library",
      h2("Library"),
      p("This section is currently under development.")
    ),

    # Analytics Tab - Placeholder
    tabPanel(
      title = "Analytics",
      icon = icon("chart-bar"),
      value = "analytics",
      h2("Analytics"),
      p("This section is currently under development.")
    ),

    # São Paulo Tab - Placeholder
    tabPanel(
      title = "São Paulo",
      icon = icon("map-marked-alt"),
      value = "saopaulo",
      h2("São Paulo"),
      p("This section is currently under development.")
    ),

    # NLP Tab - Placeholder
    tabPanel(
      title = "Text Mining",
      icon = icon("brain"),
      value = "nlp",
      h2("Text Mining"),
      p("This section is currently under development.")
    )
  )
}

cat("✅ UI definition loaded successfully (v85 - shiny::navbarPage fix)\n")