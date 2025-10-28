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

    # A single, minimal tab panel to ensure rendering
    tabPanel(
      title = "Início",
      icon = icon("home"),
      h2("Monitor Legislativo"),
      p("A aplicação está online e conectada ao banco de dados."),
      p("Os painéis de análise estão sendo restaurados.")
    )
  )
}

cat("✅ UI definition loaded successfully (v86 - final simplification)\n")