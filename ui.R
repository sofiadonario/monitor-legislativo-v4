# UI Definition - Monitor Legislativo v4
# ======================================
# v62: Fixed extent=0 error by removing $value from source() calls

# Load required packages
suppressPackageStartupMessages({
  library(shiny)
  library(bslib)
})

# Load UI modules (re-enabled after v60 debugging)
source("R/modules/search_module.R", local = FALSE)
source("R/modules/geographic_module.R", local = FALSE)
source("R/modules/citation_module.R", local = FALSE)
source("R/modules/export_module.R", local = FALSE)
source("R/modules/admin_module.R", local = FALSE)

#' Main UI Function - Monitor Legislativo v4
#'
#' v62: Fixed source() calls to work properly with bslib nav_panel()
#'
#' @param request Shiny HTTP request object
#' @return Complete Shiny UI
ui <- function(request) {

  # Load tab contents OUTSIDE of page_navbar to avoid extent=0 error
  exec_tab <- source("R/ui/executive_tab.R", local = TRUE)$value
  library_tab <- source("R/ui/library_tab.R", local = TRUE)$value
  analytics_tab <- source("R/ui/analytics_tab.R", local = TRUE)$value
  saopaulo_tab <- source("R/ui/saopaulo_tab.R", local = TRUE)$value
  nlp_tab <- source("R/ui/nlp_tab.R", local = TRUE)$value

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
      danger = "#e74c3c",
      base_font = font_google("Roboto"),
      heading_font = font_google("Roboto Slab")
    ),

    # Executive Summary Tab
    nav_panel(
      title = "Executive Summary",
      icon = icon("chart-line"),
      exec_tab
    ),

    # Library Tab
    nav_panel(
      title = "Library",
      icon = icon("book"),
      library_tab
    ),

    # Analytics Tab
    nav_panel(
      title = "Analytics",
      icon = icon("chart-bar"),
      analytics_tab
    ),

    # São Paulo Tab
    nav_panel(
      title = "São Paulo",
      icon = icon("map-marked-alt"),
      saopaulo_tab
    ),

    # NLP Tab
    nav_panel(
      title = "Text Mining",
      icon = icon("brain"),
      nlp_tab
    ),

    # Custom CSS for polish
    tags$head(
      tags$style(HTML("
        .navbar-brand {
          font-weight: 700;
          font-size: 1.5rem;
        }

        .card-header {
          background-color: #f8f9fa;
          border-bottom: 2px solid #dee2e6;
        }

        .value-box {
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          transition: transform 0.2s;
        }

        .value-box:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
      "))
    )
  )
}

cat("✅ UI definition loaded successfully (v62 - extent=0 fix)\n")
