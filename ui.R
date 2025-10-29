# UI Definition - Monitor Legislativo v4
# ======================================
# v88: REMOVE bs_theme() completely to isolate C++ crash

# Load required packages
suppressPackageStartupMessages({
  library(shiny)
  # library(bslib) # bslib is no longer used for the main UI
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
    # THEME REMOVED - This is the final step to bypass the bslib C++ crash
    
    # A single, minimal tab panel to ensure rendering
    tabPanel(
      title = "Início",
      icon = icon("home"),
      h2("Monitor Legislativo"),
      p("A aplicação está online e conectada ao banco de dados."),
      p("Os painéis de análise estão sendo restaurados."),
      p("Versão v88 - Sem bs_theme()")
    )
  )
}

cat("✅ UI definition loaded successfully (v88 - no bs_theme)\n")