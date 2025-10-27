# UI Definition - Monitor Legislativo v4
# ======================================
# v59: Binary search - ALL modules and tabs disabled

# Load required packages (since we skip global_integrated.R)
suppressPackageStartupMessages({
  library(shiny)
  library(shinydashboard)
})

# DISABLED FOR v59 TESTING: Load UI utilities
# source("R/utils/ui_utils.R", local = FALSE)

# DISABLED FOR v59 TESTING: Load UI modules
# source("R/modules/search_module.R", local = FALSE)
# source("R/modules/geographic_module.R", local = FALSE)
# source("R/modules/citation_module.R", local = FALSE)
# source("R/modules/export_module.R", local = FALSE)
# source("R/modules/admin_module.R", local = FALSE)

#' Main UI Function - Monitor Legislativo v4
#'
#' v59: Minimal UI with all modules/tabs disabled for binary search debugging
#'
#' @param request Shiny HTTP request object
#' @return Complete Shiny UI
ui <- function(request) {
  dashboardPage(
    # Header
    dashboardHeader(
      title = "Monitor Legislativo v4 - Debug Mode",
      titleWidth = 400
    ),

    # Sidebar
    dashboardSidebar(
      width = 250,
      sidebarMenu(
        id = "main_menu",
        menuItem("Debug Info", tabName = "debug", icon = icon("bug"))
      )
    ),

    # Body
    dashboardBody(
      # Custom CSS
      tags$head(
        tags$style(HTML("
          .main-header .navbar {
            background-color: #2c3e50 !important;
          }
          .main-header .logo {
            background-color: #2c3e50 !important;
            color: white !important;
          }
        "))
      ),

      tabItems(
        # Debug Tab - Simple content
        tabItem(tabName = "debug",
          fluidRow(
            box(
              title = "v59 Debug Mode - Binary Search Active",
              status = "warning",
              solidHeader = TRUE,
              width = 12,
              h3("All modules and tabs disabled"),
              p("This version has ALL module loading and tab sourcing commented out."),
              p("If this works (HTTP 200), we know the error is in one of those files."),
              p("Current status: Testing baseline with no custom code loaded."),
              hr(),
              h4("What's loaded:"),
              tags$ul(
                tags$li("library(shiny)"),
                tags$li("library(shinydashboard)"),
                tags$li("Simple dashboard structure"),
                tags$li("This static HTML content")
              ),
              h4("What's NOT loaded:"),
              tags$ul(
                tags$li("R/utils/ui_utils.R"),
                tags$li("R/modules/*.R (all 5 modules)"),
                tags$li("R/ui/*.R (all 5 tab files)")
              )
            )
          )
        )
      )
    )
  )
}

cat("✅ UI definition loaded successfully (v59 - debug mode)\n")
