# Minimal UI with empty tabs to bypass extent=0 error
# This replaces the complex tab sourcing with simple placeholders

library(shiny)
library(shinydashboard)

ui <- function(request) {
  dashboardPage(
    dashboardHeader(title = "Monitor Legislativo v4"),
    dashboardSidebar(
      sidebarMenu(
        menuItem("Painel Executivo", tabName = "executive", icon = icon("chart-line"))
      )
    ),
    dashboardBody(
      tabItems(
        tabItem(tabName = "executive",
          fluidRow(
            box(
              title = "Monitor Legislativo v4",
              status = "primary",
              solidHeader = TRUE,
              width = 12,
              h3("Aplicacao em desenvolvimento"),
              p("O sistema esta sendo configurado. Por favor, aguarde.")
            )
          )
        )
      )
    )
  )
}

cat("UI loaded successfully\n")
