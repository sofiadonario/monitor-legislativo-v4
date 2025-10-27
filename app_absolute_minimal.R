# ABSOLUTE MINIMAL TEST - v46
# No global.R, no modules, NOTHING but Shiny

library(shiny)

ui <- fluidPage(
  h1("Hello World v46")
)

server <- function(input, output, session) {
  # Empty
}

shinyApp(ui = ui, server = server)
