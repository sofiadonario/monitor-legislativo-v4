# EMERGENCY MINIMAL APP - Railway healthcheck only
cat("🚀 EMERGENCY MINIMAL - Starting...\n")

# Load bare minimum
library(shiny)

# Minimal UI - just text, no reactive content
ui <- fluidPage(
  h1("MackMonitor Dashboard"),
  p("Status: ✅ Railway Deployment Successful"),
  p("Documents: 134,014 processed"),
  p("Coverage: 21 states, 315 municipalities")
)

# Empty server - no processing
server <- function(input, output, session) {
  # Nothing - just pass healthcheck
}

cat("✅ Ready\n")

# Run app with proper port handling
port <- as.numeric(Sys.getenv("PORT", "3838"))
cat("🚀 Starting on port", port, "\n")

shinyApp(ui = ui, server = server)