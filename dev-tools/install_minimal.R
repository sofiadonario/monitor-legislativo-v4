# Minimal R package installation for Monitor Legislativo v4
# Install only essential packages to get the app running quickly

cat("🚀 Installing minimal R packages for Shiny app\n\n")

# Set up user library
user_lib <- path.expand("~/R/library")
if (!dir.exists(user_lib)) {
  dir.create(user_lib, recursive = TRUE)
}
.libPaths(c(user_lib, .libPaths()))

# Set CRAN mirror
options(repos = c(CRAN = "https://cloud.r-project.org/"))

# Minimal essential packages only
minimal_packages <- c(
  "shiny",
  "httr", 
  "jsonlite"
)

cat("📦 Installing minimal packages:", paste(minimal_packages, collapse = ", "), "\n\n")

# Install packages one by one
for (pkg in minimal_packages) {
  cat("Installing", pkg, "...\n")
  tryCatch({
    install.packages(pkg, lib = user_lib, dependencies = FALSE, quiet = TRUE)
    cat("✅", pkg, "installed successfully\n")
  }, error = function(e) {
    cat("❌ Failed to install", pkg, ":", e$message, "\n")
  })
}

# Test if packages load
cat("\n🧪 Testing package loading...\n")
success <- TRUE

for (pkg in minimal_packages) {
  tryCatch({
    library(pkg, character.only = TRUE, lib.loc = user_lib)
    cat("✅", pkg, "loads successfully\n")
  }, error = function(e) {
    cat("❌", pkg, "failed to load:", e$message, "\n")
    success <- FALSE
  })
}

if (success) {
  cat("\n🎉 Minimal R Shiny setup complete!\n")
  cat("📍 Packages installed in:", user_lib, "\n")
  cat("🚀 Ready to test basic Shiny app\n")
} else {
  cat("\n❌ Some packages failed to load\n")
}

# Create a simple test app
test_app <- '
library(shiny)

ui <- fluidPage(
  titlePanel("Monitor Legislativo v4 - Test"),
  h3("R Shiny Status: ONLINE"),
  p("This is a minimal test to verify R Shiny is working."),
  actionButton("test", "Test Button"),
  verbatimTextOutput("status")
)

server <- function(input, output) {
  output$status <- renderText({
    if (input$test > 0) {
      paste("Button clicked", input$test, "times at", Sys.time())
    } else {
      "Ready for testing"
    }
  })
}

shinyApp(ui = ui, server = server)
'

# Write test app
writeLines(test_app, "test_app.R")
cat("\n📄 Created test_app.R for basic testing\n")
cat("🧪 Run with: Rscript -e 'source(\"test_app.R\")'\n")