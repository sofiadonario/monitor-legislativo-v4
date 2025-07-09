# Simple test without installing packages
# Just test if we can create a minimal health endpoint

cat("Testing basic R functionality...\n")

# Test basic R functions
cat("R version:", R.version.string, "\n")
cat("Available packages:", length(installed.packages()[,1]), "\n")

# Create a simple health check function
health_check <- function() {
  list(
    status = "healthy",
    timestamp = Sys.time(),
    version = "1.0.0",
    r_version = R.version.string
  )
}

# Test the function
result <- health_check()
cat("Health check result:\n")
cat("Status:", result$status, "\n")
cat("Timestamp:", as.character(result$timestamp), "\n")
cat("Version:", result$version, "\n")

# Create simple HTTP server function (without shiny dependency)
simple_server <- function(port = 3838) {
  cat("Would start server on port", port, "\n")
  cat("Health endpoint: /health\n")
  cat("Status: Ready\n")
}

simple_server()

cat("Basic R functionality test completed successfully!\n")