#!/bin/bash
set -e

echo "🚀 Starting R Shiny server..."
echo "Host: 0.0.0.0"
PORT_NUMBER=${PORT:-3838}
echo "Port: ${PORT_NUMBER}"
echo "App: /app/app.R"

# Start R Shiny in foreground
exec R -e "
  cat('Loading Shiny...\n');
  library(shiny);
  cat('Starting Shiny app on port ${PORT_NUMBER}...\n');
  port <- as.numeric(Sys.getenv('PORT', '${PORT_NUMBER}'));
  shiny::runApp('/app/app.R', host='0.0.0.0', port = port, launch.browser = FALSE);
  cat('Shiny started.\n');
  Sys.sleep(Inf)
"