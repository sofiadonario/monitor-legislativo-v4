#!/bin/bash
set -e

echo "🚀 Starting R Shiny server..."
echo "Host: 0.0.0.0"
echo "Port: 3838"
echo "App: /app/app.R"

# Start R Shiny in foreground
exec R -e "
  cat('Loading Shiny...\n');
  library(shiny);
  cat('Starting Shiny app...\n');
  runApp('/app/app.R', host='0.0.0.0', port=3838, launch.browser=FALSE);
  cat('Shiny started, keeping alive...\n');
  while(TRUE) {
    Sys.sleep(10);
    cat('.');
  }
"