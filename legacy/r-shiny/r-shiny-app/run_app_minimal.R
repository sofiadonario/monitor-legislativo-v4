#!/usr/bin/env Rscript

library(shiny)

# Use Railway's PORT environment variable
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

message("Starting R Shiny app on ", host, ":", port)

# Run the app
runApp("app.R", host = host, port = port, launch.browser = FALSE)