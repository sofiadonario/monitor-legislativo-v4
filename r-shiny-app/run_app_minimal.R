#!/usr/bin/env Rscript

library(shiny)

port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

message("Starting minimal R Shiny app on ", host, ":", port)

# Simple health check endpoint
addResourcePath("health", ".")

# Run the app
runApp("app-minimal.R", host = host, port = port, launch.browser = FALSE)