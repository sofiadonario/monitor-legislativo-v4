#!/usr/bin/env Rscript

library(shiny)

port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

message("Starting minimal R Shiny app on ", host, ":", port)

options(shiny.http.response.filter = function(req, res) {
  if (req$PATH_INFO == "/health") {
    res$status <- 200
    res$headers[["Content-Type"]] <- "text/plain"
    res$body <- "OK"
    return(res)
  }
  return(res)
})

runApp("app-minimal.R", host = host, port = port, launch.browser = FALSE)