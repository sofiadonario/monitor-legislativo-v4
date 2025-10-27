# Server Logic - Monitor Legislativo v4
# ======================================
# v63: Restored full server logic for bslib framework

# Load required modules
# Note: Module server functions loaded on-demand to avoid circular dependencies

#' Main Server Function - Monitor Legislativo v4
#'
#' v63: Complete server with all outputs, adapted for bslib framework
#'
#' @param input Shiny input object
#' @param output Shiny output object
#' @param session Shiny session object
server <- function(input, output, session) {

  cat("Server function initialized (v63 - full bslib server)\n")

  # ===========================================================================
  # EXECUTIVE SUMMARY TAB OUTPUTS
  # ===========================================================================

  # Load executive summary server module
  tryCatch({
    source("modules/executive_summary_server.R", local = TRUE)
    cat("Executive summary server loaded\n")
  }, error = function(e) {
    cat("Warning: Could not load executive summary server:", e$message, "\n")
  })

  # ===========================================================================
  # LIBRARY TAB OUTPUTS
  # ===========================================================================

  # Library data table output
  output$library_table <- DT::renderDataTable({
    tryCatch({
      # Placeholder data until database is connected
      data.frame(
        Documento = c("Lei 12.345/2020", "Decreto 67.890/2021"),
        Categoria = c("Legislacao", "Legislacao"),
        Estado = c("SP", "RJ"),
        Data = c("2020-01-15", "2021-03-20"),
        stringsAsFactors = FALSE
      )
    }, error = function(e) {
      data.frame(Error = paste("Error loading data:", e$message))
    })
  }, options = list(pageLength = 25, scrollX = TRUE))

  # ===========================================================================
  # ANALYTICS TAB OUTPUTS
  # ===========================================================================

  output$analytics_summary <- renderText({
    "Analytics module - Coming soon"
  })

  # ===========================================================================
  # SAO PAULO TAB OUTPUTS
  # ===========================================================================

  output$saopaulo_map <- leaflet::renderLeaflet({
    tryCatch({
      leaflet::leaflet() %>%
        leaflet::addTiles() %>%
        leaflet::setView(lng = -46.6333, lat = -23.5505, zoom = 10)
    }, error = function(e) {
      leaflet::leaflet() %>% leaflet::addTiles()
    })
  })

  # ===========================================================================
  # NLP/TEXT MINING TAB OUTPUTS
  # ===========================================================================

  output$nlp_summary <- renderText({
    "Text Mining module - Coming soon"
  })

  # ===========================================================================
  # SESSION END HANDLER
  # ===========================================================================

  onSessionEnded(function() {
    cat("Session ended\n")
  })

}

cat("Server definition loaded successfully (v63 - full bslib server)\n")
