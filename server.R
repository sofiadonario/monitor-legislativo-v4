# Server Logic - Monitor Legislativo v4
# ======================================
# v60: Minimal server with all modules disabled (matches v59 UI)

# DISABLED FOR v60 TESTING: Load server modules
# source("R/modules/search_module.R", local = FALSE)
# source("R/modules/geographic_module.R", local = FALSE)
# source("R/modules/citation_module.R", local = FALSE)
# source("R/modules/export_module.R", local = FALSE)
# source("R/modules/admin_module.R", local = FALSE)

#' Main Server Function - Monitor Legislativo v4
#'
#' v60: Minimal server with all modules disabled for binary search debugging
#'
#' @param input Shiny input object
#' @param output Shiny output object
#' @param session Shiny session object
server <- function(input, output, session) {

  cat("✅ Server function initialized (v60 - debug mode with no modules)\n")

  # Minimal server - no outputs, no reactives, no modules
  # Just a placeholder to prevent errors

  output$debug_message <- renderText({
    "v60: Server running with all modules disabled"
  })

}

cat("✅ Server definition loaded successfully (v60 - debug mode)\n")
