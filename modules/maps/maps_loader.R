# Maps Module Loader
# This file handles loading of map modules with proper fallbacks

# Load path fix first
tryCatch({
  source("modules/maps/railway_path_fix.R", local = FALSE)
}, error = function(e) {
  # If path fix not found, define safe_source inline
  safe_source <- function(file_path, local = FALSE) {
    if (file.exists(file_path)) {
      source(file_path, local = local)
      return(TRUE)
    }
    return(FALSE)
  }
  assign("safe_source", safe_source, envir = .GlobalEnv)
})

# Initialize flags in global environment
assign("MAP_MODULE_STATUS", list(
  module_loaded = FALSE,
  simple_loaded = FALSE,
  error_messages = character(),
  working_dir = getwd(),
  app_files = list.files(pattern = "\\.R$")
), envir = .GlobalEnv)

# Try to load main modules
map_module_result <- tryCatch({
  if (exists("safe_source")) {
    ui_loaded <- safe_source("modules/maps/map_ui.R", local = FALSE)
    server_loaded <- safe_source("modules/maps/map_server.R", local = FALSE)
    ui_loaded && server_loaded
  } else {
    source("modules/maps/map_ui.R", local = FALSE)
    source("modules/maps/map_server.R", local = FALSE)
    TRUE
  }
  
  # Check if functions exist
  if (exists("mapUI", mode = "function") && exists("mapServer", mode = "function")) {
    MAP_MODULE_STATUS$module_loaded <- TRUE
    cat("✅ Map modules loaded successfully\n")
    TRUE
  } else {
    MAP_MODULE_STATUS$error_messages <- c(MAP_MODULE_STATUS$error_messages, 
                                         "Module functions not defined after sourcing")
    FALSE
  }
}, error = function(e) {
  MAP_MODULE_STATUS$error_messages <- c(MAP_MODULE_STATUS$error_messages, 
                                       paste("Module loading error:", e$message))
  cat("⚠️ Map modules not available:", e$message, "\n")
  FALSE
})

# If modules failed, try simple integration
if (!map_module_result) {
  simple_result <- tryCatch({
    # Load data and fixes first
    if (exists("safe_source")) {
      safe_source("data/brazil_states.R", local = FALSE)
      safe_source("fixes/active/map_data_fix.R", local = FALSE)
      # Load simple integration
      simple_loaded <- safe_source("modules/maps/simple_map_integration.R", local = FALSE)
    } else {
      if (file.exists("data/brazil_states.R")) {
        source("data/brazil_states.R", local = FALSE)
      }
      if (file.exists("fixes/active/map_data_fix.R")) {
        source("fixes/active/map_data_fix.R", local = FALSE)
      }
      # Load simple integration
      source("modules/maps/simple_map_integration.R", local = FALSE)
      simple_loaded <- TRUE
    }
    
    # Check if function exists
    if (exists("create_maps_tab_ui", mode = "function")) {
      MAP_MODULE_STATUS$simple_loaded <- TRUE
      assign("SIMPLE_MAP_UI_AVAILABLE", TRUE, envir = .GlobalEnv)
      cat("✅ Simple map integration loaded as fallback\n")
      TRUE
    } else {
      MAP_MODULE_STATUS$error_messages <- c(MAP_MODULE_STATUS$error_messages, 
                                           "Simple UI function not defined after sourcing")
      FALSE
    }
  }, error = function(e) {
    MAP_MODULE_STATUS$error_messages <- c(MAP_MODULE_STATUS$error_messages, 
                                         paste("Simple integration error:", e$message))
    cat("❌ Simple map integration also failed:", e$message, "\n")
    FALSE
  })
}

# If both failed, try inline fallback
if (!MAP_MODULE_STATUS$module_loaded && !MAP_MODULE_STATUS$simple_loaded) {
  inline_result <- tryCatch({
    if (exists("safe_source")) {
      safe_source("modules/maps/inline_maps_fallback.R", local = FALSE)
    } else {
      # Define inline directly if can't load file
      create_inline_maps_ui <- function() {
        tabItem(
          tabName = "maps",
          fluidRow(
            box(
              title = "Interactive Maps (Fallback Mode)",
              status = "info",
              solidHeader = TRUE,
              width = 12,
              p("Maps module is running in fallback mode."),
              p("Working directory: ", getwd()),
              plotlyOutput("fallback_map_output", height = "400px")
            )
          )
        )
      }
      assign("create_inline_maps_ui", create_inline_maps_ui, envir = .GlobalEnv)
      assign("INLINE_MAPS_AVAILABLE", TRUE, envir = .GlobalEnv)
    }
    MAP_MODULE_STATUS$inline_loaded <- TRUE
    cat("✅ Inline maps fallback activated\n")
    TRUE
  }, error = function(e) {
    MAP_MODULE_STATUS$error_messages <- c(MAP_MODULE_STATUS$error_messages,
                                         paste("Inline fallback error:", e$message))
    FALSE
  })
}

# Final status report
cat("\n📊 Map Module Loading Status:\n")
cat("  Module loaded:", MAP_MODULE_STATUS$module_loaded, "\n")
cat("  Simple loaded:", MAP_MODULE_STATUS$simple_loaded, "\n")
cat("  mapUI exists:", exists("mapUI", mode = "function"), "\n")
cat("  mapServer exists:", exists("mapServer", mode = "function"), "\n")
cat("  create_maps_tab_ui exists:", exists("create_maps_tab_ui", mode = "function"), "\n")
cat("  SIMPLE_MAP_UI_AVAILABLE:", exists("SIMPLE_MAP_UI_AVAILABLE") && SIMPLE_MAP_UI_AVAILABLE, "\n")

if (length(MAP_MODULE_STATUS$error_messages) > 0) {
  cat("\n⚠️ Errors encountered:\n")
  for (msg in MAP_MODULE_STATUS$error_messages) {
    cat("  -", msg, "\n")
  }
}

cat("\n")