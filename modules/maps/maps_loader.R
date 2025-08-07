# Maps Module Loader
# This file handles loading of map modules with proper fallbacks

# Initialize flags in global environment
assign("MAP_MODULE_STATUS", list(
  module_loaded = FALSE,
  simple_loaded = FALSE,
  error_messages = character()
), envir = .GlobalEnv)

# Try to load main modules
map_module_result <- tryCatch({
  source("modules/maps/map_ui.R", local = FALSE)
  source("modules/maps/map_server.R", local = FALSE)
  
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
    if (file.exists("data/brazil_states.R")) {
      source("data/brazil_states.R", local = FALSE)
    }
    if (file.exists("fixes/active/map_data_fix.R")) {
      source("fixes/active/map_data_fix.R", local = FALSE)
    }
    
    # Load simple integration
    source("modules/maps/simple_map_integration.R", local = FALSE)
    
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