# Maps Module Loader
# This file handles loading of map modules with proper fallbacks

# Function to find correct module path in deployment
find_module_path <- function(module_file) {
  # Get current working directory
  current_dir <- getwd()
  
  # Since Dockerfile copies modules to WORKDIR/modules, 
  # the files should be directly accessible from current directory
  direct_path <- file.path("modules", "maps", module_file)
  if (file.exists(direct_path)) {
    cat("✅ Found module at:", direct_path, "\n")
    return(direct_path)
  }
  
  # Fallback to absolute path from current directory
  abs_path <- file.path(current_dir, "modules", "maps", module_file)
  if (file.exists(abs_path)) {
    cat("✅ Found module at:", abs_path, "\n")
    return(abs_path)
  }
  
  # Common deployment paths as additional fallbacks
  possible_roots <- c(
    "/srv/shiny-server",
    "/app",
    dirname(current_dir)
  )
  
  # Try each root with modules/maps subdirectory
  for (root in possible_roots) {
    full_path <- file.path(root, "modules", "maps", module_file)
    if (file.exists(full_path)) {
      cat("✅ Found module at:", full_path, "\n")
      return(full_path)
    }
  }
  
  # Also try direct path from current directory
  direct_path <- file.path("modules", "maps", module_file)
  if (file.exists(direct_path)) {
    cat("✅ Found module at:", direct_path, "\n")
    return(direct_path)
  }
  
  cat("❌ Could not find module:", module_file, "\n")
  cat("   Searched in:", paste(possible_roots, collapse = ", "), "\n")
  return(NULL)
}

# Load path fix first
path_fix_loaded <- FALSE
path_fix_path <- find_module_path("railway_path_fix.R")
if (!is.null(path_fix_path)) {
  tryCatch({
    source(path_fix_path, local = FALSE)
    path_fix_loaded <- TRUE
    cat("✅ Path fix loaded successfully\n")
  }, error = function(e) {
    cat("⚠️ Could not load path fix:", e$message, "\n")
  })
}

# If path fix not loaded, define safe_source inline
if (!path_fix_loaded || !exists("safe_source")) {
  safe_source <- function(file_path, local = FALSE) {
    # First try the provided path
    if (file.exists(file_path)) {
      source(file_path, local = local)
      return(TRUE)
    }
    
    # Try to find it using find_module_path
    if (grepl("modules/maps/", file_path)) {
      module_name <- basename(file_path)
      full_path <- find_module_path(module_name)
      if (!is.null(full_path)) {
        source(full_path, local = local)
        return(TRUE)
      }
    }
    
    return(FALSE)
  }
  assign("safe_source", safe_source, envir = .GlobalEnv)
  assign("find_module_path", find_module_path, envir = .GlobalEnv)
}

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
  # Use find_module_path to locate the files
  ui_path <- find_module_path("map_ui.R")
  server_path <- find_module_path("map_server.R")
  
  ui_loaded <- FALSE
  server_loaded <- FALSE
  
  if (!is.null(ui_path)) {
    tryCatch({
      source(ui_path, local = FALSE)
      ui_loaded <- TRUE
      cat("✅ Map UI loaded from:", ui_path, "\n")
    }, error = function(e) {
      cat("❌ Error loading map UI:", e$message, "\n")
    })
  }
  
  if (!is.null(server_path)) {
    tryCatch({
      source(server_path, local = FALSE)
      server_loaded <- TRUE
      cat("✅ Map Server loaded from:", server_path, "\n")
    }, error = function(e) {
      cat("❌ Error loading map server:", e$message, "\n")
    })
  }
  
  ui_loaded && server_loaded
  
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
    # Load data and fixes first using simplified path
    data_loaded <- FALSE
    fix_loaded <- FALSE
    simple_loaded <- FALSE
    
    # Try to load brazil_states.R (should be in data/ from WORKDIR)
    data_paths <- c(
      file.path("data", "brazil_states.R"),
      file.path(getwd(), "data", "brazil_states.R"),
      file.path("/srv/shiny-server", "data", "brazil_states.R")
    )
    for (data_path in data_paths) {
      if (file.exists(data_path)) {
        source(data_path, local = FALSE)
        data_loaded <- TRUE
        cat("✅ Brazil states data loaded from:", data_path, "\n")
        break
      }
    }
    
    # Try to load map_data_fix.R (should be in fixes/active/ from WORKDIR)
    fix_paths <- c(
      file.path("fixes", "active", "map_data_fix.R"),
      file.path(getwd(), "fixes", "active", "map_data_fix.R"),
      file.path("/srv/shiny-server", "fixes", "active", "map_data_fix.R")
    )
    for (fix_path in fix_paths) {
      if (file.exists(fix_path)) {
        source(fix_path, local = FALSE)
        fix_loaded <- TRUE
        cat("✅ Map data fix loaded from:", fix_path, "\n")
        break
      }
    }
    
    # Load simple integration using find_module_path
    simple_path <- find_module_path("simple_map_integration.R")
    if (!is.null(simple_path)) {
      source(simple_path, local = FALSE)
      simple_loaded <- TRUE
      cat("✅ Simple map integration loaded from:", simple_path, "\n")
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
    # Use find_module_path for inline fallback
    inline_path <- find_module_path("inline_maps_fallback.R")
    if (!is.null(inline_path)) {
      source(inline_path, local = FALSE)
      cat("✅ Inline maps fallback loaded from:", inline_path, "\n")
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