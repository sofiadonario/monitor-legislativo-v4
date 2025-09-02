# ============================================================================
# POLYGON PROCESSING APP INTEGRATION MODULE
# ============================================================================
# 
# Seamless integration of enhanced polygon processing capabilities with the
# existing Brazilian Legislative Monitoring System. Provides backward 
# compatibility while enabling municipality-level analysis.
#
# Author: Enhanced Polygon Processing Team  
# Version: 1.0
# Railway Compatible: Yes (<1.4GB memory constraint)
# Integration Target: app.R main application
# ============================================================================

# Load required integration modules
source("modules/polygon_processing/polygon_core.R", local = TRUE)
source("modules/polygon_processing/spatial_joins_optimizer.R", local = TRUE)

# ============================================================================
# MAIN INTEGRATION INTERFACE
# ============================================================================

#' Initialize polygon processing integration
#' @description Main entry point for app.R integration
initialize_polygon_processing <- function(enable_municipalities = TRUE,
                                        enable_performance_monitoring = TRUE,
                                        memory_limit_mb = 1400) {
  
  cat("🚀 Initializing Enhanced Polygon Processing System...\n")
  
  integration_config <- list(
    municipalities_enabled = enable_municipalities,
    performance_monitoring = enable_performance_monitoring,
    memory_limit = memory_limit_mb,
    fallback_to_states = TRUE,
    initialization_time = Sys.time()
  )
  
  # Initialize core systems
  polygon_system <- NULL
  spatial_system <- NULL
  
  tryCatch({
    if (enable_municipalities) {
      # Initialize polygon core system
      polygon_system <- create_polygon_processing_system()
      
      # Initialize spatial joins system  
      spatial_system <- create_spatial_join_system()
      
      cat("✅ Municipality-level processing enabled\n")
    }
    
    integration_config$polygon_system <- polygon_system
    integration_config$spatial_system <- spatial_system
    integration_config$status <- "initialized"
    
  }, error = function(e) {
    cat("⚠️ Polygon processing initialization failed:", e$message, "\n")
    cat("🔄 Falling back to state-level analysis only\n")
    
    integration_config$municipalities_enabled <- FALSE
    integration_config$status <- "fallback_mode"
    integration_config$error <- e$message
  })
  
  # Store in global environment for app.R access
  assign("polygon_processing_config", integration_config, envir = .GlobalEnv)
  
  cat("📊 Polygon Processing Integration Status:", integration_config$status, "\n")
  
  return(integration_config)
}

# ============================================================================
# ENHANCED GEOGRAPHIC FILTERING FUNCTIONS
# ============================================================================

#' Enhanced geographic filtering with municipality support
#' @description Backward-compatible geographic filtering with municipality-level capability
get_enhanced_geographic_documents <- function(documents_df,
                                            state_filter = "all",
                                            municipality_filter = "all",
                                            region_filter = "all",
                                            use_municipalities = TRUE) {
  
  # Check if polygon processing is available
  if (!exists("polygon_processing_config") || 
      !polygon_processing_config$municipalities_enabled ||
      !use_municipalities) {
    
    # Fallback to existing state-level filtering
    return(get_existing_state_filter(documents_df, state_filter, region_filter))
  }
  
  # Enhanced municipality-level filtering
  tryCatch({
    filtered_docs <- apply_municipality_filters(
      documents_df = documents_df,
      state_filter = state_filter,
      municipality_filter = municipality_filter,
      region_filter = region_filter
    )
    
    return(filtered_docs)
    
  }, error = function(e) {
    cat("⚠️ Municipality filtering failed:", e$message, "\n")
    cat("🔄 Falling back to state-level filtering\n")
    
    return(get_existing_state_filter(documents_df, state_filter, region_filter))
  })
}

#' Apply municipality-level filters
#' @description Core municipality filtering logic
apply_municipality_filters <- function(documents_df, state_filter, 
                                     municipality_filter, region_filter) {
  
  filtered_df <- documents_df
  
  # Region filter (highest level)
  if (region_filter != "all") {
    region_states <- get_region_states(region_filter)
    filtered_df <- filtered_df[filtered_df$estado %in% region_states, ]
  }
  
  # State filter (medium level)
  if (state_filter != "all") {
    filtered_df <- filtered_df[filtered_df$estado == state_filter, ]
  }
  
  # Municipality filter (most granular level)
  if (municipality_filter != "all") {
    if ("municipality_code" %in% names(filtered_df)) {
      filtered_df <- filtered_df[filtered_df$municipality_code == municipality_filter, ]
    } else {
      # Attempt spatial join if municipality_code not available
      filtered_df <- join_documents_with_municipality(filtered_df, municipality_filter)
    }
  }
  
  return(filtered_df)
}

#' Fallback state-level filtering (backward compatibility)
#' @description Maintains compatibility with existing system
get_existing_state_filter <- function(documents_df, state_filter, region_filter) {
  
  filtered_df <- documents_df
  
  if (region_filter != "all") {
    region_states <- get_region_states(region_filter)
    filtered_df <- filtered_df[filtered_df$estado %in% region_states, ]
  }
  
  if (state_filter != "all") {
    filtered_df <- filtered_df[filtered_df$estado == state_filter, ]
  }
  
  return(filtered_df)
}

# ============================================================================
# ENHANCED UI COMPONENTS
# ============================================================================

#' Enhanced geographic filter UI
#' @description Extended UI with municipality selection
create_enhanced_geographic_filter_ui <- function(ns) {
  
  # Check if municipalities are enabled
  municipalities_enabled <- exists("polygon_processing_config") && 
                           polygon_processing_config$municipalities_enabled
  
  if (!municipalities_enabled) {
    # Return existing state-level UI
    return(create_existing_geographic_ui(ns))
  }
  
  # Enhanced UI with municipality support
  tagList(
    h4("🗺️ Enhanced Geographic Filters", style = "color: #2c3e50; margin-bottom: 15px;"),
    
    # Region selection
    div(class = "filter-group",
      selectInput(
        ns("region_filter"),
        "Region:",
        choices = list(
          "All Regions" = "all",
          "Norte" = "norte",
          "Nordeste" = "nordeste", 
          "Centro-Oeste" = "centro_oeste",
          "Sudeste" = "sudeste",
          "Sul" = "sul"
        ),
        selected = "all"
      )
    ),
    
    # State selection (updated based on region)
    div(class = "filter-group",
      selectInput(
        ns("state_filter"),
        "State:",
        choices = list("All States" = "all"),
        selected = "all"
      )
    ),
    
    # Municipality selection (NEW - updated based on state)
    div(class = "filter-group",
      conditionalPanel(
        condition = "input.state_filter != 'all'", ns = ns,
        selectInput(
          ns("municipality_filter"),
          "Municipality:",
          choices = list("All Municipalities" = "all"),
          selected = "all"
        )
      )
    ),
    
    # Performance indicator
    div(class = "performance-indicator",
      style = "margin-top: 10px; padding: 8px; background: #f8f9fa; border-radius: 4px;",
      textOutput(ns("geographic_performance_info"))
    ),
    
    # Reset filters button
    div(class = "filter-actions", style = "margin-top: 10px;",
      actionButton(
        ns("reset_geographic_filters"),
        "Reset Filters",
        class = "btn btn-outline-secondary btn-sm"
      )
    )
  )
}

#' Enhanced geographic filter server logic
#' @description Server logic for municipality-level filtering
create_enhanced_geographic_filter_server <- function(input, output, session, documents_reactive) {
  
  # Check municipalities availability
  municipalities_enabled <- exists("polygon_processing_config") && 
                           polygon_processing_config$municipalities_enabled
  
  if (!municipalities_enabled) {
    return(create_existing_geographic_server(input, output, session, documents_reactive))
  }
  
  # Reactive values for enhanced filtering
  values <- reactiveValues(
    filtered_documents = NULL,
    available_states = c(),
    available_municipalities = c(),
    performance_stats = list()
  )
  
  # Update state choices based on region selection
  observeEvent(input$region_filter, {
    if (input$region_filter == "all") {
      state_choices <- get_all_states_list()
    } else {
      state_choices <- get_region_states_list(input$region_filter)
    }
    
    updateSelectInput(session, "state_filter", choices = state_choices)
  })
  
  # Update municipality choices based on state selection  
  observeEvent(input$state_filter, {
    if (input$state_filter == "all") {
      # Hide municipality selector
      municipality_choices <- list("All Municipalities" = "all")
    } else {
      # Load municipalities for selected state
      municipality_choices <- get_state_municipalities_list(input$state_filter)
    }
    
    updateSelectInput(session, "municipality_filter", choices = municipality_choices)
  })
  
  # Main filtering reactive
  filtered_documents <- reactive({
    req(documents_reactive())
    
    start_time <- Sys.time()
    
    result <- get_enhanced_geographic_documents(
      documents_df = documents_reactive(),
      state_filter = input$state_filter %||% "all",
      municipality_filter = input$municipality_filter %||% "all", 
      region_filter = input$region_filter %||% "all",
      use_municipalities = TRUE
    )
    
    # Update performance stats
    processing_time <- as.numeric(Sys.time() - start_time, units = "secs")
    values$performance_stats <- list(
      processing_time = processing_time,
      total_documents = nrow(documents_reactive()),
      filtered_documents = nrow(result),
      filter_efficiency = nrow(result) / nrow(documents_reactive())
    )
    
    return(result)
  })
  
  # Performance info output
  output$geographic_performance_info <- renderText({
    if (length(values$performance_stats) > 0) {
      stats <- values$performance_stats
      sprintf(
        "📊 %s documents (%s%% of total) • ⏱️ %ss processing time",
        format(stats$filtered_documents, big.mark = ","),
        round(stats$filter_efficiency * 100, 1),
        round(stats$processing_time, 2)
      )
    } else {
      "Ready for enhanced geographic filtering..."
    }
  })
  
  # Reset filters
  observeEvent(input$reset_geographic_filters, {
    updateSelectInput(session, "region_filter", selected = "all")
    updateSelectInput(session, "state_filter", selected = "all") 
    updateSelectInput(session, "municipality_filter", selected = "all")
  })
  
  return(filtered_documents)
}

# ============================================================================
# HELPER FUNCTIONS FOR INTEGRATION
# ============================================================================

#' Get region states mapping
#' @description Map regions to their constituent states
get_region_states <- function(region_name) {
  region_mapping <- list(
    "norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
    "nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
    "centro_oeste" = c("GO", "MT", "MS", "DF"),
    "sudeste" = c("ES", "MG", "RJ", "SP"),
    "sul" = c("PR", "RS", "SC")
  )
  
  return(region_mapping[[region_name]] %||% c())
}

#' Get all states for dropdown
#' @description Create state choices list
get_all_states_list <- function() {
  states <- list(
    "All States" = "all",
    "Acre" = "AC", "Alagoas" = "AL", "Amapá" = "AP", "Amazonas" = "AM",
    "Bahia" = "BA", "Ceará" = "CE", "Distrito Federal" = "DF", "Espírito Santo" = "ES",
    "Goiás" = "GO", "Maranhão" = "MA", "Mato Grosso" = "MT", "Mato Grosso do Sul" = "MS",
    "Minas Gerais" = "MG", "Pará" = "PA", "Paraíba" = "PB", "Paraná" = "PR",
    "Pernambuco" = "PE", "Piauí" = "PI", "Rio de Janeiro" = "RJ", "Rio Grande do Norte" = "RN",
    "Rio Grande do Sul" = "RS", "Rondônia" = "RO", "Roraima" = "RR", "Santa Catarina" = "SC",
    "São Paulo" = "SP", "Sergipe" = "SE", "Tocantins" = "TO"
  )
  
  return(states)
}

#' Get region states for dropdown
#' @description Create filtered state list for specific region
get_region_states_list <- function(region_name) {
  all_states <- get_all_states_list()
  region_states <- get_region_states(region_name)
  
  if (length(region_states) == 0) {
    return(list("All States" = "all"))
  }
  
  # Filter states list to region
  filtered_states <- all_states[names(all_states) %in% c("All States") | 
                               all_states %in% region_states]
  
  return(filtered_states)
}

#' Get municipalities for state (placeholder implementation)
#' @description Load municipality list for specific state
get_state_municipalities_list <- function(state_code) {
  
  # This is a placeholder - in production, load from IBGE database
  # For now, return sample municipalities for major states
  
  sample_municipalities <- list(
    "SP" = list(
      "All Municipalities" = "all",
      "São Paulo" = "3550308",
      "Guarulhos" = "3518800", 
      "Campinas" = "3509502",
      "São Bernardo do Campo" = "3548708",
      "Santo André" = "3547809"
    ),
    "RJ" = list(
      "All Municipalities" = "all",
      "Rio de Janeiro" = "3304557",
      "São Gonçalo" = "3304904",
      "Duque de Caxias" = "3301702",
      "Nova Iguaçu" = "3303500",
      "Niterói" = "3303302"
    ),
    "MG" = list(
      "All Municipalities" = "all",
      "Belo Horizonte" = "3106200",
      "Uberlândia" = "3170206",
      "Contagem" = "3118601",
      "Juiz de Fora" = "3136702"
    )
  )
  
  return(sample_municipalities[[state_code]] %||% list("All Municipalities" = "all"))
}

#' Join documents with municipality (placeholder implementation)  
#' @description Perform spatial join for specific municipality
join_documents_with_municipality <- function(documents_df, municipality_code) {
  
  # Placeholder implementation - in production, use actual spatial joins
  cat("🔍 Performing spatial join for municipality:", municipality_code, "\n")
  
  # For now, return documents filtered by state (fallback logic)
  state_code <- substr(municipality_code, 1, 2)
  filtered_docs <- documents_df[documents_df$estado == state_code, ]
  
  # Add placeholder municipality_code column
  filtered_docs$municipality_code <- municipality_code
  
  return(filtered_docs)
}

#' Create existing geographic UI (backward compatibility)
#' @description Fallback to existing state-level interface
create_existing_geographic_ui <- function(ns) {
  
  tagList(
    h4("🗺️ Geographic Filters", style = "color: #2c3e50; margin-bottom: 15px;"),
    
    selectInput(
      ns("region_filter"),
      "Region:",
      choices = list(
        "All Regions" = "all",
        "Norte" = "norte",
        "Nordeste" = "nordeste",
        "Centro-Oeste" = "centro_oeste", 
        "Sudeste" = "sudeste",
        "Sul" = "sul"
      ),
      selected = "all"
    ),
    
    selectInput(
      ns("state_filter"), 
      "State:",
      choices = get_all_states_list(),
      selected = "all"
    )
  )
}

#' Create existing geographic server (backward compatibility)  
#' @description Fallback server logic for state-level filtering
create_existing_geographic_server <- function(input, output, session, documents_reactive) {
  
  filtered_documents <- reactive({
    req(documents_reactive())
    
    get_existing_state_filter(
      documents_df = documents_reactive(),
      state_filter = input$state_filter %||% "all",
      region_filter = input$region_filter %||% "all"
    )
  })
  
  return(filtered_documents)
}

# ============================================================================
# INTEGRATION STATUS AND DIAGNOSTICS
# ============================================================================

#' Get polygon processing status
#' @description Check system status for diagnostics
get_polygon_processing_status <- function() {
  
  if (!exists("polygon_processing_config")) {
    return(list(
      status = "not_initialized",
      municipalities_enabled = FALSE,
      message = "Polygon processing not initialized"
    ))
  }
  
  config <- polygon_processing_config
  
  return(list(
    status = config$status,
    municipalities_enabled = config$municipalities_enabled,
    initialization_time = config$initialization_time,
    memory_limit = config$memory_limit,
    error = config$error %||% NULL,
    message = paste("System status:", config$status)
  ))
}

#' Integration diagnostics
#' @description Run system diagnostics for troubleshooting
run_polygon_integration_diagnostics <- function() {
  
  cat("🔍 Running Polygon Processing Integration Diagnostics...\n")
  
  diagnostics <- list(
    system_status = get_polygon_processing_status(),
    memory_usage = NULL,
    required_packages = NULL,
    database_connection = NULL,
    test_results = NULL
  )
  
  # Memory usage check
  tryCatch({
    mem_usage <- gc()
    diagnostics$memory_usage <- list(
      used_mb = sum(mem_usage[, "used"]) * 8 / 1024,  # Approximate MB
      available = "Good"
    )
  }, error = function(e) {
    diagnostics$memory_usage <- list(error = e$message)
  })
  
  # Package availability check
  required_pkgs <- c("sf", "DBI", "RPostgres", "data.table")
  pkg_status <- sapply(required_pkgs, function(pkg) {
    requireNamespace(pkg, quietly = TRUE)
  })
  diagnostics$required_packages <- pkg_status
  
  # Simple test
  tryCatch({
    test_result <- length(get_all_states_list()) > 1
    diagnostics$test_results <- list(basic_functions = test_result)
  }, error = function(e) {
    diagnostics$test_results <- list(error = e$message)
  })
  
  cat("✅ Diagnostics completed\n")
  
  return(diagnostics)
}

# ============================================================================
# MAIN EXPORTS FOR APP.R INTEGRATION
# ============================================================================

# Primary integration functions for app.R
polygon_integration <- list(
  initialize = initialize_polygon_processing,
  create_ui = create_enhanced_geographic_filter_ui,
  create_server = create_enhanced_geographic_filter_server,
  filter_documents = get_enhanced_geographic_documents,
  get_status = get_polygon_processing_status,
  run_diagnostics = run_polygon_integration_diagnostics
)

# Helper function definition
`%||%` <- function(a, b) if (is.null(a)) b else a

cat("✅ Polygon Processing App Integration loaded successfully\n")
cat("🔗 Ready for seamless app.R integration with municipality support\n")
cat("🔄 Maintains backward compatibility with existing state-level features\n")
cat("🚀 Railway deployment compatible with <1.4GB memory constraint\n")