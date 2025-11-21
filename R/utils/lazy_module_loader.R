# =============================================================================
# Lazy Module Loading System
# =============================================================================
# Monitor Legislativo v4 - Phase 4 Task 4.2
#
# Implements on-demand module loading to improve application startup time
# and reduce initial memory footprint. Modules are loaded only when their
# tab is first accessed by the user.
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# =============================================================================

#' Lazy Module Loader
#'
#' Creates a reactive module loader that initializes modules on first access.
#' This reduces startup time and memory usage by deferring module initialization
#' until needed.
#'
#' @param session Shiny session object
#' @param input Shiny input object
#' @param db_pool Database connection pool
#' @param db_available Whether database is available
#' @param documents_table Name of documents table
#'
#' @return List of lazy-loaded module references
#'
#' @examples
#' modules <- create_lazy_module_loader(session, input, db_pool, DB_AVAILABLE, DOCUMENTS_TABLE)
#' # Module is loaded only when first accessed
#' modules$readability_analytics()
#'
#' @export
create_lazy_module_loader <- function(session, input, db_pool, db_available, documents_table) {

  # Storage for loaded modules
  loaded_modules <- reactiveValues()

  # Track which modules have been initialized
  initialized <- reactiveValues()

  # Module definitions with their loading logic
  module_definitions <- list(

    # Library Enhanced Module
    library_enhanced = list(
      server_function = "libraryEnhancedServer",
      tab_trigger = "library",
      loader = function() {
        if (exists("libraryEnhancedServer")) {
          cat("🔄 Lazy loading Enhanced Library Module\n")
          libraryEnhancedServer(
            "library_enhanced",
            db_connection = db_pool,
            db_available = db_available,
            documents_table = documents_table
          )
        } else {
          NULL
        }
      }
    ),

    # Readability Analytics Module
    readability_analytics = list(
      server_function = "readabilityServer",
      tab_trigger = "readability",
      loader = function() {
        if (exists("readabilityServer")) {
          cat("🔄 Lazy loading Readability Analytics Module\n")
          readabilityServer(
            "readability_module",
            db_connection = db_pool,
            db_available = db_available,
            documents_table = documents_table
          )
        } else {
          NULL
        }
      }
    ),

    # Jurisdictional Comparison Module
    jurisdictional_comparison = list(
      server_function = "jurisdictionalServer",
      tab_trigger = "jurisdictional",
      loader = function() {
        if (exists("jurisdictionalServer")) {
          cat("🔄 Lazy loading Multi-Jurisdictional Comparison Module\n")
          jurisdictionalServer(
            "jurisdictional_comparison",
            db_connection = db_pool,
            db_available = db_available,
            documents_table = documents_table
          )
        } else {
          NULL
        }
      }
    ),

    # Text Reuse Detection Module
    text_reuse_module = list(
      server_function = "text_reuse_server",
      tab_trigger = "text_reuse",
      loader = function() {
        if (exists("text_reuse_server")) {
          cat("🔄 Lazy loading Text Reuse Detection Module\n")
          text_reuse_server(
            "text_reuse_module",
            db_connection = db_pool
          )
        } else {
          NULL
        }
      }
    ),

    # Network Backbone Module
    network_backbone_module = list(
      server_function = "network_backbone_server",
      tab_trigger = "network_backbone",
      loader = function() {
        if (exists("network_backbone_server")) {
          cat("🔄 Lazy loading Network Backbone Module\n")
          network_backbone_server(
            "network_backbone_module",
            db_connection = db_pool
          )
        } else {
          NULL
        }
      }
    ),

    # Amendment Pattern Analysis Module
    amendment_module = list(
      server_function = "amendmentServer",
      tab_trigger = "amendment",
      loader = function() {
        if (exists("amendmentServer")) {
          cat("🔄 Lazy loading Amendment Pattern Analysis Module\n")
          amendmentServer(
            "amendment_module",
            db_connection = db_pool,
            db_available = db_available,
            documents_table = documents_table
          )
        } else {
          NULL
        }
      }
    ),

    # Anomaly Detection Module
    anomaly_module = list(
      server_function = "anomalyServer",
      tab_trigger = "anomaly",
      loader = function() {
        if (exists("anomalyServer")) {
          cat("🔄 Lazy loading Anomaly Detection Module\n")
          anomalyServer(
            "anomaly_module",
            db_connection = db_pool,
            db_available = db_available,
            documents_table = documents_table
          )
        } else {
          NULL
        }
      }
    ),

    # Semantic Search Module
    semantic_search = list(
      server_function = "semantic_search_server",
      tab_trigger = "semantic",
      loader = function() {
        if (exists("semantic_search_server")) {
          cat("🔄 Lazy loading Semantic Search Module\n")
          semantic_search_server(
            "semantic_search_module",
            db_pool = db_pool
          )
        } else {
          NULL
        }
      }
    ),

    # Topic Explorer Module
    topic_explorer = list(
      server_function = "topic_explorer_server",
      tab_trigger = "topic",
      loader = function() {
        if (exists("topic_explorer_server")) {
          cat("🔄 Lazy loading Topic Explorer Module\n")
          topic_explorer_server(
            "topic_explorer_module",
            db_pool = db_pool
          )
        } else {
          NULL
        }
      }
    ),

    # BERT Precedent Search Module
    bert_precedent = list(
      server_function = "bert_precedent_server",
      tab_trigger = "bert",
      loader = function() {
        if (exists("bert_precedent_server")) {
          cat("🔄 Lazy loading BERT Precedent Search Module\n")
          bert_precedent_server(
            "bert_precedent_module",
            db_pool = db_pool
          )
        } else {
          NULL
        }
      }
    ),

    # Survival Analysis Module
    survival_analysis = list(
      server_function = "survival_server",
      tab_trigger = "survival",
      loader = function() {
        if (exists("survival_server")) {
          cat("🔄 Lazy loading Survival Analysis Module\n")
          survival_server(
            "survival_module",
            db_pool = db_pool
          )
        } else {
          NULL
        }
      }
    )
  )

  # Create lazy loaders for each module
  lazy_modules <- lapply(names(module_definitions), function(module_name) {
    reactive({
      # Check if already loaded
      if (!isTRUE(initialized[[module_name]])) {
        # Load the module
        definition <- module_definitions[[module_name]]
        module_instance <- definition$loader()

        if (!is.null(module_instance)) {
          loaded_modules[[module_name]] <- module_instance
          initialized[[module_name]] <- TRUE

          # Log lazy load metrics
          if (exists("increment_lazy_load_counter")) {
            increment_lazy_load_counter(module_name)
          }

          cat(sprintf("✅ Module '%s' loaded on demand\n", module_name))
        } else {
          cat(sprintf("⚠️ Module '%s' not available\n", module_name))
        }
      }

      # Return the loaded module
      loaded_modules[[module_name]]
    })
  })

  names(lazy_modules) <- names(module_definitions)

  # Optional: Auto-trigger based on active tab
  observeEvent(input$navbar, {
    active_tab <- input$navbar

    # Find modules triggered by this tab
    for (module_name in names(module_definitions)) {
      definition <- module_definitions[[module_name]]
      if (grepl(definition$tab_trigger, active_tab, ignore.case = TRUE)) {
        # Trigger lazy load by accessing the reactive
        isolate(lazy_modules[[module_name]]())
      }
    }
  }, ignoreInit = TRUE)

  return(lazy_modules)
}

#' Get Lazy Load Statistics
#'
#' Returns statistics about lazy-loaded modules
#'
#' @return List with module loading stats
#' @export
get_lazy_load_stats <- function() {
  if (!exists(".lazy_load_stats", envir = .GlobalEnv)) {
    assign(".lazy_load_stats", list(
      total_modules = 0,
      loaded_modules = 0,
      load_times = list()
    ), envir = .GlobalEnv)
  }

  get(".lazy_load_stats", envir = .GlobalEnv)
}

#' Increment Lazy Load Counter
#'
#' Tracks which modules have been lazy loaded
#'
#' @param module_name Name of the module
#' @export
increment_lazy_load_counter <- function(module_name) {
  stats <- get_lazy_load_stats()

  stats$loaded_modules <- stats$loaded_modules + 1
  stats$load_times[[module_name]] <- Sys.time()

  assign(".lazy_load_stats", stats, envir = .GlobalEnv)
}

#' Preload Critical Modules
#'
#' Preloads modules that are critical for initial page load
#' while leaving others for lazy loading
#'
#' @param lazy_modules List of lazy module reactives
#' @param critical_modules Vector of module names to preload
#' @export
preload_critical_modules <- function(lazy_modules, critical_modules = c("library_enhanced")) {
  cat("🚀 Preloading critical modules:", paste(critical_modules, collapse = ", "), "\n")

  for (module_name in critical_modules) {
    if (module_name %in% names(lazy_modules)) {
      isolate(lazy_modules[[module_name]]())
    }
  }

  cat("✅ Critical modules preloaded\n")
}

cat("✅ Lazy module loading system loaded\n")
