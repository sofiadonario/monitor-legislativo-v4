# --- Shiny server version guard (prevents NA compareVersion crash) ---
local({
  v <- Sys.getenv("SHINY_SERVER_VERSION", unset = NA_character_)
  # If missing or malformed, set a benign valid semver
  if (is.na(v) || !grepl("^[0-9]+(\\.[0-9]+)*$", v)) {
    Sys.setenv(SHINY_SERVER_VERSION = "3.0.0")
  }
})

# --- Health & server options (Railway) ---
options(shiny.host = "0.0.0.0",
        shiny.port = as.integer(Sys.getenv("PORT", "3838")))

# Tiny static health path
local({
  dir.create("health", showWarnings = FALSE)
  ok <- file.path("health", "index.html")
  if (!file.exists(ok)) writeLines("<!doctype html><title>ok</title>ok", ok, useBytes = TRUE)
  if (!"health" %in% names(shiny::resourcePaths()))
    shiny::addResourcePath("health", "health")
})

# Exact /health (no slash) for Railway
if (is.null(getOption("shiny.http.response.filter"))) {
  options(shiny.http.response.filter = function(req, res) {
    path <- req$PATH_INFO %||% "/"
    if (identical(path, "/health")) {
      res$status <- 200L
      res$headers[["Content-Type"]] <- "text/plain; charset=utf-8"
      res$body <- charToRaw("ok")
      return(res)
    }
    NULL
  })
}

# Helper used elsewhere in app; does NOT touch base R
`%||%` <- function(x, y) if (is.null(x) || length(x) == 0L || (is.atomic(x) && anyNA(x))) y else x

# Assert base binding remains locked (safety net)
stopifnot(bindingIsLocked("compareVersion", asNamespace("utils")))

# Railway-specific environment check
if (identical(Sys.getenv("RAILWAY_ENVIRONMENT"), "production")) {
  cat("Railway production environment detected\n")
}

# Monitor Legislativo v4 - Complete Production Application
# ========================================================
# Brazilian Legislative Monitoring System
# Comprehensive Analytics Dashboard with Full Feature Set
# Railway Deployment Ready

# Load global configuration and system initialization with enhanced error logging
tryCatch({
  cat("[APP STARTUP] Loading global.R...\n", file = stderr())
  source("global.R")
  cat("[APP STARTUP] global.R loaded successfully\n", file = stderr())
}, error = function(e) {
  msg <- sprintf("[APP STARTUP ERROR] Failed to load global.R: %s\n", conditionMessage(e))
  cat(msg, file = stderr())
  cat("[APP STARTUP ERROR] Stack trace:\n", file = stderr())
  print(sys.calls(), stderr())
  stop(e)
})

## ---- Safe defaults for app_config used by app.R ----
if (!exists("app_config")) app_config <- list()
app_flag <- function(x, default = FALSE) {
  v <- tryCatch(app_config[[x]], error = function(e) NULL)
  isTRUE(v) || isTRUE(as.logical(v)) || default
}
# %||% already defined at top of file

MONITORING_ENABLED <- app_flag("monitoring_enabled", FALSE)

## ---- Safe existence checks for globals ----
safe_exists <- function(name) exists(name, inherits = TRUE) && !is.null(get(name, inherits = TRUE))

cat("🚀 Loading Monitor Legislativo v4 - Complete Dashboard\n")
cat("📊 Integrating all analytics systems...\n")

# ============================================================================
# LOAD MODULE SYSTEM
# ============================================================================

# Initialize module loading status with safe defaults
modules_loaded <- list(
  executive_summary = FALSE,
  library = FALSE,
  analytics = FALSE,
  geographic = FALSE,
  maps = FALSE,
  sao_paulo = FALSE,
  text_analytics = FALSE
)

# Safe module access
safe_module_loaded <- function(module_name) {
  isTRUE(modules_loaded[[module_name]])
}

# Load Executive Summary Module
tryCatch({
  if (file.exists("modules/executive_summary_ui.R") && file.exists("modules/executive_summary_server.R")) {
    source("modules/executive_summary_ui.R")
    source("modules/executive_summary_server.R")
    modules_loaded$executive_summary <- TRUE
    cat("✅ Executive Summary module loaded\n")
  }
}, error = function(e) {
  cat("⚠️ Executive Summary module failed:", e$message, "\n")
})

# Load Enhanced Library Module
tryCatch({
  if (file.exists("modules/library/enhanced_library_ui.R") && file.exists("modules/library/enhanced_library_server.R")) {
    source("modules/library/enhanced_library_ui.R")
    source("modules/library/enhanced_library_server.R")
    modules_loaded$library <- TRUE
    cat("✅ Enhanced Library module loaded\n")
  }
}, error = function(e) {
  cat("⚠️ Library module failed:", e$message, "\n")
})

# Load Advanced Analytics Module
tryCatch({
  if (file.exists("modules/analytics/analytics_ui.R") && file.exists("modules/analytics/analytics_server.R")) {
    source("modules/analytics/analytics_ui.R")
    source("modules/analytics/analytics_server.R")
    modules_loaded$analytics <- TRUE
    cat("✅ Advanced Analytics module loaded\n")
  }
}, error = function(e) {
  cat("⚠️ Analytics module failed:", e$message, "\n")
})

# Load Geographic Analysis Module
tryCatch({
  if (file.exists("modules/geographic/visualization_ui.R")) {
    source("modules/geographic/visualization_ui.R")
    # Check for corresponding server file
    geographic_server_files <- c(
      "modules/geographic/geographic_server.R",
      "modules/geographic/spatial_analysis_server.R"
    )
    for (server_file in geographic_server_files) {
      if (file.exists(server_file)) {
        source(server_file)
        break
      }
    }
    modules_loaded$geographic <- TRUE
    cat("✅ Geographic Analysis module loaded\n")
  }
}, error = function(e) {
  cat("⚠️ Geographic Analysis module failed:", e$message, "\n")
})

# Load Interactive Maps Module
tryCatch({
  if (file.exists("modules/maps/map_ui.R") && file.exists("modules/maps/map_server.R")) {
    source("modules/maps/map_ui.R")
    source("modules/maps/map_server.R")
    modules_loaded$maps <- TRUE
    cat("✅ Interactive Maps module loaded\n")
  }
}, error = function(e) {
  cat("⚠️ Maps module failed:", e$message, "\n")
})

# Load São Paulo Analysis Module
tryCatch({
  if (file.exists("modules/sao_paulo/sao_paulo_ui.R") && file.exists("modules/sao_paulo/sao_paulo_server.R")) {
    source("modules/sao_paulo/sao_paulo_ui.R")
    source("modules/sao_paulo/sao_paulo_server.R")
    modules_loaded$sao_paulo <- TRUE
    cat("✅ São Paulo Analysis module loaded\n")
  }
}, error = function(e) {
  cat("⚠️ São Paulo Analysis module failed:", e$message, "\n")
})

# Load Text Analytics Module
tryCatch({
  # Look for text analytics UI/server files
  text_ui_files <- c(
    "modules/text/text_analytics_ui.R",
    "modules/analytics/nlp_ui.R",
    "modules/ui/legislative_analytics_ui.R"
  )
  text_server_files <- c(
    "modules/text/text_analytics_server.R",
    "modules/analytics/nlp_server.R"
  )

  ui_loaded <- FALSE
  server_loaded <- FALSE

  for (ui_file in text_ui_files) {
    if (file.exists(ui_file)) {
      source(ui_file)
      ui_loaded <- TRUE
      break
    }
  }

  for (server_file in text_server_files) {
    if (file.exists(server_file)) {
      source(server_file)
      server_loaded <- TRUE
      break
    }
  }

  if (ui_loaded || server_loaded) {
    modules_loaded$text_analytics <- TRUE
    cat("✅ Text Analytics module loaded\n")
  }
}, error = function(e) {
  cat("⚠️ Text Analytics module failed:", e$message, "\n")
})

# Load Advanced Search Module
advanced_search_loaded <- FALSE
tryCatch({
  if (file.exists("modules/search/advanced_search_ui.R") && file.exists("modules/search/advanced_search_server.R")) {
    source("modules/search/advanced_search_ui.R")
    source("modules/search/advanced_search_server.R")
    advanced_search_loaded <- TRUE
    cat("✅ Advanced Search module loaded\n")
  }
}, error = function(e) {
  cat("⚠️ Advanced Search module failed:", e$message, "\n")
})

cat("📊 Module loading complete\n")

# ============================================================================
# UI DEFINITION
# ============================================================================

cat("🔍 [UI] Starting UI construction...\n")

ui <- tryCatch({
  cat("🔍 [UI] Creating dashboardPage...\n")
  dashboardPage(
  skin = "blue",

  # Header
  dashboardHeader(
    title = app_config$app_title %||% "Monitor Legislativo v4",
    tags$li(class = "dropdown",
      tags$a(href = "#", class = "dropdown-toggle", `data-toggle` = "dropdown",
        icon("user"), " System Status"
      ),
      tags$ul(class = "dropdown-menu",
        tags$li(tags$a(href = "#", paste("Environment:", app_config$environment %||% "unknown"))),
        tags$li(tags$a(href = "#", paste("Version:", app_config$app_version %||% "4.0.0"))),
        tags$li(tags$a(href = "#", paste("Modules:", sum(unlist(modules_loaded)), "/", length(modules_loaded))))
      )
    )
  ),

  # Sidebar
  dashboardSidebar(
    sidebarMenu(
      id = "sidebar_menu",
      menuItem("Executive Summary", tabName = "dashboard", icon = icon("tachometer-alt"),
               badgeLabel = if (isTRUE(safe_module_loaded("executive_summary"))) "✓" else "!",
               badgeColor = if (isTRUE(safe_module_loaded("executive_summary"))) "green" else "orange"),
      menuItem("Library", tabName = "library", icon = icon("book"),
               badgeLabel = if (isTRUE(safe_module_loaded("library"))) "✓" else "!",
               badgeColor = if (isTRUE(safe_module_loaded("library"))) "green" else "orange"),
      menuItem("Advanced Analytics", tabName = "analytics", icon = icon("chart-line"),
               badgeLabel = if (isTRUE(safe_module_loaded("analytics"))) "✓" else "!",
               badgeColor = if (isTRUE(safe_module_loaded("analytics"))) "green" else "orange"),
      menuItem("Geographic Analysis", tabName = "geographic", icon = icon("map"),
               badgeLabel = if (isTRUE(safe_module_loaded("geographic"))) "✓" else "!",
               badgeColor = if (isTRUE(safe_module_loaded("geographic"))) "green" else "orange"),
      menuItem("Interactive Maps", tabName = "maps", icon = icon("globe"),
               badgeLabel = if (isTRUE(safe_module_loaded("maps"))) "✓" else "!",
               badgeColor = if (isTRUE(safe_module_loaded("maps"))) "green" else "orange"),
      menuItem("São Paulo Analysis", tabName = "sao_paulo", icon = icon("city"),
               badgeLabel = if (isTRUE(safe_module_loaded("sao_paulo"))) "✓" else "!",
               badgeColor = if (isTRUE(safe_module_loaded("sao_paulo"))) "green" else "orange"),
      menuItem("Text Analytics", tabName = "text", icon = icon("text-height"),
               badgeLabel = if (isTRUE(safe_module_loaded("text_analytics"))) "✓" else "!",
               badgeColor = if (isTRUE(safe_module_loaded("text_analytics"))) "green" else "orange"),

      # System Information
      br(),
      menuItem("System Info", icon = icon("info-circle"),
        paste("Database:", if (exists("get_documents")) "Connected" else "Fallback"),
        br(),
        paste("Monitoring:", if (isTRUE(MONITORING_ENABLED)) "Enabled" else "Disabled")
      )
    )
  ),

  # Body
  dashboardBody(
    # Custom CSS
    tags$head(
      tags$style(HTML("
        .content-wrapper, .right-side { background-color: #f8f9fa; }
        .main-header .logo { background-color: #2c3e50 !important; }
        .main-header .navbar { background-color: #2c3e50 !important; }
        .skin-blue .main-sidebar { background-color: #34495e; }
        .box.box-solid.box-primary > .box-header { background: #3498db; }
        .box.box-solid.box-info > .box-header { background: #17a2b8; }
        .box.box-solid.box-success > .box-header { background: #28a745; }
        .value-box-icon { font-size: 60px !important; }
        .small-box { border-radius: 10px; }
      "))
    ),

    # JavaScript for enhanced interactivity
    tags$script(HTML("
      $(document).ready(function() {
        // Add loading spinners
        $('.box').prepend('<div class=\"overlay\" style=\"display:none;\"><i class=\"fa fa-refresh fa-spin\"></i></div>');

        // Show/hide loading on tab change
        $('a[data-toggle=\"tab\"]').on('shown.bs.tab', function (e) {
          var target = $(e.target).attr('href');
          $(target).find('.overlay').show();
          setTimeout(function() { $(target).find('.overlay').hide(); }, 1000);
        });
      });
    ")),

    tabItems(
      # Executive Summary Tab
      tryCatch({
        cat("🔍 [UI] Building Executive Summary tab...\n")
        tabItem(
          tabName = "dashboard",
          if (safe_module_loaded("executive_summary") && exists("executive_summary_ui")) {
            cat("🔍 [UI] Calling executive_summary_ui()...\n")
            executive_summary_ui()
          } else {
            cat("🔍 [UI] Using fallback Executive Summary UI...\n")
          # Fallback UI if module didn't load
          tagList(
            fluidRow(
              valueBoxOutput("total_docs", width = 4),
              valueBoxOutput("states_covered", width = 4),
              valueBoxOutput("municipalities_covered", width = 4)
            ),
            fluidRow(
              box(title = "System Status", status = "primary", solidHeader = TRUE, width = 12,
                  verbatimTextOutput("system_status")
              )
            ),
            fluidRow(
              box(title = "Documents by State", status = "primary", solidHeader = TRUE, width = 6,
                  plotlyOutput("state_chart")
              ),
              box(title = "Documents by Type", status = "info", solidHeader = TRUE, width = 6,
                  plotlyOutput("type_chart")
              )
            )
          )
          }
        )
      }, error = function(e) {
        cat("❌ [UI] Error in Executive Summary tab:", conditionMessage(e), "\n", file = stderr())
        tabItem(tabName = "dashboard", fluidRow(box(title = "Error", status = "danger",
          solidHeader = TRUE, width = 12, "Executive Summary failed to load")))
      }),

      # Library Tab
      tryCatch({
        cat("🔍 [UI] Building Library tab...\n")
        tabItem(
          tabName = "library",
          if (safe_module_loaded("library") && exists("enhanced_library_ui")) {
            cat("🔍 [UI] Calling enhanced_library_ui()...\n")
            enhanced_library_ui()
          } else {
            cat("🔍 [UI] Using fallback Library UI...\n")
          # Fallback library interface
          fluidRow(
            box(title = "Document Search", status = "primary", solidHeader = TRUE, width = 12,
                fluidRow(
                  column(8, textInput("search_text", "Search documents:", placeholder = "Enter search terms...")),
                  column(4, br(), actionButton("search_btn", "Search", class = "btn-primary btn-block"))
                ),
                if (advanced_search_loaded && exists("advanced_search_filters_ui")) {
                  advanced_search_filters_ui()
                } else {
                  div()
                },
                br(),
                DTOutput("documents_table")
            )
          )
          }
        )
      }, error = function(e) {
        cat("❌ [UI] Error in Library tab:", conditionMessage(e), "\n", file = stderr())
        tabItem(tabName = "library", fluidRow(box(title = "Error", status = "danger",
          solidHeader = TRUE, width = 12, "Library failed to load")))
      }),

      # Advanced Analytics Tab
      tryCatch({
        cat("🔍 [UI] Building Advanced Analytics tab...\n")
        tabItem(
          tabName = "analytics",
          if (safe_module_loaded("analytics") && exists("analytics_ui")) {
            cat("🔍 [UI] Calling analytics_ui()...\n")
            analytics_ui()
          } else {
            cat("🔍 [UI] Using fallback Analytics UI...\n")
          fluidRow(
            box(title = "Analytics Dashboard", status = "primary", solidHeader = TRUE, width = 12,
                h3("Advanced Analytics Module"),
                p("This section provides comprehensive analytical tools for legislative data including:"),
                tags$ul(
                  tags$li("Temporal trend analysis and forecasting"),
                  tags$li("Statistical significance testing"),
                  tags$li("Machine learning-based document classification"),
                  tags$li("Natural language processing and sentiment analysis"),
                  tags$li("Network analysis of legislative relationships")
                ),
                if (!safe_module_loaded("analytics")) {
                  div(class = "alert alert-warning",
                      "Analytics module not available. Please check module files.")
                } else {
                  div()
                }
            )
          )
          }
        )
      }, error = function(e) {
        cat("❌ [UI] Error in Analytics tab:", conditionMessage(e), "\n", file = stderr())
        tabItem(tabName = "analytics", fluidRow(box(title = "Error", status = "danger",
          solidHeader = TRUE, width = 12, "Analytics failed to load")))
      }),

      # Geographic Analysis Tab
      tryCatch({
        cat("🔍 [UI] Building Geographic Analysis tab...\n")
        tabItem(
          tabName = "geographic",
          if (safe_module_loaded("geographic") && exists("geographic_analysis_ui")) {
            cat("🔍 [UI] Calling geographic_analysis_ui()...\n")
            geographic_analysis_ui()
          } else if (exists("visualization_ui")) {
            cat("🔍 [UI] Calling visualization_ui()...\n")
            visualization_ui()
          } else {
            fluidRow(
              box(title = "Geographic Analysis", status = "primary", solidHeader = TRUE, width = 12,
                  h3("Geographic Distribution Analysis"),
                  p("Comprehensive geospatial analysis of Brazilian legislative documents:"),
                  tags$ul(
                    tags$li("State and municipality-level document distribution"),
                    tags$li("Choropleth maps with interactive visualization"),
                    tags$li("Regional policy trend analysis"),
                    tags$li("Geographic clustering and hotspot detection")
                  ),
                  if (!safe_module_loaded("geographic")) {
                    div(class = "alert alert-warning",
                        "Geographic analysis module not available. Please check module files.")
                  } else {
                    div()
                  }
              )
            )
          }
        )
      }, error = function(e) {
        cat("❌ [UI] Error in Geographic tab:", conditionMessage(e), "\n", file = stderr())
        tabItem(tabName = "geographic", fluidRow(box(title = "Error", status = "danger",
          solidHeader = TRUE, width = 12, "Geographic analysis failed to load")))
      }),

      # Interactive Maps Tab
      tabItem(
        tabName = "maps",
        if (safe_module_loaded("maps") && exists("map_ui")) {
          map_ui()
        } else {
          fluidRow(
            box(title = "Interactive Maps", status = "primary", solidHeader = TRUE, width = 12,
                leafletOutput("brazil_map", height = 600)
            )
          )
        }
      ),

      # São Paulo Analysis Tab
      tabItem(
        tabName = "sao_paulo",
        if (safe_module_loaded("sao_paulo") && exists("sao_paulo_ui")) {
          sao_paulo_ui()
        } else {
          fluidRow(
            box(title = "São Paulo Analysis", status = "primary", solidHeader = TRUE, width = 12,
                h3("São Paulo State Legislative Analysis"),
                p("Specialized analysis for São Paulo state and metropolitan region:"),
                tags$ul(
                  tags$li("Metropolitan governance and transport policy tracking"),
                  tags$li("Municipal coordination analysis"),
                  tags$li("Economic policy impact assessment"),
                  tags$li("Urban development legislation monitoring")
                ),
                if (!safe_module_loaded("sao_paulo")) {
                  div(class = "alert alert-warning",
                      "São Paulo analysis module not available. Please check module files.")
                } else {
                  div()
                }
            )
          )
        }
      ),

      # Text Analytics Tab
      tabItem(
        tabName = "text",
        if (safe_module_loaded("text_analytics") && exists("text_analytics_ui")) {
          text_analytics_ui()
        } else if (exists("legislative_analytics_ui")) {
          legislative_analytics_ui()
        } else {
          fluidRow(
            box(title = "Text Analytics", status = "primary", solidHeader = TRUE, width = 12,
                h3("Natural Language Processing for Legal Texts"),
                p("Comprehensive text mining and NLP analysis:"),
                tags$ul(
                  tags$li("Topic modeling and thematic analysis"),
                  tags$li("Sentiment analysis of legislative content"),
                  tags$li("Entity recognition (people, organizations, locations)"),
                  tags$li("Document similarity and clustering"),
                  tags$li("Keyword extraction and trend analysis")
                ),
                {
                  if (!safe_module_loaded("text_analytics")) {
                    div(class = "alert alert-warning",
                        "Text analytics module not available. Please check module files.")
                  } else {
                    div()
                  }
                }
            )
          )
        }
      )
    )
  )
  )
}, error = function(e) {
  cat("❌ [UI] FATAL ERROR during UI construction:\n", file = stderr())
  cat("   Error message:", conditionMessage(e), "\n", file = stderr())
  cat("   Call stack:\n", file = stderr())
  print(sys.calls(), file = stderr())
  cat("==========================================\n", file = stderr())
  stop(e)
})

cat("✅ [UI] UI construction completed successfully\n")

# ============================================================================
# SERVER LOGIC
# ============================================================================

server <- function(input, output, session) {
  # AGGRESSIVE LOGGING: Write to file AND stdout
  log_msg <- sprintf("[SERVER] %s - Server function called\n", Sys.time())
  cat(log_msg)
  try(writeLines(log_msg, "SERVER_LOG.txt", useBytes = TRUE), silent = TRUE)

  cat("===========================================\n")
  cat("[SERVER] Server function called - session started\n")
  cat("[SERVER] Timestamp:", as.character(Sys.time()), "\n")
  cat("===========================================\n")

  # Health check endpoint for Railway monitoring
  session$registerDataObj("health", list(status = "OK"), function(data, req) {
    list(status = 200L, headers = list("Content-Type" = "text/plain"), body = "OK")
  })
  cat("[SERVER] Health check endpoint registered\n")

  if (identical(Sys.getenv("APP_DEBUG"), "1")) {
    withCallingHandlers(
      {
        # Trigger initial renders that often fault when empty:
        session$onFlushed(function() {
          # no-op: ensures first render cycle completes so errors surface
        }, once = TRUE)
      },
      error = function(e) {
        diag_log_error(e, context = "first-render")
        stop(e)
      }
    )
  }

  # Load module servers with detailed logging
  cat("[SERVER INIT] Starting module server initialization...\n", file = stderr())

  if (safe_module_loaded("executive_summary") && exists("executive_summary_server")) {
    cat("[SERVER INIT] Calling executive_summary_server...\n", file = stderr())
    executive_summary_server(input, output, session)
    cat("[SERVER INIT] executive_summary_server completed\n", file = stderr())
  }

  if (safe_module_loaded("library") && exists("enhanced_library_server")) {
    cat("[SERVER INIT] Calling enhanced_library_server...\n", file = stderr())
    enhanced_library_server(input, output, session)
    cat("[SERVER INIT] enhanced_library_server completed\n", file = stderr())
  }

  if (safe_module_loaded("analytics") && exists("analytics_server")) {
    cat("[SERVER INIT] Calling analytics_server...\n", file = stderr())
    analytics_server(input, output, session)
    cat("[SERVER INIT] analytics_server completed\n", file = stderr())
  }

  if (safe_module_loaded("maps") && exists("map_server")) {
    cat("[SERVER INIT] Calling map_server...\n", file = stderr())
    map_server(input, output, session)
    cat("[SERVER INIT] map_server completed\n", file = stderr())
  }

  if (safe_module_loaded("sao_paulo") && exists("sao_paulo_server")) {
    cat("[SERVER INIT] Calling sao_paulo_server...\n", file = stderr())
    sao_paulo_server(input, output, session)
    cat("[SERVER INIT] sao_paulo_server completed\n", file = stderr())
  }

  cat("[SERVER INIT] All module servers initialized\n", file = stderr())

  # Fallback implementations for core functionality

  # System status output
  output$system_status <- safe_renderText({
    # Safe module count calculation
    modules_count <- tryCatch({
      loaded_values <- unlist(modules_loaded)
      if (is.null(loaded_values) || length(loaded_values) == 0) {
        0L
      } else {
        sum(loaded_values, na.rm = TRUE)
      }
    }, error = function(e) 0L)

    db_status <- if (exists("get_documents")) "Connected" else "Fallback Mode"

    paste(
      sprintf("Application: %s v%s", app_config$app_title %||% "Monitor Legislativo v4", app_config$app_version %||% "4.0.0"),
      sprintf("Environment: %s", app_config$environment %||% "unknown"),
      sprintf("Database: %s", db_status),
      sprintf("Modules Loaded: %s/%d", scalar_int(modules_count, 0L), length(modules_loaded)),
      sprintf("Last Updated: %s", format(Sys.time(), "%Y-%m-%d %H:%M:%S")),
      sep = "\n"
    )
  }, context = "system_status")

  # Value boxes (fallback implementations with scalar safety)
  output$total_docs <- shinydashboard::renderValueBox({
    cat("[RENDER] total_docs: START\n", file = stderr())
    tryCatch({
      metrics <- get_lexml_dashboard_metrics()
      cat(sprintf("[RENDER] total_docs: metrics$total_documents=%s (class=%s, length=%d)\n",
                  metrics$total_documents, class(metrics$total_documents), length(metrics$total_documents)), file = stderr())
      safe_valueBox(
        value = value_box_scalar(metrics$total_documents, default = 0, format_fn = function(x) format(x, big.mark = ",")),
        subtitle = "Total Documents",
        icon = icon("file-text"),
        color = "blue"
      )
    }, error = function(e) {
      safe_valueBox(value = "0", subtitle = "Total Documents", icon = icon("file-text"), color = "blue")
    })
  })

  output$states_covered <- shinydashboard::renderValueBox({
    cat("[RENDER] states_covered: START\n", file = stderr())
    tryCatch({
      metrics <- get_lexml_dashboard_metrics()
      cat(sprintf("[RENDER] states_covered: metrics$states_with_docs=%s (class=%s, length=%d)\n",
                  metrics$states_with_docs, class(metrics$states_with_docs), length(metrics$states_with_docs)), file = stderr())
      safe_valueBox(
        value = value_box_scalar(metrics$states_with_docs, default = 0),
        subtitle = "States Covered",
        icon = icon("map-marked"),
        color = "green"
      )
    }, error = function(e) {
      safe_valueBox(value = "0", subtitle = "States Covered", icon = icon("map-marked"), color = "green")
    })
  })

  output$municipalities_covered <- shinydashboard::renderValueBox({
    cat("[RENDER] municipalities_covered: START\n", file = stderr())
    tryCatch({
      metrics <- get_lexml_dashboard_metrics()
      cat(sprintf("[RENDER] municipalities_covered: metrics$municipalities_with_docs=%s (class=%s, length=%d)\n",
                  metrics$municipalities_with_docs, class(metrics$municipalities_with_docs), length(metrics$municipalities_with_docs)), file = stderr())
      safe_valueBox(
        value = value_box_scalar(metrics$municipalities_with_docs, default = 0, format_fn = function(x) format(x, big.mark = ",")),
        subtitle = "Municipalities",
        icon = icon("city"),
        color = "yellow"
      )
    }, error = function(e) {
      safe_valueBox(value = "0", subtitle = "Municipalities", icon = icon("city"), color = "yellow")
    })
  })

  # Fallback chart implementations
  output$state_chart <- renderPlotly({
    cat("[TRACE] app:state_chart start\n", file = stderr())
    tryCatch({
      data <- get_analytics_data()
      req(!is.null(data))
      req(is.data.frame(data))
      req(nrow(data) > 0)

      if (!is.null(data) && is.data.frame(data) && nrow(data) > 0) {
        chart_data <- prepare_chart_data(data, "geographic")
        req(!is.null(chart_data))
        req(is.data.frame(chart_data))
        req(nrow(chart_data) > 0)

        if (!is.null(chart_data) && is.data.frame(chart_data) && nrow(chart_data) > 0) {
          p <- ggplot(chart_data, aes(x = reorder(state, count), y = count)) +
            geom_bar(stat = "identity", fill = "#3498db") +
            labs(title = "Documents by State", x = "State", y = "Document Count") +
            coord_flip() + theme_minimal()
          ggplotly(p)
        } else {
          plotly_empty() %>% layout(title = "No geographic data available")
        }
      } else {
        plotly_empty() %>% layout(title = "Loading data...")
      }
    }, error = function(e) {
      plotly_empty() %>% layout(title = "Chart loading...")
    })
  })

  output$type_chart <- renderPlotly({
    cat("[TRACE] app:type_chart start\n", file = stderr())
    tryCatch({
      data <- get_analytics_data()
      req(!is.null(data))
      req(is.data.frame(data))
      req(nrow(data) > 0)

      if (!is.null(data) && is.data.frame(data) && nrow(data) > 0) {
        chart_data <- prepare_chart_data(data, "category")
        req(!is.null(chart_data))
        req(is.data.frame(chart_data))
        req(nrow(chart_data) > 0)

        if (!is.null(chart_data) && is.data.frame(chart_data) && nrow(chart_data) > 0) {
          p <- ggplot(chart_data, aes(x = reorder(category, count), y = count)) +
            geom_bar(stat = "identity", fill = "#e74c3c") +
            labs(title = "Documents by Category", x = "Category", y = "Document Count") +
            coord_flip() + theme_minimal()
          ggplotly(p)
        } else {
          plotly_empty() %>% layout(title = "No category data available")
        }
      } else {
        plotly_empty() %>% layout(title = "Loading data...")
      }
    }, error = function(e) {
      plotly_empty() %>% layout(title = "Chart loading...")
    })
  })

  # Document search functionality
  search_results <- eventReactive(input$search_btn, {
    search_text <- input$search_text %||% ""
    if (!is.null(search_text) && nchar(search_text) > 0) {
      filters <- list(search = search_text)
      get_documents(filters = filters, limit = 100)
    } else {
      get_documents(limit = 100)
    }
  })

  output$documents_table <- renderDT({
    if (isTRUE(input$search_btn > 0)) {
      datatable(
        search_results(),
        options = list(
          pageLength = 25,
          scrollX = TRUE,
          autoWidth = TRUE,
          columnDefs = list(list(width = '200px', targets = c(1, 2)))
        ),
        filter = "top",
        class = 'cell-border stripe'
      )
    } else {
      datatable(
        data.frame(
          Message = "Enter search terms and click Search to find documents",
          Instructions = "Use the search box above to explore the legislative database"
        ),
        options = list(dom = 't', ordering = FALSE),
        class = 'cell-border stripe'
      )
    }
  })

  # Basic Brazil map for maps tab fallback
  output$brazil_map <- renderLeaflet({
    if (requireNamespace("leaflet", quietly = TRUE)) {
      leaflet() %>%
        addTiles() %>%
        setView(lng = -47.8828, lat = -15.7942, zoom = 4) %>%
        addMarkers(lng = -47.8828, lat = -15.7942,
                  popup = "Brasília - Federal District<br>Center of Brazilian Government")
    } else {
      # Return empty div if leaflet not available
      NULL
    }
  })
}

# ============================================================================
# APPLICATION LAUNCH
# ============================================================================

cat("\n========================================\n")
cat("🚀 MONITOR LEGISLATIVO v4 - READY\n")
cat("========================================\n")
cat("📊 Modules Status:\n")
for (module_name in names(modules_loaded)) {
  status <- if (isTRUE(safe_module_loaded(module_name))) "✅ LOADED" else "⚠️  FALLBACK"
  cat(sprintf("   %s: %s\n", tools::toTitleCase(gsub("_", " ", module_name)), status))
}
db_launch_status <- if (exists("get_documents")) "CONNECTED" else "FALLBACK MODE"
cat(sprintf("🔗 Database: %s\n", db_launch_status))
cat(sprintf("🌍 Environment: %s\n", app_config$environment %||% "unknown"))
cat("========================================\n\n")

# Launch the application
shinyApp(ui = ui, server = server)
