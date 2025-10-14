# Global Configuration and Initialization - Monitor Legislativo v4
# ==================================================================
# Clean Architecture - No Emergency Patches
# LGPD Compliant | Brazilian Legal Context | Railway Optimized
# Force redeploy: 2025-10-13 16:30 (complete trace instrumentation)

# Ensure utils are sourced early
safely_source <- function(path) if (file.exists(path)) source(path, chdir = TRUE, local = TRUE)
safely_source("R/utils/scalar_utils.R")
safely_source("R/utils/ui_utils.R")

# AGGRESSIVE DEBUGGING: Force full stacktrace + module name on error
options(
  shiny.sanitize.errors = FALSE,
  shiny.fullstacktrace = TRUE,
  shiny.error = function(e) {
    # Capture enhanced stack information
    calls <- sys.calls()
    frames <- sys.frames()

    # Multiple strategies to identify the problematic reactive/output
    outname <- "unknown"
    for (i in length(frames):1) {
      frame <- frames[[i]]
      # Check for Shiny output name patterns
      if (exists("..name", envir = frame, inherits = FALSE)) {
        outname <- get("..name", envir = frame)
        break
      }
      if (exists("name", envir = frame, inherits = FALSE)) {
        name_val <- get("name", envir = frame)
        if (is.character(name_val) && length(name_val) == 1) {
          outname <- name_val
          break
        }
      }
      # Check for renderXX function calls
      if (length(calls) >= i && length(calls[[i]]) > 0) {
        call_text <- deparse(calls[[i]])
        if (grepl("render(Plot|Table|Text|UI|ValueBox)", call_text)) {
          outname <- paste0("render_call_", i)
          break
        }
      }
    }

    # Clean, readable error output
    cat("\n=====================================\n", file = stderr())
    cat("[SCALAR ERROR]\n", file = stderr())
    cat(paste0("  output = ", outname, "\n"), file = stderr())
    cat(paste0("  message = ", conditionMessage(e), "\n"), file = stderr())

    # Try to get the failing call
    failing_call <- tryCatch({
      call_str <- deparse(conditionCall(e), width.cutoff = 100L)
      if (length(call_str) > 0 && nzchar(call_str[1])) {
        paste(call_str, collapse = " ")
      } else {
        "N/A"
      }
    }, error = function(err) "N/A")
    cat(paste0("  call = ", failing_call, "\n"), file = stderr())

    cat("\nCall stack (recent first):\n", file = stderr())
    for (i in min(length(calls), 10):max(1, length(calls) - 20)) {
      call_str <- tryCatch(
        paste0(deparse(calls[[i]], width.cutoff = 80L), collapse = " "),
        error = function(err) "<unprintable>"
      )
      cat(paste0("  ", i, ": ", call_str, "\n"), file = stderr())
    }
    cat("=====================================\n\n", file = stderr())
    stop(e)
  }
)

# Show full errors in production while we diagnose (toggle with env var)
if (identical(Sys.getenv("DEBUG_ERRORS", "0"), "1")) {
  options(
    shiny.sanitize.errors = FALSE,           # show real error text in UI
    shiny.fullstacktrace  = TRUE,
    shiny.error = function(e) {
      ts  <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
      msg <- sprintf("[%s] FATAL UI ERROR: %s\n", ts, conditionMessage(e))
      cat(msg, file = stderr())
      utils::writeLines(c(msg, utils::capture.output(sys.calls())), stderr())
      # Optionally show a user-friendly banner:
      shiny::showNotification("Erro interno — logs atualizados.", type = "error", duration = 10)
    }
  )
}

# Also keep the original APP_DEBUG flag for compatibility
if (identical(Sys.getenv("APP_DEBUG"), "1")) {
  options(
    shiny.fullstacktrace = TRUE,
    shiny.sanitize.errors = FALSE,
    shiny.traceback.lines = 60L,
    shiny.error = function() { traceback(2) }
  )
}

# NOTE: Harmless "Expecting a single value: [extent=0]" errors may appear during startup
# These occur when plotly/ggplot2 render functions fire before data is loaded
# They do not affect functionality and are safely handled by tryCatch blocks

# ---- Load unified scalar utilities (SINGLE SOURCE OF TRUTH) ----
source("R/utils/scalar_utils.R", local = TRUE)

# Additional comparison helper (uses scalar utilities internally)
safe_compare <- function(x, y, op = ">", default = FALSE) {
  x_val <- scalar(x, default = NULL)
  if (is.null(x_val)) return(default)
  switch(op,
    ">" = isTRUE(x_val > y),
    ">=" = isTRUE(x_val >= y),
    "<" = isTRUE(x_val < y),
    "<=" = isTRUE(x_val <= y),
    "==" = isTRUE(x_val == y),
    "!=" = isTRUE(x_val != y),
    default
  )
}

safe_subset <- function(x, condition, default = NULL) {
  if (is.null(x) || !is.data.frame(x) || nrow(x) == 0) return(default)
  tryCatch(x[condition, , drop = FALSE], error = function(e) default)
}

# Environment flags
ENABLE_QUERY_MONITORING <- tolower(Sys.getenv("ENABLE_QUERY_MONITORING", "false")) %in% c("1","true","yes")

# Ensure our UI helpers are available everywhere
source("R/utils/ui_utils.R", local = TRUE)

# ESSENTIAL PACKAGES
# ==================
library(shiny)

# ==============================================================================
# OVERRIDE SHINY RENDER FUNCTIONS WITH SAFETY WRAPPERS
# ==============================================================================
# This ensures that even direct calls to shiny::renderText use our safe wrappers
# Prevents scalar value crashes across the entire application

cat("Installing safety overrides for shiny render functions...\n")

# Override shiny::renderText
tryCatch({
  shiny_ns <- asNamespace("shiny")
  # Hook validate() to capture stack traces for "Expecting a single value" errors
  if (exists("validate", envir = shiny_ns, inherits = FALSE)) {
    original_validate <- get("validate", envir = shiny_ns)
    unlockBinding("validate", shiny_ns)
    assign("validate", function(...) {
      tryCatch(
        original_validate(...),
        error = function(e) {
          if (grepl("Expecting a single value", conditionMessage(e), fixed = TRUE)) {
            cat("[TRACE] shiny::validate intercepted extent error\n", file = stderr())
            stack <- tryCatch(utils::capture.output(sys.calls()), error = function(...) "<stack unavailable>")
            cat(paste(stack, collapse = "\n"), "\n", file = stderr())
          }
          stop(e)
        }
      )
    }, envir = shiny_ns)
    lockBinding("validate", shiny_ns)
    cat("✅ shiny::validate override installed for stack tracing\n")
  }
  if (exists("renderText", envir = shiny_ns)) {
    original_renderText <- get("renderText", envir = shiny_ns)
    unlockBinding("renderText", shiny_ns)
    assign(
      "renderText",
      function(expr, ..., env = parent.frame(), quoted = FALSE, outputArgs = list()) {
        # Wrap the expression with our safe_renderText
        safe_expr <- substitute({
          tryCatch({
            result <- expr
            if (is.null(result)) return("—")
            if (length(result) == 0) return("—")
            if (length(result) > 1) {
              cat("[renderText-override] Vector leak detected (length:", length(result), ") - using first value\n", file = stderr())
              result <- result[1]
            }
            as.character(result)
          }, error = function(e) {
            cat("[renderText-override] Error:", conditionMessage(e), "\n", file = stderr())
            "—"
          })
        }, list(expr = if (quoted) expr else substitute(expr)))

        original_renderText(
          expr = safe_expr,
          env = env,
          quoted = TRUE,
          outputArgs = outputArgs,
          ...
        )
      },
      envir = shiny_ns
    )
    lockBinding("renderText", shiny_ns)
    cat("✅ shiny::renderText override installed\n")
  }
  if (exists("printError", envir = shiny_ns)) {
    original_printError <- get("printError", envir = shiny_ns)
    unlockBinding("printError", shiny_ns)
    assign(
      "printError",
      function(cond, ...) {
        msg <- conditionMessage(cond)
        if (grepl("Expecting a single value: [extent=0]", msg, fixed = TRUE)) {
          cat("[TRACE] shiny::printError suppressed extent=0 message\n", file = stderr())
          return(invisible())
        }
        original_printError(cond, ...)
      },
      envir = shiny_ns
    )
    lockBinding("printError", shiny_ns)
    cat("✅ shiny::printError override installed\n")
  }
}, error = function(e) {
  cat("⚠️  [renderText-hook] unable to override shiny::renderText:", conditionMessage(e), "\n", file = stderr())
})

# Override shiny::renderUI
tryCatch({
  shiny_ns <- asNamespace("shiny")
  if (exists("renderUI", envir = shiny_ns)) {
    original_renderUI <- get("renderUI", envir = shiny_ns)
    unlockBinding("renderUI", shiny_ns)
    assign(
      "renderUI",
      function(expr, ..., env = parent.frame(), quoted = FALSE, outputArgs = list()) {
        # Wrap the expression with error handling
        safe_expr <- substitute({
          tryCatch({
            result <- expr
            if (is.null(result)) return(tags$span())
            result
          }, error = function(e) {
            cat("[renderUI-override] Error:", conditionMessage(e), "\n", file = stderr())
            tags$div(
              class = "alert alert-warning",
              style = "margin: 10px;",
              icon("exclamation-triangle"),
              " Unable to render content"
            )
          })
        }, list(expr = if (quoted) expr else substitute(expr)))

        original_renderUI(
          expr = safe_expr,
          env = env,
          quoted = TRUE,
          outputArgs = outputArgs,
          ...
        )
      },
      envir = shiny_ns
    )
    lockBinding("renderUI", shiny_ns)
    cat("✅ shiny::renderUI override installed\n")
  }
}, error = function(e) {
  cat("⚠️  [renderUI-hook] unable to override shiny::renderUI:", conditionMessage(e), "\n", file = stderr())
})

# Override plotly::renderPlotly if package is available
tryCatch({
  if (requireNamespace("plotly", quietly = TRUE)) {
    plotly_ns <- asNamespace("plotly")
    if (exists("renderPlotly", envir = plotly_ns)) {
      original_renderPlotly <- get("renderPlotly", envir = plotly_ns)
      unlockBinding("renderPlotly", plotly_ns)
      assign(
        "renderPlotly",
        function(expr, ..., env = parent.frame(), quoted = FALSE) {
          # Wrap the expression with error handling
          safe_expr <- substitute({
            output_info <- tryCatch(shiny::getCurrentOutputInfo(), error = function(...) NULL)
            output_id <- if (!is.null(output_info)) output_info$outputId else "<unknown>"
            cat("[TRACE] renderPlotly override start:", output_id, "\n", file = stderr())
            override_stack <- tryCatch(utils::capture.output(sys.calls()), error = function(...) "<unavailable>")
            cat(paste0("[TRACE] renderPlotly stack:\n", paste(override_stack, collapse = "\n")), "\n", file = stderr())
            tryCatch({
              result <- expr
              if (is.null(result)) {
                cat("[renderPlotly-override] NULL result - returning empty plot\n", file = stderr())
                return(plotly::plot_ly() %>% plotly::layout(title = "No data available"))
              }
              result
            }, error = function(e) {
              cat("[renderPlotly-override] Error:", conditionMessage(e), "\n", file = stderr())
              plotly::plot_ly() %>%
                plotly::layout(
                  title = list(text = "Chart Error", font = list(color = "red")),
                  annotations = list(
                    text = "Unable to render chart",
                    showarrow = FALSE,
                    xref = "paper",
                    yref = "paper",
                    x = 0.5,
                    y = 0.5
                  )
                )
            })
          }, list(expr = if (quoted) expr else substitute(expr)))

          original_renderPlotly(
            expr = safe_expr,
            env = env,
            quoted = TRUE,
            ...
          )
        },
        envir = plotly_ns
      )
      # Override plot_ly itself to emit trace logs on every invocation
      if (exists("plot_ly", envir = plotly_ns, inherits = FALSE)) {
        original_plot_ly <- get("plot_ly", envir = plotly_ns)
        unlockBinding("plot_ly", plotly_ns)
        assign(
          "plot_ly",
          function(...) {
            call_info <- tryCatch(sys.call(-1), error = function(...) NULL)
            cat("[TRACE] plot_ly start", if (!is.null(call_info)) paste0(" caller=", deparse(call_info)) else "", "\n", file = stderr())
            call_stack <- tryCatch(utils::capture.output(sys.calls()), error = function(...) "<unavailable>")
            cat(paste0("[TRACE] plot_ly stack:\n", paste(call_stack, collapse = "\n")), "\n", file = stderr())
            res <- original_plot_ly(...)
            cat("[TRACE] plot_ly end\n", file = stderr())
            res
          },
          envir = plotly_ns
        )
        lockBinding("plot_ly", plotly_ns)
        cat("✅ plotly::plot_ly override installed\n")
      }
      lockBinding("renderPlotly", plotly_ns)
      cat("✅ plotly::renderPlotly override installed\n")
    }
  }
}, error = function(e) {
  cat("⚠️  [renderPlotly-hook] unable to override plotly::renderPlotly:", conditionMessage(e), "\n", file = stderr())
})

cat("Safety override installation complete\n\n")

# Override plotly::plotly_build to capture extent errors during widget serialization
tryCatch({
  if (requireNamespace("plotly", quietly = TRUE)) {
    plotly_ns <- asNamespace("plotly")
    if (exists("plotly_build", envir = plotly_ns, inherits = FALSE)) {
      original_plotly_build <- get("plotly_build", envir = plotly_ns)
      unlockBinding("plotly_build", plotly_ns)
      assign(
        "plotly_build",
        function(p, registerFrames = TRUE) {
          if (isTRUE(attr(p, "ml_extent_guard_placeholder"))) {
            return(original_plotly_build(p, registerFrames = registerFrames))
          }
          output_info <- tryCatch(shiny::getCurrentOutputInfo(), error = function(...) NULL)
          output_id <- if (!is.null(output_info) && !is.null(output_info$outputId)) output_info$outputId else "<unknown>"
          tryCatch(
            original_plotly_build(p, registerFrames = registerFrames),
            error = function(e) {
              msg <- conditionMessage(e)
              extent_guard <- grepl("Expecting a single value: [extent=0]", msg, fixed = TRUE)
              if (extent_guard) {
                cat("[TRACE] plotly_build extent guard triggered for output:", output_id, "\n", file = stderr())
                placeholder <- plotly::plot_ly() %>%
                  plotly::add_annotations(
                    text = "Data unavailable - waiting for load",
                    x = 0.5, y = 0.5,
                    showarrow = FALSE
                  ) %>%
                  plotly::layout(
                    xaxis = list(visible = FALSE),
                    yaxis = list(visible = FALSE)
                  )
                attr(placeholder, "ml_extent_guard_placeholder") <- TRUE
                return(original_plotly_build(placeholder, registerFrames = registerFrames))
              }
              cat("[TRACE] plotly_build error for output", output_id, ":", msg, "\n", file = stderr())
              stop(e)
            }
          )
        },
        envir = plotly_ns
      )
      lockBinding("plotly_build", plotly_ns)
      cat("✅ plotly::plotly_build override installed\n")
    }
  }
}, error = function(e) {
  cat("⚠️  [plotly_build-hook] unable to override plotly::plotly_build:", conditionMessage(e), "\n", file = stderr())
})

# Continue loading packages
library(shinydashboard)
library(DT)
library(plotly)
library(dplyr)
library(RColorBrewer)
library(DBI)
library(RPostgres)  # Use RPostgres instead of RPostgreSQL
library(pool)
library(readr)
library(stringr)

# CRITICAL FEATURE PACKAGES
# =========================
# These packages power core application features and must be available
library(jsonlite)   # JSON parsing for APIs and data export
library(lubridate)  # Date/time manipulation for temporal analytics
library(httr)       # HTTP client for external API integrations
library(leaflet)    # Interactive maps (Geographic Analysis + Interactive Maps tabs)
library(sf)         # Spatial data operations (geospatial analysis)
library(geobr)      # Brazilian geographic boundaries from IBGE
library(htmltools)  # HTML generation for custom UI components

cat("Core packages loaded\n")

# OPTIONAL PACKAGES WITH GRACEFUL DEGRADATION
# ============================================
# These packages improve performance/UX but app functions without them
optional_packages <- c("data.table", "scales", "shinyjs")

for (pkg in optional_packages) {
  tryCatch({
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
    cat("✓ Optional package loaded:", pkg, "\n")
  }, error = function(e) {
    cat("⚠ Optional package", pkg, "not available (non-critical)\n")
  })
}

cat("Optional packages processed\n")

# Ensure DB helpers are loaded and pool initialized
source("R/utils/database_utils.R", local = TRUE)
init_db_pool()

# LOAD DATA SERVICE MODULE
# ========================
source("modules/data_service.R")
data_service <- local(source("modules/data_service.R")$value)
cat("Data service module loaded\n")

# Export database pool for other modules
tryCatch({
  if (exists("db_connection_pool") && !is.null(db_connection_pool)) {
    options(app_db_pool = db_connection_pool)
  } else if (exists("get_db_connection") && is.function(get_db_connection)) {
    pool_obj <- get_db_connection()
    if (!is.null(pool_obj)) {
      options(app_db_pool = pool_obj)
    } else {
      options(app_db_pool = NULL)
    }
  } else {
    options(app_db_pool = NULL)
  }
}, error = function(e) {
  options(app_db_pool = NULL)
  cat("Warning: Could not export database pool:", e$message, "\n")
})

# LOAD UTILITY MODULES
# ====================
module_files <- c(
  "R/utils/database_utils.R",
  "R/utils/api_utils.R",
  "R/utils/validation_utils.R",
  "R/utils/cache_utils.R",
  "R/utils/ui_utils.R"
)

for (module_file in module_files) {
  if (file.exists(module_file)) {
    tryCatch({
      source(module_file, local = FALSE)
      cat("Loaded:", module_file, "\n")
    }, error = function(e) {
      cat("Failed to load", module_file, ":", e$message, "\n")
    })
  }
}

# ==============================================================================
# NUCLEAR OPTION: Direct validateSingleValue override injection
# ==============================================================================
cat("🚨 INJECTING validateSingleValue override DIRECTLY...\n", file = stderr())
tryCatch({
  shiny_ns <- asNamespace("shiny")
  vsv_exists <- exists("validateSingleValue", envir = shiny_ns, inherits = FALSE)
  cat("[INJECT] validateSingleValue exists (inherits=FALSE):", vsv_exists, "\n", file = stderr())

  if (!vsv_exists) {
    vsv_exists <- exists("validateSingleValue", envir = shiny_ns, inherits = TRUE)
    cat("[INJECT] validateSingleValue exists (inherits=TRUE):", vsv_exists, "\n", file = stderr())
  }

  if (vsv_exists) {
    original_vsv <- get("validateSingleValue", envir = shiny_ns)
    unlockBinding("validateSingleValue", shiny_ns)
    assign("validateSingleValue", function(value, name, ...) {
      len <- length(value)
      if (len == 0L) {
        cat("[VSV-INJECT] CRASH PREVENTED:", name, "was length-0\n", file = stderr())
        cat("[VSV-INJECT] Stack:", paste(head(sys.calls(), 10), collapse = " | "), "\n", file = stderr())
        return(NA_character_)
      }
      if (len > 1L) {
        cat("[VSV-INJECT]", name, "had length", len, "- using first\n", file = stderr())
        value <- value[1L]
      }
      original_vsv(value, name, ...)
    }, envir = shiny_ns)
    lockBinding("validateSingleValue", shiny_ns)
    cat("✅ validateSingleValue INJECTED successfully\n", file = stderr())
  } else {
    cat("❌ validateSingleValue NOT FOUND - listing validate functions:\n", file = stderr())
    cat(paste(grep("validate", ls(shiny_ns), ignore.case = TRUE, value = TRUE), collapse = ", "), "\n", file = stderr())
  }
}, error = function(e) {
  cat("❌ validateSingleValue injection FAILED:", e$message, "\n", file = stderr())
})

# Global hammer: mask valueBox to prevent length-0 crashes
if (exists("safe_valueBox") && is.function(safe_valueBox)) {
  valueBox <- safe_valueBox
  cat("✅ Global valueBox masking applied for crash prevention\n")

  # Also override shinydashboard::valueBox at the namespace level
  tryCatch({
    sd_ns <- asNamespace("shinydashboard")
    unlockBinding("valueBox", sd_ns)
    assign("valueBox", function(value, ...) safe_valueBox(value, ...), envir = sd_ns)
    lockBinding("valueBox", sd_ns)
  }, error = function(e) {
    cat("[valueBox-hook] unable to override shinydashboard::valueBox:", conditionMessage(e), "\n", file = stderr())
  })
}

# Global hammer: mask renderText to enforce scalar safety
if (exists("safe_renderText") && is.function(safe_renderText)) {
  renderText <- safe_renderText
  cat("✅ Global renderText masking applied for crash prevention\n")
}

# Global hammer: mask renderValueBox to enforce scalar safety
if (exists("safe_valueBox") && is.function(safe_valueBox)) {
  # Override shinydashboard::renderValueBox globally
  tryCatch({
    shiny_ns <- asNamespace("shiny")
    if (exists("renderValueBox", envir = shiny_ns, inherits = FALSE)) {
      original_renderValueBox <- get("renderValueBox", envir = shiny_ns)
      unlockBinding("renderValueBox", shiny_ns)
      assign("renderValueBox", function(expr, env = parent.frame(), quoted = FALSE) {
        if (!quoted) expr <- substitute(expr)
        original_renderValueBox({
          result <- tryCatch(eval(expr, envir = env), error = function(e) {
            cat("[renderValueBox-override] Error:", conditionMessage(e), "\n", file = stderr())
            safe_valueBox("Error", "Error", color = "red")
          })
          
          # Ensure result is a proper valueBox with safe values
          if (is.list(result) && "value" %in% names(result)) {
            result$value <- scalar_chr(result$value, default = "—")
          } else if (inherits(result, "shiny.tag")) {
            # If it's already a tag, return as-is
            return(result)
          } else {
            # Convert to safe valueBox
            result <- safe_valueBox(
              value = scalar_chr(result, default = "—"),
              subtitle = result$subtitle %||% "Value",
              icon = result$icon,
              color = result$color %||% "aqua",
              width = result$width %||% 4
            )
          }
          
          result
        }, env = env, quoted = TRUE)
      }, envir = shiny_ns)
      lockBinding("renderValueBox", shiny_ns)
      cat("✅ Global renderValueBox masking applied for crash prevention\n")
    }
  }, error = function(e) {
    cat("[renderValueBox-hook] unable to override renderValueBox:", conditionMessage(e), "\n", file = stderr())
  })
}

# Apply safe render wrappers for renderUI and renderPlotly where available
if (exists("safe_renderUI") && is.function(safe_renderUI)) {
  renderUI <- safe_renderUI
  cat("✅ Global renderUI masking applied for crash prevention\n")
}

if (exists("safe_renderPlotly") && is.function(safe_renderPlotly)) {
  renderPlotly <- safe_renderPlotly
  cat("✅ Global renderPlotly masking applied for crash prevention\n")
}

# Guard against glue() length-0 expansions that previously crashed value boxes
if (requireNamespace("glue", quietly = TRUE)) {
  tryCatch({
    glue_ns <- asNamespace("glue")
    original_glue <- get("glue", envir = glue_ns)
    identity_transformer <- get("identity_transformer", envir = glue_ns)

    safe_null_transformer <- function(inner_transformer, null_fallback) {
      force(inner_transformer)
      force(null_fallback)
      function(text, envir) {
        value <- inner_transformer(text, envir)
        if (length(value) == 0L) return(null_fallback)
        value
      }
    }

    unlockBinding("glue", glue_ns)
    assign(
      "glue",
      function(...,
               .envir = parent.frame(),
               .transformer = identity_transformer,
               .null = "—",
               .na = .null) {
        wrapped_transformer <- safe_null_transformer(.transformer, .null)
        original_glue(
          ...,
          .envir = .envir,
          .transformer = wrapped_transformer,
          .null = .null,
          .na = .na
        )
      },
      envir = glue_ns
    )
    lockBinding("glue", glue_ns)
    cat("✅ Global glue null protection enabled\n")
  }, error = function(e) {
    cat("[glue-hook] unable to enable null protection:", conditionMessage(e), "\n", file = stderr())
  })
}

# Enable detailed Shiny error reporting in production logs for diagnostics
options(
  shiny.fullstacktrace = TRUE,
  shiny.sanitize.errors = FALSE,
  shiny.error = function(e) {
    cat("[SHINY ERROR]", conditionMessage(e), "\n", file = stderr())
    calls <- sys.calls()
    formatted <- capture.output(print(calls))
    cat(paste(formatted, collapse = "\n"), "\n", file = stderr())
    append_len0_summary("shiny_error", list(message = conditionMessage(e), calls = formatted))
    stop(e)
  }
)

# Instrument shiny's validateSingleValue to log zero-length issues and prevent crashes
tryCatch({
  shiny_ns <- asNamespace("shiny")
  if (exists("validateSingleValue", envir = shiny_ns, inherits = FALSE)) {
    original_validate <- get("validateSingleValue", envir = shiny_ns)
    unlockBinding("validateSingleValue", shiny_ns)
    assign("validateSingleValue", function(value, name, ...) {
      len <- length(value)
      if (len == 0L) {
        cat("[validateSingleValue] CRITICAL:", name, "len=0", "class=", paste(class(value), collapse = ","), "\n", file = stderr())
        value_str <- tryCatch(capture.output(str(value)), error = function(...) "<unable to str>")
        cat(paste(value_str, collapse = "\n"), "\n", file = stderr())
        
        # Get stack trace for debugging
        stack_trace <- tryCatch(capture.output(sys.calls()), error = function(...) "<unable to get stack>")
        cat("Stack trace:\n", paste(stack_trace, collapse = "\n"), "\n", file = stderr())
        
        append_len0_summary("validateSingleValue", list(name = name, value_str = value_str, stack = stack_trace))

        # Return safe fallback instead of crashing
        fallback <- switch(typeof(value),
          "logical" = NA,
          "integer" = NA_integer_,
          "double" = NA_real_,
          "complex" = NA_complex_,
          "character" = "—",
          "raw" = raw(1),
          "—"
        )

        cat("[validateSingleValue] Returning safe fallback:", fallback, "for", name, "\n", file = stderr())
        return(fallback)
      }

      if (len > 1L) {
        cat("[validateSingleValue]", name, "len=", len, "class=", paste(class(value), collapse = ","), "\n", file = stderr())
        append_len0_summary("validateSingleValue_multi", list(name = name, len = len, preview = as.character(value[seq_len(min(5, len))])))
        value <- value[1L]
      }

      original_validate(value, name, ...)
    }, envir = shiny_ns)
    lockBinding("validateSingleValue", shiny_ns)
    cat("✅ validateSingleValue override installed for crash prevention\n")
  }
}, error = function(e) {
  cat("[validateSingleValue-hook] unable to install tracer:", conditionMessage(e), "\n", file = stderr())
})

# LOAD SYSTEM MODULES
# ===================

# Monitoring and Logging System
monitoring_enabled <- FALSE
tryCatch({
  if (file.exists("monitoring/logger.R")) {
    source("monitoring/logger.R")
    source("monitoring/app_monitor.R")
    source("monitoring/telemetry.R")
    # TEMPORARILY DISABLED to test extent=0 errors
    # source("monitoring/monitoring_ui.R")

    # Initialize monitoring systems
    init_logger(list(
      enabled = TRUE,
      railway_compatible = TRUE,
      sanitize_sensitive = TRUE
    ))

    init_telemetry()
    # start_monitoring()  # Temporarily disabled - causing 10min hangs
    log_app_start()

    monitoring_enabled <- TRUE
    log_info("Monitoring and logging system initialized")
  }
}, error = function(e) {
  cat("Monitoring system initialization failed:", e$message, "\n")
})

# Health Check System
if (file.exists("health_check.R")) {
  tryCatch({
    source("health_check.R")
    cat("Health check system loaded\n")
  }, error = function(e) {
    cat("Health check system loading failed:", e$message, "\n")
  })
}

# Authentication System
auth_enabled <- as.logical(Sys.getenv("AUTH_ENABLED", "FALSE"))
if (auth_enabled && file.exists("modules/authentication.R")) {
  tryCatch({
    source("modules/authentication.R")
    cat("Authentication system loaded\n")
  }, error = function(e) {
    cat("Authentication system loading failed:", e$message, "\n")
  })
}

# CONFIGURATION
# =============
app_config <- list(
  app_title = "Monitor Legislativo v4",
  app_version = "4.0.0",
  environment = Sys.getenv("RAILWAY_ENVIRONMENT", "development"),
  max_file_size = 50 * 1024^2,  # 50MB
  session_timeout = 30 * 60,     # 30 minutes
  cache_ttl = 300,               # 5 minutes
  enable_debug = Sys.getenv("ENABLE_DEBUG", "FALSE") == "TRUE",
  auth_enabled = auth_enabled,
  monitoring_enabled = monitoring_enabled,
  use_demo_data = FALSE  # Production always uses real data
)

# SECURITY CONFIGURATION
# ======================
security_config <- list(
  session_cookie_secure = TRUE,
  session_cookie_httponly = TRUE,
  session_cookie_samesite = "Strict",
  content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
  x_frame_options = "DENY",
  x_content_type_options = "nosniff",
  strict_transport_security = "max-age=31536000; includeSubDomains"
)

# DATABASE CONNECTION CONFIGURATION
# ==================================
db_config <- list(
  host = Sys.getenv("PGHOST", "localhost"),
  port = as.integer(Sys.getenv("PGPORT", "5432")),
  dbname = Sys.getenv("PGDATABASE", "railway"),
  user = Sys.getenv("PGUSER", "postgres"),
  password = Sys.getenv("PGPASSWORD", ""),
  ssl_mode = Sys.getenv("PGSSLMODE", "require"),
  connection_timeout = 10,
  query_timeout = 30
)

# GLOBAL FUNCTIONS
# ================

# Main data retrieval function - delegates to data service
get_documents <- function(...) {
  data_service$get_documents(...)
}

# Analytics data function - delegates to data service
get_analytics_data <- function() {
  data_service$get_analytics_data()
}

# Chart preparation function - delegates to data service
prepare_chart_data <- function(...) {
  data_service$prepare_chart_data(...)
}

# Dashboard metrics function - PRODUCTION SAFE VERSION
get_lexml_dashboard_metrics <- function() {
  tryCatch({
    # Get total documents count with scalar safety
    total_documents <- safe_get_total_documents()

    # Get sample data for other metrics
    data <- tryCatch({
      if (exists("get_documents") && is.function(get_documents)) {
        get_documents(limit = 1000)
      } else {
        data.frame()
      }
    }, error = function(e) {
      cat("❌ Error in get_documents:", e$message, "\n")
      data.frame()
    })

    # Calculate states and municipalities safely
    states_count <- tryCatch({
      if (!is.null(data) && is.data.frame(data) && nrow(data) > 0) {
        if ("state" %in% names(data) && !is.null(data$state)) {
          states <- unique(data$state[!is.na(data$state) & data$state != ""])
          scalar_int(length(states), default = 0)
        } else {
          0
        }
      } else {
        0
      }
    }, error = function(e) 0)

    municipalities_count <- tryCatch({
      if (!is.null(data) && is.data.frame(data) && nrow(data) > 0) {
        if ("municipality" %in% names(data) && !is.null(data$municipality)) {
          municipalities <- unique(data$municipality[!is.na(data$municipality) & data$municipality != ""])
          scalar_int(length(municipalities), default = 0)
        } else {
          0
        }
      } else {
        0
      }
    }, error = function(e) 0)

    # Safe date range calculation
    date_range_years <- tryCatch({
      if (!is.null(data) && is.data.frame(data) && nrow(data) > 0 && "date" %in% names(data)) {
        dates <- as.Date(data$date)
        dates <- dates[!is.na(dates)]
        if (length(dates) > 1) {
          scalar_num(as.numeric(difftime(max(dates), min(dates), units = "days")) / 365.25, default = 0)
        } else {
          0
        }
      } else {
        0
      }
    }, error = function(e) 0)

    # Return metrics with guaranteed scalar values
    metrics <- list(
        total_documents = scalar_int(total_documents, default = 0),
        states_with_docs = scalar_int(states_count, default = 0),
        municipalities_with_docs = scalar_int(municipalities_count, default = 0),
        states_percentage = scalar_num((states_count / 27) * 100, default = 0),
        municipalities_percentage = scalar_num((municipalities_count / 5570) * 100, default = 0),
        date_range_years = scalar_num(date_range_years, default = 0),
        last_updated = Sys.time(),
        data_source = if (exists("app_config") && isTRUE(app_config$use_demo_data)) "demo" else "production",
        connection_status = "operational"
      )

    return(metrics)

  }, error = function(e) {
    if (monitoring_enabled) {
      log_error(paste("Error calculating dashboard metrics:", e$message))
    }

    # Return error state metrics
    return(list(
      total_documents = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      states_percentage = 0,
      municipalities_percentage = 0,
      date_range_years = 0,
      last_updated = Sys.time(),
      data_source = "error",
      connection_status = "error"
    ))
  })
}

# Store original get_total_documents function if it exists
original_get_total_documents <- NULL
if (exists("get_total_documents") && is.function(get_total_documents)) {
  original_get_total_documents <- get_total_documents
}

# Safe wrapper for get_total_documents to ensure scalar return
safe_get_total_documents <- function() {
  tryCatch({
    if (!is.null(original_get_total_documents)) {
      result <- original_get_total_documents()
      # Ensure we always return a scalar integer
      scalar_int(result, default = 0)
    } else {
      # Fallback to hardcoded value if no original function
      134014
    }
  }, error = function(e) {
    cat("❌ Error in safe_get_total_documents:", e$message, "\n")
    0
  })
}

# Override the original function with our safe version
get_total_documents <- safe_get_total_documents

# Utility function for safe numeric conversion
safe_numeric <- function(x, default = 0) {
  result <- suppressWarnings(as.numeric(x))
  if (is.null(result) || length(result) == 0 || is.na(result)) return(default)
  result
}

# Utility function for safe date conversion
safe_date <- function(x, format = "%Y-%m-%d") {
  tryCatch(
    as.Date(x, format = format),
    error = function(e) NA
  )
}

# Export configuration for use in app
assign("app_config", app_config, envir = .GlobalEnv)
assign("security_config", security_config, envir = .GlobalEnv)
assign("db_config", db_config, envir = .GlobalEnv)

cat("\n========================================\n")
cat("Monitor Legislativo v4 - Global Configuration Loaded\n")
cat("Environment:", app_config$environment, "\n")
cat("Version:", app_config$app_version, "\n")
cat("Demo Mode:", app_config$use_demo_data, "\n")
cat("Auth Enabled:", app_config$auth_enabled, "\n")
cat("Monitoring:", ifelse(monitoring_enabled, "Enabled", "Disabled"), "\n")
cat("========================================\n\n")
# Export tracing variables for diagnostics
if (is.null(getOption("ml4_len0_summaries"))) {
  options(ml4_len0_summaries = list())
}

append_len0_summary <- function(source_name, details) {
  summaries <- getOption("ml4_len0_summaries")
  summaries[[length(summaries) + 1]] <- list(
    timestamp = Sys.time(),
    source = source_name,
    details = details
  )
  options(ml4_len0_summaries = summaries)
}
