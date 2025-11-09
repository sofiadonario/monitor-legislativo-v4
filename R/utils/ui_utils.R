## ---- Scalar utilities now sourced from R/utils/scalar_utils.R ----
# All scalar functions are loaded from the single source of truth

# ==============================================================================
# NAMESPACE-LEVEL SAFETY OVERRIDES (INJECTED FROM ui_utils.R)
# ==============================================================================
cat("🔧 Installing namespace-level safety overrides from ui_utils.R...\n", file = stderr())

# Override shiny::renderText at namespace level
if (requireNamespace("shiny", quietly = TRUE)) {
  tryCatch({
    shiny_ns <- asNamespace("shiny")
    if (exists("renderText", envir = shiny_ns)) {
      original_renderText <- get("renderText", envir = shiny_ns)
      unlockBinding("renderText", shiny_ns)
      assign(
        "renderText",
        function(expr, ..., env = parent.frame(), quoted = FALSE, outputArgs = list()) {
          safe_expr <- substitute({
            tryCatch({
              result <- expr
              if (is.null(result)) return("—")
              if (length(result) == 0) return("—")
              if (length(result) > 1) {
                cat("[renderText-NS-OVERRIDE] Vector leak (len:", length(result), ")\n", file = stderr())
                result <- result[1]
              }
              as.character(result)
            }, error = function(e) {
              cat("[renderText-NS-OVERRIDE] Error:", conditionMessage(e), "\n", file = stderr())
              "—"
            })
          }, list(expr = if (quoted) expr else substitute(expr)))
          original_renderText(expr = safe_expr, env = env, quoted = TRUE, outputArgs = outputArgs, ...)
        },
        envir = shiny_ns
      )
      lockBinding("renderText", shiny_ns)
      cat("✅ [ui_utils.R] shiny::renderText namespace override installed\n", file = stderr())
    }
  }, error = function(e) {
    cat("⚠️  [ui_utils.R] Failed to override renderText:", conditionMessage(e), "\n", file = stderr())
  })
}

# Override shiny::validateSingleValue to log and prevent crashes
if (requireNamespace("shiny", quietly = TRUE)) {
  tryCatch({
    shiny_ns <- asNamespace("shiny")
    cat("[DEBUG] Checking for validateSingleValue in shiny namespace...\n", file = stderr())

    # Check if validateSingleValue exists
    vsv_exists <- exists("validateSingleValue", envir = shiny_ns, inherits = FALSE)
    cat("[DEBUG] validateSingleValue exists:", vsv_exists, "\n", file = stderr())

    # Try different export methods
    if (!vsv_exists) {
      # Try without inherits restriction
      vsv_exists <- exists("validateSingleValue", envir = shiny_ns, inherits = TRUE)
      cat("[DEBUG] validateSingleValue with inherits=TRUE:", vsv_exists, "\n", file = stderr())
    }

    if (vsv_exists) {
      cat("[DEBUG] Attempting to override validateSingleValue...\n", file = stderr())
      original_validate <- get("validateSingleValue", envir = shiny_ns)
      unlockBinding("validateSingleValue", shiny_ns)
      assign("validateSingleValue", function(value, name, ...) {
        len <- length(value)
        if (len == 0L) {
          cat("[validateSingleValue-NS] CRITICAL:", name, "len=0 class=", paste(class(value), collapse = ","), "\n", file = stderr())
          cat("Stack:\n", paste(capture.output(sys.calls()), collapse = "\n"), "\n", file = stderr())

          fallback <- switch(typeof(value),
            "logical" = NA, "integer" = NA_integer_, "double" = NA_real_,
            "character" = "—", "—"
          )
          cat("[validateSingleValue-NS] Returning fallback:", fallback, "\n", file = stderr())
          return(fallback)
        }

        if (len > 1L) {
          cat("[validateSingleValue-NS]", name, "len=", len, "- taking first\n", file = stderr())
          value <- value[1L]
        }

        original_validate(value, name, ...)
      }, envir = shiny_ns)
      lockBinding("validateSingleValue", shiny_ns)
      cat("✅ [ui_utils.R] shiny::validateSingleValue namespace override installed\n", file = stderr())
    } else {
      cat("⚠️  [ui_utils.R] validateSingleValue NOT FOUND in shiny namespace\n", file = stderr())
      # List what IS in the namespace
      cat("[DEBUG] Shiny namespace contents related to 'validate':\n", file = stderr())
      shiny_names <- ls(envir = shiny_ns)
      validate_funcs <- grep("validate", shiny_names, ignore.case = TRUE, value = TRUE)
      cat(paste(validate_funcs, collapse = ", "), "\n", file = stderr())
    }
  }, error = function(e) {
    cat("⚠️  [ui_utils.R] Failed to override validateSingleValue:", conditionMessage(e), "\n", file = stderr())
    cat("[DEBUG] Error details:", e$message, "\n", file = stderr())
  })
}

cat("🔧 Namespace override installation from ui_utils.R complete\n", file = stderr())

# Additional UI-specific validation helper
require_rows <- function(df, msg = "Sem dados disponíveis") {
  shiny::validate(shiny::need(has_rows(df), msg)); df
}

default_selected <- function(choices, current = NULL) {
  if (length(current) == 1L && nzchar(as.character(current))) return(current)
  if (length(choices)) choices[[1L]] else NULL
}

## ---- Safe text matching (avoids grepl NA issues) ----
safe_grepl <- function(pattern, x, ignore.case = TRUE, ...) {
  # Replace NA with empty string before grepl
  x_safe <- ifelse(is.na(x), "", as.character(x))
  grepl(pattern, x_safe, ignore.case = ignore.case, ...)
}

## ---- Dual column name preservation ----
# Ensures both Portuguese and English column names exist for analytics compatibility
preserve_dual_column_names <- function(df) {
  if (!is.data.frame(df) || nrow(df) == 0) return(df)

  # Map of Portuguese -> English column names
  col_map <- list(
    titulo = "title",
    categoria = "category",
    estado = "state",
    data = "date",
    ementa = "summary",
    jurisdicao = "jurisdiction"
  )

  # Add English aliases if only Portuguese exists
  for (pt_name in names(col_map)) {
    en_name <- col_map[[pt_name]]
    if (pt_name %in% names(df) && !en_name %in% names(df)) {
      df[[en_name]] <- df[[pt_name]]
    }
  }

  # Add Portuguese aliases if only English exists
  for (pt_name in names(col_map)) {
    en_name <- col_map[[pt_name]]
    if (en_name %in% names(df) && !pt_name %in% names(df)) {
      df[[pt_name]] <- df[[en_name]]
    }
  }

  # Sanitize date column if present
  for (date_col in c("date", "data")) {
    if (date_col %in% names(df) && !is.null(df[[date_col]])) {
      df[[date_col]] <- as.Date(substr(as.character(df[[date_col]]), 1, 10))
    }
  }

  return(df)
}

.ml4_last_error <- NULL
diag_log_error <- function(e, context = NULL) {
  .ml4_last_error <<- list(
    time = Sys.time(),
    context = context %||% "",
    message = conditionMessage(e),
    call = tryCatch(deparse(conditionCall(e)), error = function(...) NA_character_),
    stack = utils::capture.output(sys.calls())
  )
  message("[diag] ", .ml4_last_error$message,
          if (nzchar(.ml4_last_error$context)) paste0(" @ ", .ml4_last_error$context))
}

## ---- Safe render wrappers (drop-in) ----
safe_renderText <- function(expr, default = "—", context = NULL) {
  shiny::renderText({
    val <- tryCatch(force(expr), error = function(e) { diag_log_error(e, context); default })

    output_info <- tryCatch(shiny::getCurrentOutputInfo(), error = function(...) NULL)
    output_id <- context %||% if (!is.null(output_info)) output_info$outputId else "<unknown>"

    value_len <- if (is.null(val)) 0L else length(val)
    if (value_len == 0L) {
      msg <- sprintf("[safe_renderText] %s produced length-0 value; using default '%s'", output_id, default)
      message(msg)
      append_len0_summary("safe_renderText", list(output_id = output_id, default = default, value = val))
    } else if (value_len > 1L) {
      msg <- sprintf("[safe_renderText] %s produced length-%d value; truncating", output_id, value_len)
      message(msg)
      append_len0_summary("safe_renderText_multi", list(output_id = output_id, value = val))
    }

    scalar_chr(val, default)
  })
}

safe_renderUI <- function(expr, fallback = shiny::div(), context = NULL) {
  shiny::renderUI({
    tryCatch(force(expr), error = function(e) { diag_log_error(e, context); fallback })
  })
}

safe_renderPlotly <- function(expr, context = NULL) {
  plotly::renderPlotly({
    output_info <- tryCatch(shiny::getCurrentOutputInfo(), error = function(...) NULL)
    output_id <- context %||% if (!is.null(output_info)) output_info$outputId else "<unknown>"

    # Suppress all output including C++ stderr (use capture.output for deeper suppression)
    tryCatch({
      result <- capture.output({
        suppressWarnings(suppressMessages({
          force(expr)
        }))
      }, type = "message")

      # Return last expression result (the plot)
      if (isTRUE(length(result) > 0) && inherits(result[[length(result)]], "plotly")) {
        result[[length(result)]]
      } else {
        # If capture.output consumed the plot, re-evaluate
        suppressWarnings(suppressMessages(force(expr)))
      }
    },
    error = function(e) {
      diag_log_error(e, context %||% output_id)
      plotly::plot_ly() # Return empty plot on error
    })
  })
}

safe_valueBox <- if (requireNamespace("shinydashboard", quietly = TRUE)) {
  local({
    orig <- get("valueBox", asNamespace("shinydashboard"))
    function(value, subtitle, icon = NULL, color = "aqua") {
      value <- scalar_chr(value)  # never length-0
      orig(value, subtitle, icon = icon, color = color)
    }
  })
} else {
  function(value, subtitle, icon = NULL, color = "aqua") {
    value <- scalar_chr(value)
    # Fallback: return a simple div
    div(
      style = "padding: 15px; border-radius: 4px;",
      h3(value),
      p(subtitle)
    )
  }
}

# Keep the old version for backward compatibility
safe_valueBox_old <- function(value, ..., default = "—") {
  safe_valueBox(scalar_chr(value, default), ...)
}

# Additional UI guards and safe renderers (append)

# Reusable validate/need guards
guard_nonempty_df <- function(df, msg = "Nenhum dado disponível") {
  validate(need(nz_rows(df), msg))
  invisible(TRUE)
}

guard_length1 <- function(x, msg = "Valor indisponível") {
  validate(need(nz_len(x), msg))
  invisible(TRUE)
}

# Safe wrappers for common renderers
renderValueBoxSafe <- function(expr, ...) {
  renderUI({
    out <- tryCatch(force(expr), error = function(e) {
      shiny::isolate({
        message(sprintf("[valuebox-safe] %s", conditionMessage(e)))
      })
      safe_valueBox("—", "Indisponível", color = "yellow")
    })
    out
  })
}

renderPlotlySafe <- function(expr, ...) {
  plotly::renderPlotly({
    tryCatch(force(expr), error = function(e) {
      shiny::isolate({
        message(sprintf("[plotly-safe] %s", conditionMessage(e)))
      })
      plotly::plot_ly() # empty but valid
    })
  })
}

# ============================================================================
# EMPTY STATE UI COMPONENTS (Added 2025-01-16)
# ============================================================================

#' Create empty state UI card
#' @param msg Message to display
#' @param icon Icon name (default: info-circle)
#' @return HTML div
empty_card <- function(msg = "Sem resultados. Ajuste os filtros.", icon = "info-circle") {
  shiny::div(
    class = "alert alert-info",
    style = "margin: 20px; padding: 15px; text-align: center;",
    shiny::icon(icon),
    " ",
    msg
  )
}

#' Create error state UI card
#' @param msg Error message to display
#' @return HTML div
error_card <- function(msg = "Erro ao carregar dados. Tente novamente.") {
  shiny::div(
    class = "alert alert-danger",
    style = "margin: 20px; padding: 15px; text-align: center;",
    shiny::icon("exclamation-triangle"),
    " ",
    msg
  )
}

#' Create loading state UI card
#' @param msg Loading message to display
#' @return HTML div
loading_card <- function(msg = "Carregando...") {
  shiny::div(
    class = "alert alert-secondary",
    style = "margin: 20px; padding: 15px; text-align: center;",
    shiny::icon("spinner", class = "fa-spin"),
    " ",
    msg
  )
}

#' Safe render wrapper with error handling
#' @param expr Expression to render
#' @param error_msg Error message to show users
#' @param empty_msg Message for empty results
#' @return Render function result or error UI
safe_render <- function(expr, error_msg = "Erro ao renderizar componente.", empty_msg = NULL) {
  tryCatch({
    result <- expr

    # Check for NULL/empty results
    if (is.null(result)) {
      if (!is.null(empty_msg)) {
        return(empty_card(empty_msg))
      }
      return(NULL)
    }

    # Check for empty data frames
    if (is.data.frame(result) && nrow(result) == 0) {
      if (!is.null(empty_msg)) {
        return(empty_card(empty_msg))
      }
      return(NULL)
    }

    result

  }, error = function(e) {
    log_error(sprintf("Render error: %s", conditionMessage(e)))
    error_card(error_msg)
  })
}

# ============================================================================
# UNIVERSAL RENDER WRAPPER (Added 2025-01-16 for Railway production)
# ============================================================================

#' Universal safe render wrapper with notification
#' Ensures misbehaving output never takes down the page
#' @param expr Expression to render
#' @param fallback Fallback value if error occurs
#' @param notify Whether to show notification on error
#' @param msg Notification message
#' @return Result or fallback
safe_render_universal <- function(expr, fallback = NULL, notify = TRUE, msg = "Falha ao renderizar. Ajuste filtros.") {
  tryCatch(
    force(expr),
    error = function(e) {
      if (notify) {
        shiny::showNotification(msg, type = "error", duration = 6)
      }
      log_error("Render failed:", conditionMessage(e))
      fallback
    }
  )
}

#' Safe renderText with universal wrapper
renderTextSafe <- function(expr, fallback = "–") {
  renderText(safe_render_universal(expr, fallback, notify = FALSE))
}

#' Safe renderValueBox with universal wrapper
renderValueBoxSafeUniversal <- function(expr, fallback_value = "–", fallback_subtitle = "Indisponível") {
  renderUI({
    safe_render_universal(
      expr,
      fallback = safe_valueBox(fallback_value, fallback_subtitle, color = "yellow", icon = icon("exclamation-triangle")),
      notify = TRUE
    )
  })
}
