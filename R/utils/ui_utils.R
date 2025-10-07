## ---- Scalar utilities now sourced from R/utils/scalar_utils.R ----
# All scalar functions are loaded from the single source of truth

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
    tryCatch(force(expr), error = function(e) { diag_log_error(e, context); plotly::plot_ly() })
  })
}

safe_valueBox <- local({
  orig <- get("valueBox", asNamespace("shinydashboard"))
  function(value, subtitle, icon = NULL, color = "aqua", width = 4) {
    value <- scalar_chr(value)  # never length-0
    orig(value, subtitle, icon = icon, color = color, width = width)
  }
})

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