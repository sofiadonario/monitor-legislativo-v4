# R/render_safety.R — low-noise global guards

# Helpers
scalar1 <- function(x) if (is.null(x) || length(x) == 0) NA else x[[1]]
fmt_int <- function(x) ifelse(is.na(x), "–", formatC(as.integer(x), big.mark=".", format="d"))

safe_wrap <- function(expr, fallback) {
  tryCatch(force(expr), error = function(e) fallback)
}

# Install once
if (is.null(getOption("mlv4.safe.render.installed"))) {
  options(mlv4.safe.render.installed = TRUE)

  # renderText
  renderText <- function(expr, env = parent.frame(), quoted = FALSE) {
    shiny::renderText({
      if (!quoted) expr <- substitute(expr)
      safe_wrap(eval(expr, env), fallback = "–")
    }, env, TRUE)
  }

  # renderUI
  renderUI <- function(expr, env = parent.frame(), quoted = FALSE) {
    shiny::renderUI({
      if (!quoted) expr <- substitute(expr)
      safe_wrap(eval(expr, env), fallback = div(""))
    }, env, TRUE)
  }

  # renderPlot
  renderPlot <- function(expr, width = "auto", height = "auto", res = 72, ..., env = parent.frame(), quoted = FALSE) {
    shiny::renderPlot({
      if (!quoted) expr <- substitute(expr)
      safe_wrap(eval(expr, env), fallback = NULL)
    }, width, height, res, ..., env = env, quoted = TRUE)
  }

  # Leaflet - skip wrapping (complex widget, rarely source of scalar errors)
  # if (requireNamespace("leaflet", quietly = TRUE)) {
  #   # Leaflet wrapping disabled - use validate(need()) in individual outputs
  # }

  # DT - handled by table_compat.R with renderSmartTable/smartTable
  # Skip direct wrapping to avoid "object DT not found" errors

  # shinydashboard valueBox (many apps build them inside renderUI)
  if (requireNamespace("shinydashboard", quietly = TRUE)) {
    shinydashboard::renderValueBox <- function(expr, env = parent.frame(), quoted = FALSE) {
      shiny::renderUI({
        if (!quoted) expr <- substitute(expr)
        safe_wrap({
          vb <- eval(expr, env)
          if (inherits(vb, "shiny.tag")) vb else {
            val <- scalar1(vb)
            shinydashboard::valueBox(fmt_int(val), "")
          }
        }, fallback = shinydashboard::valueBox("–", "", color = "yellow"))
      }, env, TRUE)
    }
  }
}
