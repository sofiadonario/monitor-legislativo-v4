# R/table_compat.R — Package compatibility layer with smart fallbacks

# ============================================================================
# DT COMPATIBILITY
# ============================================================================
DT_AVAILABLE <- requireNamespace("DT", quietly = TRUE)

renderSmartTable <- function(expr, env = parent.frame(), quoted = FALSE) {
  if (DT_AVAILABLE) {
    DT::renderDataTable(expr, env = env, quoted = quoted)
  } else {
    # Fallback to base renderTable
    shiny::renderTable(expr, env = env, quoted = quoted)
  }
}

smartTable <- function(data, ...) {
  if (DT_AVAILABLE) {
    DT::datatable(data, ...)
  } else {
    # Base table fallback: just return the data; renderTable will show it
    data
  }
}

# ============================================================================
# SHINYDASHBOARD COMPATIBILITY
# ============================================================================
SD_AVAILABLE <- requireNamespace("shinydashboard", quietly = TRUE)

valueBox_safe <- function(value, subtitle = "", icon = NULL, color = "aqua") {
  if (SD_AVAILABLE) {
    shinydashboard::valueBox(value, subtitle, icon = icon, color = color)
  } else {
    # Graceful fallback - simple HTML box
    shiny::div(
      class = "valuebox-fallback",
      style = "border:1px solid #ddd;padding:12px;border-radius:10px;background:#f8f9fa;",
      shiny::h3(as.character(value), style = "margin:0;"),
      shiny::p(subtitle, style = "margin:5px 0 0 0;color:#666;")
    )
  }
}

# Export to global environment
assign("DT_AVAILABLE", DT_AVAILABLE, envir = .GlobalEnv)
assign("renderSmartTable", renderSmartTable, envir = .GlobalEnv)
assign("smartTable", smartTable, envir = .GlobalEnv)
assign("SD_AVAILABLE", SD_AVAILABLE, envir = .GlobalEnv)
assign("valueBox_safe", valueBox_safe, envir = .GlobalEnv)
