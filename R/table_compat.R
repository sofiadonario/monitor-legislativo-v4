# R/table_compat.R — DT compatibility layer with smart fallbacks

# Check if DT is available
DT_AVAILABLE <- requireNamespace("DT", quietly = TRUE)

# Smart table renderer (falls back to base renderTable if DT absent)
renderSmartTable <- function(expr, env = parent.frame(), quoted = FALSE) {
  if (DT_AVAILABLE) {
    DT::renderDataTable(expr, env = env, quoted = quoted)
  } else {
    # Fallback to base renderTable
    shiny::renderTable(expr, env = env, quoted = quoted)
  }
}

# Smart datatable constructor (falls back to plain data.frame if DT absent)
smartTable <- function(data, ...) {
  if (DT_AVAILABLE) {
    DT::datatable(data, ...)
  } else {
    # Base table fallback: just return the data; renderTable will show it
    data
  }
}

# Export to global environment
assign("renderSmartTable", renderSmartTable, envir = .GlobalEnv)
assign("smartTable", smartTable, envir = .GlobalEnv)
assign("DT_AVAILABLE", DT_AVAILABLE, envir = .GlobalEnv)
