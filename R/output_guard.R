# R/output_guard.R
with_output_guard <- function(expr, fallback = NULL, label = NULL) {
  tryCatch({
    # Try to identify the output
    out_id <- NA_character_
    # Shiny >= 1.8
    out_id <- tryCatch({
      info <- shiny::getCurrentOutputInfo()
      if (!is.null(info)) info$outputId else NA_character_
    }, error = function(e) NA_character_)
    # Log entry
    cat("[GUARD:ENTER]", if (is.null(label)) "" else paste0(label," "), "outputId=", out_id, "\n")
    val <- force(expr)

    # Log "shape" of value for quick hints (length-0 shows up here)
    shape <- tryCatch({
      if (is.null(val)) "NULL"
      else if (is.atomic(val) || is.list(val)) paste0("len=", length(val), " class=", paste(class(val), collapse="|"))
      else paste0("class=", paste(class(val), collapse="|"))
    }, error = function(e) "<?>")
    cat("[GUARD:VALUE] outputId=", out_id, " ", shape, "\n")
    val
  }, error = function(e) {
    # Best-effort output id (older shiny)
    out_id <- tryCatch({
      dom <- shiny::getDefaultReactiveDomain()
      if (!is.null(dom) && !is.null(dom$outputId)) dom$outputId else NA_character_
    }, error = function(e) NA_character_)
    cat("! OUTPUT CRASH:", conditionMessage(e), " outputId=", out_id,
        if (!is.null(label)) paste0(" label=", label) else "", "\n")
    flush.console()
    fallback
  })
}

# Minimal scalar+format helpers for fallbacks
scalar1 <- function(x) if (is.null(x) || length(x) == 0) NA else x[[1]]
fmt_int <- function(x) ifelse(is.na(x), "–", formatC(as.integer(x), big.mark=".", format="d"))
