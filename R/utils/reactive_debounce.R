# =============================================================================
# Reactive Debouncing Utility Functions
# =============================================================================
# Phase 2: Performance Optimization - Task 2.5
# Debouncing and throttling for reactive inputs to reduce server load
# =============================================================================

#' Debounce a reactive expression
#'
#' @param reactive_expr Reactive expression to debounce
#' @param delay_ms Integer, delay in milliseconds (default 500)
#' @return Debounced reactive expression
#'
#' @examples
#' search_input <- textInput("search", "Search")
#' debounced_search <- debounce_reactive(input$search, delay_ms = 500)
debounce_reactive <- function(reactive_expr, delay_ms = 500) {
  if (!requireNamespace("shiny", quietly = TRUE)) {
    stop("Package 'shiny' is required for debouncing")
  }

  shiny::debounce(reactive_expr, delay_ms)
}

#' Throttle a reactive expression
#'
#' @param reactive_expr Reactive expression to throttle
#' @param delay_ms Integer, delay in milliseconds (default 1000)
#' @return Throttled reactive expression
#'
#' @examples
#' filter_input <- selectInput("filter", "Filter", choices)
#' throttled_filter <- throttle_reactive(input$filter, delay_ms = 1000)
throttle_reactive <- function(reactive_expr, delay_ms = 1000) {
  if (!requireNamespace("shiny", quietly = TRUE)) {
    stop("Package 'shiny' is required for throttling")
  }

  shiny::throttle(reactive_expr, delay_ms)
}

#' Create loading state reactive
#'
#' @param trigger_reactive Reactive that triggers loading state
#' @return ReactiveValues object with loading and error states
#'
#' @examples
#' loading_state <- create_loading_state(input$search)
#' observe({
#'   loading_state$loading <- TRUE
#'   result <- fetch_data()
#'   loading_state$loading <- FALSE
#' })
create_loading_state <- function(trigger_reactive = NULL) {
  if (!requireNamespace("shiny", quietly = TRUE)) {
    stop("Package 'shiny' is required for loading state")
  }

  shiny::reactiveValues(
    loading = FALSE,
    error = NULL,
    last_update = Sys.time()
  )
}

#' Wrap reactive with loading indicator
#'
#' @param reactive_expr Reactive expression to wrap
#' @param loading_state ReactiveValues object with loading state
#' @param error_handler Function to handle errors (optional)
#' @return Wrapped reactive expression with loading handling
#'
#' @examples
#' loading_state <- reactiveValues(loading = FALSE)
#' data <- with_loading_indicator(
#'   reactive({ fetch_data(input$search) }),
#'   loading_state
#' )
with_loading_indicator <- function(reactive_expr, loading_state, error_handler = NULL) {
  if (!requireNamespace("shiny", quietly = TRUE)) {
    stop("Package 'shiny' is required for loading indicators")
  }

  shiny::reactive({
    loading_state$loading <- TRUE
    loading_state$error <- NULL

    result <- tryCatch({
      value <- reactive_expr()
      loading_state$last_update <- Sys.time()
      value
    }, error = function(e) {
      loading_state$error <- e$message
      if (!is.null(error_handler)) {
        error_handler(e)
      }
      NULL
    }, finally = {
      loading_state$loading <- FALSE
    })

    result
  })
}

#' Create debounced search input
#'
#' @param input_id Character, input ID from Shiny input object
#' @param session Shiny session object
#' @param delay_ms Integer, debounce delay in milliseconds (default 500)
#' @return Debounced reactive expression
#'
#' @examples
#' server <- function(input, output, session) {
#'   search_debounced <- create_debounced_search("search_box", session)
#' }
create_debounced_search <- function(input_id, session, delay_ms = 500) {
  if (!requireNamespace("shiny", quietly = TRUE)) {
    stop("Package 'shiny' is required for debounced search")
  }

  debounce_reactive(
    shiny::reactive(session$input[[input_id]]),
    delay_ms = delay_ms
  )
}

#' Create throttled filter input
#'
#' @param input_id Character, input ID from Shiny input object
#' @param session Shiny session object
#' @param delay_ms Integer, throttle delay in milliseconds (default 1000)
#' @return Throttled reactive expression
#'
#' @examples
#' server <- function(input, output, session) {
#'   filter_throttled <- create_throttled_filter("filter_select", session)
#' }
create_throttled_filter <- function(input_id, session, delay_ms = 1000) {
  if (!requireNamespace("shiny", quietly = TRUE)) {
    stop("Package 'shiny' is required for throttled filters")
  }

  throttle_reactive(
    shiny::reactive(session$input[[input_id]]),
    delay_ms = delay_ms
  )
}

#' Batch multiple reactive updates
#'
#' @param reactive_list List of reactive expressions
#' @param delay_ms Integer, batch delay in milliseconds (default 1000)
#' @return Single reactive that triggers after all inputs settle
#'
#' @examples
#' batched <- batch_reactive_updates(
#'   list(input$filter1, input$filter2, input$filter3),
#'   delay_ms = 1000
#' )
batch_reactive_updates <- function(reactive_list, delay_ms = 1000) {
  if (!requireNamespace("shiny", quietly = TRUE)) {
    stop("Package 'shiny' is required for batching")
  }

  combined <- shiny::reactive({
    lapply(reactive_list, function(r) r())
  })

  throttle_reactive(combined, delay_ms = delay_ms)
}
