# Forensic Mode & Defensive Programming Guide

**Created:** 2025-01-16
**Purpose:** Eliminate "white screen of death" errors and make empty data a normal app state

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Forensic Mode](#forensic-mode)
3. [Safety Library](#safety-library)
4. [Common Failure Patterns](#common-failure-patterns)
5. [Best Practices](#best-practices)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Enable Forensic Mode (Local Development)

Edit `app.R` and uncomment these lines at the top:

```r
# ============================================================================
# FORENSIC MODE - Enable for local debugging
# ============================================================================
# Uncomment these lines for local development debugging:
options(
  shiny.error = browser,          # Drop into debugger at exact error line
  shiny.fullstacktrace = TRUE,    # Full call stack on errors
  shiny.reactlog = TRUE           # Reactive graph (Ctrl/Cmd+F3)
)
```

### How to Use Forensic Mode

1. **Reproduce the error** - Click through the app to trigger the failing component
2. **Debugger opens** - RStudio will pause at the exact error line
3. **Inspect variables** - Type variable names in the console to see their values
4. **View call stack** - See the full function call chain
5. **Press Ctrl/Cmd+F3** - Open reactlog to see the reactive dependency graph

### Safety Library Quick Reference

```r
# Load safety library (automatically loaded in app.R)
source("R/safety.R")

# Scalar extraction
state <- as_scalar(input$state, "state")  # Extract first element safely
count <- as_scalar_num(df$count, "count") # Extract & convert to numeric

# Data validation
df <- nz_rows(query_result, "query")      # NULL if empty
validate_data(df, "No documents found")   # Stops render if empty

# Safe conversions
num <- safe_as_numeric(input$value, default = 0)
date <- safe_as_date(input$date, default = Sys.Date())

# Logging
log_info("Processing", nrow(df), "documents")
log_warn("Filter returned empty results")
log_error("Database query failed:", conditionMessage(e))

# UI components
empty_card("No results. Adjust filters.")
error_card("Failed to load data. Try again.")
loading_card("Processing documents...")
```

---

## Forensic Mode

### What is Forensic Mode?

Forensic mode configures Shiny to provide maximum debugging information when errors occur:

1. **`shiny.error = browser`** - Drops into interactive debugger at error line
2. **`shiny.fullstacktrace = TRUE`** - Shows complete function call chain
3. **`shiny.reactlog = TRUE`** - Enables reactive graph visualization

### When to Use

- **Local Development**: Always enabled for debugging
- **Production**: Always disabled (errors sanitized for users)

### Reactive Graph (reactlog)

The reactive graph shows how inputs, reactives, and outputs are connected:

```r
# Press Ctrl/Cmd+F3 in browser to open reactlog
```

**What you'll see:**
- Which reactive caused the error
- What inputs triggered it
- The full dependency chain

**Common patterns:**
- **Circular dependencies** - Reactive A depends on B depends on A
- **Missing `req()`** - Render executes before data is ready
- **Vector leaks** - Length-0 vectors flowing through system

---

## Safety Library

The safety library (`R/safety.R`) provides defensive utilities to prevent crashes from empty/NULL data.

### Core Functions

#### Scalar Extraction

```r
# Problem: input$jurisdiction might be NULL or c("SP", "RJ")
jurisdiction <- input$jurisdiction[1]  # ❌ Crashes if NULL

# Solution: Safe extraction with validation
jurisdiction <- as_scalar(input$jurisdiction, "jurisdiction", allow_na = FALSE)
# ✅ Extracts first element, errors if NULL with clear message
```

**Available functions:**
- `as_scalar(x, name, allow_na = TRUE)` - Extract first element
- `as_scalar_chr(x, name, allow_na = TRUE)` - Extract as character
- `as_scalar_num(x, name, allow_na = TRUE)` - Extract as numeric
- `as_scalar_int(x, name, allow_na = TRUE)` - Extract as integer

#### Data Frame Validation

```r
# Problem: Query might return 0 rows
df <- dbGetQuery(pool, "SELECT * FROM legis_docs WHERE state = ?", params = list("XX"))
# df has 0 rows but code continues...

# Solution: Early NULL return
df <- nz_rows(df, "query_result")
if (is.null(df)) {
  return(empty_card("No documents for this state"))
}
# ✅ df is guaranteed to have rows beyond this point
```

#### Input Validation (Shiny)

```r
# In render* functions
output$results <- renderTable({
  # Validate input exists
  validate_selection(input$states, "state")

  # Get data
  df <- get_filtered_data(input$states)

  # Validate data exists
  validate_data(df, "No results for selected filters")

  # Safe to render
  df
})
```

#### Safe Conversions

```r
# Problem: User input might be "", "not a number", or NULL
year <- as.numeric(input$year)  # ❌ Returns NA, breaks downstream code

# Solution: Safe conversion with default
year <- safe_as_numeric(input$year, default = 2023)
# ✅ Returns 2023 if conversion fails
```

#### Logging

```r
# Structured logging with timestamps
log_info("Starting document search for:", input$query)
log_warn("Filter returned 0 results")
log_error("Database connection failed:", conditionMessage(e))

# Debug logging (only when DEBUG_SAFETY=TRUE)
log_debug("Query params:", jurisdiction, "from", date_from, "to", date_to)
```

Set `DEBUG_SAFETY` to enable debug logging:
```r
options(DEBUG_SAFETY = TRUE)
# or
init_safety(debug = TRUE)
```

#### UI Components

```r
# Empty state
output$results_ui <- renderUI({
  df <- data_filtered()
  if (is.null(df) || nrow(df) == 0) {
    return(empty_card("No documents found. Try different filters."))
  }
  # ... render actual UI
})

# Error state
output$map <- renderLeaflet({
  tryCatch({
    # ... render map
  }, error = function(e) {
    log_error("Map render failed:", conditionMessage(e))
    return(error_card("Failed to render map. Please try again."))
  })
})

# Loading state
output$processing_ui <- renderUI({
  if (is_processing()) {
    return(loading_card("Processing 10,000 documents..."))
  }
  # ... show results
})
```

#### Safe Render Wrapper

```r
# Wraps entire render with error/empty handling
output$chart <- renderPlotly({
  safe_render(
    {
      df <- get_data()
      plot_ly(df, x = ~state, y = ~count)
    },
    error_msg = "Failed to render chart. Check your filters.",
    empty_msg = "No data available for visualization."
  )
})
```

---

## Common Failure Patterns

### 1. Empty Input Selection

**Symptom:** App crashes when no selection is made

```r
# ❌ Problem
output$results <- renderTable({
  states <- input$states  # NULL or character(0)
  query_results(states[1])  # CRASH: subscript out of bounds
})

# ✅ Solution
output$results <- renderTable({
  req(input$states)  # Stop execution if NULL/empty
  validate_selection(input$states, "state")

  state <- as_scalar(input$states, "state")
  query_results(state)
})
```

### 2. Query Returns 0 Rows

**Symptom:** Charts/tables crash on empty data

```r
# ❌ Problem
output$chart <- renderPlotly({
  df <- get_documents()  # 0 rows
  plot_ly(df, x = ~date, y = ~count)  # CRASH: extent of x is 0
})

# ✅ Solution
output$chart <- renderPlotly({
  df <- get_documents()
  validate_data(df, "No documents to display")

  plot_ly(df, x = ~date, y = ~count)
})
```

### 3. Vector Operations on Length-0

**Symptom:** "Expecting a single value" errors

```r
# ❌ Problem
metrics <- get_metrics()  # Returns list(count = numeric(0))
valueBox(value = metrics$count, ...)  # CRASH: length 0

# ✅ Solution
metrics <- get_metrics()
count_value <- as_scalar_int(metrics$count, "count", allow_na = TRUE)
count_value <- if (is.na(count_value)) 0L else count_value

valueBox(value = count_value, ...)
```

### 4. Join Produces Empty Result

**Symptom:** Map or chart crashes after join

```r
# ❌ Problem
geo_data <- left_join(docs, states, by = "state_code")  # 0 rows (no matches)
leaflet(geo_data) %>% addPolygons(...)  # CRASH: no coordinates

# ✅ Solution
geo_data <- left_join(docs, states, by = "state_code")
if (is.null(geo_data) || nrow(geo_data) == 0) {
  return(empty_card("No geographic data available"))
}
leaflet(geo_data) %>% addPolygons(...)
```

### 5. String Input to Numeric Filter

**Symptom:** SQL returns 0 rows, downstream crashes

```r
# ❌ Problem
year <- as.numeric(input$year)  # "" becomes NA
df <- dbGetQuery(pool, "SELECT * FROM docs WHERE year = ?", params = list(year))
# SQL sees NULL, returns 0 rows, chart crashes

# ✅ Solution
year <- safe_as_numeric(input$year, default = 2023)
df <- dbGetQuery(pool, "SELECT * FROM docs WHERE year = ?", params = list(year))
df <- nz_rows(df, "year_query")
validate_data(df, sprintf("No documents for year %d", year))
```

### 6. Reactive Not Initialized

**Symptom:** Renders fail on first load

```r
# ❌ Problem
filtered_data <- reactiveVal()  # NULL initially
output$table <- renderTable(filtered_data())  # CRASH: NULL

# ✅ Solution
filtered_data <- reactiveVal(data.frame())  # Initialize with empty df
output$table <- renderTable({
  df <- filtered_data()
  validate_data(df, "No data loaded yet. Please apply filters.")
  df
})
```

---

## Best Practices

### 1. Guard Every Render

```r
output$my_component <- render*({
  # 1. Require inputs exist
  req(input$filter)

  # 2. Get data
  df <- get_data(input$filter)

  # 3. Validate data exists
  validate_data(df, "No results")

  # 4. Render
  # ... actual rendering code
})
```

### 2. Wrap Database Calls

```r
# Instead of:
df <- dbGetQuery(pool, query, params)

# Use:
df <- safe_query(pool, query, params, query_name = "state_docs")
# Returns NULL if 0 rows, logs automatically
```

### 3. Never Index Blind

```r
# Instead of:
first_state <- states[1]

# Use:
first_state <- as_scalar(states, "state", allow_na = FALSE)
```

### 4. Explicit Empty States in UI

```r
output$results_ui <- renderUI({
  df <- data_filtered()

  if (is.null(df) || nrow(df) == 0) {
    return(empty_card("No results. Try adjusting your filters."))
  }

  # Render actual component
  tagList(
    h3(sprintf("Found %d documents", nrow(df))),
    DTOutput("results_table")
  )
})
```

### 5. De-noodle Reactives

```r
# Instead of: Complex reactive chain
data_filtered <- reactive({
  req(input$year)  # Re-runs on ANY reactive change
  query_data(input$year)
})

# Use: Explicit dependencies with isolate()
data_filtered <- reactive({
  req(input$year)
  isolate({
    query_data(input$year, input$state)
  })
})
# Only re-runs when input$year changes, not input$state
```

### 6. Cache Expensive Operations

```r
# Install memoise
# install.packages("memoise")

# Wrap expensive function
memoized_query <- memoise::memoise(expensive_query_function)

# Use in reactive
data <- reactive({
  req(input$filters)
  memoized_query(input$filters)  # Cached based on input
})
```

### 7. TryCatch Fragile Blocks

```r
output$complex_viz <- renderPlotly({
  tryCatch({
    df <- get_data()
    validate_data(df)

    # Complex transformation
    processed <- complex_processing(df)

    # Render
    plot_ly(processed, ...)

  }, error = function(e) {
    log_error("Visualization failed:", conditionMessage(e))
    showNotification("Error rendering chart. Please try again.", type = "error")

    # Return fallback
    plotly_empty() %>% layout(title = "Chart unavailable")
  })
})
```

---

## Troubleshooting

### Symptom: White Screen of Death

**Cause:** Unhandled error in UI construction or critical render

**Fix:**
1. Check console logs for error messages
2. Enable forensic mode to see exact error line
3. Look for NULL/empty data flowing into renders
4. Add `req()` and `validate()` guards

### Symptom: "Expecting a single value" Error

**Cause:** Vector with length != 1 passed where scalar expected

**Fix:**
```r
# Find the offending line (forensic mode will show it)
# Replace with:
value <- as_scalar(vector, "name")
```

### Symptom: Charts Show "extent is 0" Error

**Cause:** Plotly/ggplot2 receiving empty data frame

**Fix:**
```r
output$chart <- renderPlotly({
  df <- get_data()

  # Add this validation
  validate_data(df, "No data for chart")

  # Also check for numeric columns with actual values
  req(sum(!is.na(df$value)) > 0)

  plot_ly(df, ...)
})
```

### Symptom: App Works Locally, Crashes on Railway

**Cause:** Production data differences (empty tables, missing states, etc.)

**Fix:**
1. Add defensive guards throughout
2. Test with empty database locally
3. Enable logging to see what's happening:
```r
# In production environment
options(DEBUG_SAFETY = TRUE)
```

### Symptom: Reactive Flicker/Infinite Loop

**Cause:** Circular reactive dependencies

**Fix:**
1. Press Ctrl/Cmd+F3 to open reactlog
2. Find the circular dependency
3. Break it with `isolate()` or `observeEvent()` instead of `reactive()`

---

## Running Tests

### Test Safety Library

```bash
# Run safety library tests
Rscript -e "testthat::test_file('tests/testthat/test-safety.R')"
```

**Expected output:**
```
✓ | OK F W S | Context
✓ |  8       | Safety Library - Scalar Extraction
✓ |  5       | Safety Library - Data Frame Validation
✓ |  2       | Safety Library - Vector Validation
✓ |  6       | Safety Library - Safe Conversions
✓ |  3       | Safety Library - Logging
✓ |  3       | Safety Library - UI Components
✓ |  4       | Safety Library - Safe Render
✓ |  3       | Safety Library - Integration Tests

══ Results ═══════════════════════════════════════
Duration: 0.5 s

[ FAIL 0 | WARN 0 | SKIP 0 | PASS 34 ]
```

---

## Migration Checklist

Use this checklist to harden your Shiny modules:

### Per Module

- [ ] Source `R/safety.R` at module load
- [ ] Replace all `input$foo[1]` with `as_scalar(input$foo, "foo")`
- [ ] Add `req()` at start of all render functions
- [ ] Add `validate_data()` after all data fetch operations
- [ ] Wrap database calls with `safe_query()` or add `nz_rows()` check
- [ ] Add `tryCatch()` around complex/fragile operations
- [ ] Replace hard errors with `empty_card()` or `error_card()`
- [ ] Add `log_error()` in all error handlers
- [ ] Test with empty database/NULL inputs
- [ ] Write test case for empty data scenario

### Example: Hardening a render function

**Before:**
```r
output$results <- renderTable({
  state <- input$state[1]
  df <- dbGetQuery(pool, "SELECT * FROM docs WHERE state = ?", params = list(state))
  df
})
```

**After:**
```r
output$results <- renderTable({
  # 1. Require input
  req(input$state)
  validate_selection(input$state, "state")

  # 2. Safe scalar extraction
  state <- as_scalar(input$state, "state", allow_na = FALSE)

  # 3. Safe database query
  df <- tryCatch({
    dbGetQuery(pool, "SELECT * FROM docs WHERE state = ?", params = list(state))
  }, error = function(e) {
    log_error("Query failed for state", state, ":", conditionMessage(e))
    NULL
  })

  # 4. Validate result
  validate_data(df, sprintf("No documents found for state %s", state))

  # 5. Safe to render
  log_info("Rendering", nrow(df), "documents for state", state)
  df
})
```

---

## Additional Resources

- **Shiny Debugging**: https://shiny.rstudio.com/articles/debugging.html
- **React log**: https://rstudio.github.io/reactlog/
- **Test safety.R**: `tests/testthat/test-safety.R`
- **Example usage**: See `app.R` fallback renders (lines 640-815)

---

**Remember:** Empty data is not an error—it's a normal state. Make your app handle it gracefully!
