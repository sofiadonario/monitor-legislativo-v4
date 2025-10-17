# Safety Library Quick Reference

**Location**: `R/utils/scalar_utils.R` + `R/utils/ui_utils.R`
**Auto-loaded**: Yes (via global.R)
**Created**: 2025-01-16

---

## 🚀 Quick Start

All safety functions are automatically available in your Shiny app. No need to source anything!

```r
# ✅ These work immediately in any module:
state <- scalar_chr(input$state)  # Safe scalar extraction
df <- safe_query(pool, query, params)  # Safe database query
validate_data(df, "No results")  # Stop render if empty
```

---

## 📦 Scalar Extraction

**Problem**: `input$state[1]` crashes if NULL or empty

### Basic Scalars

```r
scalar(x, default = NA)          # Generic scalar
scalar_chr(x, default = "—")     # Character scalar
scalar_num(x, default = 0)       # Numeric scalar
scalar_int(x, default = 0L)      # Integer scalar
scalar_lgl(x, default = FALSE)   # Logical scalar
```

**Example**:
```r
# Instead of:
state <- input$states[1]  # ❌ Crashes if NULL

# Use:
state <- scalar_chr(input$states)  # ✅ Returns "—" if NULL
```

### UI-Specific Scalars

```r
value_box_scalar(x, default = "—", format_fn = NULL)
text_scalar(x, default = "—", prefix = "", suffix = "")
```

**Example**:
```r
output$total_docs <- renderValueBox({
  metrics <- get_metrics()
  safe_valueBox(
    value = value_box_scalar(metrics$count, format_fn = function(x) format(x, big.mark = ",")),
    subtitle = "Total Documents",
    icon = icon("file-text"),
    color = "blue"
  )
})
```

---

## 🔢 Safe Calculations

**Problem**: `mean(df$value)` returns length-0 vector if df is empty

```r
safe_nrow(df, default = 0)             # Safe nrow()
safe_length(x, default = 0)            # Safe length()
safe_n_distinct(x, default = 0)        # Safe unique count
safe_mean(x, default = 0, na.rm = TRUE)
safe_sum(x, default = 0, na.rm = TRUE)
safe_max(x, default = 0, na.rm = TRUE)
safe_min(x, default = 0, na.rm = TRUE)
```

**Example**:
```r
# Instead of:
avg <- mean(df$count)  # ❌ Returns numeric(0) if empty

# Use:
avg <- safe_mean(df$count)  # ✅ Returns 0 if empty
```

---

## ✅ Validation & Checking

### Existence Checks

```r
nz_rows(df)   # TRUE if df has rows, FALSE otherwise
nz_len(x)     # TRUE if x has length > 0
has_rows(df)  # Alias for nz_rows()
```

**Example**:
```r
if (!nz_rows(df)) {
  return(empty_card("No data available"))
}
```

### Shiny Validation

```r
validate_selection(input_value, input_name = "selection")
validate_data(df, msg = "Sem dados disponíveis")
validate_range(range, name = "range")
```

**Example**:
```r
output$results <- renderTable({
  req(input$state)
  validate_selection(input$state, "state")

  df <- get_data(input$state)
  validate_data(df, "No results for this state")

  df
})
```

---

## 🗄️ Database Queries

```r
safe_query(pool, query, params = list(), query_name = "query")
```

**Returns**: Data frame or NULL (if 0 rows or error)
**Logs**: Automatically logs query execution and results

**Example**:
```r
df <- safe_query(
  pool,
  "SELECT * FROM docs WHERE state = ?",
  params = list(state),
  query_name = "state_docs"
)

if (is.null(df)) {
  return(empty_card("No documents for this state"))
}
```

---

## 🎨 UI Components

### Empty/Error/Loading States

```r
empty_card(msg = "Sem resultados. Ajuste os filtros.", icon = "info-circle")
error_card(msg = "Erro ao carregar dados. Tente novamente.")
loading_card(msg = "Carregando...")
```

**Example**:
```r
output$results_ui <- renderUI({
  df <- data_filtered()

  if (is.null(df) || nrow(df) == 0) {
    return(empty_card("No results. Try different filters."))
  }

  # ... render actual component
})
```

### Safe Render Wrapper

```r
safe_render(expr, error_msg = "...", empty_msg = NULL)
```

**Example**:
```r
output$chart <- renderPlotly({
  safe_render(
    {
      df <- get_data()
      plot_ly(df, x = ~state, y = ~count)
    },
    error_msg = "Failed to render chart",
    empty_msg = "No data for visualization"
  )
})
```

### Safe Renderers

```r
safe_renderText(expr, default = "—", context = NULL)
safe_renderUI(expr, fallback = div(), context = NULL)
safe_renderPlotly(expr, context = NULL)
safe_valueBox(value, subtitle, icon, color, width)
```

---

## 📊 Conversions

```r
safe_as_numeric(x, default = NA_real_)
safe_as_date(x, default = NA)
```

**Example**:
```r
year <- safe_as_numeric(input$year, default = 2023)
date <- safe_as_date(input$date, default = Sys.Date())
```

---

## 📝 Logging

```r
log_debug(...)  # Only when DEBUG_SAFETY=1
log_info(...)   # Always logged
log_warn(...)   # To stderr
log_error(...)  # To stderr
```

**Example**:
```r
log_info("Processing", nrow(df), "documents")
log_warn("Filter returned empty results")
log_error("Database query failed:", conditionMessage(e))
```

**Enable debug logging**:
```r
Sys.setenv(DEBUG_SAFETY = "1")
```

---

## 🛡️ Common Patterns

### Pattern 1: Safe ValueBox

```r
output$my_metric <- renderValueBox({
  tryCatch({
    metrics <- get_metrics()
    value <- scalar_num(metrics$count, default = 0)

    safe_valueBox(
      value = value_box_scalar(value, format_fn = function(x) format(x, big.mark = ",")),
      subtitle = "My Metric",
      icon = icon("chart-line"),
      color = "blue"
    )
  }, error = function(e) {
    safe_valueBox("Error", "My Metric", icon("exclamation-triangle"), "red")
  })
})
```

### Pattern 2: Safe Table Render

```r
output$results <- renderTable({
  req(input$filter)
  validate_selection(input$filter, "filter")

  df <- safe_query(pool, query, params = list(input$filter), query_name = "results")
  validate_data(df, "No results for this filter")

  log_info("Rendering", nrow(df), "rows")
  df
})
```

### Pattern 3: Safe Chart with Empty State

```r
output$chart <- renderPlotly({
  df <- get_data()

  if (!nz_rows(df)) {
    return(
      plot_ly() %>%
        add_annotations(
          text = "No data available",
          x = 0.5, y = 0.5,
          showarrow = FALSE
        )
    )
  }

  # Verify numeric columns have values
  req(sum(!is.na(df$value)) > 0)

  plot_ly(df, x = ~date, y = ~value)
})
```

### Pattern 4: Defensive Data Fetch

```r
data_filtered <- reactive({
  req(input$state)

  df <- tryCatch({
    dbGetQuery(pool, "SELECT * FROM docs WHERE state = ?", params = list(input$state))
  }, error = function(e) {
    log_error("Query failed:", conditionMessage(e))
    NULL
  })

  if (is.null(df) || !nz_rows(df)) {
    log_debug("No results for state:", input$state)
    return(NULL)
  }

  log_info("Found", nrow(df), "documents for state:", input$state)
  df
})
```

---

## 🐛 Debugging

### Vector Leak Detection

```r
# Enable vector leak logging
Sys.setenv(DEBUG_SCALARS = "1")

# Use logged variants
scalar_chr_logged(x, default = "—", context = "my_module")
scalar_num_logged(x, default = 0, context = "calculation")
scalar_int_logged(x, default = 0L, context = "id_extraction")

# View leak report
get_vector_leak_report()

# Clear log
clear_vector_leak_log()
```

### Forensic Mode

In `app.R`, uncomment:

```r
options(
  shiny.error = browser,          # Drop into debugger
  shiny.fullstacktrace = TRUE,    # Full stack trace
  shiny.reactlog = TRUE           # Reactive graph (Ctrl/Cmd+F3)
)
```

---

## 📚 Full Example

```r
output$state_analysis <- renderPlotly({
  # 1. Require input
  req(input$states)
  validate_selection(input$states, "state")

  # 2. Safe scalar extraction
  state <- scalar_chr(input$states)

  # 3. Safe database query
  df <- safe_query(
    pool,
    "SELECT date, count FROM docs WHERE state = ? ORDER BY date",
    params = list(state),
    query_name = "state_analysis"
  )

  # 4. Validate data exists
  validate_data(df, sprintf("No data for state %s", state))

  # 5. Safe calculations
  total <- safe_sum(df$count)
  avg <- safe_mean(df$count)

  # 6. Log
  log_info("Rendering chart for state", state, "with", nrow(df), "points")

  # 7. Render safely
  safe_render(
    {
      plot_ly(df, x = ~date, y = ~count) %>%
        layout(
          title = sprintf("%s: %s documents (avg: %s)",
                         state,
                         value_box_scalar(total, format_fn = function(x) format(x, big.mark = ",")),
                         round(avg))
        )
    },
    error_msg = "Failed to render state analysis chart",
    empty_msg = NULL  # Already validated
  )
})
```

---

## ✅ Migration Checklist

- [ ] Replace `input$foo[1]` with `scalar_chr(input$foo)`
- [ ] Replace `df$col[1]` with appropriate scalar function
- [ ] Add `req()` at start of all render functions
- [ ] Add `validate_data()` after data fetches
- [ ] Wrap DB calls with `safe_query()` or add `nz_rows()` check
- [ ] Replace hard errors with `empty_card()` or `error_card()`
- [ ] Add `log_error()` in error handlers
- [ ] Test with empty inputs/NULL values
- [ ] Enable `DEBUG_SCALARS=1` to find vector leaks

---

## 📖 See Also

- **Full Guide**: `docs/FORENSIC_MODE_GUIDE.md`
- **Tests**: `tests/testthat/test-safety-consolidated.R`
- **Source**: `R/utils/scalar_utils.R` + `R/utils/ui_utils.R`
