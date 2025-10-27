# Migration Plan: shinydashboard → bslib
## Monitor Legislativo v4

**Date**: 2025-10-26
**Reason**: Definitive fix for extent=0 error (confirmed shinydashboard incompatibility)
**Estimated Effort**: 2-4 hours
**Risk Level**: Low (straightforward component mapping)

---

## Executive Summary

After systematic binary search debugging (v46-v60), we definitively identified that the `extent=0` error originates from the `shinydashboard` package itself, not from our application code. Version v60 tested with:
- Zero custom modules
- Zero custom tabs
- Minimal dashboardPage with static HTML only
- Result: **HTTP 500 extent=0 error** with "No traceback available"

**Conclusion**: The error occurs so early in dashboardPage rendering that R cannot generate a traceback. This is a fundamental incompatibility with shinydashboard in our deployment environment.

**Solution**: Migrate to `bslib` - a modern, actively maintained framework by Posit/RStudio that has all required features and no extent=0 compatibility issues.

---

## Component Mapping Reference

### Core Layout Components

| shinydashboard | bslib Equivalent | Notes |
|----------------|------------------|-------|
| `dashboardPage()` | `page_sidebar()` or `page_navbar()` | Choose based on layout preference |
| `dashboardHeader()` | `page_sidebar(title=...)` parameter | Title embedded in page function |
| `dashboardSidebar()` | `sidebar()` | More flexible positioning |
| `dashboardBody()` | Main content area in `page_*()` | No wrapper needed |
| `sidebarMenu()` | `navset_tab()` or `navset_pill()` | For navigation |
| `menuItem()` | `nav_panel()` | Individual navigation items |
| `tabItems()` | Content passed directly to page | No wrapper needed |
| `tabItem()` | `nav_panel()` content | Each panel's content |

### Content Components

| shinydashboard | bslib Equivalent | Notes |
|----------------|------------------|-------|
| `box()` | `card()` | More flexible styling |
| `valueBox()` | `value_box()` | Similar API, better theming |
| `infoBox()` | `value_box()` with `showcase` | Use showcase for icon |

### Styling & Theming

| shinydashboard | bslib Equivalent | Notes |
|----------------|------------------|-------|
| Custom CSS in `tags$head()` | `bs_theme()` | Theme customization |
| `status` parameter | `class` parameter | Bootstrap 5 classes |
| `color` parameter | Theme customization | Uses theme colors |

---

## Migration Steps

### Phase 1: Preparation (15 minutes)

#### 1.1 Update Dockerfile
Add `bslib` package to installation list:

```r
# In Dockerfile, update the R package installation (around line 31):
RUN R -q -e "options(timeout=900, Ncpus=parallel::detectCores()); \
  install.packages(c( \
    'bslib','shiny','DT', \  # ADD bslib here, REMOVE shinydashboard
    'DBI','RPostgres','pool', \
    'dplyr','data.table','lubridate','tidyr','magrittr','stringr','readr', \
    'ggplot2','scales','RColorBrewer','plotly', \
    'htmltools','httpuv','fastmap','promises','future','jsonlite','glue','digest','httr','memoise', \
    'shinythemes','shinycssloaders','shinyjs','shinyWidgets', \
    'units','s2','sf','leaflet','openxlsx','xml2' \
  ), repos='https://cloud.r-project.org')"
```

**Note**: Remove `shinydashboard` and `shinydashboardPlus` from the list.

#### 1.2 Backup Current Production Files
```bash
cp ui.R ui.R.shinydashboard.backup
cp server.R server.R.shinydashboard.backup
cp global_integrated.R global_integrated.R.backup
```

#### 1.3 Create Version Control Checkpoint
```bash
git checkout -b migration-to-bslib
git add -A
git commit -m "checkpoint: before bslib migration (v60 - extent=0 confirmed)"
```

---

### Phase 2: UI Migration (60-90 minutes)

#### 2.1 Update Package Loading in ui.R

**Before** (lines 5-9):
```r
suppressPackageStartupMessages({
  library(shiny)
  library(shinydashboard)
})
```

**After**:
```r
suppressPackageStartupMessages({
  library(shiny)
  library(bslib)
})
```

#### 2.2 Convert Main Layout Structure

**Before** (shinydashboard):
```r
ui <- function(request) {
  dashboardPage(
    dashboardHeader(
      title = "Monitor Legislativo v4",
      titleWidth = 400
    ),
    dashboardSidebar(
      width = 250,
      sidebarMenu(
        id = "main_menu",
        menuItem("Painel Executivo", tabName = "executive", icon = icon("chart-line")),
        menuItem("Biblioteca", tabName = "library", icon = icon("book")),
        menuItem("Analytics", tabName = "analytics", icon = icon("chart-bar")),
        menuItem("São Paulo", tabName = "saopaulo", icon = icon("map")),
        menuItem("NLP", tabName = "nlp", icon = icon("brain"))
      )
    ),
    dashboardBody(
      # Custom CSS
      tags$head(
        tags$style(HTML("..."))
      ),

      tabItems(
        tabItem(tabName = "executive", ...),
        tabItem(tabName = "library", ...),
        # etc.
      )
    )
  )
}
```

**After** (bslib with page_navbar - recommended for multi-tab layout):
```r
ui <- function(request) {
  page_navbar(
    title = "Monitor Legislativo v4",
    theme = bs_theme(
      version = 5,
      bg = "#ffffff",
      fg = "#2c3e50",
      primary = "#3498db",
      base_font = font_google("Roboto")
    ),

    # Navigation panels (replaces menuItem + tabItem)
    nav_panel(
      title = "Painel Executivo",
      icon = icon("chart-line"),
      # Executive tab content goes here directly
      source("R/ui/executive_tab.R", local = TRUE)$value
    ),

    nav_panel(
      title = "Biblioteca",
      icon = icon("book"),
      source("R/ui/library_tab.R", local = TRUE)$value
    ),

    nav_panel(
      title = "Analytics",
      icon = icon("chart-bar"),
      source("R/ui/analytics_tab.R", local = TRUE)$value
    ),

    nav_panel(
      title = "São Paulo",
      icon = icon("map"),
      source("R/ui/saopaulo_tab.R", local = TRUE)$value
    ),

    nav_panel(
      title = "NLP",
      icon = icon("brain"),
      source("R/ui/nlp_tab.R", local = TRUE)$value
    )
  )
}
```

**Alternative** (bslib with page_sidebar - if you prefer sidebar navigation):
```r
ui <- function(request) {
  page_sidebar(
    title = "Monitor Legislativo v4",
    theme = bs_theme(
      version = 5,
      bg = "#ffffff",
      fg = "#2c3e50",
      primary = "#3498db"
    ),

    sidebar = sidebar(
      title = "Navegação",
      width = 250,
      # Use radioButtons or selectInput for navigation
      selectInput(
        "main_menu",
        "Selecione:",
        choices = c(
          "Painel Executivo" = "executive",
          "Biblioteca" = "library",
          "Analytics" = "analytics",
          "São Paulo" = "saopaulo",
          "NLP" = "nlp"
        )
      )
    ),

    # Main content area with conditional panels
    uiOutput("selected_tab_content")
  )
}
```

**Recommendation**: Use `page_navbar()` as it provides the cleanest migration path from shinydashboard's menu system.

#### 2.3 Convert box() Components to card()

**Pattern to Find**: All instances of `box(...)`
**Replace With**: `card(...)`

**Key Differences**:
- `status` parameter → `class` parameter with Bootstrap classes
- `solidHeader` parameter → not needed (use `card_header()` for headers)

**Before**:
```r
box(
  title = "Total de Documentos",
  status = "primary",
  solidHeader = TRUE,
  width = 3,
  valueBoxOutput("total_docs")
)
```

**After**:
```r
card(
  card_header("Total de Documentos"),
  class = "border-primary",
  valueBoxOutput("total_docs")
)
```

#### 2.4 Convert valueBox() to value_box()

**Before**:
```r
valueBox(
  value = textOutput("doc_count"),
  subtitle = "Total de Documentos",
  icon = icon("file-alt"),
  color = "blue"
)
```

**After**:
```r
value_box(
  title = "Total de Documentos",
  value = textOutput("doc_count"),
  showcase = icon("file-alt"),
  theme = "primary"  # or "info", "success", "warning", "danger"
)
```

#### 2.5 Update Layout Helpers

**Before** (shinydashboard uses standard fluidRow/column):
```r
fluidRow(
  column(width = 3, box(...)),
  column(width = 9, box(...))
)
```

**After** (bslib supports same syntax, but also has layout_columns):
```r
# Option 1: Keep existing fluidRow/column (works fine)
fluidRow(
  column(width = 3, card(...)),
  column(width = 9, card(...))
)

# Option 2: Use modern layout_columns (recommended)
layout_columns(
  col_widths = c(3, 9),
  card(...),
  card(...)
)
```

---

### Phase 3: Tab Content Migration (30-60 minutes)

Migrate each tab file in `R/ui/*.R`:

#### 3.1 Executive Tab (R/ui/executive_tab.R)

**Key Changes**:
1. Replace all `box()` with `card()`
2. Replace all `valueBox()` with `value_box()`
3. Update `status` parameters to Bootstrap 5 classes
4. Keep all `fluidRow()` and `column()` as-is (compatible)

**Example Conversion**:

**Before**:
```r
# R/ui/executive_tab.R
fluidRow(
  valueBoxOutput("total_docs_box"),
  valueBoxOutput("recent_docs_box"),
  valueBoxOutput("categories_box")
),
fluidRow(
  box(
    title = "Distribuição por Categoria",
    status = "primary",
    solidHeader = TRUE,
    width = 6,
    plotlyOutput("category_plot")
  ),
  box(
    title = "Evolução Temporal",
    status = "info",
    solidHeader = TRUE,
    width = 6,
    plotlyOutput("temporal_plot")
  )
)
```

**After**:
```r
# R/ui/executive_tab.R
layout_columns(
  col_widths = c(4, 4, 4),
  value_box(
    title = "Total de Documentos",
    value = textOutput("total_docs_value"),
    showcase = icon("file-alt"),
    theme = "primary"
  ),
  value_box(
    title = "Documentos Recentes",
    value = textOutput("recent_docs_value"),
    showcase = icon("clock"),
    theme = "info"
  ),
  value_box(
    title = "Categorias",
    value = textOutput("categories_value"),
    showcase = icon("tags"),
    theme = "success"
  )
),
layout_columns(
  col_widths = c(6, 6),
  card(
    card_header("Distribuição por Categoria"),
    plotlyOutput("category_plot")
  ),
  card(
    card_header("Evolução Temporal"),
    plotlyOutput("temporal_plot")
  )
)
```

#### 3.2 Library Tab (R/ui/library_tab.R)

**Focus Areas**:
- Search interface remains mostly unchanged
- Convert result display boxes to cards
- Update any infoBox() to value_box()

#### 3.3 Analytics, São Paulo, NLP Tabs

**Pattern**: Same conversion as above:
1. `box()` → `card()`
2. `valueBox()` / `infoBox()` → `value_box()`
3. Update status/color parameters to Bootstrap 5 themes

---

### Phase 4: Server-Side Updates (15-30 minutes)

#### 4.1 Update renderValueBox to renderUI

**Before** (shinydashboard):
```r
output$total_docs_box <- renderValueBox({
  valueBox(
    value = format(nrow(data), big.mark = ","),
    subtitle = "Total de Documentos",
    icon = icon("file-alt"),
    color = "blue"
  )
})
```

**After** (bslib):
```r
output$total_docs_value <- renderText({
  format(nrow(data), big.mark = ",")
})

# Or if you need dynamic value_box:
output$total_docs_box <- renderUI({
  value_box(
    title = "Total de Documentos",
    value = format(nrow(data), big.mark = ","),
    showcase = icon("file-alt"),
    theme = "primary"
  )
})
```

**Recommendation**: For static value boxes, define them in UI and use `renderText()` for the value. For dynamic value boxes (changing themes/icons), use `renderUI()`.

#### 4.2 Update Menu Selection Logic (if using page_sidebar)

If you chose `page_sidebar()` with conditional panels:

```r
output$selected_tab_content <- renderUI({
  switch(input$main_menu,
    "executive" = source("R/ui/executive_tab.R", local = TRUE)$value,
    "library" = source("R/ui/library_tab.R", local = TRUE)$value,
    "analytics" = source("R/ui/analytics_tab.R", local = TRUE)$value,
    "saopaulo" = source("R/ui/saopaulo_tab.R", local = TRUE)$value,
    "nlp" = source("R/ui/nlp_tab.R", local = TRUE)$value
  )
})
```

**Note**: If using `page_navbar()`, this is not needed - navigation is automatic.

#### 4.3 Remove shinydashboard-specific Code

**Search for and remove/update**:
- `updateTabItems()` → Not needed with page_navbar
- Any references to `shinydashboard::` namespace
- Dashboard-specific reactive values

---

### Phase 5: Theming & Polish (30 minutes)

#### 5.1 Create Custom Theme

Replace the custom CSS in `tags$head()` with a bslib theme:

**Before** (Custom CSS):
```r
tags$head(
  tags$style(HTML("
    .main-header .navbar {
      background-color: #2c3e50 !important;
    }
    .main-header .logo {
      background-color: #2c3e50 !important;
      color: white !important;
    }
    .content-wrapper {
      background-color: #ecf0f1;
    }
  "))
)
```

**After** (bslib theme):
```r
theme = bs_theme(
  version = 5,

  # Core colors
  bg = "#ecf0f1",           # Background color
  fg = "#2c3e50",           # Foreground (text) color
  primary = "#3498db",      # Primary brand color
  secondary = "#95a5a6",    # Secondary color
  success = "#27ae60",      # Success color
  info = "#3498db",         # Info color
  warning = "#f39c12",      # Warning color
  danger = "#e74c3c",       # Danger color

  # Typography
  base_font = font_google("Roboto"),
  heading_font = font_google("Roboto Slab"),
  code_font = font_google("Fira Code"),

  # Spacing
  "border-radius" = "0.5rem",
  "card-border-width" = "1px"
)
```

#### 5.2 Add Theme Customization (Optional)

```r
# In global_integrated.R or at top of server.R:
library(bslib)

# Allow users to switch themes (optional feature)
bs_themer()  # Adds interactive theme customization panel
```

#### 5.3 Responsive Design Checks

bslib is mobile-first by default. Test these breakpoints:
- Desktop (>= 992px): Full layout
- Tablet (768-991px): Adjusted columns
- Mobile (< 768px): Stacked layout

**No code changes needed** - bslib handles this automatically.

---

### Phase 6: Testing & Deployment (30 minutes)

#### 6.1 Local Testing Checklist

```bash
# Test the application locally
R -e "shiny::runApp('app.R', host='0.0.0.0', port=3838)"
```

**Test Scenarios**:
- [ ] Application starts without errors
- [ ] All navigation tabs load correctly
- [ ] Executive dashboard displays metrics
- [ ] Library search functions work
- [ ] Analytics visualizations render
- [ ] Geographic maps display (São Paulo tab)
- [ ] NLP analysis displays
- [ ] Export functionality works
- [ ] All plots/charts render correctly
- [ ] No console errors in browser

#### 6.2 Build v61 - bslib Migration

Update Dockerfile comment:
```dockerfile
# FIX v61: Migrated from shinydashboard to bslib (fixes extent=0 error definitively)
```

Build and deploy:
```bash
cd "/Users/sofiadonario/Library/CloudStorage/OneDrive-Personal/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4"

gcloud builds submit \
  --tag us-central1-docker.pkg.dev/mackmonitor/monitor-repo/mackmonitor:v61-bslib \
  --project=mackmonitor \
  --region=us-central1

gcloud run deploy mackmonitor \
  --image us-central1-docker.pkg.dev/mackmonitor/monitor-repo/mackmonitor:v61-bslib \
  --platform managed \
  --region southamerica-east1 \
  --allow-unauthenticated \
  --project=mackmonitor
```

#### 6.3 Verify Deployment

```bash
# Get the service URL
SERVICE_URL=$(gcloud run services describe mackmonitor \
  --region=southamerica-east1 \
  --format='value(status.url)')

# Test the application
curl -I "$SERVICE_URL"
# Expected: HTTP/2 200

# Test in browser
echo "Open: $SERVICE_URL"
```

**Success Criteria**:
- ✅ HTTP 200 response
- ✅ No extent=0 error in logs
- ✅ All tabs accessible
- ✅ All visualizations render
- ✅ No JavaScript console errors

---

## File-by-File Checklist

### Files to Modify

- [ ] `/Dockerfile` - Replace shinydashboard with bslib in package list
- [ ] `/ui.R` - Complete rewrite using bslib components
- [ ] `/server.R` - Update renderValueBox → renderUI/renderText
- [ ] `/global_integrated.R` - Update library() calls if present
- [ ] `/R/ui/executive_tab.R` - Convert boxes and valueBoxes
- [ ] `/R/ui/library_tab.R` - Convert boxes
- [ ] `/R/ui/analytics_tab.R` - Convert boxes and plots
- [ ] `/R/ui/saopaulo_tab.R` - Convert boxes and maps
- [ ] `/R/ui/nlp_tab.R` - Convert boxes and text displays

### Files That Don't Need Changes

- ✅ `/app.R` - No changes needed
- ✅ `/R/modules/*.R` - Module logic unchanged
- ✅ `/R/utils/database_utils.R` - Database logic unchanged
- ✅ `/modules/data_service.R` - Data service unchanged
- ✅ All data processing scripts

---

## Common Pitfalls & Solutions

### Pitfall 1: Missing theme parameter
**Error**: `argument "theme" is missing, with no default`
**Solution**: Add `theme = bs_theme()` to `page_navbar()` or `page_sidebar()`

### Pitfall 2: valueBox showcase not displaying
**Error**: Icon doesn't appear in value_box
**Solution**: Use `showcase = icon("icon-name")`, not `icon` parameter

### Pitfall 3: Card headers not styled
**Error**: Card headers look plain
**Solution**: Use `card_header()` function instead of `title` parameter

### Pitfall 4: Navigation not working
**Error**: Clicking nav items doesn't change content
**Solution**: With `page_navbar()`, don't use `tabsetPanel()` - navigation is automatic

### Pitfall 5: Colors not matching brand
**Error**: Default Bootstrap colors don't match your brand
**Solution**: Customize `bs_theme()` with exact hex colors

---

## Rollback Plan

If migration encounters critical issues:

```bash
# Restore from backup
cp ui.R.shinydashboard.backup ui.R
cp server.R.shinydashboard.backup server.R
cp global_integrated.R.backup global_integrated.R

# Or revert via git
git checkout main -- ui.R server.R global_integrated.R

# Redeploy previous working version
git checkout v46-absolute-minimal  # Last known working version
# Deploy that version
```

---

## Post-Migration Benefits

### Performance Improvements
- **Faster rendering**: bslib uses Bootstrap 5 (lighter than shinydashboard)
- **Better caching**: Modern asset management
- **Smaller bundle size**: Fewer dependencies

### Developer Experience
- **Active maintenance**: Regular updates from Posit/RStudio
- **Better documentation**: Comprehensive guides and examples
- **Modern patterns**: Aligns with current Shiny best practices

### User Experience
- **Responsive by default**: Better mobile/tablet experience
- **Accessibility**: WCAG 2.1 compliant out of the box
- **Customization**: Easy theming without custom CSS

### Future-Proofing
- **Long-term support**: shinydashboard is in maintenance mode
- **New features**: bslib gets new components regularly
- **Community**: Growing ecosystem of bslib extensions

---

## References

- [bslib Documentation](https://rstudio.github.io/bslib/)
- [Migration Guide: shinydashboard → bslib](https://rstudio.github.io/bslib/articles/dashboards.html)
- [Bootstrap 5 Documentation](https://getbootstrap.com/docs/5.3/)
- [Shiny for R](https://shiny.posit.co/)

---

## Version History

- **v61**: Initial bslib migration (fixes extent=0 error)
- **v60**: Binary search - confirmed shinydashboard incompatibility
- **v59**: Binary search - disabled UI modules/tabs
- **v46**: Last known minimal working version (no dashboardPage)

---

**Next Step**: Proceed with Phase 1 - Update Dockerfile and create backups.
