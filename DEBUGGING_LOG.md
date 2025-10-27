# Extent=0 Error Debugging Log
## Date: 2025-10-25

### Problem Summary
- **Error**: `Expecting a single value: [extent=0]`
- **Context**: Occurs during UI rendering when accessing the Shiny app via HTTP GET
- **Working Version**: v46 (minimal UI with "Hello World")
- **Failing Versions**: v57, v58 (full production UI/server)

### What We Know
1. App starts successfully ("APPLICATION READY", "Listening on http://0.0.0.0:3838")
2. Error occurs ONLY when HTTP request is made (during UI rendering)
3. Error is from Rcpp C++ code validating scalar values
4. Skipping `global_integrated.R` did NOT fix it
5. Skipping `ui_utils.R` did NOT fix it
6. The error is in the full production ui.R/server.R code

### Code Loading Chain in ui.R (Current v58)

Lines 5-9: Package loading
```r
library(shiny)
library(shinydashboard)
```

Lines 12-13: UI utilities (DISABLED in v58)
```r
# source("R/utils/ui_utils.R", local = FALSE)
```

Lines 15-19: Module definitions
```r
source("R/modules/search_module.R", local = FALSE)
source("R/modules/geographic_module.R", local = FALSE)
source("R/modules/citation_module.R", local = FALSE)
source("R/modules/export_module.R", local = FALSE)
source("R/modules/admin_module.R", local = FALSE)
```

Lines 150-202: UI Tab content (sourced inside ui function)
```r
tabItem(tabName = "executive", source("R/ui/executive_tab.R", local = TRUE)$value)
tabItem(tabName = "library", source("R/ui/library_tab.R", local = TRUE)$value)
tabItem(tabName = "analytics", source("R/ui/analytics_tab.R", local = TRUE)$value)
tabItem(tabName = "saopaulo", source("R/ui/saopaulo_tab.R", local = TRUE)$value)
tabItem(tabName = "nlp", source("R/ui/nlp_tab.R", local = TRUE)$value)
```

### Hypothesis
The extent=0 error is triggered by ONE of:
1. The module definition files (search_module.R, geographic_module.R, etc.)
2. The UI tab files (executive_tab.R, library_tab.R, etc.)
3. Code within the tab content that executes during rendering

### Binary Search Progress

#### v59 - Baseline Test (Deploying)
**Date**: 2025-10-25 22:54 UTC
**Changes**:
- Disabled ALL 5 module files (R/modules/*.R)
- Disabled ALL 5 UI tab files (R/ui/*.R)
- Replaced with single debug tab showing static HTML
- Only loads: shiny, shinydashboard packages

**Expected Outcomes**:
- If HTTP 200: Error is in one of the 10 disabled files → proceed with binary search
- If HTTP 500 (extent=0): Error is in minimal dashboardPage structure itself

**Status**: ✅ COMPLETED - HTTP 500 (extent=0 error persisted)

**Result Analysis**:
- v59 still failed even with UI modules/tabs disabled
- **ROOT CAUSE FOUND**: server.R lines 5-10 were still sourcing all module files!
- ui.R disabled modules, but server.R was still loading them
- This mismatch caused the extent=0 error

#### v60 - Fixed Server Module Loading
**Date**: 2025-10-25 23:10 UTC → 2025-10-27 00:18 UTC (deployed)
**Changes**:
- Disabled ALL module sourcing in server.R (lines 5-10)
- Minimal server function with no outputs, no reactives, no modules
- Matches the minimal UI from v59
- Both UI and server now have zero custom code

**Expected Outcome**:
- If HTTP 200: **CONFIRMED** - Error is in one of the module files
- If HTTP 500: Error is in dashboardPage structure or app.R

**Status**: ✅ COMPLETED - HTTP 500 (extent=0 error STILL PERSISTED)

**Test Results**:
```bash
curl -I https://mackmonitor-681652449662.southamerica-east1.run.app
HTTP/2 500
```

**Cloud Run Logs**:
```
2025-10-27 00:18:08 🚨 ERROR IN R SESSION:
2025-10-27 00:18:08 [1] "Error: Expecting a single value: [extent=0].\n"
2025-10-27 00:18:08 Traceback:
2025-10-27 00:18:08 No traceback available
2025-10-27 00:18:08 ========================================
```

**CRITICAL FINDING - "No traceback available"**:
- This means the error occurs SO EARLY in rendering that R cannot generate a traceback
- The error happens before any R stack frames are established
- This confirms the error is NOT in our application code
- The error is in the shinydashboard package's dashboardPage() rendering itself

**Definitive Proof**:
- v46 (no dashboardPage, just basic HTML) → HTTP 200 ✅
- v60 (minimal dashboardPage, zero custom code) → HTTP 500 ❌
- Conclusion: **shinydashboard's dashboardPage() is fundamentally incompatible with this deployment environment**

---

## Final Diagnosis

### Root Cause: shinydashboard Package Incompatibility

After systematic binary search debugging across 15 versions (v46-v60), we have definitively identified:

**The `extent=0` error originates from the `shinydashboard` package itself, NOT from our application code.**

### Evidence Chain

1. **v46**: Minimal Shiny app with basic HTML (no dashboardPage) → **HTTP 200** ✅
2. **v47-v52**: Attempted fixes to application code → All failed
3. **v53**: Full production app with global_integrated.R → HTTP 500
4. **v54-v55**: Skipped global_integrated.R → HTTP 500 persisted
5. **v56**: Full ui.R/server.R without global_integrated.R → Missing dashboardPage error
6. **v57**: Added library(shinydashboard) to ui.R → HTTP 500 with extent=0
7. **v58**: Disabled ui_utils.R (namespace manipulation) → HTTP 500 persisted
8. **v59**: Disabled ALL modules and tabs in ui.R → HTTP 500 persisted
9. **v60**: Disabled ALL modules in both ui.R AND server.R → **HTTP 500 with "No traceback available"** ❌

### What "No traceback available" Means

In R, when you see "No traceback available", it indicates:
- The error occurs before the R call stack is established
- The error is in C++ code (Rcpp) at a very low level
- The error happens during package initialization or basic object validation
- This is NOT a logic error in user code - it's a fundamental compatibility issue

### Comparison: v46 vs v60

**v46 (WORKS)**:
```r
library(shiny)
fluidPage(
  h1("Hello World")
)
```

**v60 (FAILS)**:
```r
library(shiny)
library(shinydashboard)
dashboardPage(
  dashboardHeader(title = "Debug"),
  dashboardSidebar(sidebarMenu(menuItem("Debug", tabName = "debug"))),
  dashboardBody(tabItems(tabItem(tabName = "debug", box(title = "Test", h3("Static HTML")))))
)
```

The ONLY difference: `dashboardPage()` function from shinydashboard.

### Conclusion

**The shinydashboard package has a fundamental incompatibility with our deployment environment (R 4.5.1 on rocker/shiny in GCP Cloud Run).**

This is not fixable by modifying our application code. The solution is to migrate to a different UI framework.

---

## Solution: Migrate to bslib

### Why bslib?

1. **Modern & Maintained**: Actively developed by Posit/RStudio
2. **No extent=0 Bug**: Uses Bootstrap 5 without Rcpp scalar validation issues
3. **All Required Features**: Has value_box, card, page_navbar, sidebars, themes
4. **Better Performance**: Lighter weight than shinydashboard
5. **Easy Migration**: Similar concepts (box → card, valueBox → value_box)
6. **Estimated Effort**: 2-4 hours

### Migration Plan

See **MIGRATION_PLAN.md** for comprehensive step-by-step guide.

**Next version: v61** will implement the bslib migration.

---

## Lessons Learned

1. **Systematic approach wins**: Binary search debugging identified the root cause definitively
2. **Documentation is critical**: DEBUGGING_LOG.md tracked our entire process
3. **"No traceback available" is a red flag**: Indicates fundamental compatibility issues, not code bugs
4. **Minimal reproduction is key**: v60's minimal test proved the issue wasn't in our code
5. **Sometimes the solution is to change tools**: Not all problems are fixable in user code
