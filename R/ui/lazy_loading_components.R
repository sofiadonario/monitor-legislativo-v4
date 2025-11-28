# Lazy Loading & Virtual Scrolling Components - Week 8 Performance
# Monitor Legislativo v4 - Efficient UI for 134k+ Documents
# ===============================================================
# Advanced UI components with lazy loading and virtual scrolling
# optimized for Brazilian legislative document browsing on Railway

# Check and load required packages
LAZY_LOADING_DEPENDENCIES <- requireNamespace("shiny", quietly = TRUE) &&
                                requireNamespace("DT", quietly = TRUE) &&
                                requireNamespace("htmlwidgets", quietly = TRUE)

if (!LAZY_LOADING_DEPENDENCIES) {
  warning("lazy_loading_components dependencies not available (shiny, DT, htmlwidgets)")
}


# shinydashboard loaded via R/000_load_shinydashboard.R preload file
