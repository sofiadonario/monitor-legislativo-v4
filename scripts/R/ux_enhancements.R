# UX ENHANCEMENTS - Monitor Legislativo v4
# User Experience Restoration Implementation
# Addresses critical UX issues identified in Phase 1 assessment

cat("🎨 Loading UX Enhancement Layer\n")

# Enhanced CSS for loading states and user feedback
enhanced_ui_css <- "
/* Loading overlays for better user feedback */
.map-loading-overlay {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(255, 255, 255, 0.9);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  border-radius: 4px;
}

.loading-content {
  text-align: center;
  color: #e1001e;
  font-weight: bold;
}

.loading-spinner {
  color: #e1001e;
  margin-bottom: 10px;
}

/* Enhanced DataTable loading states */
.dataTables_processing {
  background: rgba(225, 0, 30, 0.1) !important;
  color: #e1001e !important;
  font-weight: bold !important;
  border: 2px solid #e1001e !important;
}

/* Progress indicators */
.progress-indicator {
  background: linear-gradient(90deg, #e1001e 0%, #c50019 100%);
  height: 4px;
  width: 100%;
  animation: progress-animation 2s ease-in-out infinite;
}

@keyframes progress-animation {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}

/* User feedback notifications */
.notification-success {
  background-color: #d4edda !important;
  border-color: #c3e6cb !important;
  color: #155724 !important;
}

.notification-error {
  background-color: #f8d7da !important;
  border-color: #f5c6cb !important;
  color: #721c24 !important;
}

.notification-info {
  background-color: #d1ecf1 !important;
  border-color: #bee5eb !important;
  color: #0c5460 !important;
}

/* Enhanced search interface */
.search-filters-container {
  background: #f8f9fa;
  padding: 15px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.search-result-summary {
  background: #e8f4f8;
  padding: 10px;
  border-left: 4px solid #e1001e;
  margin-bottom: 15px;
}

/* Data export buttons */
.export-options {
  margin-top: 15px;
  padding: 10px;
  background: #f8f9fa;
  border-radius: 4px;
}

.export-btn {
  margin-right: 10px;
  margin-bottom: 5px;
}

/* Academic citation tools */
.citation-tools {
  background: #fff3cd;
  border: 1px solid #ffeaa7;
  padding: 15px;
  border-radius: 4px;
  margin-top: 10px;
}

/* Responsive improvements */
@media (max-width: 768px) {
  .box-header h3 {
    font-size: 16px !important;
  }
  
  .value-box-text {
    font-size: 14px !important;
  }
  
  .leaflet-container {
    height: 300px !important;
  }
}

/* Accessibility improvements */
.btn:focus, .btn:active:focus {
  outline: 3px solid #ffbf47 !important;
  outline-offset: 2px !important;
}

/* Data quality indicators */
.data-quality-indicator {
  display: inline-block;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  margin-right: 5px;
}

.data-quality-high { background-color: #28a745; }
.data-quality-medium { background-color: #ffc107; }
.data-quality-low { background-color: #dc3545; }
"

# Enhanced loading state functions
show_loading <- function(element_id, message = "Loading...") {
  paste0("
    $('#", element_id, "-loading').show();
    $('#", element_id, "-loading .loading-message').text('", message, "');
  ")
}

hide_loading <- function(element_id) {
  paste0("$('#", element_id, "-loading').hide();")
}

# User feedback notification system
show_notification <- function(message, type = "info", duration = 5000) {
  type_class <- switch(type,
    "success" = "notification-success",
    "error" = "notification-error", 
    "warning" = "notification-warning",
    "notification-info"
  )
  
  paste0("
    Shiny.notifications.show({
      html: '<div class=\"", type_class, "\" style=\"padding: 10px; border-radius: 4px;\">",
      message, "</div>',
      duration: ", duration, ",
      closeButton: true
    });
  ")
}

# Enhanced search interface improvements
get_search_filter_ui <- function() {
  div(class = "search-filters-container",
    h4("🔍 Advanced Search & Filter Options", style = "color: #e1001e; margin-bottom: 15px;"),
    
    fluidRow(
      column(12,
        textInput("searchText", "Search Terms:", 
                 placeholder = "Enter keywords to search across 278,152 documents...",
                 width = "100%")
      )
    ),
    
    fluidRow(
      column(4,
        selectizeInput("documentTypeFilter", "Document Type:", 
                     choices = list(
                       "All Documents" = "",
                       "Legislation" = "legislacao", 
                       "Jurisprudence" = "jurisprudencia",
                       "Doctrine" = "doutrina",
                       "Other" = "outros"
                     ), 
                     selected = "",
                     options = list(placeholder = "Select document type"))
      ),
      column(4,
        selectizeInput("transportModeFilter", "Transport Mode:", 
                     choices = list(
                       "All Modes" = "",
                       "General" = "geral",
                       "Road Transport" = "rodoviario", 
                       "Air Transport" = "aereo",
                       "Maritime Transport" = "maritimo"
                     ), 
                     selected = "",
                     options = list(placeholder = "Select transport mode"))
      ),
      column(4,
        selectizeInput("stateFilter", "Geographic Scope:", 
                     choices = NULL, 
                     multiple = TRUE,
                     options = list(placeholder = "Select states/regions"))
      )
    ),
    
    fluidRow(
      column(6,
        dateInput("dateFromFilter", "Date From:", 
                 value = NULL,
                 format = "dd/mm/yyyy",
                 language = "pt-BR")
      ),
      column(6,
        dateInput("dateToFilter", "Date To:", 
                 value = NULL,
                 format = "dd/mm/yyyy", 
                 language = "pt-BR")
      )
    ),
    
    hr(),
    
    div(class = "text-center",
      actionButton("executeSearch", "🔍 Search Documents", 
                   class = "btn-primary btn-lg", 
                   style = "margin-right: 10px;"),
      actionButton("clearFilters", "✖️ Clear All", 
                   class = "btn-secondary"),
      actionButton("saveSearch", "💾 Save Search", 
                   class = "btn-info", 
                   style = "margin-left: 10px;")
    )
  )
}

# Enhanced data export functionality for academic users
get_export_options_ui <- function() {
  div(class = "export-options",
    h5("📥 Data Export Options", style = "color: #e1001e;"),
    p("Export search results in multiple formats for academic research:"),
    
    fluidRow(
      column(3,
        downloadButton("exportCSV", "CSV Format", 
                      class = "btn-success export-btn",
                      icon = icon("table"))
      ),
      column(3,
        downloadButton("exportExcel", "Excel Format", 
                      class = "btn-success export-btn",
                      icon = icon("file-excel"))
      ),
      column(3,
        downloadButton("exportJSON", "JSON Format", 
                      class = "btn-success export-btn",
                      icon = icon("code"))
      ),
      column(3,
        downloadButton("exportBibTeX", "BibTeX Citations", 
                      class = "btn-info export-btn",
                      icon = icon("quote-right"))
      )
    ),
    
    # Academic citation tools
    div(class = "citation-tools",
      h6("📚 Academic Citation Tools"),
      p("Generate properly formatted citations for academic papers:"),
      selectInput("citationStyle", "Citation Style:",
                 choices = list(
                   "ABNT (Brazilian Standard)" = "abnt",
                   "APA Style" = "apa", 
                   "Chicago Style" = "chicago",
                   "Vancouver Style" = "vancouver"
                 ),
                 selected = "abnt"),
      actionButton("generateCitations", "Generate Citations", 
                   class = "btn-info btn-sm")
    )
  )
}

# Performance optimization for large datasets
optimize_datatable_performance <- function(data, max_display = 1000) {
  if (nrow(data) > max_display) {
    # Show warning for large datasets
    list(
      data = data[1:max_display, ],
      warning = paste("Showing first", max_display, "of", nrow(data), "results for performance. Use filters to refine your search.")
    )
  } else {
    list(data = data, warning = NULL)
  }
}

# Enhanced user guidance system
get_user_guidance <- function(user_type = "general") {
  guidance <- switch(user_type,
    "academic" = list(
      title = "👨‍🎓 Academic Researcher Guide",
      tips = c(
        "Use advanced filters to narrow down to specific legal domains",
        "Export results in BibTeX format for citation management",
        "Geographic analysis provides policy diffusion insights",
        "Temporal analysis shows regulatory evolution patterns"
      )
    ),
    "policymaker" = list(
      title = "🏛️ Policymaker Dashboard Guide", 
      tips = c(
        "Dashboard provides executive overview of regulatory landscape",
        "Maps show geographic distribution of policy activity",
        "Analytics section offers forecasting and trend analysis",
        "Search by state to understand local vs federal regulation"
      )
    ),
    "citizen" = list(
      title = "👥 Citizen Access Guide",
      tips = c(
        "Use simple search terms to find relevant regulations",
        "Filter by transport mode for specific interests",
        "Document details provide plain language summaries",
        "Maps show which regulations apply in your region"
      )
    ),
    list(
      title = "📖 Platform Guide",
      tips = c(
        "Platform contains 278,152 legislative documents from 1829-2025",
        "Use filters to refine searches across the full dataset",
        "Interactive maps provide geographic context",
        "Export functionality supports academic and professional use"
      )
    )
  )
  
  div(class = "alert alert-info",
    h5(guidance$title),
    tags$ul(
      lapply(guidance$tips, function(tip) tags$li(tip))
    )
  )
}

# Error handling and graceful degradation
handle_data_loading_error <- function(error_message, fallback_action = NULL) {
  div(class = "alert alert-warning",
    h5("⚠️ Data Loading Issue"),
    p("We encountered an issue loading data from the database:"),
    tags$code(error_message),
    if (!is.null(fallback_action)) {
      div(
        hr(),
        p("Attempting to load from backup data source..."),
        fallback_action
      )
    } else {
      div(
        hr(),
        p("Please try refreshing the page or contact support if the issue persists.")
      )
    }
  )
}

# Accessibility enhancements
add_accessibility_features <- function() {
  list(
    # Screen reader support
    tags$script(HTML("
      // Add ARIA labels to dynamic content
      $(document).ready(function() {
        $('.leaflet-container').attr('aria-label', 'Interactive map showing legislative document distribution');
        $('.dataTables_wrapper').attr('aria-label', 'Data table with legislative documents');
        $('.progress-bar').attr('aria-label', 'Loading progress indicator');
      });
    ")),
    
    # Keyboard navigation improvements
    tags$script(HTML("
      // Enhanced keyboard navigation
      $(document).on('keydown', function(e) {
        if (e.altKey && e.key === 's') {
          e.preventDefault();
          $('#executeSearch').focus().click();
        }
        if (e.altKey && e.key === 'c') {
          e.preventDefault(); 
          $('#clearFilters').focus().click();
        }
      });
    ")),
    
    # High contrast mode support
    tags$style(HTML("
      @media (prefers-contrast: high) {
        .btn-primary { 
          background-color: #000 !important; 
          border-color: #fff !important; 
          color: #fff !important; 
        }
        .box { 
          border: 2px solid #000 !important; 
        }
      }
    "))
  )
}

cat("✅ UX Enhancement Layer loaded successfully\n")