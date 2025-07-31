# SEARCH INTERFACE FIX - Monitor Legislativo v4
# Fixes critical UI inconsistencies in the search functionality
# Addresses "Gender:" field mislabeling and other interface issues

cat("🔧 Loading Search Interface Fix\n")

# Fixed search UI with proper labels and user-friendly interface
get_corrected_search_ui <- function(database_connected = TRUE) {
  if (database_connected) {
    div(
      fluidRow(
        column(12,
          textInput("searchText", "🔍 Search Terms:", 
                   placeholder = "Enter keywords to search across 278,152 legislative documents...",
                   width = "100%")
        )
      ),
      fluidRow(
        column(4,
          selectizeInput("documentTypeFilter", "📄 Document Type:", 
                       choices = list(
                         "All Types" = "", 
                         "Legislation (Laws & Decrees)" = "legislacao", 
                         "Jurisprudence (Court Decisions)" = "jurisprudencia",
                         "Doctrine (Academic Papers)" = "doutrina",
                         "Other Documents" = "outros"
                       ), 
                       selected = "",
                       options = list(placeholder = "Select document type"))
        ),
        column(4,
          selectizeInput("transportModeFilter", "🚛 Transport Mode:", 
                       choices = NULL, 
                       multiple = TRUE,
                       options = list(placeholder = "Select transport modes"))
        ),
        column(4,
          selectizeInput("authorityFilter", "🏛️ Authority Level:", 
                       choices = list(
                         "All Levels" = "",
                         "Federal" = "federal",
                         "State" = "state", 
                         "Municipal" = "municipal",
                         "Regional" = "regional"
                       ),
                       selected = "",
                       options = list(placeholder = "Select authority level"))
        )
      ),
      fluidRow(
        column(6,
          selectizeInput("stateFilter", "🗺️ Geographic Scope:", 
                       choices = NULL, 
                       multiple = TRUE,
                       options = list(placeholder = "Select states (optional)"))
        ),
        column(3,
          dateInput("dateFromFilter", "📅 Date From:", 
                   value = NULL,
                   format = "dd/mm/yyyy",
                   language = "pt-BR")
        ),
        column(3,
          dateInput("dateToFilter", "📅 Date To:", 
                   value = NULL,
                   format = "dd/mm/yyyy",
                   language = "pt-BR")
        )
      ),
      hr(),
      fluidRow(
        column(12,
          div(class = "text-center",
            actionButton("searchBtn", "🔍 Search Documents", 
                        icon = icon("search"), 
                        class = "btn-primary btn-lg",
                        style = "margin-right: 10px;"),
            actionButton("clearBtn", "🗑️ Clear Filters", 
                        icon = icon("times"), 
                        class = "btn-secondary",
                        style = "margin-right: 10px;"),
            actionButton("advancedOptions", "⚙️ Advanced Options", 
                        icon = icon("cog"), 
                        class = "btn-info")
          )
        )
      ),
      
      # Advanced options panel (collapsible)
      conditionalPanel(
        condition = "input.advancedOptions % 2 == 1",
        div(style = "margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 4px;",
          h5("⚙️ Advanced Search Options"),
          fluidRow(
            column(4,
              selectizeInput("yearRange", "📊 Year Range:",
                           choices = NULL,
                           multiple = TRUE,
                           options = list(placeholder = "Select years"))
            ),
            column(4,
              selectizeInput("legalInstrument", "📋 Legal Instrument:",
                           choices = list(
                             "All Instruments" = "",
                             "Law" = "lei",
                             "Decree" = "decreto", 
                             "Resolution" = "resolucao",
                             "Ordinance" = "portaria",
                             "Instruction" = "instrucao"
                           ),
                           selected = "",
                           options = list(placeholder = "Select instrument type"))
            ),
            column(4,
              selectizeInput("regulatoryAgency", "🏢 Regulatory Agency:",
                           choices = NULL,
                           multiple = TRUE,
                           options = list(placeholder = "Select agencies"))
            )
          ),
          fluidRow(
            column(6,
              checkboxInput("includeRevoked", "Include Revoked Documents", value = FALSE)
            ),
            column(6,
              checkboxInput("fullTextSearch", "Full Text Search (slower)", value = FALSE)
            )
          )
        )
      ),
      
      hr(),
      
      # Search results section with enhanced feedback
      div(id = "searchResultsContainer",
        # Search summary
        conditionalPanel(
          condition = "output.searchExecuted",
          div(class = "search-result-summary",
            uiOutput("searchSummary"),
            
            # Export options for results
            div(style = "margin-top: 10px;",
              downloadButton("exportSearchCSV", "📥 Export CSV", 
                           class = "btn-success btn-sm export-btn"),
              downloadButton("exportSearchExcel", "📊 Export Excel", 
                           class = "btn-success btn-sm export-btn"),
              downloadButton("exportCitations", "📚 Export Citations", 
                           class = "btn-info btn-sm export-btn")
            )
          )
        ),
        
        # Loading indicator for search
        div(id = "searchLoading", style = "display: none; text-align: center; padding: 20px;",
          icon("spinner", class = "fa-spin fa-2x", style = "color: #e1001e;"),
          br(), br(),
          h5("Searching across 278,152 documents...", style = "color: #e1001e;"),
          div(class = "progress", style = "width: 60%; margin: 0 auto;",
            div(class = "progress-bar", style = "width: 0%; background-color: #e1001e;", 
                id = "searchProgressBar")
          )
        ),
        
        # Search results table
        DT::dataTableOutput("searchResults")
      )
    )
  } else {
    # Fallback UI when database is not connected
    div(
      class = "alert alert-warning",
      icon("database"), 
      h4("Search Functionality Temporarily Unavailable"),
      p("The search feature requires database connectivity to access the full dataset of 278,152 documents."),
      p("Current status: Database connection not established."),
      hr(),
      p("Available alternatives:"),
      tags$ul(
        tags$li("Browse documents by category in the Documents tab"),
        tags$li("View overview statistics in the Dashboard"),
        tags$li("Check connection status and retry")
      ),
      actionButton("retryConnection", "🔄 Retry Database Connection", 
                   class = "btn-primary")
    )
  }
}

# Enhanced search result summary
generate_search_summary <- function(results, search_params) {
  if (is.null(results) || nrow(results) == 0) {
    return(div(class = "alert alert-info",
      icon("info-circle"),
      " No documents found matching your search criteria. Try adjusting your filters or search terms."
    ))
  }
  
  total_docs <- nrow(results)
  
  # Document type breakdown
  type_breakdown <- table(results$tipo)
  
  # Geographic breakdown  
  state_breakdown <- table(results$estado)
  top_states <- head(sort(state_breakdown, decreasing = TRUE), 3)
  
  # Date range
  date_range <- if ("data" %in% names(results)) {
    min_date <- min(results$data, na.rm = TRUE)
    max_date <- max(results$data, na.rm = TRUE)
    paste("from", format(min_date, "%Y"), "to", format(max_date, "%Y"))
  } else {
    "Date range not available"
  }
  
  div(
    h5(paste("📊 Search Results:", format(total_docs, big.mark = ","), "documents found")),
    
    fluidRow(
      column(4,
        h6("📄 Document Types:"),
        tags$ul(
          lapply(names(type_breakdown), function(type) {
            count <- type_breakdown[type]
            percentage <- round(count / total_docs * 100, 1)
            tags$li(paste(type, ":", count, "(", percentage, "%)"))
          })
        )
      ),
      column(4,
        h6("🗺️ Top Regions:"),
        tags$ul(
          lapply(names(top_states), function(state) {
            count <- top_states[state]
            percentage <- round(count / total_docs * 100, 1)
            tags$li(paste(state, ":", count, "(", percentage, "%)"))
          })
        )
      ),
      column(4,
        h6("📅 Temporal Coverage:"),
        p(date_range),
        if (!is.null(search_params$search_text) && search_params$search_text != "") {
          p(paste("Search terms:", tags$em(search_params$search_text)))
        }
      )
    )
  )
}

# User-friendly error messages
get_user_friendly_error <- function(error_type, error_message = NULL) {
  switch(error_type,
    "database" = div(class = "alert alert-danger",
      icon("exclamation-triangle"),
      h5("Database Connection Error"),
      p("We're having trouble connecting to the document database."),
      p("This may be due to:"),
      tags$ul(
        tags$li("Temporary server maintenance"),
        tags$li("Network connectivity issues"), 
        tags$li("High system load")
      ),
      p("Please try again in a few moments or contact support if the issue persists.")
    ),
    
    "search" = div(class = "alert alert-warning",
      icon("search"),
      h5("Search Error"),
      p("Your search could not be completed."),
      if (!is.null(error_message)) p(paste("Technical details:", error_message)),
      p("Suggestions:"),
      tags$ul(
        tags$li("Try simpler search terms"),
        tags$li("Remove some filters to broaden results"),
        tags$li("Check date ranges are valid")
      )
    ),
    
    "export" = div(class = "alert alert-warning", 
      icon("download"),
      h5("Export Error"),
      p("We couldn't export your results at this time."),
      p("This could be due to:"),
      tags$ul(
        tags$li("Large result set (try filtering first)"),
        tags$li("Temporary server overload"),
        tags$li("File format not supported")
      )
    ),
    
    # Default error
    div(class = "alert alert-danger",
      icon("exclamation"),
      h5("Unexpected Error"),
      p("Something went wrong. Please refresh the page and try again."),
      if (!is.null(error_message)) {
        div(
          hr(),
          h6("Technical Details:"),
          tags$code(error_message)
        )
      }
    )
  )
}

# Performance optimization for search results
optimize_search_results <- function(results, max_display = 1000) {
  if (is.null(results) || nrow(results) == 0) {
    return(list(data = NULL, message = "No results found"))
  }
  
  total_results <- nrow(results)
  
  if (total_results > max_display) {
    optimized_results <- results[1:max_display, ]
    message <- paste(
      "Displaying first", format(max_display, big.mark = ","), 
      "of", format(total_results, big.mark = ","), 
      "results for optimal performance. Use filters to refine your search."
    )
    
    list(
      data = optimized_results,
      message = message,
      total_count = total_results,
      showing_count = max_display
    )
  } else {
    list(
      data = results,
      message = paste("Showing all", format(total_results, big.mark = ","), "results"),
      total_count = total_results, 
      showing_count = total_results
    )
  }
}

cat("✅ Search Interface Fix loaded successfully\n")
cat("   - Fixed 'Gender:' mislabeling to 'Document Type:'\n")
cat("   - Added user-friendly field labels with icons\n") 
cat("   - Implemented progressive disclosure for advanced options\n")
cat("   - Enhanced error handling and user feedback\n")
cat("   - Added performance optimization for large result sets\n")