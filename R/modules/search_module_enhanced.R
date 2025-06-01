# Advanced Search Module - Week 3 Implementation
# Monitor Legislativo v4 - Enhanced Search System
# ================================================

#' Advanced Legislative Document Search Module UI
#' 
#' Comprehensive Shiny module UI for searching Brazilian legislative documents
#' with advanced PostgreSQL full-text search, geographic filters, temporal analysis,
#' auto-complete functionality, and LGPD-compliant security features.
#' Designed specifically for academic research workflows in legislative analysis.
#' 
#' Week 3 Implementation: Advanced Search System with <2s response time target
#' for complex queries on 134k+ Brazilian legislative documents.
#' 
#' This module provides a complete search interface including intelligent text input
#' with auto-complete, advanced geographic and temporal filters, faceted search,
#' results display with relevance scoring, and export functionality optimized
#' for Brazilian legal document research.
#' 
#' @details
#' **Advanced UI Components:**
#' - **Smart Search Input**: Auto-complete text input with Portuguese legal term suggestions
#' - **Geographic Filters**: Brazilian states and municipalities with hierarchical selection
#' - **Temporal Filters**: Date ranges, validity periods, and year-based filtering  
#' - **Document Type Filters**: Lei, decreto, portaria, resolução with faceted counts
#' - **Advanced Query Operators**: AND, OR, NOT, phrase search, fuzzy matching
#' - **Results Display**: Interactive DataTable with relevance scoring and highlighting
#' - **Search Analytics**: Real-time performance metrics and search statistics
#' - **Export Options**: CSV, BibTeX, and JSON with ABNT-compliant citations
#' 
#' **Advanced Academic Features:**
#' - PostgreSQL full-text search with Portuguese language processing
#' - Intelligent relevance ranking with legal term boosting
#' - Auto-complete with Brazilian legal terminology
#' - Hierarchical geographic filtering (state → municipality)
#' - Advanced temporal analysis with date ranges and validity periods
#' - Faceted search with result counts per category
#' - Search result highlighting with contextual snippets
#' - Performance monitoring with <2s response time target
#' 
#' **Accessibility:**
#' - Screen reader compatible labels and descriptions
#' - Keyboard navigation support with auto-complete
#' - Mobile-responsive layout for field research
#' - Progressive disclosure of advanced features
#' 
#' @param id Character string for module namespace ID
#' @return Shiny UI tagList containing all advanced search interface elements
#' @family search-modules
#' @export
searchAdvancedUI <- function(id) {
  ns <- NS(id)
  
  tagList(
    # Advanced Search Input Section with Auto-complete
    fluidRow(
      column(
        width = 10,
        div(
          class = "search-input-container",
          style = "position: relative;",
          textInput(
            ns("query"),
            "Search Legislative Documents",
            placeholder = "Enter search terms (e.g., 'transporte público', 'lei orgânica', 'direito administrativo')",
            width = "100%"
          ),
          # Auto-complete dropdown (dynamically populated)
          div(
            id = ns("autocomplete_dropdown"),
            class = "autocomplete-dropdown",
            style = "display: none; position: absolute; top: 100%; left: 0; right: 0; z-index: 1000;",
            uiOutput(ns("suggestions"))
          )
        ),
        # Search operators help
        div(
          class = "search-help text-muted small",
          style = "margin-top: 5px;",
          HTML("Use quotes for exact phrases, + for required terms, - to exclude terms. <a href='#' onclick='$(\"#search-help-modal\").modal(\"show\");'>Advanced operators</a>")
        )
      ),
      column(
        width = 2,
        br(),
        actionButton(
          ns("search"),
          "Search",
          class = "btn-primary btn-block",
          icon = icon("search"),
          style = "height: 38px;"
        )
      )
    ),
    
    # Advanced Filters (Collapsible)
    div(
      id = ns("filters_container"),
      style = "margin-top: 15px;",
      
      actionButton(
        ns("toggle_filters"),
        "Advanced Filters",
        icon = icon("filter"),
        class = "btn-secondary btn-sm"
      ),
      
      conditionalPanel(
        condition = paste0("input['", ns("toggle_filters"), "'] % 2 == 1"),
        
        br(), br(),
        
        wellPanel(
          # Geographic Filters Row
          fluidRow(
            column(4,
              selectInput(
                ns("estado"),
                "State (Estado)",
                choices = c("All States" = ""),
                width = "100%"
              ),
              conditionalPanel(
                condition = paste0("input['", ns("estado"), "'] != ''"),
                selectInput(
                  ns("municipio"),
                  "Municipality (Município)",
                  choices = c("All Municipalities" = ""),
                  width = "100%"
                )
              )
            ),
            column(4,
              selectInput(
                ns("tipo"),
                "Document Type (Tipo)",
                choices = c("All Types" = ""),
                width = "100%"
              ),
              selectInput(
                ns("categoria"),
                "Category (Categoria)",
                choices = c("All Categories" = ""),
                width = "100%"
              )
            ),
            column(4,
              dateInput(
                ns("data_inicio"),
                "Start Date",
                value = as.Date("2000-01-01"),
                format = "dd/mm/yyyy",
                language = "pt-BR",
                width = "100%"
              ),
              dateInput(
                ns("data_fim"),
                "End Date",
                value = Sys.Date(),
                format = "dd/mm/yyyy",
                language = "pt-BR",
                width = "100%"
              )
            )
          ),
          
          # Year Range and Advanced Options Row
          fluidRow(
            column(3,
              numericInput(
                ns("ano_min"),
                "Year From",
                value = 2000,
                min = 1900,
                max = 2025,
                width = "100%"
              )
            ),
            column(3,
              numericInput(
                ns("ano_max"),
                "Year To",
                value = 2025,
                min = 1900,
                max = 2025,
                width = "100%"
              )
            ),
            column(3,
              selectInput(
                ns("sort_by"),
                "Sort By",
                choices = list(
                  "Relevance" = "relevance",
                  "Date (Newest)" = "date_desc",
                  "Date (Oldest)" = "date_asc",
                  "Title" = "title"
                ),
                selected = "relevance",
                width = "100%"
              )
            ),
            column(3,
              checkboxInput(
                ns("fuzzy_search"),
                "Enable fuzzy search",
                value = FALSE
              ),
              checkboxInput(
                ns("phrase_search"),
                "Exact phrase search",
                value = FALSE
              )
            )
          ),
          
          # Search Options and Performance Settings Row
          fluidRow(
            column(4,
              numericInput(
                ns("limit"),
                "Max Results",
                value = 100,
                min = 10,
                max = 1000,
                step = 10,
                width = "100%"
              )
            ),
            column(4,
              checkboxInput(
                ns("include_content"),
                "Include full content in results",
                value = FALSE
              ),
              checkboxInput(
                ns("include_highlights"),
                "Show search term highlights",
                value = TRUE
              )
            ),
            column(4,
              # Search performance indicator
              div(
                class = "search-performance",
                style = "margin-top: 25px;",
                uiOutput(ns("search_performance"))
              )
            )
          )
        )
      )
    ),
    
    # Search Statistics and Faceted Navigation
    div(
      id = ns("stats_container"),
      style = "margin-top: 15px;",
      fluidRow(
        column(8,
          uiOutput(ns("search_stats"))
        ),
        column(4,
          uiOutput(ns("faceted_navigation"))
        )
      )
    ),
    
    # Advanced Results Display with Tabs
    div(
      id = ns("results_container"),
      style = "margin-top: 20px;",
      
      tabsetPanel(
        id = ns("results_tabs"),
        type = "tabs",
        
        tabPanel(
          "Search Results",
          value = "results",
          br(),
          DT::DTOutput(ns("results")),
          
          # Quick action buttons for selected results
          br(),
          conditionalPanel(
            condition = paste0("output['", ns("results"), "_rows_selected'] != null"),
            div(
              class = "selected-actions",
              actionButton(
                ns("cite_selected"),
                "Cite Selected",
                class = "btn-sm btn-secondary",
                icon = icon("quote-right")
              ),
              actionButton(
                ns("export_selected"),
                "Export Selected",
                class = "btn-sm btn-secondary",
                icon = icon("download")
              )
            )
          )
        ),
        
        tabPanel(
          "Search Analytics",
          value = "analytics",
          br(),
          fluidRow(
            column(6,
              h4("Search Performance"),
              tableOutput(ns("search_performance_table"))
            ),
            column(6,
              h4("Popular Search Terms"),
              tableOutput(ns("popular_terms_table"))
            )
          )
        )
      ),
      
      # Export Options
      div(
        style = "margin-top: 15px;",
        
        fluidRow(
          column(8,
            downloadButton(
              ns("export_csv"),
              "Export CSV",
              class = "btn-secondary",
              icon = icon("download")
            ),
            
            downloadButton(
              ns("export_bibtex"),
              "Export BibTeX",
              class = "btn-secondary",
              icon = icon("quote-right")
            ),
            
            downloadButton(
              ns("export_json"),
              "Export JSON",
              class = "btn-secondary",
              icon = icon("code")
            ),
            
            # Save search button
            actionButton(
              ns("save_search"),
              "Save Search",
              class = "btn-secondary",
              icon = icon("bookmark")
            )
          ),
          column(4,
            div(
              class = "pull-right",
              uiOutput(ns("pagination_info"))
            )
          )
        )
      )
    ),
    
    # Advanced Search Help Modal
    div(
      class = "modal fade",
      id = "search-help-modal",
      tabindex = "-1",
      HTML('
        <div class="modal-dialog modal-lg">
          <div class="modal-content">
            <div class="modal-header">
              <h4 class="modal-title">Advanced Search Operators</h4>
              <button type="button" class="close" data-dismiss="modal">&times;</button>
            </div>
            <div class="modal-body">
              <h5>Search Operators</h5>
              <table class="table table-sm">
                <tr><th>Operator</th><th>Description</th><th>Example</th></tr>
                <tr><td>"phrase"</td><td>Exact phrase search</td><td>"direito público"</td></tr>
                <tr><td>+term</td><td>Required term</td><td>+lei +federal</td></tr>
                <tr><td>-term</td><td>Exclude term</td><td>lei -municipal</td></tr>
                <tr><td>OR</td><td>Either term</td><td>lei OR decreto</td></tr>
                <tr><td>AND</td><td>Both terms</td><td>transporte AND público</td></tr>
                <tr><td>*</td><td>Wildcard</td><td>admin* (administration, administrative)</td></tr>
              </table>
              <h5>Tips for Better Results</h5>
              <ul>
                <li>Use specific legal terms for better relevance</li>
                <li>Combine geographic and temporal filters</li>
                <li>Enable fuzzy search for typo tolerance</li>
                <li>Use exact phrase search for legal citations</li>
              </ul>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
            </div>
          </div>
        </div>
      ')
    ),
    
    # Auto-complete CSS and JavaScript
    tags$style(HTML("
      .autocomplete-dropdown {
        background: white;
        border: 1px solid #ccc;
        border-top: none;
        border-radius: 0 0 4px 4px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        max-height: 200px;
        overflow-y: auto;
      }
      .autocomplete-item {
        padding: 8px 12px;
        cursor: pointer;
        border-bottom: 1px solid #eee;
      }
      .autocomplete-item:hover {
        background-color: #f5f5f5;
      }
      .autocomplete-item.selected {
        background-color: #337ab7;
        color: white;
      }
      .search-performance {
        font-size: 0.85em;
        color: #666;
      }
      .faceted-navigation {
        background: #f8f9fa;
        padding: 10px;
        border-radius: 4px;
        font-size: 0.9em;
      }
      .facet-item {
        margin: 2px 0;
        cursor: pointer;
      }
      .facet-count {
        color: #666;
        font-size: 0.85em;
      }
    "))
  )
}

cat("✅ Advanced Search UI Module loaded - Week 3 Implementation\n")