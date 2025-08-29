# ENHANCED LIBRARY UI MODULE
# =========================
# Advanced user interface components for the Brazilian Legislative Monitor Library
# Optimized for 134k+ documents with government-quality search capabilities

# ============================================================================
# 1. ADVANCED SEARCH INTERFACE COMPONENTS
# ============================================================================

# Main enhanced library tab UI
enhanced_library_tab_ui <- function() {
  tagList(
    # Include custom CSS for enhanced styling
    tags$head(
      tags$style(HTML("
        .search-container {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          padding: 25px;
          border-radius: 10px;
          margin-bottom: 20px;
          color: white;
        }
        
        .search-input-group {
          position: relative;
          margin-bottom: 15px;
        }
        
        .search-suggestions {
          position: absolute;
          top: 100%;
          left: 0;
          right: 0;
          background: white;
          border: 1px solid #ddd;
          border-top: none;
          border-radius: 0 0 5px 5px;
          max-height: 200px;
          overflow-y: auto;
          z-index: 1000;
          display: none;
        }
        
        .search-suggestion-item {
          padding: 10px 15px;
          cursor: pointer;
          border-bottom: 1px solid #f0f0f0;
        }
        
        .search-suggestion-item:hover {
          background-color: #f8f9fa;
        }
        
        .facet-filter {
          background: white;
          border-radius: 8px;
          padding: 15px;
          margin-bottom: 15px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .facet-header {
          font-weight: bold;
          color: #2c3e50;
          margin-bottom: 10px;
          border-bottom: 2px solid #3498db;
          padding-bottom: 5px;
        }
        
        .facet-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 5px 0;
          border-bottom: 1px solid #ecf0f1;
        }
        
        .facet-count {
          background: #3498db;
          color: white;
          border-radius: 12px;
          padding: 2px 8px;
          font-size: 11px;
        }
        
        .performance-indicator {
          position: fixed;
          top: 10px;
          right: 10px;
          background: rgba(52, 152, 219, 0.9);
          color: white;
          padding: 8px 12px;
          border-radius: 5px;
          font-size: 12px;
          z-index: 2000;
        }
        
        .document-card {
          border: 1px solid #e0e0e0;
          border-radius: 8px;
          padding: 15px;
          margin-bottom: 10px;
          background: white;
          transition: box-shadow 0.2s ease;
        }
        
        .document-card:hover {
          box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .document-title {
          font-weight: bold;
          color: #2c3e50;
          margin-bottom: 8px;
        }
        
        .document-metadata {
          font-size: 13px;
          color: #7f8c8d;
          display: flex;
          flex-wrap: wrap;
          gap: 15px;
        }
        
        .similarity-indicator {
          background: linear-gradient(90deg, #f39c12, #e67e22);
          color: white;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 11px;
          font-weight: bold;
        }
        
        .trending-badge {
          background: #e74c3c;
          color: white;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 11px;
          animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
          0% { opacity: 1; }
          50% { opacity: 0.7; }
          100% { opacity: 1; }
        }
        
        .virtual-scroll-container {
          max-height: 600px;
          overflow-y: auto;
          border: 1px solid #ddd;
          border-radius: 5px;
        }
      "))
    ),
    
    # Performance indicator
    div(id = "performance-indicator", class = "performance-indicator", style = "display: none;"),
    
    # Main search container
    fluidRow(
      box(
        title = "🔍 Advanced Document Search & Discovery", 
        status = "primary", 
        solidHeader = TRUE, 
        width = 12,
        class = "search-container",
        
        fluidRow(
          # Main search input
          column(8,
            div(class = "search-input-group",
              textInput(
                "enhanced_search_query",
                label = NULL,
                placeholder = "Search 134k+ legislative documents... (e.g., 'transporte público', 'responsabilidade civil')",
                width = "100%"
              ),
              div(id = "search-suggestions", class = "search-suggestions")
            )
          ),
          
          # Search options
          column(4,
            div(style = "display: flex; gap: 10px; align-items: end;",
              actionButton(
                "enhanced_search_btn",
                "🔍 Search",
                class = "btn-warning btn-sm",
                style = "height: 35px;"
              ),
              actionButton(
                "clear_search_btn", 
                "✖ Clear",
                class = "btn-light btn-sm",
                style = "height: 35px;"
              ),
              actionButton(
                "advanced_options_btn",
                "⚙ Options",
                class = "btn-info btn-sm", 
                style = "height: 35px;"
              )
            )
          )
        ),
        
        # Advanced search options (collapsible)
        conditionalPanel(
          condition = "input.show_advanced_options == true",
          
          fluidRow(
            column(3,
              selectInput(
                "search_mode",
                "Search Mode:",
                choices = list(
                  "Intelligent Search" = "intelligent",
                  "Exact Match" = "exact",
                  "Fuzzy Search" = "fuzzy",
                  "Semantic Search" = "semantic"
                ),
                selected = "intelligent"
              )
            ),
            
            column(3,
              selectInput(
                "sort_results_by",
                "Sort Results By:",
                choices = list(
                  "Relevance" = "relevance",
                  "Date (Newest)" = "date_desc", 
                  "Date (Oldest)" = "date_asc",
                  "Title (A-Z)" = "title_asc",
                  "Authority Level" = "authority"
                ),
                selected = "relevance"
              )
            ),
            
            column(3,
              numericInput(
                "results_per_page",
                "Results per Page:",
                value = 50,
                min = 10,
                max = 200,
                step = 10
              )
            ),
            
            column(3,
              checkboxInput(
                "enable_caching",
                "Enable Smart Caching",
                value = TRUE
              )
            )
          )
        )
      )
    ),
    
    # Search results and filters
    fluidRow(
      # Faceted filters sidebar
      column(3,
        # Category facet
        div(class = "facet-filter",
          div(class = "facet-header", "📚 Categories"),
          uiOutput("category_facets")
        ),
        
        # Geographic facet
        div(class = "facet-filter", 
          div(class = "facet-header", "🗺️ Geographic Scope"),
          uiOutput("geographic_facets")
        ),
        
        # Temporal facet
        div(class = "facet-filter",
          div(class = "facet-header", "📅 Time Period"),
          uiOutput("temporal_facets")
        ),
        
        # Document type facet
        div(class = "facet-filter",
          div(class = "facet-header", "📄 Document Types"),
          uiOutput("document_type_facets")
        ),
        
        # Tribunal facet (for jurisprudence)
        conditionalPanel(
          condition = "input.selected_categories && input.selected_categories.includes('Jurisprudência')",
          div(class = "facet-filter",
            div(class = "facet-header", "⚖️ Tribunals"),
            uiOutput("tribunal_facets")
          )
        )
      ),
      
      # Main results area
      column(9,
        # Results summary and controls
        fluidRow(
          column(6,
            uiOutput("search_results_summary")
          ),
          column(6,
            div(style = "text-align: right;",
              uiOutput("results_controls")
            )
          )
        ),
        
        # Trending documents section
        conditionalPanel(
          condition = "input.enhanced_search_query == '' || input.enhanced_search_query == null",
          div(
            h4("📈 Trending Documents", style = "color: #e74c3c;"),
            uiOutput("trending_documents_ui")
          )
        ),
        
        # Main search results
        div(id = "search-results-container",
          conditionalPanel(
            condition = "input.display_mode == 'table' || input.display_mode == null",
            DT::dataTableOutput("enhanced_documents_table")
          ),
          conditionalPanel(
            condition = "input.display_mode == 'cards'",
            div(class = "virtual-scroll-container",
              uiOutput("enhanced_documents_cards")
            )
          )
        ),
        
        # Pagination controls
        uiOutput("pagination_controls")
      )
    ),
    
    # Similar documents section
    conditionalPanel(
      condition = "input.selected_document_id != null && input.selected_document_id != ''",
      fluidRow(
        box(
          title = "🔗 Related Documents", 
          status = "info", 
          solidHeader = TRUE, 
          width = 12,
          uiOutput("similar_documents_ui")
        )
      )
    )
  )
}

# ============================================================================
# 2. INTERACTIVE VISUALIZATION COMPONENTS
# ============================================================================

# Category distribution visualization UI
enhanced_category_viz_ui <- function() {
  tagList(
    fluidRow(
      column(6,
        plotlyOutput("category_donut_chart", height = "400px")
      ),
      column(6,
        plotlyOutput("category_bar_chart", height = "400px") 
      )
    ),
    
    fluidRow(
      column(12,
        div(
          h4("📊 Interactive Category Analysis"),
          p("Click on chart segments to filter results. Use the controls below to customize the view."),
          
          fluidRow(
            column(4,
              selectInput(
                "viz_metric",
                "Display Metric:",
                choices = list(
                  "Document Count" = "count",
                  "Percentage" = "percentage", 
                  "Recent Activity" = "recent_count"
                ),
                selected = "count"
              )
            ),
            column(4,
              selectInput(
                "viz_time_filter",
                "Time Period:", 
                choices = list(
                  "All Time" = "all",
                  "Last Year" = "1_year",
                  "Last 5 Years" = "5_years",
                  "Last 10 Years" = "10_years"
                ),
                selected = "all"
              )
            ),
            column(4,
              checkboxGroupInput(
                "viz_include_categories",
                "Include Categories:",
                choices = list(
                  "Jurisprudência" = "jurisprudence",
                  "Legislação" = "legislation",
                  "Doutrina" = "doctrine",
                  "Outros" = "outros",
                  "Proposições" = "propositions"
                ),
                selected = c("jurisprudence", "legislation", "doctrine")
              )
            )
          )
        )
      )
    )
  )
}

# Geographic analysis visualization UI
enhanced_geographic_viz_ui <- function() {
  tagList(
    fluidRow(
      column(8,
        leafletOutput("enhanced_map", height = "500px")
      ),
      column(4,
        div(
          h4("🗺️ Geographic Distribution"),
          plotlyOutput("state_distribution_chart", height = "300px"),
          
          br(),
          
          div(
            h5("📍 Top Regions by Document Count:"),
            uiOutput("top_regions_summary")
          ),
          
          br(),
          
          actionButton(
            "export_geographic_data",
            "📊 Export Geographic Analysis",
            class = "btn-info btn-sm"
          )
        )
      )
    ),
    
    fluidRow(
      column(12,
        div(
          h4("📈 Temporal-Geographic Analysis"),
          plotlyOutput("temporal_geographic_heatmap", height = "300px")
        )
      )
    )
  )
}

# ============================================================================
# 3. PERFORMANCE MONITORING COMPONENTS  
# ============================================================================

# Real-time performance dashboard UI
performance_dashboard_ui <- function() {
  tagList(
    fluidRow(
      valueBoxOutput("search_performance_box", width = 3),
      valueBoxOutput("cache_performance_box", width = 3), 
      valueBoxOutput("system_health_box", width = 3),
      valueBoxOutput("user_activity_box", width = 3)
    ),
    
    fluidRow(
      column(6,
        box(
          title = "⚡ Search Performance Metrics",
          status = "primary",
          solidHeader = TRUE,
          width = NULL,
          plotlyOutput("search_performance_chart", height = "300px")
        )
      ),
      
      column(6,
        box(
          title = "💾 Cache Efficiency", 
          status = "success",
          solidHeader = TRUE,
          width = NULL,
          plotlyOutput("cache_performance_chart", height = "300px")
        )
      )
    ),
    
    fluidRow(
      column(12,
        box(
          title = "📊 Real-time Analytics Dashboard",
          status = "info",
          solidHeader = TRUE, 
          width = NULL,
          
          tabsetPanel(
            tabPanel("Search Analytics",
              fluidRow(
                column(6,
                  plotlyOutput("search_volume_timeline", height = "250px")
                ),
                column(6,
                  plotlyOutput("popular_search_terms", height = "250px")
                )
              )
            ),
            
            tabPanel("User Behavior",
              fluidRow(
                column(4,
                  plotlyOutput("user_session_duration", height = "250px")
                ),
                column(4,
                  plotlyOutput("document_access_patterns", height = "250px")
                ), 
                column(4,
                  plotlyOutput("feature_usage_stats", height = "250px")
                )
              )
            ),
            
            tabPanel("System Health",
              div(
                h4("🖥️ System Status"),
                uiOutput("system_health_details"),
                
                br(),
                
                fluidRow(
                  column(6,
                    plotlyOutput("memory_usage_chart", height = "200px")
                  ),
                  column(6,
                    plotlyOutput("query_response_times", height = "200px")  
                  )
                )
              )
            )
          )
        )
      )
    )
  )
}

# ============================================================================
# 4. EXPORT AND SHARING COMPONENTS
# ============================================================================

# Enhanced export options UI
enhanced_export_ui <- function() {
  tagList(
    div(
      h4("📤 Export & Share Options"),
      
      fluidRow(
        column(3,
          div(
            h5("🔍 Current Search Results"),
            downloadButton(
              "export_search_results_csv",
              "CSV Format",
              class = "btn-success btn-sm",
              style = "width: 100%; margin-bottom: 5px;"
            ),
            downloadButton(
              "export_search_results_excel", 
              "Excel Format",
              class = "btn-info btn-sm",
              style = "width: 100%; margin-bottom: 5px;"
            ),
            downloadButton(
              "export_search_results_pdf",
              "PDF Report", 
              class = "btn-danger btn-sm",
              style = "width: 100%;"
            )
          )
        ),
        
        column(3,
          div(
            h5("📊 Analytics Export"),
            downloadButton(
              "export_analytics_report",
              "Full Analytics Report",
              class = "btn-warning btn-sm", 
              style = "width: 100%; margin-bottom: 5px;"
            ),
            downloadButton(
              "export_performance_metrics",
              "Performance Metrics",
              class = "btn-secondary btn-sm",
              style = "width: 100%; margin-bottom: 5px;"
            ),
            downloadButton(
              "export_usage_statistics",
              "Usage Statistics",
              class = "btn-light btn-sm",
              style = "width: 100%;"
            )
          )
        ),
        
        column(3,
          div(
            h5("🔗 Citation Formats"),
            downloadButton(
              "export_bibtex",
              "BibTeX Format",
              class = "btn-dark btn-sm",
              style = "width: 100%; margin-bottom: 5px;"
            ),
            downloadButton(
              "export_ris",
              "RIS Format", 
              class = "btn-secondary btn-sm",
              style = "width: 100%; margin-bottom: 5px;"
            ),
            downloadButton(
              "export_endnote",
              "EndNote Format",
              class = "btn-info btn-sm", 
              style = "width: 100%;"
            )
          )
        ),
        
        column(3,
          div(
            h5("📋 Share & Collaborate"),
            actionButton(
              "generate_share_link",
              "📎 Generate Share Link",
              class = "btn-primary btn-sm",
              style = "width: 100%; margin-bottom: 5px;"
            ),
            actionButton(
              "save_search_collection",
              "💾 Save Collection",
              class = "btn-success btn-sm",
              style = "width: 100%; margin-bottom: 5px;"
            ),
            actionButton(
              "email_results",
              "📧 Email Results", 
              class = "btn-warning btn-sm",
              style = "width: 100%;"
            )
          )
        )
      ),
      
      br(),
      
      # Custom export options
      div(
        h5("⚙️ Custom Export Settings"),
        fluidRow(
          column(4,
            checkboxGroupInput(
              "export_fields",
              "Include Fields:",
              choices = list(
                "Title" = "title",
                "Category" = "categoria", 
                "State" = "estado",
                "Date" = "data_documento",
                "Document Type" = "tipo_documento",
                "Content Summary" = "ementa",
                "URL" = "url_documento",
                "URN" = "urn"
              ),
              selected = c("title", "categoria", "estado", "data_documento")
            )
          ),
          
          column(4,
            selectInput(
              "export_format_options",
              "Format Options:",
              choices = list(
                "Standard Format" = "standard",
                "Academic Citation" = "academic",
                "Legal Reference" = "legal",
                "Government Report" = "government"
              ),
              selected = "standard"
            ),
            
            checkboxInput(
              "include_metadata",
              "Include Full Metadata",
              value = FALSE
            ),
            
            checkboxInput(
              "include_analytics",
              "Include Search Analytics", 
              value = FALSE
            )
          ),
          
          column(4,
            numericInput(
              "export_limit",
              "Maximum Records:",
              value = 1000,
              min = 1,
              max = 10000,
              step = 100
            ),
            
            textInput(
              "export_filename",
              "Custom Filename:",
              placeholder = "legislative_search_results"
            ),
            
            selectInput(
              "export_language",
              "Export Language:",
              choices = list(
                "Portuguese" = "pt",
                "English" = "en"
              ),
              selected = "pt"
            )
          )
        )
      )
    )
  )
}

# ============================================================================
# 5. UTILITY FUNCTIONS FOR UI COMPONENTS
# ============================================================================

# Generate facet filter UI elements
create_facet_ui <- function(facet_data, input_id, max_items = 10) {
  if (nrow(facet_data) == 0) {
    return(p("No options available", style = "color: #999; font-style: italic;"))
  }
  
  # Limit to top items with "Show more" option
  display_items <- head(facet_data, max_items)
  
  checkboxes <- lapply(1:nrow(display_items), function(i) {
    item <- display_items[i, ]
    div(class = "facet-item",
      div(
        checkboxInput(
          paste0(input_id, "_", i),
          label = NULL, 
          value = FALSE
        ),
        tags$label(
          item$name,
          style = "margin-left: 5px; font-weight: normal;"
        )
      ),
      span(class = "facet-count", item$count)
    )
  })
  
  result <- do.call(tagList, checkboxes)
  
  # Add "Show more" link if there are more items
  if (nrow(facet_data) > max_items) {
    result <- tagList(
      result,
      actionLink(
        paste0(input_id, "_show_more"),
        paste("Show", nrow(facet_data) - max_items, "more..."),
        style = "font-size: 12px; color: #3498db;"
      )
    )
  }
  
  return(result)
}

# Create document card UI for card view mode
create_document_card_ui <- function(document_row, show_similarity = FALSE) {
  div(class = "document-card",
    div(class = "document-title", document_row$title),
    
    div(class = "document-metadata",
      span(paste("📚", document_row$categoria)),
      span(paste("🗺️", document_row$estado)),
      span(paste("📅", format(as.Date(document_row$data_documento), "%d/%m/%Y"))),
      if (!is.na(document_row$tipo_documento)) span(paste("📄", document_row$tipo_documento))
    ),
    
    if (!is.na(document_row$ementa) && nchar(document_row$ementa) > 0) {
      div(
        style = "margin-top: 10px; color: #34495e; font-size: 14px;",
        substr(document_row$ementa, 1, 200),
        if (nchar(document_row$ementa) > 200) "..."
      )
    },
    
    div(
      style = "margin-top: 10px; display: flex; justify-content: space-between; align-items: center;",
      
      div(
        if (show_similarity && !is.na(document_row$total_similarity)) {
          span(
            class = "similarity-indicator",
            paste("Similarity:", round(document_row$total_similarity * 100, 1), "%")
          )
        },
        
        if (!is.na(document_row$trending_score) && document_row$trending_score > 5) {
          span(class = "trending-badge", "TRENDING")
        }
      ),
      
      div(
        actionButton(
          paste0("view_doc_", document_row$id),
          "👁 View",
          class = "btn-primary btn-xs",
          style = "margin-right: 5px;"
        ),
        actionButton(
          paste0("similar_docs_", document_row$id), 
          "🔗 Similar",
          class = "btn-info btn-xs",
          style = "margin-right: 5px;"
        ),
        actionButton(
          paste0("export_doc_", document_row$id),
          "📤 Export", 
          class = "btn-secondary btn-xs"
        )
      )
    )
  )
}

cat("✅ Enhanced Library UI Module loaded successfully\n")
cat("🎨 Features: Advanced Search Interface, Interactive Visualizations\n") 
cat("📊 Components: Performance Dashboard, Export Options, Faceted Filters\n")
cat("💡 Design: Responsive, Accessible, Government-Quality Interface\n")