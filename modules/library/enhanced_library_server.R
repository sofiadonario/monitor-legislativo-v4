# ENHANCED LIBRARY SERVER MODULE  
# ===============================
# Server-side implementation for advanced library functionality
# Handles 134k+ documents with sub-2 second response times

# ============================================================================
# 1. MAIN SERVER FUNCTION FOR ENHANCED LIBRARY
# ============================================================================

enhanced_library_server <- function(input, output, session, documents_data) {
  
  # Initialize reactive values for state management
  values <- reactiveValues(
    search_results = data.frame(),
    filtered_data = data.frame(),
    current_filters = list(),
    selected_document = NULL,
    search_query = "",
    performance_metrics = list(),
    user_session_data = list(
      searches = character(),
      accessed_documents = character(),
      session_start = Sys.time()
    )
  )
  
  # Load the enhanced analytics module
  source("modules/library/enhanced_library_analytics.R", local = TRUE)
  
  # ============================================================================
  # 2. SEARCH FUNCTIONALITY
  # ============================================================================
  
  # Main search reactive
  search_results <- eventReactive(input$enhanced_search_btn, {
    req(input$enhanced_search_query)
    
    start_time <- Sys.time()
    query <- str_trim(input$enhanced_search_query)
    
    if (nchar(query) < 2) {
      return(data.frame())
    }
    
    # Update user session tracking
    values$user_session_data$searches <- c(values$user_session_data$searches, query)
    values$search_query <- query
    
    # Check cache first
    cache_key <- digest::digest(list(query, input$search_mode, input$sort_results_by))
    cached_result <- get_from_cache(cache_key, "search_results")
    
    if (!is.null(cached_result) && input$enable_caching) {
      showNotification("🚀 Results loaded from cache", type = "message", duration = 2)
      return(cached_result)
    }
    
    # Perform search based on mode
    search_result <- switch(input$search_mode,
      "intelligent" = optimize_fulltext_search(query, documents_data(), limit = input$results_per_page * 5),
      "exact" = perform_exact_search(query, documents_data()),
      "fuzzy" = perform_fuzzy_search(query, documents_data()),
      "semantic" = perform_semantic_search(query, documents_data()),
      optimize_fulltext_search(query, documents_data(), limit = input$results_per_page * 5)
    )
    
    # Apply additional filtering
    filtered_results <- search_result$results
    if (length(values$current_filters) > 0) {
      filtered_results <- apply_facet_filters(filtered_results, values$current_filters)
    }
    
    # Calculate relevance and ranking
    final_results <- calculate_document_relevance(
      filtered_results, 
      query, 
      user_context = values$user_session_data
    )
    
    # Cache results
    if (input$enable_caching) {
      store_in_cache(cache_key, final_results, "search_results")
    }
    
    # Update performance metrics
    search_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
    values$performance_metrics$last_search_time <- search_time
    
    # Show performance indicator
    output$performance_indicator <- renderUI({
      div(
        class = "performance-indicator",
        style = "display: block;",
        sprintf("⚡ %d results in %dms", nrow(final_results), round(search_time))
      )
    })
    
    # Hide performance indicator after 3 seconds
    invalidateLater(3000)
    output$performance_indicator <- renderUI({
      div(class = "performance-indicator", style = "display: none;")
    })
    
    return(final_results)
  })
  
  # Auto-complete suggestions
  observe({
    query <- input$enhanced_search_query
    if (!is.null(query) && nchar(query) >= 2) {
      suggestions <- generate_search_suggestions(query, documents_data(), limit = 8)
      
      output$search_suggestions <- renderUI({
        if (length(suggestions) > 0) {
          suggestion_items <- lapply(suggestions, function(term) {
            div(
              class = "search-suggestion-item",
              onclick = sprintf("Shiny.setInputValue('selected_suggestion', '%s')", term),
              term
            )
          })
          
          div(
            id = "search-suggestions",
            class = "search-suggestions",
            style = "display: block;",
            do.call(tagList, suggestion_items)
          )
        }
      })
    } else {
      output$search_suggestions <- renderUI({
        div(id = "search-suggestions", class = "search-suggestions", style = "display: none;")
      })
    }
  })
  
  # Handle suggestion selection
  observeEvent(input$selected_suggestion, {
    updateTextInput(session, "enhanced_search_query", value = input$selected_suggestion)
    # Trigger search automatically
    delay(500, click("enhanced_search_btn"))
  })
  
  # Clear search functionality
  observeEvent(input$clear_search_btn, {
    updateTextInput(session, "enhanced_search_query", value = "")
    values$current_filters <- list()
    values$search_results <- data.frame()
    values$filtered_data <- documents_data()
    
    # Reset all filter inputs
    updateCheckboxGroupInput(session, "selected_categories", selected = character(0))
    updateCheckboxGroupInput(session, "selected_states", selected = character(0))
    updateCheckboxGroupInput(session, "selected_years", selected = character(0))
  })
  
  # ============================================================================
  # 3. FACETED FILTERING SYSTEM
  # ============================================================================
  
  # Get filtered data based on current filters and search
  filtered_documents <- reactive({
    base_data <- if (nchar(values$search_query) > 0 && nrow(values$search_results) > 0) {
      values$search_results
    } else {
      documents_data()
    }
    
    if (length(values$current_filters) > 0) {
      return(apply_facet_filters(base_data, values$current_filters))
    }
    
    return(base_data)
  })
  
  # Generate facet data
  facet_data <- reactive({
    create_faceted_filters(documents_data(), values$current_filters)
  })
  
  # Render category facets
  output$category_facets <- renderUI({
    facets <- facet_data()$categories
    create_facet_ui(facets, "category_filter", max_items = 8)
  })
  
  # Render geographic facets
  output$geographic_facets <- renderUI({
    facets <- facet_data()$states
    create_facet_ui(facets, "state_filter", max_items = 10)
  })
  
  # Render temporal facets
  output$temporal_facets <- renderUI({
    facets <- facet_data()$years

    if (!is.null(facets) && is.data.frame(facets) && nrow(facets) > 0) {
      # Create year range slider instead of checkboxes - safe extraction
      year_vals <- facets$name[!is.na(facets$name)]

      # Explicit handling of empty/single year cases
      if (length(year_vals) == 0) {
        return(p("No year data available", style = "color: #999; padding: 10px;"))
      }
      if (length(year_vals) == 1) {
        return(p(paste("Single year only:", year_vals[1]), style = "color: #999; padding: 10px;"))
      }

      # Safe range calculation with validation
      year_range <- range(year_vals, na.rm = TRUE)
      if (any(is.infinite(year_range)) || any(is.na(year_range))) {
        return(p("Invalid year data", style = "color: #999; padding: 10px;"))
      }
      
      tagList(
        sliderInput(
          "year_range_filter",
          "Year Range:",
          min = year_range[1],
          max = year_range[2], 
          value = year_range,
          step = 1,
          sep = ""
        ),
        div(
          style = "font-size: 12px; color: #666; margin-top: 5px;",
          paste("Total documents:", sum(facets$count))
        )
      )
    } else {
      p("No date information available", style = "color: #999; font-style: italic;")
    }
  })
  
  # Render document type facets
  output$document_type_facets <- renderUI({
    facets <- facet_data()$document_types
    create_facet_ui(facets, "doc_type_filter", max_items = 8)
  })
  
  # Render tribunal facets
  output$tribunal_facets <- renderUI({
    facets <- facet_data()$tribunals
    create_facet_ui(facets, "tribunal_filter", max_items = 6)
  })
  
  # Update filters when facets change
  observe({
    # Collect selected filters
    new_filters <- list()
    
    # Category filters
    category_selections <- get_selected_facet_items("category_filter", facet_data()$categories)
    if (length(category_selections) > 0) {
      new_filters$categories <- category_selections
    }
    
    # State filters
    state_selections <- get_selected_facet_items("state_filter", facet_data()$states)
    if (length(state_selections) > 0) {
      new_filters$states <- state_selections
    }
    
    # Year range filter
    if (!is.null(input$year_range_filter)) {
      new_filters$years <- seq(input$year_range_filter[1], input$year_range_filter[2])
    }
    
    # Document type filters
    doc_type_selections <- get_selected_facet_items("doc_type_filter", facet_data()$document_types)
    if (length(doc_type_selections) > 0) {
      new_filters$document_types <- doc_type_selections
    }
    
    # Tribunal filters
    tribunal_selections <- get_selected_facet_items("tribunal_filter", facet_data()$tribunals)
    if (length(tribunal_selections) > 0) {
      new_filters$tribunals <- tribunal_selections
    }
    
    values$current_filters <- new_filters
  })
  
  # ============================================================================
  # 4. RESULTS DISPLAY AND INTERACTION
  # ============================================================================
  
  # Results summary
  output$search_results_summary <- renderUI({
    filtered_data <- filtered_documents()
    
    # Safe nrow() calls
    total_count <- if (!is.null(documents_data()) && is.data.frame(documents_data())) nrow(documents_data()) else 0
    filtered_count <- if (!is.null(filtered_data) && is.data.frame(filtered_data)) nrow(filtered_data) else 0
    
    # Safe string length check
    has_search_query <- !is.null(values$search_query) && is.character(values$search_query) && length(values$search_query) > 0 && nchar(values$search_query) > 0
    
    summary_text <- if (has_search_query) {
      sprintf("Found %s results for '%s' (from %s total documents)", 
             format(filtered_count, big.mark = ","),
             values$search_query,
             format(total_count, big.mark = ","))
    } else {
      sprintf("Browsing %s documents", format(filtered_count, big.mark = ","))
    }
    
    # Add filters summary
    if (length(values$current_filters) > 0) {
      filter_summary <- sprintf(" • %d filters applied", length(values$current_filters))
      summary_text <- paste0(summary_text, filter_summary)
    }
    
    # Safe performance time check
    search_time <- tryCatch(values$performance_metrics$last_search_time, error = function(e) 0)
    show_perf <- !is.null(search_time) && length(search_time) > 0 && is.numeric(search_time) && search_time > 0
    
    div(
      h5(summary_text, style = "color: #2c3e50; margin-bottom: 5px;"),
      if (show_perf) {
        tags$small(
          sprintf("Search completed in %dms", round(search_time)),
          style = "color: #27ae60;"
        )
      }
    )
  })
  
  # Results controls
  output$results_controls <- renderUI({
    div(
      style = "display: flex; gap: 10px; align-items: center;",
      
      selectInput(
        "display_mode",
        "View:",
        choices = list(
          "📋 Table" = "table",
          "🗃️ Cards" = "cards"
        ),
        selected = "table",
        width = "120px"
      ),
      
      actionButton(
        "export_current_results",
        "📤 Export",
        class = "btn-secondary btn-sm"
      ),
      
      actionButton(
        "save_current_search",
        "💾 Save",
        class = "btn-info btn-sm"
      )
    )
  })
  
  # Enhanced documents table
  output$enhanced_documents_table <- DT::renderDataTable({
    filtered_data <- filtered_documents()
    
    if (is.null(filtered_data) || !is.data.frame(filtered_data) || nrow(filtered_data) == 0) {
      return(DT::datatable(
        data.frame(Message = "No documents found matching your criteria"),
        options = list(dom = 't', searching = FALSE, paging = FALSE, info = FALSE)
      ))
    }
    
    # Prepare display data
    display_data <- filtered_data %>%
      select(
        Title = title,
        Category = categoria,
        State = estado, 
        Date = data_documento,
        Type = tipo_documento,
        URN = urn
      ) %>%
      mutate(
        Date = format(as.Date(Date), "%d/%m/%Y"),
        Title = ifelse(nchar(Title) > 80, paste0(substr(Title, 1, 80), "..."), Title),
        Actions = sprintf('<button class="btn btn-xs btn-primary" onclick="Shiny.setInputValue(\'view_document\', \'%s\')">👁 View</button> <button class="btn btn-xs btn-info" onclick="Shiny.setInputValue(\'find_similar\', \'%s\')">🔗 Similar</button>', URN, URN)
      ) %>%
      select(-URN)
    
    DT::datatable(
      display_data,
      options = list(
        pageLength = input$results_per_page %||% 50,
        scrollX = TRUE,
        searching = FALSE,  # We handle search separately
        columnDefs = list(
          list(orderable = FALSE, targets = ncol(display_data) - 1),  # Actions column
          list(width = '300px', targets = 0),  # Title column
          list(width = '100px', targets = 1),  # Category column
          list(width = '80px', targets = 2),   # State column
          list(width = '100px', targets = 3),  # Date column
          list(width = '120px', targets = 4)   # Type column
        )
      ),
      class = "compact stripe hover",
      escape = FALSE,
      filter = 'none'
    )
  })
  
  # Enhanced documents cards view
  output$enhanced_documents_cards <- renderUI({
    filtered_data <- filtered_documents()
    
    if (is.null(filtered_data) || !is.data.frame(filtered_data) || nrow(filtered_data) == 0) {
      return(div(
        style = "text-align: center; padding: 50px; color: #999;",
        h4("No documents found"),
        p("Try adjusting your search criteria or filters")
      ))
    }
    
    # Create pagination for cards
    page_size <- input$results_per_page %||% 50
    current_page <- input$cards_page %||% 1
    
    paginated_data <- create_virtual_scroll_data(filtered_data, page_size, current_page)
    
    cards <- lapply(1:nrow(paginated_data$data), function(i) {
      create_document_card_ui(
        paginated_data$data[i, ],
        show_similarity = nchar(values$search_query) > 0
      )
    })
    
    tagList(
      do.call(tagList, cards),
      
      # Pagination for cards
      if (paginated_data$pagination$total_pages > 1) {
        div(
          style = "text-align: center; margin-top: 20px;",
          sprintf("Page %d of %d (%s total results)",
                 paginated_data$pagination$current_page,
                 paginated_data$pagination$total_pages,
                 format(paginated_data$pagination$total_results, big.mark = ","))
        )
      }
    )
  })
  
  # ============================================================================
  # 5. DOCUMENT DISCOVERY AND SIMILARITY
  # ============================================================================
  
  # Handle document view requests
  observeEvent(input$view_document, {
    if (!is.null(input$view_document) && input$view_document != "") {
      values$selected_document <- input$view_document
      values$user_session_data$accessed_documents <- c(
        values$user_session_data$accessed_documents,
        input$view_document
      )
      
      # Show document details modal
      showModal(modalDialog(
        title = "📄 Document Details",
        size = "l",
        
        # Document details content
        uiOutput("document_details_content"),
        
        footer = tagList(
          actionButton("find_similar_from_modal", "🔗 Find Similar Documents", class = "btn-info"),
          modalButton("Close")
        )
      ))
    }
  })
  
  # Handle find similar requests
  observeEvent(input$find_similar, {
    if (!is.null(input$find_similar) && input$find_similar != "") {
      similar_docs <- find_similar_documents(
        input$find_similar, 
        documents_data(),
        similarity_threshold = 0.2,
        limit = 10
      )
      
      values$similar_documents <- similar_docs
    }
  })
  
  # Render similar documents
  output$similar_documents_ui <- renderUI({
    if (is.null(values$similar_documents) || nrow(values$similar_documents) == 0) {
      return(div(
        style = "text-align: center; color: #999;",
        p("No similar documents found")
      ))
    }
    
    similar_cards <- lapply(1:nrow(values$similar_documents), function(i) {
      create_document_card_ui(values$similar_documents[i, ], show_similarity = TRUE)
    })
    
    do.call(tagList, similar_cards)
  })
  
  # ============================================================================
  # 6. TRENDING DOCUMENTS
  # ============================================================================
  
  # Render trending documents when no search is active
  output$trending_documents_ui <- renderUI({
    trending_docs <- identify_trending_documents(
      documents_data(),
      access_log = NULL,  # Would use real access log if available
      time_window_days = 30
    )
    
    if (is.null(trending_docs) || !is.data.frame(trending_docs) || nrow(trending_docs) == 0) {
      return(p("No trending documents available"))
    }
    
    # Show top 5 trending documents
    top_trending <- head(trending_docs, 5)
    
    trending_items <- lapply(1:nrow(top_trending), function(i) {
      doc <- top_trending[i, ]
      
      div(
        class = "document-card",
        style = "border-left: 4px solid #e74c3c;",
        
        div(class = "document-title", doc$title),
        
        div(class = "document-metadata",
          span(paste("📚", doc$categoria)),
          span(paste("🗺️", doc$estado)),
          span(paste("📅", format(as.Date(doc$data_documento), "%d/%m/%Y"))),
          span(class = "trending-badge", "TRENDING")
        ),
        
        if (!is.null(doc$ementa) && length(doc$ementa) > 0 && !is.na(doc$ementa[1]) && nchar(doc$ementa[1]) > 0) {
          div(
            style = "margin-top: 8px; color: #555; font-size: 13px;",
            substr(doc$ementa, 1, 150),
            if (nchar(doc$ementa) > 150) "..."
          )
        }
      )
    })
    
    do.call(tagList, trending_items)
  })
  
  # ============================================================================
  # 7. PERFORMANCE MONITORING
  # ============================================================================
  
  # Generate performance metrics
  performance_metrics <- reactive({
    generate_performance_report()
  })
  
  # Performance value boxes
  output$search_performance_box <- renderValueBox({
    metrics <- performance_metrics()
    req(metrics)

    avg_time <- tryCatch({
      scalar_num(metrics$search_performance$avg_response_time, default = 0)
    }, error = function(e) 0)
    avg_time <- round(avg_time, 0)

    safe_valueBox(
      value = value_box_scalar(paste0(avg_time, "ms")),
      subtitle = "Avg Search Time",
      icon = icon("clock"),
      color = if (avg_time < 200) "green" else if (avg_time < 500) "yellow" else "red"
    )
  })
  
  output$cache_performance_box <- renderValueBox({
    metrics <- performance_metrics()
    req(metrics)

    hit_rate <- tryCatch({
      rate <- scalar_num(metrics$cache_performance$hit_rate, default = 0)
      round(rate * 100, 1)
    }, error = function(e) 0)

    safe_valueBox(
      value = value_box_scalar(paste0(hit_rate, "%")),
      subtitle = "Cache Hit Rate",
      icon = icon("database"),
      color = if (hit_rate > 80) "green" else if (hit_rate > 50) "yellow" else "red"
    )
  })
  
  output$system_health_box <- renderValueBox({
    metrics <- performance_metrics()
    req(metrics)

    memory_mb <- tryCatch({
      mem_str <- scalar_chr(metrics$system_status$memory_usage, default = "0 Mb")
      scalar_num(gsub(" Mb", "", mem_str), default = 0)
    }, error = function(e) 0)

    safe_valueBox(
      value = value_box_scalar(paste0(round(memory_mb), "MB")),
      subtitle = "Memory Usage",
      icon = icon("memory"),
      color = if (memory_mb < 100) "green" else if (memory_mb < 200) "yellow" else "red"
    )
  })
  
  output$user_activity_box <- renderValueBox({
    search_count <- safe_length(values$user_session_data$searches, default = 0L)

    safe_valueBox(
      value = value_box_scalar(search_count),
      subtitle = "Searches This Session",
      icon = icon("search"),
      color = "blue"
    )
  })
  
  # ============================================================================
  # 8. UTILITY FUNCTIONS
  # ============================================================================
  
  # Get selected items from facet UI
  get_selected_facet_items <- function(base_id, facet_data) {
    if (is.null(facet_data) || !is.data.frame(facet_data) || nrow(facet_data) == 0) return(character(0))
    
    selected_items <- character(0)
    for (i in 1:min(nrow(facet_data), 20)) {  # Check up to 20 items
      input_id <- paste0(base_id, "_", i)
      if (isTRUE(input[[input_id]])) {
        selected_items <- c(selected_items, facet_data$name[i])
      }
    }
    
    return(selected_items)
  }
  
  # Apply facet filters to data
  apply_facet_filters <- function(data, filters) {
    if ((is.null(data) || !is.data.frame(data) || nrow(data) == 0) || (is.null(filters) || length(filters) == 0)) return(data)
    
    filtered_data <- data
    
    # Apply category filter
    if ("categories" %in% names(filters) && length(filters$categories) > 0) {
      filtered_data <- filtered_data[filtered_data$categoria %in% filters$categories, ]
    }
    
    # Apply state filter
    if ("states" %in% names(filters) && length(filters$states) > 0) {
      filtered_data <- filtered_data[filtered_data$estado %in% filters$states, ]
    }
    
    # Apply year filter - safe vector handling
    if ("years" %in% names(filters) && length(filters$years) > 0) {
      if (!is.null(filtered_data) && is.data.frame(filtered_data) && nrow(filtered_data) > 0 && "data_documento" %in% names(filtered_data)) {
        valid_rows <- !is.na(filtered_data$data_documento) &
                      year(as.Date(filtered_data$data_documento)) %in% filters$years
        # Ensure valid_rows is a logical vector with no NAs
        valid_rows[is.na(valid_rows)] <- FALSE
        filtered_data <- filtered_data[valid_rows, , drop = FALSE]
      }
    }
    
    # Apply document type filter
    if ("document_types" %in% names(filters) && length(filters$document_types) > 0) {
      filtered_data <- filtered_data[filtered_data$tipo_documento %in% filters$document_types, ]
    }
    
    # Apply tribunal filter
    if ("tribunals" %in% names(filters) && length(filters$tribunals) > 0) {
      tribunal_patterns <- list(
        "STF" = "supremo.tribunal.federal",
        "STJ" = "superior.tribunal.justica", 
        "TST" = "tribunal.superior.trabalho",
        "TRF" = "tribunal.regional.federal",
        "TRT" = "tribunal.regional.trabalho",
        "TJ" = "tribunal.justica"
      )
      
      tribunal_conditions <- sapply(filters$tribunals, function(tribunal) {
        if (tribunal %in% names(tribunal_patterns)) {
          grepl(tribunal_patterns[[tribunal]], filtered_data$urn, ignore.case = TRUE)
        } else {
          rep(FALSE, nrow(filtered_data))
        }
      })
      
      if (is.matrix(tribunal_conditions)) {
        tribunal_match <- apply(tribunal_conditions, 1, any)
      } else {
        tribunal_match <- tribunal_conditions
      }
      
      filtered_data <- filtered_data[tribunal_match, ]
    }
    
    return(filtered_data)
  }
  
  # Simple search implementations for different modes
  perform_exact_search <- function(query, documents_df) {
    matches <- documents_df[grepl(paste0("\\b", query, "\\b"), documents_df$title, ignore.case = TRUE), ]
    return(list(results = matches, search_time_ms = 50, total_matches = nrow(matches)))
  }
  
  perform_fuzzy_search <- function(query, documents_df) {
    # Simple fuzzy search using agrep (approximate grep)
    matches <- documents_df[agrep(query, documents_df$title, ignore.case = TRUE, max.distance = 0.2), ]
    return(list(results = matches, search_time_ms = 100, total_matches = nrow(matches)))
  }
  
  perform_semantic_search <- function(query, documents_df) {
    # Placeholder for semantic search - would integrate with actual semantic model
    # For now, falls back to intelligent search
    return(optimize_fulltext_search(query, documents_df))
  }
  
  # Return the reactive values for use by other modules
  return(list(
    search_results = reactive(values$search_results),
    filtered_data = filtered_documents,
    selected_document = reactive(values$selected_document),
    performance_metrics = performance_metrics
  ))
}

cat("✅ Enhanced Library Server Module loaded successfully\n")
cat("🔧 Functions: Search, Filtering, Discovery, Performance Monitoring\n")
cat("⚡ Optimized: Caching, Indexing, Real-time Analytics\n")
cat("🎯 Target: Sub-2 second response times for 134k+ documents\n")