# ============================================================================
# AUTOCOMPLETE SERVER INTEGRATION MODULE
# ============================================================================
#
# This module integrates the intelligent autocomplete engine with the 
# existing advanced search server, providing real-time suggestions
# with sub-100ms performance and intelligent caching.
#
# Features:
# - Seamless integration with existing search server architecture
# - Real-time autocomplete with debouncing (150ms delay)
# - Context-aware suggestions based on current filters
# - Redis caching integration for high performance
# - Fallback mechanisms for reliability
# - Performance monitoring and analytics
# - Portuguese language optimization
#
# Author: Senior Data Scientist - Brazilian Legal Analytics Team
# Date: January 2025
# Version: 1.0 - Production Ready
# ============================================================================

cat("🔗 Loading Autocomplete Server Integration...\n")

# Ensure intelligent autocomplete engine is loaded
if (!exists("get_autocomplete_suggestions")) {
  tryCatch({
    source("modules/search/intelligent_autocomplete_engine.R")
  }, error = function(e) {
    cat("❌ Failed to load intelligent autocomplete engine:", e$message, "\n")
    cat("🚨 Autocomplete will use fallback methods\n")
  })
}

# ============================================================================
# AUTOCOMPLETE SERVER CONFIGURATION
# ============================================================================

.autocomplete_server_config <- list(
  # Performance settings
  debounce_delay_ms = 150,
  max_suggestions = 10,
  min_query_length = 2,
  max_query_length = 100,
  
  # Caching settings  
  enable_caching = TRUE,
  cache_ttl_seconds = 300,  # 5 minutes
  max_cache_entries = 1000,
  
  # Performance targets
  target_response_time_ms = 100,
  performance_monitoring = TRUE,
  
  # Fallback settings
  fallback_enabled = TRUE,
  fallback_suggestions_count = 5
)

# Global autocomplete state
.autocomplete_state <- reactiveValues(
  last_query = "",
  last_suggestions = list(),
  performance_metrics = list(),
  cache_stats = list(hits = 0, misses = 0),
  is_processing = FALSE
)

# ============================================================================
# REAL-TIME AUTOCOMPLETE SERVER FUNCTION
# ============================================================================

#' Enhanced autocomplete server module for advanced search
#' @param id Module namespace ID
#' @param search_filters_reactive Reactive containing current search filters
#' @return Server function for autocomplete functionality
autocomplete_server <- function(id, search_filters_reactive = NULL) {
  moduleServer(id, function(input, output, session) {
    
    # Debounced reactive for query input
    query_debounced <- reactive({
      input$search_query
    }) %>% debounce(.autocomplete_server_config$debounce_delay_ms)
    
    # Current search context (filters)
    search_context <- reactive({
      if (!is.null(search_filters_reactive) && is.function(search_filters_reactive)) {
        return(search_filters_reactive())
      } else {
        # Fallback context extraction from inputs
        return(list(
          estado = input$state_filter %||% "all",
          region = input$region_filter %||% "all", 
          transport_category = input$transport_category %||% "all",
          document_type = input$document_type_filter,
          species = input$species_filter
        ))
      }
    })
    
    # Main autocomplete logic
    autocomplete_suggestions <- reactive({
      query <- str_trim(query_debounced() %||% "")
      
      # Validate query
      if (nchar(query) < .autocomplete_server_config$min_query_length) {
        return(list(suggestions = list(), metadata = list(query = query, message = "Query too short")))
      }
      
      if (nchar(query) > .autocomplete_server_config$max_query_length) {
        query <- substr(query, 1, .autocomplete_server_config$max_query_length)
      }
      
      # Avoid processing same query repeatedly
      if (query == .autocomplete_state$last_query && length(.autocomplete_state$last_suggestions) > 0) {
        return(.autocomplete_state$last_suggestions)
      }
      
      .autocomplete_state$is_processing <- TRUE
      on.exit(.autocomplete_state$is_processing <- FALSE)
      
      start_time <- Sys.time()
      
      tryCatch({
        # Get suggestions with context
        context <- search_context()
        
        if (exists("get_contextual_suggestions")) {
          result <- get_contextual_suggestions(
            partial_query = query,
            search_filters = context,
            max_suggestions = .autocomplete_server_config$max_suggestions
          )
        } else if (exists("get_autocomplete_suggestions")) {
          result <- get_autocomplete_suggestions(
            partial_query = query,
            context = context,
            max_suggestions = .autocomplete_server_config$max_suggestions,
            use_cache = .autocomplete_server_config$enable_caching
          )
        } else {
          # Fallback to basic suggestions
          result <- generate_fallback_suggestions(query, context)
        }
        
        # Performance monitoring
        end_time <- Sys.time()
        processing_time <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
        
        result$metadata$server_processing_time_ms <- round(processing_time, 2)
        result$metadata$timestamp <- Sys.time()
        result$metadata$context_applied <- length(context) > 0
        
        # Update performance metrics
        if (.autocomplete_server_config$performance_monitoring) {
          update_performance_metrics(query, processing_time, length(result$suggestions))
        }
        
        # Update cache statistics
        if (!is.null(result$metadata$cache_hit)) {
          if (result$metadata$cache_hit) {
            .autocomplete_state$cache_stats$hits <- .autocomplete_state$cache_stats$hits + 1
          } else {
            .autocomplete_state$cache_stats$misses <- .autocomplete_state$cache_stats$misses + 1
          }
        }
        
        # Store for next comparison
        .autocomplete_state$last_query <- query
        .autocomplete_state$last_suggestions <- result
        
        return(result)
        
      }, error = function(e) {
        cat("❌ Autocomplete error:", e$message, "\n")
        
        # Return error response with fallback
        error_result <- list(
          suggestions = if (.autocomplete_server_config$fallback_enabled) {
            generate_fallback_suggestions(query, search_context())$suggestions
          } else {
            list()
          },
          metadata = list(
            query = query,
            error = e$message,
            timestamp = Sys.time(),
            fallback_used = .autocomplete_server_config$fallback_enabled
          )
        )
        
        return(error_result)
      })
    })
    
    # Send suggestions to frontend
    observe({
      suggestions_data <- autocomplete_suggestions()
      
      if (!is.null(suggestions_data) && length(suggestions_data$suggestions) > 0) {
        # Format for JavaScript consumption
        js_suggestions <- lapply(suggestions_data$suggestions, function(sugg) {
          list(
            text = sugg$text,
            value = sugg$text,
            description = sugg$description %||% "",
            category = sugg$category %||% "",
            icon = sugg$icon %||% "fas fa-search",
            score = sugg$score %||% 0
          )
        })
        
        # Send to frontend
        session$sendCustomMessage("updateAutocomplete", list(
          suggestions = js_suggestions,
          query = suggestions_data$metadata$query,
          total_found = suggestions_data$metadata$total_found %||% length(js_suggestions),
          processing_time = suggestions_data$metadata$server_processing_time_ms %||% 0,
          cache_hit = suggestions_data$metadata$cache_hit %||% FALSE
        ))
        
      } else if (!is.null(suggestions_data) && nchar(suggestions_data$metadata$query %||% "") >= .autocomplete_server_config$min_query_length) {
        # Send empty results message
        session$sendCustomMessage("updateAutocomplete", list(
          suggestions = list(),
          query = suggestions_data$metadata$query,
          message = "Nenhuma sugestão encontrada",
          total_found = 0
        ))
      }
    })
    
    # Clear autocomplete when query is empty or too short
    observe({
      query <- str_trim(input$search_query %||% "")
      if (nchar(query) < .autocomplete_server_config$min_query_length) {
        session$sendCustomMessage("clearAutocomplete", list())
      }
    })
    
    # Handle autocomplete selection
    observeEvent(input$autocomplete_selected, {
      if (!is.null(input$autocomplete_selected$value)) {
        selected_value <- input$autocomplete_selected$value
        
        # Update search input
        updateTextInput(session, "search_query", value = selected_value)
        
        # Log selection for analytics
        if (.autocomplete_server_config$performance_monitoring) {
          log_autocomplete_selection(selected_value, input$autocomplete_selected$category %||% "unknown")
        }
        
        # Trigger search if configured
        if (input$autocomplete_selected$trigger_search %||% FALSE) {
          # Trigger immediate search
          session$sendCustomMessage("triggerSearch", list())
        }
      }
    })
    
    # Return reactive values for external use
    return(list(
      suggestions = autocomplete_suggestions,
      performance_metrics = reactive(.autocomplete_state$performance_metrics),
      cache_stats = reactive(.autocomplete_state$cache_stats),
      is_processing = reactive(.autocomplete_state$is_processing)
    ))
  })
}

# ============================================================================
# PERFORMANCE MONITORING AND ANALYTICS
# ============================================================================

#' Update performance metrics for monitoring
#' @param query Search query
#' @param processing_time Processing time in milliseconds
#' @param suggestions_count Number of suggestions returned
update_performance_metrics <- function(query, processing_time, suggestions_count) {
  tryCatch({
    # Initialize metrics if needed
    if (is.null(.autocomplete_state$performance_metrics$queries)) {
      .autocomplete_state$performance_metrics <- list(
        queries = list(),
        avg_processing_time = 0,
        max_processing_time = 0,
        min_processing_time = Inf,
        total_queries = 0,
        slow_queries = 0,
        target_compliance_rate = 0
      )
    }
    
    metrics <- .autocomplete_state$performance_metrics
    
    # Update counters
    metrics$total_queries <- metrics$total_queries + 1
    
    # Update processing time statistics
    metrics$max_processing_time <- max(metrics$max_processing_time, processing_time)
    metrics$min_processing_time <- min(metrics$min_processing_time, processing_time)
    
    # Calculate rolling average (last 100 queries)
    if (length(metrics$queries) >= 100) {
      metrics$queries <- tail(metrics$queries, 99)
    }
    
    metrics$queries[[length(metrics$queries) + 1]] <- list(
      query = substr(query, 1, 20),  # Truncate for privacy
      processing_time = processing_time,
      suggestions_count = suggestions_count,
      timestamp = Sys.time()
    )
    
    # Calculate average processing time
    recent_times <- sapply(metrics$queries, function(x) x$processing_time)
    metrics$avg_processing_time <- mean(recent_times)
    
    # Count slow queries (above target)
    if (processing_time > .autocomplete_server_config$target_response_time_ms) {
      metrics$slow_queries <- metrics$slow_queries + 1
    }
    
    # Calculate target compliance rate
    metrics$target_compliance_rate <- ((metrics$total_queries - metrics$slow_queries) / metrics$total_queries) * 100
    
    .autocomplete_state$performance_metrics <- metrics
    
  }, error = function(e) {
    cat("⚠️ Performance metrics update failed:", e$message, "\n")
  })
}

#' Log autocomplete selection for analytics
#' @param selected_term Selected term
#' @param category Term category
log_autocomplete_selection <- function(selected_term, category) {
  tryCatch({
    cat("📊 Autocomplete selection:", selected_term, "(", category, ")\n")
    
    # Here you could integrate with analytics systems
    # Example: send to Google Analytics, Mixpanel, etc.
    
  }, error = function(e) {
    # Silent fail for logging
  })
}

# ============================================================================
# FALLBACK SUGGESTION GENERATION
# ============================================================================

#' Generate fallback suggestions when main engine is unavailable
#' @param query User query
#' @param context Search context
#' @return Fallback suggestions list
generate_fallback_suggestions <- function(query, context = list()) {
  
  # Basic Portuguese legal terms for fallback
  basic_legal_terms <- c(
    "Lei Federal", "Lei Estadual", "Decreto", "Portaria", "Resolução",
    "Constituição Federal", "Código Civil", "Código Penal", "Medida Provisória",
    "STF", "STJ", "Supremo Tribunal Federal", "Superior Tribunal de Justiça",
    "Ministério Público", "Advocacia-Geral da União", "Tribunal de Contas",
    "Transporte Público", "Transporte Rodoviário", "Mobilidade Urbana",
    "São Paulo", "Rio de Janeiro", "Brasília", "Federal", "Estadual", "Municipal",
    "ANTT", "ANAC", "ANTAQ", "Código de Trânsito", "Licitação"
  )
  
  query_lower <- str_to_lower(query)
  matches <- basic_legal_terms[str_detect(str_to_lower(basic_legal_terms), fixed(query_lower))]
  
  # Limit to configured count
  matches <- head(matches, .autocomplete_server_config$fallback_suggestions_count)
  
  # Format as suggestion objects
  suggestions <- lapply(matches, function(term) {
    list(
      text = term,
      description = "Termo Legal (Fallback)",
      category = "Legal",
      type = "fallback",
      icon = "fas fa-search"
    )
  })
  
  return(list(
    suggestions = suggestions,
    metadata = list(
      query = query,
      total_found = length(suggestions),
      source = "fallback",
      timestamp = Sys.time()
    )
  ))
}

# ============================================================================
# CLIENT-SIDE JAVASCRIPT INTEGRATION
# ============================================================================

#' Generate JavaScript code for frontend autocomplete integration
#' @return JavaScript code as character string
get_autocomplete_javascript <- function() {
  js_code <- "
// Enhanced Autocomplete JavaScript Integration
(function() {
  let autocompleteContainer = null;
  let currentQuery = '';
  let selectedIndex = -1;
  let suggestions = [];
  
  // Initialize autocomplete when DOM is ready
  $(document).ready(function() {
    initializeAutocomplete();
  });
  
  function initializeAutocomplete() {
    const searchInput = $('#search_query, .search-main-input');
    
    if (searchInput.length === 0) {
      console.warn('Search input not found for autocomplete');
      return;
    }
    
    // Create autocomplete container
    autocompleteContainer = $('<div id=\"autocomplete-dropdown\" class=\"autocomplete-dropdown\"></div>');
    searchInput.parent().append(autocompleteContainer);
    
    // Bind events
    bindAutocompleteEvents(searchInput);
    
    console.log('✅ Autocomplete initialized');
  }
  
  function bindAutocompleteEvents(searchInput) {
    // Input event for real-time suggestions
    searchInput.on('input', function(e) {
      const query = $(this).val();
      currentQuery = query;
      
      if (query.length >= 2) {
        // Trigger server-side suggestion request
        Shiny.setInputValue('search_query', query, {priority: 'event'});
      } else {
        hideAutocomplete();
      }
    });
    
    // Keyboard navigation
    searchInput.on('keydown', function(e) {
      if (!autocompleteContainer.is(':visible')) return;
      
      switch(e.key) {
        case 'ArrowDown':
          e.preventDefault();
          navigateAutocomplete(1);
          break;
        case 'ArrowUp':
          e.preventDefault();
          navigateAutocomplete(-1);
          break;
        case 'Enter':
          e.preventDefault();
          selectCurrentSuggestion();
          break;
        case 'Escape':
          hideAutocomplete();
          break;
      }
    });
    
    // Hide on outside click
    $(document).on('click', function(e) {
      if (!$(e.target).closest('.search-input-wrapper, .autocomplete-dropdown').length) {
        hideAutocomplete();
      }
    });
  }
  
  function navigateAutocomplete(direction) {
    if (suggestions.length === 0) return;
    
    // Remove current highlight
    $('.autocomplete-item').removeClass('highlighted');
    
    // Update selected index
    selectedIndex += direction;
    
    if (selectedIndex < -1) selectedIndex = suggestions.length - 1;
    if (selectedIndex >= suggestions.length) selectedIndex = -1;
    
    // Highlight new selection
    if (selectedIndex >= 0) {
      $('.autocomplete-item').eq(selectedIndex).addClass('highlighted');
    }
    
    // Update ARIA attributes for accessibility
    updateAriaAttributes();
  }
  
  function selectCurrentSuggestion() {
    if (selectedIndex >= 0 && suggestions.length > selectedIndex) {
      const suggestion = suggestions[selectedIndex];
      selectSuggestion(suggestion);
    } else {
      // No selection, trigger search with current input
      triggerSearch();
    }
  }
  
  function selectSuggestion(suggestion) {
    // Update input value
    $('#search_query, .search-main-input').val(suggestion.text);
    
    // Send selection to server
    Shiny.setInputValue('autocomplete_selected', {
      value: suggestion.text,
      category: suggestion.category,
      trigger_search: true,
      timestamp: Date.now()
    }, {priority: 'event'});
    
    // Hide autocomplete
    hideAutocomplete();
    
    // Announce selection to screen readers
    announceToScreenReader('Selecionado: ' + suggestion.text);
  }
  
  function triggerSearch() {
    hideAutocomplete();
    $('#search_btn').click();
  }
  
  function showAutocomplete(data) {
    if (!data || !data.suggestions || data.suggestions.length === 0) {
      hideAutocomplete();
      return;
    }
    
    suggestions = data.suggestions;
    selectedIndex = -1;
    
    // Build HTML
    let html = '';
    suggestions.forEach((suggestion, index) => {
      html += `
        <div class=\"autocomplete-item\" data-index=\"${index}\" role=\"option\">
          <div class=\"autocomplete-content\">
            <i class=\"${suggestion.icon}\"></i>
            <div class=\"autocomplete-text\">
              <div class=\"autocomplete-main\">${escapeHtml(suggestion.text)}</div>
              <div class=\"autocomplete-description\">${escapeHtml(suggestion.description)}</div>
            </div>
            <div class=\"autocomplete-category\">${escapeHtml(suggestion.category)}</div>
          </div>
        </div>
      `;
    });
    
    // Add performance info if available
    if (data.processing_time) {
      html += `<div class=\"autocomplete-footer\">
        <small class=\"text-muted\">
          ${data.total_found} sugestões em ${data.processing_time}ms
          ${data.cache_hit ? '(cache)' : ''}
        </small>
      </div>`;
    }
    
    autocompleteContainer.html(html).show();
    
    // Bind click events
    $('.autocomplete-item').on('click', function() {
      const index = parseInt($(this).data('index'));
      if (suggestions[index]) {
        selectSuggestion(suggestions[index]);
      }
    });
    
    // Update ARIA attributes
    updateAriaAttributes();
    
    // Announce to screen readers
    announceToScreenReader(data.suggestions.length + ' sugestões disponíveis');
  }
  
  function hideAutocomplete() {
    if (autocompleteContainer) {
      autocompleteContainer.hide().empty();
    }
    suggestions = [];
    selectedIndex = -1;
  }
  
  function updateAriaAttributes() {
    const searchInput = $('#search_query, .search-main-input');
    
    if (suggestions.length > 0) {
      searchInput.attr({
        'aria-expanded': 'true',
        'aria-activedescendant': selectedIndex >= 0 ? 'autocomplete-item-' + selectedIndex : ''
      });
      
      $('.autocomplete-item').each(function(index) {
        $(this).attr('id', 'autocomplete-item-' + index);
      });
    } else {
      searchInput.attr('aria-expanded', 'false').removeAttr('aria-activedescendant');
    }
  }
  
  function announceToScreenReader(message) {
    const announcement = $('<div>').attr({
      'aria-live': 'polite',
      'aria-atomic': 'true',
      'class': 'sr-only'
    }).text(message);
    
    $('body').append(announcement);
    setTimeout(() => announcement.remove(), 1000);
  }
  
  function escapeHtml(unsafe) {
    return unsafe
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
  
  // Custom message handlers from Shiny
  Shiny.addCustomMessageHandler('updateAutocomplete', function(data) {
    showAutocomplete(data);
  });
  
  Shiny.addCustomMessageHandler('clearAutocomplete', function(data) {
    hideAutocomplete();
  });
  
  Shiny.addCustomMessageHandler('triggerSearch', function(data) {
    triggerSearch();
  });
  
  console.log('✅ Autocomplete JavaScript loaded');
})();
"
  
  return(js_code)
}

# ============================================================================
# SYSTEM DIAGNOSTICS
# ============================================================================

#' Get autocomplete system status
#' @return System status information
get_autocomplete_system_status <- function() {
  
  status <- list(
    engine_loaded = exists("get_autocomplete_suggestions"),
    server_config = .autocomplete_server_config,
    performance_metrics = .autocomplete_state$performance_metrics,
    cache_stats = .autocomplete_state$cache_stats,
    capabilities = list(
      intelligent_suggestions = exists("get_autocomplete_suggestions"),
      contextual_suggestions = exists("get_contextual_suggestions"),
      fuzzy_matching = requireNamespace("stringdist", quietly = TRUE),
      caching = exists("get_redis_cache") || exists(".autocomplete_cache"),
      performance_monitoring = .autocomplete_server_config$performance_monitoring,
      fallback_enabled = .autocomplete_server_config$fallback_enabled
    )
  )
  
  # Determine overall system health
  critical_components <- c("intelligent_suggestions", "fallback_enabled")
  critical_status <- sapply(critical_components, function(comp) {
    status$capabilities[[comp]] %||% FALSE
  })
  
  status$system_health <- if (all(critical_status)) "healthy" else "degraded"
  
  return(status)
}

# ============================================================================
# INITIALIZATION
# ============================================================================

cat("✅ Autocomplete Server Integration loaded successfully\n")
cat("   🔗 Integration with advanced search server\n")
cat("   ⚡ Real-time suggestions with", .autocomplete_server_config$debounce_delay_ms, "ms debouncing\n")
cat("   🎯 Target response time:", .autocomplete_server_config$target_response_time_ms, "ms\n")
cat("   💾 Caching:", if(.autocomplete_server_config$enable_caching) "enabled" else "disabled", "\n")
cat("   🛡️ Fallback:", if(.autocomplete_server_config$fallback_enabled) "enabled" else "disabled", "\n")

# Export main functions
.GlobalEnv$autocomplete_server <- autocomplete_server
.GlobalEnv$get_autocomplete_javascript <- get_autocomplete_javascript
.GlobalEnv$get_autocomplete_system_status <- get_autocomplete_system_status

cat("🚀 AUTOCOMPLETE SERVER INTEGRATION READY!\n")